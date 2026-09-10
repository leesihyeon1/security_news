(function () {
  "use strict";

  const PAGE_SIZE = 30;
  const IOC_DISPLAY_LIMIT = 5; // 본문에 IOC가 많아도 인사이트 상세에는 상위 5건만 보이고 나머지는 개수만 표시
  const INSIGHT_DRAWER_LIMIT = 10; // 드로어는 "빠른 확인용" — 전체 이력은 인사이트 탭에서
  const SUMMARY_HIGHLIGHTS_LIMIT = 10; // 요약 탭은 빠른 개요가 목적 — 전체는 국내/해외(일간) 또는 History 탭 검색(주간)에서
  const SEARCH_LOG_URL = "https://click-tracker-two.vercel.app/api/search-log";
  const SEARCH_LOG_DEBOUNCE_MS = 1000;
  const ANALYZE_URL = "https://click-tracker-two.vercel.app/api/analyze";
  const INSIGHTS_URL = "https://click-tracker-two.vercel.app/api/insights";

  // 탭 구성이 기간별로 다르다 — 일간은 기사 원문을 국내/해외로 나눠 계속 보여주고,
  // 주간은 그 대신 통계(분포·주간 동향·순위)를 보여준다. 인사이트는 왼쪽 고정
  // 토글 드로어(화면 폭과 무관하게 항상 접근 가능)와 별개로, History 옆에 탭으로도
  // 접근 가능하다 — 드로어는 빠른 확인용, 탭은 History처럼 전체 이력을 훑어보는 용도.
  function tabsForPeriod(period) {
    return period === "weekly"
      ? ["all", "recommended", "cve", "stats", "insight", "history"]
      : ["all", "recommended", "cve", "domestic", "overseas", "insight", "history"];
  }

  const state = {
    period: "daily",
    tab: "all", // all | domestic | overseas | recommended | cve | stats | history
    cache: {}, // period -> payload
    query: "",
    searchIndex: null, // null = 아직 로딩 전, 로드되면 배열
    pages: {}, // pageKey -> 현재 페이지 번호(1부터)
    // "심층분석 보기" 결과 히스토리 — 새로 누른 게 앞에 오도록 unshift한다. analyze.js가
    // 새 분석마다 서버(Redis insights:list)에도 같이 적어두므로, 페이지를 새로고침하거나
    // 다른 사람이 접속해도 loadInsights()가 이 목록을 그대로 불러와 이어서 보여준다.
    insightHistory: [],
    insightHistoryLoaded: false,
    insightDetailIdx: null, // 현재 전체화면 상세로 열려 있는 항목의 insightHistory 인덱스(재분석용)
    trending: null, // null = 아직 로딩 전, 로드되면 {generated_at, items}
  };

  const $app = document.getElementById("app");
  const $loading = document.getElementById("loading");
  const $generatedAt = document.getElementById("generated-at");
  const $searchInput = document.getElementById("search-input");
  const $keywordSidebar = document.getElementById("keyword-sidebar");
  const $trendSidebar = document.getElementById("trend-sidebar");
  const $trendingSidebar = document.getElementById("trending-sidebar");
  const $insightToggle = document.getElementById("insight-toggle");
  const $insightBadge = document.getElementById("insight-badge");
  const $insightDrawer = document.getElementById("insight-drawer");
  const $insightDrawerBody = document.getElementById("insight-drawer-body");
  const $insightDrawerCount = document.getElementById("insight-drawer-count");
  const $insightDrawerClose = document.getElementById("insight-drawer-close");
  const $insightDetail = document.getElementById("insight-detail");
  const $insightDetailBody = document.getElementById("insight-detail-body");
  const $insightDetailBack = document.getElementById("insight-detail-back");
  const $insightDetailClose = document.getElementById("insight-detail-close");
  const $insightDetailReanalyze = document.getElementById("insight-detail-reanalyze");

  // ===== Theme =====
  function initTheme() {
    const saved = localStorage.getItem("theme");
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
    document.getElementById("theme-toggle").addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme");
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      const currentlyDark = current ? current === "dark" : prefersDark;
      const next = currentlyDark ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("theme", next);
    });
  }

  // ===== Utilities =====
  function esc(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
  }

  // 심층분석 결과(analyze.js)는 LLM이 자연스럽게 "**키워드**" 같은 마크다운 볼드를
  // 섞어 쓰는데, 기존엔 줄바꿈만 <br>로 바꾸고 별표는 그대로 노출됐다. 먼저 esc()로
  // 이스케이프해 안전하게 만든 뒤(별표는 안 건드림), 볼드·줄바꿈만 최소한으로 변환한다.
  // 용어 툴팁은 본문에서 같은 문자열을 찾아 감싸는 방식이라, 용어에 마크다운 기호가
  // 한 글자라도 붙어 있으면(예: "횡적 이동**") 본문의 "횡적 이동"과 절대 매칭되지
  // 않는다. analyze.js의 파싱을 고쳤지만 분석 결과 캐시가 90일이라 이미 저장된 항목은
  // 그대로 남으므로, 표시 직전에 한 번 더 다듬고 형태가 깨진 건 버린다. 규칙은 서버의
  // normalizeGlossaryTerm/isUsableGlossaryTerm과 같다.
  const GLOSSARY_TERM_MAX_CHARS = 40;

  function normalizeGlossary(glossary) {
    const cleaned = {};
    if (!glossary || typeof glossary !== "object") return cleaned;
    Object.keys(glossary).forEach((rawTerm) => {
      const def = glossary[rawTerm];
      if (typeof def !== "string" || !def.trim()) return;
      const term = String(rawTerm)
        .replace(/^(?:[-•]\s*|\*\s+)/, "")
        .replace(/^\d+[.)]\s*/, "")
        .replace(/^[\s*_`~]+/, "")
        .replace(/[\s*_`~]+$/, "")
        .trim();
      if (!term || term.length > GLOSSARY_TERM_MAX_CHARS) return;
      if (/[\[\]]/.test(term) || /[.!?]$/.test(term) || /^\d+$/.test(term)) return;
      cleaned[term] = def.trim();
    });
    return cleaned;
  }

  function renderAnalysisText(value, glossary) {
    let html = esc(value)
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/\n/g, "<br>");

    const terms = normalizeGlossary(glossary);
    // 긴 용어부터 감싸야 짧은 용어가 긴 용어 안쪽을 먼저 먹지 않는다.
    Object.keys(terms)
      .sort((a, b) => b.length - a.length)
      .forEach((term) => {
        html = wrapGlossaryTerm(html, term, terms[term]);
      });
    return html;
  }

  function wrapGlossaryTerm(html, term, def) {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString("<div>" + html + "</div>", "text/html");
      const root = doc.body.firstChild;

      function walk(node) {
        if (node.nodeType === 3) {
          const text = node.nodeValue;
          const idx = text.toLowerCase().indexOf(term.toLowerCase());
          if (idx >= 0 && node.parentNode.className !== "glossary-term") {
            const beforeText = text.slice(0, idx);
            const matchedText = text.slice(idx, idx + term.length);
            const afterText = text.slice(idx + term.length);

            const beforeNode = document.createTextNode(beforeText);
            const spanNode = document.createElement("span");
            spanNode.className = "glossary-term";
            spanNode.setAttribute("data-tooltip", def);
            spanNode.textContent = matchedText;
            const afterNode = document.createTextNode(afterText);

            const parent = node.parentNode;
            parent.insertBefore(beforeNode, node);
            parent.insertBefore(spanNode, node);
            parent.insertBefore(afterNode, node);
            parent.removeChild(node);

            walk(afterNode);
          }
        } else if (node.nodeType === 1 && node.className !== "glossary-term") {
          const children = Array.from(node.childNodes);
          children.forEach(walk);
        }
      }

      walk(root);
      return root.innerHTML;
    } catch (e) {
      const escapedTerm = term.replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&");
      const regexSimple = new RegExp(`(${escapedTerm})`, "gi");
      return html.replace(regexSimple, `<span class="glossary-term" data-tooltip="${esc(def)}">$1</span>`);
    }
  }

  function fmtDate(iso) {
    if (!iso) return "";
    try {
      const d = new Date(iso);
      return d.toLocaleString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
    } catch (e) {
      return iso;
    }
  }

  async function loadPeriod(period) {
    if (state.cache[period]) return state.cache[period];
    const res = await fetch("data/" + period + "-latest.json", { cache: "no-cache" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const payload = await res.json();
    state.cache[period] = payload;
    return payload;
  }

  // History 탭·검색은 기간(daily/weekly)과 무관한 별도 누적 인덱스를 쓴다.
  async function loadSearchIndex() {
    if (state.searchIndex) return state.searchIndex;
    try {
      const res = await fetch("data/search-index.json", { cache: "no-cache" });
      state.searchIndex = res.ok ? await res.json() : [];
    } catch (error) {
      state.searchIndex = [];
    }
    return state.searchIndex;
  }

  // 인사이트(심층분석 결과) 히스토리를 서버(Redis 공유 목록)에서 불러온다 — 모든
  // 방문자가 같은 목록을 본다. 페이지 로드 시 한 번만 불러오고, 이후 새로 분석한
  // 항목은 runAnalysis()가 로컬에 unshift해서 새로고침 전까지 즉시 반영한다.
  async function loadInsights() {
    if (state.insightHistoryLoaded) return state.insightHistory;
    try {
      const res = await fetch(INSIGHTS_URL, { cache: "no-cache" });
      const data = res.ok ? await res.json() : { insights: [] };
      state.insightHistory = data.insights || [];
    } catch (error) {
      state.insightHistory = [];
    }
    state.insightHistoryLoaded = true;
    return state.insightHistory;
  }

  // "최근 화제 키워드" 사이드 위젯용 — publish_trending_titles.py가 홈 PC
  // 스케줄러(30분 주기)에서 이 파일을 갱신한다. 대시보드 자체 배포 주기(하루 1번)와
  // 무관하게 이 정적 파일만 더 자주 바뀌므로 no-cache로 매번 새로 받는다.
  async function loadTrending() {
    if (state.trending) return state.trending;
    try {
      const res = await fetch("data/trending.json", { cache: "no-cache" });
      state.trending = res.ok ? await res.json() : { items: [] };
    } catch (error) {
      state.trending = { items: [] };
    }
    return state.trending;
  }

  // ===== Renderers =====
  const INFO_CATEGORY_TOP_N = 5;

  function renderStatStrip(stats) {
    const tiles = [
      { label: "총 건수", value: stats.total, cls: "" },
      { label: "P1 · 긴급", value: stats.p1, cls: "p1", title: "P1: 실제 악용 중이며 자사 자산과 관련된 건 (최우선 대응 필요)" },
      { label: "P2 · 주의", value: stats.p2, cls: "p2", title: "P2: 실제 악용 중이거나, PoC 공개·중대한 영향에 자사 자산이 걸린 건" },
    ];
    // "기타"는 상위 N개 후보에서 빼고 항상 오버플로 몫과 합쳐 "기타" 타일 하나로만
    // 보여준다 — 카테고리 값 "기타"와 상위 N개 밖으로 밀린 "그 외"가 따로 뜨면
    // 사실상 같은 뜻의 타일이 두 개로 보여 헷갈린다.
    const etcCount = (stats.info_by_category || {})["기타"] || 0;
    const categoryEntries = Object.entries(stats.info_by_category || {}).filter(([name]) => name !== "기타");
    categoryEntries.slice(0, INFO_CATEGORY_TOP_N).forEach(([name, count]) => {
      tiles.push({ label: name, value: count, cls: "" });
    });
    const restCount = etcCount + categoryEntries.slice(INFO_CATEGORY_TOP_N).reduce((sum, [, count]) => sum + count, 0);
    if (restCount > 0) tiles.push({ label: "기타", value: restCount, cls: "" });
    return (
      '<div class="stat-strip">' +
      tiles.map((t) =>
        '<div class="stat-tile ' + t.cls + '"' + (t.title ? ' title="' + esc(t.title) + '"' : "") + '><div class="num">' + esc(t.value) + '</div><div class="label">' + esc(t.label) + "</div></div>"
      ).join("") +
      "</div>"
    );
  }

  function renderLevelBadge(level) {
    if (level !== "P1" && level !== "P2") return "";
    return '<span class="level-badge ' + level + '">' + level + "</span>";
  }

  // ===== Pagination (국내/해외, History 검색·월별 아카이브에서 공용) =====
  function paginate(items, page) {
    const totalPages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
    const clamped = Math.min(Math.max(1, page), totalPages);
    const start = (clamped - 1) * PAGE_SIZE;
    return { pageItems: items.slice(start, start + PAGE_SIZE), page: clamped, totalPages: totalPages };
  }

  function renderPagination(pageKey, page, totalPages) {
    if (totalPages <= 1) return "";
    let buttons = "";
    for (let p = 1; p <= totalPages; p++) {
      buttons +=
        '<button type="button" class="page-btn' + (p === page ? " is-active" : "") + '" data-page-key="' +
        esc(pageKey) + '" data-page="' + p + '">' + p + "</button>";
    }
    return '<div class="pagination">' + buttons + "</div>";
  }

  function insightEntryFor(ref) {
    return state.insightHistory.find((entry) => entry.ref === ref);
  }

  // 심층분석 버튼 — opts.analyzable로 켜진 곳(추천기사 탭)에서만 표시된다. 결과는
  // 이 자리에 바로 안 보여주고 인사이트 드로어(오른쪽 위 토글 버튼)로 보낸다 —
  // 이미 분석된 기사는 버튼 대신 짧은 확인 문구만 남긴다(재클릭·중복 히스토리 방지).
  // event.ref가 없으면(구버전 payload 캐시 등) 버튼 자체를 안 만든다.
  function renderAnalyzeBox(event) {
    if (!event.ref) return "";
    if (insightEntryFor(event.ref)) {
      return '<div class="analyze-box analyze-done">✓ 인사이트에서 확인 가능</div>';
    }
    return (
      '<div class="analyze-box" data-ref="' + esc(event.ref) + '" data-url="' + esc(event.url || "") +
      '" data-title="' + esc(event.title || "") + '" data-source-label="' + esc(event.source_label || event.source || "") +
      '" data-category="' + esc(event.category || "") + '">' +
      '<button type="button" class="analyze-btn">심층분석 보기</button>' +
      '<div class="analyze-result"></div>' +
      "</div>"
    );
  }

  function renderItem(event, opts) {
    opts = opts || {};
    const metaBits = [];
    if (event.category) metaBits.push(esc(event.category));
    if (event.published_at) metaBits.push(esc(fmtDate(event.published_at)));
    const href = event.url ? esc(event.url) : "#";
    return (
      '<div class="item">' +
      '<div class="item-top">' +
      (opts.hideSource ? "" : '<span class="item-source">' + esc(event.source_label || event.source || "") + "</span>") +
      renderLevelBadge(event.level) +
      "</div>" +
      '<div class="item-title"><a href="' + href + '" target="_blank" rel="noopener">' + esc(event.title) + "</a></div>" +
      (metaBits.length ? '<div class="item-meta">' + metaBits.map((b) => "<span>" + b + "</span>").join("") + "</div>" : "") +
      ((event.reason_bits || []).length
        ? '<div class="item-reason">' + event.reason_bits.map((b) => '<span class="pill">' + esc(b) + "</span>").join("") + "</div>"
        : "") +
      (event.summary ? '<div class="item-summary">' + esc(event.summary) + "</div>" : "") +
      (opts.analyzable ? renderAnalyzeBox(event) : "") +
      "</div>"
    );
  }

  function renderItemList(events, opts) {
    if (!events || !events.length) {
      return '<div class="empty-state">해당 없음</div>';
    }
    return '<div class="item-list">' + events.map((e) => renderItem(e, opts)).join("") + "</div>";
  }

  // 추천기사(trend_reads)는 소스별 그룹핑 대신 score(importance_score) 내림차순 플랫
  // 리스트로 보여준다 — "이게 왜 추천됐는지"를 심층분석 클릭 전에도 바로 판단할 수 있게.
  function sortByScore(events) {
    return events.slice().sort((a, b) => (b.score || 0) - (a.score || 0));
  }

  function groupBySource(events) {
    const order = [];
    const groups = {};
    events.forEach((event) => {
      const key = event.source_label || event.source || "기타";
      if (!groups[key]) {
        groups[key] = [];
        order.push(key);
      }
      groups[key].push(event);
    });
    return order
      .map((key) => ({ source: key, items: groups[key] }))
      .sort((a, b) => b.items.length - a.items.length);
  }

  // pageKey를 주면 그 목록을 PAGE_SIZE 단위로 잘라서 보여주고 페이지 번호를 붙인다
  // (국내/해외 탭용) — 안 주면(추천기사 탭) 예전처럼 전부 보여준다. opts.analyzable를
  // 켜면(추천기사 탭) 각 항목에 심층분석 버튼이 붙는다.
  function renderBySource(events, pageKey, opts) {
    opts = opts || {};
    if (!events || !events.length) {
      return '<div class="empty-state">해당 없음</div>';
    }
    let items = events;
    let paginationHtml = "";
    if (pageKey) {
      const result = paginate(events, state.pages[pageKey] || 1);
      items = result.pageItems;
      paginationHtml = renderPagination(pageKey, result.page, result.totalPages);
    }
    const groupsHtml = groupBySource(items).map((group) =>
      '<div class="source-group">' +
      '<div class="source-group-head">' + esc(group.source) + ' <span class="count">' + group.items.length + '건</span></div>' +
      '<div class="item-list">' +
      group.items.map((e) => renderItem(e, { hideSource: true, analyzable: opts.analyzable })).join("") +
      "</div>" +
      "</div>"
    ).join("");
    return groupsHtml + paginationHtml;
  }

  function renderCveCard(card) {
    const levelCls = card.level ? "level-" + card.level : "";
    const bits = (card.severity_bits || []).map((b) => '<span class="pill">' + esc(b) + "</span>").join("");
    const links = (card.items || [])
      .map((item) => '<a href="' + esc(item.url || "#") + '" target="_blank" rel="noopener">' + esc(item.source_label) + "</a>")
      .join("");
    return (
      '<div class="cve-card ' + levelCls + '">' +
      '<div class="cve-card-head"><span>' + esc(card.cve) + "</span>" +
      '<span class="cve-card-sources">소스 ' + esc((card.sources || []).length) + "개: " + esc((card.sources || []).join(", ")) + "</span>" +
      "</div>" +
      (bits ? '<div class="cve-card-bits">' + bits + "</div>" : "") +
      (card.products && card.products.length ? '<div class="cve-card-summary">영향: ' + esc(card.products.join(", ")) + "</div>" : "") +
      (card.remediation ? '<div class="cve-card-summary">조치: ' + esc(card.remediation) + (card.due_date ? " (기한 " + esc(card.due_date) + ")" : "") + "</div>" : "") +
      (card.summary ? '<div class="cve-card-summary">' + esc(card.summary) + "</div>" : "") +
      (links ? '<div class="cve-card-links">' + links + "</div>" : "") +
      "</div>"
    );
  }

  // ===== 통계 탭 =====
  const WEEKLY_TREND_GROUP_LABELS = [
    ["actors", "위협 행위자"],
    ["malware", "악성코드"],
    ["techniques", "ATT&CK 기법"],
    ["categories", "기사 분류"],
  ]; // "자산 매칭"은 자사 보유 자산/제품명이라 대시보드 payload 자체에서 이미 제외됨

  function renderDistTiles(entries) {
    if (!entries.length) return '<div class="empty-state">해당 없음</div>';
    return (
      '<div class="stat-strip">' +
      entries.map(([name, count]) =>
        '<div class="stat-tile"><div class="num">' + esc(count) + '</div><div class="label">' + esc(name) + "</div></div>"
      ).join("") +
      "</div>"
    );
  }

  function formatWeeklyTrendItem(key, item) {
    if (key === "categories") {
      return esc(item.name) + " 비중 " + item.previous_share.toFixed(0) + "%→" + item.share.toFixed(0) + "% (+" + item.delta.toFixed(0) + "%p)";
    }
    return item.previous === 0
      ? esc(item.name) + " " + item.count + "건 (신규)"
      : esc(item.name) + " " + item.count + "건 (전주 " + item.previous + "건, +" + item.delta + ")";
  }

  function renderWeeklyTrendSection(weeklyTrends) {
    if (!weeklyTrends) return ""; // 주간 리포트에만 존재 — 일간에서는 섹션 자체를 안 보여줌
    const groupsHtml = WEEKLY_TREND_GROUP_LABELS.map(([key, label]) => {
      const items = weeklyTrends[key] || [];
      if (!items.length) return "";
      return (
        '<div class="trend-group"><span class="trend-group-label">' + esc(label) + "</span>" +
        items.map((item) => '<span class="pill">' + formatWeeklyTrendItem(key, item) + "</span>").join("") +
        "</div>"
      );
    }).filter(Boolean).join("");

    return (
      '<div class="section"><div class="section-title">주간 동향 <span class="count">전주 대비 급증</span></div>' +
      (groupsHtml || '<div class="empty-state">전주 대비 특이 변화 없음</div>') +
      "</div>"
    );
  }

  function renderRankList(items) {
    if (!items.length) return '<div class="empty-state">해당 없음</div>';
    return (
      '<div class="rank-list">' +
      items.map(([name, count], idx) =>
        '<div class="rank-item"><span class="rank-num">' + (idx + 1) + '</span>' +
        '<span class="rank-name">' + esc(name) + '</span>' +
        '<span class="rank-count">' + esc(count) + "건</span></div>"
      ).join("") +
      "</div>"
    );
  }

  function renderStatsTab(payload) {
    const stats = payload.stats || {};
    let html = "";

    html +=
      '<div class="section"><div class="section-title">카테고리별 분포 <span class="count">' +
      Object.keys(stats.info_by_category || {}).length + "종</span></div>" +
      renderDistTiles(Object.entries(stats.info_by_category || {})) +
      "</div>";

    html +=
      '<div class="section"><div class="section-title">소스별 분포 <span class="count">' +
      Object.keys(stats.by_source || {}).length + "개</span></div>" +
      renderDistTiles(Object.entries(stats.by_source || {})) +
      "</div>";

    html += renderWeeklyTrendSection(payload.weekly_trends);

    [["top_actors", "TOP 위협 행위자"], ["top_malware", "TOP 악성코드"], ["top_cves", "TOP CVE"]].forEach(([key, label]) => {
      const items = stats[key] || [];
      html +=
        '<div class="section"><div class="section-title">' + esc(label) + ' <span class="count">' + items.length + "건</span></div>" +
        renderRankList(items) +
        "</div>";
    });

    return html;
  }

  // ===== History tab (검색 + 월별 아카이브) =====
  function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // esc()로 이스케이프된(HTML-safe) 텍스트 위에서 검색어만 <mark>로 감싼다 —
  // 태그·속성이 없는 순수 텍스트라 이스케이프 후에 처리해도 안전하다.
  function highlightEscaped(escapedText, words) {
    if (!words.length) return escapedText;
    const pattern = new RegExp("(" + words.map(escapeRegExp).join("|") + ")", "gi");
    return escapedText.replace(pattern, "<mark>$1</mark>");
  }

  // "오늘의 키워드"는 AI가 총평을 쓸 때 자기 배경지식으로 "Sapphire Sleet
  // (Lazarus Group)"처럼 괄호 별칭을 덧붙이는 경우가 있는데, 실제 기사 본문엔
  // 그 별칭이 한 번도 안 나오는 경우가 많다(그룹명 하나로만 불림). 모든 단어를
  // AND로 찾는 지금 방식이라 괄호 안 단어가 없으면 전체가 결과 없음으로 빠진다
  // — 그래서 괄호로 묶인 부분은 검색어에서 통째로 제외한다. 남은 단어 앞뒤에
  // 괄호가 그대로 붙어 나오는 경우("(lazarus", "group)")도 문장부호를 떼어낸다.
  function queryWords(query) {
    return query
      .replace(/\([^)]*\)/g, " ")
      .trim()
      .toLowerCase()
      .split(/\s+/)
      .map((word) => word.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, ""))
      .filter(Boolean);
  }

  function renderHistoryItem(entry, words) {
    words = words || [];
    const href = entry.url ? esc(entry.url) : "#";
    const metaBits = [esc(entry.date)];
    if (entry.category) metaBits.push(esc(entry.category));
    return (
      '<div class="item">' +
      '<div class="item-top">' +
      '<span class="item-source">' + esc(entry.source_label || "") + "</span>" +
      renderLevelBadge(entry.level) +
      "</div>" +
      '<div class="item-title"><a href="' + href + '" target="_blank" rel="noopener">' +
      highlightEscaped(esc(entry.title), words) + "</a></div>" +
      '<div class="item-meta">' + metaBits.map((b) => "<span>" + b + "</span>").join("") + "</div>" +
      (entry.summary ? '<div class="item-summary">' + highlightEscaped(esc(entry.summary), words) + "</div>" : "") +
      "</div>"
    );
  }

  // AND 매칭: 입력한 모든 단어가 (순서·인접 무관하게) 어딘가에 다 있어야 매칭.
  // 제목에서 매칭되면 요약/카테고리/소스명에서만 매칭된 것보다 높은 점수를 준다.
  function matchScore(entry, words) {
    const title = (entry.title || "").toLowerCase();
    const rest = [entry.summary, entry.category, entry.source_label].join(" ").toLowerCase();
    let score = 0;
    for (const word of words) {
      const inTitle = title.indexOf(word) !== -1;
      const inRest = rest.indexOf(word) !== -1;
      if (!inTitle && !inRest) return -1;
      score += inTitle ? 3 : 1;
    }
    return score;
  }

  function renderHistorySearchResults(index, query) {
    const words = queryWords(query);
    const scored = index
      .map((entry) => ({ entry: entry, score: matchScore(entry, words) }))
      .filter((s) => s.score >= 0)
      .sort((a, b) => b.score - a.score || (b.entry.date || "").localeCompare(a.entry.date || ""));

    if (!scored.length) {
      return (
        '<div class="section"><div class="section-title">검색 결과 <span class="count">0건</span></div>' +
        '<div class="empty-state">"' + esc(query) + '"에 대한 결과가 없습니다.</div></div>'
      );
    }
    const result = paginate(scored, state.pages["history-search"] || 1);
    return (
      '<div class="section"><div class="section-title">검색 결과 <span class="count">' + scored.length + '건</span></div>' +
      '<div class="item-list">' + result.pageItems.map((s) => renderHistoryItem(s.entry, words)).join("") + "</div>" +
      renderPagination("history-search", result.page, result.totalPages) +
      "</div>"
    );
  }

  function renderHistoryBrowser(index) {
    if (!index.length) {
      return '<div class="empty-state">과거 데이터가 아직 없습니다.</div>';
    }
    const groups = {};
    const order = [];
    index.forEach((entry) => {
      const month = (entry.date || "").slice(0, 7); // "YYYY-MM"
      if (!groups[month]) {
        groups[month] = [];
        order.push(month);
      }
      groups[month].push(entry);
    });
    order.sort().reverse();

    return order.map((month, idx) => {
      const items = groups[month];
      const pageKey = "history-month-" + month;
      const result = paginate(items, state.pages[pageKey] || 1);
      return (
        '<div class="section history-month' + (idx === 0 ? " is-open" : "") + '" data-month="' + esc(month) + '">' +
        '<button type="button" class="history-month-toggle">' + esc(month) +
        ' <span class="count">' + items.length + "건</span></button>" +
        '<div class="history-month-body">' +
        '<div class="item-list">' + result.pageItems.map((e) => renderHistoryItem(e)).join("") + "</div>" +
        renderPagination(pageKey, result.page, result.totalPages) +
        "</div>" +
        "</div>"
      );
    }).join("");
  }

  function renderHistorySection() {
    if (state.searchIndex === null) {
      loadSearchIndex().then(() => {
        if (state.tab === "history") render(state.cache[state.period]);
      });
      return '<div class="loading">불러오는 중…</div>';
    }
    const query = (state.query || "").trim().toLowerCase();
    return query ? renderHistorySearchResults(state.searchIndex, query) : renderHistoryBrowser(state.searchIndex);
  }

  // 탭별로 필요한 데이터만 추려서 반환. 읽을만한 동향(trend_reads)은 요약/국내/해외에
  // 섞이지 않고 recommended 탭에서만 다룬다 — 같은 기사가 여러 탭에 중복 노출되지 않게.
  function tabData(payload) {
    if (state.tab === "domestic") return { highlights: payload.domestic.highlights || [] };
    if (state.tab === "overseas") return { highlights: payload.overseas.highlights || [] };
    if (state.tab === "recommended") {
      return { trend_reads: sortByScore((payload.domestic.trend_reads || []).concat(payload.overseas.trend_reads || [])) };
    }
    if (state.tab === "cve") return { cards: payload.cards || [] };
    if (state.tab === "stats" || state.tab === "history" || state.tab === "insight") return {};
    return { highlights: (payload.domestic.highlights || []).concat(payload.overseas.highlights || []) };
  }

  // publish_trending_titles.py가 이전 발행분과 비교해 계산해둔 순위 변동을 그대로
  // 표시한다 — 새 항목은 NEW, 오르면 ▲n, 내리면 ▼n, 안 바뀌면 -.
  function renderTrendingChange(item) {
    if (item.status === "new") return '<span class="trending-change trending-new">NEW</span>';
    if (item.status === "up") return '<span class="trending-change trending-up">▲' + esc(item.delta) + "</span>";
    if (item.status === "down") return '<span class="trending-change trending-down">▼' + esc(item.delta) + "</span>";
    return '<span class="trending-change trending-same">-</span>';
  }

  // 최근 LOOKBACK_DAYS일간 제목·태깅된 개체(위협 행위자·
  // 악성코드·제품명)에서 반복된 것 상위 10개 — publish_trending_titles.py(홈 PC에서
  // 30분 주기 스케줄)가 갱신하는 data/trending.json을 그대로 보여준다. 기본은
  // 접혀 있고 헤더를 누르면 펼쳐진다. 항목 클릭은 "오늘의 키워드"와 같은 방식으로
  // History 검색으로 이어진다.
  function renderTrendingSidebar() {
    const items = (state.trending && state.trending.items) || [];
    if (!items.length) {
      $trendingSidebar.innerHTML = "";
      return;
    }
    $trendingSidebar.innerHTML =
      '<button type="button" class="trending-header" id="trending-toggle">' +
      "<span>🔥 최근 화제 키워드</span><span class=\"trending-caret\">▾</span>" +
      "</button>" +
      '<div class="trending-body"><div class="rank-list">' +
      items.map((item, idx) =>
        '<button type="button" class="rank-item trending-item-btn" data-term="' + esc(item.term) + '">' +
        '<span class="rank-num">' + (idx + 1) + "</span>" +
        '<span class="rank-name">' + esc(item.term) + "</span>" +
        renderTrendingChange(item) +
        "</button>"
      ).join("") +
      "</div></div>";

    document.getElementById("trending-toggle").addEventListener("click", () => {
      $trendingSidebar.classList.toggle("is-open");
    });

    $trendingSidebar.querySelectorAll(".trending-item-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const term = btn.dataset.term;
        $searchInput.value = term;
        state.query = term;
        state.pages["history-search"] = 1;
        state.tab = "history";
        render(state.cache[state.period]);
        logSearch(term);
      });
    });
  }

  // AI가 리포트 생성 시 하루 한 번 뽑아준 고유명사(위협 행위자·멀웨어명·CVE 등) 태그.
  // 클릭하면 검색으로 바로 이어진다 — 넓은 화면에서 .page 좌우 여백을 쓰는 사이드바.
  function renderKeywordSidebar(payload) {
    const keywords = payload.keywords || [];
    if (!keywords.length) {
      $keywordSidebar.innerHTML = "";
      return;
    }
    const label = payload.period === "weekly" ? "이번 주 키워드" : "오늘의 키워드";
    $keywordSidebar.innerHTML =
      '<div class="keyword-sidebar-title">' + esc(label) + "</div>" +
      '<div class="keyword-tag-list">' +
      keywords.map((kw) =>
        '<button type="button" class="keyword-tag" data-keyword="' + esc(kw) + '">' + esc(kw) + "</button>"
      ).join("") +
      "</div>";

    $keywordSidebar.querySelectorAll(".keyword-tag").forEach((btn) => {
      btn.addEventListener("click", () => {
        const keyword = btn.dataset.keyword;
        $searchInput.value = keyword;
        state.query = keyword;
        state.pages["history-search"] = 1;
        state.tab = "history";
        render(payload);
        logSearch(keyword); // 클릭도 검색으로 취급 — 디바운스 기다리지 않고 바로 기록
      });
    });
  }

  // 추천기사 탭과 같은 데이터를 넓은 화면에서 사이드바로도 보여준다(탭은 그대로 유지 —
  // 좁은 화면 사용자는 탭으로 접근). 출처·제목만 보이고 클릭하면 요약이 펼쳐진다.
  function renderTrendSidebar(payload) {
    const items = sortByScore((payload.domestic.trend_reads || []).concat(payload.overseas.trend_reads || []));
    if (!items.length) {
      $trendSidebar.innerHTML = "";
      return;
    }
    $trendSidebar.innerHTML =
      '<div class="trend-sidebar-title">추천 기사 <span class="count">' + items.length + '건</span></div>' +
      '<div class="trend-list">' +
      items.map((item, idx) =>
        '<div class="trend-item" data-idx="' + idx + '">' +
        '<button type="button" class="trend-item-head">' +
        '<span class="trend-item-source">' + esc(item.source_label || "") + "</span>" +
        '<span class="trend-item-title">' + esc(item.title) + "</span>" +
        "</button>" +
        (item.summary || item.url || (item.reason_bits || []).length
          ? '<div class="trend-item-body">' +
            ((item.reason_bits || []).length
              ? '<div class="item-reason">' + item.reason_bits.map((b) => '<span class="pill">' + esc(b) + "</span>").join("") + "</div>"
              : "") +
            (item.summary ? '<p class="item-summary">' + esc(item.summary) + "</p>" : "") +
            (item.url ? '<a href="' + esc(item.url) + '" target="_blank" rel="noopener" class="trend-item-link">기사 보기</a>' : "") +
            "</div>"
          : "") +
        "</div>"
      ).join("") +
      "</div>";

    $trendSidebar.querySelectorAll(".trend-item-head").forEach((btn) => {
      btn.addEventListener("click", () => {
        btn.closest(".trend-item").classList.toggle("is-open");
      });
    });
  }

  // 인사이트 드로어의 목록 — 각 항목은 아코디언이 아니라 클릭하면 전체화면
  // 상세 보기(openInsightDetail)를 여는 버튼이다. 리포트가 점점 길어질 예정이라
  // 드로어(380px 폭) 안에서 펼치는 대신 화면 전체를 쓰는 별도 뷰로 보여준다.
  function renderInsightEntries(items) {
    return (
      '<div class="insight-list">' +
      items.map((entry, idx) =>
        '<button type="button" class="insight-list-item" data-idx="' + idx + '">' +
        '<span class="insight-list-top">' +
        '<span class="insight-list-source">' + esc(entry.source_label || "") + "</span>" +
        (entry.category ? '<span class="pill">' + esc(entry.category) + "</span>" : "") +
        "</span>" +
        '<span class="insight-list-title">' + esc(entry.title) + "</span>" +
        "</button>"
      ).join("") +
      "</div>"
    );
  }

  // analysis 텍스트를 "[섹션명]" 헤더 기준으로 쪼갠다 — 위협형/비위협형 템플릿의
  // 섹션 이름이 달라도(예: [기술적 세부사항] vs [주요 내용]) 헤더 패턴만 보고 파싱하므로
  // 프롬프트가 바뀌어도 그대로 동작한다. 헤더가 하나도 없으면(모델이 형식을 안 따른
  // 경우) 빈 배열을 반환해 호출부가 통짜 텍스트로 폴백하게 한다.
  //
  // 헤더 줄이 "[핵심 요약]"처럼 단독으로 오는 경우와 "[핵심 요약] 실제 문장..."처럼
  // 내용이 같은 줄에 바로 붙는 경우를 둘 다 인식한다 — 프롬프트에 "[섹션명] 설명"
  // 형태로 지시를 써둔 걸 모델이 출력 형식으로도 그대로 따라할 때가 있어서, 단독
  // 줄만 헤더로 인정하면 그 줄이 아직 안 열린 섹션(current=null)에 걸려 통째로
  // 버려지는 문제가 있었다.
  function parseAnalysisSections(text) {
    const lines = (text || "").split("\n");
    const sections = [];
    let current = null;
    lines.forEach((line) => {
      const match = line.match(/^\s*\[(.+?)\]\s*(.*)$/);
      if (match) {
        current = { title: match[1].trim(), lines: [] };
        if (match[2].trim()) current.lines.push(match[2].trim());
        sections.push(current);
      } else if (current) {
        current.lines.push(line);
      }
    });
    return sections
      .map((s) => ({ title: s.title, content: s.lines.join("\n").trim() }))
      .filter((s) => s.content);
  }

  // 분석 텍스트 섹션 + MITRE + IOC + 관련 링크를 모두 같은 카드 그리드의 항목으로
  // 만든다 — 예전처럼 텍스트 블록 하나 아래에 MITRE/IOC/링크를 따로 쌓으면 세로로
  // 계속 늘어나 스크롤이 그대로였다. 짧은 카드(핵심 요약·CVSS·MITRE·IOC·링크)는
  // 나란히, 번호 목록이 있거나 긴 텍스트 섹션(기술적 세부사항·영향 범위 등)만 폭
  // 전체를 쓴다.
  function buildDetailCards(entry) {
    const cards = parseAnalysisSections(entry.analysis || "").map((s) => ({
      title: s.title,
      bodyHtml: renderAnalysisText(s.content, entry.glossary),
      wide: s.content.length > 150 || /^\d+\.\s/.test(s.content),
    }));

    if ((entry.attack_techniques || []).length) {
      cards.push({
        title: "MITRE ATT&CK 기법",
        bodyHtml: entry.attack_techniques.map((t) => '<span class="pill">' + esc(t) + "</span>").join(""),
        wide: false,
      });
    }

    if ((entry.iocs || []).length) {
      const shown = entry.iocs.slice(0, IOC_DISPLAY_LIMIT);
      cards.push({
        title: "본문 내 IOC",
        bodyHtml:
          '<ul class="ioc-list">' +
          shown.map((ioc) =>
            '<li><span class="ioc-type">' + esc((ioc.type || "").toUpperCase()) + '</span>' + esc(ioc.value) + "</li>"
          ).join("") +
          "</ul>" +
          (entry.iocs.length > IOC_DISPLAY_LIMIT
            ? '<div class="analyze-iocs-more">외 ' + (entry.iocs.length - IOC_DISPLAY_LIMIT) + "건 더 있음</div>"
            : ""),
        wide: false,
      });
    }

    if ((entry.links || []).length) {
      cards.push({
        title: "원문 내 관련 링크",
        bodyHtml:
          '<ul class="links-list">' +
          entry.links.map((link) =>
            '<li><a href="' + esc(link.url) + '" target="_blank" rel="noopener">' + esc(link.text) + "</a></li>"
          ).join("") +
          "</ul>",
        wide: false,
      });
    }

    return cards;
  }

  function renderDetailCards(cards) {
    if (!cards.length) return "";
    return (
      '<div class="analysis-grid">' +
      cards.map((c) =>
        '<div class="analysis-card' + (c.wide ? " wide" : "") + '">' +
        (c.title ? '<div class="analysis-card-title">' + esc(c.title) + "</div>" : "") +
        '<div class="analysis-card-body">' + c.bodyHtml + "</div>" +
        "</div>"
      ).join("") +
      "</div>"
    );
  }

  function renderInsightDetailBody(entry) {
    const cards = buildDetailCards(entry);
    return (
      '<div class="insight-detail-top">' +
      '<span class="insight-detail-source">' + esc(entry.source_label || "") + "</span>" +
      (entry.category ? '<span class="pill">' + esc(entry.category) + "</span>" : "") +
      "</div>" +
      '<h3 class="insight-detail-title">' + esc(entry.title) + "</h3>" +
      (cards.length
        ? renderDetailCards(cards)
        : '<div class="analyze-text">' + renderAnalysisText(entry.analysis || "", entry.glossary) + "</div>") +
      (entry.url ? '<a href="' + esc(entry.url) + '" target="_blank" rel="noopener" class="trend-item-link">기사 보기</a>' : "")
    );
  }

  // 목록에서 항목을 클릭하면 드로어/본문을 가리고 그 항목만 전체화면으로 보여준다
  // (페이지 이동 없음 — 순수 표시 전환). 뒤로가기(← 목록)는 드로어로, 닫기(✕)는
  // 완전히 닫는다.
  function openInsightDetail(idx) {
    const entry = state.insightHistory[idx];
    if (!entry) return;
    state.insightDetailIdx = idx;
    $insightDetailBody.innerHTML = renderInsightDetailBody(entry);
    $insightDetailReanalyze.disabled = false;
    $insightDetailReanalyze.textContent = "재분석";
    $insightDetail.classList.add("is-open");
  }

  function closeInsightDetail() {
    $insightDetail.classList.remove("is-open");
  }

  function bindInsightListClicks(container) {
    container.querySelectorAll(".insight-list-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        openInsightDetail(parseInt(btn.dataset.idx, 10));
      });
    });
  }

  // 인사이트 접근 경로는 두 가지다: 상단 ≡ 토글 드로어(화면 폭과 무관하게 항상
  // 접근 가능한 "빠른 확인용" — 최근 INSIGHT_DRAWER_LIMIT건만), History 옆 인사이트
  // 탭(전체 이력). 드로어에 전체를 다 넣으면 쌓일수록(서버 최대 300건) 계속
  // 길어지므로 최근 것만 보이고, 더 있으면 탭으로 넘어가는 링크를 둔다.
  // loadInsights() 완료 시, runAnalysis()가 새 분석을 unshift한 직후 다시 그린다.
  function renderInsightDrawer() {
    const count = state.insightHistory.length;
    $insightBadge.hidden = count === 0;
    $insightBadge.textContent = count;
    $insightDrawerCount.textContent = count ? count + "건" : "";

    if (!count) {
      $insightDrawerBody.innerHTML = '<div class="empty-state">아직 분석한 기사가 없습니다. 추천기사 탭에서 심층분석 버튼을 눌러보세요.</div>';
      return;
    }

    const recent = state.insightHistory.slice(0, INSIGHT_DRAWER_LIMIT);
    $insightDrawerBody.innerHTML =
      renderInsightEntries(recent) +
      (count > INSIGHT_DRAWER_LIMIT
        ? '<button type="button" id="insight-drawer-see-all" class="insight-drawer-see-all">전체 ' + count + "건 보기(인사이트 탭) →</button>"
        : "");

    bindInsightListClicks($insightDrawerBody);

    const seeAllBtn = document.getElementById("insight-drawer-see-all");
    if (seeAllBtn) {
      seeAllBtn.addEventListener("click", () => {
        $insightDrawer.classList.remove("is-open");
        state.tab = "insight";
        render(state.cache[state.period]);
      });
    }
  }

  function render(payload) {
    // 기간이 바뀌면 이전 탭이 새 기간에 없을 수 있다(예: 주간 "통계" 탭 상태에서 일간으로
    // 전환) — 그럴 땐 요약 탭으로 되돌린다.
    if (!tabsForPeriod(payload.period).includes(state.tab)) {
      state.tab = "all";
    }
    const data = tabData(payload);
    $generatedAt.textContent = payload.title + " · 기간: " + payload.period_label + " · 생성: " + fmtDate(payload.generated_at);
    renderTrendingSidebar();
    renderKeywordSidebar(payload);
    renderTrendSidebar(payload);

    let html = "";
    html += renderStatStrip(payload.stats);

    html +=
      '<div class="region-tabs">' +
      tabsForPeriod(payload.period).map((t) => {
        const label = t === "all" ? "요약" : t === "domestic" ? "국내" : t === "overseas" ? "해외" :
          t === "stats" ? "통계" : t === "insight" ? "인사이트" :
          t === "cve" ? "CVE" : t === "history" ? "History" : "추천기사";
        const active = state.tab === t ? " is-active" : "";
        return '<button type="button" class="region-tab' + active + '" data-region="' + t + '">' + label + "</button>";
      }).join("") +
      "</div>";

    if (state.tab === "all") {
      // 요약 탭: AI 총평 + 핵심 취약점 + 주요뉴스(읽을만한 동향은 추천기사 탭으로 분리됨)
      if (payload.narrative) {
        html += '<div class="section"><div class="section-title">AI 분석</div><div class="narrative">' + esc(payload.narrative) + "</div></div>";
      }

      if (payload.cards && payload.cards.length) {
        html +=
          '<div class="section"><div class="section-title">핵심 취약점 <span class="count">복수 소스 교차 확인 · ' + payload.cards.length + '건</span></div>' +
          '<div class="card-list">' + payload.cards.map(renderCveCard).join("") + "</div></div>";
      }

      // 전체(캡 없음)는 일간=국내/해외 탭, 주간=History 탭 검색 몫 — 요약은 상위 N건만 보여주는 빠른 개요로 유지
      const allHighlights = data.highlights || [];
      const topHighlights = allHighlights.slice(0, SUMMARY_HIGHLIGHTS_LIMIT);
      const seeAllHint = payload.period === "weekly" ? "History 탭 검색에서" : "국내/해외 탭에서";
      html +=
        '<div class="section"><div class="section-title">주요 뉴스 <span class="count">상위 ' +
        topHighlights.length + "건 · 전체 " + allHighlights.length + '건은 ' + seeAllHint + '</span></div>' +
        renderItemList(topHighlights) +
        "</div>";
    } else if (state.tab === "recommended") {
      // 추천기사 탭: 읽을만한 동향(국내+해외 통합)을 우선순위(score) 내림차순 플랫 리스트로
      // 표시 + 심층분석 버튼. 소스별 그룹핑을 쓰지 않는 이유: 그룹핑은 그룹 노출 순서를
      // 소스당 건수로 정렬해(app.js groupBySource) 우선순위와 무관하게 뒤섞어 버린다.
      html +=
        '<div class="section"><div class="section-title">추천 기사 <span class="count">' + (data.trend_reads || []).length + "건</span></div>" +
        renderItemList(data.trend_reads, { analyzable: true }) +
        "</div>";
    } else if (state.tab === "cve") {
      // CVE 탭: 크로스소스 상관관계 카드(요약 탭의 "핵심 취약점"과 동일 데이터)만 모아서 표시
      const cards = data.cards || [];
      html +=
        '<div class="section"><div class="section-title">CVE <span class="count">복수 소스 교차 확인 · ' + cards.length + "건</span></div>" +
        (cards.length ? '<div class="card-list">' + cards.map(renderCveCard).join("") + "</div>" : '<div class="empty-state">해당 없음</div>') +
        "</div>";
    } else if (state.tab === "stats") {
      // 통계 탭: 카테고리·소스 전체 분포 + 주간 동향(전주 대비 급증, 주간 리포트에만 존재) + TOP 순위
      html += renderStatsTab(payload);
    } else if (state.tab === "insight") {
      // 인사이트 탭: 왼쪽 토글 드로어와 같은 데이터(state.insightHistory)를 History처럼
      // 탭에서도 훑어볼 수 있게 하는 별도 진입점 — 드로어 자체는 그대로 두고 추가된 것.
      html +=
        '<div class="section"><div class="section-title">인사이트 <span class="count">' +
        state.insightHistory.length + "건</span></div>" +
        (state.insightHistory.length
          ? renderInsightEntries(state.insightHistory)
          : '<div class="empty-state">아직 분석한 기사가 없습니다. 추천기사 탭에서 심층분석 버튼을 눌러보세요.</div>') +
        "</div>";
    } else if (state.tab === "history") {
      // History 탭: 검색어가 있으면 전체 기간 검색 결과, 없으면 월별 아카이브 브라우저
      html += renderHistorySection();
    } else if (state.tab === "domestic" || state.tab === "overseas") {
      // 국내/해외 탭(일간 전용): AI 총평·핵심 취약점 없이, 주요 뉴스만 소스별로 묶어서 나열(30건씩 페이지네이션)
      html +=
        '<div class="section"><div class="section-title">기사 <span class="count">' + (data.highlights || []).length + "건</span></div>" +
        renderBySource(data.highlights, "region-" + state.tab) +
        "</div>";
    }

    $app.innerHTML = html;

    $app.querySelectorAll(".region-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.tab = btn.dataset.region;
        if (state.tab !== "history") {
          state.query = "";
          $searchInput.value = "";
        }
        render(payload);
      });
    });

    $app.querySelectorAll(".analyze-btn").forEach((btn) => {
      btn.addEventListener("click", () => runAnalysis(btn));
    });

    bindInsightListClicks($app); // 인사이트 탭의 목록 항목 — 드로어와 같은 상세 보기를 연다

    $app.querySelectorAll(".history-month-toggle").forEach((btn) => {
      btn.addEventListener("click", () => {
        btn.closest(".history-month").classList.toggle("is-open");
      });
    });

    $app.querySelectorAll(".page-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.pages[btn.dataset.pageKey] = parseInt(btn.dataset.page, 10);
        render(payload);
      });
    });
  }

  async function refresh() {
    $app.innerHTML = "";
    $app.appendChild($loading);
    $loading.style.display = "block";
    try {
      const payload = await loadPeriod(state.period);
      loadSearchIndex(); // History 탭 클릭 전에 미리 받아둠 (fire-and-forget)
      // 인사이트 드로어는 별도 갱신(fire-and-forget). 다른 사람이 이미 분석해둔 기사의
      // "심층분석 보기" 버튼도 이걸 반영해야 하므로 본문도 다시 그린다.
      loadInsights().then(() => {
        renderInsightDrawer();
        render(payload);
      });
      loadTrending().then(renderTrendingSidebar); // 별도 정적 파일, fire-and-forget
      render(payload);
    } catch (error) {
      const tpl = document.getElementById("tpl-error");
      const node = tpl.content.cloneNode(true);
      node.querySelector(".empty-state-detail").textContent = String(error);
      $app.innerHTML = "";
      $app.appendChild(node);
      $generatedAt.textContent = "";
      console.error(error);
    }
  }

  function initPeriodSwitch() {
    document.querySelectorAll("#period-switch .segmented-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.dataset.period === state.period) return;
        document.querySelectorAll("#period-switch .segmented-btn").forEach((b) => {
          b.classList.toggle("is-active", b === btn);
          b.setAttribute("aria-selected", b === btn ? "true" : "false");
        });
        state.period = btn.dataset.period;
        refresh();
      });
    });
  }

  // analyze.js는 실패 원인을 error/reason으로 담아 보내지만, Vercel이 함수 자체를
  // 끊어버린 경우(504)엔 JSON이 아닌 HTML이 와서 data가 빈 객체가 된다 — 그때도
  // "다시 누르면 될 일"인지 아닌지는 알려줘야 해서 상태 코드로 문구를 나눈다.
  function analyzeErrorMessage(res, data) {
    if (data && data.error) return data.error;
    if (res.status === 504) return "분석 시간이 초과되었습니다. 잠시 후 다시 시도해주세요.";
    if (res.status === 429) return "요청이 많습니다. 잠시 후 다시 시도해주세요.";
    return "분석에 실패했습니다.";
  }

  // 화면에는 사람이 읽을 문구만 보여주고, 어느 모델이 몇 초 만에 무슨 오류로 끝났는지는
  // 콘솔로 흘린다 — 사용자에게 보여줄 내용은 아니지만, 원인을 물어볼 때 이게 있으면
  // 배포 로그를 열지 않고도 답이 나온다.
  function logAnalyzeFailure(res, data) {
    console.warn(
      "[analyze] " + res.status + " " + ((data && data.reason) || "") + " " + ((data && data.detail) || ""),
      (data && data.diagnostics) || {}
    );
  }

  // "심층분석 보기" 버튼 클릭 시 analyze.js를 호출한다. 서버가 캐시·요청 제한을
  // 관리하므로 여기서는 로딩/에러 표시만 신경 쓰면 된다. 성공하면 이 자리에 결과를
  // 바로 안 보여주고 insightHistory에 넣은 뒤 재렌더링한다 — 결과는 오른쪽 위
  // "인사이트" 토글 드로어에서 확인(버튼도 그때 "확인 가능" 문구로 바뀐다).
  async function runAnalysis(btn) {
    const box = btn.closest(".analyze-box");
    const resultEl = box.querySelector(".analyze-result");
    const requestBody = {
      ref: box.dataset.ref,
      url: box.dataset.url,
      title: box.dataset.title,
      source_label: box.dataset.sourceLabel,
      category: box.dataset.category,
    };

    btn.disabled = true;
    btn.textContent = "분석 중…";
    resultEl.innerHTML = "";

    let res, data;
    try {
      res = await fetch(ANALYZE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });
      data = await res.json().catch(() => ({}));
    } catch (error) {
      resultEl.innerHTML = '<div class="analyze-error">분석 요청에 실패했습니다.</div>';
      btn.disabled = false;
      btn.textContent = "심층분석 보기";
      return;
    }

    if (!res.ok) {
      logAnalyzeFailure(res, data);
      resultEl.innerHTML = '<div class="analyze-error">' + esc(analyzeErrorMessage(res, data)) + "</div>";
      btn.disabled = false;
      btn.textContent = "심층분석 보기";
      return;
    }

    state.insightHistory.unshift({
      ref: requestBody.ref,
      title: requestBody.title,
      url: requestBody.url,
      source_label: box.dataset.sourceLabel,
      analysis: data.analysis || "",
      links: data.links || [],
      iocs: data.iocs || [],
      category: data.category || "",
      attack_techniques: data.attack_techniques || [],
      glossary: data.glossary || {},
    });
    renderInsightDrawer();
    render(state.cache[state.period]);
  }

  // 이미 분석된 기사를 캐시 무시하고 다시 분석한다 — 프롬프트를 고친 뒤 같은
  // 기사로 품질이 실제로 좋아졌는지 확인하고 싶을 때 쓴다. force:true는 analyze.js
  // 에서 캐시 조회만 건너뛰게 하고, IP 요청 제한·하루 신규 분석 상한은 그대로
  // 적용된다(진짜 LLM 호출이라 비용이 새 분석과 똑같이 들기 때문).
  async function runReanalysis() {
    const idx = state.insightDetailIdx;
    const entry = state.insightHistory[idx];
    if (!entry) return;

    $insightDetailReanalyze.disabled = true;
    $insightDetailReanalyze.textContent = "재분석 중…";

    let res, data;
    try {
      res = await fetch(ANALYZE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ref: entry.ref,
          url: entry.url,
          title: entry.title,
          source_label: entry.source_label,
          category: entry.category,
          force: true,
        }),
      });
      data = await res.json().catch(() => ({}));
    } catch (error) {
      $insightDetailReanalyze.disabled = false;
      $insightDetailReanalyze.textContent = "재분석 실패 — 다시 시도";
      return;
    }

    if (!res.ok) {
      logAnalyzeFailure(res, data);
      $insightDetailReanalyze.disabled = false;
      // textContent는 그 자체로 이스케이프되므로 esc()를 거치면 "&amp;" 같은 문자열이
      // 그대로 보인다 — 여기서는 원문 그대로 넣는다.
      $insightDetailReanalyze.textContent = analyzeErrorMessage(res, data);
      return;
    }

    state.insightHistory[idx] = {
      ref: entry.ref,
      title: entry.title,
      url: entry.url,
      source_label: entry.source_label,
      analysis: data.analysis || "",
      links: data.links || [],
      iocs: data.iocs || [],
      category: data.category || "",
      attack_techniques: data.attack_techniques || [],
      glossary: data.glossary || {},
    };

    openInsightDetail(idx); // 갱신된 내용으로 상세를 다시 그린다(버튼 상태도 초기화됨)
    renderInsightDrawer();
    if (state.tab === "insight") render(state.cache[state.period]);
  }

  function initInsightDrawer() {
    $insightToggle.addEventListener("click", () => {
      $insightDrawer.classList.toggle("is-open");
    });
    $insightDetailReanalyze.addEventListener("click", runReanalysis);
    $insightDrawerClose.addEventListener("click", () => {
      $insightDrawer.classList.remove("is-open");
    });
    // 뒤로가기: 상세만 닫아서 드로어 목록으로 돌아간다. 닫기: 상세+드로어 둘 다 닫는다.
    $insightDetailBack.addEventListener("click", () => {
      closeInsightDetail();
    });
    $insightDetailClose.addEventListener("click", () => {
      closeInsightDetail();
      $insightDrawer.classList.remove("is-open");
    });
  }

  // 검색어 입력이 멈춘 뒤(SEARCH_LOG_DEBOUNCE_MS) 한 번만 기록한다 — 관심사 파악·
  // 결과 0건 케이스(검색 공백·검색 로직 개선 지점) 추적용. 실패해도 검색 자체엔 영향 없음.
  function logSearch(query) {
    loadSearchIndex().then((index) => {
      const words = queryWords(query);
      const resultCount = index.filter((entry) => matchScore(entry, words) >= 0).length;
      fetch(SEARCH_LOG_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query, result_count: resultCount }),
        keepalive: true,
      }).catch(() => {});
    });
  }

  function initSearch() {
    let logTimer = null;
    $searchInput.addEventListener("input", () => {
      state.query = $searchInput.value;
      state.pages["history-search"] = 1;
      if (state.query.trim() && state.tab !== "history") {
        state.tab = "history";
      }
      if (state.cache[state.period]) render(state.cache[state.period]);

      if (logTimer) clearTimeout(logTimer);
      const query = state.query.trim();
      if (query) {
        logTimer = setTimeout(() => logSearch(query), SEARCH_LOG_DEBOUNCE_MS);
      }
    });
  }

  initTheme();
  initPeriodSwitch();
  initSearch();
  initInsightDrawer();
  refresh();
})();
