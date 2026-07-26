(function () {
  "use strict";

  const PAGE_SIZE = 30;
  const SUMMARY_HIGHLIGHTS_LIMIT = 10; // 요약 탭은 빠른 개요가 목적 — 전체는 국내/해외 탭에서
  const SEARCH_LOG_URL = "https://click-tracker-two.vercel.app/api/search-log";
  const SEARCH_LOG_DEBOUNCE_MS = 1000;

  const state = {
    period: "daily",
    tab: "all", // all | domestic | overseas | recommended | cve | history
    cache: {}, // period -> payload
    query: "",
    searchIndex: null, // null = 아직 로딩 전, 로드되면 배열
    pages: {}, // pageKey -> 현재 페이지 번호(1부터)
  };

  const $app = document.getElementById("app");
  const $loading = document.getElementById("loading");
  const $generatedAt = document.getElementById("generated-at");
  const $searchInput = document.getElementById("search-input");
  const $keywordSidebar = document.getElementById("keyword-sidebar");
  const $trendSidebar = document.getElementById("trend-sidebar");

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

  // ===== Renderers =====
  const INFO_CATEGORY_TOP_N = 5;

  function renderStatStrip(stats) {
    const tiles = [
      { label: "총 건수", value: stats.total, cls: "" },
      { label: "P1 · 긴급", value: stats.p1, cls: "p1", title: "P1: 실제 악용 중이며 자사 자산과 관련된 건 (최우선 대응 필요)" },
      { label: "P2 · 주의", value: stats.p2, cls: "p2", title: "P2: 실제 악용 중이거나, PoC 공개·중대한 영향에 자사 자산이 걸린 건" },
    ];
    const categoryEntries = Object.entries(stats.info_by_category || {});
    categoryEntries.slice(0, INFO_CATEGORY_TOP_N).forEach(([name, count]) => {
      tiles.push({ label: name, value: count, cls: "" });
    });
    const restCount = categoryEntries.slice(INFO_CATEGORY_TOP_N).reduce((sum, [, count]) => sum + count, 0);
    if (restCount > 0) tiles.push({ label: "그 외", value: restCount, cls: "" });
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
      (event.summary ? '<div class="item-summary">' + esc(event.summary) + "</div>" : "") +
      "</div>"
    );
  }

  function renderItemList(events) {
    if (!events || !events.length) {
      return '<div class="empty-state">해당 없음</div>';
    }
    return '<div class="item-list">' + events.map((e) => renderItem(e)).join("") + "</div>";
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
  // (국내/해외 탭용) — 안 주면(추천기사 탭) 예전처럼 전부 보여준다.
  function renderBySource(events, pageKey) {
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
      '<div class="item-list">' + group.items.map((e) => renderItem(e, { hideSource: true })).join("") + "</div>" +
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

  function queryWords(query) {
    return query.trim().toLowerCase().split(/\s+/).filter(Boolean);
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
      return { trend_reads: (payload.domestic.trend_reads || []).concat(payload.overseas.trend_reads || []) };
    }
    if (state.tab === "cve") return { cards: payload.cards || [] };
    if (state.tab === "history") return {};
    return { highlights: (payload.domestic.highlights || []).concat(payload.overseas.highlights || []) };
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
    const items = (payload.domestic.trend_reads || []).concat(payload.overseas.trend_reads || []);
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
        (item.summary || item.url
          ? '<div class="trend-item-body">' +
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

  function render(payload) {
    const data = tabData(payload);
    $generatedAt.textContent = payload.title + " · 기간: " + payload.period_label + " · 생성: " + fmtDate(payload.generated_at);
    renderKeywordSidebar(payload);
    renderTrendSidebar(payload);

    let html = "";
    html += renderStatStrip(payload.stats);

    html +=
      '<div class="region-tabs">' +
      ["all", "recommended", "cve", "domestic", "overseas", "history"].map((t) => {
        const label = t === "all" ? "요약" : t === "domestic" ? "국내" : t === "overseas" ? "해외" :
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

      // 전체(캡 없음)는 국내/해외 탭 몫 — 요약은 상위 N건만 보여주는 빠른 개요로 유지
      const allHighlights = data.highlights || [];
      const topHighlights = allHighlights.slice(0, SUMMARY_HIGHLIGHTS_LIMIT);
      html +=
        '<div class="section"><div class="section-title">주요 뉴스 <span class="count">상위 ' +
        topHighlights.length + "건 · 전체 " + allHighlights.length + '건은 국내/해외 탭에서</span></div>' +
        renderItemList(topHighlights) +
        "</div>";
    } else if (state.tab === "recommended") {
      // 추천기사 탭: 읽을만한 동향(국내+해외 통합)을 소스별로 묶어서 표시
      html +=
        '<div class="section"><div class="section-title">추천 기사 <span class="count">' + (data.trend_reads || []).length + "건</span></div>" +
        renderBySource(data.trend_reads) +
        "</div>";
    } else if (state.tab === "cve") {
      // CVE 탭: 크로스소스 상관관계 카드(요약 탭의 "핵심 취약점"과 동일 데이터)만 모아서 표시
      const cards = data.cards || [];
      html +=
        '<div class="section"><div class="section-title">CVE <span class="count">복수 소스 교차 확인 · ' + cards.length + "건</span></div>" +
        (cards.length ? '<div class="card-list">' + cards.map(renderCveCard).join("") + "</div>" : '<div class="empty-state">해당 없음</div>') +
        "</div>";
    } else if (state.tab === "history") {
      // History 탭: 검색어가 있으면 전체 기간 검색 결과, 없으면 월별 아카이브 브라우저
      html += renderHistorySection();
    } else {
      // 국내/해외 탭: AI 총평·핵심 취약점 없이, 주요 뉴스만 소스별로 묶어서 나열(30건씩 페이지네이션)
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
  refresh();
})();
