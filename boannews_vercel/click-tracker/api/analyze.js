// 대시보드(인사이트/추천기사 탭)의 "심층분석" 버튼이 호출하는 엔드포인트.
// 기사 원문을 서버에서 다시 가져와 LLM으로 심층 분석해 반환한다 — 대시보드는
// 정적 사이트라 title/summary만 갖고 있어서, 여기서 원문을 재수집해야 한다.
//
// 비용 통제 (공개 엔드포인트라 아무나 누를 수 있음을 전제로 설계):
//   1) 캐싱 — 같은 기사(ref)는 한 번 분석되면 결과를 ANALYSIS_CACHE_TTL_SECONDS 동안
//      재사용한다. 같은 기사를 몇 명이 눌러도 LLM 호출은 한 번만 나간다 — 가장 큰
//      비용 방어선.
//   2) IP당 요청 제한 — 캐시 미스(=실제 LLM 호출로 이어지는 요청)에만 적용.
//   3) 하루 총 "신규" 분석 건수 상한(DAILY_NEW_ANALYSIS_LIMIT) — 여러 사람이 동시에
//      서로 다른 기사를 눌러도 최악의 하루 비용을 예측 가능한 선으로 막는 최종 방어선.
// 세 장치 다 Redis가 없거나 장애면 그냥 통과시킨다(click.js/search-log.js와 같은
// fail-open 철학) — 단, 이 경우 비용 방어가 전혀 없어지므로 REDIS_URL은 필수로 설정할 것.
//
// 시간 통제: 이 함수는 vercel.json의 maxDuration(60초)을 넘기면 Vercel이 HTML 504로
// 끊어버려서, 대시보드엔 원인 없는 "분석에 실패했습니다."만 뜨고 소모한 하루 카운터도
// 되돌리지 못한다. 그래서 원문 수집·LLM 호출·재시도가 전부 createDeadline()의 단일
// 예산(FUNCTION_BUDGET_MS)을 나눠 쓰고, 완주할 수 없는 호출은 시작하지 않는다.
//
// 필요 환경변수(이 click-tracker Vercel 프로젝트에 별도로 등록 필요 — boannews_mail의
// 로컬 .env와는 무관):
//   REDIS_URL — click.js와 동일한 값
//   NVIDIA_API_KEY — NVIDIA NIM API 키(scripts/common_utils.py의 _generate_nvidia와 동일 API)
//   NVIDIA_MODEL — 선택. 기본값 openai/gpt-oss-120b. 여기서는 품질 파라미터가 아니라
//     사실상 성능 파라미터다(모델별 실측 차이가 10배 이상) — 바꾸려면 본문 24,000자
//     기준 응답 시간을 반드시 재보고, 60초 예산에 여유가 있는 것만 쓸 것.
//   NVIDIA_FALLBACK_MODEL — 선택. 1차 모델 실패 시 예산이 남아 있으면 한 번 더 시도.

const Redis = require("ioredis");
const { isRateLimited, getClientIp } = require("../lib/redisGuards");

const RATE_LIMIT = 5; // IP당 1분에 5건까지 "신규"(캐시 미스) 분석 요청
const RATE_WINDOW_SECONDS = 60;
const DAILY_NEW_ANALYSIS_LIMIT = 20;
const ANALYSIS_CACHE_TTL_SECONDS = 60 * 60 * 24 * 90; // 90일 — 사실상 영구 수준이되 Redis가 무한정 자라진 않게
// 시간이 모자라 중간에서 끊긴 분석은 짧게만 캐시한다 — 바로 다시 눌렀을 때 재생성을
// 피할 정도면 충분하고, 잘린 보고서가 90일씩 남아 있으면 안 된다.
const PARTIAL_CACHE_TTL_SECONDS = 60 * 60;
// 잘린 분석을 완전한 것처럼 보여주면 안 된다 — 본문 끝에 사실대로 덧붙인다.
const PARTIAL_ANALYSIS_NOTICE =
  "\n\n(※ 생성 시간이 초과되어 여기까지만 표시됩니다. 다시 분석하면 이어지는 내용을 받을 수 있습니다.)";
// LLM에 실제로 넘기는 본문 상한(비용/타임아웃과 직결). 심층 리포트(수천~1만 단어급)는
// 이걸로도 다 못 덮지만, 무료(Hobby) 플랜의 서버리스 실행시간 제한을 고려한 절충값.
// IOC/링크 추출은 이 상한과 무관하게 원문 전체를 본다(정규식이라 비용이 0이라서).
const BODY_MAX_CHARS = 24000;
const FETCH_TIMEOUT_MS = 10000;
const MAX_EXTRACTED_LINKS = 6;
// vercel.json의 maxDuration(60s)에 실제로 걸리면 Vercel이 JSON이 아닌 HTML 504를
// 돌려줘서 대시보드는 원인을 구분하지 못하고, 소모한 하루 카운터를 되돌릴 기회도
// 없이 함수가 죽는다. 그보다 앞에서 우리가 먼저 끊고 제대로 된 응답을 만든다.
const FUNCTION_BUDGET_MS = 55000;
// 응답 직렬화와 Redis 기록(캐시 저장 + 인사이트 목록 갱신)에 남겨두는 몫.
const RESPONSE_RESERVE_MS = 4000;
// 이보다 예산이 적게 남았으면 새 LLM 호출을 아예 시작하지 않는다 — 시작해봐야 함수
// 상한에 걸려 죽을 뿐이라, 차라리 타임아웃임을 명시한 응답을 돌려주는 게 낫다.
const MIN_LLM_ATTEMPT_MS = 15000;
// 인사이트 탭/사이드바를 모든 방문자가 공유해서 보도록 하는 서버 저장 목록 —
// insights.js가 여기서 읽어간다. 캐시 미스(=새로 분석한 경우)에만 추가한다 —
// upsertInsightRecord()가 같은 ref의 기존 항목을 걸러내고 다시 쓰므로, 재분석
// (force)해도 목록에 같은 기사가 중복으로 쌓이지 않는다.
const INSIGHTS_LIST_KEY = "insights:list";
const MAX_INSIGHTS_LIST_SIZE = 300;
// 소셜 공유·메신저·앵커 등 본문 참고자료로서 의미 없는 링크는 후보에서 제외한다.
const NOISE_LINK_PATTERN = /facebook\.com|twitter\.com|x\.com\/|linkedin\.com|t\.me\/|wa\.me\/|whatsapp\.com|pinterest\.com|reddit\.com\/submit|mailto:|javascript:|\/category\/|\/author\/|\/tag\/|\/archive\/|\/feed\/|about:|^\/?$/i;

const NVIDIA_API_URL = process.env.NVIDIA_API_URL || "https://integrate.api.nvidia.com/v1/chat/completions";
// 같은 프롬프트(본문 24,000자 / max_tokens 3072)를 재는 실측에서 모델별 응답 시간이
// 한 자릿수 배 차이가 났다 — meta/llama-3.1-70b-instruct 153.6초, nemotron-3-ultra
// 93.3초인 반면 openai/gpt-oss-120b는 4개 사이트 12회 반복에서 10.2~14.2초(평균
// 12.7초, 실패 0)로 안정적이었다. 본문 상한을 줄이지 않고 함수 시간 제한을 지킬 수
// 있는 유일한 축이라 모델 선택이 여기서는 사실상 성능 파라미터다.
const NVIDIA_MODEL = process.env.NVIDIA_MODEL || "openai/gpt-oss-120b";
// 1차 모델이 실패하거나 NIM이 불안정할 때 남은 예산 안에서 한 번 더 노려보는 대체
// 모델(실측 20.1초). 빈손으로 돌려주는 것보다는 낫다는 정도의 위치다.
const NVIDIA_FALLBACK_MODEL = process.env.NVIDIA_FALLBACK_MODEL || "mistralai/mistral-nemotron";
// 2048에서는 [선수 정보] 섹션이 잘린 채 finish_reason이 length로 끝났다. 3072면
// 자연 종료(stop)되고, 실측상 소요 시간은 12.8초로 사실상 같다.
const LLM_MAX_TOKENS = 3072;

let redisClient = null;
function getRedisClient() {
  if (!process.env.REDIS_URL) return null;
  if (!redisClient) {
    redisClient = new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 1, connectTimeout: 3000 });
    redisClient.on("error", (error) => console.error("redis client error", error));
  }
  return redisClient;
}

// 함수 시작 시각을 기준으로 "앞으로 몇 ms 더 쓸 수 있는지"를 알려주는 예산 추적기.
// 원문 수집·LLM 호출·재시도가 각자 자기 타임아웃만 보고 움직이면 합계가 함수 상한을
// 넘길 수 있어서, 전부 이 하나의 예산을 나눠 쓰게 한다.
function createDeadline(budgetMs) {
  const startedAt = Date.now();
  return {
    remaining: function () {
      return budgetMs - (Date.now() - startedAt);
    },
  };
}

// 타임아웃으로 끝난 실패는 "잠시 후 재시도하면 될 일"이라 LLM 자체가 거부·오류를 낸
// 경우와 구분해서 알려줘야 한다 — 대시보드가 문구를 나눠 쓰는 근거가 이 플래그다.
function timeoutError(message) {
  const error = new Error(message);
  error.isTimeout = true;
  return error;
}

function isTimeoutError(error) {
  if (!error) return false;
  // AbortController로 끊은 fetch는 AbortError로 오지만, 런타임에 따라 그게 상위
  // 오류의 cause에 감싸여 오기도 한다 — 둘 다 타임아웃으로 본다.
  if (error.isTimeout || error.name === "AbortError") return true;
  return Boolean(error.cause && error.cause.name === "AbortError");
}

// 태그를 다 벗겨낸 "다음"에 남는 개별 엔티티만 처리하면 된다(태그 제거 정규식이
// 엔티티 자체를 건드리진 않으므로). &nbsp;만 처리하던 걸 흔한 엔티티 전반 +
// 숫자/16진 엔티티(&#39; / &#x27; 등)까지 넓혔다 — 안 하면 본문에 "&amp;" 같은
// 깨진 문자열이 그대로 LLM에 들어간다.
function decodeEntities(text) {
  return text
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&apos;|&#0*39;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)));
}

function stripHtml(html) {
  return decodeEntities(
    html
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
  )
    .replace(/\s+/g, " ")
    .trim();
}

// 정규식 기반 "가짜 DOM 파싱"이라 완벽하지 않다(중첩 <article> 등에서 어긋날 수
// 있음) — 그래도 페이지 전체를 통째로 벗기는 것보다는 훨씬 낫다. 네비게이션·헤더·
// 푸터·사이드바를 먼저 들어내고, <article>/<main> 중 텍스트가 가장 긴 블록을
// 우선 쓴다. 둘 다 없거나 너무 짧으면(광고 배너 등으로 오탐) 페이지 전체로 폴백.
const NOISE_BLOCK_RE = /<(script|style|nav|header|footer|aside)\b[\s\S]*?<\/\1>/gi;
const COMMENT_RE = /<!--[\s\S]*?-->/g;
const MIN_CONTENT_BLOCK_CHARS = 200;

function stripNoiseBlocks(html) {
  return html.replace(COMMENT_RE, " ").replace(NOISE_BLOCK_RE, " ");
}

function largestTagBlock(html, tagName) {
  const re = new RegExp("<" + tagName + "\\b[^>]*>([\\s\\S]*?)<\\/" + tagName + ">", "gi");
  let match;
  let best = "";
  while ((match = re.exec(html)) !== null) {
    if (match[1].length > best.length) best = match[1];
  }
  return best;
}

function extractArticleHtml(html) {
  const cleaned = stripNoiseBlocks(html);
  for (const tag of ["article", "main"]) {
    const block = largestTagBlock(cleaned, tag);
    if (block && block.replace(/<[^>]+>/g, "").trim().length >= MIN_CONTENT_BLOCK_CHARS) {
      return block;
    }
  }
  return cleaned;
}

const ARTICLE_FETCH_RETRIES = 2;
const ARTICLE_FETCH_RETRY_DELAY_MS = 1500;

// "여기"/"링크" 같은 텍스트는 그 자체로는 무슨 링크인지 알 수 없다 — 이런 경우에만
// 링크 앞의 문장 일부로 대체해 맥락을 준다(이미 설명적인 링크 텍스트는 그대로 둬서
// 목록이 불필요하게 길어지지 않게 한다).
const GENERIC_LINK_TEXT_PATTERN = /^(여기|바로가기|링크|더보기|클릭|기사|본문|원문|확인|source|here|click here|read more|more|link)$/i;
const LINK_CONTEXT_CHARS = 60;

// 앵커 텍스트가 의미 없을 때만 쓰는 대체 문맥 — 링크 앞쪽 원문 텍스트를 최대
// LINK_CONTEXT_CHARS만큼 잘라온다. 잘린 첫 단어는 어색하니 버리고 그 다음
// 단어부터 시작한다.
function extractPrecedingContext(html, matchStart) {
  const raw = html.slice(Math.max(0, matchStart - LINK_CONTEXT_CHARS * 2), matchStart);
  const text = decodeEntities(raw.replace(/<[^>]*>?/g, " ")).replace(/\s+/g, " ").trim();
  if (!text) return "";
  let snippet = text.slice(-LINK_CONTEXT_CHARS);
  if (snippet.length === LINK_CONTEXT_CHARS) {
    const firstSpace = snippet.indexOf(" ");
    if (firstSpace > 0) snippet = snippet.slice(firstSpace + 1);
  }
  return snippet.trim();
}

// 원문 HTML의 <a href> 중 본문 참고자료로 볼 만한 것만 결정적으로(LLM 없이) 추출한다.
// LLM이 "참고 자료가 있다"고 말만 하고 실제 링크는 안 주는 문제를 막기 위한 것 —
// 원문에 실재하는 링크만 그대로 복사하므로 지어낼 여지가 없다. extractArticleHtml()로
// 이미 노이즈(네비·헤더·푸터)를 걷어낸 본문 블록에서 뽑으므로 사이트 공통 링크가 덜 섞인다.
function extractArticleLinks(html, baseUrl) {
  const links = [];
  const seen = new Set([baseUrl]);
  const anchorPattern = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = anchorPattern.exec(html)) && links.length < MAX_EXTRACTED_LINKS) {
    const rawHref = match[1];
    if (NOISE_LINK_PATTERN.test(rawHref)) continue;

    let resolved;
    try {
      resolved = new URL(rawHref, baseUrl).toString();
    } catch (error) {
      continue;
    }
    let originUrl = "";
    try {
      originUrl = new URL(baseUrl).origin;
    } catch (e) {}

    if (!/^https?:\/\//i.test(resolved) || seen.has(resolved) || resolved === baseUrl || resolved === baseUrl + '/' || (originUrl && (resolved === originUrl || resolved === originUrl + '/'))) continue;

    let text = decodeEntities(match[2].replace(/<[^>]*>?/g, "").replace(/\s+/g, " ")).trim().slice(0, 120);
    if (!text || /[<>\\"]/.test(text) || /(\.png|\.jpg|\.jpeg|\.gif|\.svg|\.webp)/i.test(text)) continue;

    if (GENERIC_LINK_TEXT_PATTERN.test(text.replace(/\s+/g, " ").trim()) || text.length <= 4) {
      const context = extractPrecedingContext(html, match.index);
      if (context) text = context.slice(0, 120);
    }

    seen.add(resolved);
    links.push({ url: resolved, text: text });
  }
  return links;
}

const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
// 일반 도메인·URL은 뉴스 본문 오탐이 너무 많아서(회사명, 참고 사이트 등) 제외하고,
// 작성자가 의도적으로 디팽(defang)한 것(example[.]com, hxxp://)만 IOC로 간주한다 —
// scripts/common_utils.py의 extract_iocs()와 같은 방침. JS의 \b는 항상 ASCII 기준이라
// (Python처럼 re.ASCII를 따로 켤 필요 없음) 한글 조사가 도메인에 붙어 나오는 문제가 없다.
const DEFANGED_DOMAIN_RE = /\b[A-Za-z0-9][A-Za-z0-9-]*(?:(?:\.|\[\.\])[A-Za-z0-9-]+)*\[\.\][A-Za-z]{2,}\b/g;
const HXXP_URL_RE = /\bhxxps?:\/\/[^\s"'<>]+/gi;
const IOC_EXTRACT_LIMIT = 50;
const PRIVATE_IP_PREFIXES = ["0.", "10.", "127.", "169.254.", "192.168.", "224.", "255."];

function isPublicIp(ip) {
  if (PRIVATE_IP_PREFIXES.some((prefix) => ip.startsWith(prefix)) || ip.endsWith(".0")) return false;
  const second = parseInt(ip.split(".")[1], 10);
  return !(ip.startsWith("172.") && second >= 16 && second <= 31);
}

// 본문에서 IP/도메인/해시(IOC)를 뽑는다 — LLM 없이 결정적으로. 벤인 인프라 필터
// (common_utils.is_benign_ioc, 로컬 intel 데이터 필요)는 이 서버리스 함수엔 없어서
// 흔한 CDN·DNS가 디팽돼 언급되면 섞일 수 있다 — 발견 시 목록만 확장해서 대응.
function extractIocs(text) {
  if (!text) return [];
  const found = [];
  const seen = new Set();

  function add(type, rawValue) {
    const value = rawValue.trim().replace(/[.,;:)\]}]+$/, "");
    const key = value.toLowerCase();
    if (!value || seen.has(key)) return;
    seen.add(key);
    found.push({ type: type, value: value });
  }

  (text.match(HXXP_URL_RE) || []).forEach((match) => {
    add("url", match.replace(/^hxxp/i, "http").replace(/\[\.\]/g, "."));
  });
  const textWithoutUrls = text.replace(HXXP_URL_RE, " ");
  (textWithoutUrls.match(DEFANGED_DOMAIN_RE) || []).forEach((match) => add("domain", match.replace(/\[\.\]/g, ".")));

  const refanged = text.replace(/\[\.\]/g, ".");
  [[SHA256_RE, "sha256"], [SHA1_RE, "sha1"], [MD5_RE, "md5"]].forEach(([pattern, type]) => {
    (refanged.match(pattern) || []).forEach((match) => add(type, match.toLowerCase()));
  });
  (refanged.match(IPV4_RE) || []).forEach((match) => {
    if (isPublicIp(match)) add("ipv4", match);
  });

  return found.slice(0, IOC_EXTRACT_LIMIT);
}

// body_selector 같은 사이트별 설정 없이 범용으로 시도 — boannews_mail의
// fetch_article_body()가 <article> 태그로 폴백하는 것과 같은 수준의 best-effort.
// 네트워크 실패는 봇 차단 등 일시적인 경우가 흔해 재시도한다(선택자 실패처럼
// 구조적인 문제는 재시도해도 안 바뀌므로 대상이 아님).
async function fetchArticleText(url, deadline) {
  let html = null;
  for (let attempt = 1; attempt <= ARTICLE_FETCH_RETRIES; attempt += 1) {
    // 원문 수집에 예산을 다 써버리면 정작 분석을 못 한다 — LLM 호출 몫을 남겨두고,
    // 그보다 적게 남았으면 즉시 포기해서 제목만으로라도 분석이 돌게 한다.
    const budgetMs = deadline.remaining() - RESPONSE_RESERVE_MS - MIN_LLM_ATTEMPT_MS;
    if (budgetMs <= 0) break;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(FETCH_TIMEOUT_MS, budgetMs));
    try {
      const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 boannews-analyzer/1.0" },
        signal: controller.signal,
      });
      if (response.ok) {
        html = await response.text();
        break;
      }
    } catch (error) {
      console.error("article fetch failed (attempt " + attempt + ")", error);
    } finally {
      clearTimeout(timer);
    }
    // 재시도 대기도 예산에서 나가는 시간이라, 대기 후 실제 시도까지 할 여유가
    // 남지 않으면 기다리지 않고 끝낸다.
    if (attempt < ARTICLE_FETCH_RETRIES &&
        deadline.remaining() - ARTICLE_FETCH_RETRY_DELAY_MS - RESPONSE_RESERVE_MS > MIN_LLM_ATTEMPT_MS) {
      await new Promise((resolve) => setTimeout(resolve, ARTICLE_FETCH_RETRY_DELAY_MS));
    }
  }
  if (!html) return { text: "", fullText: "", links: [] };
  const articleHtml = extractArticleHtml(html);
  const fullText = stripHtml(articleHtml);
  // fullText는 IOC 추출용(비용 없는 정규식이라 안 잘라도 됨) — LLM에는 text(잘린 것)만 넘긴다.
  return { text: fullText.slice(0, BODY_MAX_CHARS), fullText: fullText, links: extractArticleLinks(articleHtml, url) };
}

// boannews_mail scripts/common_utils.py의 ENRICH_PROMPT category 항목과 같은
// 목록 — 대시보드 통계 탭의 카테고리 분포와 같은 체계를 써야 인사이트에서만 다른
// 분류가 따로 노는 걸 피할 수 있다.
const REPORT_CATEGORIES = "취약점|악성코드|침해사고|개인정보유출|공격캠페인|공급망공격|피싱사기|정책규제|기술동향|제품행사|기타";

// 이 안에 든 것만 "위협/공격"형 — CVSS·공격기법·IOC 프레임이 실제로 맞는 기사다.
// 정책규제·기술동향·제품행사·기타는 위협이 아닌데도 같은 프레임을 강제하면 모델이
// "심각도: Low(본문에 명시 안 됨 — 추정, 이건 그냥 홍보 기사라...)" 처럼 억지로
// 끼워맞춘 문장을 만든다 — 그래서 섹션 구성 자체를 다르게 분기한다.
const THREAT_CATEGORIES = new Set(["취약점", "악성코드", "침해사고", "공격캠페인", "공급망공격", "피싱사기", "개인정보유출"]);

function isThreatCategory(category) {
  return THREAT_CATEGORIES.has((category || "").trim());
}

function buildPrompt(title, body, category) {
  const threat = isThreatCategory(category);

  const persona = threat
    ? "당신은 SOC 보안관제 조직의 위협 인텔리전스 분석가이다."
    : "당신은 보안 전문 매체의 분석 기자다.";

  // 위협형: CVSS·공격기법·IOC·즉시조치 프레임. 비위협형(정책규제·기술동향·제품행사·
  // 기타): 공격을 전제하지 않는 중립적인 섹션 — "위험도"·"조치"를 억지로 만들지 않는다.
  const sections = threat
    ? (
      "[CVSS/심각도] 본문에 CVSS 점수·벡터가 명시돼 있으면 그대로 인용하라(예: \"CVSS: 9.8 (Critical) " +
      "— 벡터: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"). 점수는 없고 심각도 등급(Critical/High/Medium/Low " +
      "등)만 언급됐으면 그 등급만 쓰라. 점수도 등급도 본문에 전혀 없으면, 공격 벡터·필요 권한·영향 범위를 " +
      "근거로 Critical/High/Medium/Low 중 하나를 직접 판단하되 반드시 \"(본문에 명시 안 됨 — 추정)\"이라고 " +
      "표시하고 판단 근거를 한 문장 덧붙여라 — 공식 수치인 것처럼 지어내지 마라.\n" +
      // 지시가 한 줄뿐이던 섹션들이 정확히 부실하게 나왔다(반면 지시가 상세한 [CVSS/심각도]는
      // 잘 나온다). 무엇을 어느 깊이로 쓸지 못박은 뒤 실측에서 분량 +25%, [권장 대응] 항목이
      // 3개→5개로 늘고 IOC 기반 탐지·설정 정책 같은 실행 가능한 내용이 들어왔다.
      "[기술적 세부사항] 공격 체인을 침투 → 실행 → 지속화 → 확산 → 목적 달성 순서로 단계별로 " +
      "서술하라. 본문에 나온 구체값(CVE 번호, 영향받는 제품·버전, 파일명·경로, 실행 명령어, " +
      "도메인·IP·해시, 포트, 계정·패키지 이름, 수치)은 빠뜨리지 말고 그대로 인용하라. " +
      "\"악성코드를 삽입했습니다\" 같은 뭉뚱그린 서술은 쓰지 마라 — 무엇을 어떻게 했는지 본문 " +
      "근거로 쓰라. 5문장 이상.\n" +
      "[MITRE ATT&CK] 본문 서술로 식별되는 공격 기법을 MITRE ATT&CK Enterprise 기법 ID와 " +
      "이름으로 나열하라(예: T1566 (피싱), T1059.001 (파워셸)). 한 줄에 콤마로 구분해서만 " +
      "쓰고, 본문에 근거가 없는 기법은 지어내지 마라 — 식별되는 게 없으면 \"해당 없음\"이라고 " +
      "써라.\n" +
      "[영향 범위 및 위험도] 영향받는 대상(제품·버전·조직 유형·지역)과 규모를 본문의 수치로 " +
      "명시하고, 공격이 성공하면 실제로 무엇을 잃는지 쓰라. 3문장 이상.\n" +
      "[권장 대응] 실무자가 바로 실행할 수 있는 조치 3~5개. 각 항목에 대상(무엇을)과 방법" +
      "(어떻게)을 함께 쓰고, 본문에 패치 버전·설정값·탐지 지표가 있으면 그대로 넣어라. " +
      "\"최신 패치를 적용하십시오\"처럼 어느 기사에나 통하는 일반론은 쓰지 마라.\n"
    )
    : (
      "[주요 내용] 본문의 핵심 사실·수치·일정·고유명사를 빠뜨리지 말고 구체적으로 서술하라" +
      "(위협·공격을 전제로 지어내지 말 것). 5문장 이상.\n" +
      "[의미와 영향] 보안 업계·기업·이용자에게 어떤 의미·영향이 있는지, 무엇이 달라지는지를 " +
      "본문 근거로 쓰라. 3문장 이상.\n" +
      "[참고 사항] 실무자가 확인·검토해볼 점 3개. 각 항목에 무엇을 어떻게 확인할지 함께 쓰고, " +
      "어느 기사에나 통하는 일반론은 쓰지 마라.\n"
    );

  return (
    persona + " 아래 보안 관련 기사를 심층 분석해 한국어 존댓말로 작성하라.\n\n" +
    "제목: " + title + "\n\n" +
    "본문:\n" + (body || "(본문을 가져오지 못해 제목만으로 분석합니다.)") + "\n\n" +
    "출력의 맨 첫 줄에 이 기사가 다음 중 무엇에 해당하는지 정확히 하나만 골라 " +
    "\"[분류: 카테고리명]\" 형식으로 써라(목록 밖의 이름을 만들지 마라) — 목록: " +
    REPORT_CATEGORIES + ". 그 다음 줄부터 아래 형식을 따라라.\n\n" +
    "출력 형식:\n" +
    "[핵심 요약] 2~3문장\n" +
    sections +
    "[선수 정보]\n" +
    "- 용어명1: 이 용어를 모르면 위 분석을 이해할 수 없는 실무자를 위한 1문장 해설\n" +
    "- 용어명2: 용어명1과 동일한 형태의 해설\n\n" +
    // 실측: 용어가 비어 있던 15건 중 11건이 [권장 대응]에서 그냥 끝나 있었다(나머지 4건만
    // max_tokens 잘림). 마지막 섹션이라 모델이 통째로 생략하는 게 주된 누락 원인이라
    // 별도 규칙으로 못박는다.
    "섹션 누락 금지: 위 출력 형식의 섹션을 [선수 정보]까지 하나도 빠짐없이 순서대로 써라 — " +
    "[권장 대응]에서 끝내지 마라.\n\n" +
    "번호 목록 작성 규칙: 번호(예: \"1.\")만 쓰고 뒤에 설명 문장을 비워두지 마라 — " +
    "쓰기로 한 항목은 반드시 같은 줄에 실질적인 문장으로 채우고, 번호는 1부터 순서대로 매겨라.\n\n" +
    "강조 규칙: 각 섹션에서 가장 핵심적인 용어·수치·행위만 **이렇게** 볼드로 표시하라. 섹션당 " +
    "2~4개로 제한하고, 문장 전체나 절 단위를 통째로 볼드 처리하지 마라 — 술술 읽다가도 " +
    "핵심만 눈에 들어오게 하는 목적이니 과도하게 표시하면 안 된다.\n\n" +
    // 이전 규칙은 독자를 "보안 비전문가"로 정의하고 "2~3개를 선정하라"고 개수를 강제해서,
    // 모델이 악성코드·피싱·자격 증명 같은 실무자 상식어로 칸을 채웠다. 독자를 실무자로
    // 바꾸고 개수 하한을 없애는 것이 이 규칙의 핵심이다.
    "선수 정보 작성 규칙: 독자는 보안 실무자다. \"이 단어를 모르면 위 분석을 못 읽는가\"만 " +
    "기준으로 삼아라.\n" +
    "- 고를 것: 특정 기술·기법·표준·시스템의 이름(예: Active Directory, RMM, 횡적 이동, " +
    "DLL 사이드로딩, KCMVP, Adversary Emulation)\n" +
    "- 고르지 말 것: 실무자가 이미 아는 보안 상식어(악성코드, 피싱, 랜섬웨어, 자격 증명, " +
    "데이터 유출, 취약점, 보안 패치, 공급망 공격 등), 널리 알려진 서비스·회사명(GitHub, " +
    "npm, AWS, Windows), 이 기사에만 등장하는 제품·브랜드명\n" +
    "- 최대 3개까지만 쓰고, 개수를 채우려고 상식어를 넣지 마라. 기준에 맞는 용어가 하나도 " +
    "없으면 항목 대신 \"- 해당 없음\" 한 줄만 써라.\n" +
    "- 해설에 용어를 그대로 되풀이하지 마라 — \"CI 러너: CI 자동화를 수행하는 러너입니다\"는 " +
    "설명이 아니다. 그 용어가 무엇을 하는지, 이 기사에서 왜 중요한지를 써라.\n" +
    "- 용어명은 본문에 나온 표기 그대로 쓰고 볼드(**)나 번호를 붙이지 마라.\n\n" +
    "주의: 본문에 없는 사실을 지어내지 마라. 본문이 부실하면 그 사실을 그대로 밝혀라. " +
    "모든 출력은 한국어로만 쓰고 한자·중국어를 섞지 마라."
  );
}

const LLM_CALL_RETRIES = 2;
const LLM_CALL_RETRY_DELAY_MS = 1000;

// 한 번의 호출. 응답을 통째로 기다리지 않고 스트리밍으로 받는 이유가 둘 있다.
//   1) 첫 토큰까지 걸린 시간(TTFT)을 따로 잴 수 있다 — 호출이 느릴 때 "큐에서 대기 중"인지
//      "생성 자체가 느린"지 구분되는 유일한 단서다. 배포 환경에서만 50초 넘게 걸리던 원인을
//      좁히려면 이 값이 필요하다.
//   2) 예산이 다 돼서 끊더라도 그때까지 받은 분량이 손에 남는다. 통째로 기다리던 이전에는
//      50초를 쓰고도 빈손으로 실패했다.
// stat은 호출자가 넘기는 기록용 객체 — 실패해도 TTFT·수신 분량을 진단에 남기기 위해
// 반환값이 아니라 인자로 받는다.
async function callNvidiaOnce(model, prompt, timeoutMs, stat) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = Date.now();
  let content = "";
  let truncated = false;

  // SSE는 "data: {...}" 줄 단위라, 청크 경계가 줄 중간을 자를 수 있다 — 버퍼에 모았다가
  // 개행이 나올 때만 한 줄씩 처리한다.
  let buffer = "";

  function handleLine(rawLine) {
    const line = rawLine.trim();
    if (!line || line.indexOf("data:") !== 0) return;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]") return;
    let chunk;
    try {
      chunk = JSON.parse(payload);
    } catch (error) {
      return;
    }
    const choice = chunk && chunk.choices && chunk.choices[0];
    const delta = choice && choice.delta && choice.delta.content;
    if (delta) {
      if (stat.ttftMs === null) stat.ttftMs = Date.now() - startedAt;
      content += delta;
      stat.chars = content.length;
    }
  }

  function pump(text) {
    buffer += text;
    let newlineIndex = buffer.indexOf("\n");
    while (newlineIndex >= 0) {
      handleLine(buffer.slice(0, newlineIndex));
      buffer = buffer.slice(newlineIndex + 1);
      newlineIndex = buffer.indexOf("\n");
    }
  }

  try {
    const response = await fetch(NVIDIA_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + process.env.NVIDIA_API_KEY,
      },
      body: JSON.stringify({
        model: model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.2,
        max_tokens: LLM_MAX_TOKENS,
        stream: true,
      }),
      signal: controller.signal,
    });
    if (!response.ok) {
      // NVIDIA가 돌려주는 사유("invalid api key" 등)까지 실어야 401이 키 값 문제인지
      // 권한 문제인지 갈린다. 이 본문에 우리 키가 담기지는 않는다.
      let reason = "";
      try {
        reason = (await response.text()).replace(/\s+/g, " ").trim().slice(0, 150);
      } catch (error) {
        reason = "";
      }
      throw new Error("HTTP " + response.status + (reason ? " — " + reason : ""));
    }

    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const result = await reader.read();
        if (result.done) break;
        pump(decoder.decode(result.value, { stream: true }));
      }
    } else {
      // 스트림을 못 얻는 런타임 대비 — 같은 파서로 통째로 처리한다(부분 결과 이점만 없다).
      pump(await response.text());
    }
    if (buffer) handleLine(buffer);
  } catch (error) {
    // 예산이 다 돼 끊긴 경우, 받아둔 분량이 있으면 실패로 버리지 않고 부분 결과로 살린다.
    if (!isTimeoutError(error) || !content.trim()) throw error;
    truncated = true;
  } finally {
    clearTimeout(timer);
  }

  const cleaned = content.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
  if (!cleaned) throw new Error("빈 응답");
  stat.truncated = truncated;
  return { content: cleaned, truncated: truncated };
}

// 401이 났을 때 "환경변수에 무엇이 들어있는가"를 키 자체를 노출하지 않고 판별하기 위한
// 최소 정보. 길이·고정 접두사(nvapi-)·따옴표나 공백 혼입 여부만 본다 — 이것만으로도
// 모델명 같은 엉뚱한 값이 들어갔는지, 복사 과정에서 공백이 붙었는지가 바로 드러난다.
// 실패 응답에만 싣는다.
function describeKeyShape() {
  const raw = process.env.NVIDIA_API_KEY;
  if (!raw) return { present: false };
  return {
    present: true,
    length: raw.length,
    prefix: raw.slice(0, 6),
    looks_like_nvapi: raw.indexOf("nvapi-") === 0,
    has_edge_whitespace: raw !== raw.trim(),
    has_quotes: /^["']|["']$/.test(raw),
  };
}

// 오류를 응답에 실어 보낼 수 있는 짧은 문자열로. 이 함수가 만드는 값은 공개 엔드포인트의
// 응답에 그대로 들어가므로, 키가 섞일 수 있는 스택 트레이스가 아니라 메시지만 쓴다.
function describeError(error) {
  if (!error) return "unknown";
  if (isTimeoutError(error)) return "timeout(aborted)";
  return String(error.message || error.name || error).slice(0, 200);
}

// 1차 모델로 재시도까지 해보고, 그래도 안 되면 대체 모델로 한 번 더. 단 매 시도 직전에
// 남은 예산을 확인해서, 어차피 완주 못 할 호출은 시작하지 않고 타임아웃으로 끝낸다 —
// 그래야 하루 카운터를 되돌리고 원인이 담긴 JSON을 돌려줄 시간이 남는다.
//
// attempts에는 시도마다 {model, ms, error}가 한 줄씩 쌓인다. 성공하든 실패하든 호출자가
// 그대로 읽어 응답에 실어 보내기 위한 것 — 배포 환경에서만 재현되는 지연은 로그를 열지
// 않고는 원인을 좁힐 수 없어서, 어느 모델이 몇 초를 먹고 무슨 오류로 끝났는지를 응답
// 자체가 말하게 한다.
async function callNvidia(prompt, deadline, attempts) {
  if (!process.env.NVIDIA_API_KEY) throw new Error("NVIDIA_API_KEY 미설정");

  const models = [NVIDIA_MODEL];
  if (NVIDIA_FALLBACK_MODEL && NVIDIA_FALLBACK_MODEL !== NVIDIA_MODEL) {
    models.push(NVIDIA_FALLBACK_MODEL);
  }

  let lastError = null;
  for (const model of models) {
    for (let attempt = 1; attempt <= LLM_CALL_RETRIES; attempt += 1) {
      const budgetMs = deadline.remaining() - RESPONSE_RESERVE_MS;
      if (budgetMs < MIN_LLM_ATTEMPT_MS) {
        attempts.push({ model: model, ms: 0, error: "skipped(no budget)" });
        // 예산이 모자라 더 못 돌리는 것뿐이므로, 앞선 시도에 진짜 오류가 있었다면
        // 그쪽을 원인으로 남긴다 — 전부 timeout으로 뭉뚱그리면 "다시 눌러보세요"라는
        // 틀린 안내가 나가고 실제 원인(모델 거부, 인증 실패 등)이 가려진다.
        throw lastError || timeoutError("분석 시간이 초과되었습니다.");
      }
      const startedAt = Date.now();
      const stat = { ttftMs: null, chars: 0, truncated: false };
      try {
        const result = await callNvidiaOnce(model, prompt, budgetMs, stat);
        attempts.push({
          model: model, ms: Date.now() - startedAt, ttft_ms: stat.ttftMs,
          chars: stat.chars, truncated: result.truncated, error: null,
        });
        return result;
      } catch (error) {
        lastError = error;
        attempts.push({
          model: model, ms: Date.now() - startedAt, ttft_ms: stat.ttftMs,
          chars: stat.chars, error: describeError(error),
        });
        console.error("nvidia call failed (" + model + ", attempt " + attempt + ")", error);
      }
      // 백오프는 같은 모델을 다시 부를 때만 의미가 있다 — 모델을 바꿔 넘어가거나
      // 마지막 시도였다면 기다려봐야 예산만 축낸다.
      if (attempt < LLM_CALL_RETRIES &&
          deadline.remaining() - LLM_CALL_RETRY_DELAY_MS - RESPONSE_RESERVE_MS >= MIN_LLM_ATTEMPT_MS) {
        await new Promise((resolve) => setTimeout(resolve, LLM_CALL_RETRY_DELAY_MS));
      }
    }
  }
  throw lastError || timeoutError("분석 시간이 초과되었습니다.");
}

// 맨 첫 줄의 "[분류: 카테고리명]"을 뽑아내고 본문에서는 지운다 — 인사이트 목록/
// 상세 보기에서 배지로 따로 보여줄 값이라, 분석 텍스트 안에 그대로 남겨두면 중복
// 노출된다. 모델이 지시를 안 따라 첫 줄에 없으면 category는 빈 문자열로 둔다.
//
// "[분류: 취약점]"이 기대 형식이지만, 다른 섹션 헤더에서도 확인된 것처럼 모델이
// 콜론을 빼거나("[분류] 취약점") 값을 다음 줄에 쓰는("[분류]\n취약점") 등 형식을
// 살짝 벗어날 때가 있다. \s*가 개행도 포함하므로 "[분류" 뒤에 콜론·괄호 유무나
// 줄바꿈 여부와 무관하게, 알려진 카테고리 값(REPORT_CATEGORIES) 중 하나가 나오면
// 그 지점까지 통째로 인식한다 — 인사이트 목록에서 분류 배지가 항목마다 들쭉날쭉
// 뜨던 원인이었다.
const CATEGORY_LINE_RE = new RegExp("^\\s*\\[분류\\]?:?\\s*(" + REPORT_CATEGORIES + ")\\]?\\s*\\n?");

function extractReportCategory(text) {
  const match = text.match(CATEGORY_LINE_RE);
  if (!match) return { category: "", analysis: text };
  return { category: match[1].trim(), analysis: text.slice(match[0].length).replace(/^\s*\n/, "") };
}

// 용어는 대시보드에서 본문의 같은 단어를 찾아 툴팁을 다는 데 쓰인다 — 그래서 본문에
// 실제로 나타나는 형태와 정확히 같아야 하고, 마크다운 기호가 한 글자라도 붙으면 영영
// 매칭되지 않는다. 다음 세 가지가 실제로 관찰된 오염이다:
//   "횡적 이동**"        볼드 여는 별표만 불릿으로 오인해 벗겨지고 닫는 쪽이 남음
//   "1. **로그인 포털**"  다른 섹션의 번호 목록이 용어로 딸려 들어옴
//   "1. 피싱"            같은 원인
const GLOSSARY_TERM_MAX_CHARS = 40;

// 앞뒤에 붙은 강조 기호만 벗긴다(용어 안쪽의 기호는 원문 그대로 둬야 본문과 매칭된다).
function normalizeGlossaryTerm(raw) {
  return String(raw || "").replace(/^[\s*_`~]+/, "").replace(/[\s*_`~]+$/, "").trim();
}

// 용어로 쓸 수 있는 형태인지. 길거나 문장으로 끝나면 설명문이 통째로 딸려온 것이고,
// 대괄호가 남아 있으면 섹션 헤더를 잘못 집은 것이다.
function isUsableGlossaryTerm(term) {
  if (!term || term.length > GLOSSARY_TERM_MAX_CHARS) return false;
  if (/[\[\]]/.test(term)) return false;
  if (/[.!?]$/.test(term)) return false;
  if (/^\d+$/.test(term)) return false;
  return true;
}

// 프롬프트에 "상식어는 넣지 마라"라고 명시해도 모델이 종종 어긴다 — generate_report.py의
// _GENERIC_KEYWORD_WORDS와 같은 취지의 2차 방어선이다. 공백을 지운 형태가 이 목록과
// 정확히 일치할 때만 버려서, 목록에 없는 조각이 섞인 진짜 용어(예: "공급망 무결성 검증")는
// 살아남게 한다.
const GENERIC_GLOSSARY_TERMS = new Set([
  "악성코드", "멀웨어", "malware", "피싱", "피싱공격", "스피어피싱", "랜섬웨어", "ransomware",
  "자격증명", "사용자자격증명", "자격증명도용", "크리덴셜", "데이터유출", "정보유출",
  "개인정보유출", "취약점", "제로데이", "보안패치", "패치", "업데이트", "공급망공격",
  "디도스", "ddos", "백도어", "트로이목마", "바이러스", "웜", "스팸", "해킹", "해커",
  "방화벽", "안티바이러스", "백신", "로그인", "로그인포털", "인증", "이중인증", "다중인증",
  "암호화", "복호화", "사회공학", "사회공학공격", "익스플로잇", "페이로드", "봇넷",
  "스니핑", "스푸핑", "무차별대입공격", "권한", "관리자권한",
  "github", "npm", "aws", "azure", "windows", "linux", "macos", "android", "ios",
  "python", "javascript", "docker", "kubernetes", "chrome", "firefox", "vpn", "api",
  "powershell", "파워셸", "ai", "인공지능", "머신러닝", "ai해킹", "인공지능의활용",
  "클라우드", "서버", "네트워크", "데이터베이스", "브라우저", "이메일",
]);

function compactTerm(value) {
  return String(value || "").toLowerCase().replace(/[\s·・\-_‑–—]/g, "");
}

function isGenericGlossaryTerm(term) {
  return GENERIC_GLOSSARY_TERMS.has(compactTerm(term));
}

// "CI 러너: CI 자동화를 수행하는 러너입니다"처럼 용어를 설명에 그대로 돌려쓰면 해설이
// 아니다. 용어를 이루는 조각이 전부 설명 안에 다시 나오면 버린다. 조각이 하나뿐인 용어는
// 대상에서 뺀다 — "KCMVP: KCMVP는 …"처럼 용어로 문장을 시작하는 건 정상적인 서술이다.
function isCircularDefinition(term, definition) {
  const parts = term.split(/\s+/).filter((part) => part.length >= 2);
  if (parts.length < 2) return false;
  const compactDefinition = compactTerm(definition);
  return parts.every((part) => compactDefinition.includes(compactTerm(part)));
}

// 한자가 섞인 해설이 실제로 관찰됐다("…접근하는入口입니다", "…정보를窃取하기 위해").
// 한국어로만 쓰라고 프롬프트에 넣었지만, 새면 그대로 화면에 나가므로 여기서도 막는다.
const CJK_RE = /[一-鿿]/;

// "[선수 정보]" 섹션의 내용만 잘라온다 — 다음 "[섹션명]" 헤더 직전까지. 이전에는
// 문서 끝까지([\s\S]*$) 가져와서, 모델이 이 섹션 뒤에 다른 섹션을 더 쓰면 그쪽
// 번호 목록이 전부 용어로 저장됐다.
//
// 헤더 앞뒤의 "**"까지 같이 먹는다 — 모델이 "**[선수 정보]**"처럼 헤더를 볼드로 쓰는
// 경우가 실제로 관찰됐고, 그러면 여는 "**"가 본문 끝에 미아로 남고 닫는 "**"가 용어
// 목록의 첫 줄로 들어간다.
const GLOSSARY_SECTION_RE = /\n?[ \t]*\**\[선수 정보\]\**[ \t]*\n?([\s\S]*?)(?=\n\s*\**\[[^\]\n]+\]|$)/i;

function extractGlossary(text) {
  const match = text.match(GLOSSARY_SECTION_RE);
  if (!match) return { glossary: {}, analysis: text };

  // 섹션 뒤에 남은 내용은 버리지 않고 본문에 다시 붙인다 — 예전에는 용어로 흡수되면서
  // 화면에서도 사라졌다.
  const before = text.slice(0, match.index);
  const after = text.slice(match.index + match[0].length);
  const cleanedAnalysis = (before + "\n" + after).trim();
  const glossary = {};

  match[1].trim().split("\n").forEach((line) => {
    // 불릿과 번호는 목록 표시일 뿐이라 지우되, 볼드(**)는 여기서 건드리지 않는다 —
    // "*"를 불릿과 뭉뚱그려 지운 것이 "횡적 이동**"이 생긴 원인이었다. 불릿으로서의
    // "*"는 뒤에 공백이 오는 경우로만 한정한다.
    const cleanLine = line
      .trim()
      .replace(/^(?:[-•]\s*|\*\s+)/, "")
      .replace(/^\d+[.)]\s*/, "")
      .trim();
    const colonIndex = cleanLine.indexOf(":");
    if (colonIndex <= 0) return;

    const term = normalizeGlossaryTerm(cleanLine.slice(0, colonIndex));
    const definition = cleanLine.slice(colonIndex + 1).trim();
    if (!isUsableGlossaryTerm(term) || !definition) return;
    if (isGenericGlossaryTerm(term)) return;
    if (isCircularDefinition(term, definition)) return;
    if (CJK_RE.test(definition)) return;
    glossary[term] = definition;
  });

  return { glossary: glossary, analysis: cleanedAnalysis };
}

// "[MITRE ATT&CK] T1566 (피싱), T1059.001 (파워셸)" 한 줄을 뽑아내고 본문에서는
// 지운다 — 비위협형 템플릿엔 이 섹션 자체가 없어서 매칭이 안 되면 빈 배열로 둔다.
function extractMitreTechniques(text) {
  const match = text.match(/\n?\[MITRE ATT&CK\]\s*([^\n]*)\n?/);
  if (!match) return { techniques: [], analysis: text };
  const cleanedAnalysis = text.slice(0, match.index) + text.slice(match.index + match[0].length);
  const raw = match[1].trim();
  if (!raw || /^(해당\s*없음|없음|none|n\/a)$/i.test(raw)) {
    return { techniques: [], analysis: cleanedAnalysis };
  }
  const techniques = raw.split(",").map((s) => s.trim()).filter(Boolean).slice(0, 8);
  return { techniques: techniques, analysis: cleanedAnalysis };
}

// generate_report.py의 _renumber_lists()와 동일한 로직 — "2. / 3."처럼 1번이
// 빠진 채 번호가 어긋나는 경우(간헐적으로 관찰됨)를 항상 1부터 순서대로
// 재배열하는 최종 방어선. 불릿("-")은 원래 순서가 없는 목록이라 건드리지 않는다.
function renumberLists(text) {
  const lines = text.split("\n");
  let i = 0;
  while (i < lines.length) {
    if (!/^\d+\.\s/.test(lines[i])) {
      i += 1;
      continue;
    }
    const numberedPositions = [];
    let j = i;
    while (j < lines.length) {
      const stripped = lines[j].trim();
      // "[섹션명]"이 단독 줄이든 "[섹션명] 내용..."처럼 같은 줄에 내용이 붙든
      // 둘 다 다음 섹션의 시작으로 보고 경계를 끊는다(app.js의 parseAnalysisSections
      // 와 같은 이유 — 모델이 프롬프트의 "[섹션명] 설명" 표기를 출력 형식으로도
      // 따라할 때가 있다).
      if (stripped === "" || /^\[.+?\]/.test(stripped)) break;
      if (/^\d+\.\s/.test(lines[j])) numberedPositions.push(j);
      j += 1;
    }
    numberedPositions.forEach((pos, idx) => {
      const rest = lines[pos].replace(/^\d+\.\s/, "");
      lines[pos] = (idx + 1) + ". " + rest;
    });
    i = j;
  }
  return lines.join("\n");
}

// 같은 ref로 재분석(force)하면 기존 항목을 최신 결과로 교체한다 — 그냥 RPUSH만
// 하면 재분석마다 인사이트 목록에 같은 기사가 중복으로 쌓인다. 목록 전체를 읽어
// 걸러낸 뒤 다시 쓰는 방식이라 비용이 있지만, 목록 상한(300)이 작아 감당 가능하다.
async function upsertInsightRecord(client, record) {
  const raw = await client.lrange(INSIGHTS_LIST_KEY, 0, -1);
  const filtered = raw.filter((item) => {
    try {
      return JSON.parse(item).ref !== record.ref;
    } catch (error) {
      return true;
    }
  });
  filtered.push(JSON.stringify(record));
  const trimmed = filtered.slice(-MAX_INSIGHTS_LIST_SIZE);

  const multi = client.multi();
  multi.del(INSIGHTS_LIST_KEY);
  if (trimmed.length) multi.rpush(INSIGHTS_LIST_KEY, ...trimmed);
  await multi.exec();
}

// 분석을 끝내지 못한 요청은 하루 상한을 소모하지 않아야 한다 — 상한은 "실제로 나간
// LLM 호출"을 세려고 둔 비용 방어선인데, 실패가 카운트되면 성공은 한 건도 없이 하루치가
// 소진돼 재시도조차 막힌다(타임아웃이 반복되던 동안 실제로 이렇게 낭비됐다).
async function releaseDailySlot(client, dailyKey) {
  if (!client || !dailyKey) return;
  try {
    await client.decr(dailyKey);
  } catch (error) {
    console.error("daily count rollback failed", error);
  }
}

module.exports = async (req, res) => {
  const deadline = createDeadline(FUNCTION_BUDGET_MS);

  // 대시보드와 이 함수가 서로 다른 Vercel 프로젝트(다른 오리진)라 CORS 허용 필요
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method Not Allowed" });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (error) {
      body = {};
    }
  }
  body = body || {};

  const ref = typeof body.ref === "string" ? body.ref.trim() : "";
  const url = typeof body.url === "string" ? body.url.trim() : "";
  const title = typeof body.title === "string" ? body.title.trim().slice(0, 300) : "";
  const sourceLabel = typeof body.source_label === "string" ? body.source_label.trim().slice(0, 100) : "";
  // 대시보드가 리포트 생성 시 이미 분류해둔 값 — 어느 프롬프트 템플릿(위협형/비위협형)을
  // 쓸지 미리 결정하는 데만 쓴다. 모델이 다시 매기는 [분류] 결과(표시용 배지)와는 별개다.
  const categoryHint = typeof body.category === "string" ? body.category.trim().slice(0, 50) : "";
  // 이미 분석된 기사를 캐시 무시하고 재분석 — 프롬프트를 고친 뒤 같은 기사로 품질
  // 변화를 확인하고 싶을 때 쓴다. IP 요청 제한·하루 신규 분석 상한은 그대로
  // 적용된다(캐시 조회만 건너뛸 뿐, 진짜 LLM 호출이라 비용은 새 분석과 동일).
  const force = body.force === true;

  if (!ref || !url || !title) {
    res.status(400).json({ error: "ref, url, title이 모두 필요합니다." });
    return;
  }
  try {
    // eslint-disable-next-line no-new
    new URL(url);
  } catch (error) {
    res.status(400).json({ error: "url이 유효하지 않습니다." });
    return;
  }

  const client = getRedisClient();
  const cacheKey = "analysis:" + ref;
  // 하루 상한 카운터를 실제로 올린 경우에만 채워진다 — 실패 시 되돌릴 대상.
  let dailyKey = "";

  if (client) {
    if (!force) {
      try {
        const cached = await client.get(cacheKey);
        if (cached) {
          // 캐시 TTL이 90일이라, 이 기능 배포 전에 저장된 값은 분석 텍스트만 담긴
          // 순수 문자열이다 — JSON 파싱이 안 되면 links 없이 그 문자열 그대로 반환한다.
          try {
            const parsedCache = JSON.parse(cached);
            res.status(200).json({
              analysis: parsedCache.analysis,
              links: parsedCache.links || [],
              iocs: parsedCache.iocs || [],
              category: parsedCache.category || "",
              attack_techniques: parsedCache.attack_techniques || [],
              glossary: parsedCache.glossary || {},
              partial: parsedCache.partial === true,
              cached: true,
            });
          } catch (error) {
            res.status(200).json({ analysis: cached, links: [], iocs: [], category: "", attack_techniques: [], glossary: {}, cached: true });
          }
          return;
        }
      } catch (error) {
        console.error("analysis cache lookup failed", error);
      }
    }

    const ipLimited = await isRateLimited(client, "analyze", getClientIp(req), RATE_LIMIT, RATE_WINDOW_SECONDS);
    if (ipLimited) {
      res.status(429).json({ error: "잠시 후 다시 시도해주세요.", reason: "rate_limited" });
      return;
    }

    try {
      const key = "analysis:daily-count:" + new Date().toISOString().slice(0, 10);
      const dailyCount = await client.incr(key);
      // INCR이 성공한 뒤에야 되돌릴 대상이 생긴다 — 여기서 잡아둬야 아래 어느 경로로
      // 실패하든 소모한 한 건을 돌려놓을 수 있다.
      dailyKey = key;
      if (dailyCount === 1) await client.expire(key, 60 * 60 * 26);
      if (dailyCount > DAILY_NEW_ANALYSIS_LIMIT) {
        await releaseDailySlot(client, dailyKey);
        res.status(429).json({ error: "오늘의 분석 가능 건수를 모두 사용했습니다. 내일 다시 시도해주세요.", reason: "daily_cap" });
        return;
      }
    } catch (error) {
      console.error("daily cap check failed", error);
    }
  }

  // 단계별 소요 시간과 시도 내역 — 성공/실패 양쪽 응답에 실어 보낸다. 배포 환경에서만
  // 재현되는 지연은 이게 없으면 로그를 열기 전까지 원인을 좁힐 수 없다.
  const fetchStartedAt = Date.now();
  const { text: articleText, fullText, links } = await fetchArticleText(url, deadline);
  const fetchMs = Date.now() - fetchStartedAt;
  const attempts = [];

  function diagnostics() {
    return {
      total_ms: FUNCTION_BUDGET_MS - deadline.remaining(),
      fetch_ms: fetchMs,
      body_chars: articleText.length,
      attempts: attempts,
    };
  }

  const iocs = extractIocs(fullText);
  let analysis;
  let category;
  let attackTechniques;
  let glossary;
  let partial = false;
  try {
    const llmResult = await callNvidia(buildPrompt(title, articleText, categoryHint), deadline, attempts);
    partial = llmResult.truncated;
    const rawAnalysis = renumberLists(llmResult.content);
    const categoryExtracted = extractReportCategory(rawAnalysis);
    const glossaryExtracted = extractGlossary(categoryExtracted.analysis);
    const mitreExtracted = extractMitreTechniques(glossaryExtracted.analysis);
    analysis = mitreExtracted.analysis + (partial ? PARTIAL_ANALYSIS_NOTICE : "");
    glossary = glossaryExtracted.glossary;
    category = categoryExtracted.category;
    attackTechniques = mitreExtracted.techniques;
  } catch (error) {
    console.error("llm call failed", error);
    await releaseDailySlot(client, dailyKey);
    // 시간이 모자라 못 끝낸 것과 LLM이 오류를 낸 것은 사용자가 할 일이 다르다
    // (전자는 그냥 다시 누르면 되고, 후자는 반복해도 같을 가능성이 크다).
    const timedOut = isTimeoutError(error);
    res.status(timedOut ? 504 : 502).json({
      error: timedOut
        ? "분석 시간이 초과되었습니다. 잠시 후 다시 시도해주세요."
        : "분석 생성에 실패했습니다. 잠시 후 다시 시도해주세요.",
      reason: timedOut ? "timeout" : "llm_failed",
      detail: describeError(error),
      // 인증 실패는 코드가 아니라 환경변수 문제라, 무엇이 들어있는지 알아야 고칠 수 있다.
      key_shape: /HTTP 40[13]/.test(describeError(error)) ? describeKeyShape() : undefined,
      diagnostics: diagnostics(),
    });
    return;
  }

  if (client) {
    try {
      await client.set(
        cacheKey,
        JSON.stringify({ analysis: analysis, links: links, iocs: iocs, category: category, attack_techniques: attackTechniques, glossary: glossary, partial: partial }),
        "EX",
        partial ? PARTIAL_CACHE_TTL_SECONDS : ANALYSIS_CACHE_TTL_SECONDS
      );
    } catch (error) {
      console.error("analysis cache write failed", error);
    }

    try {
      await upsertInsightRecord(client, {
        ref: ref,
        title: title,
        url: url,
        source_label: sourceLabel,
        analysis: analysis,
        links: links,
        iocs: iocs,
        category: category,
        attack_techniques: attackTechniques,
        glossary: glossary,
        analyzed_at: new Date().toISOString(),
      });
    } catch (error) {
      console.error("insights list write failed", error);
    }
  }

  res.status(200).json({
    analysis: analysis,
    links: links,
    iocs: iocs,
    category: category,
    attack_techniques: attackTechniques,
    glossary: glossary,
    cached: false,
    // 시간이 모자라 중간에서 끊긴 결과임을 알린다 — 본문 끝에도 같은 사실을 덧붙였다.
    partial: partial,
    // 성공했을 때도 같이 보낸다 — 실패했을 때만 재면 "평소엔 몇 초였는지"라는 기준선이
    // 없어서 느려진 건지 원래 그런 건지 판단할 수 없다.
    diagnostics: diagnostics(),
  });
};
