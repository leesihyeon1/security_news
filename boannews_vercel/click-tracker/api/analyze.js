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
// 필요 환경변수(이 click-tracker Vercel 프로젝트에 별도로 등록 필요 — boannews_mail의
// 로컬 .env와는 무관):
//   REDIS_URL — click.js와 동일한 값
//   NVIDIA_API_KEY — NVIDIA NIM API 키(scripts/common_utils.py의 _generate_nvidia와 동일 API)
//   NVIDIA_MODEL — 선택, 기본값은 boannews_mail 쪽과 동일

const Redis = require("ioredis");
const { isRateLimited, getClientIp } = require("../lib/redisGuards");

const RATE_LIMIT = 5; // IP당 1분에 5건까지 "신규"(캐시 미스) 분석 요청
const RATE_WINDOW_SECONDS = 60;
const DAILY_NEW_ANALYSIS_LIMIT = 20;
const ANALYSIS_CACHE_TTL_SECONDS = 60 * 60 * 24 * 90; // 90일 — 사실상 영구 수준이되 Redis가 무한정 자라진 않게
const BODY_MAX_CHARS = 6000;
const FETCH_TIMEOUT_MS = 10000;
const MAX_EXTRACTED_LINKS = 6;
// 소셜 공유·메신저·앵커 등 본문 참고자료로서 의미 없는 링크는 후보에서 제외한다.
const NOISE_LINK_PATTERN = /facebook\.com|twitter\.com|x\.com\/|linkedin\.com|t\.me\/|wa\.me\/|whatsapp\.com|pinterest\.com|reddit\.com\/submit|mailto:|javascript:/i;

const NVIDIA_API_URL = process.env.NVIDIA_API_URL || "https://integrate.api.nvidia.com/v1/chat/completions";
const NVIDIA_MODEL = process.env.NVIDIA_MODEL || "nvidia/nemotron-3-ultra-550b-a55b";

let redisClient = null;
function getRedisClient() {
  if (!process.env.REDIS_URL) return null;
  if (!redisClient) {
    redisClient = new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 1, connectTimeout: 3000 });
    redisClient.on("error", (error) => console.error("redis client error", error));
  }
  return redisClient;
}

function stripHtml(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// 원문 HTML의 <a href> 중 본문 참고자료로 볼 만한 것만 결정적으로(LLM 없이) 추출한다.
// LLM이 "참고 자료가 있다"고 말만 하고 실제 링크는 안 주는 문제를 막기 위한 것 —
// 원문에 실재하는 링크만 그대로 복사하므로 지어낼 여지가 없다.
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
    if (!/^https?:\/\//i.test(resolved) || seen.has(resolved)) continue;

    const text = stripHtml(match[2]).trim().slice(0, 120);
    if (!text) continue;

    seen.add(resolved);
    links.push({ url: resolved, text: text });
  }
  return links;
}

// body_selector 같은 사이트별 설정 없이 범용으로 시도 — boannews_mail의
// fetch_article_body()가 <article> 태그로 폴백하는 것과 같은 수준의 best-effort.
async function fetchArticleText(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; boannews-analyzer/1.0)" },
      signal: controller.signal,
    });
    if (!response.ok) return { text: "", links: [] };
    const html = await response.text();
    return { text: stripHtml(html).slice(0, BODY_MAX_CHARS), links: extractArticleLinks(html, url) };
  } catch (error) {
    console.error("article fetch failed", error);
    return { text: "", links: [] };
  } finally {
    clearTimeout(timer);
  }
}

function buildPrompt(title, body) {
  return (
    "당신은 SOC 보안관제 조직의 위협 인텔리전스 분석가이다. 아래 보안 기사를 심층 분석해 " +
    "한국어 존댓말로 작성하라.\n\n" +
    "제목: " + title + "\n\n" +
    "본문:\n" + (body || "(본문을 가져오지 못해 제목만으로 분석합니다.)") + "\n\n" +
    "출력 형식(반드시 아래 4개 섹션만 사용하고, 이 외의 섹션을 임의로 추가하지 마라):\n" +
    "[핵심 요약] 2~3문장\n" +
    "[기술적 세부사항] 공격 기법·취약점·IOC 등 본문에 있는 구체적 정보 위주로 서술\n" +
    "[영향 범위 및 위험도] 무엇이 왜 위험한지. CVSS 점수나 심각도 등급은 본문에 명시적으로 나온 " +
    "경우에만 그대로 인용하고, 본문에 없으면 추정치를 지어내지 말고 심각도 자체를 언급하지 마라.\n" +
    "[권장 대응] 실무자가 바로 할 수 있는 구체적 행동 2~3개\n\n" +
    "주의: 본문에 없는 사실을 지어내지 마라. 본문이 부실하면 그 사실을 그대로 밝혀라."
  );
}

async function callNvidia(prompt) {
  if (!process.env.NVIDIA_API_KEY) throw new Error("NVIDIA_API_KEY 미설정");
  const response = await fetch(NVIDIA_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + process.env.NVIDIA_API_KEY,
    },
    body: JSON.stringify({
      model: NVIDIA_MODEL,
      messages: [{ role: "user", content: prompt }],
      temperature: 0.2,
      max_tokens: 2048,
      stream: false,
    }),
  });
  if (!response.ok) throw new Error("HTTP " + response.status);
  const data = await response.json();
  const content = data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
  if (!content) throw new Error("빈 응답");
  return content.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
}

module.exports = async (req, res) => {
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

  if (client) {
    try {
      const cached = await client.get(cacheKey);
      if (cached) {
        // 캐시 TTL이 90일이라, 이 기능 배포 전에 저장된 값은 분석 텍스트만 담긴
        // 순수 문자열이다 — JSON 파싱이 안 되면 links 없이 그 문자열 그대로 반환한다.
        try {
          const parsedCache = JSON.parse(cached);
          res.status(200).json({ analysis: parsedCache.analysis, links: parsedCache.links || [], cached: true });
        } catch (error) {
          res.status(200).json({ analysis: cached, links: [], cached: true });
        }
        return;
      }
    } catch (error) {
      console.error("analysis cache lookup failed", error);
    }

    const ipLimited = await isRateLimited(client, "analyze", getClientIp(req), RATE_LIMIT, RATE_WINDOW_SECONDS);
    if (ipLimited) {
      res.status(429).json({ error: "잠시 후 다시 시도해주세요." });
      return;
    }

    try {
      const dailyKey = "analysis:daily-count:" + new Date().toISOString().slice(0, 10);
      const dailyCount = await client.incr(dailyKey);
      if (dailyCount === 1) await client.expire(dailyKey, 60 * 60 * 26);
      if (dailyCount > DAILY_NEW_ANALYSIS_LIMIT) {
        res.status(429).json({ error: "오늘의 분석 가능 건수를 모두 사용했습니다. 내일 다시 시도해주세요." });
        return;
      }
    } catch (error) {
      console.error("daily cap check failed", error);
    }
  }

  const { text: articleText, links } = await fetchArticleText(url);
  let analysis;
  try {
    analysis = await callNvidia(buildPrompt(title, articleText));
  } catch (error) {
    console.error("llm call failed", error);
    res.status(502).json({ error: "분석 생성에 실패했습니다. 잠시 후 다시 시도해주세요." });
    return;
  }

  if (client) {
    try {
      await client.set(cacheKey, JSON.stringify({ analysis: analysis, links: links }), "EX", ANALYSIS_CACHE_TTL_SECONDS);
    } catch (error) {
      console.error("analysis cache write failed", error);
    }
  }

  res.status(200).json({ analysis: analysis, links: links, cached: false });
};
