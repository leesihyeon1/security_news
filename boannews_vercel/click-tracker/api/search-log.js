// 대시보드(boannews_vercel/dashboard/) 검색창에서 입력한 검색어를 기록한다.
//
// 대시보드는 정적 사이트라 자체 서버가 없어서, click.js와 같은 Redis(REDIS_URL)를
// 재사용해 검색 이벤트를 쌓아둔다. scripts/search_log_puller.py가 여기 쌓인 로그를
// 읽어가 data/search_log.jsonl에 누적한다 — 자주 검색되는 키워드로 관심사를 파악하거나,
// 결과 0건인 검색어로 수집 공백·검색 로직 개선 지점을 찾는 데 쓴다.
//
// 필요 환경변수: REDIS_URL — click.js와 동일한 값(같은 Redis 인스턴스)을 그대로 씀.
// 없으면 로깅만 건너뛰고 204를 반환한다(검색 자체 동작에는 영향 없음).
//
// 대시보드와 이 함수가 서로 다른 Vercel 프로젝트(다른 오리진)라 브라우저의
// fetch() 호출이 CORS 프리플라이트를 거친다 — 아래서 명시적으로 허용한다.

const Redis = require("ioredis");

let redisClient = null;
function getRedisClient() {
  if (!process.env.REDIS_URL) return null;
  if (!redisClient) {
    redisClient = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 1,
      connectTimeout: 3000,
    });
    redisClient.on("error", (error) => console.error("redis client error", error));
  }
  return redisClient;
}

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "POST") {
    res.status(405).send("Method Not Allowed");
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

  const query = typeof body.query === "string" ? body.query.trim().slice(0, 200) : "";
  const resultCount = Number.isFinite(body.result_count) ? body.result_count : null;

  if (!query) {
    res.status(400).send("Missing query");
    return;
  }

  const client = getRedisClient();
  if (client) {
    const record = JSON.stringify({ query, result_count: resultCount, ts: new Date().toISOString() });
    try {
      await client.rpush("search_log", record);
    } catch (error) {
      // 로그 실패해도 검색 자체는 이미 클라이언트에서 끝난 동작이라 사용자에게 영향 없음
      console.error("search log failed", error);
    }
  }

  res.status(204).end();
};
