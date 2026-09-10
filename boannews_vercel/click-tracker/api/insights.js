// 심층분석(analyze.js) 결과를 모든 방문자가 함께 보는 서버 저장 목록으로 반환한다.
// 예전엔 state.insightHistory가 브라우저 메모리에만 있어 새로고침하면 사라졌는데,
// analyze.js가 새로 분석할 때마다 INSIGHTS_LIST_KEY에 같이 적어두는 걸(RPUSH+LTRIM)
// 여기서 읽어 대시보드 로드 시 인사이트 탭/사이드바를 채운다.
const Redis = require("ioredis");

const INSIGHTS_LIST_KEY = "insights:list";

let redisClient = null;
function getRedisClient() {
  if (!process.env.REDIS_URL) return null;
  if (!redisClient) {
    redisClient = new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 1, connectTimeout: 3000 });
    redisClient.on("error", (error) => console.error("redis client error", error));
  }
  return redisClient;
}

module.exports = async (req, res) => {
  // 대시보드와 이 함수가 서로 다른 Vercel 프로젝트(다른 오리진)라 CORS 허용 필요
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "GET") {
    res.status(405).json({ error: "Method Not Allowed" });
    return;
  }

  const client = getRedisClient();
  if (!client) {
    res.status(200).json({ insights: [] });
    return;
  }

  try {
    // RPUSH로 뒤에 쌓이므로 최신순으로 보이게 뒤집어서 반환한다.
    const raw = await client.lrange(INSIGHTS_LIST_KEY, 0, -1);
    const insights = raw
      .map((item) => {
        try {
          return JSON.parse(item);
        } catch (error) {
          return null;
        }
      })
      .filter(Boolean)
      .reverse();
    res.status(200).json({ insights: insights });
  } catch (error) {
    console.error("insights list read failed", error);
    res.status(200).json({ insights: [] });
  }
};
