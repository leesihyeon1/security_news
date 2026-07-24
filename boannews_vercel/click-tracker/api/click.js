// 리포트/알림 링크 클릭을 기록하고 원본 URL로 리다이렉트한다.
//
// boannews_mail 프로젝트(scripts/common_utils.py의 tracking_url())가 기사 링크를
// 이 엔드포인트(/api/click?ref=<10자리 해시>&url=<원본 URL>) 경유로 바꿔서 내보내고,
// scripts/click_feedback_puller.py가 여기 쌓인 클릭 로그를 Redis에서 읽어가
// useful 피드백 라벨로 변환한다.
//
// 필요 환경변수(Vercel 프로젝트 설정 > Environment Variables, Storage 연결 시 자동 생성):
//   REDIS_URL — redis://... 형식의 네이티브 Redis 연결 문자열
// 없으면 로깅만 건너뛰고 리다이렉트는 그대로 동작한다.

const Redis = require("ioredis");

// 서버리스 함수가 재사용(warm start)될 때 연결을 재활용 — 매 요청마다 새로 연결하지 않는다.
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
  const { ref, url } = req.query;

  if (!url || typeof url !== "string") {
    res.status(400).send("Missing url parameter");
    return;
  }

  let target;
  try {
    target = decodeURIComponent(url);
    // eslint-disable-next-line no-new
    new URL(target); // 유효한 절대 URL인지 검증 — 아니면 오픈 리다이렉트 악용 방지 위해 거부
  } catch (error) {
    res.status(400).send("Invalid url parameter");
    return;
  }

  const client = getRedisClient();
  if (client && ref) {
    const record = JSON.stringify({ ref: String(ref), url: target, ts: new Date().toISOString() });
    try {
      await client.rpush("clicks", record);
    } catch (error) {
      // 로그 실패해도 사용자 리다이렉트는 반드시 진행 — 추적 실패가 열람을 막으면 안 됨
      console.error("click log failed", error);
    }
  }

  res.writeHead(302, { Location: target });
  res.end();
};
