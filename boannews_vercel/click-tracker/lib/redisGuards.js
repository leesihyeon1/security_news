// click.js / search-log.js가 공유하는 두 가지 안전장치.
//
// 1) isRateLimited: IP별 요청 빈도 제한. 서버리스라 인스턴스 간 메모리 공유가 안 되므로
//    카운터를 Redis에 둔다(INCR + 첫 호출에만 EXPIRE). Redis 자체가 안 되거나 IP를
//    못 구하면 그냥 통과시킨다 — 제한 기능 장애가 서비스 자체를 막으면 안 된다.
// 2) capList: RPUSH 직후 LTRIM으로 리스트 길이를 상한 이하로 유지한다. 풀러가 한동안
//    안 돌아도(예: 그 서버가 꺼져있었다든지) Redis에 무한정 쌓이는 걸 막는 하한선이다
//    (풀러의 정상 동작 자체는 이 상한보다 훨씬 작은 배치 단위로 이미 처리한다).

async function isRateLimited(redisClient, keyPrefix, ip, limit, windowSeconds) {
  if (!redisClient || !ip) return false;
  const key = "ratelimit:" + keyPrefix + ":" + ip;
  try {
    const count = await redisClient.incr(key);
    if (count === 1) {
      await redisClient.expire(key, windowSeconds);
    }
    return count > limit;
  } catch (error) {
    console.error("rate limit check failed", error);
    return false;
  }
}

async function capList(redisClient, listKey, maxSize) {
  if (!redisClient) return;
  try {
    await redisClient.ltrim(listKey, -maxSize, -1);
  } catch (error) {
    console.error("list cap failed", error);
  }
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return String(forwarded).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "";
}

module.exports = { isRateLimited, capList, getClientIp };
