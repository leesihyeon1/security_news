// 리포트/알림 링크 클릭을 기록하고 원본 URL로 리다이렉트한다.
//
// boannews_mail 프로젝트(scripts/common_utils.py의 tracking_url())가 기사 링크를
// 이 엔드포인트(/api/click?ref=<10자리 해시>&url=<원본 URL>) 경유로 바꿔서 내보내고,
// scripts/click_feedback_puller.py가 여기 쌓인 클릭 로그를 Upstash에서 읽어가
// useful 피드백 라벨로 변환한다.
//
// 필요 환경변수(Vercel 프로젝트 설정 > Environment Variables):
//   UPSTASH_REDIS_REST_URL
//   UPSTASH_REDIS_REST_TOKEN
// 없으면 로깅만 건너뛰고 리다이렉트는 그대로 동작한다.

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

  const restUrl = process.env.UPSTASH_REDIS_REST_URL;
  const restToken = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (restUrl && restToken && ref) {
    const record = JSON.stringify({ ref: String(ref), url: target, ts: new Date().toISOString() });
    try {
      await fetch(restUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${restToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(["RPUSH", "clicks", record]),
      });
    } catch (error) {
      // 로그 실패해도 사용자 리다이렉트는 반드시 진행 — 추적 실패가 열람을 막으면 안 됨
      console.error("click log failed", error);
    }
  }

  res.writeHead(302, { Location: target });
  res.end();
};
