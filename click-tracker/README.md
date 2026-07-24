# click-tracker

boannews_mail 리포트/알림 링크의 클릭을 기록하는 Vercel 서버리스 함수. 클릭 로그는
Upstash Redis에 쌓이고, 메인 프로젝트의 `scripts/click_feedback_puller.py`가 주기적으로
읽어가 `data/feedback.jsonl`에 `useful` 라벨로 기록한다.

이 디렉토리는 메인 프로젝트(boannews_mail)와 독립된 별도 배포 단위다 — Python 프로젝트와
같이 배포되지 않고, 별도로 Vercel에 배포한다.

## 배포 순서

1. **Upstash 계정 생성** — https://upstash.com (무료 티어로 충분) → Redis 데이터베이스 하나 생성
   → "REST API" 탭에서 `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` 값 확인

2. **Vercel 계정 생성** — https://vercel.com

3. **이 디렉토리를 Vercel에 배포**:
   - Vercel CLI 사용 시: `npm i -g vercel` 설치 후 이 디렉토리(`click-tracker/`)에서 `vercel deploy`
   - 또는 Vercel 대시보드에서 이 저장소를 Import하고 "Root Directory"를 `click-tracker`로 지정

4. **Vercel 프로젝트의 Environment Variables**에 Upstash 값 등록:
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`
   등록 후 재배포(redeploy) 필요

5. 배포 완료 후 발급되는 URL(예: `https://your-project.vercel.app`)을 메인 프로젝트의
   `.env`에 `CLICK_TRACK_BASE_URL=https://your-project.vercel.app`로 등록 — 이 값이 설정된
   순간부터 `common_utils.tracking_url()`이 리포트 링크를 이 서버 경유로 바꿔서 내보낸다.

6. 메인 프로젝트의 `.env`에 Upstash 값도 동일하게 등록(`click_feedback_puller.py`가 같은
   Redis를 읽어가야 함):
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`

## 동작 확인

```
curl -I "https://your-project.vercel.app/api/click?ref=test&url=https%3A%2F%2Fexample.com"
```
`302`와 `Location: https://example.com` 헤더가 보이면 정상. Upstash 대시보드의
데이터 브라우저에서 `clicks` 리스트에 항목이 쌓이는지도 확인 가능.

## 장애/설정 누락 시 동작

- `CLICK_TRACK_BASE_URL`(메인 프로젝트)이 설정 안 돼 있으면 링크는 그냥 원본 URL 그대로
  나간다(추적 없음, 에러 없음) — `tracking_url()`의 기본 동작.
- Upstash 환경변수가 이 Vercel 함수에 없으면 로깅만 건너뛰고 리다이렉트는 정상 동작한다.
- 리다이렉트 자체는 Upstash 호출 성공 여부와 무관하게 항상 수행된다 — 추적 실패가
  사용자의 열람을 막지 않는다.
