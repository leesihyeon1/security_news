# click-tracker

boannews_mail 리포트/알림 링크의 클릭을 기록하는 Vercel 서버리스 함수. 클릭 로그는
Upstash Redis에 쌓이고, 메인 프로젝트의 `scripts/click_feedback_puller.py`가 주기적으로
읽어가 `data/feedback.jsonl`에 `useful` 라벨로 기록한다.

`boannews_vercel` 저장소 안의 하위 프로젝트 중 하나다(다른 하나는 `../dashboard/`).
같은 저장소를 공유하지만 **완전히 별도의 Vercel 프로젝트**로 배포한다(Root Directory
설정으로 구분) — 환경변수도 프로젝트별로 분리되므로 여기 등록한 Upstash 자격증명이
dashboard 쪽에 노출되지 않는다. 저장소 최상위 구조는 `../README.md` 참고.

## 배포 순서

1. **Upstash 계정 생성** — https://upstash.com (무료 티어로 충분) → Redis 데이터베이스 하나 생성
   → "REST API" 탭에서 `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` 값 확인

2. **Vercel 계정 생성** — https://vercel.com

3. **`boannews_vercel` 저장소를 Vercel에 (dashboard와는 별개로 한 번 더) Import**하고
   프로젝트 설정에서 **Root Directory = `click-tracker`** 지정

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
