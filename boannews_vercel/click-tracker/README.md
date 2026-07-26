# click-tracker

boannews_mail 리포트/알림 링크의 클릭과, `../dashboard/` 검색창 검색어를 기록하는
Vercel 서버리스 함수 모음(`api/click.js`, `api/search-log.js`). 둘 다 같은 Redis에
쌓이고, 메인 프로젝트의 `scripts/click_feedback_puller.py` / `scripts/search_log_puller.py`가
주기적으로 읽어가 각각 `data/feedback.jsonl`(`useful` 라벨) / `data/search_log.jsonl`에
기록한다.

`boannews_vercel` 저장소 안의 하위 프로젝트 중 하나다(다른 하나는 `../dashboard/`).
같은 저장소를 공유하지만 **완전히 별도의 Vercel 프로젝트**로 배포한다(Root Directory
설정으로 구분) — 환경변수도 프로젝트별로 분리되므로 여기 등록한 Redis 자격증명이
dashboard 쪽에 노출되지 않는다. 저장소 최상위 구조는 `../README.md` 참고.

Redis 클라이언트로 [ioredis](https://github.com/redis/ioredis)를 쓴다(네이티브
Redis 프로토콜, REST API 아님) — `package.json`에 의존성으로 등록돼 있어 Vercel이
배포 시 자동으로 설치한다.

## 배포 순서

1. **Redis 준비** — 둘 중 하나:
   - Vercel 대시보드 → 이 프로젝트(생성 후) → **Storage** 탭 → Redis 스토리지 생성 →
     프로젝트에 Connect(환경변수 자동 등록됨)
   - 또는 [Upstash](https://upstash.com)/Redis Cloud 등에서 직접 만들어 연결 문자열
     (`redis://default:<password>@<host>:<port>`) 발급받기

2. **Vercel 계정 생성** — https://vercel.com (아직 없으면)

3. **`boannews_vercel` 저장소를 Vercel에 (dashboard와는 별개로 한 번 더) Import**하고
   프로젝트 설정에서 **Root Directory = `click-tracker`** 지정

4. **`REDIS_URL` 환경변수 확인**: 1번에서 Vercel Storage로 만들었다면 Connect 시 자동
   등록됨. 직접 만들었다면 Environment Variables에 `REDIS_URL=redis://...` 수동 등록
   후 재배포(redeploy)

5. 배포 완료 후 발급되는 URL(예: `https://your-project.vercel.app`)을 메인 프로젝트의
   `.env`에 `CLICK_TRACK_BASE_URL=https://your-project.vercel.app`로 등록 — 이 값이 설정된
   순간부터 `common_utils.tracking_url()`이 리포트 링크를 이 서버 경유로 바꿔서 내보낸다.

6. 메인 프로젝트의 `.env`에도 **같은** `REDIS_URL` 값을 등록(`click_feedback_puller.py`가
   같은 Redis를 읽어가야 함).

## 동작 확인

```
curl -I "https://your-project.vercel.app/api/click?ref=test&url=https%3A%2F%2Fexample.com"
```
`302`와 `Location: https://example.com` 헤더가 보이면 정상. Redis 대시보드(Vercel
Storage든 Upstash든)에서 `clicks` 리스트에 항목이 쌓이는지도 확인 가능.

```
curl -X POST "https://your-project.vercel.app/api/search-log" \
  -H "Content-Type: application/json" \
  -d '{"query":"test","result_count":3}'
```
`204`면 정상. Redis `search_log` 리스트에 항목이 쌓이는지 확인 가능.

## 장애/설정 누락 시 동작

- `CLICK_TRACK_BASE_URL`(메인 프로젝트)이 설정 안 돼 있으면 링크는 그냥 원본 URL 그대로
  나간다(추적 없음, 에러 없음) — `tracking_url()`의 기본 동작.
- `REDIS_URL`이 이 Vercel 함수에 없으면 로깅만 건너뛰고 리다이렉트는 정상 동작한다.
- 리다이렉트 자체는 Redis 호출 성공 여부와 무관하게 항상 수행된다 — 추적 실패가
  사용자의 열람을 막지 않는다.
- `api/search-log.js`도 `REDIS_URL` 없으면 조용히 204만 반환(검색 자체엔 영향 없음).
