# click-tracker

boannews_mail 리포트/알림 링크의 클릭과, `../dashboard/` 검색창 검색어를 기록하는
Vercel 서버리스 함수 모음(`api/click.js`, `api/search-log.js`). 둘 다 같은 Redis에
쌓이고, 메인 프로젝트의 `scripts/click_feedback_puller.py` / `scripts/search_log_puller.py`가
주기적으로 읽어가 각각 `data/feedback.jsonl`(`useful` 라벨) / `data/search_log.jsonl`에
기록한다.

`api/analyze.js`는 성격이 다르다 — 대시보드 인사이트/추천기사 탭의 "심층분석 보기"
버튼이 호출하며, 기사 원문을 서버에서 다시 가져와 LLM으로 분석해 반환한다(Redis
기록용이 아니라 즉시 응답하는 API). 자세한 설정은 아래 "심층분석(analyze.js)" 절 참고.

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

## 요청 제한·리스트 크기 상한 (`lib/redisGuards.js`)

IP당 요청 빈도 제한(`click.js` 분당 60회, `search-log.js` 분당 30회)과, `clicks`/
`search_log` Redis 리스트 길이 상한(5000건)을 둔다 — 스팸성 요청이나 풀러가 오래
안 도는 상황에서도 Redis가 무한정 커지지 않게 하는 안전장치다. `click.js`는 제한에
걸려도 로깅만 건너뛰고 **리다이렉트는 항상 수행**한다(추적 실패가 열람을 막으면 안
됨). `search-log.js`는 제한에 걸리면 `429`를 반환하는데, 클라이언트(`app.js`)가
어차피 실패를 조용히 무시하므로 사용자 경험에는 영향 없다.

## 심층분석(`api/analyze.js`)

대시보드가 정적 사이트라 title/summary만 갖고 있어서, 이 함수가 기사 URL을 서버에서
다시 가져와 LLM(NVIDIA NIM API)으로 심층 분석한 뒤 반환한다. 공개 엔드포인트라
아무나 호출할 수 있다는 전제로 비용을 세 겹으로 통제한다:

1. **영구에 가까운 캐싱** — 같은 기사(ref)는 한 번 분석되면 결과를 90일간 Redis에
   저장해두고 재사용한다. 같은 기사를 몇 명이 눌러도 LLM 호출은 한 번만 나간다 —
   가장 큰 비용 방어선.
2. **IP당 요청 제한** — 캐시 미스(=실제 LLM 호출로 이어지는 요청)에만 분당 5회 적용.
3. **하루 총 "신규" 분석 건수 상한**(기본 20건) — 여러 사람이 동시에 서로 다른 기사를
   눌러도 하루 최대 비용이 예측 가능한 선에서 막히는 최종 방어선.

세 장치 다 Redis가 없거나 장애면 통과시킨다(다른 함수들과 같은 fail-open 철학)지만,
이 경우 비용 방어가 전혀 없어지므로 **`REDIS_URL`은 필수로 설정할 것**.

### 필요 환경변수 (이 Vercel 프로젝트에 추가 등록)

- `REDIS_URL` — 위 `click.js`와 동일한 값
- `NVIDIA_API_KEY` — NVIDIA NIM API 키. 메인 프로젝트(`scripts/common_utils.py`)가
  쓰는 키를 그대로 써도 되고, 이 공개 엔드포인트 전용으로 별도 발급받아 사용량을
  분리 추적해도 된다.
- `NVIDIA_MODEL` — 선택. 기본값은 메인 프로젝트와 동일(`nvidia/nemotron-3-ultra-550b-a55b`)

### 동작 확인

```
curl -X POST "https://your-project.vercel.app/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{"ref":"test1234ab","url":"https://example.com/article","title":"테스트 기사"}'
```
`{"analysis": "...", "cached": false}`가 오면 정상(첫 호출은 LLM을 실제로 부르므로
몇 초 걸릴 수 있음). 같은 요청을 한 번 더 보내면 `"cached": true`로 즉시 응답돼야 함.
