# dashboard

일간/주간 보안 인텔리전스 리포트를 국내/해외 탭으로 보여주는 정적 대시보드.
빌드 스텝 없는 순수 HTML/CSS/JS라 Vercel에 그대로 배포하면 된다.

`boannews_vercel` 저장소 안의 하위 프로젝트 중 하나다(다른 하나는 `../click-tracker/`).
저장소 최상위 구조는 `../README.md` 참고.

데이터는 boannews_mail 프로젝트(`scripts/generate_report.py` → `scripts/publish_web_dashboard.py`)가
리포트 생성 직후 이 폴더의 `data/daily-latest.json` / `data/weekly-latest.json`을 갱신하고
커밋·푸시하는 방식으로 갱신된다 — 이 폴더 자체는 그 데이터를 읽어서 그리기만 한다.

## 구조

```
index.html        메인 페이지
assets/style.css   스타일(라이트/다크 모드 자동 대응)
assets/app.js      데이터 fetch + 렌더링(빌드 불필요, 바닐라 JS)
data/
  daily-latest.json    일간 리포트 최신본
  weekly-latest.json   주간 리포트 최신본
  daily-YYYY-MM-DD.json   히스토리(발행할 때마다 누적)
vercel.json        /data/*.json 캐시 무효화 헤더
```

지금 `data/`에 들어있는 JSON은 실제 파이프라인 스키마와 동일하게 생성한 예시 데이터다 —
처음 배포했을 때 빈 화면이 아니라 바로 동작하는 모습을 보기 위한 것. 실제 첫 리포트가
발행되면 덮어써진다.

## 배포

1. `boannews_vercel` 저장소를 Vercel에 Import
2. 프로젝트 설정에서 **Root Directory = `dashboard`** 지정(다른 설정은 불필요 — 정적 파일 그대로 서빙)
3. boannews_mail 프로젝트의 `.env`에 `WEB_DASHBOARD_REPO_PATH`를 **`boannews_vercel` 저장소의
   로컬 clone 경로**(이 폴더가 아니라 그 한 단계 위, 저장소 루트)로 설정
   — 리포트 생성 스크립트가 `<그 경로>/dashboard/data`에 파일을 쓰고 git commit/push까지 수행한다

## 데이터 스키마

`scripts/generate_report.py`의 `build_dashboard_payload()`가 만드는 형태 그대로다:

```jsonc
{
  "title": "일간 보안 인텔리전스 리포트",
  "period": "daily" | "weekly",
  "period_label": "2026-07-24 09:00 ~ 2026-07-25 09:00 (UTC)",
  "generated_at": "2026-07-25T09:00:00Z",
  "narrative": "AI 총평 텍스트",
  "stats": { "total": 24, "p1": 1, "p2": 2, "critical": 1, "kev": 1, "ransomware": 1, "by_source": {"asec": 5, ...} },
  "cards": [ /* CVE 상관관계 카드 — 국내/해외 구분 없음(카드 하나에 여러 소스 섞여 있을 수 있어서) */ ],
  "domestic": { "highlights": [...], "trend_reads": [...] },
  "overseas": { "highlights": [...], "trend_reads": [...] }
}
```

기사 항목(`highlights`/`trend_reads`) 공통 필드: `title`, `url`(설정된 경우 클릭추적
서버 경유), `source`, `source_label`, `level`("P1"/"P2"/""), `category`, `published_at`,
`summary`.

**의도적으로 빼는 정보** — 둘 다 조직 내부 정보라 이 공개 가능 사이트에는 안 담는다
(이메일/슬랙/텍스트 리포트는 내부용이라 그대로 보여줌. 매칭 로직 자체는 전혀 안 바뀜,
여기서 직렬화만 안 함):
- `matched_assets`(자사 보유 자산·제품 매칭 결과) — 어떤 제품을 보유하는지 노출 방지.
  CVE 카드의 `severity_bits`도 자산매칭 문구를 뺀 버전. `stats.asset_hits`(건수)도
  같은 이유로 뺀다 — 숫자만으로도 "자산 인벤토리를 추적한다"는 사실이 드러나므로
- `pir_groups`/`pir_gaps`(우선 정보 요구사항 매칭) — 조직이 무엇을 우선순위로 보는지
  (예: 특정 산업 표적 위협 추적 여부) 노출 방지
