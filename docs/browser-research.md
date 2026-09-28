# 격리 브라우저 조사

심층 분석은 기사별 질문 중 웹 유포·ClickFix·DOM·HTTP 질문이 있을 때 저장된
urlscan 스캔의 DOM/HTTP 관측을 질문에 연결합니다. 실제 페이지 확인이 필요한
질문은 격리 브라우저 워커가 설정된 경우 한 페이지에서 버튼 한 번의 전후 차이를
확인합니다. 결과는 `browser_research.results`, `question_lookups`,
`followup_results`, `lookup_status`에 기록됩니다. 조회가 실패하거나 실행되지
않으면 `deferred` 또는 `failed`로 남으며 미탐지로 처리하지 않습니다.

브라우저는 공개 `/api/analyze` 큐에서 들어온 URL의 JavaScript를 실제 Chromium으로
해석할 수 있습니다. 복사된 명령을 실행하거나 다운로드를 저장하지는 않지만, 브라우저
취약점·자원 고갈·외부 요청 같은 위험이 0은 아닙니다. 일회성으로 제한된 공개 페이지만
관찰한다면 최신 Chromium, 개인 프로필·인증정보 없음, 일반 사용자 권한만으로 위험을
낮출 수 있어 별도 VM이 절대 필수는 아닙니다. 워커를 상시 운영하거나 공격 캠페인 URL을
반복 분석한다면 내부망과 분리된 VM 또는 컨테이너를 권장합니다. 방화벽에서 사설망·
메타데이터 주소로 가는 연결도 차단해야 하며, 코드의 URL 검사와 빈 브라우저 프로필은
네트워크 격리를 대체하지 않습니다.

격리 워커 준비:

```powershell
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
$env:BROWSER_RESEARCH_ENABLED = '1'
$env:BROWSER_RESEARCH_ISOLATED_WORKER = '1'
python scripts/analysis_worker.py
```

`.env`에서는 아래처럼 두 값을 모두 `1`로 바꿔야 실제 브라우저 조사가 실행됩니다.
둘 중 하나라도 `0`이면 분석은 urlscan 관측까지만 남기고 브라우저 조사는 보류합니다.
`BROWSER_RESEARCH_ISOLATED_WORKER`는 VM·컨테이너 여부를 자동 검증하는 값이 아니라,
운영자가 격리된 워커에서 실행한다는 확인용 안전 게이트입니다.

```dotenv
BROWSER_RESEARCH_ENABLED = "1"
BROWSER_RESEARCH_ISOLATED_WORKER = "1"
```

작업 스케줄러 등 기존 워커 구동 방식에서 위 두 변수를 격리 워커에만 설정합니다.
한 분석에서 브라우저 대상은 최대 한 페이지입니다. 클립보드에 복사하려는 텍스트는
실행하지 않고 길이·해시·행위 표식만 공개 결과에 남깁니다. HTTP 쿼리 값은
버리고 키만 기록합니다. 원본 증거가 필요한 분석가는 urlscan 결과 링크와
격리 환경의 브라우저 기록을 대조해야 합니다.

`scripts/browser_research.py`는 Playwright Python을 직접 호출합니다. MCP는
추후 여러 조사 도구를 같은 호출 형식으로 연결할 때 감쌀 수 있지만, 현재
워커 실행에는 필요하지 않습니다.
