# boannews_vercel

boannews_mail 프로젝트가 발행하는 웹 관련 정적/서버리스 자산 모음. 하위 폴더별로
**별도의 Vercel 프로젝트**로 배포한다(Vercel의 "Root Directory" 기능 사용) — 저장소는
하나로 관리하되 배포·환경변수는 완전히 분리된다.

## 하위 프로젝트

### `dashboard/`
일간/주간 보안 리포트를 국내/해외 탭으로 보여주는 정적 대시보드. 자세한 내용은
`dashboard/README.md` 참고. Vercel 프로젝트 설정: **Root Directory = `dashboard`**.

### `click-tracker/`
리포트 링크 클릭을 기록하고 원본 URL로 리다이렉트하는 서버리스 함수(Upstash Redis
필요, 선택사항). 자세한 내용은 `click-tracker/README.md` 참고. Vercel 프로젝트 설정:
**Root Directory = `click-tracker`**.

## Vercel 배포 시 주의

두 폴더를 각각 별도 Vercel 프로젝트로 Import해야 한다(하나의 저장소를 두 번
Import, Root Directory만 다르게 지정). 환경변수는 프로젝트 단위로 분리되므로
`click-tracker` 프로젝트에 넣은 Upstash 자격증명이 `dashboard` 프로젝트에 노출되는
일은 없다.
