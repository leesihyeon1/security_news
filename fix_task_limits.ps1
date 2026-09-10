# 스케줄 작업의 ExecutionTimeLimit(실행 시간 제한)을 현실적인 값으로 낮춘다.
#
# 왜: 전 작업이 기본값 PT72H(3일)로 걸려 있다. 한 번 멈추면(네트워크 행, LLM 응답
# 무한 대기 등) MultipleInstances=IgnoreNew 때문에 이후 실행이 전부 스킵되어
# 최대 3일간 조용히 죽는다. 실제로 대시보드 발행이 스테일 락으로 5일, 보안뉴스
# 메일러가 죽은 피드로 10일 방치된 전례가 있다.
# 제한을 걸어두면 행이 걸린 실행이 강제 종료되고 다음 주기에 자동 복구된다.
#
# 실행 방법: 관리자 권한 PowerShell 에서
#   powershell -ExecutionPolicy Bypass -File "C:\Users\lsh\Downloads\dev\boannews_mail\fix_task_limits.ps1"
#
# 되돌리려면 백업 XML 로 재등록:
#   Register-ScheduledTask -TaskName <이름> -Xml (Get-Content <백업>.xml -Raw) -Force

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] 관리자 권한으로 실행해야 합니다." -ForegroundColor Red
    exit 1
}

# 주기 실행형은 1시간, 리포트/집계형은 LLM 작업이 길어 4시간
$limits = @{
    'asec_notifier5MinMailer'  = 'PT1H'
    'BoanNews5MinMailer'       = 'PT1H'
    'Cve5MinMailer'            = 'PT1H'
    'Kisa5MinMailer'           = 'PT1H'
    'MicrosoftPatch5MinMailer' = 'PT1H'
    'rss_collector5MinMailer'  = 'PT1H'
    'publish_trending'         = 'PT1H'
    'curator_digestMailer'     = 'PT4H'
    'daily_report'             = 'PT4H'
    'weekly_report'            = 'PT4H'
    'slack_feedback'           = 'PT4H'
}

Write-Host "Windows 계정($env:USERNAME) 비밀번호를 입력하세요 - 작업에 저장된 자격증명을 갱신하는 용도입니다." -ForegroundColor Cyan
$cred = Get-Credential -UserName $env:USERNAME -Message '스케줄 작업 실행 계정 비밀번호'
$plain = $cred.GetNetworkCredential().Password

$ok = 0; $fail = 0
foreach ($name in $limits.Keys | Sort-Object) {
    try {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop
        $before = $task.Settings.ExecutionTimeLimit
        $task.Settings.ExecutionTimeLimit = $limits[$name]

        Set-ScheduledTask -TaskName $name -Settings $task.Settings -User $cred.UserName -Password $plain | Out-Null
        Write-Host ("[+] {0,-26} {1} -> {2}" -f $name, $before, $limits[$name]) -ForegroundColor Green
        $ok++
    } catch {
        Write-Host ("[-] {0,-26} {1}" -f $name, $_.Exception.Message) -ForegroundColor Yellow
        $fail++
    }
}

# publish_trending 만 로그 리다이렉트 없이 등록돼 있어 출력이 전부 버려진다.
# 이번에 git 자격증명 대기로 멈췄을 때 아무 흔적도 안 남은 이유다 -
# 다른 작업들처럼 .bat 경유로 바꿔 logs\publish_trending_run_log.txt 에 남긴다.
try {
    $bat = Join-Path $PSScriptRoot 'publish_trending.bat'
    if (Test-Path $bat) {
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $bat" -WorkingDirectory $PSScriptRoot
        Set-ScheduledTask -TaskName 'publish_trending' -Action $action -User $cred.UserName -Password $plain | Out-Null
        Write-Host "[+] publish_trending -> $bat (로그 기록 추가)" -ForegroundColor Green
    } else {
        Write-Host "[-] publish_trending.bat 이 없어 건너뜁니다" -ForegroundColor Yellow
    }
} catch {
    Write-Host ("[-] publish_trending 액션 변경 실패: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

$plain = $null

Write-Host ""
Write-Host "완료: 성공 $ok / 실패 $fail" -ForegroundColor Cyan
Write-Host ""
Write-Host "--- 변경 후 ---"
foreach ($name in $limits.Keys | Sort-Object) {
    $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($t) { "{0,-26} {1}" -f $name, $t.Settings.ExecutionTimeLimit }
}
