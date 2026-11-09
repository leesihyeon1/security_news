# 보안뉴스 스케줄 작업 경로를 D:\dev\boannews_mail -> C:\Users\lsh\Downloads\dev\boannews_mail 로 변경
#
# 실행 방법: 관리자 권한 PowerShell 에서
#   powershell -ExecutionPolicy Bypass -File "C:\Users\lsh\Downloads\dev\boannews_mail\tasks\repoint_tasks.ps1"
#
# 작업들이 LogonType=Password 로 등록돼 있어(로그오프 상태에서도 실행되는 방식)
# 수정 시 Windows 계정 비밀번호를 한 번 다시 입력해야 한다.
# 되돌리려면 백업 XML 로 재등록:
#   Register-ScheduledTask -TaskName <이름> -Xml (Get-Content <백업>.xml -Raw) -Force
# 백업 위치: C:\Users\lsh\AppData\Local\Temp\claude\C--Users-lsh-Downloads-dev-boannews-mail\44955278-8964-45ce-b4c6-c6db6cfa39d2\scratchpad\task_backup

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] 관리자 권한으로 실행해야 합니다. PowerShell 을 '관리자 권한으로 실행' 후 다시 시도하세요." -ForegroundColor Red
    exit 1
}

$old = 'D:\dev\boannews_mail'
$new = 'C:\Users\lsh\Downloads\dev\boannews_mail'

if (-not (Test-Path $new)) {
    Write-Host "[!] 대상 경로가 없습니다: $new" -ForegroundColor Red
    exit 1
}

$names = @(
    'asec_notifier5MinMailer'
    'BoanNews5MinMailer'
    'curator_digestMailer'
    'Cve5MinMailer'
    'daily_report'
    'Kisa5MinMailer'
    'MicrosoftPatch5MinMailer'
    'publish_trending'
    'rss_collector5MinMailer'
    'slack_feedback'
    'weekly_report'
)

Write-Host "Windows 계정($env:USERNAME) 비밀번호를 입력하세요 - 작업에 저장된 자격증명을 갱신하는 용도입니다." -ForegroundColor Cyan
$cred = Get-Credential -UserName $env:USERNAME -Message '스케줄 작업 실행 계정 비밀번호'
$plain = $cred.GetNetworkCredential().Password

$ok = 0; $fail = 0
foreach ($n in $names) {
    try {
        $task = Get-ScheduledTask -TaskName $n -ErrorAction Stop

        $actions = @()
        foreach ($a in $task.Actions) {
            $exec = $a.Execute
            $arg  = $a.Arguments
            if ($exec) { $exec = $exec.Replace($old, $new) }
            if ($arg)  { $arg  = $arg.Replace($old, $new) }
            $actions += New-ScheduledTaskAction -Execute $exec -Argument $arg -WorkingDirectory $new
        }

        Set-ScheduledTask -TaskName $n -Action $actions -User $cred.UserName -Password $plain | Out-Null
        Write-Host ("[+] {0}" -f $n) -ForegroundColor Green
        $ok++
    } catch {
        Write-Host ("[-] {0} : {1}" -f $n, $_.Exception.Message) -ForegroundColor Yellow
        $fail++
    }
}

$plain = $null

Write-Host ""
Write-Host "완료: 성공 $ok / 실패 $fail" -ForegroundColor Cyan
Write-Host ""
Write-Host "--- 변경 후 상태 ---"
foreach ($n in $names) {
    $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
    if ($t) {
        foreach ($a in $t.Actions) {
            "{0,-26} {1} {2}" -f $n, $a.Execute, $a.Arguments
        }
    }
}
