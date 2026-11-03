# GitHub Security Advisory(고위험·치명) 수집기를 1시간 주기 작업으로 등록한다.
#
# 왜: 수집 스크립트는 정상인데 예약 작업이 등록되지 않아 2026-06-16 이후 한 번도 돌지
# 않았다(이벤트 0건). 한 번에 최신 권고 100건(약 6일치)을 받으므로 1시간이면 충분하고,
# 인증 없는 GitHub API 한도(시간당 60회)에도 여유가 있다.
#
# 실행 방법: 관리자 권한 PowerShell 에서
#   powershell -ExecutionPolicy Bypass -File "C:\Users\lsh\Downloads\dev\boannews_mail\tasks\register_github_advisory.ps1"
#
# 비밀번호 없이 등록하려면 -NoPassword 를 붙인다(설명은 register_analysis_worker.ps1 참고).
#
# 되돌리려면:
#   Unregister-ScheduledTask -TaskName 'GithubAdvisoryMailer' -Confirm:$false

param(
    # 비밀번호 없이 등록한다(LogonType=S4U). 관리자 권한도 필요 없다 — 대신 작업이
    # 최고 권한(RunLevel=Highest)으로 돌지 않는다. 이 워커는 python으로 네트워크·
    # Redis만 쓰므로 승격이 필요 없어서 기능상 차이가 없다. S4U는 다른 메일러들의
    # LogonType=Password와 마찬가지로 로그오프 상태에서도 실행된다.
    [switch]$NoPassword
)

$ErrorActionPreference = 'Stop'

if (-not $NoPassword) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[!] 관리자 권한으로 실행해야 합니다(또는 -NoPassword 로 실행)." -ForegroundColor Red
        exit 1
    }
}

$taskName = 'GithubAdvisoryMailer'
$bat = Join-Path $PSScriptRoot 'github_advisory.bat'
if (-not (Test-Path $bat)) {
    Write-Host "[!] $bat 이 없습니다." -ForegroundColor Red
    exit 1
}

$cred = $null
$plain = $null
if (-not $NoPassword) {
    Write-Host "Windows 계정($env:USERNAME) 비밀번호를 입력하세요 - 다른 작업들과 같은 방식(로그오프 상태에서도 실행)으로 등록합니다." -ForegroundColor Cyan
    $cred = Get-Credential -UserName $env:USERNAME -Message '스케줄 작업 실행 계정 비밀번호'
    $plain = $cred.GetNetworkCredential().Password
}

$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $bat" -WorkingDirectory (Split-Path -Parent $PSScriptRoot)

# 1시간마다 무기한 반복
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(7)
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 1)).Repetition

# 한 회차가 길어져도 다음 회차가 겹쳐 돌지 않게(IgnoreNew), 그리고 행이 걸려도
# 1시간이면 강제 종료되도록 — 다른 작업들과 같은 정책이다.
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) -StartWhenAvailable

try {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "[*] 기존 작업을 제거하고 새로 등록합니다."
    }
    if ($NoPassword) {
        # S4U(로그오프 상태에서도 실행)는 비밀번호는 필요 없지만 등록 자체에 관리자
        # 권한이 필요하다("Access is denied."). 승격 없이 실행된 경우 Interactive로
        # 내려서 등록한다 — 이건 로그온 중일 때만 돌지만 권한 없이 등록된다.
        try {
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Limited
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Settings $settings -Principal $principal | Out-Null
        } catch {
            Write-Host "[!] S4U 등록 실패($($_.Exception.Message)) - Interactive로 등록합니다." -ForegroundColor Yellow
            Write-Host "    주의: 로그오프 상태에서는 실행되지 않습니다. 로그오프에서도 돌려면" -ForegroundColor Yellow
            Write-Host "    관리자 권한 PowerShell에서 -NoPassword 없이 다시 실행하세요." -ForegroundColor Yellow
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Settings $settings -Principal $principal | Out-Null
        }
    } else {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -User $cred.UserName -Password $plain -RunLevel Highest | Out-Null
    }
    Write-Host "[+] $taskName 등록 완료" -ForegroundColor Green
} catch {
    Write-Host "[-] 등록 실패: $($_.Exception.Message)" -ForegroundColor Yellow
    exit 1
} finally {
    $plain = $null
}

$info = Get-ScheduledTaskInfo -TaskName $taskName
$task = Get-ScheduledTask -TaskName $taskName
Write-Host ""
Write-Host "--- 등록 결과 ---"
"{0,-22} {1}" -f 'action', ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" })
"{0,-22} {1}" -f 'repeat', ($task.Triggers | ForEach-Object { $_.Repetition.Interval })
"{0,-22} {1}" -f 'ExecutionTimeLimit', $task.Settings.ExecutionTimeLimit
"{0,-22} {1}" -f 'NextRunTime', $info.NextRunTime
