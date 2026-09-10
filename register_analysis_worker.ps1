# 대시보드 "심층분석" 요청을 처리하는 워커를 5분 주기 작업으로 등록한다.
#
# 왜: 심층분석을 수행하던 Vercel 함수의 모델(openai/gpt-oss-120b)이 폐기되면서
# 남은 대체 모델이 전부 60초 상한에 걸려 항상 타임아웃으로 끝났다. 이제 대시보드는
# 요청을 Redis 큐에 넣기만 하고, 시간 제한이 없는 이 PC의 워커가 실제 분석을 한다.
#
# 실행 방법: 관리자 권한 PowerShell 에서
#   powershell -ExecutionPolicy Bypass -File "C:\Users\lsh\Downloads\dev\boannews_mail\register_analysis_worker.ps1"
#
# 비밀번호·관리자 권한 없이 등록하려면(-NoPassword):
#   powershell -ExecutionPolicy Bypass -File "...\register_analysis_worker.ps1" -NoPassword
#
# 되돌리려면:
#   Unregister-ScheduledTask -TaskName 'analysis_worker' -Confirm:$false

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

$taskName = 'analysis_worker'
$bat = Join-Path $PSScriptRoot 'analysis_worker.bat'
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

$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $bat" -WorkingDirectory $PSScriptRoot

# 5분마다 무기한 반복 — 다른 5분 주기 메일러들과 같은 형태
# 10분 주기. 기사 한 건이 분석 150초 + 패턴 합성 60~150초 + 종합 판단 160초로
# 400초를 넘겨서, 5분 주기로는 회차가 겹친다. 겹침 자체는 IgnoreNew와 워커의
# 파일 잠금이 막지만, 그러면 매 회차가 그냥 버려져 큐가 늦게 빠진다.
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(1)
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 10)).Repetition

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
