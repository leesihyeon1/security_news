# 예약 작업이 저장소 최상위의 .bat 대신 tasks\ 폴더의 .bat을 실행하게 바꾼다.
# 실행 주기·시간 제한 등 나머지 설정은 그대로 둔다. 관리자 PowerShell에서 실행:
#   powershell -ExecutionPolicy Bypass -File "C:\Users\lsh\Downloads\dev\boannews_mail\tasks\move_tasks_to_folder.ps1"
$repo = Split-Path -Parent $PSScriptRoot
$tasks = Get-ScheduledTask | Where-Object {
  ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -match [regex]::Escape($repo)
}
foreach ($t in $tasks) {
  $a = $t.Actions[0]
  if ($a.Arguments -match '\\tasks\\') { Write-Host "이미 이동됨  $($t.TaskName)"; continue }
  if ($a.Arguments -notmatch '\\([\w]+\.bat)') { Write-Host "건너뜀      $($t.TaskName): $($a.Arguments)"; continue }
  $bat = Join-Path $PSScriptRoot $Matches[1]
  if (-not (Test-Path $bat)) { Write-Host "파일 없음   $bat" -ForegroundColor Yellow; continue }
  $action = New-ScheduledTaskAction -Execute $a.Execute -Argument "/c $bat" -WorkingDirectory $repo
  try {
    Set-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Action $action -ErrorAction Stop | Out-Null
    Write-Host "변경        $($t.TaskName) -> tasks\$($Matches[1])" -ForegroundColor Green
  } catch {
    Write-Host "실패        $($t.TaskName): $($_.Exception.Message)" -ForegroundColor Red
  }
}
