# Run from the collection operating checkout after this change is deployed.
# Registers a two-hour Telegram refresh, matching the existing X refresh.
$ErrorActionPreference = 'Stop'
$taskName = 'publish_telegram_posts'
$batch = Join-Path $PSScriptRoot 'publish_telegram_posts.bat'
if (-not (Test-Path -LiteralPath $batch)) { throw "Missing $batch" }

$action = New-ScheduledTaskAction -Execute $batch -WorkingDirectory (Split-Path -Parent $PSScriptRoot)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 2)).Repetition
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State, Actions, Triggers
