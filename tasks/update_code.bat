@echo off
rem Keep this (operational) checkout on the latest main.
rem publish_trending.bat runs a temp copy of this file as its last step
rem (every 30 minutes), passing the repository root. A copy, because
rem cmd reads a running .bat line by line and the update may rewrite it.
rem Only fast-forwards: it never merges, and it skips the update when the
rem folder is not on main or has uncommitted edits to tracked files.
if "%~1"=="" (cd /d "%~dp0..") else (cd /d "%~1")
if not exist "logs" mkdir "logs"
set "LOG=logs\update_code_log.txt"

for /f %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"
if /i not "%BRANCH%"=="main" (
  echo [%date% %time%] skip: on branch %BRANCH%, not main>> "%LOG%"
  exit /b 0
)
git diff-index --quiet HEAD --
if errorlevel 1 (
  echo [%date% %time%] skip: uncommitted edits to tracked files>> "%LOG%"
  exit /b 0
)

for /f %%h in ('git rev-parse HEAD') do set "OLD=%%h"
git fetch -q origin main >> "%LOG%" 2>&1
if errorlevel 1 (
  echo [%date% %time%] fetch failed>> "%LOG%"
  exit /b 0
)
git merge -q --ff-only origin/main >> "%LOG%" 2>&1
if errorlevel 1 (
  echo [%date% %time%] fast-forward failed: local main has commits that are not on origin>> "%LOG%"
  exit /b 0
)
for /f %%h in ('git rev-parse HEAD') do set "NEW=%%h"
if "%OLD%"=="%NEW%" exit /b 0

echo [%date% %time%] updated %OLD:~0,7% -^> %NEW:~0,7%>> "%LOG%"
git diff --quiet %OLD% %NEW% -- requirements.txt
if errorlevel 1 (
  echo [%date% %time%] requirements.txt changed, installing>> "%LOG%"
  python -m pip install -q -r requirements.txt >> "%LOG%" 2>&1
)
exit /b 0
