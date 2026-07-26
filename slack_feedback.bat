@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\slack_feedback_poller.py >> "logs\slack_feedback_run_log.txt" 2>&1
python scripts\click_feedback_puller.py >> "logs\slack_feedback_run_log.txt" 2>&1
python scripts\search_log_puller.py >> "logs\slack_feedback_run_log.txt" 2>&1
python scripts\kev_feedback_labeler.py >> "logs\slack_feedback_run_log.txt" 2>&1
python scripts\evaluate_feedback.py >> "logs\slack_feedback_run_log.txt" 2>&1
python scripts\train_weights.py >> "logs\slack_feedback_run_log.txt" 2>&1
