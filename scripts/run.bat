@echo off
cd /d "%~dp0\.."
set PORT=8765
set TF_ENABLE_ONEDNN_OPTS=0
if not exist .venv\Scripts\activate.bat (
  echo No virtual environment found. Run scripts\setup.bat first.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
set PYTHONPATH=%cd%
echo Starting the dashboard on http://localhost:%PORT%  (the first start can take about a minute)
start "" cmd /c "timeout /t 25 /nobreak >nul & start http://localhost:%PORT%"
uvicorn backend.server:app --port %PORT%
pause