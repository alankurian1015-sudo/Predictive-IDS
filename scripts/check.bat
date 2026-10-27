@echo off
cd /d "%~dp0\.."
if not exist .venv\Scripts\activate.bat (echo Run scripts\setup.bat first. & pause & exit /b 1)
call .venv\Scripts\activate.bat
set TF_ENABLE_ONEDNN_OPTS=0
python scripts\check_setup.py
pause