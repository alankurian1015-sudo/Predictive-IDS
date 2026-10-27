@echo off
cd /d "%~dp0\.."
if not exist .venv (
  echo Creating the virtual environment...
  python -m venv .venv || (echo Could not create it. Is Python installed? & pause & exit /b 1)
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt || (echo Installation failed. See the messages above. & pause & exit /b 1)
echo.
echo Setup finished. Put your files in models\ and data\, then run scripts\check.bat and scripts\run.bat.
pause