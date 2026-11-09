@echo off
setlocal
cd /d "%~dp0ai-agentic-soc"

if not exist .venv\Scripts\python.exe (
  if exist .venv (
    echo Existing .venv is not a Windows virtualenv. Remove it or run the WSL/Linux script.
    exit /b 1
  )
  python -m venv .venv
  if errorlevel 1 (
    echo Could not create .venv. Install Python 3.11-3.13 and retry.
    exit /b 1
  )
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m services.triage_api
endlocal
