@echo off
setlocal
cd /d "%~dp0"

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
python -c "import streamlit" >nul 2>&1
if errorlevel 1 (
  python -m pip install -r requirements.txt
)
python -m streamlit run app.py --server.address 127.0.0.1
endlocal
