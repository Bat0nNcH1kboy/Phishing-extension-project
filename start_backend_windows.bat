@echo off
setlocal
cd /d %~dp0backend
if not exist .venv (
  py -3 -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
set PHISHING_DNS_CHECK_ENABLED=1
set PHISHING_DEMO_ENDPOINTS=1
python app.py
