@echo off
setlocal
cd /d %~dp0backend
if not exist .venv (
  py -3 -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
cd ..
python scripts\check_project.py
