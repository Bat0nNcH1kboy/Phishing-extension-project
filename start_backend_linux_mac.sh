#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/backend"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
export PHISHING_DNS_CHECK_ENABLED=1
export PHISHING_DEMO_ENDPOINTS=1
python app.py
