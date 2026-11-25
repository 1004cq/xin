#!/bin/sh
set -eu
python -m pip install -r requirements.txt pytest httpx pip-audit
python -m compileall -q src scripts verify.py
python -m pytest -q --ignore=tests/test_responsive_ui.py
python -m pip_audit -r requirements.txt
