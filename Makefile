# CyberSentry AI — common developer tasks.
# Python 3.11 via uv; frontend is Vite + React + Tailwind.

UV      ?= uv
BACKEND := backend
FRONTEND := frontend
VENV    := $(CURDIR)/$(BACKEND)/.venv
PY      := $(VENV)/bin/python
PYTEST  := $(VENV)/bin/pytest
DEMO_DB := $(CURDIR)/backend/cybersentry-demo.sqlite3

.PHONY: install run test eval demo

install:
	cd $(BACKEND) && $(UV) venv --python 3.11 && $(UV) pip install -e ".[dev]"
	cd $(FRONTEND) && npm ci

run:
	cd $(BACKEND) && $(PY) -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

test:
	cd $(BACKEND) && $(PYTEST)

eval:
	$(PY) $(CURDIR)/eval/run.py
	$(PY) $(CURDIR)/eval/run_eval.py

demo:
	cd $(BACKEND) && CYBERSENTRY_DB_PATH=$(DEMO_DB) $(PY) -m app.demo
	cd $(BACKEND) && CYBERSENTRY_DB_PATH=$(DEMO_DB) CYBERSENTRY_REPORT_MODE=cached $(PY) -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
