PY ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help install backend frontend test lint build run docker docker-down clean

help:
	@echo "make install   - create .venv, install Python + Node dependencies"
	@echo "make backend   - run the API with auto-reload on :8000"
	@echo "make frontend  - run the Vite dev server on :5173 (proxies /api to :8000)"
	@echo "make test      - run the backend test suite"
	@echo "make lint      - ruff lint + format check"
	@echo "make build     - build the UI into frontend/dist (served by the API on :8000)"
	@echo "make run       - build the UI, then serve UI + API on :8000"
	@echo "make docker    - docker compose up --build (app + postgres)"

install:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -r backend/requirements-dev.txt
	cd frontend && npm install

backend:
	cd backend && ../$(BIN)/uvicorn app.main:app --reload --port 8000

frontend:
	cd frontend && npm run dev

test:
	cd backend && ../$(BIN)/python -m pytest

lint:
	cd backend && ../$(BIN)/ruff check app tests && ../$(BIN)/ruff format --check app tests

build:
	cd frontend && npm run build

run: build
	cd backend && ../$(BIN)/uvicorn app.main:app --port 8000

docker:
	docker compose up --build

docker-down:
	docker compose down

clean:
	rm -rf frontend/dist frontend/node_modules backend/sentinel.db backend/.pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
