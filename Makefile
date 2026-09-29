.PHONY: install lint typecheck test up down scanner-image

install:
	pip install -e ".[dev]"

lint:
	ruff check audittrail tests

typecheck:
	mypy audittrail

test:
	pytest -q

up:
	docker compose build
	docker build -f Dockerfile.scanner -t audittrail-scanner:local .
	docker compose up -d

down:
	docker compose down -v

scanner-image:
	docker build -f Dockerfile.scanner -t audittrail-scanner:local .
