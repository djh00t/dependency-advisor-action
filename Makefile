.PHONY: install check quality-gates clean build publish test lint format

install:
	uv sync --all-groups

check:
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy
	uv run pytest

quality-gates:
	$(MAKE) check
	uv build

clean:
	rm -rf .coverage .mypy_cache .pytest_cache .ruff_cache .venv build dist htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

build:
	uv build

publish: build
	uv publish

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run mypy

format:
	uv run ruff format .
	uv run ruff check --fix .
