.PHONY: install test check demo build

install:
	python -m pip install -e '.[dev]'

test:
	python -m pytest -q

check: test
	python -m ruff check src/nextaudit/scanner.py src/nextaudit/reports.py src/nextaudit/cli.py tests

demo:
	python -m nextaudit demo-scan
	python -m nextaudit demo

build:
	python -m build
