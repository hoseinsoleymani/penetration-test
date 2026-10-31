# Contributing

Thanks for contributing to NextAudit.

1. Open an issue describing the behavior and a minimal, sanitized reproduction. Do not upload secrets, production traffic or private customer information.
2. Create a branch and add isolated regression tests. No test should contact real third-party domains.
3. Install `python -m pip install -e '.[dev]'`, run `python -m pytest -q`, `python -m ruff check src/nextaudit/scanner.py src/nextaudit/reports.py src/nextaudit/cli.py tests`, and `python -m build`.
4. Keep network checks read-only by default, bounded by scope and rate controls; staged active tests require explicit confirmation and test data.
5. Open a pull request explaining false-positive trade-offs, intended security impact, and any compatibility changes.

We prefer small, readable checks over broad claims of automatically proving exploitability. Please do not submit attack payloads designed to break unrelated systems.
