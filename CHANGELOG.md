# Changelog

## 1.0.0 — 2026-11-01

- Repackaged into an installable `src/nextaudit` CLI with working entrypoint.
- Added bounded same-origin website crawling, Next.js fingerprinting, source-map review and redacted static findings.
- Added SARIF and Markdown reports, severity threshold exit codes, scope and response-size controls.
- Retained API access, offline HAR, local payment invariants and staging race utilities as separate commands.
- Replaced the site-specific live probe with generic authorized scan commands; excluded previously collected private target inventories and reports.
- Repaired the broken demo runner and moved all lab credentials to ephemeral environment variables.
- Added a disposable `demo-scan` website fixture, no public network required.
- Added automated offline tests, CI, license, release guidance and a complete README.
