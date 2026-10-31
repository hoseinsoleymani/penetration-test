# NextAudit

**Read-only website security posture and Next.js frontend review, from your terminal.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Mode](https://img.shields.io/badge/Default%20mode-GET%20only-informational)

NextAudit helps developers and authorized security reviewers find configuration gaps, publicly accessible source maps, client-side code patterns that need investigation, and visible API paths. It includes a bounded access-control reconnaissance helper, a sanitized HAR reviewer, and a **separate, local/staging-only** payment logic and race-condition lab.

> **Scope matters.** This is *not* a proof-of-exploit tool, not an indiscriminate vulnerability scanner, and not a guarantee that every bug can be found. Run it only against hosts you own or have explicit permission to test. The normal scanner sends GET requests only; it does not fuzz forms, brute-force authentication, exploit SQL injection, or issue state-changing requests. Do not use the lab tools on real balances or production payments.

## Features

| Area | What it checks | Notes |
| --- | --- | --- |
| HTTP headers | CSP, HSTS (HTTPS), nosniff, referrer policy, frame protection | Reports missing controls, not confirmed exploits |
| Cookies | Secure (HTTPS), HttpOnly, SameSite attributes | Review whether each cookie should have the flags |
| Frontend discovery | Same-origin HTML links, script assets, Next.js Pages / App Router indicators | Optional bounded crawl; does not execute JavaScript |
| Source maps | JavaScript `sourceMappingURL` or adjacent `.map` resources | Only parses valid v3 maps, never saves source contents |
| Frontend source review | Possible credential patterns, AWS key-shaped strings, JWT-shaped strings, HTML sinks, eval, redirect sinks | Heuristic detection; **secret values redacted** |
| API visibility | Literal paths found in `fetch` / `axios` and Next.js build manifests | Discovery only; no automatic API probing |
| CORS | Optional Origin-reflection check | `--check-cors`; finding still requires manual validation |
| Reporting | Rich terminal summary, JSON, Markdown, SARIF, severity-based CI exit codes | Reports deliberately omit secret matches |
| Special-purpose tools | Read-only API access checks, offline HAR review, controlled staging race test, isolated payment lab | Separate subcommands and safeguards |

## Requirements

- Python 3.10 or newer (3.10–3.13 supported in CI)
- Network access to the **authorized** target for network scans
- No API key or cloud service required

## Installation

### Install from a cloned repository

```bash
git clone https://github.com/OWNER/nextaudit.git
cd nextaudit
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
nextaudit --version
```

Replace `OWNER` with the repository's actual account/organization. Until the repository exists, install from your local extracted project directory instead (`python -m pip install .`).

For development:

```bash
python -m pip install -e '.[dev]'
pytest -q
python -m nextaudit --help
```

`pipx install .` is also supported from the project root if you use pipx. **The package has not been published to PyPI by this repository.** Do not assume `pip install nextaudit` downloads this project until you've verified the PyPI project owner.

## Quick start

**Try a no-external-network demonstration first:**

```bash
nextaudit demo-scan
```

This launches a disposable loopback-only site with deliberately weak headers, a fake credential pattern and a source map, scans it, then shuts it down. `nextaudit demo-scan -o reports/fixture.json` saves the report.


```bash
# Baseline scan, authorized HTTPS website
nextaudit scan -u https://app.example.com --authorized

# Larger, still bounded scan with JSON report
nextaudit scan -u https://app.example.com --authorized \
  --sitemap --max-pages 25 --max-scripts 60 --max-requests 160 \
  --concurrency 3 --delay 0.5 --output reports/audit.json

# Source-map, CORS, or client-code findings in SARIF format
nextaudit scan -u https://app.example.com --authorized \
  --check-cors --format sarif --output reports/audit.sarif

# Markdown report for a manual review
nextaudit scan -u https://app.example.com --authorized \
  --format markdown -o reports/audit.md

# Local server, explicitly permit loopback HTTP
nextaudit scan -u http://127.0.0.1:8000 --allow-local --authorized
```

If your app requires an Authorization header, do **not** put a token in your shell history or command-line options. Set an environment variable in your shell, then use:

```bash
nextaudit scan -u https://app.example.com --authorized \
  --auth-env NEXTAUDIT_AUTHORIZATION -o reports/authenticated.json
```

The variable should contain the *complete* header value (for example, `Bearer ...`). The scanner does not write the token to its report. It does not deliberately replay cookies set by the site. Treat authenticated reports and asset paths as private regardless.

### CI example

```bash
nextaudit scan -u https://staging.example.com --authorized \
  --max-pages 10 --max-requests 60 --fail-on high \
  --format sarif --output reports/nextaudit.sarif
```

Exit codes: `0` = success with no finding at/above the requested threshold; `1` = unable to inspect an HTML page; `2` = findings at/above the `--fail-on` threshold (or CLI usage error, as standard `argparse`). A partial report due to timeouts may still exit `0` if the threshold is not met; inspect `status` and `errors` in JSON. For CI, review partial reports before treating the run as conclusive.

### Scanner options

```text
nextaudit scan --help
  -u, --url URL             Required HTTP(S) target
  --authorized              Mandatory authorization acknowledgment
  --allow-local             Allow local/private hosts; remote HTTPS remains preferred
  --max-pages N             Default 10 (1..100)
  --max-scripts N           Default 30 (1..200)
  --max-sourcemaps N        Default 12 (0..100)
  --max-requests N          Default 90 (1..500)
  --max-bytes N             Default 1500000 decompressed bytes per response
  --concurrency N           Default 3 (1..10)
  --delay SECONDS           Default 0.3; minimum 0.1
  --timeout SECONDS         Default 10
  --no-crawl                Inspect only initial HTML page
  --sitemap                 Seed crawl with same-origin /sitemap.xml URLs
  --no-manifest             Skip Next.js build manifest lookup
  --check-cors              One additional GET with test Origin header
  --auth-env ENV_VAR        Authorization header from environment
  --ignore-rule RULE_ID     Exclude an individual rule (repeatable)
  --format json|sarif|markdown
  -o, --output FILE         Save report (optional)
  --fail-on none|critical|high|medium|low|info
  --quiet                   Suppress Rich summary
```

**Behavior and limits:** The crawler follows only same-origin HTML anchors, script/preload URLs and optional sitemap entries, strips query strings and fragments before fetching, does not follow redirects, does not submit forms, and uses GET only. Stops on HTTP 429 or 5xx to avoid hammering a struggling server. Limits on pages, scripts, map retrievals, total requests, response size, concurrency and minimum spacing reduce load. It does not honor or parse robots.txt; instead, you should agree scope, capacity and permitted paths with the owner before scanning. Avoid scanning sensitive or state-changing GET endpoints. The scanner has no JavaScript browser engine; JS-rendered-only routes may be missed. DNS rebinding and unusual proxy/router configurations can complicate strict origin assumptions; never run untrusted targets from a network with sensitive internal services.

## Additional commands

**Read-only API access review (GET only):** supply *your own* endpoint inventory, not data scraped from an unrelated site. An example is included in `examples/inventory.example.json`.

```bash
nextaudit access --base https://app.example.com/api \
  --inventory examples/inventory.example.json --authorized \
  --max-get 20 --max-response-bytes 65536 --delay 1.0 --report reports/access.json

# Optional comparison using a test user's credentials (no response bodies saved)
# Set AUDIT_TOKEN in the shell; do not paste it into your history.
nextaudit access --base https://app.example.com/api \
  --inventory examples/inventory.example.json --authorized \
  --with-auth --auth-format bearer --report reports/access-auth.json
```

An HTTP 200 on a supposedly private route is **not** proof of an IDOR or authorization bypass: review the JSON shape, actual ownership and expected behavior manually. Unauthenticated and authenticated response bodies are not preserved.

**Offline HAR review:** Export a HAR from your own browser session, keep the raw HAR private, then run:

```bash
nextaudit har my-session.har --domain app.example.com --out reports/har-redacted.json
```

The reviewer emits request metadata and field *types*, not raw tokens, cookies or values; it is still your responsibility to check the output before sharing it.

**Local payment logic demonstration:** Uses loopback-only ephemeral credentials, fake money and disposable in-memory state. It demonstrates that invariants can pass in a secure fixture and fail in an intentionally vulnerable fixture.

```bash
nextaudit demo
```

The following commands have distinct safeguards and should **only** be used on your own isolated lab or authorized HTTPS staging host, with disposable accounts and fake-money integrations. They may issue state-changing requests:

```bash
nextaudit payment-lab --help
nextaudit race --help
nextaudit lab --help
```

For manual lab execution, set `NEXTAUDIT_LAB_A_TOKEN`, `NEXTAUDIT_LAB_B_TOKEN` and `NEXTAUDIT_LAB_SECRET` (at least 16 characters for each token) and use matching `PAY_A_TOKEN`, `PAY_B_TOKEN` and `PAY_AUDIT_SECRET` for the payment test. The `demo` command handles this automatically. Never reuse production credentials.

## Interpreting findings

Findings have a **rule ID, severity, confidence, location, evidence, and suggested remediation**. A missing header is a directly observable condition, but actual impact depends on the app. A JavaScript pattern such as `dangerouslySetInnerHTML` requires tracing whether attackers can control its input; `NEXT_PUBLIC_*` variables are intentionally exposed by Next.js and are informational. A source map may be publicly intended. Treat the results as a review queue, validate them manually, and avoid publishing live credentials or private architecture details in GitHub issues.

Coverage is limited to reachable pages, downloaded bundles and supplied local/staging fixtures. It does **not** establish that a site is free from XSS, SQL injection, SSRF, auth/IDOR, file upload weaknesses, broken access control, business logic abuse, race bugs or other server-side vulnerabilities. Professional security reviews require manual testing, verified scope, multiple safe tools and access to backend code.

## Repository layout

```text
src/nextaudit/
  cli.py              CLI and command routing
  scanner.py          Bounded read-only web and Next.js scanner
  reports.py          JSON / SARIF / Markdown and terminal output
  access_audit.py     GET-only API access review
  har_review.py       Offline HAR metadata review
  payment_audit.py    Payment invariants (lab/staging only)
  race_staging.py     Controlled duplicate-request test (staging only)
  lab_server.py       Loopback-only secure/vulnerable teaching fixture
  run_demo.py         Automated payment fixtures
  demo_scan.py        Disposable loopback website scan fixture
examples/             Sanitized configuration examples
tests/                No-external-network regression tests
.github/workflows/     CI and code-security checks
docs/                 Additional guidance
```

## Privacy and responsible use

- The included examples are synthetic. Original third-party target URLs, site-specific inventory and previous scan outputs are deliberately **not included** in this public release.
- Credentials must come from environment variables; never commit `.env`, HAR files, private endpoint inventories or scan reports.
- No real site has been scanned as part of packaging or project tests. Tests use in-memory HTTP fakes and a local fixture.
- If you discover a vulnerability in someone else's service, follow the owner’s disclosure policy and do not publish exploit details or data.

## Development and release

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m ruff check src/nextaudit/scanner.py src/nextaudit/reports.py src/nextaudit/cli.py tests
python -m build
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/PUBLISHING.md](docs/PUBLISHING.md). GitHub Actions runs unit tests, offline CLI checks and packaging checks on pull requests. Before public upload, set your own repo URL, choose an available package name if publishing to PyPI, and review the archive for accidental secrets.

## License

MIT — see [LICENSE](LICENSE).
# penetration-test
