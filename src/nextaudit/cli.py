"""CLI entrypoint; all operational target values are runtime parameters."""
from __future__ import annotations

import argparse
import asyncio
import importlib
import os
import sys

from . import __version__
from .reports import SEVERITY_ORDER, save_report, show_report
from .scanner import ScanOptions, Scanner

TOOLS = {
    "access": "access_audit", "race": "race_staging", "payment-lab": "payment_audit",
    "har": "har_review", "lab": "lab_server", "demo": "run_demo",
    "demo-scan": "demo_scan",
}


def _scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nextaudit scan", description="Read-only site and frontend security posture audit")
    p.add_argument("-u", "--url", required=True, help="Site URL (HTTPS unless --allow-local)")
    p.add_argument("--authorized", action="store_true", help="Confirm you own or have permission to assess the target")
    p.add_argument("--allow-local", action="store_true", help="Permit local/private targets and lab HTTP URLs")
    p.add_argument("--max-pages", type=int, default=10)
    p.add_argument("--max-scripts", type=int, default=30)
    p.add_argument("--max-sourcemaps", type=int, default=12)
    p.add_argument("--max-requests", type=int, default=90)
    p.add_argument("--max-bytes", type=int, default=1_500_000, help="Maximum decompressed response bytes")
    p.add_argument("--concurrency", "-c", type=int, default=3)
    p.add_argument("--delay", type=float, default=0.3, help="Minimum seconds between request starts")
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--no-crawl", action="store_true", help="Inspect only the supplied page")
    p.add_argument("--sitemap", action="store_true", help="Seed the bounded crawl from /sitemap.xml")
    p.add_argument("--no-manifest", action="store_true", help="Do not retrieve the Next.js build manifest")
    p.add_argument("--check-cors", action="store_true", help="Add a read-only request with a test Origin header")
    p.add_argument("--auth-env", metavar="ENV_VAR", help="Read Authorization header value from this environment variable")
    p.add_argument("--ignore-rule", action="append", default=[], help="Ignore a rule ID (repeatable)")
    p.add_argument("--format", choices=("json", "sarif", "markdown"), default="json")
    p.add_argument("-o", "--output", metavar="FILE", help="Report path (stdout summary if omitted)")
    p.add_argument("--fail-on", choices=("none", *[s.lower() for s in SEVERITY_ORDER]), default="none")
    p.add_argument("--quiet", action="store_true", help="Suppress rich summary")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in TOOLS:
        command = argv.pop(0)
        module = importlib.import_module("." + TOOLS[command], package="nextaudit")
        old_argv = sys.argv
        try:
            sys.argv = [f"nextaudit {command}", *argv]
            result = module.main()
        finally:
            sys.argv = old_argv
        return 0 if result is None else int(result)
    if argv and argv[0] == "scan":
        argv.pop(0)
    if argv in ([], ["--help"], ["-h"]):
        print(f"NextAudit {__version__} | read-only web security scanner\n")
        print("Usage: nextaudit scan -u https://example.com --authorized [options]")
        print("       nextaudit <access|race|payment-lab|har|lab|demo|demo-scan> --help")
        print("       nextaudit --version\n")
        print("Scan options: nextaudit scan --help")
        return 0
    if argv == ["--version"]:
        print(__version__)
        return 0
    p = _scan_parser()
    args = p.parse_args(argv)
    if not args.authorized:
        p.error("Scanning requires --authorized (only test assets you own or are authorized to assess)")
    if args.auth_env and not args.auth_env.isidentifier():
        p.error("--auth-env must be a valid environment variable name")
    auth = os.environ.get(args.auth_env, "") if args.auth_env else None
    if args.auth_env and not auth:
        p.error(f"Missing or empty {args.auth_env} environment variable")
    options = ScanOptions(
        target=args.url, max_pages=args.max_pages, max_scripts=args.max_scripts,
        max_sourcemaps=args.max_sourcemaps, max_requests=args.max_requests,
        max_bytes=args.max_bytes, concurrency=args.concurrency, delay=args.delay,
        timeout=args.timeout, crawl=not args.no_crawl, sitemap=args.sitemap, next_manifest=not args.no_manifest, check_cors=args.check_cors,
        allow_local=args.allow_local, auth_header=auth, ignored_rules=frozenset(args.ignore_rule),
    )
    try:
        options.validate()
        report = asyncio.run(Scanner(options).run())
        if args.output:
            save_report(report, args.output, args.format)
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    if not args.quiet:
        show_report(report)
        if args.output:
            print("Report written:", args.output)
    if report.status == "error":
        return 1
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER.index(args.fail_on.upper())
        if any(SEVERITY_ORDER.index(f.severity) <= threshold for f in report.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
