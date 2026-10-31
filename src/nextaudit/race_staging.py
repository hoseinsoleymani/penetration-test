#!/usr/bin/env python3
"""Controlled, low-concurrency duplicate-request test for *staging* or localhost only.
Never use on a production payment gateway, real-wallet balance, or real users.
"""
import argparse
import asyncio
import json
import os
import re
import secrets
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import httpx


def staging_url(value):
    p = urlsplit(value)
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password or p.fragment:
        raise ValueError("Invalid URL")
    host = p.hostname.lower()
    local = host in ("127.0.0.1", "localhost", "::1")
    stage = (host.split(".")[0] in {"staging", "stage", "qa", "sandbox", "dev", "test"}
             or host.endswith((".test", ".localhost")))
    if not (local or stage):
        raise ValueError("Production / unknown hosts blocked. Use localhost or a staging/test subdomain.")
    if p.scheme == "http" and not local:
        raise ValueError("Remote staging must use HTTPS")
    return p


def safe_read_state_data(data, dotted):
    if not dotted:
        return None
    value = data
    for piece in dotted.split("."):
        if not isinstance(value, dict) or piece not in value:
            return "FIELD_NOT_PRESENT"
        value = value[piece]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return "NON_NUMERIC_FIELD_NOT_DISPLAYED"


async def run(args):
    request_url = urlsplit(args.url)
    staging_url(args.url)
    if args.state_url:
        state_url = urlsplit(args.state_url)
        staging_url(args.state_url)
        if (state_url.scheme, state_url.hostname, state_url.port) != (request_url.scheme, request_url.hostname, request_url.port):
            raise ValueError("--state-url must be on the same origin")
    body = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    if not isinstance(body, dict):
        raise ValueError("Payload must be a JSON object")
    token = os.environ.get("AUDIT_TOKEN", "").strip()
    auth = ("Bearer " + token) if args.auth_format == "bearer" and token else token
    test_id = "audit-" + secrets.token_hex(12)
    common = {"Accept": "application/json", "Idempotency-Key": test_id,
              "X-Audit-Test": "staging-idempotency", "User-Agent": "OwnedSiteRaceStaging/1.0"}
    if auth:
        common["Authorization"] = auth
    print("Staging/test URL:", args.url)
    print("Parallel requests:", args.requests)
    print("Shared idempotency key:", test_id)
    print("All requests use exactly the same test payload; no automatic retries.")

    async with httpx.AsyncClient(timeout=args.timeout, follow_redirects=False, trust_env=False,
                                 headers=common) as client:
        async def state():
            if not args.state_url: return None
            try:
                r = await client.get(args.state_url)
                return {"status":r.status_code, "field":safe_read_state_data(r.json(), args.state_field)}
            except (httpx.RequestError, ValueError) as exc:
                return {"error":type(exc).__name__}

        before = await state()
        start = asyncio.Event()

        async def worker(index):
            await start.wait()
            try:
                r = await client.post(args.url, json=body)
                # Intentionally do not print or save body; may contain test account data.
                return {"index":index, "status":r.status_code, "content_type":r.headers.get("content-type", "")[:60]}
            except httpx.RequestError as exc:
                return {"index":index, "error":type(exc).__name__}

        workers = [asyncio.create_task(worker(i+1)) for i in range(args.requests)]
        await asyncio.sleep(0.10)  # allow workers to enter shared gate
        start.set()
        results = await asyncio.gather(*workers)
        after = await state()

    print("Status counts:", dict(Counter(str(x.get("status", x.get("error"))) for x in results)))
    if before is not None: print("State before:", before)
    if after is not None: print("State after: ", after)
    print("Interpretation: multiple 2xx responses alone do NOT prove a race bug.")
    print("Check the authoritative DB/ledger: the unique operation must have the intended single effect.")
    if args.report:
        out = {"url":args.url,"idempotency_key":test_id,"results":results,"state_before":before,"state_after":after}
        Path(args.report).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print("Report:",args.report)


def main():
    ap = argparse.ArgumentParser(description="Controlled duplicate-write test: staging only")
    ap.add_argument("--url", required=True, help="Staging/local POST endpoint")
    ap.add_argument("--payload", required=True, help="JSON file with disposable test-account data")
    ap.add_argument("--requests", type=int, default=3, help="2..5 concurrent requests")
    ap.add_argument("--timeout", type=float, default=8)
    ap.add_argument("--auth-format", choices=("raw", "bearer"), default="raw")
    ap.add_argument("--state-url", help="Optional GET of test state, same-origin only")
    ap.add_argument("--state-field", help="Dotted numeric JSON field path for comparison, e.g. count")
    ap.add_argument("--report", default="race_staging_report.json")
    ap.add_argument("--confirm-test-only", action="store_true",
                    help="I have ensured that this is a sandbox/staging environment with disposable data")
    args = ap.parse_args()
    if not args.confirm_test_only:
        ap.error("Supply --confirm-test-only after verifying that this is an isolated test environment")
    if not 2 <= args.requests <= 5:
        ap.error("--requests must be 2..5")
    try:
        asyncio.run(run(args))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        ap.error(str(exc))


if __name__ == "__main__":
    main()
