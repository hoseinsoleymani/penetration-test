#!/usr/bin/env python3
"""Low-rate, read-only audit of unauthenticated GET access to known API routes.

Does not send POST/PATCH/PUT/DELETE, follow redirects, crawl identifiers,
store response bodies, or send cookies. For systems you own/control only.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

DENIAL_WORDS = re.compile(
    r"unauth(?:orized|enticated)|not authenticated|access denied|login required|"
    r"forbidden|not logged in|احراز هویت|وارد حساب|وارد شوید|لاگین|دسترسی غیرمجاز",
    re.IGNORECASE,
)
PRIVATE_KEY_WORDS = re.compile(
    r"(^|_)(email|mobile|phone|national_code|address|balance|wallet|"
    r"transaction|birthdate|order|access_token|secret|password)($|_)",
    re.IGNORECASE,
)
DEFAULT_MAX_RESPONSE = 65536  # bytes transiently examined; bodies never appear in reports


def valid_base(base):
    p = urlsplit(base)
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password:
        raise ValueError("--base must be an HTTPS API URL (or HTTP on localhost)")
    if p.scheme == "http" and p.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Refusing to send HTTP requests or tokens to a remote host")
    if p.query or p.fragment:
        raise ValueError("--base must not contain a query string or fragment")
    return base.rstrip("/")


def safe_endpoint(path):
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return False
    p = urlsplit(path)
    return not (p.scheme or p.netloc or p.fragment or "\\" in path or
                "\r" in path or "\n" in path or ".." in p.path or "${" in path or "…" in path)


def summarize(body, content_type):
    keys = set()
    denial = False
    data = None
    if "json" in content_type.lower() or body.lstrip()[:1] in (b"{", b"["):
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
        except (ValueError, TypeError):
            pass
    if isinstance(data, dict):
        keys = {str(k) for k in data.keys()}
        for field in ("message", "error", "detail", "error_message", "code"):
            val = data.get(field)
            if isinstance(val, str) and DENIAL_WORDS.search(val[:300]):
                denial = True
        if data.get("status") in (401, 403) or data.get("code") in (401, 403):
            denial = True
    is_json = data is not None
    return {
        "json": is_json,
        "json_type": type(data).__name__ if is_json else None,
        "top_level_keys": sorted(keys)[:25],
        "possibly_sensitive_key_names": sorted(k for k in keys if PRIVATE_KEY_WORDS.search(k))[:15],
        "application_level_access_denial": denial,
        "body_sha256_prefix": hashlib.sha256(body).hexdigest()[:12] if body else None,
    }


def one_get(client, url, headers, max_response=DEFAULT_MAX_RESPONSE):
    try:
        with client.stream("GET", url, headers=headers, follow_redirects=False) as response:
            parts, size, truncated = [], 0, False
            for chunk in response.iter_bytes():
                if size + len(chunk) > max_response:
                    parts.append(chunk[:max_response - size]); size = max_response
                    truncated = True
                    break
                parts.append(chunk); size += len(chunk)
            body = b"".join(parts)
            ctype = response.headers.get("content-type", "")
            summary = summarize(body, ctype)
            return {
                "status": response.status_code,
                "content_type": ctype[:100],
                "sample_bytes": size,
                "sample_truncated": truncated,
                "location": (urlsplit(response.headers.get("location", "")).path[:120]
                             if 300 <= response.status_code < 400 else None),
                **summary,
            }
    except httpx.RequestError as exc:
        return {"error": type(exc).__name__}


def classify(result, expected):
    if "error" in result:
        return "NETWORK_ERROR"
    status = result["status"]
    if status in (401, 403):
        return "ACCESS_DENIED"
    if result.get("application_level_access_denial"):
        return "ACCESS_DENIED_IN_JSON_REVIEW"
    if status == 404:
        return "NOT_FOUND"
    if status == 405:
        return "METHOD_NOT_ALLOWED"
    if status in (429, 503):
        return "RATE_LIMIT_OR_UNAVAILABLE"
    if 300 <= status < 400:
        return "REDIRECT_REVIEW"
    if 200 <= status < 300:
        if expected == "private_review":
            return "REVIEW_PRIVATE_2XX" if result.get("json") else "REVIEW_PRIVATE_NON_JSON_2XX"
        return "PUBLIC_OR_REVIEW_2XX"
    return "OTHER_STATUS_REVIEW"


def main():
    ap = argparse.ArgumentParser(description="Non-destructive authorization audit: GET only")
    ap.add_argument("--authorized", action="store_true", help="Confirm testing authorization")
    ap.add_argument("--base", required=True, help="Example: https://your-domain.tld/api/v1.0")
    ap.add_argument("--inventory", required=True, help="Your own endpoint inventory JSON")
    ap.add_argument("--report", default="access_audit_report.json")
    ap.add_argument("--delay", type=float, default=0.8, help="Seconds between requests, default 0.8")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-get", type=int, default=30)
    ap.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE,
                    help="Max transient bytes read per GET response, default 65536")
    ap.add_argument("--with-auth", action="store_true", help="Compare with AUDIT_TOKEN env variable")
    ap.add_argument("--auth-format", choices=("raw", "bearer"), default="raw",
                    help="Your JS snippet uses raw Authorization header")
    args = ap.parse_args()
    if not args.authorized:
        ap.error("This command requires --authorized")
    try:
        base = valid_base(args.base)
        if args.delay < 0.5 or args.max_get < 1:
            ap.error("--delay must be >= 0.5 and --max-get >= 1")
        if not 1024 <= args.max_response_bytes <= 1_048_576:
            ap.error("--max-response-bytes must be 1024..1048576")
        token = os.environ.get("AUDIT_TOKEN", "").strip() if args.with_auth else ""
        if args.with_auth and not token:
            ap.error("--with-auth requires an AUDIT_TOKEN environment variable")
        inv = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
        entries = inv["endpoints"]
        if not isinstance(entries, list):
            raise ValueError("Invalid inventory: endpoints must be an array")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        ap.error(str(exc))

    tested, skipped, seen = [], [], set()
    auth_header = ("Bearer " + token if args.auth_format == "bearer" else token) if token else None
    headers = {"Accept": "application/json", "Cache-Control": "no-store", "User-Agent": "NextAuditAccess/1.0", "Cookie": ""}

    print("Scope:", base, "| only GET | no cookies | no redirects | no raw data saved")
    with httpx.Client(timeout=args.timeout, follow_redirects=False, trust_env=False) as client:
        for item in entries:
            if not isinstance(item, dict):
                skipped.append({"reason": "invalid_inventory_entry"})
                continue
            method, path = item.get("method"), item.get("path")
            if method != "GET":
                skipped.append({"method": method, "expression": item.get("source_expression"), "reason": "state_changing_method"})
                continue
            if not path or not safe_endpoint(path):
                skipped.append({"method": method, "expression": item.get("source_expression"), "reason": "unresolved_dynamic_endpoint"})
                continue
            if path in seen:
                continue
            seen.add(path)
            if len(tested) >= args.max_get:
                skipped.append({"method": method, "expression": item.get("source_expression"), "reason": "max_get_cap"})
                continue
            url = base + path
            unauth = one_get(client, url, headers, args.max_response_bytes)
            expected = item.get("expected", "public_or_context")
            label = classify(unauth, expected)
            auth = None
            if auth_header:
                time.sleep(args.delay)
                auth = one_get(client, url, {**headers, "Authorization": auth_header}, args.max_response_bytes)
            result = {"method": method, "path": path, "expected": expected,
                      "unauthenticated": unauth, "classification": label}
            if auth is not None:
                result["authenticated"] = auth
                result["auth_response_differs"] = (
                    unauth.get("status") != auth.get("status") or
                    unauth.get("body_sha256_prefix") != auth.get("body_sha256_prefix")
                ) if "error" not in auth and "error" not in unauth else None
            tested.append(result)
            status = unauth.get("status", unauth.get("error", "ERR"))
            auth_status = auth.get("status", auth.get("error", "ERR")) if auth else "-"
            print(f"{str(status):>5} / {str(auth_status):>5}  {label:<27} {path}")
            time.sleep(args.delay)

    out = {"created_utc": datetime.now(timezone.utc).isoformat(),
           "base_url": base, "requests_mode": "GET without cookies, no redirects",
           "authenticated_baseline": bool(auth_header), "tested": tested, "skipped": skipped,
           "disclaimer": "200 != vulnerability; inspect server logs and authorized state. No response bodies are saved."}
    Path(args.report).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nGET paths tested: {len(tested)} | skipped inventory records: {len(skipped)}")
    print("Report:", args.report)
    print("REVIEW_PRIVATE_2XX is a manual-review alert, not proof of data leakage.")


if __name__ == "__main__":
    main()
