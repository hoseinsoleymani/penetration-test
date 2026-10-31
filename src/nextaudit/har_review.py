
#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl

MARKERS = re.compile(
    r"wallet|payment|otp|charge|order|cart|"
    r"checkout|transaction|gateway|verify|"
    r"callback|webhook|factor|receipt",
    re.I
)

SAFE_KEY = re.compile(
    r"^[a-zA-Z_][a-zA-Z_0-9-]{0,49}$"
)

SAFE_SEGMENT = re.compile(
    r"^[a-z][a-z0-9_.-]{0,28}$"
)


def mask_path(path):
    result = []

    for part in path.split("/"):
        if not part:
            continue

        if (
            SAFE_SEGMENT.fullmatch(part.lower())
            and len(part) < 30
            and not re.fullmatch(
                r"[0-9a-f]{12,}", part, re.I
            )
        ):
            result.append(part.lower())
        else:
            result.append(":id")

    return "/" + "/".join(result)


def kind(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "other"


def fields(obj, prefix="", depth=0, output=None):
    output = [] if output is None else output

    if depth >= 3 or len(output) >= 35:
        return output

    if isinstance(obj, dict):
        for key, value in list(obj.items())[:35]:
            label = (
                key
                if isinstance(key, str)
                and SAFE_KEY.fullmatch(key)
                else "<dynamic-key>"
            )

            field = (
                f"{prefix}.{label}"
                if prefix else label
            )

            output.append(
                f"{field}:{kind(value)}"
            )

            if isinstance(value, (dict, list)):
                fields(
                    value,
                    field,
                    depth + 1,
                    output
                )

            if len(output) >= 35:
                break

    elif isinstance(obj, list) and obj:
        fields(
            obj[0],
            prefix + "[]",
            depth + 1,
            output
        )

    return output


def json_fields(raw):
    if (
        not isinstance(raw, str)
        or len(raw) > 1000000
    ):
        return []

    try:
        return fields(json.loads(raw))
    except (ValueError, TypeError):
        return []


def has_header(headers, name):
    return any(
        str(h.get("name", "")).lower() == name
        for h in headers or []
    )


def inspect_entry(entry, index, allowed_domains, include_subdomains=False):
    if not isinstance(entry, dict):
        return None
    req = entry.get("request") or {}
    resp = entry.get("response") or {}

    if not isinstance(req, dict) or not isinstance(resp, dict):
        return None
    try:
        uri = urlsplit(req.get("url", ""))
        domain = (uri.hostname or "").lower()
    except (TypeError, ValueError):
        return None

    allowed = any(
        domain == approved or (include_subdomains and domain.endswith("." + approved))
        for approved in allowed_domains
    )

    if not allowed:
        return None

    if not MARKERS.search(uri.path):
        return None

    post = req.get("postData") or {}
    req_type = (
        post.get("mimeType") or ""
    ).lower()

    request_fields = (
        json_fields(post.get("text"))
        if "json" in req_type
        else []
    )

    if (
        not request_fields
        and isinstance(post.get("params"), list)
    ):
        request_fields = [
            f"{p['name']}:form"
            for p in post["params"][:35]
            if (
                isinstance(p.get("name"), str)
                and SAFE_KEY.fullmatch(p["name"])
            )
        ]

    content = resp.get("content") or {}
    content_type = (
        content.get("mimeType") or ""
    ).lower()

    response_fields = []

    if (
        "json" in content_type
        and content.get("encoding") != "base64"
    ):
        response_fields = json_fields(
            content.get("text")
        )

    headers = req.get("headers") or []

    query_keys = sorted({
        k
        for k, _ in parse_qsl(
            uri.query,
            keep_blank_values=True
        )
        if SAFE_KEY.fullmatch(k)
    })

    return {
        "har_entry": index,
        "method": req.get("method", "UNKNOWN"),
        "path_template": mask_path(uri.path),
        "query_keys_only": query_keys[:25],
        "request_fields_and_types": request_fields,
        "response_status": resp.get("status"),
        "response_fields_and_types": response_fields,
        "sent_auth": has_header(
            headers, "authorization"
        ),
        "sent_cookie": (
            bool(req.get("cookies"))
            or has_header(headers, "cookie")
        ),
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "har",
        help="HAR exported from your browser"
    )

    parser.add_argument(
        "--domain", action="append", required=True,
        help="Include only this domain (repeatable); prevent importing unrelated HAR traffic"
    )
    parser.add_argument(
        "--include-subdomains", action="store_true",
        help="Also match subdomains of each --domain"
    )
    parser.add_argument(
        "--out",
        default="wallet_har_redacted.json"
    )

    args = parser.parse_args()
    domains = [x.lower().rstrip(".") for x in args.domain]
    if any(not x or "/" in x or ":" in x or " " in x for x in domains):
        parser.error("--domain must be a hostname only, e.g. app.example.com")

    raw = Path(args.har).read_bytes()
    document = json.loads(raw)

    entries = document.get(
        "log", {}
    ).get("entries", [])

    if not isinstance(entries, list):
        raise SystemExit(
            "Invalid HAR: log.entries missing"
        )

    extracted = []

    for index, entry in enumerate(entries):
        result = inspect_entry(entry, index, domains, args.include_subdomains)

        if result is not None:
            extracted.append(result)

    report = {
        "source_har_sha256": hashlib.sha256(
            raw
        ).hexdigest(),
        "har_entries": len(entries),
        "relevant_requests": len(extracted),
        "note": (
            "Metadata only. No tokens, cookies, "
            "request values or response values. "
            "No confirmed vulnerabilities."
        ),
        "requests": extracted,
    }

    Path(args.out).write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    print(
        f"Relevant requests: "
        f"{len(extracted)} of {len(entries)}"
    )

    for result in extracted:
        print(
            f"#{result['har_entry']:03d} "
            f"{result['method']:6s} "
            f"{result['response_status']} "
            f"{result['path_template']}"
        )

        fields_found = result[
            "request_fields_and_types"
        ]

        if fields_found:
            print(
                "  Request fields:",
                ", ".join(fields_found[:15])
            )

    print("Report saved:", args.out)


if __name__ == "__main__":
    main()
