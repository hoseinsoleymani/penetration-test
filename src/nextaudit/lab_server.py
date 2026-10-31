#!/usr/bin/env python3
"""INSECURE/SECURE local teaching fixture, NOT a deployable payment service.
Binding is loopback-only; uses throwaway fake money, fake identities and fake gateway.
"""
import argparse
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

# Secrets belong to the local demo process, not the committed source.
AUDIT_SECRET = os.environ.get("NEXTAUDIT_LAB_SECRET", "")
TOKENS = {token: user for token, user in (
    (os.environ.get("NEXTAUDIT_LAB_A_TOKEN", ""), "a"),
    (os.environ.get("NEXTAUDIT_LAB_B_TOKEN", ""), "b"),
) if token}
CURRENCY = os.environ.get("NEXTAUDIT_LAB_CURRENCY", "IRR")


class Lab:
    def __init__(self, unsafe=False):
        self.lock = threading.RLock()
        self.unsafe = unsafe
        self.balances = {"a": 5000, "b": 5000}
        self.topups = {}
        self.topups_by_key = {}
        self.spends_by_key = {}
        self.credits = []
        self.debits = []


def handler_for(lab):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            return

        def send_json(self, status, obj):
            b = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(b)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def read_json(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size < 8192:
                    return None
                obj = json.loads(self.rfile.read(size))
                return obj if isinstance(obj, dict) else None
            except (ValueError, json.JSONDecodeError):
                return None

        def user(self):
            return TOKENS.get(self.headers.get("Authorization", ""))

        def audit_ok(self):
            return bool(AUDIT_SECRET) and self.headers.get("X-Audit-Secret", "") == AUDIT_SECRET

        def do_GET(self):
            u = urlsplit(self.path)
            if u.path != "/__audit/state":
                return self.send_json(404, {"error": "unknown"})

            if not self.audit_ok():
                return self.send_json(403, {"error": "audit forbidden"})

            account = parse_qs(u.query).get("account", [""])[0]
            if account not in ("a", "b"):
                return self.send_json(400, {"error": "account"})

            with lab.lock:
                return self.send_json(200, {
                    "balance_minor": lab.balances[account],
                    "ledger_credits": sum(
                        x["user"] == account for x in lab.credits
                    ),
                    "ledger_debits": sum(
                        x["user"] == account for x in lab.debits
                    ),
                    "pending_count": sum(
                        x["user"] == account
                        for x in lab.topups.values()
                    ),
                })

        def do_POST(self):
            path = urlsplit(self.path).path
            data = self.read_json()

            if data is None:
                return self.send_json(400, {"error": "invalid JSON"})

            if path == "/__audit/gateway-settle":
                if not self.audit_ok():
                    return self.send_json(
                        403, {"error": "audit forbidden"}
                    )

                topup_id = data.get("topup_id")
                with lab.lock:
                    topup = lab.topups.get(topup_id)
                    if not topup:
                        return self.send_json(
                            404, {"error": "not found"}
                        )

                    topup["gateway"] = {
                        "status": data.get("status", "succeeded"),
                        "amount_minor": data.get("amount_minor"),
                        "currency": data.get("currency"),
                    }

                return self.send_json(200, {"ok": True})

            user = self.user()
            if user is None:
                return self.send_json(
                    401, {"error": "unauthenticated"}
                )

            if path == "/api/v1.0/users/wallet/charge":
                amount = data.get("amount_minor")

                if (
                    type(amount) is not int
                    or not 100 <= amount <= 100000
                    or data.get("currency") != CURRENCY
                ):
                    return self.send_json(
                        422, {"error": "invalid amount/currency"}
                    )

                key = self.headers.get("Idempotency-Key", "")
                if len(key) < 8 or len(key) > 120:
                    return self.send_json(
                        400, {"error": "idempotency key required"}
                    )

                with lab.lock:
                    k = (user, key)

                    if k in lab.topups_by_key:
                        old = lab.topups[lab.topups_by_key[k]]

                        if (
                            old["amount_minor"] != amount
                            or old["currency"] != CURRENCY
                        ):
                            return self.send_json(
                                409,
                                {"error": "idempotency conflict"}
                            )

                        return self.send_json(200, {
                            "topup_id": old["id"],
                            "status": "pending"
                        })

                    ref = "lab-" + uuid.uuid4().hex

                    lab.topups[ref] = {
                        "id": ref,
                        "user": user,
                        "amount_minor": amount,
                        "currency": CURRENCY,
                        "credited": False,
                        "gateway": None,
                    }

                    lab.topups_by_key[k] = ref

                return self.send_json(201, {
                    "topup_id": ref,
                    "status": "pending"
                })

            if path == "/api/v1.0/payments/verify":
                topup_id = data.get("topup_id")

                with lab.lock:
                    tx = lab.topups.get(topup_id)

                    if tx is None:
                        return self.send_json(
                            404, {"error": "not found"}
                        )

                    if tx["user"] != user:
                        return self.send_json(
                            403, {"error": "forbidden"}
                        )

                    g = tx["gateway"]

                    if (
                        g is None
                        or g.get("status") != "succeeded"
                    ):
                        return self.send_json(
                            409, {"error": "payment unverified"}
                        )

                    if (
                        g.get("amount_minor") != tx["amount_minor"]
                        or g.get("currency") != tx["currency"]
                    ):
                        return self.send_json(
                            409, {"error": "gateway mismatch"}
                        )

                    if not lab.unsafe:
                        if tx["credited"]:
                            return self.send_json(
                                200,
                                {"status": "already_processed"}
                            )

                        tx["credited"] = True
                        lab.balances[user] += tx["amount_minor"]

                        lab.credits.append({
                            "user": user,
                            "tx": topup_id,
                            "amount": tx["amount_minor"]
                        })

                        return self.send_json(
                            200, {"status": "credited"}
                        )

                # INTENTIONAL race bug: local demo only
                if tx["credited"]:
                    return self.send_json(
                        200, {"status": "already_processed"}
                    )

                time.sleep(0.06)

                with lab.lock:
                    tx["credited"] = True
                    lab.balances[user] += tx["amount_minor"]

                    lab.credits.append({
                        "user": user,
                        "tx": topup_id,
                        "amount": tx["amount_minor"]
                    })

                return self.send_json(
                    200, {"status": "credited"}
                )

            if path == "/api/v1.0/users/wallet/spend":
                amt = data.get("amount_minor")

                if (
                    type(amt) is not int
                    or amt <= 0
                    or amt > 100000
                ):
                    return self.send_json(
                        422, {"error": "invalid spend"}
                    )

                key = self.headers.get("Idempotency-Key", "")
                if len(key) < 8:
                    return self.send_json(
                        400, {"error": "idempotency key required"}
                    )

                with lab.lock:
                    k = (user, key)

                    if k in lab.spends_by_key:
                        return self.send_json(
                            409, {"error": "duplicate"}
                        )

                    if not lab.unsafe:
                        if lab.balances[user] < amt:
                            return self.send_json(
                                409, {"error": "insufficient"}
                            )

                        lab.spends_by_key[k] = True
                        lab.balances[user] -= amt

                        lab.debits.append({
                            "user": user,
                            "amount": amt
                        })

                        return self.send_json(
                            200, {"status": "spent"}
                        )

                    if lab.balances[user] < amt:
                        return self.send_json(
                            409, {"error": "insufficient"}
                        )

                # INTENTIONAL TOCTOU bug in local lab
                time.sleep(0.06)

                with lab.lock:
                    lab.spends_by_key[k] = True
                    lab.balances[user] -= amt

                    lab.debits.append({
                        "user": user,
                        "amount": amt
                    })

                return self.send_json(
                    200, {"status": "spent"}
                )

            return self.send_json(
                404, {"error": "unknown"}
            )

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port", type=int, default=8766
    )
    parser.add_argument(
        "--unsafe-local-demo",
        action="store_true",
        help="Enable intentionally vulnerable mode FOR LOCAL DEMO ONLY"
    )
    args = parser.parse_args()
    if not AUDIT_SECRET or len(TOKENS) != 2 or not all(len(t) >= 16 for t in TOKENS):
        parser.error("Set NEXTAUDIT_LAB_SECRET, NEXTAUDIT_LAB_A_TOKEN and NEXTAUDIT_LAB_B_TOKEN (two different tokens, at least 16 characters each)")
    if not (1 <= args.port <= 65535):
        parser.error("--port must be 1..65535")

    print(
        f"LOCAL payment lab port={args.port} "
        f"unsafe={args.unsafe_local_demo}",
        flush=True
    )

    ThreadingHTTPServer(
        ("127.0.0.1", args.port),
        handler_for(Lab(args.unsafe_local_demo))
    ).serve_forever()


if __name__ == "__main__":
    main()