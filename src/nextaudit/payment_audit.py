#!/usr/bin/env python3
"""Bounded wallet/payment invariants test for an isolated lab or authorized staging.
Never targets production, never uses real payment gateways, no mass scanning.
The default request/response contract matches lab_server.py ONLY.
"""
import argparse
import asyncio
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

DEFAULT_ROUTES = {
    "charge": "/api/v1.0/users/wallet/charge",
    "verify": "/api/v1.0/payments/verify",
    "spend": "/api/v1.0/users/wallet/spend",
    "state": "/__audit/state",
    "settle": "/__audit/gateway-settle",
}


def validate_target(raw):
    p = urlsplit(raw)

    if (
        not p.hostname
        or p.username
        or p.password
        or p.query
        or p.fragment
        or p.path not in ("", "/")
    ):
        raise ValueError(
            "--base must be a host origin without path, "
            "query, credentials or fragment"
        )

    host = p.hostname.lower()

    local = host in {
        "127.0.0.1",
        "localhost",
        "::1"
    }

    stage = (
        host.split(".")[0] in {
            "staging", "stage", "qa",
            "sandbox", "test", "dev"
        }
        or host.endswith((".test", ".localhost"))
    )

    if (
        p.scheme not in (
            {"http", "https"} if local else {"https"}
        )
        or not (local or stage)
    ):
        raise ValueError(
            "Blocked: only localhost or clearly named "
            "HTTPS staging/test host allowed"
        )

    return raw.rstrip("/"), local


def routes_from_config(path):
    if path is None:
        return DEFAULT_ROUTES.copy()

    content = json.loads(
        Path(path).read_text(encoding="utf-8")
    )

    routes = {
        **DEFAULT_ROUTES,
        **content.get("routes", {})
    }

    for key, val in routes.items():
        if (
            key not in DEFAULT_ROUTES
            or not isinstance(val, str)
            or not val.startswith("/")
            or val.startswith("//")
            or "?" in val
            or "#" in val
            or "\\" in val
        ):
            raise ValueError("Invalid route: " + key)

    return routes


@dataclass
class Case:
    name: str
    verdict: str
    evidence: dict


class Audit:
    def __init__(
        self,
        base,
        routes,
        token_a,
        token_b,
        secret,
        auth_format,
        timeout
    ):
        self.base = base
        self.routes = routes

        self.token = {
            "a": token_a,
            "b": token_b
        }

        self.secret = secret
        self.auth_format = auth_format

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
            headers={
                "Accept": "application/json",
                "User-Agent": "IsolatedPaymentAudit/1.0"
            },
            limits=httpx.Limits(
                max_connections=5,
                max_keepalive_connections=5
            ),
        )

        self.cases = []
        self.previous = {}

    async def close(self):
        await self.client.aclose()

    def auth(self, account):
        if not account:
            return {}

        value = self.token[account]

        return {
            "Authorization": (
                "Bearer " + value
                if self.auth_format == "bearer"
                else value
            )
        }

    async def send(
        self,
        route,
        *,
        method="POST",
        account=None,
        data=None,
        key=None,
        audit=False,
        params=None
    ):
        headers = self.auth(account)

        if key is not None:
            headers["Idempotency-Key"] = key

        if audit:
            headers["X-Audit-Secret"] = self.secret

        r = await self.client.request(
            method,
            self.base + self.routes[route],
            headers=headers,
            json=data,
            params=params
        )

        if r.status_code in (301, 302, 303, 307, 308):
            raise RuntimeError(
                f"Unexpected redirect on {route}: "
                f"{r.status_code}; refused to follow"
            )

        content_type = r.headers.get(
            "content-type", ""
        )

        try:
            payload = (
                r.json()
                if "json" in content_type
                else None
            )
        except ValueError:
            payload = None

        return r.status_code, payload

    async def state(self, account):
        code, data = await self.send(
            "state",
            method="GET",
            audit=True,
            params={"account": account}
        )

        names = (
            "balance_minor",
            "ledger_credits",
            "ledger_debits",
            "pending_count"
        )

        if (
            code != 200
            or not isinstance(data, dict)
            or any(
                type(data.get(n)) is not int
                for n in names
            )
        ):
            raise RuntimeError(
                "Audit-state unavailable or missing "
                "integer counters; cannot validate "
                "financial side effects"
            )

        return {
            n: data[n]
            for n in names
        }

    async def charge(
        self,
        amount,
        account="a",
        key=None,
        extra=None
    ):
        d = {
            "amount_minor": amount,
            "currency": "IRR"
        }

        if extra:
            d.update(extra)

        return await self.send(
            "charge",
            account=account,
            data=d,
            key=key or "test-" + secrets.token_hex(12)
        )

    async def settle(
        self,
        topup_id,
        amt,
        currency="IRR",
        status="succeeded"
    ):
        code, data = await self.send(
            "settle",
            audit=True,
            data={
                "topup_id": topup_id,
                "amount_minor": amt,
                "currency": currency,
                "status": status
            }
        )

        if code != 200:
            raise RuntimeError(
                "Fake-gateway-settle unavailable: "
                f"HTTP {code}. Only available "
                "in a test adapter"
            )

    async def verify(
        self,
        topup_id,
        account="a",
        extra=None
    ):
        payload = {
            "topup_id": topup_id
        }

        if extra:
            payload.update(extra)

        return await self.send(
            "verify",
            account=account,
            data=payload
        )

    async def new_topup(self, amount):
        code, data = await self.charge(amount)

        if (
            code not in (200, 201)
            or not isinstance(data, dict)
            or not isinstance(
                data.get("topup_id"), str
            )
        ):
            raise RuntimeError(
                f"Topup initiation failed: HTTP {code}; "
                "check route/payload mapping"
            )

        return data["topup_id"]

    def add(self, name, ok, **evidence):
        verdict = "PASS" if ok else "FAIL"

        self.cases.append(
            Case(name, verdict, evidence)
        )

        print(
            f"[{verdict:4}] {name}: {evidence}"
        )

    async def test_unauthenticated(self):
        before = await self.state("a")

        code, _ = await self.send(
            "charge",
            data={
                "amount_minor": 500,
                "currency": "IRR"
            },
            key="test-" + secrets.token_hex(12)
        )

        after = await self.state("a")

        self.add(
            "charge_without_auth",
            code in (401, 403) and before == after,
            status=code,
            unchanged=(before == after)
        )

    async def test_invalid_amounts(self):
        before = await self.state("a")
        codes = []

        for bad in (
            0,
            -100,
            "100",
            100.5,
            999999999
        ):
            code, _ = await self.charge(bad)
            codes.append(code)

        after = await self.state("a")

        self.add(
            "invalid_amounts",
            all(
                x in (400, 422)
                for x in codes
            ) and before == after,
            statuses=codes,
            unchanged=(before == after)
        )

    async def test_init_idempotency(self):
        before = await self.state("a")

        key = "test-" + secrets.token_hex(12)

        c1, b1 = await self.charge(
            400, key=key
        )
        c2, b2 = await self.charge(
            400, key=key
        )

        after = await self.state("a")

        same = (
            isinstance(b1, dict)
            and isinstance(b2, dict)
            and b1.get("topup_id") == b2.get("topup_id")
            and bool(b1.get("topup_id"))
        )

        # Returning 409 on duplicate is also acceptable
        acceptable = same or c2 == 409

        ok = (
            c1 in (200, 201)
            and acceptable
            and (
                after["pending_count"]
                - before["pending_count"]
            ) == 1
            and (
                after["balance_minor"]
                == before["balance_minor"]
            )
        )

        self.add(
            "initiation_idempotency",
            ok,
            statuses=[c1, c2],
            same_reference=same,
            pending_delta=(
                after["pending_count"]
                - before["pending_count"]
            )
        )

    async def test_no_gateway(self):
        ref = await self.new_topup(500)

        before = await self.state("a")

        code, _ = await self.verify(
            ref,
            extra={
                "amount_minor": 500,
                "status": "succeeded"
            }
        )

        after = await self.state("a")

        self.add(
            "unverified_payment_cannot_credit",
            code not in range(200, 300)
            and before == after,
            status=code,
            unchanged=before == after
        )

    async def test_mismatch(self, currency=False):
        amount = 600
        ref = await self.new_topup(amount)

        await self.settle(
            ref,
            amount if currency else amount - 1,
            "USD" if currency else "IRR"
        )

        before = await self.state("a")
        code, _ = await self.verify(ref)
        after = await self.state("a")

        name = (
            "gateway_currency_mismatch"
            if currency
            else "gateway_amount_mismatch"
        )

        self.add(
            name,
            code not in range(200, 300)
            and before == after,
            status=code,
            unchanged=before == after
        )

    async def test_failed_gateway(self):
        ref = await self.new_topup(500)

        await self.settle(
            ref,
            500,
            status="failed"
        )

        before = await self.state("a")
        code, _ = await self.verify(ref)
        after = await self.state("a")

        self.add(
            "failed_gateway_cannot_credit",
            code not in range(200, 300)
            and before == after,
            status=code,
            unchanged=before == after
        )

    async def test_cross_account(self):
        ref = await self.new_topup(650)
        await self.settle(ref, 650)

        before_a = await self.state("a")
        before_b = await self.state("b")

        code, _ = await self.verify(
            ref,
            account="b"
        )

        after_a = await self.state("a")
        after_b = await self.state("b")

        self.add(
            "cross_account_verification",
            (
                code in (401, 403, 404)
                and before_a == after_a
                and before_b == after_b
            ),
            status=code,
            both_unchanged=(
                before_a == after_a
                and before_b == after_b
            )
        )

    async def test_override_and_replay(self):
        ref = await self.new_topup(800)
        await self.settle(ref, 800)

        before_a = await self.state("a")
        before_b = await self.state("b")

        code, _ = await self.verify(
            ref,
            extra={
                "amount_minor": 80000,
                "user_id": "b"
            }
        )

        after_a = await self.state("a")
        after_b = await self.state("b")

        amount_delta = (
            after_a["balance_minor"]
            - before_a["balance_minor"]
        )
        ledger_delta = (
            after_a["ledger_credits"]
            - before_a["ledger_credits"]
        )

        untouched_b = before_b == after_b

        safe_rejection = (
            code in (400, 401, 403, 404, 409, 422)
            and before_a == after_a
            and untouched_b
        )

        safe_acceptance = (
            code in (200, 201, 204)
            and amount_delta == 800
            and ledger_delta == 1
            and untouched_b
        )

        self.add(
            "client_amount_override",
            safe_rejection or safe_acceptance,
            status=code,
            credited_minor=amount_delta,
            credit_entries=ledger_delta,
            other_account_unchanged=untouched_b,
            safe_rejection=safe_rejection
        )

        if safe_rejection:
            init_status, _ = await self.verify(ref)
            first_confirmed = await self.state("a")

            credit_ok = (
                init_status in (200, 201, 204)
                and (
                    first_confirmed["balance_minor"]
                    - before_a["balance_minor"]
                ) == 800
                and (
                    first_confirmed["ledger_credits"]
                    - before_a["ledger_credits"]
                ) == 1
            )

            if not credit_ok:
                self.cases.append(
                    Case(
                        "sequential_replay",
                        "BLOCKED",
                        {
                            "reason":
                            "first legitimate confirmation not established"
                        }
                    )
                )
                return

        elif safe_acceptance:
            first_confirmed = after_a

        else:
            self.cases.append(
                Case(
                    "sequential_replay",
                    "BLOCKED",
                    {
                        "reason":
                        "initial confirmation result ambiguous"
                    }
                )
            )
            return

        code2, _ = await self.verify(ref)
        replay_after = await self.state("a")

        self.add(
            "sequential_replay",
            first_confirmed == replay_after,
            status=code2,
            unchanged=first_confirmed == replay_after
        )
    
    async def test_parallel_verify(self):
        ref = await self.new_topup(900)
        await self.settle(ref, 900)

        before = await self.state("a")

        gate = asyncio.Event()

        async def call():
            await gate.wait()

            status, _ = await self.verify(ref)
            return status

        tasks = [
            asyncio.create_task(call())
            for _ in range(3)
        ]

        await asyncio.sleep(0.05)
        gate.set()

        codes = await asyncio.gather(*tasks)

        after = await self.state("a")

        delta = (
            after["balance_minor"]
            - before["balance_minor"]
        )

        credits = (
            after["ledger_credits"]
            - before["ledger_credits"]
        )

        self.add(
            "concurrent_gateway_confirmation_3",
            delta == 900 and credits == 1,
            statuses=codes,
            credited_minor=delta,
            credit_entries=credits
        )

    async def test_parallel_spend(self):
        before = await self.state("b")

        # Each spend is more than half the balance
        amount = before["balance_minor"] * 7 // 10

        if amount <= 0:
            raise RuntimeError(
                "Fixture account b has "
                "insufficient test balance"
            )

        gate = asyncio.Event()

        async def call():
            await gate.wait()

            code, _ = await self.send(
                "spend",
                account="b",
                data={
                    "amount_minor": amount
                },
                key="test-" + secrets.token_hex(12)
            )

            return code

        tasks = [
            asyncio.create_task(call())
            for _ in range(2)
        ]

        await asyncio.sleep(0.05)
        gate.set()

        codes = await asyncio.gather(*tasks)

        after = await self.state("b")

        debits = (
            after["ledger_debits"]
            - before["ledger_debits"]
        )

        delta = (
            before["balance_minor"]
            - after["balance_minor"]
        )

        self.add(
            "concurrent_overspend_2",
            (
                after["balance_minor"] >= 0
                and debits == 1
                and delta == amount
            ),
            statuses=codes,
            debit_amount_minor=delta,
            debit_entries=debits,
            balance_minor=after["balance_minor"]
        )

    async def execute(self):
        tests = [
            self.test_unauthenticated,
            self.test_invalid_amounts,
            self.test_init_idempotency,
            self.test_no_gateway,
            self.test_mismatch,
            lambda: self.test_mismatch(
                currency=True
            ),
            self.test_failed_gateway,
            self.test_cross_account,
            self.test_override_and_replay,
            self.test_parallel_verify,
            self.test_parallel_spend
        ]

        for test in tests:
            try:
                await test()

            except (
                httpx.RequestError,
                RuntimeError,
                ValueError,
                KeyError,
                TypeError
            ) as e:

                name = getattr(
                    test,
                    "__name__",
                    "gateway_currency_mismatch"
                )

                self.cases.append(
                    Case(
                        name,
                        "BLOCKED",
                        {
                            "reason": str(e)[:160]
                        }
                    )
                )

                print(
                    f"[BLOCKED] {name}: "
                    f"{type(e).__name__}: "
                    f"{str(e)[:120]}"
                )

                if (
                    "Audit-state" in str(e)
                    or "gateway-settle" in str(e)
                    or isinstance(e, httpx.RequestError)
                ):
                    break

        passed = sum(
            x.verdict == "PASS"
            for x in self.cases
        )

        failed = sum(
            x.verdict == "FAIL"
            for x in self.cases
        )

        blocked = sum(
            x.verdict == "BLOCKED"
            for x in self.cases
        )

        return {
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "target": self.base,
            "note": (
                "No tokens, gateway secret, "
                "request/response payloads or "
                "personal data stored."
            ),
            "counts": {
                "pass": passed,
                "fail": failed,
                "blocked": blocked
            },
            "scenarios": [
                vars(x)
                for x in self.cases
            ]
        }


def main():
    p = argparse.ArgumentParser(
        description=(
            "Isolated payment logic tests "
            "with financial state assertions"
        )
    )

    p.add_argument(
        "--base",
        default="http://127.0.0.1:8766",
        help=(
            "Origin only: local lab or "
            "clearly named HTTPS staging"
        )
    )

    p.add_argument(
        "--config",
        help=(
            "Optional JSON route overrides; "
            "request schema must match lab adapter"
        )
    )

    p.add_argument(
        "--auth-format",
        choices=("raw", "bearer"),
        default="raw"
    )

    p.add_argument(
        "--confirm-staging",
        action="store_true",
        help=(
            "Confirm isolated test accounts "
            "and fake-money gateway"
        )
    )

    p.add_argument(
        "--report",
        default="payment_report.json"
    )

    p.add_argument(
        "--timeout",
        type=float,
        default=8.0
    )

    args = p.parse_args()

    try:
        base, local = validate_target(
            args.base
        )

        routes = routes_from_config(
            args.config
        )

        if not local and not args.confirm_staging:
            p.error(
                "Remote testing requires "
                "--confirm-staging after "
                "verifying fake money + "
                "disposable accounts"
            )

        token_a = os.environ.get("PAY_A_TOKEN", "")
        token_b = os.environ.get("PAY_B_TOKEN", "")
        secret = os.environ.get("PAY_AUDIT_SECRET", "")
        if not token_a or not token_b or not secret:
            p.error("Set PAY_A_TOKEN, PAY_B_TOKEN, and PAY_AUDIT_SECRET for your lab/staging fixture")

        if token_a == token_b:
            p.error(
                "Test account tokens must differ"
            )

        async def run_all():
            audit = Audit(
                base,
                routes,
                token_a,
                token_b,
                secret,
                args.auth_format,
                args.timeout
            )

            try:
                return await audit.execute()
            finally:
                await audit.close()

        report = asyncio.run(run_all())

        Path(args.report).write_text(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

        print(
            "\nSUMMARY:",
            report["counts"],
            "\nReport:",
            args.report
        )

        raise SystemExit(
            2 if (
                report["counts"]["fail"]
                or report["counts"]["blocked"]
            ) else 0
        )

    except (
        ValueError,
        OSError,
        json.JSONDecodeError
    ) as e:
        p.error(str(e))


if __name__ == "__main__":
    main()