"""Exercise secure and intentionally vulnerable local payment fixtures.

Runs entirely on loopback, with ephemeral credentials and disposable state.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, process: subprocess.Popen) -> None:
    for _ in range(80):
        if process.poll() is not None:
            raise RuntimeError("Lab exited before it was reachable")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Lab failed to listen on local port {port}")


def exercise(unsafe: bool, path: Path, env: dict[str, str]) -> dict[str, int]:
    port = free_port()
    command = [sys.executable, "-m", "nextaudit.lab_server", "--port", str(port)]
    if unsafe:
        command += ["--unsafe-local-demo"]
    process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        wait_port(port, process)
        result = subprocess.run(
            [sys.executable, "-m", "nextaudit.payment_audit", "--base", f"http://127.0.0.1:{port}", "--report", str(path)],
            env=env, capture_output=True, text=True, timeout=90, check=False,
        )
        if result.returncode not in (0, 2):
            raise RuntimeError("Payment audit failed: " + result.stderr[-1200:])
        if not path.is_file():
            raise RuntimeError("Payment audit did not write a fresh report")
        report = json.loads(path.read_text(encoding="utf-8"))
        print(f"{'VULNERABLE' if unsafe else 'SECURE'} fixture: {report['counts']}")
        return report["counts"]
    finally:
        process.terminate()
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)


def main() -> int:
    env = dict(os.environ)
    token_a, token_b, secret = (secrets.token_urlsafe(32) for _ in range(3))
    env.update({"NEXTAUDIT_LAB_A_TOKEN": token_a, "NEXTAUDIT_LAB_B_TOKEN": token_b,
                "NEXTAUDIT_LAB_SECRET": secret, "PAY_A_TOKEN": token_a,
                "PAY_B_TOKEN": token_b, "PAY_AUDIT_SECRET": secret})
    with tempfile.TemporaryDirectory(prefix="nextaudit-demo-") as tmp:
        secure = exercise(False, Path(tmp) / "secure.json", env)
        vulnerable = exercise(True, Path(tmp) / "vulnerable.json", env)
    if secure != {"pass": 12, "fail": 0, "blocked": 0} or vulnerable["fail"] < 2:
        print("Unexpected lab result; inspect fixture logic", file=sys.stderr)
        return 1
    print("Local demo passed. No external hosts or real payments were used.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
