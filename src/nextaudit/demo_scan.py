"""Run a small, intentionally misconfigured scan fixture on localhost.

It never contacts a public target and is not intended for deployment.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .reports import save_report, show_report
from .scanner import ScanOptions, Scanner


class Handler(BaseHTTPRequestHandler):
    """In-memory demo of common *indicators*, not confirmed exploits."""

    credential = ""

    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):
        if self.path == "/":
            content_type = "text/html"
            content = ('<html><script id="__NEXT_DATA__" type="application/json">'
                       '{"buildId":"example-build","props":{}}</script>'
                       '<script src="/static/app.js"></script><a href="/about">About</a></html>')
        elif self.path == "/about":
            content_type = "text/html"
            content = "<html><title>Local fixture</title><p>Illustrative site</p></html>"
        elif self.path == "/static/app.js":
            content_type = "application/javascript"
            content = (f'const api_key="{self.credential}"; fetch("/api/demo"); '
                       'document.body.innerHTML = "demo";\n//# sourceMappingURL=app.js.map')
        elif self.path == "/static/app.js.map":
            content_type = "application/json"
            content = json.dumps({"version": 3, "sources": ["src/app.js"],
                                  "sourcesContent": ['fetch("/api/demo")']})
        else:
            self.send_error(404)
            return
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Set-Cookie", "session=fixture; Path=/")
        self.end_headers()
        self.wfile.write(encoded)


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan an intentionally weak, loopback-only fixture")
    parser.add_argument("-o", "--output", help="Save a JSON demonstration report")
    args = parser.parse_args()
    Handler.credential = secrets.token_urlsafe(25)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        print("Scanning a deliberately weak LOCAL fixture; no external service is accessed.")
        report = asyncio.run(Scanner(ScanOptions(f"http://127.0.0.1:{server.server_port}",
                                                 allow_local=True, delay=0.1, max_pages=3)).run())
        show_report(report)
        if args.output:
            save_report(report, args.output, "json")
            print("Demo report saved:", args.output)
        return 0 if report.pages and report.source_maps else 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
