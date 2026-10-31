"""Regression tests use in-memory HTTP only: no public site contact."""
import asyncio
import json

import httpx
import pytest

from nextaudit.reports import markdown, sarif
from nextaudit.scanner import ScanOptions, Scanner, normalize_link, validate_url


def test_url_scope():
    assert validate_url("https://Example.COM/anything") == "https://example.com/anything"
    with pytest.raises(ValueError):
        validate_url("https://example.com/?auth=private")
    with pytest.raises(ValueError):
        validate_url("http://example.com/")
    with pytest.raises(ValueError):
        validate_url("http://example.com/", allow_local=True)
    with pytest.raises(ValueError):
        validate_url("http://127.0.0.1:9000/")
    assert validate_url("http://127.0.0.1:9000/", allow_local=True) == "http://127.0.0.1:9000/"
    with pytest.raises(ValueError):
        validate_url("https://name:password@example.com")
    with pytest.raises(ValueError):
        validate_url("https://192.168.1.1/")


def test_link_scope():
    origin = "https://example.com/"
    assert normalize_link(origin, "/p?q=secret#frag", origin) == "https://example.com/p"
    assert normalize_link(origin, "//attacker.example/p", origin) is None
    assert normalize_link(origin, "javascript:alert(1)", origin) is None
    assert normalize_link(origin, "https://example.com:444/", origin) is None


def test_limits():
    with pytest.raises(ValueError):
        ScanOptions(target="https://example.com/", concurrency=99).validate()
    with pytest.raises(ValueError):
        ScanOptions(target="https://example.com/", max_requests=0).validate()


def test_end_to_end_no_secret_leak():
    requested = []
    token = "AKIA" + "A" * 16
    secret = "1234567890123456"
    page = '''<html><script id="__NEXT_DATA__" type="application/json">{"buildId":"dev-test","props":{}}</script>
    <script src="/static/bundle.js"></script><a href="/about?token=secret">about</a>
    <script src="https://outside.invalid/test.js"></script></html>'''
    bundle = f'''const api_key="{secret}"; const leaked="{token}";
    fetch("/api/health"); eval(source);
    //# sourceMappingURL=bundle.js.map'''
    mapdata = {"version": 3, "sources": ["src/app.js"], "sourcesContent": ["document.body.innerHTML = untrusted;"]}

    def respond(request: httpx.Request) -> httpx.Response:
        requested.append((str(request.url), request.method))
        p = request.url.path
        if p == "/":
            return httpx.Response(200, headers={"content-type": "text/html", "set-cookie": "session=abc; Path=/"}, text=page)
        if p == "/about":
            return httpx.Response(200, headers={"content-type": "text/html"}, text="<a href='https://outside.invalid/'>offsite</a>")
        if p == "/static/bundle.js":
            return httpx.Response(200, headers={"content-type": "application/javascript"}, text=bundle)
        if p == "/static/bundle.js.map":
            return httpx.Response(200, headers={"content-type": "application/json"}, json=mapdata)
        return httpx.Response(404)

    options = ScanOptions("https://example.com/", max_pages=3, delay=0.1, max_requests=15)
    report = asyncio.run(Scanner(options, transport=httpx.MockTransport(respond)).run())
    assert report.framework == "Next.js Pages Router"
    assert report.build_id == "dev-test"
    assert report.status == "complete"
    assert len(report.pages) == 2
    assert len(report.source_maps) == 1
    assert "/api/health" in report.api_endpoints
    assert {"AWS_ACCESS_KEY", "JS_SECRET_ASSIGNMENT", "EXPOSED_SOURCEMAP", "DOM_HTML_SINK"}.issubset({x.rule_id for x in report.findings})
    rendered = json.dumps(report.to_dict()) + json.dumps(sarif(report)) + markdown(report)
    assert token not in rendered
    assert secret not in rendered
    assert all(m == "GET" for _, m in requested)
    assert all(u.startswith("https://example.com/") for u, _ in requested)
    assert not any("token=secret" in u for u, _ in requested)


def test_cors_check_only_when_requested():
    def respond(request):
        headers = {"content-type": "text/html"}
        if request.headers.get("origin") == "https://audit-origin.invalid":
            headers.update({"access-control-allow-origin": "https://audit-origin.invalid",
                            "access-control-allow-credentials": "true"})
        return httpx.Response(200, headers=headers, text="<p>ok</p>")

    opts = ScanOptions("https://example.com", check_cors=True, max_pages=1, delay=0.1)
    found = asyncio.run(Scanner(opts, transport=httpx.MockTransport(respond)).run())
    assert "CORS_REFLECTION" in {f.rule_id for f in found.findings}
    opts2 = ScanOptions("https://example.com", check_cors=False, max_pages=1, delay=0.1)
    not_found = asyncio.run(Scanner(opts2, transport=httpx.MockTransport(respond)).run())
    assert "CORS_REFLECTION" not in {f.rule_id for f in not_found.findings}


def test_error_status_and_stop():
    def respond(request):
        return httpx.Response(429, text="slow down")

    report = asyncio.run(Scanner(ScanOptions("https://example.com", delay=0.1),
                                 transport=httpx.MockTransport(respond)).run())
    assert report.status == "error"
    assert report.requests_made == 1
    assert any("429" in warning for warning in report.errors)


def test_optional_sitemap_increases_bounded_coverage():
    paths = []

    def respond(request):
        paths.append(request.url.path)
        if request.url.path == "/sitemap.xml":
            return httpx.Response(200, text="<urlset><url><loc>https://example.com/extra?p=2</loc></url>"
                                                  "<url><loc>https://different.invalid/external</loc></url></urlset>")
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<p>local fixture</p>")

    options = ScanOptions("https://example.com", sitemap=True, max_pages=2, delay=0.1)
    report = asyncio.run(Scanner(options, transport=httpx.MockTransport(respond)).run())
    assert "/sitemap.xml" in paths
    assert "/extra" in paths
    assert all(not p.startswith("/external") for p in paths)
    assert len(report.pages) == 2
