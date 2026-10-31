from nextaudit import __version__
from nextaudit.cli import main
from nextaudit.access_audit import safe_endpoint
from nextaudit.payment_audit import validate_target


def test_version(capsys):
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_authorization_gate():
    import pytest
    with pytest.raises(SystemExit) as err:
        main(["scan", "-u", "https://example.com"])
    assert err.value.code == 2


def test_access_safety():
    assert safe_endpoint("/health")
    assert not safe_endpoint("//evil.test/api")
    assert not safe_endpoint("/../private")
    assert not safe_endpoint("https://elsewhere.example/")


def test_payment_staging_gate():
    import pytest
    with pytest.raises(ValueError):
        validate_target("https://production.example.com")
    assert validate_target("http://127.0.0.1:8766")[1] is True
    assert validate_target("https://staging.example.com")[1] is False


def test_har_domain_filter():
    from nextaudit.har_review import inspect_entry

    entry = {"request": {"url": "https://other.example.com/api/wallet/charge", "method": "POST"},
             "response": {"status": 200}}
    assert inspect_entry(entry, 1, ["app.example.com"]) is None
    assert inspect_entry(entry, 1, ["example.com"], include_subdomains=True) is not None


def test_access_cookie_and_redirect_redaction():
    import httpx
    from nextaudit.access_audit import one_get

    seen_cookies = []

    def respond(request):
        seen_cookies.append(request.headers.get("cookie", ""))
        if request.url.path.endswith("start"):
            return httpx.Response(200, headers={"Set-Cookie": "session=private-value"}, json={"ok": True})
        return httpx.Response(302, headers={"Location": "https://example.com/redirect?token=do-not-leak"})

    with httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=False) as client:
        one_get(client, "https://example.com/start", {"Cookie": ""})
        after = one_get(client, "https://example.com/redirect", {"Cookie": ""})
    assert seen_cookies == ["", ""]
    assert after["location"] == "/redirect"
