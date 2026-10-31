"""Read-only web auditor with strict same-origin crawl and bounded downloads.

All network operations use GET (and one optional GET with a test Origin header).
Findings are indicators for manual verification, not exploit confirmations.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import asdict, dataclass, field
from html import unescape
from datetime import datetime, timezone
import ipaddress
import json
import re
import time
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from . import __version__

USER_AGENT = f"NextAudit/{__version__} (authorized, read-only security inspection)"
SCRIPT_PATTERN = re.compile(r"(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['\"`](/[^'\"`\s?]{1,180})", re.I)
ROUTE_PATTERN = re.compile(r"['\"](/(?:[A-Za-z0-9_\-\[\]/]{1,120}))['\"]")
SOURCE_MAPPING = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*([^\s]+)")
SITEMAP_LOC = re.compile(r"<loc>\s*([^<]{1,2048})\s*</loc>", re.I)

# The scanner does not include code fragments or detected secret values in reports.
CODE_RULES: tuple[tuple[str, str, str, str, re.Pattern[str]], ...] = (
    ("JS_SECRET_ASSIGNMENT", "Potential embedded credential", "HIGH", "medium",
     re.compile(r"(?i)\b(?:api[_-]?key|secret|auth[_-]?token|password|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9._\-+/=]{16,}['\"]")),
    ("AWS_ACCESS_KEY", "AWS access-key-shaped string", "HIGH", "medium",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("JWT_IN_BUNDLE", "JWT-shaped token in client code", "HIGH", "medium",
     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}")),
    ("GOOGLE_API_KEY", "Google API-key-shaped string (usually public)", "INFO", "medium",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("DOM_HTML_SINK", "HTML injection sink; verify sanitization", "MEDIUM", "low",
     re.compile(r"\bdangerouslySetInnerHTML\b|\.innerHTML\s*=")),
    ("DYNAMIC_EVAL", "Dynamic JavaScript execution; review inputs", "MEDIUM", "low",
     re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")),
    ("NEXT_PUBLIC_ENV", "Public Next.js environment variable reference", "INFO", "high",
     re.compile(r"process\.env\.NEXT_PUBLIC_[A-Z][A-Z0-9_]*")),
    ("REDIRECT_SINK", "Potential client-side redirect sink", "LOW", "low",
     re.compile(r"\b(?:window\.location\.(?:assign|replace)|router\.push)\s*\(")),
)
REMEDIATION = {
    "MISSING_CSP": "Adopt a restrictive, tested Content-Security-Policy; account for legitimate scripts.",
    "MISSING_HSTS": "For HTTPS sites, configure Strict-Transport-Security after verifying HTTPS coverage.",
    "MISSING_NOSNIFF": "Set X-Content-Type-Options: nosniff.",
    "MISSING_REFERRER_POLICY": "Set an appropriate Referrer-Policy, such as strict-origin-when-cross-origin.",
    "MISSING_FRAMING_POLICY": "Set CSP frame-ancestors or X-Frame-Options to control framing.",
    "COOKIE_FLAGS": "Review each cookie's purpose and use Secure, HttpOnly and SameSite when applicable.",
    "CORS_REFLECTION": "Whitelist exact trusted origins; never reflect arbitrary Origin with credentials.",
    "EXPOSED_SOURCEMAP": "Review source-map publishing settings and remove sensitive sources from public builds.",
    "JS_SECRET_ASSIGNMENT": "Move server credentials to server-only secrets; rotate any truly exposed keys.",
    "AWS_ACCESS_KEY": "Investigate key ownership, rotate if live, and avoid placing secrets in client bundles.",
    "JWT_IN_BUNDLE": "Determine whether this is a sample or live token and stop embedding session tokens.",
    "GOOGLE_API_KEY": "Browser API keys can be intentionally public; restrict their API permissions and origins.",
    "DOM_HTML_SINK": "Trace untrusted inputs and use contextual encoding or proven HTML sanitization.",
    "DYNAMIC_EVAL": "Avoid eval/new Function with untrusted input; prefer data parsing.",
    "NEXT_PUBLIC_ENV": "NEXT_PUBLIC values are intentionally public; check that none are sensitive.",
    "REDIRECT_SINK": "Validate destination URLs against an allowlist at the actual redirect call site.",
}


@dataclass(frozen=True)
class ScanOptions:
    target: str
    max_pages: int = 10
    max_scripts: int = 30
    max_sourcemaps: int = 12
    max_bytes: int = 1_500_000
    max_requests: int = 90
    concurrency: int = 3
    delay: float = 0.3
    timeout: float = 10.0
    crawl: bool = True
    sitemap: bool = False
    next_manifest: bool = True
    check_cors: bool = False
    allow_local: bool = False
    auth_header: str | None = field(default=None, repr=False)
    ignored_rules: frozenset[str] = frozenset()

    def validate(self) -> str:
        if not 1 <= self.max_pages <= 100 or not 1 <= self.max_scripts <= 200:
            raise ValueError("--max-pages must be 1..100; --max-scripts must be 1..200")
        if not 0 <= self.max_sourcemaps <= 100 or not 1 <= self.concurrency <= 10:
            raise ValueError("--max-sourcemaps must be 0..100; --concurrency must be 1..10")
        if not 1 <= self.max_requests <= 500 or not 4096 <= self.max_bytes <= 10_000_000:
            raise ValueError("--max-requests must be 1..500; --max-bytes must be 4096..10000000")
        if not 0.1 <= self.delay <= 30 or not 1 <= self.timeout <= 120:
            raise ValueError("--delay must be 0.1..30 seconds; --timeout must be 1..120")
        return validate_url(self.target, self.allow_local)


def validate_url(raw: str, allow_local: bool = False) -> str:
    """Require an unambiguous HTTP(S) origin with optional path, no query/fragment."""
    p = urlsplit(raw)
    if (p.scheme not in ("http", "https") or not p.hostname or p.username or p.password
            or p.query or p.fragment or "\\" in raw or any(c.isspace() for c in raw)):
        raise ValueError("Target must be an HTTP(S) URL without credentials, query or fragment")
    try:
        port = p.port
    except ValueError as exc:
        raise ValueError("Invalid target port") from exc
    host = p.hostname.lower().rstrip(".")
    local_hostname = host == "localhost" or host.endswith((".localhost", ".local", ".internal"))
    try:
        local_ip = not ipaddress.ip_address(host).is_global
    except ValueError:
        local_ip = False
    if p.scheme == "http" and not (allow_local and (local_hostname or local_ip)):
        raise ValueError("HTTP is allowed only for explicit local/private targets with --allow-local")
    if not allow_local:
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise ValueError("Private/local targets require --allow-local")
        try:
            ip = ipaddress.ip_address(host)
            if not ip.is_global:
                raise ValueError("Private/reserved IP targets require --allow-local")
        except ValueError as exc:
            if "require --allow-local" in str(exc):
                raise
        if p.scheme != "https":
            raise ValueError("Remote targets require HTTPS; use --allow-local for a local HTTP lab")
    if p.netloc.endswith(":") or (port is not None and port == 0):
        raise ValueError("Invalid target port")
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", ""))


def normalize_link(base: str, href: str, origin: str) -> str | None:
    """Resolve only same-origin paths; strip query strings and fragments."""
    if not isinstance(href, str) or not href or href.strip().lower().startswith(("javascript:", "data:", "mailto:", "tel:")):
        return None
    resolved = urlsplit(urljoin(base, href))
    if (resolved.scheme, resolved.netloc.lower()) != (urlsplit(origin).scheme, urlsplit(origin).netloc.lower()):
        return None
    if "\\" in href or not resolved.path.startswith("/") or any(x in resolved.path.lower() for x in ("%0d", "%0a", "%2f", "%5c")):
        return None
    return urlunsplit((resolved.scheme, resolved.netloc, resolved.path or "/", "", ""))


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    location: str
    detail: str
    remediation: str


@dataclass
class ScanReport:
    target: str
    started_at: str
    scanner_version: str = __version__
    status: str = "complete"
    framework: str = "Unknown"
    build_id: str | None = None
    pages: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    discovered_routes: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    requests_made: int = 0
    limits_reached: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["summary"] = {s: sum(f.severity == s for f in self.findings)
                             for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        return result


class Scanner:
    def __init__(self, options: ScanOptions, transport: httpx.AsyncBaseTransport | None = None):
        self.options = options
        self.origin = options.validate()
        self.report = ScanReport(target=self.origin, started_at=datetime.now(timezone.utc).isoformat())
        self._sem = asyncio.Semaphore(options.concurrency)
        self._time_lock = asyncio.Lock()
        self._request_lock = asyncio.Lock()
        self._last_start = 0.0
        self._seen_findings: set[tuple[str, str]] = set()
        self._transport = transport
        self._map_lock = asyncio.Lock()
        self._map_attempts = 0

    def _finding(self, rule: str, title: str, severity: str, confidence: str, location: str, detail: str) -> None:
        if rule in self.options.ignored_rules or (rule, location) in self._seen_findings:
            return
        self._seen_findings.add((rule, location))
        self.report.findings.append(Finding(rule, title, severity, confidence, location,
                                            detail, REMEDIATION[rule]))

    async def _get(self, client: httpx.AsyncClient, url: str, *, origin_probe: bool = False) -> tuple[httpx.Response, bytes] | None:
        url = normalize_link(self.origin, url, self.origin)
        if url is None:
            return None
        async with self._sem:
            async with self._request_lock:
                if self._stop:
                    return None
                if self.report.requests_made >= self.options.max_requests:
                    if "max_requests" not in self.report.limits_reached:
                        self.report.limits_reached.append("max_requests")
                    return None
                self.report.requests_made += 1
            async with self._time_lock:
                elapsed = time.monotonic() - self._last_start
                if self._last_start and elapsed < self.options.delay:
                    await asyncio.sleep(self.options.delay - elapsed)
                self._last_start = time.monotonic()
            headers = {"Accept": "text/html,application/javascript,application/json,*/*", "Cookie": ""}
            if origin_probe:
                headers["Origin"] = "https://audit-origin.invalid"
            try:
                async with client.stream("GET", url, headers=headers) as response:
                    if response.status_code == 429 or response.status_code >= 500:
                        self.report.errors.append(f"HTTP {response.status_code} at {url}; scanner stopped requesting more URLs")
                        self._stop = True
                    data = bytearray()
                    async for part in response.aiter_bytes():
                        remaining = self.options.max_bytes - len(data)
                        if len(part) > remaining:
                            self.report.errors.append(f"Response too large (capped) at {url}")
                            return None
                        data.extend(part)
                    return response, bytes(data)
            except (httpx.RequestError, httpx.TimeoutException) as exc:
                self.report.errors.append(f"{type(exc).__name__} at {url}")
                return None

    def _audit_headers(self, response: httpx.Response, url: str) -> None:
        h = response.headers
        csp = h.get("content-security-policy", "")
        if not csp:
            self._finding("MISSING_CSP", "No Content-Security-Policy", "MEDIUM", "high", url, "CSP response header absent")
        if urlsplit(url).scheme == "https" and not h.get("strict-transport-security"):
            self._finding("MISSING_HSTS", "No HSTS header", "LOW", "high", url, "HSTS absent on HTTPS response")
        if not h.get("x-content-type-options", "").lower().startswith("nosniff"):
            self._finding("MISSING_NOSNIFF", "Missing nosniff", "LOW", "high", url, "X-Content-Type-Options is not nosniff")
        if not h.get("referrer-policy"):
            self._finding("MISSING_REFERRER_POLICY", "Missing Referrer-Policy", "LOW", "high", url, "Referrer-Policy absent")
        if not h.get("x-frame-options") and "frame-ancestors" not in csp.lower():
            self._finding("MISSING_FRAMING_POLICY", "No framing restriction", "MEDIUM", "high", url, "Neither X-Frame-Options nor CSP frame-ancestors")
        for cookie in h.get_list("set-cookie"):
            name = cookie.split("=", 1)[0].strip()[:64]
            flags = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]}
            missing = [flag for flag in ("httponly", "samesite") if flag not in flags]
            if urlsplit(url).scheme == "https" and "secure" not in flags:
                missing.append("secure")
            if missing:
                self._finding("COOKIE_FLAGS", "Cookie security flags", "LOW", "high", url + "#cookie=" + name,
                              f"Cookie {name}: absent {', '.join(missing)} (review cookie purpose)")

    def _fingerprint(self, soup: BeautifulSoup) -> None:
        data = soup.select_one("script#__NEXT_DATA__")
        if data and data.string:
            self.report.framework = "Next.js Pages Router"
            try:
                parsed = json.loads(data.string)
                value = parsed.get("buildId")
                if isinstance(value, str):
                    self.report.build_id = value[:100]
            except (ValueError, AttributeError):
                pass
        elif any("self.__next_f.push" in (x.string or "") for x in soup.find_all("script")):
            self.report.framework = "Next.js App Router"

    def _scan_code(self, code: str, url: str) -> None:
        for rule_id, title, severity, confidence, regex in CODE_RULES:
            match = regex.search(code)
            if match:
                line = code.count("\n", 0, match.start()) + 1
                self._finding(rule_id, title, severity, confidence, url, f"Pattern found near line {line}; value redacted")
        for match in SCRIPT_PATTERN.finditer(code):
            path = match.group(1)
            if path not in self.report.api_endpoints and len(self.report.api_endpoints) < 500:
                self.report.api_endpoints.append(path)
        if "_buildManifest" in url:
            for route in ROUTE_PATTERN.findall(code):
                if route not in self.report.discovered_routes and len(self.report.discovered_routes) < 500:
                    self.report.discovered_routes.append(route)

    async def _process_script(self, client: httpx.AsyncClient, url: str) -> None:
        if self._stop:
            return
        retrieved = await self._get(client, url)
        if retrieved is None:
            return
        response, raw = retrieved
        if response.status_code != 200 or "text/html" in response.headers.get("content-type", ""):
            return
        code = raw.decode("utf-8", "replace")
        self._scan_code(code, url)
        async with self._map_lock:
            if self._map_attempts >= self.options.max_sourcemaps or self._stop:
                return
            self._map_attempts += 1
        match = SOURCE_MAPPING.search(code[-4000:])
        candidate = urljoin(url, match.group(1)) if match and not match.group(1).startswith("data:") else url + ".map"
        mapped = normalize_link(url, candidate, self.origin)
        if not mapped:
            return
        sm = await self._get(client, mapped)
        if sm is None or sm[0].status_code != 200:
            return
        try:
            data = json.loads(sm[1])
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(data, dict) or not isinstance(data.get("sources"), list) or data.get("version") != 3:
            return
        self.report.source_maps.append(mapped)
        self._finding("EXPOSED_SOURCEMAP", "Public JavaScript source map", "MEDIUM", "high", mapped,
                      f"Valid v3 source map includes {len(data['sources'])} source references")
        contents = data.get("sourcesContent", [])
        if isinstance(contents, list):
            for index, source in enumerate(contents[:200]):
                if not isinstance(source, str) or len(source) > self.options.max_bytes:
                    continue
                source_name = str(data["sources"][index]) if index < len(data["sources"]) else f"file-{index}"
                if "node_modules" in source_name or "webpack/bootstrap" in source_name:
                    continue
                # Use map URL as location; original source names can contain user data.
                self._scan_code(source, mapped)

    async def run(self) -> ScanReport:
        self._stop = False
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, **({"Authorization": self.options.auth_header} if self.options.auth_header else {})},
            timeout=self.options.timeout, follow_redirects=False, trust_env=False,
            http2=True, transport=self._transport,
        ) as client:
            pending = deque([self.origin])
            if self.options.sitemap and self.options.crawl:
                sitemap_url = urljoin(self.origin, "/sitemap.xml")
                sitemap_response = await self._get(client, sitemap_url)
                if sitemap_response and sitemap_response[0].status_code == 200:
                    try:
                        sitemap_text = sitemap_response[1].decode("utf-8")
                        for raw_url in SITEMAP_LOC.findall(sitemap_text)[:self.options.max_pages * 5]:
                            url = normalize_link(sitemap_url, unescape(raw_url).strip(), self.origin)
                            if url and url not in pending and len(pending) <= self.options.max_pages * 5:
                                pending.append(url)
                    except UnicodeError:
                        self.report.errors.append("Invalid UTF-8 sitemap; continuing without it")
            seen_pages: set[str] = set()
            scripts: list[str] = []
            seen_scripts: set[str] = set()
            while pending and len(seen_pages) < self.options.max_pages and not self._stop:
                page = pending.popleft()
                if page in seen_pages:
                    continue
                seen_pages.add(page)
                r = await self._get(client, page)
                if r is None:
                    continue
                response, raw = r
                if response.status_code != 200 or "html" not in response.headers.get("content-type", "").lower():
                    if page == self.origin:
                        self.report.errors.append(f"Initial URL did not return HTML 200 (HTTP {response.status_code}); use its canonical URL")
                    continue
                self.report.pages.append(page)
                self._audit_headers(response, page)
                soup = BeautifulSoup(raw, "html.parser")
                if len(self.report.pages) == 1:
                    self._fingerprint(soup)
                for s in [*soup.find_all("script", src=True), *[x for x in soup.find_all("link", href=True)
                          if "modulepreload" in x.get("rel", []) or ("preload" in x.get("rel", []) and x.get("as") == "script")]]:
                    url = normalize_link(page, s.get("src") or s.get("href"), self.origin)
                    if url and url not in seen_scripts and len(scripts) < self.options.max_scripts:
                        seen_scripts.add(url)
                        scripts.append(url)
                if not self.options.crawl:
                    continue
                for a in soup.find_all("a", href=True):
                    url = normalize_link(page, a["href"], self.origin)
                    if url and url not in seen_pages and url not in pending and len(pending) < self.options.max_pages * 5:
                        pending.append(url)
            if self.options.next_manifest and self.report.build_id and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", self.report.build_id):
                manifest = normalize_link(self.origin, f"/_next/static/{self.report.build_id}/_buildManifest.js", self.origin)
                if manifest and manifest not in seen_scripts and len(scripts) < self.options.max_scripts:
                    scripts.append(manifest)
            self.report.scripts = scripts
            if self.options.check_cors and not self._stop:
                probe = await self._get(client, self.origin, origin_probe=True)
                if probe:
                    hdr = probe[0].headers
                    if (hdr.get("access-control-allow-origin") == "https://audit-origin.invalid"
                            and hdr.get("access-control-allow-credentials", "").lower() == "true"):
                        self._finding("CORS_REFLECTION", "Credentialed CORS origin reflection", "HIGH", "medium",
                                      self.origin, "Arbitrary Origin reflected together with Allow-Credentials")
            await asyncio.gather(*(self._process_script(client, script) for script in scripts))
        if self.report.errors or self.report.limits_reached or not self.report.pages:
            self.report.status = "partial" if self.report.pages else "error"
        self.report.findings.sort(key=lambda f: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.severity], f.rule_id, f.location))
        self.report.discovered_routes.sort()
        self.report.api_endpoints.sort()
        return self.report
