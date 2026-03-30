"""
GetNexova Shuvon Scanner Suite (v2)
=====================================
Specialized scanners that ACTUALLY make HTTP requests
to confirm vulnerabilities, not just pattern match.

- IDORScanner:     Sends requests with manipulated IDs, compares responses
- OAuthScanner:    Tests redirect_uri manipulation, state parameter
- RaceScanner:     Sends concurrent requests to detect race conditions
- GraphQLScanner:  Sends introspection query to confirm exposure
- AIProbeScanner:  Probes sensitive endpoints with real HTTP HEAD requests
"""

import asyncio
import json
import logging
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

logger = logging.getLogger("getnexova.shuvon")

# Try aiohttp for real HTTP requests
try:
    import aiohttp
    AIOHTTP_OK = True
except ImportError:
    AIOHTTP_OK = False
    logger.warning("aiohttp not installed — Shuvon scanners will run in passive mode")

# Try urllib as fallback
if not AIOHTTP_OK:
    from urllib.request import Request, urlopen
    from urllib.error import URLError


@dataclass
class ShuvonFinding:
    scanner: str
    vulnerability_type: str
    target: str
    severity: str = "medium"
    confidence: float = 0.7
    evidence: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    poc: str = ""


class _HTTPClient:
    """Minimal async HTTP client wrapper for Shuvon scanners."""

    def __init__(self, timeout: int = 10, headers: Optional[Dict] = None):
        self.timeout = timeout
        self.headers = headers or {"User-Agent": "GetNexova/4.0 (Security Scanner)"}

    async def get(self, url: str) -> Tuple[int, str, Dict[str, str]]:
        """GET request → (status_code, body, headers)."""
        if AIOHTTP_OK:
            try:
                ct = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=ct, headers=self.headers) as s:
                    async with s.get(url, ssl=False, allow_redirects=False) as r:
                        body = await r.text(errors="replace")
                        return r.status, body[:5000], dict(r.headers)
            except Exception as e:
                return 0, str(e), {}
        else:
            # Sync fallback
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._sync_get, url)

    async def post(self, url: str, data: Any = None, json_data: Any = None) -> Tuple[int, str, Dict]:
        if AIOHTTP_OK:
            try:
                ct = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=ct, headers=self.headers) as s:
                    async with s.post(url, data=data, json=json_data, ssl=False) as r:
                        body = await r.text(errors="replace")
                        return r.status, body[:5000], dict(r.headers)
            except Exception as e:
                return 0, str(e), {}
        return 0, "no http client", {}

    async def head(self, url: str) -> Tuple[int, Dict[str, str]]:
        if AIOHTTP_OK:
            try:
                ct = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=ct, headers=self.headers) as s:
                    async with s.head(url, ssl=False, allow_redirects=False) as r:
                        return r.status, dict(r.headers)
            except Exception:
                return 0, {}
        return 0, {}

    def _sync_get(self, url: str) -> Tuple[int, str, Dict]:
        try:
            req = Request(url, headers=self.headers, method="GET")
            with urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")[:5000], dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}


class IDORScanner:
    """IDOR detection by actually comparing responses with different IDs."""

    def __init__(self):
        self.name = "idor"
        self.http = _HTTPClient()
        self._patterns = [
            (r'([?&])id=(\d+)', 'id'),
            (r'([?&])user_id=(\d+)', 'user_id'),
            (r'([?&])account=(\d+)', 'account'),
            (r'([?&])order_id=(\d+)', 'order_id'),
            (r'/api/\w+/(\d+)(?:/|$)', 'path_id'),
        ]

    async def scan(self, urls: List[str], auth_headers: Optional[Dict] = None) -> List[ShuvonFinding]:
        findings = []
        if auth_headers:
            self.http.headers.update(auth_headers)

        sem = asyncio.Semaphore(5)
        for url in urls[:50]:  # Limit to avoid flooding
            async with sem:
                result = await self._test_url(url)
                if result:
                    findings.append(result)
        logger.info(f"IDOR scanner: {len(findings)} confirmed IDORs")
        return findings

    async def _test_url(self, url: str) -> Optional[ShuvonFinding]:
        for pattern, param_name in self._patterns:
            match = re.search(pattern, url)
            if not match:
                continue

            if param_name == "path_id":
                original_id = match.group(1)
            else:
                original_id = match.group(2)

            try:
                num = int(original_id)
            except ValueError:
                continue

            # Get original response
            status_orig, body_orig, _ = await self.http.get(url)
            if status_orig == 0 or status_orig >= 400:
                continue

            # Try with incremented ID
            test_url = url.replace(f"={original_id}", f"={num + 1}")
            if param_name == "path_id":
                test_url = url.replace(f"/{original_id}", f"/{num + 1}")

            status_test, body_test, _ = await self.http.get(test_url)

            # IDOR indicators:
            # - Both return 200 with different content
            # - The response has similar structure but different data
            if status_test == 200 and status_orig == 200:
                len_diff = abs(len(body_orig) - len(body_test))
                # Similar length but different content → likely IDOR
                if body_orig != body_test and len_diff < len(body_orig) * 0.5:
                    return ShuvonFinding(
                        scanner="idor",
                        vulnerability_type="Confirmed IDOR — Different data returned for different ID",
                        target=url,
                        severity="high",
                        confidence=0.75,
                        evidence=(
                            f"Original ID {original_id} → {status_orig} ({len(body_orig)} bytes), "
                            f"Test ID {num+1} → {status_test} ({len(body_test)} bytes), "
                            f"Content differs — potential access control bypass"
                        ),
                        poc=f"curl -v '{test_url}'",
                    )
        return None


class OAuthScanner:
    """Tests OAuth endpoints for real misconfigurations."""

    def __init__(self):
        self.name = "oauth"
        self.http = _HTTPClient()

    async def scan(self, urls: List[str], auth_headers: Optional[Dict] = None) -> List[ShuvonFinding]:
        findings = []
        oauth_urls = [u for u in urls if any(
            p in u.lower() for p in
            ['redirect_uri', 'response_type', '/oauth/', '/auth/callback', '/sso/']
        )]

        for url in oauth_urls[:20]:
            results = await self._test_oauth(url)
            findings.extend(results)

        logger.info(f"OAuth scanner: {len(findings)} findings")
        return findings

    async def _test_oauth(self, url: str) -> List[ShuvonFinding]:
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test 1: redirect_uri to external domain
        if "redirect_uri" in params:
            evil_url = url.replace(
                params["redirect_uri"][0],
                "https://evil.com/steal"
            )
            status, body, headers = await self.http.get(evil_url)
            # If it redirects to our evil URL, it's vulnerable
            location = headers.get("Location", "")
            if "evil.com" in location:
                results.append(ShuvonFinding(
                    scanner="oauth",
                    vulnerability_type="OAuth Open Redirect — redirect_uri accepts external domain",
                    target=url,
                    severity="high",
                    confidence=0.9,
                    evidence=f"Server redirected to: {location}",
                    poc=f"curl -v '{evil_url}'",
                ))
            elif status in (200, 302) and "evil.com" in body:
                results.append(ShuvonFinding(
                    scanner="oauth",
                    vulnerability_type="OAuth Open Redirect — redirect_uri reflected",
                    target=url,
                    severity="high",
                    confidence=0.7,
                    evidence=f"evil.com reflected in response body (status={status})",
                    poc=evil_url,
                ))

        # Test 2: missing state parameter
        if "response_type" in params and "state" not in params:
            results.append(ShuvonFinding(
                scanner="oauth",
                vulnerability_type="OAuth CSRF — Missing state parameter",
                target=url,
                severity="medium",
                confidence=0.8,
                evidence="OAuth flow initiated without state parameter",
            ))

        return results


class RaceScanner:
    """Sends concurrent requests to detect race conditions."""

    def __init__(self, concurrent_count: int = 10):
        self.name = "race"
        self.http = _HTTPClient(timeout=5)
        self.concurrent = concurrent_count

    async def scan(self, urls: List[str], auth_headers: Optional[Dict] = None) -> List[ShuvonFinding]:
        findings = []
        if auth_headers:
            self.http.headers.update(auth_headers)

        race_urls = [u for u in urls if any(
            p in u.lower() for p in
            ['/pay', '/checkout', '/redeem', '/coupon', '/vote',
             '/like', '/transfer', '/apply', '/claim']
        )]

        for url in race_urls[:10]:
            result = await self._test_race(url)
            if result:
                findings.append(result)

        logger.info(f"Race scanner: {len(findings)} potential races")
        return findings

    async def _test_race(self, url: str) -> Optional[ShuvonFinding]:
        """Send concurrent requests and compare responses."""
        if not AIOHTTP_OK:
            # Can't do real concurrent testing without aiohttp
            return ShuvonFinding(
                scanner="race",
                vulnerability_type=f"Potential Race Condition (untested)",
                target=url, severity="medium", confidence=0.3,
                evidence="Race-prone endpoint detected, manual testing needed",
            )

        # Fire concurrent GET requests
        results = []
        async def _fire():
            s, body, _ = await self.http.get(url)
            return s, len(body), hashlib.md5(body.encode()).hexdigest()[:8]

        tasks = [_fire() for _ in range(self.concurrent)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        valid = [r for r in responses if not isinstance(r, Exception) and r[0] > 0]
        if len(valid) < 3:
            return None

        # If all responses are identical, less likely to be raceable
        hashes = set(r[2] for r in valid)
        statuses = set(r[0] for r in valid)

        if len(hashes) > 1 or len(statuses) > 1:
            return ShuvonFinding(
                scanner="race",
                vulnerability_type="Race Condition — Inconsistent concurrent responses",
                target=url,
                severity="high",
                confidence=0.6,
                evidence=(
                    f"Sent {self.concurrent} concurrent requests: "
                    f"{len(hashes)} different response bodies, "
                    f"{len(statuses)} different status codes"
                ),
                poc=f"Use turbo intruder or send {self.concurrent} concurrent requests to {url}",
            )
        return None


class GraphQLScanner:
    """Actually sends introspection queries to GraphQL endpoints."""

    def __init__(self):
        self.name = "graphql"
        self.http = _HTTPClient()
        self._paths = ["/graphql", "/graphiql", "/gql", "/api/graphql", "/v1/graphql"]

    async def scan(self, urls: List[str], auth_headers: Optional[Dict] = None) -> List[ShuvonFinding]:
        findings = []
        if auth_headers:
            self.http.headers.update(auth_headers)

        # Extract unique base URLs
        bases = set()
        for url in urls:
            parsed = urlparse(url)
            bases.add(f"{parsed.scheme}://{parsed.netloc}")
            if any(p in parsed.path.lower() for p in self._paths):
                bases.add(url.split("?")[0])

        for base in list(bases)[:10]:
            result = await self._test_graphql(base)
            findings.extend(result)

        logger.info(f"GraphQL scanner: {len(findings)} findings")
        return findings

    async def _test_graphql(self, base_url: str) -> List[ShuvonFinding]:
        results = []
        endpoints = [base_url] if any(p in base_url.lower() for p in self._paths) else [
            base_url.rstrip("/") + p for p in self._paths
        ]

        introspection_query = '{"query":"{__schema{types{name,fields{name}}}}"}'

        for endpoint in endpoints:
            # Test introspection
            self.http.headers["Content-Type"] = "application/json"
            status, body, _ = await self.http.post(
                endpoint, data=introspection_query
            )

            if status == 200 and "__schema" in body:
                # Count exposed types
                try:
                    data = json.loads(body)
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]
                    results.append(ShuvonFinding(
                        scanner="graphql",
                        vulnerability_type="GraphQL Introspection Enabled",
                        target=endpoint,
                        severity="medium",
                        confidence=0.95,
                        evidence=f"Introspection returned {len(type_names)} types: {', '.join(type_names[:10])}...",
                        poc=f"curl -X POST {endpoint} -H 'Content-Type: application/json' -d '{introspection_query}'",
                    ))
                except json.JSONDecodeError:
                    results.append(ShuvonFinding(
                        scanner="graphql",
                        vulnerability_type="GraphQL Introspection Enabled",
                        target=endpoint,
                        severity="medium",
                        confidence=0.8,
                        evidence=f"__schema found in response (status={status})",
                    ))
                break  # Found it, no need to try other paths
            elif status == 200:
                results.append(ShuvonFinding(
                    scanner="graphql",
                    vulnerability_type="GraphQL Endpoint Detected",
                    target=endpoint,
                    severity="info",
                    confidence=0.7,
                    evidence=f"Endpoint responds with {status}, introspection may be disabled",
                ))
                break

        return results


class AIProbeScanner:
    """Probes sensitive endpoints with actual HTTP HEAD/GET requests."""

    def __init__(self):
        self.name = "ai_probe"
        self.http = _HTTPClient(timeout=5)
        self._probes = {
            "git_exposure": ("/.git/config", "high", "[core]"),
            "env_exposure": ("/.env", "high", "DB_"),
            "ds_store": ("/.DS_Store", "low", None),
            "debug": ("/debug", "medium", None),
            "admin": ("/admin", "medium", None),
            "swagger": ("/swagger/index.html", "medium", "swagger"),
            "api_docs": ("/api-docs", "medium", None),
            "graphiql": ("/graphiql", "medium", "graphiql"),
            "phpinfo": ("/phpinfo.php", "medium", "phpinfo"),
            "wp_config": ("/wp-config.php.bak", "critical", "DB_PASSWORD"),
            "server_status": ("/server-status", "medium", "Apache"),
            "elmah": ("/elmah.axd", "medium", None),
        }

    async def scan(self, urls: List[str], auth_headers: Optional[Dict] = None) -> List[ShuvonFinding]:
        findings = []

        # Extract unique base URLs
        bases = set()
        for url in urls:
            parsed = urlparse(url)
            bases.add(f"{parsed.scheme}://{parsed.netloc}")

        sem = asyncio.Semaphore(5)
        for base in list(bases)[:10]:
            for probe_name, (path, severity, signature) in self._probes.items():
                async with sem:
                    full_url = base.rstrip("/") + path
                    status, body, headers = await self.http.get(full_url)

                    confirmed = False
                    if status == 200:
                        if signature:
                            confirmed = signature.lower() in body.lower()
                        else:
                            # 200 without redirect and non-trivial body
                            confirmed = len(body) > 100
                    elif status == 403 and probe_name in ("git_exposure", "admin"):
                        # 403 on .git means it exists but is blocked
                        findings.append(ShuvonFinding(
                            scanner="ai_probe",
                            vulnerability_type=f"Sensitive path exists (blocked): {path}",
                            target=full_url, severity="low", confidence=0.5,
                            evidence=f"Server returned 403 for {path} — path exists",
                        ))

                    if confirmed:
                        findings.append(ShuvonFinding(
                            scanner="ai_probe",
                            vulnerability_type=f"Sensitive File/Endpoint Exposed: {path}",
                            target=full_url,
                            severity=severity,
                            confidence=0.9,
                            evidence=f"HTTP {status}, signature '{signature}' found in response",
                            poc=f"curl -v '{full_url}'",
                        ))

        logger.info(f"AI Probe scanner: {len(findings)} confirmed exposures")
        return findings


class ShuvonScannerSuite:
    """Orchestrates all Shuvon scanners."""

    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self.idor = IDORScanner()
        self.oauth = OAuthScanner()
        self.race = RaceScanner()
        self.graphql = GraphQLScanner()
        self.ai_probe = AIProbeScanner()
        self._scanners = [self.idor, self.oauth, self.race, self.graphql, self.ai_probe]

    async def run_all(
        self, urls: List[str], auth_headers: Optional[Dict] = None,
        skip: Optional[List[str]] = None,
    ) -> Dict[str, List[ShuvonFinding]]:
        skip = skip or []
        results: Dict[str, List[ShuvonFinding]] = {}

        sem = asyncio.Semaphore(self.max_concurrent)
        async def _run(scanner):
            async with sem:
                return scanner.name, await scanner.scan(urls, auth_headers)

        tasks = [_run(s) for s in self._scanners if s.name not in skip]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        total = 0
        for result in completed:
            if isinstance(result, Exception):
                logger.error(f"Shuvon scanner error: {result}")
                continue
            name, findings = result
            results[name] = findings
            total += len(findings)

        logger.info(f"Shuvon suite: {total} findings from {len(results)} scanners")
        return results

    @staticmethod
    def findings_to_dicts(results: Dict[str, List[ShuvonFinding]]) -> List[Dict[str, Any]]:
        dicts = []
        for scanner_name, findings in results.items():
            for f in findings:
                dicts.append({
                    "id": f"shuvon-{f.scanner}-{hash(f.target+f.vulnerability_type)&0xFFFF:04x}",
                    "tool": f"shuvon/{f.scanner}",
                    "target": f.target,
                    "vulnerability_type": f.vulnerability_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "raw_output": json.dumps(f.details)[:2000] if f.details else "",
                    "validated": False, "is_false_positive": False,
                    "metadata": {"poc": f.poc, "scanner": f.scanner, "details": f.details},
                })
        return dicts
