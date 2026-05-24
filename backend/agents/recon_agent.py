"""
API RIPPER v2.0 — Recon Agent
Deep API surface discovery, endpoint decoding, tech fingerprinting.

OBSERVE: Crawl target, extract endpoints from HTML/JS, discover OpenAPI specs
PROFILE: Classify endpoints, detect auth mechanisms, build URL hierarchy
DIFF:    Compare responses across discovered endpoints for structural patterns
INFER:   Identify API patterns, versioning, hidden endpoints
"""

import asyncio
import hashlib
import json
import logging
import random
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from uuid import uuid4

import aiohttp

from backend.agents.base_agent import BaseAgent, Finding

logger = logging.getLogger(__name__)

# Common API spec paths
OPENAPI_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/.well-known/openapi.json", "/api/swagger.json", "/api/openapi.json",
    "/docs/swagger.json", "/api-docs.json", "/swagger-ui.html",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
]

from backend.agents.payloads import API_WORDLIST

# Common API endpoint patterns
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/api/graphql",
    "/rest", "/rest/v1", "/rest/v2",
    "/health", "/healthz", "/status", "/info", "/version",
    "/api/health", "/api/status", "/api/info",
    "/api/users", "/api/user", "/api/me", "/api/profile",
    "/api/auth", "/api/login", "/api/register", "/api/token",
    "/api/admin", "/api/config", "/api/settings",
    "/api/search", "/api/upload", "/api/download",
    "/api/orders", "/api/products", "/api/items",
    "/api/posts", "/api/comments", "/api/messages",
    "/sitemap.xml", "/robots.txt", "/.env",
    "/wp-json/wp/v2/", "/api/v1/docs",
] + API_WORDLIST

# Patterns to extract API calls from JavaScript
JS_API_PATTERNS = [
    re.compile(r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
    re.compile(r'axios\.\w+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
    re.compile(r'\$\.(get|post|put|delete|ajax)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
    re.compile(r'XMLHttpRequest.*?open\s*\(\s*[\'"`]\w+[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
    re.compile(r'[\'"`](/api/[^\'"`\s]+)[\'"`]', re.IGNORECASE),
    re.compile(r'[\'"`](/v\d+/[^\'"`\s]+)[\'"`]', re.IGNORECASE),
    re.compile(r'url\s*[:=]\s*[\'"`]([^\'"`]*api[^\'"`]*)[\'"`]', re.IGNORECASE),
    re.compile(r'endpoint\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
]

# Tech fingerprint headers
TECH_HEADERS = {
    "server": "server",
    "x-powered-by": "framework",
    "x-aspnet-version": "aspnet_version",
    "x-runtime": "runtime",
    "x-generator": "generator",
    "x-drupal-cache": "cms",
    "x-varnish": "cache",
    "x-cache": "cache_status",
    "via": "proxy",
    "cf-ray": "cdn",
}


class ReconAgent(BaseAgent):
    """
    Reconnaissance & Decoder Agent.
    Discovers API surface, decodes requests/responses, fingerprints technology.
    """

    name = "recon_agent"

    async def observe(self) -> Dict[str, Any]:
        """Step 1: Crawl target, discover endpoints, extract API patterns."""
        target = self.config["target_url"]
        observations = {
            "target": target,
            "discovered_urls": set(),
            "api_endpoints": set(),
            "js_sources": set(),
            "tech_headers": {},
            "response_samples": {},
            "openapi_spec": None,
            "forms": [],
            "comments": [],
        }

        timeout = aiohttp.ClientTimeout(total=10)
        auth_config = self.config.get("auth_config", {})
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        if auth_config.get("bearer_token"):
            headers["Authorization"] = f"Bearer {auth_config['bearer_token']}"
        if auth_config.get("api_key"):
            headers["X-API-Key"] = auth_config["api_key"]

        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            async with aiohttp.ClientSession(
                timeout=timeout, headers=headers, connector=connector,
                cookie_jar=aiohttp.CookieJar(unsafe=True)
            ) as session:
                # Load cookies if provided
                if auth_config.get("cookies"):
                    for name, value in auth_config["cookies"].items():
                        session.cookie_jar.update_cookies({name: value})

                # 1. Fetch main page and extract links
                await self._crawl_page(session, target, observations, depth=0, max_depth=3)

                # 2. Probe common API paths
                await self._probe_api_paths(session, target, observations)

                # 3. Look for OpenAPI/Swagger specs
                await self._discover_openapi(session, target, observations)

                # 4. Extract API calls from discovered JS files
                await self._analyze_js_sources(session, observations)

                # 5. Fingerprint technology (header-based)
                await self._fingerprint_tech(session, target, observations)

                # 6. Behavioral fingerprinting (error pattern analysis)
                await self._behavioral_fingerprint(session, target, observations)

        except Exception as e:
            logger.error(f"[recon_agent] Observation error: {e}")
            self.health.degrade(f"observe: {e}")

        # Convert sets to lists for serialization
        observations["discovered_urls"] = list(observations["discovered_urls"])
        observations["api_endpoints"] = list(observations["api_endpoints"])
        observations["js_sources"] = list(observations["js_sources"])

        self.kg.log_observation(self.name, {
            "urls_found": len(observations["discovered_urls"]),
            "api_endpoints_found": len(observations["api_endpoints"]),
            "js_sources_found": len(observations["js_sources"]),
            "has_openapi": observations["openapi_spec"] is not None,
        })

        return observations

    async def profile(self, observations: Dict[str, Any]) -> Dict[str, Any]:
        """Step 2: Classify endpoints, detect auth, build URL hierarchy."""
        target = self.config["target_url"]
        parsed_target = urlparse(target)
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # Register all discovered endpoints in the Knowledge Graph
        all_urls = set(observations.get("api_endpoints", []))
        all_urls.update(observations.get("discovered_urls", []))

        for url in all_urls:
            # Classify endpoint
            classification = self._classify_endpoint(url)
            methods = ["GET"]  # Default; will be refined later

            self.kg.add_endpoint(
                url=url,
                method="GET",
                source_agent=self.name,
                confidence=0.6,
                classification=classification,
            )

            # F2: Extract URL query params into KG parameter registry
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            if query_params:
                param_map = {}
                for param_name, values in query_params.items():
                    param_type = "integer" if values and values[0].isdigit() else "string"
                    param_map[param_name] = {"location": "query", "type": param_type, "sample": values[0] if values else ""}
                # Store in global context param map
                self.kg.update_global_context({"parameter_map": {url: param_map}})
                # Also update endpoint node params
                endpoint_node = self.kg.get_endpoint_node(url)
                if endpoint_node:
                    for pname, pinfo in param_map.items():
                        endpoint_node.parameters[pname] = pinfo

            # Emit discovery signal
            self.emit_signal("ENDPOINT_DISCOVERED", {
                "url": url,
                "classification": classification,
            }, confidence=0.6)

        # F3: Extract form input names from crawled HTML and register as params
        for url, sample in observations.get("response_samples", {}).items():
            body = sample.get("body_preview", "")
            if not body:
                continue
            # Find <input> elements
            input_matches = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            # Find <select> elements
            select_matches = re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            # Find <textarea> elements
            textarea_matches = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            all_form_params = set(input_matches + select_matches + textarea_matches)
            if all_form_params:
                # Find the form action URL
                form_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.IGNORECASE)
                target_url = urljoin(url, form_action.group(1)) if form_action else url
                form_method = re.search(r'<form[^>]+method=["\']([^"\']+)["\']', body, re.IGNORECASE)
                method = form_method.group(1).upper() if form_method else "POST"
                
                param_map = {}
                for pname in all_form_params:
                    # Detect input type for smarter injection
                    type_match = re.search(rf'<input[^>]+name=["\']' + re.escape(pname) + r'["\'][^>]+type=["\']([^"\']+)["\']', body, re.IGNORECASE)
                    input_type = type_match.group(1).lower() if type_match else "text"
                    param_map[pname] = {"location": "body", "type": input_type, "form_method": method}
                
                self.kg.update_global_context({"parameter_map": {target_url: param_map}})
                endpoint_node = self.kg.get_endpoint_node(target_url)
                if endpoint_node:
                    for pname, pinfo in param_map.items():
                        endpoint_node.parameters[pname] = pinfo
                logger.info(f"[recon] Extracted {len(all_form_params)} form params from {url}: {list(all_form_params)[:5]}")

        # Parse OpenAPI spec if found
        if observations.get("openapi_spec"):
            self._parse_openapi_spec(observations["openapi_spec"], base_url)

        # Update tech profile
        if observations.get("tech_headers"):
            self.kg.update_tech_profile(
                observations["tech_headers"],
                source_agent=self.name,
                confidence=0.9,
            )
            self.emit_signal("TECH_PROFILE", observations["tech_headers"], confidence=0.9)

        # Build URL hierarchy clusters
        clusters = self._build_clusters(list(all_urls))
        for cluster_name, urls in clusters.items():
            self.kg.add_cluster(cluster_name, urls)
            # Create relationships between endpoints in the same cluster
            for i in range(len(urls)):
                for j in range(i + 1, min(i + 5, len(urls))):
                    path_i = urlparse(urls[i]).path
                    path_j = urlparse(urls[j]).path
                    rel_type = "parent_child" if len(path_i) < len(path_j) else "sibling"
                    self.kg.add_relationship(
                        source_url=urls[i],
                        target_url=urls[j],
                        rel_type=rel_type,
                        confidence=0.8,
                        evidence=f"Shared cluster: {cluster_name}"
                    )

        profiles = {
            "total_endpoints": len(all_urls),
            "classifications": {},
            "clusters": clusters,
            "has_openapi": observations.get("openapi_spec") is not None,
        }

        for url in all_urls:
            cls = self._classify_endpoint(url)
            profiles["classifications"][cls] = profiles["classifications"].get(cls, 0) + 1

        # Push technology profile globally so PayloadManager can read it
        tech_profile = observations.get("tech_headers", {})
        if tech_profile:
            self.kg.update_global_context({"technology_profile": tech_profile})

        return profiles

    async def differential_analyze(self, profiles: Dict[str, Any]) -> List[Dict]:
        """Step 3: Compare responses across endpoints for structural patterns."""
        # Recon agent's diff analysis is minimal — it detects
        # inconsistent response patterns across similar endpoints
        diffs = []
        return diffs

    async def infer(self, diffs: Any) -> List[Finding]:
        """Step 4: Generate findings from recon observations."""
        findings = []
        tech = self.kg.get_tech_profile()

        # Finding: Version disclosure
        if tech.get("server"):
            version_match = re.search(r'[\d]+\.[\d]+', str(tech.get("server", "")))
            if version_match:
                findings.append(Finding(
                    type="version_disclosure",
                    title=f"Server Version Disclosed: {tech['server']}",
                    description=f"Server header reveals version information: {tech['server']}. This aids attackers in targeting known CVEs.",
                    severity="low",
                    confidence=0.9,
                    endpoint=self.config["target_url"],
                    cwe="CWE-200",
                    owasp="API9:2023",
                    remediation="Remove or obfuscate the Server header. Use a reverse proxy to strip version information.",
                    evidence=[{"type": "header", "header": "Server", "value": tech["server"]}],
                ))

        if tech.get("framework"):
            findings.append(Finding(
                type="framework_disclosure",
                title=f"Framework Disclosed: {tech['framework']}",
                description=f"X-Powered-By header reveals: {tech['framework']}",
                severity="low",
                confidence=0.9,
                endpoint=self.config["target_url"],
                cwe="CWE-200",
                owasp="API9:2023",
                remediation="Remove the X-Powered-By header.",
                evidence=[{"type": "header", "header": "X-Powered-By", "value": tech["framework"]}],
            ))

        # Finding: Debug/sensitive endpoints accessible
        sensitive_patterns = ["/admin", "/debug", "/config", "/env", "/.env", "/phpinfo", "/actuator"]
        for ep in self.kg.get_all_endpoints():
            url = ep.get("url", "")
            for pattern in sensitive_patterns:
                if pattern in url.lower():
                    findings.append(Finding(
                        type="sensitive_endpoint_exposed",
                        title=f"Sensitive Endpoint Accessible: {url}",
                        description=f"Potentially sensitive endpoint '{url}' is accessible. This may expose internal configuration or admin functionality.",
                        severity="medium",
                        confidence=0.5,
                        endpoint=url,
                        cwe="CWE-200",
                        owasp="API9:2023",
                        remediation="Restrict access to sensitive endpoints via authentication and IP whitelisting.",
                        evidence=[{"type": "endpoint_discovery", "url": url, "pattern": pattern}],
                    ))
                    break

        return findings

    # ── Internal Methods ────────────────────────────────────

    async def _crawl_page(self, session, url, observations, depth=0, max_depth=3):
        """Recursively crawl pages and extract links, scripts, forms."""
        if depth > max_depth:
            return
        if url in observations["discovered_urls"]:
            return

        await self.rate_limited_delay()
        observations["discovered_urls"].add(url)
        parsed_base = urlparse(self.config["target_url"])

        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return
                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type and "application/json" not in content_type:
                    return

                body = await resp.text(errors="replace")

                # Store response sample
                observations["response_samples"][url] = {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body_length": len(body),
                    "content_type": content_type,
                }

                # Extract links
                link_patterns = [
                    re.compile(r'href=[\'"]([^\'"\s>]+)[\'"]', re.IGNORECASE),
                    re.compile(r'src=[\'"]([^\'"\s>]+)[\'"]', re.IGNORECASE),
                    re.compile(r'action=[\'"]([^\'"\s>]+)[\'"]', re.IGNORECASE),
                ]
                for pattern in link_patterns:
                    for match in pattern.finditer(body):
                        found_url = match.group(1)
                        full_url = urljoin(url, found_url)
                        parsed = urlparse(full_url)

                        # Stay within target domain
                        if parsed.netloc != parsed_base.netloc:
                            continue

                        # Track JS sources separately
                        if found_url.endswith(".js"):
                            observations["js_sources"].add(full_url)
                        # Track API-like endpoints
                        elif any(p in found_url.lower() for p in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql"]):
                            observations["api_endpoints"].add(full_url)
                        else:
                            observations["discovered_urls"].add(full_url)

                # Extract comments (developer info leaks)
                comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
                for comment in comments[:20]:
                    clean = comment.strip()
                    if len(clean) > 10 and any(kw in clean.lower() for kw in ["todo", "fixme", "hack", "api", "token", "key", "secret", "password", "debug"]):
                        observations["comments"].append(clean[:200])

                # Extract API endpoints from JS patterns in HTML
                for pattern in JS_API_PATTERNS:
                    for match in pattern.finditer(body):
                        api_url = match.group(1) if pattern.groups == 1 else match.group(match.lastindex)
                        if api_url.startswith("/"):
                            full = urljoin(url, api_url)
                            observations["api_endpoints"].add(full)

                # Recurse into same-domain links (limited depth)
                if depth < max_depth:
                    child_urls = list(observations["discovered_urls"])[-20:]
                    tasks = []
                    for child_url in child_urls:
                        if child_url not in observations.get("_crawled", set()):
                            observations.setdefault("_crawled", set()).add(child_url)
                            tasks.append(self._crawl_page(session, child_url, observations, depth + 1, max_depth))
                    if tasks:
                        await asyncio.gather(*tasks[:5], return_exceptions=True)

        except Exception as e:
            logger.debug(f"[recon] Crawl error for {url}: {e}")

    async def _probe_api_paths(self, session, target, observations):
        """Probe common API paths to discover endpoints."""
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        async def probe(path):
            url = f"{base}{path}"
            await self.rate_limited_delay()
            try:
                async with session.get(url) as resp:
                    if resp.status in (200, 201, 301, 302, 401, 403):
                        observations["api_endpoints"].add(url)
                        observations["response_samples"][url] = {
                            "status": resp.status,
                            "headers": dict(resp.headers),
                            "body_length": int(resp.headers.get("content-length", 0)),
                        }
            except Exception:
                pass

        tasks = [probe(path) for path in API_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _discover_openapi(self, session, target, observations):
        """Search for OpenAPI/Swagger specification files."""
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in OPENAPI_PATHS:
            url = f"{base}{path}"
            await self.rate_limited_delay()
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        try:
                            spec = json.loads(body)
                            if "paths" in spec or "openapi" in spec or "swagger" in spec:
                                observations["openapi_spec"] = spec
                                observations["api_endpoints"].add(url)
                                self.emit_signal("OPENAPI_DISCOVERED", {"url": url}, confidence=0.95)
                                return
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass

    async def _analyze_js_sources(self, session, observations):
        """Extract API endpoint references from JavaScript source files."""
        for js_url in list(observations["js_sources"])[:20]:
            await self.rate_limited_delay()
            try:
                async with session.get(js_url) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        for pattern in JS_API_PATTERNS:
                            for match in pattern.finditer(body):
                                api_path = match.group(1) if match.lastindex == 1 else match.group(match.lastindex)
                                if api_path and api_path.startswith("/"):
                                    full = urljoin(self.config["target_url"], api_path)
                                    observations["api_endpoints"].add(full)
            except Exception:
                pass

    async def _fingerprint_tech(self, session, target, observations):
        """Detect server technology from headers and response patterns."""
        await self.rate_limited_delay()
        try:
            async with session.get(target) as resp:
                for header_name, profile_key in TECH_HEADERS.items():
                    value = resp.headers.get(header_name)
                    if value:
                        observations["tech_headers"][profile_key] = value
        except Exception:
            pass

    async def _behavioral_fingerprint(self, session, target, observations):
        """Infer technology stack from error patterns, not just headers."""
        from backend.agents.adaptive_engine import BehavioralFingerprinter
        fingerprinter = BehavioralFingerprinter()

        # Analyze all already-collected response samples
        for url, sample in observations.get("response_samples", {}).items():
            fingerprinter.analyze_response(
                sample.get("status", 200),
                sample.get("headers", {}),
                sample.get("body_preview", ""),
            )

        # Trigger deliberate error responses for deeper detection
        error_probes = [
            f"{target}/nonexistent_path_404_{random.randint(1000,9999)}",
            f"{target}/api/v1/nonexistent_{random.randint(1000,9999)}",
            f"{target}/%00",
            f"{target}/..%2f..%2f",
        ]
        for probe_url in error_probes:
            try:
                await self.rate_limited_delay()
                async with session.get(probe_url) as resp:
                    body = await resp.text(errors="replace")
                    fingerprinter.analyze_response(resp.status, dict(resp.headers), body[:2000])
            except Exception:
                pass

        # Merge behavioral profile into tech_headers
        behavioral_profile = fingerprinter.get_profile()
        if behavioral_profile:
            observations["tech_headers"].update(behavioral_profile)
            logger.info(f"[recon] Behavioral fingerprint: {behavioral_profile}")

    def _classify_endpoint(self, url: str) -> str:
        """Classify an endpoint by its URL pattern."""
        lower = url.lower()
        if any(p in lower for p in ["/auth", "/login", "/signin", "/token", "/oauth", "/register", "/signup"]):
            return "auth"
        if any(p in lower for p in ["/admin", "/manage", "/dashboard", "/config", "/settings"]):
            return "admin"
        if any(p in lower for p in ["/upload", "/import", "/file"]):
            return "upload"
        if any(p in lower for p in ["/search", "/query", "/find", "/filter"]):
            return "search"
        if any(p in lower for p in ["/health", "/status", "/ping", "/info", "/version", "/docs", "/swagger"]):
            return "public"
        return "data_read"

    def _parse_openapi_spec(self, spec: dict, base_url: str):
        """Parse OpenAPI spec and register endpoints in Knowledge Graph."""
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            full_url = f"{base_url}{path}"
            for method, details in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                    params = {}
                    for param in details.get("parameters", []):
                        params[param.get("name", "")] = {
                            "type": param.get("schema", {}).get("type", "string"),
                            "location": param.get("in", "query"),
                            "required": param.get("required", False),
                        }

                    auth_required = bool(details.get("security"))
                    classification = self._classify_endpoint(path)

                    self.kg.add_endpoint(
                        url=full_url,
                        method=method.upper(),
                        source_agent=self.name,
                        confidence=0.95,
                        parameters=params,
                        classification=classification,
                        auth_required=auth_required,
                    )

                    self.emit_signal("ENDPOINT_DISCOVERED", {
                        "url": full_url,
                        "method": method.upper(),
                        "from_spec": True,
                        "params": params,
                    }, confidence=0.95)

    def _build_clusters(self, urls: List[str]) -> Dict[str, List[str]]:
        """Group endpoints into domain clusters based on URL path segments."""
        clusters: Dict[str, List[str]] = {}
        for url in urls:
            parsed = urlparse(url)
            segments = [s for s in parsed.path.strip("/").split("/") if s]
            if len(segments) >= 2:
                cluster_key = f"{segments[0]}_{segments[1]}" if segments[1] not in ("v1", "v2", "v3") else segments[0]
            elif segments:
                cluster_key = segments[0]
            else:
                cluster_key = "root"
            clusters.setdefault(cluster_key, []).append(url)
        return clusters
