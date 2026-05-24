"""
API RIPPER v4.0 — Cloud Security Engine
Detects cloud-native misconfigurations, metadata exposure, serverless flaws,
container escape vectors, and IAM privilege escalation paths.

Capabilities:
  1. Cloud Metadata Harvesting — AWS/GCP/Azure IMDS probing via SSRF
  2. Serverless Misconfig Detection — Lambda/Functions env leak, cold-start abuse
  3. Container Security — Docker socket exposure, K8s API access, escape vectors
  4. IAM Privilege Escalation — Overprivileged roles, AssumeRole chains
  5. Storage Misconfiguration — S3/GCS/Blob public access, listing
  6. Cloud-Native API Abuse — API Gateway bypass, service mesh injection
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)


# ── Cloud Provider Detection Signatures ─────────────────────

CLOUD_SIGNATURES = {
    "aws": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id", "x-amz-request-id"],
        "cookies": ["awsalb", "awsalbcors", "AWSALB"],
        "body_patterns": ["amazonaws.com", "aws_access_key", "AWSAccessKeyId",
                          "arn:aws:", "lambda", "api gateway"],
        "error_patterns": ["AccessDenied", "InvalidClientTokenId",
                           "ExpiredToken", "SignatureDoesNotMatch"],
    },
    "gcp": {
        "headers": ["x-cloud-trace-context", "x-goog-", "server: Google Frontend"],
        "cookies": [],
        "body_patterns": ["googleapis.com", "google cloud", "gcloud",
                          "projects/", "cloud.google.com"],
        "error_patterns": ["PERMISSION_DENIED", "UNAUTHENTICATED", "NOT_FOUND"],
    },
    "azure": {
        "headers": ["x-ms-request-id", "x-ms-correlation-request-id", "x-azure-ref"],
        "cookies": ["ARRAffinity", "ARRAffinitySameSite"],
        "body_patterns": ["azure", "microsoft", ".azurewebsites.net",
                          "blob.core.windows.net", "login.microsoftonline"],
        "error_patterns": ["AuthorizationFailed", "InvalidAuthenticationToken"],
    },
}

# ── Cloud Metadata Endpoints ────────────────────────────────

METADATA_ENDPOINTS = {
    "aws_imds_v1": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "method": "GET",
        "headers": {},
        "paths": [
            "ami-id", "instance-id", "instance-type", "local-hostname",
            "local-ipv4", "public-hostname", "public-ipv4",
            "iam/security-credentials/", "iam/info",
            "network/interfaces/macs/",
            "identity-credentials/ec2/security-credentials/ec2-instance",
        ],
    },
    "aws_imds_v2": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "method": "GET",
        "token_url": "http://169.254.169.254/latest/api/token",
        "token_header": "X-aws-ec2-metadata-token-ttl-seconds",
        "token_value": "21600",
        "headers": {},
        "paths": ["iam/security-credentials/", "identity-credentials/ec2/info"],
    },
    "gcp_metadata": {
        "url": "http://169.254.169.254/computeMetadata/v1/",
        "method": "GET",
        "headers": {"Metadata-Flavor": "Google"},
        "paths": [
            "project/project-id", "project/numeric-project-id",
            "instance/service-accounts/default/token",
            "instance/service-accounts/default/email",
            "instance/attributes/", "instance/zone", "instance/name",
            "instance/network-interfaces/0/access-configs/0/external-ip",
        ],
    },
    "azure_imds": {
        "url": "http://169.254.169.254/metadata/instance",
        "method": "GET",
        "headers": {"Metadata": "true"},
        "params": "api-version=2021-12-13",
        "paths": [
            "", "/compute", "/network",
        ],
    },
    "azure_identity": {
        "url": "http://169.254.169.254/metadata/identity/oauth2/token",
        "method": "GET",
        "headers": {"Metadata": "true"},
        "params": "api-version=2018-02-01&resource=https://management.azure.com/",
        "paths": [],
    },
    "alibaba": {
        "url": "http://100.100.100.200/latest/meta-data/",
        "method": "GET",
        "headers": {},
        "paths": ["instance-id", "region-id", "ram/security-credentials/"],
    },
    "digitalocean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "method": "GET",
        "headers": {},
        "paths": ["id", "hostname", "region", "interfaces/", "dns/"],
    },
}

# ── Container / K8s Endpoints ───────────────────────────────

CONTAINER_ENDPOINTS = {
    "docker_socket": [
        "http://127.0.0.1:2375/version",
        "http://127.0.0.1:2375/containers/json",
        "http://127.0.0.1:2376/version",
    ],
    "k8s_api": [
        "https://kubernetes.default.svc/api/v1/namespaces",
        "https://kubernetes.default.svc/api/v1/pods",
        "https://kubernetes.default.svc/api/v1/secrets",
        "https://10.96.0.1/api/v1/namespaces",
    ],
    "k8s_service_account": [
        "http://127.0.0.1:10255/pods",  # Kubelet read-only
        "http://127.0.0.1:10248/healthz",  # Kubelet healthz
    ],
    "consul": [
        "http://127.0.0.1:8500/v1/agent/self",
        "http://127.0.0.1:8500/v1/kv/?recurse",
    ],
    "etcd": [
        "http://127.0.0.1:2379/v2/keys/",
        "http://127.0.0.1:2379/version",
    ],
}

# ── Storage Misconfiguration Patterns ───────────────────────

STORAGE_PATTERNS = {
    "s3": {
        "url_patterns": [
            r"https?://[\w.-]+\.s3[\w.-]*\.amazonaws\.com",
            r"https?://s3[\w.-]*\.amazonaws\.com/[\w.-]+",
        ],
        "test_paths": ["", "?list-type=2&max-keys=10"],
        "indicators": ["<ListBucketResult", "<Contents>", "<Key>", "AccessDenied"],
    },
    "gcs": {
        "url_patterns": [
            r"https?://storage\.googleapis\.com/[\w.-]+",
            r"https?://[\w.-]+\.storage\.googleapis\.com",
        ],
        "test_paths": ["", "?prefix=&max-keys=10"],
        "indicators": ["<ListBucketResult", "storage.googleapis.com", "AccessDenied"],
    },
    "azure_blob": {
        "url_patterns": [
            r"https?://[\w]+\.blob\.core\.windows\.net/[\w.-]+",
        ],
        "test_paths": ["?restype=container&comp=list&maxresults=10"],
        "indicators": ["<EnumerationResults", "<Blob>", "<Name>", "AuthorizationFailure"],
    },
}

# ── Serverless Detection Payloads ───────────────────────────

SERVERLESS_ENV_VARS = {
    "aws_lambda": [
        "AWS_LAMBDA_FUNCTION_NAME", "AWS_LAMBDA_FUNCTION_VERSION",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_REGION", "AWS_EXECUTION_ENV", "_HANDLER", "LAMBDA_TASK_ROOT",
    ],
    "azure_functions": [
        "AZURE_FUNCTIONS_ENVIRONMENT", "WEBSITE_SITE_NAME",
        "FUNCTIONS_WORKER_RUNTIME", "AzureWebJobsStorage",
        "WEBSITE_RESOURCE_GROUP", "WEBSITE_OWNER_NAME",
    ],
    "gcp_functions": [
        "FUNCTION_NAME", "FUNCTION_TARGET", "GCLOUD_PROJECT",
        "GCP_PROJECT", "GOOGLE_CLOUD_PROJECT", "K_SERVICE", "K_REVISION",
    ],
}


# ── Cloud Finding ───────────────────────────────────────────

@dataclass
class CloudFinding:
    """A cloud security finding."""
    id: str = field(default_factory=lambda: str(uuid4()))
    type: str = ""
    title: str = ""
    description: str = ""
    severity: str = "high"
    confidence: float = 0.0
    provider: str = ""
    service: str = ""
    endpoint: str = ""
    evidence: List[Dict] = field(default_factory=list)
    remediation: str = ""
    cwe: str = ""

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "type": self.type, "title": self.title,
            "description": self.description, "severity": self.severity,
            "confidence": self.confidence, "provider": self.provider,
            "service": self.service, "endpoint": self.endpoint,
            "evidence_count": len(self.evidence), "remediation": self.remediation,
            "cwe": self.cwe,
        }


# ── Cloud Security Engine ──────────────────────────────────

class CloudSecurityEngine:
    """
    Cloud-native security assessment engine.

    Phases:
      1. Provider Detection — Identify cloud provider from response signatures
      2. Metadata Probing — SSRF-based IMDS access attempts
      3. Container Assessment — Docker/K8s exposure detection
      4. Storage Audit — Public bucket/blob detection
      5. Serverless Analysis — Environment variable leakage
      6. IAM Analysis — Privilege escalation path detection
    """

    def __init__(self, knowledge_graph=None):
        self.kg = knowledge_graph
        self._provider: str = "unknown"
        self._provider_confidence: float = 0.0
        self._findings: List[CloudFinding] = []
        self._metadata_harvested: Dict[str, str] = {}
        self._stats = {
            "provider": "unknown", "metadata_found": 0, "container_exposed": 0,
            "storage_exposed": 0, "serverless_leaks": 0, "total_findings": 0,
        }

    # ── Phase 1: Provider Detection ─────────────────────────

    def detect_provider(self, headers: Dict[str, str], body: str = "",
                         cookies: Dict[str, str] = None) -> Tuple[str, float]:
        """Detect cloud provider from HTTP response data."""
        scores: Dict[str, float] = {}
        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
        lower_body = body.lower()[:5000]
        cookie_names = list((cookies or {}).keys())

        for provider, sigs in CLOUD_SIGNATURES.items():
            score = 0.0

            for h in sigs["headers"]:
                if h.lower() in lower_headers:
                    score += 0.3

            for c in sigs["cookies"]:
                if c in cookie_names or any(c.lower() in cn.lower() for cn in cookie_names):
                    score += 0.2

            for p in sigs["body_patterns"]:
                if p.lower() in lower_body:
                    score += 0.15

            for ep in sigs["error_patterns"]:
                if ep.lower() in lower_body:
                    score += 0.25

            scores[provider] = score

        if scores:
            best = max(scores, key=scores.get)
            if scores[best] >= 0.2:
                self._provider = best
                self._provider_confidence = min(1.0, scores[best])
                self._stats["provider"] = best
                logger.info(f"[CloudSecurity] Provider detected: {best} (conf={scores[best]:.2f})")
                return best, self._provider_confidence

        return "unknown", 0.0

    # ── Phase 2: SSRF Metadata Probing ──────────────────────

    async def probe_metadata(self, request_func, ssrf_param: str = "url",
                              base_endpoint: str = "") -> List[CloudFinding]:
        """Probe cloud metadata endpoints via SSRF vectors."""
        findings = []

        # Determine which metadata services to test
        targets = []
        if self._provider == "aws" or self._provider == "unknown":
            targets.extend([("aws", METADATA_ENDPOINTS["aws_imds_v1"])])
        if self._provider == "gcp" or self._provider == "unknown":
            targets.extend([("gcp", METADATA_ENDPOINTS["gcp_metadata"])])
        if self._provider == "azure" or self._provider == "unknown":
            targets.extend([("azure", METADATA_ENDPOINTS["azure_imds"])])
        if self._provider == "unknown":
            targets.extend([
                ("alibaba", METADATA_ENDPOINTS["alibaba"]),
                ("digitalocean", METADATA_ENDPOINTS["digitalocean"]),
            ])

        for provider, meta_config in targets:
            base_url = meta_config["url"]
            meta_headers = meta_config.get("headers", {})

            for path in meta_config.get("paths", [""])[:6]:
                full_url = f"{base_url}{path}"

                # Direct SSRF via parameter
                if base_endpoint:
                    sep = "&" if "?" in base_endpoint else "?"
                    ssrf_url = f"{base_endpoint}{sep}{ssrf_param}={full_url}"
                else:
                    ssrf_url = full_url

                resp = await request_func(ssrf_url, "GET", headers=meta_headers)
                if not resp:
                    continue

                status = resp.get("status", 0)
                body = resp.get("body", resp.get("body_preview", ""))

                if status == 200 and body and len(body) > 10:
                    # Validate it's actual metadata, not an error page
                    is_metadata = self._validate_metadata_response(body, provider, path)
                    if is_metadata:
                        self._metadata_harvested[f"{provider}:{path}"] = body[:500]
                        self._stats["metadata_found"] += 1

                        severity = "critical"
                        if "security-credentials" in path or "token" in path:
                            severity = "critical"
                        elif "iam" in path:
                            severity = "critical"

                        findings.append(CloudFinding(
                            type="cloud_metadata_exposure",
                            title=f"Cloud Metadata Exposed: {provider.upper()} ({path})",
                            description=f"SSRF to {provider.upper()} metadata service returned valid data. "
                                        f"Path: {path}. This may expose IAM credentials, instance identity, "
                                        f"or internal network configuration.",
                            severity=severity,
                            confidence=0.95,
                            provider=provider,
                            service="IMDS",
                            endpoint=ssrf_url,
                            evidence=[{
                                "path": path, "status": status,
                                "body_preview": body[:200],
                                "metadata_type": self._classify_metadata(path),
                            }],
                            remediation=self._get_metadata_remediation(provider),
                            cwe="CWE-918",
                        ))

        self._findings.extend(findings)
        return findings

    def _validate_metadata_response(self, body: str, provider: str, path: str) -> bool:
        """Validate that the response is actual cloud metadata."""
        lower = body.lower()

        if provider == "aws":
            indicators = ["ami-", "i-", "ip-", "arn:aws:", "security-credentials",
                          "instance-id", "us-east", "us-west", "eu-west", "ap-"]
            return any(ind in lower for ind in indicators) or len(body.strip().split('\n')) > 1

        elif provider == "gcp":
            indicators = ["project", "zone", "instance", "service-account", "token",
                          "access_token", "projects/"]
            return any(ind in lower for ind in indicators)

        elif provider == "azure":
            indicators = ["subscriptionid", "resourcegroup", "vmid", "location",
                          "access_token", "client_id"]
            return any(ind in lower for ind in indicators)

        return len(body.strip()) > 20

    @staticmethod
    def _classify_metadata(path: str) -> str:
        if "credential" in path or "token" in path:
            return "credentials"
        elif "iam" in path:
            return "iam_config"
        elif "network" in path or "interface" in path:
            return "network_config"
        elif "identity" in path:
            return "identity"
        return "instance_metadata"

    @staticmethod
    def _get_metadata_remediation(provider: str) -> str:
        remediations = {
            "aws": "Enable IMDSv2 (require token). Block SSRF to 169.254.169.254. "
                   "Use VPC endpoints. Apply least-privilege IAM roles.",
            "gcp": "Restrict metadata server access. Use Workload Identity. "
                   "Block SSRF to metadata.google.internal.",
            "azure": "Use managed identities with minimal permissions. "
                     "Block SSRF to 169.254.169.254. Enable NSG rules.",
        }
        return remediations.get(provider, "Block access to cloud metadata endpoints. Validate SSRF inputs.")

    # ── Phase 3: Container Assessment ───────────────────────

    async def assess_containers(self, request_func,
                                 ssrf_endpoint: str = "",
                                 ssrf_param: str = "url") -> List[CloudFinding]:
        """Detect exposed Docker/K8s/service mesh endpoints."""
        findings = []

        for service, urls in CONTAINER_ENDPOINTS.items():
            for url in urls[:3]:
                if ssrf_endpoint:
                    sep = "&" if "?" in ssrf_endpoint else "?"
                    test_url = f"{ssrf_endpoint}{sep}{ssrf_param}={url}"
                else:
                    test_url = url

                resp = await request_func(test_url, "GET")
                if not resp:
                    continue

                status = resp.get("status", 0)
                body = resp.get("body", resp.get("body_preview", ""))

                if status == 200 and body:
                    is_valid = self._validate_container_response(body, service)
                    if is_valid:
                        self._stats["container_exposed"] += 1
                        findings.append(CloudFinding(
                            type="container_exposure",
                            title=f"Container Service Exposed: {service}",
                            description=f"Internal {service} endpoint accessible. "
                                        f"This may allow container escape, secret extraction, "
                                        f"or lateral movement.",
                            severity="critical",
                            confidence=0.9,
                            provider=self._provider,
                            service=service,
                            endpoint=test_url,
                            evidence=[{"url": url, "status": status, "body_preview": body[:200]}],
                            remediation=f"Restrict access to {service}. Use network policies. "
                                        f"Disable unauthenticated API access.",
                            cwe="CWE-284",
                        ))

        self._findings.extend(findings)
        return findings

    def _validate_container_response(self, body: str, service: str) -> bool:
        lower = body.lower()
        validators = {
            "docker_socket": ["apiversion", "version", "containers", "docker"],
            "k8s_api": ["apiversion", "kind", "items", "namespace", "kubernetes"],
            "k8s_service_account": ["pod", "container", "namespace"],
            "consul": ["config", "member", "consul"],
            "etcd": ["etcdserver", "etcdcluster", "node"],
        }
        indicators = validators.get(service, [])
        return any(ind in lower for ind in indicators)

    # ── Phase 4: Storage Audit ──────────────────────────────

    async def audit_storage(self, request_func, discovered_urls: List[str] = None) -> List[CloudFinding]:
        """Detect misconfigured cloud storage (S3, GCS, Azure Blob)."""
        findings = []
        urls_to_test = discovered_urls or []

        # Extract storage URLs from KG
        if self.kg:
            for ep in self.kg.get_all_endpoints():
                ep_url = ep.get("url", "")
                for provider, config in STORAGE_PATTERNS.items():
                    for pattern in config["url_patterns"]:
                        if re.search(pattern, ep_url, re.I):
                            urls_to_test.append(ep_url)

        for url in set(urls_to_test)[:10]:
            for provider, config in STORAGE_PATTERNS.items():
                if not any(re.search(p, url, re.I) for p in config["url_patterns"]):
                    continue

                for test_path in config["test_paths"]:
                    test_url = f"{url.rstrip('/')}/{test_path}" if test_path else url
                    resp = await request_func(test_url, "GET")
                    if not resp:
                        continue

                    body = resp.get("body", resp.get("body_preview", ""))
                    status = resp.get("status", 0)

                    if status == 200:
                        listing_indicators = ["<ListBucketResult", "<Contents>",
                                              "<EnumerationResults", "<Blob>"]
                        is_listing = any(ind in body for ind in listing_indicators)

                        if is_listing:
                            self._stats["storage_exposed"] += 1
                            findings.append(CloudFinding(
                                type="storage_misconfiguration",
                                title=f"Public Storage Listing: {provider.upper()}",
                                description=f"Cloud storage bucket/container allows public listing. "
                                            f"Sensitive data may be exposed.",
                                severity="critical",
                                confidence=0.95,
                                provider=provider,
                                service="storage",
                                endpoint=test_url,
                                evidence=[{"url": test_url, "status": status,
                                           "listing_detected": True,
                                           "body_preview": body[:300]}],
                                remediation=f"Disable public access on {provider.upper()} storage. "
                                            f"Enable bucket policies. Use signed URLs.",
                                cwe="CWE-284",
                            ))

        self._findings.extend(findings)
        return findings

    # ── Phase 5: Serverless Analysis ────────────────────────

    async def detect_serverless_leaks(self, request_func, endpoint: str,
                                       method: str = "GET") -> List[CloudFinding]:
        """Detect serverless environment variable leakage."""
        findings = []

        # Test for env var leakage via error triggering
        error_payloads = [
            ("__proto__", '{"__proto__":{"env":true}}'),
            ("type_error", "undefined"),
            ("null_deref", None),
            ("overflow", "A" * 100000),
        ]

        for name, payload in error_payloads:
            if payload is None:
                resp = await request_func(endpoint, method)
            else:
                resp = await request_func(
                    endpoint, "POST",
                    body=payload if isinstance(payload, str) else json.dumps(payload),
                    content_type="application/json"
                )
            if not resp:
                continue

            body = resp.get("body", resp.get("body_preview", ""))

            # Check for env var exposure in error responses
            for platform, env_vars in SERVERLESS_ENV_VARS.items():
                exposed = [v for v in env_vars if v in body]
                if exposed:
                    self._stats["serverless_leaks"] += 1
                    severity = "critical" if any(k in exposed for k in
                        ["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AzureWebJobsStorage"]) else "high"

                    findings.append(CloudFinding(
                        type="serverless_env_leak",
                        title=f"Serverless Environment Leak: {platform}",
                        description=f"Error response exposes {len(exposed)} serverless environment "
                                    f"variables. Credentials may be compromised.",
                        severity=severity,
                        confidence=0.9,
                        provider=platform.split("_")[0],
                        service="serverless",
                        endpoint=endpoint,
                        evidence=[{"exposed_vars": exposed, "trigger": name,
                                   "body_preview": body[:300]}],
                        remediation="Disable verbose error responses in production. "
                                    "Use secrets manager instead of environment variables. "
                                    "Enable custom error pages.",
                        cwe="CWE-209",
                    ))
                    break  # One finding per platform is enough

        self._findings.extend(findings)
        return findings

    # ── Full Cloud Scan ─────────────────────────────────────

    async def full_scan(self, request_func, target_url: str,
                         ssrf_endpoints: List[Dict] = None) -> List[CloudFinding]:
        """Run the complete cloud security assessment pipeline."""
        all_findings = []

        # Phase 1: Provider detection (from initial response)
        resp = await request_func(target_url, "GET")
        if resp:
            headers = resp.get("headers", {})
            body = resp.get("body", resp.get("body_preview", ""))
            self.detect_provider(headers, body)

        # Phase 2: Metadata probing via any SSRF-susceptible endpoints
        ssrf_eps = ssrf_endpoints or []
        for ep_info in ssrf_eps[:3]:
            ep = ep_info.get("endpoint", "")
            param = ep_info.get("param", "url")
            metadata_findings = await self.probe_metadata(request_func, param, ep)
            all_findings.extend(metadata_findings)

        # Phase 3: Container assessment
        for ep_info in ssrf_eps[:2]:
            ep = ep_info.get("endpoint", "")
            param = ep_info.get("param", "url")
            container_findings = await self.assess_containers(request_func, ep, param)
            all_findings.extend(container_findings)

        # Phase 4: Storage audit
        storage_findings = await self.audit_storage(request_func)
        all_findings.extend(storage_findings)

        # Phase 5: Serverless leak detection
        serverless_findings = await self.detect_serverless_leaks(request_func, target_url)
        all_findings.extend(serverless_findings)

        self._stats["total_findings"] = len(all_findings)
        return all_findings

    # ── Statistics ──────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "provider_confidence": self._provider_confidence,
            "metadata_keys": list(self._metadata_harvested.keys()),
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.stats()
