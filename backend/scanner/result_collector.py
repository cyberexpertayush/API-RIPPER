"""
API RIPPER — Result Collector
Captures output from ARSec modules and converts them to structured findings.
Wraps print/colorama output, strips ANSI codes, parses known patterns.
"""

import re
import io
import sys
import logging
from contextlib import contextmanager
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# ANSI escape code pattern
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def strip_ansi(text: str) -> str:
    """Strip ANSI color codes from text"""
    return ANSI_RE.sub('', text)


class CapturedFinding:
    """A structured finding captured from module output"""

    def __init__(
        self,
        category: str,
        module_name: str,
        severity: str = "info",
        title: str = "",
        description: str = "",
        endpoint_url: str = "",
        method: str = "GET",
        details: dict = None,
        remediation: str = "",
        cwe_id: str = None,
        cvss_score: float = None,
    ):
        self.category = category
        self.module_name = module_name
        self.severity = severity
        self.title = title
        self.description = description
        self.endpoint_url = endpoint_url
        self.method = method
        self.details = details or {}
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.cvss_score = cvss_score
        self.discovered_at = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "module_name": self.module_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "endpoint_url": self.endpoint_url,
            "method": self.method,
            "details": self.details,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
        }


class ResultCollector:
    """
    Collects findings from ARSec module execution.
    Can capture stdout to parse CLI output and also accept structured findings directly.
    """

    # Lines containing these phrases are status/progress messages, NOT findings
    NEGATIVE_INDICATORS = [
        'not vulnerable', 'no issues', 'no vulnerabilities found',
        'no .* found', 'no .* detected', 'not detected', 'not found',
        'no .* vulnerabilities', 'done', 'starting', 'complete',
        'report saved', 'saved to', 'scan complete', 'best practices',
        'establishing baseline', 'detecting server', 'discovering',
        'consistent', 'could not detect', 'testing', 'scanning',
        'checked', 'passed', 'safe', 'secure', 'properly configured',
        'not susceptible', 'protected', 'no evidence',
    ]

    # Lines MUST contain one of these to be a real finding from stdout
    POSITIVE_INDICATORS = [
        ('VULNERABLE!', 'high'),
        ('POSSIBLE!', 'medium'),
        ('FOUND!', 'medium'),
        ('MISCONFIGURED', 'medium'),
        ('INSECURE!', 'medium'),
        ('EXPOSED!', 'high'),
        ('Inconsistencies detected', 'medium'),
    ]

    def __init__(self, scan_id: str, target_url: str):
        self.scan_id = scan_id
        self.target_url = target_url
        self.findings: List[CapturedFinding] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.raw_output: List[str] = []
        self.current_module: str = ""
        self.current_category: str = ""
        self._seen_titles: set = set()  # deduplication
        self._has_structured_findings: bool = False  # skip stdout when structured data exists

    def set_module(self, module_name: str, category: str):
        """Set the currently executing module"""
        self.current_module = module_name
        self.current_category = category
        self._has_structured_findings = False

    def add_finding(self, finding: CapturedFinding):
        """Add a structured finding (with deduplication)"""
        key = (finding.title.strip().lower(), finding.module_name)
        if key in self._seen_titles:
            return
        self._seen_titles.add(key)
        self.findings.append(finding)
        self._has_structured_findings = True

    def add_finding_simple(
        self,
        title: str,
        severity: str = "info",
        description: str = "",
        endpoint_url: str = "",
        details: dict = None,
    ):
        """Add a finding with minimal parameters, using current module context"""
        self.add_finding(CapturedFinding(
            category=self.current_category,
            module_name=self.current_module,
            severity=severity,
            title=title,
            description=description,
            endpoint_url=endpoint_url or self.target_url,
            details=details or {},
        ))

    def add_endpoint(self, url: str, method: str = "GET", status_code: int = 0, **kwargs):
        """Record a discovered endpoint"""
        # Deduplicate endpoints
        for existing in self.endpoints:
            if existing.get("url") == url and existing.get("method") == method:
                return
        self.endpoints.append({
            "url": url,
            "method": method,
            "status_code": status_code,
            **kwargs,
        })

    @contextmanager
    def capture_stdout(self):
        """Context manager to capture stdout from ARSec modules"""
        captured = io.StringIO()
        old_stdout = sys.stdout

        class TeeOutput:
            def write(self, text):
                captured.write(text)
                # Don't forward to real stdout to avoid noise in server logs
            def flush(self):
                captured.flush()

        sys.stdout = TeeOutput()
        try:
            yield captured
        finally:
            sys.stdout = old_stdout
            output = captured.getvalue()
            if output.strip():
                self.raw_output.append(strip_ansi(output))
                # Only parse stdout if the module didn't return structured findings
                if not self._has_structured_findings:
                    self._parse_output(output)

    def _is_negative_line(self, line: str) -> bool:
        """Check if a line is a status/progress message or negative result"""
        lower = line.lower()
        # Explicit negative patterns first
        for neg in self.NEGATIVE_INDICATORS:
            if neg in lower:
                return True
        # Skip lines that are just module status prefixes like "[*] ...", "[+] ..."
        # followed by "Done" or similar
        if re.match(r'^\[[\*\+\-!]\]\s+', line) and lower.endswith('done'):
            return True
        # Lines starting with [+] No ... or [+] Not ... are negative results
        if re.match(r'^\[[\+\*]\]\s+(no|not)\s+', lower):
            return True
        return False

    def _parse_output(self, raw: str):
        """
        Parse raw CLI output for CONFIRMED vulnerability findings only.
        Skips status lines, progress messages, and negative results.
        """
        clean = strip_ansi(raw)
        lines = clean.split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Skip negative/status lines first
            if self._is_negative_line(line):
                continue

            # Only match lines with strong positive indicators
            for keyword, severity in self.POSITIVE_INDICATORS:
                if keyword.lower() in line.lower():
                    self.add_finding_simple(
                        title=line[:200],
                        severity=severity,
                        description=line,
                    )
                    break

    def get_severity_counts(self) -> Dict[str, int]:
        """Return counts by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def get_summary(self) -> dict:
        counts = self.get_severity_counts()
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "total_findings": len(self.findings),
            "total_endpoints": len(self.endpoints),
            "severity_counts": counts,
            "modules_run": list(set(f.module_name for f in self.findings)),
        }
