"""
GetNexova PoC Generator
=========================
Generates proof-of-concept scripts for validated findings.
Creates curl commands, Python scripts, and browser-ready payloads.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import quote

logger = logging.getLogger("getnexova.poc")


class PoCGenerator:
    """
    Generates proof-of-concept code for vulnerability findings.

    Supports:
    - curl commands for HTTP-based vulns
    - Python requests scripts
    - Browser URL payloads
    - Nuclei template references
    """

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path("reports/pocs")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate PoC for a finding.

        Returns dict of format -> poc_content.
        """
        vuln_type = finding.get("vulnerability_type", "").lower()
        target = finding.get("target", "")
        url = finding.get("url", target)
        evidence = finding.get("evidence", "")
        metadata = finding.get("metadata", {})

        pocs: Dict[str, str] = {}

        # Curl command
        curl = self._generate_curl(url, finding)
        if curl:
            pocs["curl"] = curl

        # Python script
        python_poc = self._generate_python(url, finding)
        if python_poc:
            pocs["python"] = python_poc

        # Browser payload (for XSS, open redirect)
        if "xss" in vuln_type or "redirect" in vuln_type:
            browser = self._generate_browser(url, finding)
            if browser:
                pocs["browser"] = browser

        # Nuclei template reference
        template_id = metadata.get("template_id", "")
        if template_id:
            pocs["nuclei"] = f"nuclei -u {url} -t {template_id} -v"

        return pocs

    def generate_all(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, str]]:
        """Generate PoCs for all findings."""
        results = {}
        for finding in findings:
            fid = finding.get("id", "unknown")
            try:
                pocs = self.generate(finding)
                if pocs:
                    results[fid] = pocs
            except Exception as e:
                logger.warning(f"PoC generation failed for {fid}: {e}")
        logger.info(f"Generated PoCs for {len(results)}/{len(findings)} findings")
        return results

    def save_pocs(
        self, pocs: Dict[str, Dict[str, str]], target: str
    ) -> Path:
        """Save all PoCs to files."""
        poc_dir = self.output_dir / target.replace(".", "_")
        poc_dir.mkdir(parents=True, exist_ok=True)

        for finding_id, poc_types in pocs.items():
            for fmt, content in poc_types.items():
                ext = {"curl": "sh", "python": "py", "browser": "txt", "nuclei": "sh"}
                filename = f"{finding_id}_{fmt}.{ext.get(fmt, 'txt')}"
                filepath = poc_dir / filename
                filepath.write_text(content, encoding="utf-8")

        logger.info(f"Saved PoCs to {poc_dir}")
        return poc_dir

    def _generate_curl(self, url: str, finding: Dict[str, Any]) -> str:
        """Generate a curl command."""
        method = finding.get("metadata", {}).get("method", "GET")
        lines = [
            f"#!/bin/bash",
            f"# GetNexova PoC — {finding.get('vulnerability_type', 'Unknown')}",
            f"# Target: {finding.get('target', '')}",
            f"# Severity: {finding.get('severity', 'unknown')}",
            f"",
        ]

        if method == "GET":
            lines.append(f'curl -v -k "{url}"')
        else:
            body = finding.get("metadata", {}).get("body", "")
            lines.append(f'curl -v -k -X {method} "{url}" \\')
            lines.append(f'  -H "Content-Type: application/json" \\')
            if body:
                lines.append(f"  -d '{body}'")

        return "\n".join(lines)

    def _generate_python(self, url: str, finding: Dict[str, Any]) -> str:
        """Generate a Python requests script."""
        return f'''#!/usr/bin/env python3
"""
GetNexova PoC — {finding.get('vulnerability_type', 'Unknown')}
Target: {finding.get('target', '')}
Severity: {finding.get('severity', 'unknown')}
CVSS: {finding.get('cvss_score', 'N/A')}
"""

import requests

url = "{url}"

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings()

response = requests.get(url, verify=False, timeout=10)

print(f"Status: {{response.status_code}}")
print(f"Headers: {{dict(response.headers)}}")
print(f"Body (first 500 chars): {{response.text[:500]}}")

# Evidence: {finding.get('evidence', 'N/A')[:200]}
'''

    def _generate_browser(self, url: str, finding: Dict[str, Any]) -> str:
        """Generate a browser-ready payload."""
        poc = finding.get("metadata", {}).get("poc", "")
        return f"""GetNexova PoC — Browser Payload
================================
Type: {finding.get('vulnerability_type', '')}
Target: {finding.get('target', '')}

Open this URL in a browser:
{poc or url}

Expected behavior:
{finding.get('evidence', 'Check for unexpected behavior')}
"""
