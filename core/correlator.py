"""
GetNexova Finding Correlation Engine
========================================
Goes beyond type-based graph matching. Tracks actual discovery
chains where one finding's output enables the next finding.

Example narrative:
  subfinder → admin.target.com → httpx confirms 401 →
  nikto finds /admin/config.bak → gitleaks finds AWS keys in backup

This builds an evidence-based attack story, not just a
theoretical vulnerability chain.
"""

import logging
import hashlib
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("getnexova.correlator")


@dataclass
class DiscoveryLink:
    """A link in a discovery chain — one finding enabling another."""
    source_finding_id: str
    target_finding_id: str
    link_type: str          # "discovered_on", "exposed_by", "leads_to"
    evidence: str           # What specifically connects them
    confidence: float = 0.7


@dataclass
class CorrelationChain:
    """A complete correlation chain — a real attack narrative."""
    chain_id: str
    title: str
    narrative: str          # Human-readable attack story
    findings: List[Dict[str, Any]]
    links: List[DiscoveryLink]
    combined_severity: str
    combined_cvss: float
    business_impact: str
    steps_to_reproduce: List[str]


class FindingCorrelator:
    """
    Correlates findings by actual discovery relationships.

    Unlike the GraphChainEngine which matches vulnerability TYPES,
    this engine correlates specific findings based on:
    - Same host/subdomain (asset-level correlation)
    - One finding's output containing another's target
    - Technology → vulnerability mapping
    - Credential exposure → access escalation
    """

    def __init__(self):
        self._findings: List[Dict[str, Any]] = []
        self._by_host: Dict[str, List[Dict]] = defaultdict(list)
        self._by_type: Dict[str, List[Dict]] = defaultdict(list)
        self._links: List[DiscoveryLink] = []
        self._chains: List[CorrelationChain] = []

    def ingest(self, findings: List[Dict[str, Any]], technologies: Dict[str, List[str]] = None) -> None:
        """Ingest findings and optionally technology detection results."""
        self._findings = findings
        self._by_host.clear()
        self._by_type.clear()

        for f in findings:
            # Extract host from target/url
            host = self._extract_host(f.get("target", "") or f.get("url", ""))
            self._by_host[host].append(f)
            vtype = f.get("vulnerability_type", "").lower()
            for keyword in self._extract_keywords(vtype):
                self._by_type[keyword].append(f)

        # Add technology correlations
        if technologies:
            self._correlate_technologies(technologies)

    def correlate(self) -> List[CorrelationChain]:
        """Run all correlation strategies and build chains."""
        self._links.clear()
        self._chains.clear()

        # Strategy 1: Host-level correlation
        self._correlate_by_host()

        # Strategy 2: Credential → Access escalation
        self._correlate_credential_chains()

        # Strategy 3: Info disclosure → Exploitation
        self._correlate_info_to_exploit()

        # Strategy 4: Missing security headers → Impact amplification
        self._correlate_header_amplification()

        # Build chains from links
        self._build_chains()

        logger.info(
            f"Correlation: {len(self._links)} links, "
            f"{len(self._chains)} chains from {len(self._findings)} findings"
        )
        return self._chains

    def _correlate_by_host(self) -> None:
        """Find correlations between findings on the same host."""
        for host, host_findings in self._by_host.items():
            if len(host_findings) < 2:
                continue

            # Sort by severity for priority
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_f = sorted(host_findings, key=lambda f: sev_order.get(f.get("severity", "info"), 5))

            # Look for info→vuln patterns on same host
            info_findings = [f for f in sorted_f if f.get("severity") == "info"]
            vuln_findings = [f for f in sorted_f if f.get("severity") in ("medium", "high", "critical")]

            for info_f in info_findings:
                for vuln_f in vuln_findings:
                    # Open port → service vulnerability
                    if "open port" in info_f.get("vulnerability_type", "").lower():
                        port = info_f.get("metadata", {}).get("port", 0)
                        vuln_target = vuln_f.get("target", "")
                        if str(port) in vuln_target:
                            self._links.append(DiscoveryLink(
                                source_finding_id=info_f.get("id", ""),
                                target_finding_id=vuln_f.get("id", ""),
                                link_type="discovered_on",
                                evidence=f"Service on port {port} hosts vulnerable endpoint",
                                confidence=0.7,
                            ))

    def _correlate_credential_chains(self) -> None:
        """Link credential exposure to potential account takeover."""
        cred_findings = [
            f for f in self._findings
            if any(kw in f.get("vulnerability_type", "").lower()
                   for kw in ["credential", "secret", "key", "token", "password", ".env"])
        ]
        access_findings = [
            f for f in self._findings
            if any(kw in f.get("vulnerability_type", "").lower()
                   for kw in ["admin", "dashboard", "internal", "api"])
        ]

        for cred in cred_findings:
            for access in access_findings:
                cred_host = self._extract_host(cred.get("target", ""))
                access_host = self._extract_host(access.get("target", ""))

                # Same domain or related
                if self._hosts_related(cred_host, access_host):
                    self._links.append(DiscoveryLink(
                        source_finding_id=cred.get("id", ""),
                        target_finding_id=access.get("id", ""),
                        link_type="leads_to",
                        evidence=(
                            f"Exposed credentials from {cred_host} may grant "
                            f"access to {access.get('vulnerability_type', '')} on {access_host}"
                        ),
                        confidence=0.6,
                    ))

    def _correlate_info_to_exploit(self) -> None:
        """Link information disclosure to exploitable vulnerabilities."""
        info_findings = [
            f for f in self._findings
            if f.get("severity") in ("info", "low") and
               any(kw in f.get("vulnerability_type", "").lower()
                   for kw in ["directory", "backup", "config", "debug", "stack trace", "error"])
        ]
        exploit_findings = [
            f for f in self._findings
            if f.get("severity") in ("high", "critical")
        ]

        for info_f in info_findings:
            for exploit_f in exploit_findings:
                if self._hosts_related(
                    self._extract_host(info_f.get("target", "")),
                    self._extract_host(exploit_f.get("target", "")),
                ):
                    self._links.append(DiscoveryLink(
                        source_finding_id=info_f.get("id", ""),
                        target_finding_id=exploit_f.get("id", ""),
                        link_type="exposed_by",
                        evidence=(
                            f"{info_f.get('vulnerability_type', '')} may reveal "
                            f"information useful for exploiting "
                            f"{exploit_f.get('vulnerability_type', '')}"
                        ),
                        confidence=0.5,
                    ))

    def _correlate_header_amplification(self) -> None:
        """Missing security headers amplify other vulnerabilities."""
        header_findings = [
            f for f in self._findings
            if any(kw in f.get("vulnerability_type", "").lower()
                   for kw in ["csp", "hsts", "x-frame", "header", "cors"])
        ]
        xss_findings = [
            f for f in self._findings
            if "xss" in f.get("vulnerability_type", "").lower()
        ]

        for header in header_findings:
            for xss in xss_findings:
                if self._hosts_related(
                    self._extract_host(header.get("target", "")),
                    self._extract_host(xss.get("target", "")),
                ):
                    self._links.append(DiscoveryLink(
                        source_finding_id=header.get("id", ""),
                        target_finding_id=xss.get("id", ""),
                        link_type="amplifies",
                        evidence=(
                            f"Missing {header.get('vulnerability_type', '')} "
                            f"amplifies XSS impact — no browser-level mitigation"
                        ),
                        confidence=0.8,
                    ))

    def _correlate_technologies(self, technologies: Dict[str, List[str]]) -> None:
        """Correlate detected technologies with known vulnerabilities."""
        for host, techs in technologies.items():
            tech_str = " ".join(techs).lower()
            host_findings = self._by_host.get(host, [])

            for f in host_findings:
                # WordPress + wpscan findings
                if "wordpress" in tech_str and "wp" in f.get("tool", "").lower():
                    f.setdefault("metadata", {})["tech_confirmed"] = True

    def _build_chains(self) -> None:
        """Build correlation chains from discovered links."""
        if not self._links:
            return

        # Group links into connected components
        finding_map = {f.get("id", ""): f for f in self._findings}
        adjacency: Dict[str, List[DiscoveryLink]] = defaultdict(list)
        for link in self._links:
            adjacency[link.source_finding_id].append(link)

        visited: Set[str] = set()
        for start_id in adjacency:
            if start_id in visited:
                continue

            # BFS to find connected chain
            chain_ids = []
            chain_links = []
            queue = [start_id]
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                chain_ids.append(current)
                for link in adjacency.get(current, []):
                    chain_links.append(link)
                    if link.target_finding_id not in visited:
                        queue.append(link.target_finding_id)

            if len(chain_ids) < 2:
                continue

            chain_findings = [finding_map[fid] for fid in chain_ids if fid in finding_map]
            if not chain_findings:
                continue

            # Build narrative
            narrative = self._build_narrative(chain_findings, chain_links)
            steps = [
                f"Step {i+1}: {f.get('vulnerability_type', '?')} on {f.get('target', '?')}"
                for i, f in enumerate(chain_findings)
            ]

            # Calculate combined severity
            sev_scores = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
            max_sev = max(sev_scores.get(f.get("severity", "info"), 0) for f in chain_findings)
            combined = min(max_sev + len(chain_findings) * 0.5, 10.0)
            combined_severity = (
                "critical" if combined >= 9.0 else
                "high" if combined >= 7.0 else "medium"
            )

            chain_id = hashlib.md5("|".join(chain_ids).encode()).hexdigest()[:8]

            self._chains.append(CorrelationChain(
                chain_id=chain_id,
                title=f"{chain_findings[0].get('vulnerability_type','?')} → {chain_findings[-1].get('vulnerability_type','?')}",
                narrative=narrative,
                findings=chain_findings,
                links=chain_links,
                combined_severity=combined_severity,
                combined_cvss=round(combined, 1),
                business_impact=f"Multi-step attack combining {len(chain_findings)} vulnerabilities on related assets",
                steps_to_reproduce=steps,
            ))

        self._chains.sort(key=lambda c: c.combined_cvss, reverse=True)

    def _build_narrative(self, findings: List[Dict], links: List[DiscoveryLink]) -> str:
        """Build a human-readable attack narrative."""
        parts = []
        for i, f in enumerate(findings):
            target = f.get("target", "unknown")
            vtype = f.get("vulnerability_type", "unknown")
            if i == 0:
                parts.append(f"The attack begins with {vtype} discovered on {target}.")
            else:
                # Find the link connecting to this finding
                link_desc = ""
                for link in links:
                    if link.target_finding_id == f.get("id"):
                        link_desc = f" This {link.link_type.replace('_', ' ')} "
                        break
                parts.append(f"{link_desc}{vtype} on {target}.")
        return " ".join(parts)

    @staticmethod
    def _extract_host(target: str) -> str:
        if "://" in target:
            from urllib.parse import urlparse
            return urlparse(target).netloc
        return target.split("/")[0].split(":")[0]

    @staticmethod
    def _hosts_related(h1: str, h2: str) -> bool:
        if not h1 or not h2:
            return False
        if h1 == h2:
            return True
        # Same base domain
        parts1 = h1.lower().split(".")
        parts2 = h2.lower().split(".")
        if len(parts1) >= 2 and len(parts2) >= 2:
            return parts1[-2:] == parts2[-2:]
        return False

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        keywords = []
        for kw in ["xss", "sqli", "ssrf", "idor", "rce", "lfi",
                    "credential", "secret", "admin", "redirect",
                    "cors", "csrf", "csp", "header", "upload",
                    "port", "debug", "config", "backup"]:
            if kw in text:
                keywords.append(kw)
        return keywords

    def get_chains_as_dicts(self) -> List[Dict[str, Any]]:
        return [
            {
                "chain_id": c.chain_id,
                "title": c.title,
                "narrative": c.narrative,
                "combined_severity": c.combined_severity,
                "combined_cvss": c.combined_cvss,
                "business_impact": c.business_impact,
                "steps": c.steps_to_reproduce,
                "finding_count": len(c.findings),
            }
            for c in self._chains
        ]
