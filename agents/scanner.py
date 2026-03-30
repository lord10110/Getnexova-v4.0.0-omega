"""
GetNexova Scanner Agent (v2)
==============================
REAL pipeline with data flow between tools:
  subfinder → output file → httpx reads it → output file → nuclei reads it
  httpx JSON → parsed live hosts + URLs → dalfox reads them
  gau/katana → URL list → feeds Shuvon scanners

Every phase writes output to workspace files and passes
file paths to downstream tools via the pipeline context.
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional

from core.tool_health import HealthReport, is_tool_available
from core.auth_handler import AuthHandler
from core.rate_limiter import AdaptiveRateLimiter
from core.errors import ToolError, get_error_aggregator

logger = logging.getLogger("getnexova.scanner")


@dataclass
class Finding:
    """Normalized vulnerability finding."""
    id: str = ""
    tool: str = ""
    target: str = ""
    vulnerability_type: str = ""
    severity: str = "info"
    confidence: float = 0.5
    evidence: str = ""
    raw_output: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    url: str = ""
    timestamp: str = ""
    validated: bool = False
    is_false_positive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "tool": self.tool, "target": self.target,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity, "confidence": self.confidence,
            "evidence": self.evidence, "raw_output": self.raw_output,
            "cvss_score": self.cvss_score, "cvss_vector": self.cvss_vector,
            "url": self.url, "validated": self.validated,
            "is_false_positive": self.is_false_positive,
            "metadata": self.metadata,
        }


@dataclass
class PipelineContext:
    """
    Shared context that flows between pipeline phases.
    Each phase reads from and writes to this context.
    """
    target: str = ""
    workspace: Path = field(default_factory=lambda: Path("/tmp/getnexova"))
    # Files produced by phases
    subdomain_file: str = ""       # subfinder output
    live_hosts_file: str = ""      # httpx live hosts (one per line)
    live_hosts_json: str = ""      # httpx full JSON output
    urls_file: str = ""            # discovered URLs
    # Parsed data
    subdomains: List[str] = field(default_factory=list)
    live_hosts: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    # Accumulator
    all_findings: List[Finding] = field(default_factory=list)

    def setup(self, target: str, workspace: Path) -> None:
        self.target = target
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.workspace / "scan_data").mkdir(exist_ok=True)
        # Pre-create file paths
        data = self.workspace / "scan_data"
        self.subdomain_file = str(data / "subdomains.txt")
        self.live_hosts_file = str(data / "live_hosts.txt")
        self.live_hosts_json = str(data / "httpx_output.jsonl")
        self.urls_file = str(data / "urls.txt")


class ScannerAgent:
    """
    Executes security tools with REAL data flow between phases.

    Phase outputs are written to files in the workspace.
    Downstream phases read those files as input.
    """

    def __init__(
        self,
        health_report: HealthReport,
        workspace: Path,
        auth: Optional[AuthHandler] = None,
        rate_limiter: Optional[AdaptiveRateLimiter] = None,
        timeout: int = 300,
        max_concurrent: int = 3,
    ):
        self.health = health_report
        self.workspace = workspace
        self.auth = auth
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.ctx = PipelineContext()
        self.errors = get_error_aggregator()

    async def run_pipeline(
        self, target: str, mode: str = "standard"
    ) -> PipelineContext:
        """
        Execute the full scanning pipeline with real data flow.

        Returns the PipelineContext with all findings and data.
        """
        self.ctx.setup(target, self.workspace / "scans" / target.replace(".", "_"))
        logger.info(f"▶ Starting {mode} scan pipeline for {target}")

        # Phase 1: Subdomain enumeration
        await self._phase_subdomain_enum(target)

        # Phase 2: HTTP probing (reads subdomain file)
        await self._phase_http_probe()

        # Phase 3: URL discovery
        if mode in ("standard", "deep"):
            await self._phase_url_discovery(target)

        # Phase 4: Vulnerability scanning (reads live hosts)
        await self._phase_nuclei_scan()

        # Phase 5: XSS scanning
        if mode in ("standard", "deep"):
            await self._phase_xss_scan()

        # Phase 6: Web server scanning (deep only)
        if mode == "deep":
            await self._phase_web_scan(target)

        # Phase 7: Network scanning (deep only)
        if mode == "deep":
            await self._phase_network_scan(target)

        # Phase 8: DNS enumeration (deep only)
        if mode == "deep":
            await self._phase_dns_enum(target)

        # Phase 9: Code/secret analysis (deep only)
        if mode == "deep":
            await self._phase_code_analysis()

        logger.info(
            f"✓ Pipeline complete: {len(self.ctx.subdomains)} subdomains, "
            f"{len(self.ctx.live_hosts)} live hosts, "
            f"{len(self.ctx.urls)} URLs, "
            f"{len(self.ctx.all_findings)} findings"
        )
        return self.ctx

    # ─── Phase implementations ────────────────────────────────────

    async def _phase_subdomain_enum(self, target: str) -> None:
        """Phase 1: Discover subdomains and write to file."""
        logger.info("  Phase 1: Subdomain enumeration")
        if not is_tool_available("subfinder", self.health):
            # Fallback: just use the target itself
            self.ctx.subdomains = [target]
            Path(self.ctx.subdomain_file).write_text(target + "\n")
            return

        output = await self._exec(
            ["subfinder", "-d", target, "-silent"],
            "subfinder",
        )
        if output:
            subs = [l.strip() for l in output.strip().split("\n") if l.strip()]
            # Always include the main target
            if target not in subs:
                subs.insert(0, target)
            self.ctx.subdomains = subs
            Path(self.ctx.subdomain_file).write_text("\n".join(subs) + "\n")
            logger.info(f"    → {len(subs)} subdomains discovered")
        else:
            self.ctx.subdomains = [target]
            Path(self.ctx.subdomain_file).write_text(target + "\n")

    async def _phase_http_probe(self) -> None:
        """Phase 2: Probe subdomains with httpx, write live hosts."""
        logger.info("  Phase 2: HTTP probing")
        if not is_tool_available("httpx", self.health):
            # Fallback: assume all subdomains are live
            self.ctx.live_hosts = [f"https://{s}" for s in self.ctx.subdomains]
            Path(self.ctx.live_hosts_file).write_text(
                "\n".join(self.ctx.live_hosts) + "\n"
            )
            return

        # httpx reads the subdomain file directly
        cmd = [
            "httpx", "-l", self.ctx.subdomain_file,
            "-silent", "-json",
            "-o", self.ctx.live_hosts_json,
            "-td",  # tech detection
        ]
        if self.auth and self.auth.is_configured:
            cmd = self.auth.inject_into_command(cmd, "httpx")

        output = await self._exec(cmd, "httpx")

        # Parse httpx JSON output for live hosts, URLs, and technologies
        live_hosts = []
        json_file = Path(self.ctx.live_hosts_json)
        # httpx may write to -o file OR stdout depending on version
        lines = []
        if json_file.exists():
            lines = json_file.read_text().strip().split("\n")
        elif output:
            lines = output.strip().split("\n")

        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                if url:
                    live_hosts.append(url)
                # Collect technologies
                techs = data.get("tech", [])
                host = data.get("host", "")
                if techs and host:
                    self.ctx.technologies[host] = techs
            except json.JSONDecodeError:
                # Plain text line (just a URL)
                if line.strip().startswith("http"):
                    live_hosts.append(line.strip())

        self.ctx.live_hosts = live_hosts
        # Write plain host list for tools that need it
        Path(self.ctx.live_hosts_file).write_text(
            "\n".join(live_hosts) + "\n"
        )
        logger.info(f"    → {len(live_hosts)} live hosts confirmed")

        # Detect WordPress for later phases
        for host, techs in self.ctx.technologies.items():
            tech_str = " ".join(techs).lower()
            if "wordpress" in tech_str:
                logger.info(f"    → WordPress detected on {host}")

    async def _phase_url_discovery(self, target: str) -> None:
        """Phase 3: Discover URLs using gau, waybackurls, katana."""
        logger.info("  Phase 3: URL discovery")
        all_urls: set = set()

        # Try gau (Get All URLs)
        if is_tool_available("gau", self.health):
            output = await self._exec(
                ["gau", "--threads", "3", "--o", "/dev/stdout", target],
                "gau",
            )
            if output:
                for line in output.strip().split("\n"):
                    u = line.strip()
                    if u and u.startswith("http"):
                        all_urls.add(u)

        # Try waybackurls
        if is_tool_available("waybackurls", self.health):
            output = await self._exec(
                ["waybackurls", target],
                "waybackurls",
            )
            if output:
                for line in output.strip().split("\n"):
                    u = line.strip()
                    if u and u.startswith("http"):
                        all_urls.add(u)

        # Try katana (crawling)
        if is_tool_available("katana", self.health) and self.ctx.live_hosts:
            for host in self.ctx.live_hosts[:5]:  # Limit crawling
                output = await self._exec(
                    ["katana", "-u", host, "-silent", "-d", "2", "-jc"],
                    "katana",
                )
                if output:
                    for line in output.strip().split("\n"):
                        u = line.strip()
                        if u and u.startswith("http"):
                            all_urls.add(u)

        # Also add live hosts as URLs
        all_urls.update(self.ctx.live_hosts)

        self.ctx.urls = sorted(all_urls)
        Path(self.ctx.urls_file).write_text("\n".join(self.ctx.urls) + "\n")
        logger.info(f"    → {len(self.ctx.urls)} unique URLs discovered")

    async def _phase_nuclei_scan(self) -> None:
        """Phase 4: Template-based vulnerability scanning."""
        logger.info("  Phase 4: Nuclei vulnerability scanning")
        if not is_tool_available("nuclei", self.health):
            logger.warning("    Nuclei not available — skipping")
            return

        # Use live hosts file as input
        input_file = self.ctx.live_hosts_file
        if not Path(input_file).exists() or Path(input_file).stat().st_size == 0:
            input_file = self.ctx.subdomain_file

        cmd = [
            "nuclei", "-l", input_file,
            "-json", "-severity", "low,medium,high,critical",
            "-silent",
        ]
        if self.auth and self.auth.is_configured:
            cmd = self.auth.inject_into_command(cmd, "nuclei")

        output = await self._exec(cmd, "nuclei", timeout=600)
        if output:
            findings = self._parse_nuclei(output)
            self.ctx.all_findings.extend(findings)
            logger.info(f"    → {len(findings)} nuclei findings")

    async def _phase_xss_scan(self) -> None:
        """Phase 5: XSS scanning with dalfox on URLs with parameters."""
        logger.info("  Phase 5: XSS scanning")
        if not is_tool_available("dalfox", self.health):
            logger.warning("    dalfox not available — skipping")
            return

        # Filter URLs that have query parameters
        param_urls = [u for u in self.ctx.urls if "?" in u and "=" in u]
        if not param_urls:
            logger.info("    No URLs with parameters found — skipping XSS scan")
            return

        # Write param URLs to file
        param_file = str(self.ctx.workspace / "scan_data" / "param_urls.txt")
        Path(param_file).write_text("\n".join(param_urls[:100]) + "\n")

        cmd = ["dalfox", "file", param_file, "--silence", "--format", "json"]
        if self.auth and self.auth.is_configured:
            cmd = self.auth.inject_into_command(cmd, "dalfox")

        output = await self._exec(cmd, "dalfox", timeout=300)
        if output:
            findings = self._parse_dalfox(output)
            self.ctx.all_findings.extend(findings)
            logger.info(f"    → {len(findings)} XSS findings")

    async def _phase_web_scan(self, target: str) -> None:
        """Phase 6: Web server scanning with nikto."""
        logger.info("  Phase 6: Web server scanning (nikto)")
        if not is_tool_available("nikto", self.health):
            return

        # Scan each live host (limit to 5)
        for host in self.ctx.live_hosts[:5]:
            output = await self._exec(
                ["nikto", "-h", host, "-Format", "json", "-output", "/dev/stdout"],
                "nikto", timeout=300,
            )
            if output:
                findings = self._parse_nikto(output, host)
                self.ctx.all_findings.extend(findings)

    async def _phase_network_scan(self, target: str) -> None:
        """Phase 7: Network scanning with nmap."""
        logger.info("  Phase 7: Network scanning (nmap)")
        if not is_tool_available("nmap", self.health):
            return

        output = await self._exec(
            ["nmap", "-sV", "-sC", "-T4", "-oX", "-", target],
            "nmap", timeout=600,
        )
        if output:
            findings = self._parse_nmap(output, target)
            self.ctx.all_findings.extend(findings)
            logger.info(f"    → {len(findings)} network findings")

    async def _phase_dns_enum(self, target: str) -> None:
        """Phase 8: DNS enumeration."""
        logger.info("  Phase 8: DNS enumeration")
        for tool in ["dnsrecon", "dnsenum"]:
            if is_tool_available(tool, self.health):
                if tool == "dnsrecon":
                    await self._exec(
                        ["dnsrecon", "-d", target, "-j",
                         str(self.ctx.workspace / "scan_data" / "dns.json")],
                        tool, timeout=120,
                    )
                break

    async def _phase_code_analysis(self) -> None:
        """Phase 9: Code/secret analysis."""
        logger.info("  Phase 9: Code/secret analysis")
        if is_tool_available("gitleaks", self.health):
            output = await self._exec(
                ["gitleaks", "detect", "--source", ".",
                 "--report-format", "json", "--report-path", "/dev/stdout"],
                "gitleaks", timeout=120,
            )
            if output:
                try:
                    secrets = json.loads(output)
                    if isinstance(secrets, list):
                        for s in secrets:
                            self.ctx.all_findings.append(Finding(
                                id=f"gitleaks-{s.get('RuleID', 'x')}-{hash(s.get('File',''))&0xFFFF:04x}",
                                tool="gitleaks",
                                target=self.ctx.target,
                                vulnerability_type="Exposed Secret/Credential",
                                severity="high",
                                confidence=0.85,
                                evidence=f"Rule: {s.get('RuleID','')} File: {s.get('File','')}",
                                raw_output=json.dumps(s)[:1000],
                            ))
                except json.JSONDecodeError:
                    pass

    # ─── Tool execution ───────────────────────────────────────────

    async def _exec(
        self, cmd: List[str], tool: str, timeout: Optional[int] = None
    ) -> Optional[str]:
        """Execute a tool command with timeout and error handling."""
        effective_timeout = timeout or self.timeout
        async with self._semaphore:
            try:
                logger.debug(f"    exec: {' '.join(cmd[:6])}...")
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=effective_timeout
                )
                output = stdout.decode("utf-8", errors="replace")
                if proc.returncode != 0 and not output:
                    err = stderr.decode("utf-8", errors="replace")[:200]
                    logger.warning(f"    {tool} exit code {proc.returncode}: {err}")
                return output if output.strip() else None
            except asyncio.TimeoutError:
                logger.warning(f"    {tool} timed out after {effective_timeout}s")
                self.errors.record(
                    ToolError(f"{tool} timed out"), phase="scanning", tool=tool
                )
                return None
            except FileNotFoundError:
                logger.warning(f"    {tool} binary not found")
                return None
            except Exception as e:
                logger.error(f"    {tool} error: {e}")
                self.errors.record(e, phase="scanning", tool=tool)
                return None

    # ─── Output parsers ───────────────────────────────────────────

    def _parse_nuclei(self, output: str) -> List[Finding]:
        findings = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                tid = data.get("template-id", "unknown")
                findings.append(Finding(
                    id=f"nuclei-{tid}-{len(findings)}",
                    tool="nuclei",
                    target=data.get("host", self.ctx.target),
                    vulnerability_type=info.get("name", tid),
                    severity=info.get("severity", "info").lower(),
                    confidence=0.75,
                    evidence=data.get("matched-at", ""),
                    raw_output=line[:2000],
                    url=data.get("matched-at", ""),
                    metadata={
                        "template_id": tid,
                        "tags": info.get("tags", []),
                        "reference": info.get("reference", []),
                        "description": info.get("description", ""),
                        "matcher_name": data.get("matcher-name", ""),
                    },
                ))
            except json.JSONDecodeError:
                continue
        return findings

    def _parse_dalfox(self, output: str) -> List[Finding]:
        findings = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append(Finding(
                    id=f"dalfox-xss-{len(findings)}",
                    tool="dalfox",
                    target=data.get("data", self.ctx.target),
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    severity="medium",
                    confidence=0.8,
                    evidence=data.get("poc", data.get("data", "")),
                    raw_output=line[:2000],
                    url=data.get("data", ""),
                    metadata={"type": data.get("type", ""), "poc": data.get("poc", "")},
                ))
            except json.JSONDecodeError:
                continue
        return findings

    def _parse_nmap(self, output: str, target: str) -> List[Finding]:
        findings = []
        ports = re.findall(
            r'<port protocol="(\w+)" portid="(\d+)".*?'
            r'<state state="open".*?'
            r'<service name="([^"]*)".*?(?:version="([^"]*)")?',
            output, re.DOTALL,
        )
        for proto, port, service, version in ports:
            findings.append(Finding(
                id=f"nmap-{target}-{port}",
                tool="nmap",
                target=target,
                vulnerability_type=f"Open Port: {port}/{proto} ({service})",
                severity="info",
                confidence=0.9,
                evidence=f"{service} {version or 'unknown'} on {port}/{proto}",
                metadata={"port": int(port), "protocol": proto,
                          "service": service, "version": version or ""},
            ))
        return findings

    def _parse_nikto(self, output: str, host: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(output)
            for vuln in data.get("vulnerabilities", []):
                findings.append(Finding(
                    id=f"nikto-{vuln.get('id', len(findings))}",
                    tool="nikto", target=host,
                    vulnerability_type=vuln.get("msg", "Web Server Finding"),
                    severity="medium" if "OSVDB" in str(vuln) else "low",
                    confidence=0.6,
                    evidence=vuln.get("msg", ""),
                    url=vuln.get("url", host),
                ))
        except json.JSONDecodeError:
            pass
        return findings

    def get_findings_summary(self) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.ctx.all_findings:
            s = f.severity.lower()
            if s in summary:
                summary[s] += 1
        return summary
