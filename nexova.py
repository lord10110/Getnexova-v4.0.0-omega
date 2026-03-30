"""
GetNexova Main Orchestrator (v2)
===================================
Wires all modules together with real data flow.
Every phase reads from the previous phase's actual output.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from core.config import GetNexovaConfig, REPORTS_DIR, LOGS_DIR, DATA_DIR
from core.logging_config import setup_logging, get_logger
from core.tool_health import check_all_tools, HealthReport
from core.scope import ScopeEnforcer, ProgramScope
from core.errors import get_error_aggregator, reset_error_aggregator
from core.maestro import MaestroResourceManager
from core.rate_limiter import AdaptiveRateLimiter
from core.auth_handler import AuthHandler
from core.checkpoint import CheckpointManager
from core.validator_omega import OmegaDualValidator
from core.plugin_manager import PluginManager
from core.screenshots import ScreenshotCapture
from core.correlator import FindingCorrelator

from agents.ai_engine import AIEngine
from agents.planner import PlannerAgent
from agents.scanner import ScannerAgent, Finding
from agents.researcher import ResearcherAgent
from agents.reporter import ReporterAgent
from agents.graph_engine import GraphChainEngine

from integrations.notifications import NotificationDispatcher
from integrations.clawteam import ClawTeamManager, ClawTeamConfig
from integrations.submission_pipeline import SubmissionPipeline

from scanners.shuvon_scanners import ShuvonScannerSuite

from skills.continuous_learning.learner import ContinuousLearner
from reports.poc_generator import PoCGenerator
from reports.diff_report import DiffReporter
from memory.knowledge_base import KnowledgeBase

logger = get_logger("orchestrator")

BANNER = r"""
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║   ██████╗ ███████╗████████╗███╗   ██╗███████╗██╗  ██╗   ║
  ║  ██╔════╝ ██╔════╝╚══██╔══╝████╗  ██║██╔════╝╚██╗██╔╝   ║
  ║  ██║  ███╗█████╗     ██║   ██╔██╗ ██║█████╗   ╚███╔╝    ║
  ║  ██║   ██║██╔══╝     ██║   ██║╚██╗██║██╔══╝   ██╔██╗    ║
  ║  ╚██████╔╝███████╗   ██║   ██║ ╚████║███████╗██╔╝ ██╗   ║
  ║   ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ║
  ║              ╔═╗╦  ╦╔═╗                                   ║
  ║              ║ ║╚╗╔╝╠═╣                                   ║
  ║              ╚═╝ ╚╝ ╩ ╩                                   ║
  ║                                                          ║
  ║       GetNexova v4.0.0 OMEGA — Bug Bounty Engine         ║
  ║            getnexova.com | Authorized Use Only            ║
  ╚══════════════════════════════════════════════════════════╝
"""


@dataclass
class ScanResult:
    target: str
    mode: str
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    subdomains_found: int = 0
    live_hosts_found: int = 0
    urls_discovered: int = 0
    total_findings: int = 0
    validated_findings: int = 0
    false_positives: int = 0
    chains_found: int = 0
    correlations_found: int = 0
    screenshots_captured: int = 0
    pocs_generated: int = 0
    severity_summary: Dict[str, int] = field(default_factory=dict)
    report_paths: Dict[str, str] = field(default_factory=dict)
    tools_used: List[str] = field(default_factory=list)
    ai_cost: float = 0.0
    errors: List[str] = field(default_factory=list)
    validation_stats: Dict[str, int] = field(default_factory=dict)


class GetNexova:
    """Main orchestrator — wires all modules with real data flow."""

    def __init__(self, config: Optional[GetNexovaConfig] = None):
        self.config = config or GetNexovaConfig()
        setup_logging(log_dir=LOGS_DIR, level=logging.DEBUG)

    async def run(
        self,
        target: str,
        mode: str = "standard",
        exclude_domains: Optional[List[str]] = None,
        no_ai: bool = False,
        report_format: str = "all",
        resume: bool = False,
        auth_token: str = "",
        auth_cookies: str = "",
    ) -> ScanResult:
        start = time.time()
        result = ScanResult(
            target=target, mode=mode,
            start_time=datetime.now(timezone.utc).isoformat(),
        )
        print(BANNER)

        # ─── Phase 1: Initialize everything ───────────────────
        logger.info("Phase 1: Initialization")
        reset_error_aggregator()
        errors = get_error_aggregator()

        health = check_all_tools()
        print(health.summary())

        workspace = Path(self.config.scan.workspace if hasattr(self.config.scan, 'workspace')
                        else "data") / "workspaces" / target.replace(".", "_")
        workspace.mkdir(parents=True, exist_ok=True)

        # Initialize all components
        maestro = MaestroResourceManager()
        await maestro.start()

        ai_engine = AIEngine(self.config) if not no_ai else None
        rate_limiter = AdaptiveRateLimiter(default_rps=self.config.scan.requests_per_second)

        auth = AuthHandler()
        if auth_token or auth_cookies:
            auth.setup(token=auth_token, cookies=auth_cookies)

        checkpoint = CheckpointManager(workspace, f"scan_{int(time.time())}")

        # Check for resume
        if resume:
            cp = checkpoint.load(target)
            if cp:
                logger.info(f"Resuming from phase {cp.current_phase}: {cp.completed_phases}")

        clawteam = ClawTeamManager(
            config=ClawTeamConfig(
                enabled=self.config.docker.advanced_tools_enabled,
                api_url=self.config.docker.advanced_tools_url,
            ),
            workspace=workspace,
        )
        if self.config.docker.advanced_tools_enabled:
            await clawteam.initialize()

        knowledge = KnowledgeBase(db_path=DATA_DIR / "knowledge.db")
        learner = ContinuousLearner()
        plugins = PluginManager(workspace / "plugins")
        plugins.discover()
        plugins.load_all()

        notifier = NotificationDispatcher(
            discord_webhook=self.config.notification.discord_webhook,
            slack_webhook=self.config.notification.slack_webhook,
            telegram_token=self.config.notification.telegram_bot_token,
            telegram_chat_id=self.config.notification.telegram_chat_id,
        )

        # ─── Phase 2: Scope ───────────────────────────────────
        logger.info(f"Phase 2: Scope for {target}")
        scope = ProgramScope(program_name=target)
        scope.add_domain(target)
        scope.add_domain(f"*.{target}")
        if exclude_domains:
            for ex in exclude_domains:
                scope.add_domain(ex, include=False)
        scope_enforcer = ScopeEnforcer(scope)

        # ─── Phase 3-9: Scanning pipeline ─────────────────────
        logger.info("Phases 3-9: Scanning pipeline")
        scanner = ScannerAgent(
            health_report=health,
            workspace=workspace,
            auth=auth if auth.is_configured else None,
            rate_limiter=rate_limiter,
            timeout=self.config.scan.timeout_per_tool,
            max_concurrent=min(
                self.config.scan.max_concurrent_scans,
                maestro.recommended_concurrency,
            ),
        )

        ctx = await scanner.run_pipeline(target, mode)

        result.subdomains_found = len(ctx.subdomains)
        result.live_hosts_found = len(ctx.live_hosts)
        result.urls_discovered = len(ctx.urls)
        result.tools_used = list(set(f.tool for f in ctx.all_findings if f.tool))

        # Save checkpoint after scanning
        checkpoint.save(
            target=target, mode=mode,
            phase=9, phase_name="scanning_complete",
            subdomains=ctx.subdomains,
            live_hosts=ctx.live_hosts,
            urls=ctx.urls,
            findings_count=len(ctx.all_findings),
        )

        # ─── Phase 10: Shuvon scanners ────────────────────────
        logger.info("Phase 10: Shuvon vulnerability scanners")
        shuvon = ShuvonScannerSuite(max_concurrent=3)
        auth_headers = auth.get_headers() if auth.is_configured else None

        shuvon_results = await shuvon.run_all(
            urls=ctx.urls,
            auth_headers=auth_headers,
        )
        shuvon_dicts = ShuvonScannerSuite.findings_to_dicts(shuvon_results)

        # Merge Shuvon findings into main findings
        for sd in shuvon_dicts:
            ctx.all_findings.append(Finding(**{
                k: v for k, v in sd.items() if k in Finding.__dataclass_fields__
            }))

        # ─── Phase 11: Plugin scanners ────────────────────────
        plugin_findings = await plugins.run_hook("scanner", {
            "target": target, "urls": ctx.urls,
            "live_hosts": ctx.live_hosts, "mode": mode,
        })

        # ─── Phase 12: Deep scan (advanced tools) ─────────────
        if mode == "deep" and clawteam.is_available:
            logger.info("Phase 12: Deep scan (advanced tools container)")
            deep_findings = await self._run_deep_scan(
                clawteam, target, ctx, scanner
            )
            ctx.all_findings.extend(deep_findings)

        result.total_findings = len(ctx.all_findings)

        # ─── Phase 13: Dual Validation ────────────────────────
        all_finding_dicts = [f.to_dict() for f in ctx.all_findings]
        validated_dicts = all_finding_dicts
        validation_stats = {}

        if not no_ai and ai_engine:
            logger.info("Phase 13: Dual Validation (4-gate)")
            validator = OmegaDualValidator(
                scope_enforcer=scope_enforcer,
                ai_engine=ai_engine,
                enable_retest=mode == "deep",
            )
            validated_dicts, stats = await validator.validate_all(all_finding_dicts)
            validation_stats = validator.get_stats_dict()
            result.validated_findings = stats.passed
            result.false_positives = stats.failed
            result.validation_stats = validation_stats
        else:
            result.validated_findings = len(all_finding_dicts)

        # ─── Phase 14: CVSS scoring (AI) ──────────────────────
        if not no_ai and ai_engine:
            logger.info("Phase 14: AI CVSS scoring")
            researcher = ResearcherAgent(ai_engine)
            for f in validated_dicts:
                if f.get("severity") in ("medium", "high", "critical") and f.get("validated"):
                    scored = await researcher.score_cvss(
                        Finding(**{k: v for k, v in f.items() if k in Finding.__dataclass_fields__})
                    )
                    f["cvss_score"] = scored.cvss_score
                    f["cvss_vector"] = scored.cvss_vector

        # ─── Phase 15: Chain + Correlation analysis ───────────
        logger.info("Phase 15: Chain & Correlation analysis")

        # Graph chain engine (type-based)
        graph = GraphChainEngine()
        graph.build_graph(validated_dicts)
        type_chains = graph.find_chains()

        # Correlation engine (evidence-based)
        correlator = FindingCorrelator()
        correlator.ingest(validated_dicts, ctx.technologies)
        correlation_chains = correlator.correlate()

        # Combine both chain types
        all_chains = graph.get_chains_as_dicts() + correlator.get_chains_as_dicts()
        result.chains_found = len(type_chains)
        result.correlations_found = len(correlation_chains)

        # ─── Phase 16: Screenshots ────────────────────────────
        logger.info("Phase 16: Screenshot capture")
        screenshotter = ScreenshotCapture(workspace)
        if screenshotter.is_available:
            screenshot_map = await screenshotter.capture_findings(
                validated_dicts, max_screenshots=15
            )
            result.screenshots_captured = len(screenshot_map)
            # Attach screenshot paths to findings
            for fid, path in screenshot_map.items():
                for f in validated_dicts:
                    if f.get("id") == fid:
                        f.setdefault("metadata", {})["screenshot"] = path

        # ─── Phase 17: PoC generation ─────────────────────────
        logger.info("Phase 17: PoC generation")
        poc_gen = PoCGenerator(output_dir=workspace / "pocs")
        pocs = poc_gen.generate_all(validated_dicts)
        if pocs:
            poc_gen.save_pocs(pocs, target)
        result.pocs_generated = len(pocs)

        # ─── Phase 18: Report generation ──────────────────────
        logger.info("Phase 18: Report generation")
        reporter = ReporterAgent(
            ai_engine=ai_engine,
            output_dir=REPORTS_DIR,
        )
        scan_metadata = {
            "mode": mode, "duration_seconds": time.time() - start,
            "tools_used": result.tools_used,
            "subdomains": result.subdomains_found,
            "live_hosts": result.live_hosts_found,
            "urls": result.urls_discovered,
            "ai_enabled": not no_ai,
            "screenshots": result.screenshots_captured,
            "pocs": result.pocs_generated,
        }
        report_paths = await reporter.generate_report(
            target=target, findings=[
                Finding(**{k: v for k, v in f.items() if k in Finding.__dataclass_fields__})
                for f in validated_dicts if f.get("validated", True)
            ],
            chains=all_chains, scan_metadata=scan_metadata,
            format=report_format,
        )
        result.report_paths = report_paths

        # Diff report
        diff_reporter = DiffReporter(knowledge)
        diff = diff_reporter.compare(target, validated_dicts)
        if diff.has_changes:
            diff_md = diff_reporter.format_markdown(diff)
            diff_path = REPORTS_DIR / f"diff_{target.replace('.','_')}.md"
            diff_path.write_text(diff_md)
            result.report_paths["diff"] = str(diff_path)

        # ─── Phase 19: Knowledge update ───────────────────────
        logger.info("Phase 19: Knowledge base update & learning")
        knowledge.store_scan(target, mode, time.time()-start, validated_dicts, scan_metadata)
        for f in validated_dicts:
            learner.learn_from_finding(f)

        # ─── Phase 20: Notifications ──────────────────────────
        logger.info("Phase 20: Notifications")
        # Severity summary
        for f in validated_dicts:
            s = f.get("severity", "info")
            result.severity_summary[s] = result.severity_summary.get(s, 0) + 1

        if notifier.is_enabled:
            crit = result.severity_summary.get("critical", 0)
            high = result.severity_summary.get("high", 0)
            await notifier.notify(
                "scan_complete", "Scan Complete",
                f"Target: {target} | Valid: {result.validated_findings} | "
                f"Chains: {result.chains_found + result.correlations_found} | "
                f"Critical: {crit} | High: {high}",
                data=result.severity_summary,
            )
            if crit > 0:
                await notifier.notify(
                    "critical", f"{crit} Critical Findings!",
                    f"{crit} critical vulnerabilities on {target}",
                )

        # ─── Finalize ─────────────────────────────────────────
        await maestro.stop()
        result.end_time = datetime.now(timezone.utc).isoformat()
        result.duration_seconds = time.time() - start
        result.errors = [e.message for e in errors.errors[:10]]
        if ai_engine:
            result.ai_cost = ai_engine.cost_tracker.run_cost

        checkpoint.clear()  # Clean up on success
        self._print_summary(result)
        return result

    async def _run_deep_scan(
        self, clawteam: ClawTeamManager, target: str,
        ctx: Any, scanner: ScannerAgent,
    ) -> List[Finding]:
        """Execute deep scanning via advanced tools container."""
        findings: List[Finding] = []

        # Nmap deep scan
        logger.info("  Deep: nmap -sV -sC -O -T4")
        r = await clawteam.dispatch_advanced_tool(
            "nmap", ["-sV", "-sC", "-O", "-T4", target], timeout=600
        )
        if r and r.get("output"):
            findings.extend(scanner._parse_nmap(r["output"], target))

        # SQLMap on URLs with query parameters
        param_urls = [u for u in ctx.urls if "?" in u and "=" in u]
        for url in param_urls[:5]:
            logger.info(f"  Deep: sqlmap on {url[:60]}...")
            r = await clawteam.dispatch_advanced_tool(
                "sqlmap", ["--url", url, "--batch", "--level", "1"], timeout=120
            )

        # WPScan if WordPress detected
        for host, techs in ctx.technologies.items():
            if any("wordpress" in t.lower() for t in techs):
                logger.info(f"  Deep: wpscan on {host}")
                r = await clawteam.dispatch_advanced_tool(
                    "wpscan", ["--url", f"https://{host}", "--batch", "--format", "json"],
                    timeout=300,
                )
                if r and r.get("output"):
                    try:
                        wp_data = json.loads(r["output"])
                        for vuln in wp_data.get("vulnerabilities", []):
                            findings.append(Finding(
                                id=f"wpscan-{vuln.get('title','x')[:20]}",
                                tool="wpscan", target=host,
                                vulnerability_type=vuln.get("title", "WordPress Vulnerability"),
                                severity="high", confidence=0.8,
                                evidence=vuln.get("description", "")[:500],
                            ))
                    except json.JSONDecodeError:
                        pass
                break

        # Gitleaks
        r = await clawteam.dispatch_advanced_tool(
            "gitleaks", ["detect", "--source", ".", "--report-format", "json"],
            timeout=120,
        )
        if r and r.get("output"):
            try:
                secrets = json.loads(r["output"])
                if isinstance(secrets, list):
                    for s in secrets:
                        findings.append(Finding(
                            id=f"gitleaks-deep-{s.get('RuleID','x')}",
                            tool="gitleaks", target=target,
                            vulnerability_type="Exposed Secret/Credential",
                            severity="high", confidence=0.85,
                            evidence=f"Rule: {s.get('RuleID','')} File: {s.get('File','')}",
                        ))
            except json.JSONDecodeError:
                pass

        logger.info(f"  Deep scan: {len(findings)} additional findings")
        return findings

    def _print_summary(self, r: ScanResult) -> None:
        dur = r.duration_seconds / 60
        print(f"""
╔══════════════════════════════════════════════════════════╗
║                GetNexova Scan Summary                    ║
╠══════════════════════════════════════════════════════════╣
║  Target:       {r.target:<42s}║
║  Mode:         {r.mode:<42s}║
║  Duration:     {dur:.1f} min{' '*(36-len(f'{dur:.1f} min'))}║
╠──────────────────────────────────────────────────────────╣
║  Subdomains:   {r.subdomains_found:<42d}║
║  Live hosts:   {r.live_hosts_found:<42d}║
║  URLs:         {r.urls_discovered:<42d}║
╠──────────────────────────────────────────────────────────╣
║  Findings:     {r.total_findings:<42d}║
║  Validated:    {r.validated_findings:<42d}║
║  False pos:    {r.false_positives:<42d}║
║  Chains:       {r.chains_found:<42d}║
║  Correlations: {r.correlations_found:<42d}║
║  Screenshots:  {r.screenshots_captured:<42d}║
║  PoCs:         {r.pocs_generated:<42d}║
╠──────────────────────────────────────────────────────────╣""")
        for sev in ["critical","high","medium","low","info"]:
            c = r.severity_summary.get(sev, 0)
            if c:
                icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
                print(f"║  {icons.get(sev,' ')} {sev.upper():<16s} {c:<40d}║")
        print(f"""╠──────────────────────────────────────────────────────────╣
║  AI Cost:      ${r.ai_cost:<41.4f}║
╠──────────────────────────────────────────────────────────╣""")
        for fmt, path in r.report_paths.items():
            p = path if len(path) < 50 else "..." + path[-47:]
            print(f"║  📄 {fmt.upper():<8s} {p:<47s}║")
        print(f"╚══════════════════════════════════════════════════════════╝")
