"""
GetNexova Complete Test Suite
================================
Tests for ALL modules: core, agents, scanners, integrations, reports, skills.
Run with: pytest tests/ -v
"""

import json
import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import asdict


# ═══════════════════════════════════════════════════════════
# CORE TESTS
# ═══════════════════════════════════════════════════════════

class TestConfig:
    def test_default_config(self):
        from core.config import GetNexovaConfig
        config = GetNexovaConfig()
        assert config.scan.mode == "standard"
        assert config.llm.max_cost_per_run == 5.0
        assert len(config.llm.free_models) >= 2

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("NEXOVA_MODE", "deep")
        monkeypatch.setenv("MAX_COST_PER_RUN", "10.0")
        from core.config import GetNexovaConfig
        config = GetNexovaConfig()
        assert config.scan.mode == "deep"
        assert config.llm.max_cost_per_run == 10.0

    def test_config_to_dict(self):
        from core.config import GetNexovaConfig
        config = GetNexovaConfig()
        d = config.to_dict()
        assert "llm" in d
        assert "scan" in d
        assert "docker" in d


class TestErrors:
    def test_error_hierarchy(self):
        from core.errors import (
            GetNexovaError, CriticalError, RecoverableError,
            RateLimitError, ToolError, ScopeError, AIError,
        )
        assert issubclass(CriticalError, GetNexovaError)
        assert issubclass(RecoverableError, GetNexovaError)
        assert issubclass(RateLimitError, RecoverableError)
        assert issubclass(ToolError, RecoverableError)
        assert issubclass(ScopeError, CriticalError)

    def test_critical_not_recoverable(self):
        from core.errors import CriticalError
        e = CriticalError("fatal")
        assert e.recoverable is False

    def test_recoverable_is_recoverable(self):
        from core.errors import RecoverableError
        e = RecoverableError("retry")
        assert e.recoverable is True

    def test_error_aggregator(self):
        from core.errors import ErrorAggregator, ToolError, RateLimitError
        agg = ErrorAggregator()
        agg.record(ToolError("nmap failed"), phase="scanning", tool="nmap")
        agg.record(RateLimitError("429"), phase="scanning", tool="httpx")
        summary = agg.get_summary()
        assert summary["total_errors"] == 2
        assert "scanning" in summary["by_phase"]

    def test_aggregator_suppresses_duplicates(self):
        from core.errors import ErrorAggregator, ToolError
        agg = ErrorAggregator()
        for _ in range(10):
            agg.record(ToolError("same error"), phase="scan", tool="x")
        assert agg.get_summary()["total_errors"] == 1
        assert agg.get_summary()["suppressed_duplicates"] == 9

    def test_error_hints(self):
        from core.errors import ErrorAggregator, RateLimitError
        agg = ErrorAggregator()
        agg.record(RateLimitError("429"), phase="scan", tool="api")
        hints = agg.get_hints()
        assert len(hints) > 0

    def test_safe_async_decorator(self):
        from core.errors import safe_async, get_error_aggregator, reset_error_aggregator
        reset_error_aggregator()

        @safe_async(phase="test", tool="test_tool")
        async def failing_func():
            raise ValueError("test error")

        asyncio.get_event_loop().run_until_complete(failing_func())
        assert get_error_aggregator().get_summary()["total_errors"] == 1


class TestScopeEnforcer:
    def test_domain_in_scope(self):
        from core.scope import ScopeEnforcer, ProgramScope
        scope = ProgramScope(program_name="test")
        scope.add_domain("example.com")
        scope.add_domain("*.example.com")
        enforcer = ScopeEnforcer(scope)
        assert enforcer.is_in_scope("example.com")
        assert enforcer.is_in_scope("sub.example.com")
        assert not enforcer.is_in_scope("other.com")

    def test_domain_excluded(self):
        from core.scope import ScopeEnforcer, ProgramScope
        scope = ProgramScope(program_name="test")
        scope.add_domain("*.example.com")
        scope.add_domain("staging.example.com", include=False)
        enforcer = ScopeEnforcer(scope)
        assert enforcer.is_in_scope("app.example.com")
        assert not enforcer.is_in_scope("staging.example.com")

    def test_url_scope(self):
        from core.scope import ScopeEnforcer, ProgramScope
        scope = ProgramScope(program_name="test")
        scope.add_domain("example.com")
        enforcer = ScopeEnforcer(scope)
        assert enforcer.is_in_scope("https://example.com/path")
        assert not enforcer.is_in_scope("https://other.com/path")

    def test_validate_targets(self):
        from core.scope import ScopeEnforcer, ProgramScope
        scope = ProgramScope(program_name="test")
        scope.add_domain("*.example.com")
        enforcer = ScopeEnforcer(scope)
        valid, invalid = enforcer.validate_targets([
            "app.example.com", "api.example.com", "evil.com",
        ])
        assert len(valid) == 2
        assert len(invalid) == 1


class TestCostTracker:
    def test_record_call(self):
        from core.cost_tracker import CostTracker
        with tempfile.TemporaryDirectory() as d:
            t = CostTracker(cost_file=Path(d) / "cost.jsonl")
            t.record_call("groq/llama", 100, 50, 0.001, "classify", True, 500)
            assert t.run_cost == 0.001

    def test_budget_enforcement(self):
        from core.cost_tracker import CostTracker
        with tempfile.TemporaryDirectory() as d:
            t = CostTracker(max_cost_per_run=0.01, cost_file=Path(d) / "c.jsonl")
            t.record_call("x", 0, 0, 0.009, "t", True, 0)
            assert t.can_afford(0.001)
            assert not t.can_afford(0.01)


class TestRateLimiter:
    def test_creation(self):
        from core.rate_limiter import AdaptiveRateLimiter
        rl = AdaptiveRateLimiter(default_rps=5.0, max_concurrent=10)
        assert rl.default_rps == 5.0

    def test_report_error_reduces_rps(self):
        from core.rate_limiter import AdaptiveRateLimiter
        rl = AdaptiveRateLimiter(default_rps=5.0)
        initial = rl._domains["test.com"].current_rps
        rl.report_error("test.com", status_code=429)
        assert rl._domains["test.com"].current_rps < initial

    def test_report_success(self):
        from core.rate_limiter import AdaptiveRateLimiter
        rl = AdaptiveRateLimiter()
        rl.report_success("test.com")
        assert rl._domains["test.com"].consecutive_errors == 0

    def test_stats(self):
        from core.rate_limiter import AdaptiveRateLimiter
        rl = AdaptiveRateLimiter()
        rl.report_success("a.com")
        stats = rl.get_stats()
        assert "a.com" in stats


class TestAuthHandler:
    def test_not_configured_by_default(self):
        from core.auth_handler import AuthHandler
        auth = AuthHandler()
        assert not auth.is_configured
        assert not auth.is_authenticated

    def test_token_auth(self):
        from core.auth_handler import AuthHandler
        auth = AuthHandler()
        auth.setup(token="mytoken123")
        assert auth.is_configured
        assert auth.is_authenticated
        headers = auth.get_headers()
        assert "Authorization" in headers
        assert "mytoken123" in headers["Authorization"]

    def test_cookie_auth(self):
        from core.auth_handler import AuthHandler
        auth = AuthHandler()
        auth.setup(cookies="session=abc; csrf=xyz")
        assert auth.is_authenticated
        cookie_str = auth.get_cookie_string()
        assert "session=abc" in cookie_str

    def test_inject_into_nuclei(self):
        from core.auth_handler import AuthHandler
        auth = AuthHandler()
        auth.setup(cookies="sess=123")
        cmd = ["nuclei", "-u", "target.com"]
        new_cmd = auth.inject_into_command(cmd, "nuclei")
        assert "-H" in new_cmd
        assert any("Cookie" in a for a in new_cmd)

    def test_inject_into_dalfox(self):
        from core.auth_handler import AuthHandler
        auth = AuthHandler()
        auth.setup(cookies="sess=123")
        cmd = ["dalfox", "url", "target.com"]
        new_cmd = auth.inject_into_command(cmd, "dalfox")
        assert "--cookie" in new_cmd

    def test_summary_redacted(self):
        from core.auth_handler import AuthHandler
        auth = AuthHandler()
        auth.setup(token="secret_token")
        summary = auth.get_summary()
        assert summary["method"] == "token"
        assert "secret_token" not in str(summary)


class TestCheckpointManager:
    def test_save_and_load(self):
        from core.checkpoint import CheckpointManager
        with tempfile.TemporaryDirectory() as d:
            cp = CheckpointManager(Path(d), "test_session")
            cp.save("example.com", "standard", 5, "nuclei_scan",
                    subdomains=["a.example.com", "b.example.com"])
            loaded = cp.load("example.com")
            assert loaded is not None
            assert loaded.target == "example.com"
            assert len(loaded.subdomains) == 2
            assert "nuclei_scan" in loaded.completed_phases

    def test_should_skip_phase(self):
        from core.checkpoint import CheckpointManager
        with tempfile.TemporaryDirectory() as d:
            cp = CheckpointManager(Path(d), "test_session")
            cp.save("example.com", "standard", 3, "http_probe")
            assert cp.should_skip_phase("http_probe")
            assert not cp.should_skip_phase("nuclei_scan")

    def test_clear(self):
        from core.checkpoint import CheckpointManager
        with tempfile.TemporaryDirectory() as d:
            cp = CheckpointManager(Path(d), "test_session")
            cp.save("example.com", "standard", 1, "init")
            cp.clear()
            assert cp.load("example.com") is None


class TestValidatorOmega:
    def test_four_gate_scope_check(self):
        from core.validator_omega import FourGateValidator
        from core.scope import ScopeEnforcer, ProgramScope
        scope = ProgramScope(program_name="test")
        scope.add_domain("*.example.com")
        enforcer = ScopeEnforcer(scope)
        validator = FourGateValidator(scope_enforcer=enforcer)

        result = asyncio.get_event_loop().run_until_complete(
            validator.validate({"id": "1", "target": "app.example.com",
                                "vulnerability_type": "XSS", "severity": "medium",
                                "evidence": "reflected input"})
        )
        assert result.passed
        assert "scope" in result.gates_passed

    def test_four_gate_out_of_scope(self):
        from core.validator_omega import FourGateValidator
        from core.scope import ScopeEnforcer, ProgramScope
        scope = ProgramScope(program_name="test")
        scope.add_domain("example.com")
        enforcer = ScopeEnforcer(scope)
        validator = FourGateValidator(scope_enforcer=enforcer)

        result = asyncio.get_event_loop().run_until_complete(
            validator.validate({"id": "2", "target": "evil.com",
                                "vulnerability_type": "XSS", "severity": "high",
                                "evidence": "test"})
        )
        assert not result.passed
        assert "scope" in result.gates_failed

    def test_duplicate_detection(self):
        from core.validator_omega import FourGateValidator
        validator = FourGateValidator()
        finding = {"id": "1", "target": "a.com", "url": "",
                   "vulnerability_type": "XSS", "severity": "medium",
                   "evidence": "test123"}
        r1 = asyncio.get_event_loop().run_until_complete(validator.validate(finding))
        r2 = asyncio.get_event_loop().run_until_complete(validator.validate(finding))
        assert r1.passed
        assert not r2.passed
        assert "duplicate" in r2.gates_failed

    def test_evidence_gate(self):
        from core.validator_omega import FourGateValidator
        validator = FourGateValidator()
        # High severity with no evidence should fail
        result = asyncio.get_event_loop().run_until_complete(
            validator.validate({"id": "x", "target": "a.com", "url": "",
                                "vulnerability_type": "SQLi", "severity": "high",
                                "evidence": "", "raw_output": ""})
        )
        assert not result.passed
        assert "evidence" in result.gates_failed

    def test_omega_dual_validator_stats(self):
        from core.validator_omega import OmegaDualValidator
        validator = OmegaDualValidator()
        findings = [
            {"id": "1", "target": "a.com", "url": "", "vulnerability_type": "XSS",
             "severity": "medium", "evidence": "reflected parameter confirmed"},
            {"id": "2", "target": "a.com", "url": "", "vulnerability_type": "Info",
             "severity": "info", "evidence": ""},
        ]
        validated, stats = asyncio.get_event_loop().run_until_complete(
            validator.validate_all(findings)
        )
        assert stats.total_processed == 2
        assert stats.passed + stats.failed == 2


class TestPluginManager:
    def test_discover_empty(self):
        from core.plugin_manager import PluginManager
        with tempfile.TemporaryDirectory() as d:
            pm = PluginManager(Path(d))
            assert pm.discover() == 0

    def test_summary(self):
        from core.plugin_manager import PluginManager
        with tempfile.TemporaryDirectory() as d:
            pm = PluginManager(Path(d))
            summary = pm.get_summary()
            assert summary["discovered"] == 0
            assert summary["loaded"] == 0

    def test_discover_plugin(self):
        from core.plugin_manager import PluginManager
        with tempfile.TemporaryDirectory() as d:
            plugin_dir = Path(d) / "test_plugin"
            plugin_dir.mkdir()
            (plugin_dir / "plugin.json").write_text(json.dumps({
                "name": "test_plugin", "version": "1.0",
                "hook": "scanner", "entry_point": "scanner.py"
            }))
            (plugin_dir / "scanner.py").write_text("def run(ctx): return []")
            pm = PluginManager(Path(d))
            assert pm.discover() == 1
            assert pm.load_all() == 1


class TestMaestro:
    def test_snapshot(self):
        from core.maestro import MaestroResourceManager
        m = MaestroResourceManager()
        state = m.snapshot()
        # Should return a state object even without psutil
        assert hasattr(state, "cpu_percent")
        assert hasattr(state, "ram_percent")

    def test_recommended_concurrency(self):
        from core.maestro import MaestroResourceManager, MaestroConfig
        config = MaestroConfig(max_concurrent_default=5)
        m = MaestroResourceManager(config)
        assert m.recommended_concurrency == 5

    def test_alerts_empty(self):
        from core.maestro import MaestroResourceManager
        m = MaestroResourceManager()
        assert m.alerts == []

    def test_summary(self):
        from core.maestro import MaestroResourceManager
        m = MaestroResourceManager()
        s = m.get_summary()
        assert "current_state" in s
        assert "recommended_concurrency" in s


class TestParallelExecutor:
    def test_run_all(self):
        from core.parallel_executor import ParallelExecutor
        pe = ParallelExecutor(max_workers=2)

        async def task1(): return "a"
        async def task2(): return "b"

        results = asyncio.get_event_loop().run_until_complete(
            pe.run_all([task1, task2], "test")
        )
        assert results == ["a", "b"]

    def test_handles_failures(self):
        from core.parallel_executor import ParallelExecutor
        pe = ParallelExecutor()

        async def good(): return "ok"
        async def bad(): raise ValueError("fail")

        results = asyncio.get_event_loop().run_until_complete(
            pe.run_all([good, bad], "test")
        )
        assert results[0] == "ok"
        assert results[1] is None
        assert pe.get_stats()["failed"] == 1


class TestScreenshots:
    def test_no_tool_available(self):
        from core.screenshots import ScreenshotCapture
        with tempfile.TemporaryDirectory() as d:
            sc = ScreenshotCapture(Path(d))
            # May or may not have gowitness/chrome
            summary = sc.get_summary()
            assert "tool" in summary
            assert "captured" in summary


class TestCorrelator:
    def test_ingest_findings(self):
        from core.correlator import FindingCorrelator
        c = FindingCorrelator()
        c.ingest([
            {"id": "1", "target": "https://a.example.com/admin",
             "vulnerability_type": "Exposed Credentials", "severity": "high"},
            {"id": "2", "target": "https://a.example.com/dashboard",
             "vulnerability_type": "Admin Dashboard", "severity": "medium"},
        ])
        chains = c.correlate()
        # Should find credential→access correlation on same host
        assert isinstance(chains, list)

    def test_same_host_correlation(self):
        from core.correlator import FindingCorrelator
        c = FindingCorrelator()
        c.ingest([
            {"id": "1", "target": "https://app.test.com",
             "vulnerability_type": "Open Port: 8080/tcp (http)",
             "severity": "info", "metadata": {"port": 8080}},
            {"id": "2", "target": "https://app.test.com:8080/admin",
             "vulnerability_type": "Admin Panel Exposed",
             "severity": "high"},
        ])
        chains = c.correlate()
        assert isinstance(chains, list)

    def test_header_amplification(self):
        from core.correlator import FindingCorrelator
        c = FindingCorrelator()
        c.ingest([
            {"id": "1", "target": "https://app.test.com",
             "vulnerability_type": "Missing CSP Header", "severity": "medium"},
            {"id": "2", "target": "https://app.test.com/search",
             "vulnerability_type": "Reflected XSS", "severity": "medium"},
        ])
        chains = c.correlate()
        # Missing CSP should amplify XSS
        dicts = c.get_chains_as_dicts()
        assert isinstance(dicts, list)


class TestToolHealth:
    def test_health_report(self):
        from core.tool_health import HealthReport
        r = HealthReport()
        assert r.healthy
        assert r.summary() is not None

    def test_is_tool_available(self):
        from core.tool_health import is_tool_available
        result = is_tool_available("python3")
        assert isinstance(result, bool)


# ═══════════════════════════════════════════════════════════
# AGENT TESTS
# ═══════════════════════════════════════════════════════════

class TestAgentLoader:
    def test_load_existing(self):
        from agents.agent_loader import load_agent_def
        d = load_agent_def("planner")
        assert d.name in ("Planner", "planner")

    def test_load_missing(self):
        from agents.agent_loader import load_agent_def
        d = load_agent_def("nonexistent_xyz")
        assert d.name == "nonexistent_xyz"

    def test_get_all_agents(self):
        from agents.agent_loader import get_all_agents
        agents = get_all_agents()
        assert len(agents) >= 4


class TestPromptBuilders:
    def test_classify(self):
        from agents.ai_engine import PromptBuilder
        p = PromptBuilder.classify_vulnerability({
            "tool": "nuclei", "type": "XSS",
            "target": "example.com", "evidence": "reflected",
            "raw_output": "test",
        })
        assert "vulnerability" in p.lower()
        assert "JSON" in p

    def test_cvss(self):
        from agents.ai_engine import PromptBuilder
        p = PromptBuilder.score_cvss({
            "vulnerability_type": "SQLi", "target": "a.com", "evidence": "e"
        })
        assert "CVSS" in p

    def test_chain(self):
        from agents.ai_engine import PromptBuilder
        p = PromptBuilder.analyze_chain([
            {"severity": "medium", "vulnerability_type": "XSS",
             "target": "a.com", "evidence": "r"},
        ])
        assert "chain" in p.lower()


class TestGraphEngine:
    def test_build_graph(self):
        from agents.graph_engine import GraphChainEngine
        g = GraphChainEngine()
        edges = g.build_graph([
            {"id": "1", "vulnerability_type": "SSRF", "target": "a.com",
             "severity": "high", "cvss_score": 7.5},
            {"id": "2", "vulnerability_type": "Internal API Access",
             "target": "a.com", "severity": "high", "cvss_score": 8.0},
        ])
        assert isinstance(edges, int)

    def test_find_chains(self):
        from agents.graph_engine import GraphChainEngine
        g = GraphChainEngine()
        g.build_graph([
            {"id": "1", "vulnerability_type": "SSRF", "target": "a.com",
             "severity": "high", "cvss_score": 7.5},
            {"id": "2", "vulnerability_type": "Internal credential exposure",
             "target": "a.com", "severity": "critical", "cvss_score": 9.0},
        ])
        chains = g.find_chains()
        assert isinstance(chains, list)

    def test_empty_graph(self):
        from agents.graph_engine import GraphChainEngine
        g = GraphChainEngine()
        g.build_graph([])
        chains = g.find_chains()
        assert chains == []

    def test_summary(self):
        from agents.graph_engine import GraphChainEngine
        g = GraphChainEngine()
        g.build_graph([{"id": "1", "vulnerability_type": "XSS",
                        "target": "a.com", "severity": "medium"}])
        s = g.get_summary()
        assert s["nodes"] == 1


class TestScannerFinding:
    def test_finding_to_dict(self):
        from agents.scanner import Finding
        f = Finding(id="test-1", tool="nuclei", target="a.com",
                    vulnerability_type="XSS", severity="medium",
                    evidence="reflected input")
        d = f.to_dict()
        assert d["id"] == "test-1"
        assert d["severity"] == "medium"

    def test_pipeline_context_setup(self):
        from agents.scanner import PipelineContext
        with tempfile.TemporaryDirectory() as d:
            ctx = PipelineContext()
            ctx.setup("example.com", Path(d) / "workspace")
            assert ctx.target == "example.com"
            assert ctx.subdomain_file.endswith("subdomains.txt")
            assert Path(ctx.subdomain_file).parent.exists()


# ═══════════════════════════════════════════════════════════
# SCANNER TESTS
# ═══════════════════════════════════════════════════════════

class TestShuvonScanners:
    def test_idor_pattern_detection(self):
        from scanners.shuvon_scanners import IDORScanner
        scanner = IDORScanner()
        # Test that ID patterns are detected in URLs
        import re
        url = "https://api.test.com/users?id=1234"
        matched = False
        for pattern, _ in scanner._patterns:
            if re.search(pattern, url):
                matched = True
                break
        assert matched

    def test_oauth_pattern_detection(self):
        from scanners.shuvon_scanners import OAuthScanner
        scanner = OAuthScanner()
        url = "https://app.com/auth/callback?redirect_uri=https://app.com&response_type=token"
        is_oauth = any(p in url.lower() for p in scanner._oauth_patterns)
        assert is_oauth

    def test_race_pattern_detection(self):
        from scanners.shuvon_scanners import RaceScanner
        scanner = RaceScanner()
        url = "https://shop.com/api/redeem-coupon"
        matched = False
        for category, patterns in scanner._race_patterns.items():
            import re
            for pattern in patterns:
                if re.search(pattern, url.lower()):
                    matched = True
        assert matched

    def test_graphql_paths(self):
        from scanners.shuvon_scanners import GraphQLScanner
        scanner = GraphQLScanner()
        assert "/graphql" in scanner._paths
        assert "/api/graphql" in scanner._paths

    def test_ai_probe_patterns(self):
        from scanners.shuvon_scanners import AIProbeScanner
        scanner = AIProbeScanner()
        assert "git_exposure" in scanner._probes
        assert "env_exposure" in scanner._probes
        assert "wp_config" in scanner._probes

    def test_findings_to_dicts(self):
        from scanners.shuvon_scanners import ShuvonScannerSuite, ShuvonFinding
        results = {
            "idor": [ShuvonFinding(scanner="idor", vulnerability_type="IDOR",
                                    target="a.com", severity="high")],
        }
        dicts = ShuvonScannerSuite.findings_to_dicts(results)
        assert len(dicts) == 1
        assert dicts[0]["tool"] == "shuvon/idor"
        assert dicts[0]["severity"] == "high"


# ═══════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════

class TestClawTeam:
    def test_config_defaults(self):
        from integrations.clawteam import ClawTeamConfig
        c = ClawTeamConfig()
        assert not c.enabled
        assert c.default_timeout == 300

    def test_manager_not_available_when_disabled(self):
        from integrations.clawteam import ClawTeamManager, ClawTeamConfig
        m = ClawTeamManager(config=ClawTeamConfig(enabled=False))
        assert not m.is_available

    def test_dispatch_blocked_tool(self):
        from integrations.clawteam import ClawTeamManager, ClawTeamConfig
        m = ClawTeamManager(config=ClawTeamConfig(enabled=True))
        result = asyncio.get_event_loop().run_until_complete(
            m.dispatch_advanced_tool("rm", ["-rf", "/"], timeout=5)
        )
        assert result is None  # blocked tool

    def test_summary(self):
        from integrations.clawteam import ClawTeamManager
        m = ClawTeamManager()
        s = m.get_summary()
        assert "enabled" in s
        assert "stats" in s


class TestNotifications:
    def test_disabled_by_default(self):
        from integrations.notifications import NotificationDispatcher
        n = NotificationDispatcher()
        assert not n.is_enabled

    def test_enabled_with_discord(self):
        from integrations.notifications import NotificationDispatcher
        n = NotificationDispatcher(discord_webhook="https://discord.com/api/webhooks/test")
        assert n.is_enabled


class TestPlatforms:
    def test_supported_platforms(self):
        from integrations.platforms import PlatformManager
        pm = PlatformManager()
        platforms = pm.get_supported_platforms()
        assert "intigriti" in platforms
        assert "yeswehack" in platforms
        assert "hackerone" in platforms


class TestSubmissionPipeline:
    def test_prepare_submission(self):
        from integrations.submission_pipeline import SubmissionPipeline
        with tempfile.TemporaryDirectory() as d:
            sp = SubmissionPipeline(Path(d))
            sub = sp.prepare_submission({
                "id": "1", "vulnerability_type": "XSS",
                "severity": "high", "target": "app.test.com",
                "evidence": "reflected input", "cvss_score": 6.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "metadata": {"poc": "curl -v 'https://app.test.com/?q=<script>'"},
            }, platform="intigriti")
            assert "[HIGH]" in sub["title"]
            assert sub["platform"] == "intigriti"
            assert "Steps to Reproduce" in sub["description"]


# ═══════════════════════════════════════════════════════════
# REPORT TESTS
# ═══════════════════════════════════════════════════════════

class TestPoCGenerator:
    def test_generate_curl(self):
        from reports.poc_generator import PoCGenerator
        with tempfile.TemporaryDirectory() as d:
            pg = PoCGenerator(Path(d))
            pocs = pg.generate({
                "id": "1", "vulnerability_type": "XSS",
                "target": "app.com", "url": "https://app.com/search?q=test",
                "severity": "medium", "evidence": "reflected",
                "metadata": {},
            })
            assert "curl" in pocs
            assert "app.com" in pocs["curl"]

    def test_generate_python(self):
        from reports.poc_generator import PoCGenerator
        with tempfile.TemporaryDirectory() as d:
            pg = PoCGenerator(Path(d))
            pocs = pg.generate({
                "id": "1", "vulnerability_type": "IDOR",
                "target": "api.com", "url": "https://api.com/users?id=1",
                "severity": "high", "evidence": "different data",
                "metadata": {},
            })
            assert "python" in pocs
            assert "requests" in pocs["python"]

    def test_generate_all(self):
        from reports.poc_generator import PoCGenerator
        with tempfile.TemporaryDirectory() as d:
            pg = PoCGenerator(Path(d))
            results = pg.generate_all([
                {"id": "f1", "vulnerability_type": "XSS",
                 "target": "a.com", "url": "https://a.com", "severity": "medium",
                 "evidence": "x", "metadata": {}},
                {"id": "f2", "vulnerability_type": "SQLi",
                 "target": "b.com", "url": "https://b.com", "severity": "high",
                 "evidence": "y", "metadata": {}},
            ])
            assert len(results) == 2


class TestDiffReporter:
    def test_all_new(self):
        from reports.diff_report import DiffReporter
        dr = DiffReporter()
        diff = dr.compare("test.com", [
            {"vulnerability_type": "XSS", "target": "a.com", "url": "", "severity": "medium"},
        ])
        assert len(diff.new_findings) == 1
        assert len(diff.resolved_findings) == 0

    def test_resolved(self):
        from reports.diff_report import DiffReporter
        dr = DiffReporter()
        previous = [
            {"vulnerability_type": "XSS", "target": "a.com", "url": "", "severity": "medium"},
            {"vulnerability_type": "SQLi", "target": "b.com", "url": "", "severity": "high"},
        ]
        current = [
            {"vulnerability_type": "XSS", "target": "a.com", "url": "", "severity": "medium"},
        ]
        diff = dr.compare("test.com", current, previous)
        assert len(diff.resolved_findings) == 1
        assert len(diff.persistent_findings) == 1

    def test_markdown_output(self):
        from reports.diff_report import DiffReporter
        dr = DiffReporter()
        diff = dr.compare("test.com", [
            {"vulnerability_type": "XSS", "target": "a.com", "url": "", "severity": "high"},
        ])
        md = dr.format_markdown(diff)
        assert "New Findings" in md
        assert "test.com" in md


# ═══════════════════════════════════════════════════════════
# SKILL TESTS
# ═══════════════════════════════════════════════════════════

class TestContinuousLearner:
    def test_learn_valid_finding(self):
        from skills.continuous_learning.learner import ContinuousLearner
        with tempfile.TemporaryDirectory() as d:
            l = ContinuousLearner(store_path=Path(d) / "l.jsonl")
            l.learn_from_finding({"tool": "nuclei", "vulnerability_type": "XSS",
                                  "severity": "high", "target": "a.com",
                                  "validated": True, "is_false_positive": False})
            assert "nuclei:XSS" in l._patterns

    def test_learn_false_positive(self):
        from skills.continuous_learning.learner import ContinuousLearner
        with tempfile.TemporaryDirectory() as d:
            l = ContinuousLearner(store_path=Path(d) / "l.jsonl")
            l.learn_from_finding({"tool": "nikto", "vulnerability_type": "Info",
                                  "target": "t.com", "validated": False,
                                  "is_false_positive": True})
            fp = l.is_likely_false_positive("nikto", "Info", "t.com")
            assert fp > 0


class TestStrategicCompactor:
    def test_no_compression(self):
        from skills.strategic_compact.compactor import StrategicCompactor
        c = StrategicCompactor(max_tokens=1000)
        assert c.compact("Short text") == "Short text"

    def test_compression(self):
        from skills.strategic_compact.compactor import StrategicCompactor
        c = StrategicCompactor(max_tokens=50)
        result = c.compact("A" * 5000)
        assert len(result) < 5000

    def test_compact_findings_priority(self):
        from skills.strategic_compact.compactor import StrategicCompactor
        c = StrategicCompactor()
        findings = [
            {"vulnerability_type": "XSS", "severity": "low", "target": "a.com",
             "evidence": "x" * 500, "tool": "t"},
            {"vulnerability_type": "RCE", "severity": "critical", "target": "a.com",
             "evidence": "y" * 500, "tool": "t"},
        ]
        result = c.compact_findings(findings)
        assert result[0]["severity"] == "critical"


# ═══════════════════════════════════════════════════════════
# KNOWLEDGE BASE TESTS
# ═══════════════════════════════════════════════════════════

class TestKnowledgeBase:
    def test_store_and_stats(self):
        from memory.knowledge_base import KnowledgeBase
        with tempfile.TemporaryDirectory() as d:
            kb = KnowledgeBase(db_path=Path(d) / "test.db")
            kb.store_scan("a.com", "standard", 60, [
                {"id": "1", "tool": "nuclei", "target": "a.com",
                 "vulnerability_type": "XSS", "severity": "high",
                 "confidence": 0.8, "cvss_score": 6.1, "cvss_vector": "",
                 "evidence": "test", "validated": True,
                 "is_false_positive": False, "metadata": {}},
            ], {"tools": ["nuclei"]})
            stats = kb.get_statistics()
            assert stats["total_scans"] == 1
            assert stats["total_findings"] == 1

    def test_target_history(self):
        from memory.knowledge_base import KnowledgeBase
        with tempfile.TemporaryDirectory() as d:
            kb = KnowledgeBase(db_path=Path(d) / "test.db")
            kb.store_scan("a.com", "standard", 60, [], {})
            kb.store_scan("a.com", "deep", 120, [], {})
            h = kb.get_target_history("a.com")
            assert h["scan_count"] == 2
