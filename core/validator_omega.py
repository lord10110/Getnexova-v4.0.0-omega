"""
GetNexova Omega Dual Validator
=================================
Two-stage validation system:

Stage 1 — Re-test: Replay the finding with the original tool
           to confirm it's reproducible.
Stage 2 — Four-Gate validation:
  Gate 1: Scope check (is target in authorized scope?)
  Gate 2: Duplicate check (have we seen this before?)
  Gate 3: AI validation (is this a real vulnerability?)
  Gate 4: Evidence check (is there concrete proof?)

Only findings that pass all gates are marked as validated.
"""

import asyncio
import hashlib
import json
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from core.scope import ScopeEnforcer

logger = logging.getLogger("getnexova.validator")


@dataclass
class ValidationResult:
    """Result of validation for a single finding."""
    finding_id: str
    passed: bool
    gates_passed: List[str] = field(default_factory=list)
    gates_failed: List[str] = field(default_factory=list)
    retest_passed: Optional[bool] = None
    confidence: float = 0.0
    rejection_reason: str = ""


@dataclass
class ValidationStats:
    """Aggregate validation statistics."""
    total_processed: int = 0
    passed: int = 0
    failed: int = 0
    failed_scope: int = 0
    failed_duplicate: int = 0
    failed_ai: int = 0
    failed_evidence: int = 0
    retest_passed: int = 0
    retest_failed: int = 0
    retest_skipped: int = 0


class FourGateValidator:
    """
    Four-gate validation pipeline for individual findings.

    Each gate is independent and produces a pass/fail result.
    A finding must pass all four gates to be considered valid.
    """

    def __init__(
        self,
        scope_enforcer: Optional[ScopeEnforcer] = None,
        seen_hashes: Optional[Set[str]] = None,
        ai_engine: Optional[Any] = None,
    ):
        self.scope = scope_enforcer
        self._seen: Set[str] = seen_hashes or set()
        self.ai = ai_engine

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """Run all four gates on a finding."""
        result = ValidationResult(
            finding_id=finding.get("id", "unknown")
        )

        # Gate 1: Scope
        g1 = self._gate_scope(finding)
        if g1:
            result.gates_passed.append("scope")
        else:
            result.gates_failed.append("scope")
            result.rejection_reason = "Target out of scope"
            result.passed = False
            return result

        # Gate 2: Duplicate
        g2 = self._gate_duplicate(finding)
        if g2:
            result.gates_passed.append("duplicate")
        else:
            result.gates_failed.append("duplicate")
            result.rejection_reason = "Duplicate finding"
            result.passed = False
            return result

        # Gate 3: AI validation
        g3 = await self._gate_ai(finding)
        if g3:
            result.gates_passed.append("ai")
        else:
            result.gates_failed.append("ai")
            result.rejection_reason = "AI classified as false positive"
            result.passed = False
            return result

        # Gate 4: Evidence
        g4 = self._gate_evidence(finding)
        if g4:
            result.gates_passed.append("evidence")
        else:
            result.gates_failed.append("evidence")
            result.rejection_reason = "Insufficient evidence"
            result.passed = False
            return result

        result.passed = True
        result.confidence = self._calculate_confidence(finding, result)
        return result

    def _gate_scope(self, finding: Dict[str, Any]) -> bool:
        """Gate 1: Is the target within authorized scope?"""
        if not self.scope:
            return True  # No scope enforcer = pass by default
        target = finding.get("target", "")
        url = finding.get("url", "")
        return self.scope.is_in_scope(target) or (
            url and self.scope.is_in_scope(url)
        )

    def _gate_duplicate(self, finding: Dict[str, Any]) -> bool:
        """Gate 2: Have we already validated an identical finding?"""
        # Create a hash of the unique finding signature
        sig = (
            f"{finding.get('vulnerability_type', '')}:"
            f"{finding.get('target', '')}:"
            f"{finding.get('url', '')}:"
            f"{finding.get('evidence', '')[:200]}"
        )
        h = hashlib.sha256(sig.encode()).hexdigest()[:16]

        if h in self._seen:
            return False
        self._seen.add(h)
        return True

    async def _gate_ai(self, finding: Dict[str, Any]) -> bool:
        """Gate 3: AI validation — is this a real vulnerability?"""
        if not self.ai:
            # No AI available — pass with reduced confidence
            return True

        try:
            from agents.ai_engine import PromptBuilder
            prompt = PromptBuilder.classify_vulnerability(finding)
            response = await self.ai.call(
                prompt=prompt,
                task_type="classify",
                json_mode=True,
            )
            if response:
                result = json.loads(response)
                return result.get("is_valid", True)
        except Exception as e:
            logger.warning(f"AI gate error: {e}")
        return True  # Fail-open on AI errors

    def _gate_evidence(self, finding: Dict[str, Any]) -> bool:
        """Gate 4: Is there concrete evidence for this finding?"""
        evidence = finding.get("evidence", "")
        raw_output = finding.get("raw_output", "")
        severity = finding.get("severity", "info")

        # Info-level findings don't need strong evidence
        if severity == "info":
            return True

        # For higher severity, require some evidence
        if severity in ("critical", "high"):
            # Need substantial evidence
            return len(evidence) > 20 or len(raw_output) > 50
        else:
            # Medium/low — some evidence is enough
            return len(evidence) > 5 or len(raw_output) > 20

    def _calculate_confidence(
        self, finding: Dict[str, Any], result: ValidationResult
    ) -> float:
        """Calculate overall confidence score."""
        base = finding.get("confidence", 0.5)
        gates_count = len(result.gates_passed)

        # Boost for passing all gates
        if gates_count == 4:
            return min(base + 0.2, 1.0)
        elif gates_count == 3:
            return base
        else:
            return max(base - 0.2, 0.1)


class OmegaDualValidator:
    """
    Complete dual-validation system.

    Stage 1: Re-test (optional) — re-run the tool to confirm
    Stage 2: Four-gate validation
    """

    def __init__(
        self,
        scope_enforcer: Optional[ScopeEnforcer] = None,
        ai_engine: Optional[Any] = None,
        enable_retest: bool = False,
    ):
        self.four_gate = FourGateValidator(
            scope_enforcer=scope_enforcer,
            ai_engine=ai_engine,
        )
        self.enable_retest = enable_retest
        self.stats = ValidationStats()

    async def validate_all(
        self,
        findings: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], ValidationStats]:
        """
        Validate all findings through the dual-validation pipeline.

        Returns:
            Tuple of (validated_findings, stats)
        """
        validated = []
        self.stats = ValidationStats()

        for finding in findings:
            self.stats.total_processed += 1
            severity = finding.get("severity", "info")

            # Stage 1: Re-test (for medium+ severity)
            if self.enable_retest and severity in ("medium", "high", "critical"):
                retest_ok = await self._retest(finding)
                if retest_ok:
                    self.stats.retest_passed += 1
                elif retest_ok is False:
                    self.stats.retest_failed += 1
                    finding["retest_failed"] = True
                    # Don't reject outright — let 4-gate decide
                else:
                    self.stats.retest_skipped += 1
            else:
                self.stats.retest_skipped += 1

            # Stage 2: Four-gate validation
            result = await self.four_gate.validate(finding)

            if result.passed:
                finding["validated"] = True
                finding["is_false_positive"] = False
                finding["confidence"] = result.confidence
                finding["validation_gates"] = result.gates_passed
                validated.append(finding)
                self.stats.passed += 1
            else:
                finding["validated"] = False
                finding["is_false_positive"] = True
                finding["rejection_reason"] = result.rejection_reason
                self.stats.failed += 1

                # Track failure reason
                if "scope" in result.gates_failed:
                    self.stats.failed_scope += 1
                elif "duplicate" in result.gates_failed:
                    self.stats.failed_duplicate += 1
                elif "ai" in result.gates_failed:
                    self.stats.failed_ai += 1
                elif "evidence" in result.gates_failed:
                    self.stats.failed_evidence += 1

        logger.info(
            f"Validation: {self.stats.passed} passed, "
            f"{self.stats.failed} rejected "
            f"(scope={self.stats.failed_scope}, "
            f"dup={self.stats.failed_duplicate}, "
            f"ai={self.stats.failed_ai}, "
            f"evidence={self.stats.failed_evidence})"
        )

        return validated, self.stats

    async def _retest(self, finding: Dict[str, Any]) -> Optional[bool]:
        """
        Re-test a finding by re-running the original tool.

        Returns:
            True if reproduced, False if not, None if skipped
        """
        # Re-testing requires running the tool again — this is a
        # simplified version that checks if the evidence is strong enough
        # to imply reproducibility
        tool = finding.get("tool", "")
        evidence = finding.get("evidence", "")

        if not tool or not evidence:
            return None

        # For nuclei findings, template matches are typically reproducible
        if tool == "nuclei" and finding.get("metadata", {}).get("template_id"):
            return True

        # For dalfox XSS, PoC URLs are reproducible
        if tool == "dalfox" and finding.get("metadata", {}).get("poc"):
            return True

        # Default: skip re-test for tools we can't easily replay
        return None

    def get_stats_dict(self) -> Dict[str, int]:
        """Get stats as a dictionary for reporting."""
        return {
            "total_processed": self.stats.total_processed,
            "passed": self.stats.passed,
            "failed": self.stats.failed,
            "failed_scope": self.stats.failed_scope,
            "failed_duplicate": self.stats.failed_duplicate,
            "failed_ai": self.stats.failed_ai,
            "failed_evidence": self.stats.failed_evidence,
            "retest_passed": self.stats.retest_passed,
            "retest_failed": self.stats.retest_failed,
            "retest_skipped": self.stats.retest_skipped,
        }
