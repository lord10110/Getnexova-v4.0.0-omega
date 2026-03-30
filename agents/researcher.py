"""
GetNexova Researcher Agent
============================
Analyzes raw findings using AI to classify vulnerabilities,
score CVSS, identify attack chains, and filter false positives.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import asdict

from agents.agent_loader import load_agent_def
from agents.ai_engine import AIEngine, PromptBuilder
from agents.scanner import Finding

logger = logging.getLogger("getnexova.researcher")


class ResearcherAgent:
    """
    AI-powered vulnerability researcher.

    Analyzes raw scanner findings to:
    - Classify vulnerability types accurately
    - Score CVSS v3.1 vectors
    - Identify false positives
    - Discover attack chains between findings
    """

    def __init__(self, ai_engine: AIEngine):
        self.ai = ai_engine
        self.definition = load_agent_def("researcher")

    async def classify_finding(self, finding: Finding) -> Finding:
        """
        Use AI to classify and validate a single finding.

        Updates the finding with classification results.
        """
        finding_dict = {
            "tool": finding.tool,
            "type": finding.vulnerability_type,
            "target": finding.target,
            "evidence": finding.evidence,
            "raw_output": finding.raw_output,
        }

        prompt = PromptBuilder.classify_vulnerability(finding_dict)
        system_prompt = self.definition.soul or (
            "You are a precise vulnerability analyst. "
            "Minimize false positives while never missing true vulnerabilities. "
            "Respond only with valid JSON."
        )

        response = await self.ai.call(
            prompt=prompt,
            task_type="classify",
            system_prompt=system_prompt,
            json_mode=True,
        )

        if response:
            try:
                result = json.loads(response)
                finding.validated = result.get("is_valid", False)
                finding.is_false_positive = not finding.validated
                finding.confidence = result.get("confidence", finding.confidence)
                finding.vulnerability_type = result.get(
                    "vulnerability_type", finding.vulnerability_type
                )
                finding.severity = result.get("severity", finding.severity)
                finding.metadata["ai_reasoning"] = result.get("reasoning", "")
                finding.metadata["recommendations"] = result.get(
                    "recommendations", []
                )
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse classification response: {e}")

        return finding

    async def score_cvss(self, finding: Finding) -> Finding:
        """Calculate CVSS v3.1 score for a validated finding."""
        if not finding.validated:
            return finding

        finding_dict = {
            "vulnerability_type": finding.vulnerability_type,
            "target": finding.target,
            "evidence": finding.evidence,
            "context": finding.metadata.get("description", "web application"),
        }

        prompt = PromptBuilder.score_cvss(finding_dict)
        response = await self.ai.call(
            prompt=prompt,
            task_type="cvss",
            json_mode=True,
        )

        if response:
            try:
                result = json.loads(response)
                finding.cvss_score = float(result.get("cvss_score", 0.0))
                finding.cvss_vector = result.get("cvss_vector", "")
                finding.metadata["cvss_justification"] = result.get(
                    "metric_justification", {}
                )
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Failed to parse CVSS response: {e}")

        return finding

    async def analyze_chains(
        self, findings: List[Finding]
    ) -> List[Dict[str, Any]]:
        """
        Identify attack chains across multiple findings.

        Returns list of chain objects with combined severity.
        """
        # Only analyze validated, non-info findings
        relevant = [
            f for f in findings
            if f.validated and f.severity != "info"
        ]

        if len(relevant) < 2:
            logger.info("Not enough findings for chain analysis")
            return []

        findings_dicts = [
            {
                "severity": f.severity,
                "vulnerability_type": f.vulnerability_type,
                "target": f.target,
                "evidence": f.evidence[:200],
            }
            for f in relevant
        ]

        prompt = PromptBuilder.analyze_chain(findings_dicts)
        response = await self.ai.call(
            prompt=prompt,
            task_type="chain",
            json_mode=True,
        )

        if response:
            try:
                result = json.loads(response)
                chains = result.get("chains", [])
                logger.info(f"Identified {len(chains)} attack chains")
                return chains
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse chain response: {e}")

        return []

    async def analyze_all(
        self,
        findings: List[Finding],
        skip_info: bool = True,
    ) -> tuple:
        """
        Run full analysis pipeline on all findings.

        Args:
            findings: Raw findings from scanners
            skip_info: Skip AI analysis for info-level findings

        Returns:
            Tuple of (analyzed_findings, chains)
        """
        analyzed: List[Finding] = []

        for finding in findings:
            if skip_info and finding.severity == "info":
                analyzed.append(finding)
                continue

            # Classify
            finding = await self.classify_finding(finding)

            # Score CVSS for validated findings
            if finding.validated and finding.severity in ("medium", "high", "critical"):
                finding = await self.score_cvss(finding)

            analyzed.append(finding)

        # Chain analysis
        chains = await self.analyze_chains(analyzed)

        # Summary
        valid_count = sum(1 for f in analyzed if f.validated)
        fp_count = sum(1 for f in analyzed if f.is_false_positive)
        logger.info(
            f"Analysis complete: {valid_count} valid, "
            f"{fp_count} false positives, {len(chains)} chains"
        )

        return analyzed, chains
