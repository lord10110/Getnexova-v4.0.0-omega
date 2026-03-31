"""
GetNexova Reporter Agent
==========================
Generates professional vulnerability reports in multiple formats
(HTML, Markdown, JSON) suitable for bug bounty platform submission.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from agents.agent_loader import load_agent_def
from agents.ai_engine import AIEngine, PromptBuilder
from agents.scanner import Finding

logger = logging.getLogger("getnexova.reporter")


class ReporterAgent:
    """
    Generates professional vulnerability reports.

    Supports multiple formats and includes executive summaries,
    detailed findings, PoC instructions, and remediation advice.
    """

    def __init__(
        self,
        ai_engine: Optional[AIEngine] = None,  # Changed to Optional
        output_dir: Optional[Path] = None,
    ):
        self.ai = ai_engine
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.definition = load_agent_def("reporter")

    async def generate_report(
        self,
        target: str,
        findings: List[Finding],
        chains: List[Dict[str, Any]],
        scan_metadata: Dict[str, Any],
        format: str = "all",
    ) -> Dict[str, str]:
        """
        Generate vulnerability report in specified formats.

        Args:
            target: Target that was scanned
            findings: Validated findings
            chains: Attack chains
            scan_metadata: Scan run metadata (duration, tools used, etc.)
            format: Output format (html/markdown/json/all)

        Returns:
            Dict of format -> file path for generated reports
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_name = f"getnexova_{target.replace('.', '_')}_{timestamp}"

        # Filter to validated findings only
        valid_findings = [f for f in findings if f.validated]

        # Generate AI-enhanced report content (fallback if AI is disabled)
        ai_report = await self._generate_ai_content(
            target, valid_findings, chains
        )

        generated: Dict[str, str] = {}

        if format in ("json", "all"):
            path = self._write_json(
                report_name, target, valid_findings, chains, scan_metadata
            )
            generated["json"] = str(path)

        if format in ("markdown", "all"):
            path = self._write_markdown(
                report_name, target, valid_findings, chains,
                scan_metadata, ai_report
            )
            generated["markdown"] = str(path)

        if format in ("html", "all"):
            path = self._write_html(
                report_name, target, valid_findings, chains,
                scan_metadata, ai_report
            )
            generated["html"] = str(path)

        logger.info(f"Reports generated: {list(generated.keys())}")
        return generated

    async def _generate_ai_content(
        self,
        target: str,
        findings: List[Finding],
        chains: List[Dict[str, Any]],
    ) -> str:
        """Use AI to generate professional report narrative. Returns fallback if AI disabled."""
        # Check if AI engine is available
        if self.ai is None:
            logger.info("AI engine disabled, using fallback report generator")
            return self._fallback_report(target, findings, chains)

        findings_dicts = [
            {
                "severity": f.severity,
                "vulnerability_type": f.vulnerability_type,
                "target": f.target,
                "evidence": f.evidence[:200],
                "cvss_score": f.cvss_score,
            }
            for f in findings[:30]
        ]

        prompt = PromptBuilder.generate_report(target, findings_dicts, chains)
        system_prompt = self.definition.soul or (
            "You are a professional security report writer. "
            "Write clear, factual, actionable reports suitable for "
            "bug bounty platform submission."
        )

        try:
            response = await self.ai.call(
                prompt=prompt,
                task_type="report",
                system_prompt=system_prompt,
            )
        except Exception as e:
            logger.error(f"AI call failed: {e}, using fallback report")
            return self._fallback_report(target, findings, chains)

        return response or self._fallback_report(target, findings, chains)

    def _fallback_report(
        self,
        target: str,
        findings: List[Finding],
        chains: List[Dict[str, Any]],
    ) -> str:
        """Generate a basic report without AI assistance."""
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        lines = [
            f"# GetNexova Security Assessment Report",
            f"## Target: {target}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"",
            f"## Executive Summary",
            f"Automated security assessment of {target} discovered "
            f"{len(findings)} validated findings.",
            f"",
            f"### Severity Distribution",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"- **{sev.upper()}**: {count}")

        lines.append(f"\n## Findings\n")
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. [{f.severity.upper()}] {f.vulnerability_type}")
            lines.append(f"- **Target:** {f.target}")
            lines.append(f"- **Tool:** {f.tool}")
            if f.cvss_score:
                lines.append(f"- **CVSS:** {f.cvss_score} ({f.cvss_vector})")
            if f.evidence:
                lines.append(f"- **Evidence:** {f.evidence[:300]}")
            lines.append("")

        if chains:
            lines.append("## Attack Chains\n")
            for chain in chains:
                lines.append(f"### {chain.get('name', 'Chain')}")
                lines.append(
                    f"**Combined Severity:** {chain.get('combined_severity', 'N/A')}"
                )
                for step in chain.get("steps", []):
                    lines.append(f"  - {step}")
                lines.append("")

        return "\n".join(lines)

    def _write_json(
        self,
        name: str,
        target: str,
        findings: List[Finding],
        chains: List[Dict[str, Any]],
        metadata: Dict[str, Any],
    ) -> Path:
        """Write JSON report."""
        path = self.output_dir / f"{name}.json"
        report = {
            "project": "GetNexova",
            "version": "4.0.0",
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata,
            "summary": {
                "total_findings": len(findings),
                "by_severity": {},
            },
            "findings": [],
            "chains": chains,
        }

        for f in findings:
            sev = f.severity.lower()
            report["summary"]["by_severity"][sev] = (
                report["summary"]["by_severity"].get(sev, 0) + 1
            )
            report["findings"].append({
                "id": f.id,
                "tool": f.tool,
                "target": f.target,
                "type": f.vulnerability_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "evidence": f.evidence,
                "url": f.url,
                "metadata": f.metadata,
            })

        with open(path, "w") as fp:
            json.dump(report, fp, indent=2)
        return path

    def _write_markdown(
        self,
        name: str,
        target: str,
        findings: List[Finding],
        chains: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        ai_content: str,
    ) -> Path:
        """Write Markdown report."""
        path = self.output_dir / f"{name}.md"
        with open(path, "w") as fp:
            fp.write(ai_content)
        return path

    def _write_html(
        self,
        name: str,
        target: str,
        findings: List[Finding],
        chains: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        ai_content: str,
    ) -> Path:
        """Write HTML report with GetNexova branding."""
        path = self.output_dir / f"{name}.html"

        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#2563eb",
            "info": "#6b7280",
        }

        findings_html = ""
        for f in findings:
            color = severity_colors.get(f.severity, "#6b7280")
            screenshot_html = ""
            poc_html = ""
            # Include screenshot if available
            if f.metadata.get("screenshot"):
                screenshot_html = f'<p><strong>Screenshot:</strong> <a href="{f.metadata["screenshot"]}">View Evidence</a></p>'
            # Include PoC if available
            poc = f.metadata.get("poc", "")
            if poc:
                poc_html = f'<div style="margin-top:8px;"><strong>PoC:</strong><pre style="background:#1a1a2e;color:#38bdf8;padding:10px;border-radius:4px;overflow-x:auto;font-size:12px;">{poc[:500]}</pre></div>'

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 16px; margin: 16px 0; background: #f8f9fa; border-radius: 4px;">
                <h3><span style="color: {color}; font-weight: bold;">[{f.severity.upper()}]</span> {f.vulnerability_type}</h3>
                <p><strong>Target:</strong> {f.target}</p>
                <p><strong>Tool:</strong> {f.tool}</p>
                {"<p><strong>CVSS:</strong> " + str(f.cvss_score) + " (" + f.cvss_vector + ")</p>" if f.cvss_score else ""}
                {"<p><strong>Evidence:</strong> <code>" + f.evidence[:300] + "</code></p>" if f.evidence else ""}
                {screenshot_html}
                {poc_html}
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GetNexova Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1a1a2e; background: #f0f2f5; }}
        .header {{ background: linear-gradient(135deg, #0a1628 0%, #1a365d 100%); color: white; padding: 40px; text-align: center; }}
        .header h1 {{ font-size: 2.5rem; margin-bottom: 8px; }}
        .header .subtitle {{ color: #38bdf8; font-size: 1.1rem; }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 32px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }}
        .summary-card {{ background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .summary-card .count {{ font-size: 2rem; font-weight: 700; }}
        .finding {{ transition: transform 0.1s; }}
        .finding:hover {{ transform: translateX(4px); }}
        .footer {{ text-align: center; padding: 32px; color: #6b7280; font-size: 0.875rem; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>GetNexova</h1>
        <div class="subtitle">Security Assessment Report</div>
        <p style="margin-top: 16px; opacity: 0.8;">Target: {target} | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
    </div>
    <div class="container">
        <div class="summary-grid">
            <div class="summary-card">
                <div class="count" style="color: #dc2626;">{sum(1 for f in findings if f.severity == 'critical')}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #ea580c;">{sum(1 for f in findings if f.severity == 'high')}</div>
                <div>High</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #d97706;">{sum(1 for f in findings if f.severity == 'medium')}</div>
                <div>Medium</div>
            