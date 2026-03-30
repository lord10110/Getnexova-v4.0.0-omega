"""
GetNexova Diff Reporter
=========================
Compares current scan results against previous scans for the
same target. Highlights new findings, resolved findings, and
severity changes.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("getnexova.diff_report")


@dataclass
class DiffResult:
    """Result of comparing two scans."""
    target: str
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = field(default_factory=list)
    persistent_findings: List[Dict[str, Any]] = field(default_factory=list)
    severity_changes: List[Dict[str, Any]] = field(default_factory=list)
    previous_scan_date: str = ""
    current_scan_date: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings or self.resolved_findings or self.severity_changes)

    def summary(self) -> Dict[str, int]:
        return {
            "new": len(self.new_findings),
            "resolved": len(self.resolved_findings),
            "persistent": len(self.persistent_findings),
            "severity_changed": len(self.severity_changes),
        }


class DiffReporter:
    """
    Generates diff reports between scan runs.

    Compares findings by creating a signature hash for each
    finding and tracking which are new, resolved, or changed.
    """

    def __init__(self, knowledge_base=None):
        self.kb = knowledge_base

    def compare(
        self,
        target: str,
        current_findings: List[Dict[str, Any]],
        previous_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> DiffResult:
        """
        Compare current findings against previous scan.

        If previous_findings is None, tries to load from knowledge base.
        """
        diff = DiffResult(
            target=target,
            current_scan_date=datetime.now(timezone.utc).isoformat(),
        )

        # Load previous findings if not provided
        if previous_findings is None and self.kb:
            previous_findings = self.kb.get_recent_findings(target, limit=200)
            if previous_findings:
                diff.previous_scan_date = previous_findings[0].get("timestamp", "")

        if not previous_findings:
            # No previous scan — all current are "new"
            diff.new_findings = current_findings
            return diff

        # Create signature sets
        current_sigs = {self._signature(f): f for f in current_findings}
        previous_sigs = {self._signature(f): f for f in previous_findings}

        current_keys = set(current_sigs.keys())
        previous_keys = set(previous_sigs.keys())

        # New findings (in current but not in previous)
        for sig in current_keys - previous_keys:
            diff.new_findings.append(current_sigs[sig])

        # Resolved findings (in previous but not in current)
        for sig in previous_keys - current_keys:
            diff.resolved_findings.append(previous_sigs[sig])

        # Persistent findings (in both)
        for sig in current_keys & previous_keys:
            current_f = current_sigs[sig]
            previous_f = previous_sigs[sig]
            diff.persistent_findings.append(current_f)

            # Check for severity changes
            if current_f.get("severity") != previous_f.get("severity"):
                diff.severity_changes.append({
                    "finding": current_f,
                    "old_severity": previous_f.get("severity"),
                    "new_severity": current_f.get("severity"),
                })

        logger.info(
            f"Diff: {len(diff.new_findings)} new, "
            f"{len(diff.resolved_findings)} resolved, "
            f"{len(diff.persistent_findings)} persistent"
        )
        return diff

    def format_markdown(self, diff: DiffResult) -> str:
        """Format diff result as Markdown."""
        lines = [
            f"# GetNexova Diff Report",
            f"**Target:** {diff.target}",
            f"**Current scan:** {diff.current_scan_date}",
            f"**Previous scan:** {diff.previous_scan_date or 'None'}",
            "",
        ]

        if diff.new_findings:
            lines.append(f"## New Findings ({len(diff.new_findings)})")
            for f in diff.new_findings:
                lines.append(
                    f"- **[{f.get('severity', '?').upper()}]** "
                    f"{f.get('vulnerability_type', '?')} → {f.get('target', '')}"
                )
            lines.append("")

        if diff.resolved_findings:
            lines.append(f"## Resolved ({len(diff.resolved_findings)})")
            for f in diff.resolved_findings:
                lines.append(
                    f"- ~~[{f.get('severity', '?').upper()}] "
                    f"{f.get('vulnerability_type', '?')}~~"
                )
            lines.append("")

        if diff.severity_changes:
            lines.append(f"## Severity Changes ({len(diff.severity_changes)})")
            for sc in diff.severity_changes:
                lines.append(
                    f"- {sc['finding'].get('vulnerability_type', '?')}: "
                    f"{sc['old_severity']} → {sc['new_severity']}"
                )

        if not diff.has_changes:
            lines.append("*No changes since last scan.*")

        return "\n".join(lines)

    @staticmethod
    def _signature(finding: Dict[str, Any]) -> str:
        """Create a unique signature for a finding."""
        parts = [
            finding.get("vulnerability_type", ""),
            finding.get("target", ""),
            finding.get("url", ""),
        ]
        return "|".join(parts).lower().strip()
