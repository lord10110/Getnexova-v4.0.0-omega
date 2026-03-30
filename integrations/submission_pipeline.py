"""
GetNexova Submission Pipeline
================================
Prepares and optionally submits validated findings to
bug bounty platforms. Formats reports according to each
platform's requirements.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger("getnexova.submission")


class SubmissionPipeline:
    """
    Prepares findings for platform submission.

    Formats reports for Intigriti, YesWeHack, and HackerOne,
    applying platform-specific templates and conventions.
    """

    def __init__(self, workspace: Path, platform_manager=None):
        self.workspace = workspace
        self.platforms = platform_manager
        self.submissions_dir = workspace / "submissions"
        self.submissions_dir.mkdir(parents=True, exist_ok=True)

    def prepare_submission(
        self,
        finding: Dict[str, Any],
        platform: str = "intigriti",
        program: str = "",
    ) -> Dict[str, Any]:
        """
        Prepare a single finding for platform submission.

        Returns a formatted submission object.
        """
        vuln_type = finding.get("vulnerability_type", "Unknown")
        severity = finding.get("severity", "medium")
        target = finding.get("target", "")
        evidence = finding.get("evidence", "")
        cvss = finding.get("cvss_score", 0)
        cvss_vector = finding.get("cvss_vector", "")
        metadata = finding.get("metadata", {})
        poc = metadata.get("poc", "")
        recommendations = metadata.get("recommendations", [])

        # Build platform-ready report
        title = f"[{severity.upper()}] {vuln_type} on {target}"

        description = self._build_description(
            vuln_type, target, evidence, cvss, cvss_vector, poc, recommendations
        )

        submission = {
            "title": title,
            "severity": severity,
            "target": target,
            "vulnerability_type": vuln_type,
            "description": description,
            "cvss_score": cvss,
            "cvss_vector": cvss_vector,
            "platform": platform,
            "program": program,
            "prepared_at": datetime.now(timezone.utc).isoformat(),
            "finding_id": finding.get("id", ""),
        }

        return submission

    def prepare_batch(
        self,
        findings: List[Dict[str, Any]],
        platform: str = "intigriti",
        program: str = "",
        min_severity: str = "low",
    ) -> List[Dict[str, Any]]:
        """Prepare multiple findings for submission."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_level = severity_order.get(min_severity, 3)

        submissions = []
        for finding in findings:
            sev = finding.get("severity", "info")
            if severity_order.get(sev, 5) <= min_level:
                sub = self.prepare_submission(finding, platform, program)
                submissions.append(sub)

        # Sort by severity
        submissions.sort(key=lambda s: severity_order.get(s["severity"], 5))

        # Save to disk
        if submissions:
            out_file = self.submissions_dir / f"batch_{program}_{int(datetime.now().timestamp())}.json"
            with open(out_file, "w") as f:
                json.dump(submissions, f, indent=2)
            logger.info(f"Prepared {len(submissions)} submissions → {out_file}")

        return submissions

    def _build_description(
        self,
        vuln_type: str,
        target: str,
        evidence: str,
        cvss: float,
        cvss_vector: str,
        poc: str,
        recommendations: List[str],
    ) -> str:
        """Build a platform-ready description."""
        lines = [
            f"## Summary",
            f"A {vuln_type} vulnerability was identified on `{target}`.",
            "",
            f"## Severity",
            f"**CVSS Score:** {cvss}" + (f" ({cvss_vector})" if cvss_vector else ""),
            "",
            f"## Steps to Reproduce",
        ]

        if poc:
            lines.extend([
                "1. Navigate to the target URL",
                f"2. {poc}",
                "3. Observe the vulnerable behavior",
            ])
        else:
            lines.extend([
                "1. Navigate to the target URL",
                "2. See evidence below",
            ])

        lines.extend([
            "",
            f"## Evidence",
            f"```",
            evidence[:1000] if evidence else "See attached screenshots",
            f"```",
            "",
            f"## Impact",
            f"This vulnerability allows an attacker to exploit {vuln_type.lower()} ",
            f"on the target application.",
        ])

        if recommendations:
            lines.extend(["", "## Recommendations"])
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")

        lines.extend([
            "",
            "---",
            "*Report generated by GetNexova v4.0.0 OMEGA*",
        ])

        return "\n".join(lines)
