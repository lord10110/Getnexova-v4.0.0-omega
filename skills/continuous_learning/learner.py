"""
GetNexova Continuous Learning Skill
=====================================
Extracts patterns from validated findings and scan results
to evolve detection capabilities over time. Maintains a
local knowledge base of successful discoveries.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger("getnexova.skills.learning")


class ContinuousLearner:
    """
    Learns from validated vulnerability findings to improve
    future scan accuracy and reduce false positives.

    Tracks:
    - Successful vulnerability patterns (tool + target type → finding type)
    - Common false positive signatures
    - Effective tool configurations per target type
    - Historical scan statistics
    """

    def __init__(self, store_path: Optional[Path] = None):
        self.store_path = store_path or Path("memory/store/learning.jsonl")
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._patterns: Dict[str, Any] = {}
        self._fp_signatures: List[str] = []
        self._load_knowledge()

    def _load_knowledge(self) -> None:
        """Load existing knowledge from the store."""
        if not self.store_path.exists():
            return
        try:
            with open(self.store_path, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_type = entry.get("type")
                        if entry_type == "pattern":
                            key = entry.get("key", "")
                            self._patterns[key] = entry.get("data", {})
                        elif entry_type == "fp_signature":
                            self._fp_signatures.append(entry.get("signature", ""))
                    except json.JSONDecodeError:
                        continue
            logger.info(
                f"Loaded {len(self._patterns)} patterns, "
                f"{len(self._fp_signatures)} FP signatures"
            )
        except Exception as e:
            logger.error(f"Failed to load learning data: {e}")

    def learn_from_finding(self, finding: Dict[str, Any]) -> None:
        """
        Extract and store patterns from a validated finding.

        Args:
            finding: Dictionary with finding details
        """
        tool = finding.get("tool", "unknown")
        vuln_type = finding.get("vulnerability_type", "unknown")
        severity = finding.get("severity", "info")
        target = finding.get("target", "")
        validated = finding.get("validated", False)
        is_fp = finding.get("is_false_positive", False)

        if is_fp:
            # Learn false positive signature
            fp_sig = f"{tool}:{vuln_type}:{self._extract_domain_pattern(target)}"
            if fp_sig not in self._fp_signatures:
                self._fp_signatures.append(fp_sig)
                self._persist({
                    "type": "fp_signature",
                    "signature": fp_sig,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            return

        if validated:
            # Learn successful detection pattern
            pattern_key = f"{tool}:{vuln_type}"
            if pattern_key not in self._patterns:
                self._patterns[pattern_key] = {
                    "count": 0,
                    "severities": {},
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                }
            pattern = self._patterns[pattern_key]
            pattern["count"] += 1
            pattern["severities"][severity] = pattern["severities"].get(severity, 0) + 1
            pattern["last_seen"] = datetime.now(timezone.utc).isoformat()

            self._persist({
                "type": "pattern",
                "key": pattern_key,
                "data": pattern,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def learn_from_scan(self, scan_results: Dict[str, Any]) -> None:
        """Learn from overall scan results (tool effectiveness, timing)."""
        self._persist({
            "type": "scan_result",
            "target": scan_results.get("target", ""),
            "mode": scan_results.get("mode", ""),
            "total_findings": scan_results.get("total_findings", 0),
            "validated_findings": scan_results.get("validated_findings", 0),
            "false_positives": scan_results.get("false_positives", 0),
            "duration_seconds": scan_results.get("duration_seconds", 0),
            "tools_used": scan_results.get("tools_used", []),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def is_likely_false_positive(
        self, tool: str, vuln_type: str, target: str
    ) -> float:
        """
        Check if a finding matches known false positive patterns.

        Returns:
            Probability (0.0-1.0) that this is a false positive
        """
        domain_pattern = self._extract_domain_pattern(target)
        check_sig = f"{tool}:{vuln_type}:{domain_pattern}"

        # Exact match
        if check_sig in self._fp_signatures:
            return 0.8

        # Partial match (tool + vuln type)
        partial_sig = f"{tool}:{vuln_type}:"
        partial_matches = sum(
            1 for s in self._fp_signatures if s.startswith(partial_sig)
        )
        if partial_matches > 3:
            return 0.6

        return 0.0

    def get_pattern_confidence(self, tool: str, vuln_type: str) -> float:
        """
        Get confidence boost for a tool+vuln_type combination
        based on historical success.

        Returns:
            Confidence modifier (0.0 = no data, positive = boost)
        """
        key = f"{tool}:{vuln_type}"
        pattern = self._patterns.get(key)
        if not pattern:
            return 0.0

        count = pattern.get("count", 0)
        if count >= 10:
            return 0.2
        elif count >= 5:
            return 0.1
        elif count >= 2:
            return 0.05
        return 0.0

    def get_statistics(self) -> Dict[str, Any]:
        """Get learning statistics summary."""
        return {
            "total_patterns": len(self._patterns),
            "total_fp_signatures": len(self._fp_signatures),
            "top_patterns": sorted(
                self._patterns.items(),
                key=lambda x: x[1].get("count", 0),
                reverse=True,
            )[:10],
        }

    def _extract_domain_pattern(self, target: str) -> str:
        """Extract a generalizable domain pattern from a target."""
        # Remove protocol and path
        domain = target.split("://")[-1].split("/")[0].split(":")[0]
        # Get the base domain (last two parts)
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def _persist(self, entry: Dict[str, Any]) -> None:
        """Append an entry to the learning store."""
        try:
            with open(self.store_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to persist learning data: {e}")
