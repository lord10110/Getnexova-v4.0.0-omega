"""
GetNexova Strategic Compact Skill
====================================
Compresses long contexts and prompts to fit within LLM token
limits while preserving critical information. Uses intelligent
summarization and prioritization.
"""

import logging
import re
from typing import List, Optional, Dict, Any

logger = logging.getLogger("getnexova.skills.compact")


class StrategicCompactor:
    """
    Intelligently compresses prompts and contexts that exceed
    token limits while preserving the most critical information.

    Strategies:
    1. Remove redundant/repetitive content
    2. Summarize verbose sections
    3. Prioritize by relevance to the task
    4. Truncate least important sections
    """

    # Approximate tokens per character (conservative estimate)
    CHARS_PER_TOKEN = 3.5

    def __init__(self, max_tokens: int = 8000):
        self.max_tokens = max_tokens
        self.max_chars = int(max_tokens * self.CHARS_PER_TOKEN)

    def compact(
        self,
        text: str,
        priority_sections: Optional[List[str]] = None,
        task_type: str = "analysis",
    ) -> str:
        """
        Compact text to fit within token limits.

        Args:
            text: The text to compact
            priority_sections: Sections to preserve (keywords)
            task_type: Type of task for priority decisions

        Returns:
            Compacted text within token limits
        """
        estimated_tokens = self._estimate_tokens(text)
        if estimated_tokens <= self.max_tokens:
            return text  # Already within limits

        logger.info(
            f"Compacting: ~{estimated_tokens} tokens → ~{self.max_tokens} target"
        )

        # Apply compression strategies in order
        text = self._remove_redundancy(text)
        if self._estimate_tokens(text) <= self.max_tokens:
            return text

        text = self._compress_raw_output(text)
        if self._estimate_tokens(text) <= self.max_tokens:
            return text

        text = self._truncate_sections(text, priority_sections or [])
        if self._estimate_tokens(text) <= self.max_tokens:
            return text

        # Final hard truncation
        text = self._hard_truncate(text, priority_sections or [])

        final_tokens = self._estimate_tokens(text)
        logger.info(f"Compacted to ~{final_tokens} tokens")
        return text

    def compact_findings(
        self,
        findings: List[Dict[str, Any]],
        max_findings: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Compact a list of findings for prompt inclusion.

        Prioritizes by severity, removes redundant raw output,
        and limits to max_findings.
        """
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 5),
        )

        compacted = []
        for finding in sorted_findings[:max_findings]:
            compact_finding = {
                "type": finding.get("vulnerability_type", "unknown"),
                "severity": finding.get("severity", "info"),
                "target": finding.get("target", ""),
                "evidence": finding.get("evidence", "")[:200],
                "tool": finding.get("tool", ""),
            }
            # Include CVSS only if scored
            if finding.get("cvss_score"):
                compact_finding["cvss"] = finding["cvss_score"]
            compacted.append(compact_finding)

        return compacted

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count from character count."""
        return int(len(text) / self.CHARS_PER_TOKEN)

    def _remove_redundancy(self, text: str) -> str:
        """Remove duplicate lines and redundant whitespace."""
        lines = text.split("\n")
        seen = set()
        unique_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped and stripped not in seen:
                seen.add(stripped)
                unique_lines.append(line)
            elif not stripped:
                # Keep one blank line between sections
                if unique_lines and unique_lines[-1].strip():
                    unique_lines.append("")

        # Collapse multiple blank lines
        result = "\n".join(unique_lines)
        result = re.sub(r"\n{3,}", "\n\n", result)
        return result

    def _compress_raw_output(self, text: str) -> str:
        """Truncate raw tool output sections which tend to be verbose."""
        # Find sections labeled as raw output and truncate them
        def truncate_raw(match):
            content = match.group(1)
            if len(content) > 500:
                return f"Raw Output (truncated): {content[:500]}..."
            return match.group(0)

        text = re.sub(
            r"(?:Raw Output|raw_output|Evidence)[:\s]*(.{500,}?)(?=\n\n|\n[A-Z]|\Z)",
            truncate_raw,
            text,
            flags=re.DOTALL,
        )
        return text

    def _truncate_sections(
        self, text: str, priority_keywords: List[str]
    ) -> str:
        """Truncate non-priority sections progressively."""
        sections = re.split(r"(##?\s+.+)", text)

        priority_parts = []
        other_parts = []

        for i, section in enumerate(sections):
            is_priority = any(
                kw.lower() in section.lower() for kw in priority_keywords
            )
            if is_priority or i < 3:  # Always keep first sections
                priority_parts.append(section)
            else:
                other_parts.append(section)

        # Start with priority content
        result = "\n".join(priority_parts)

        # Add other sections until we hit the limit
        for part in other_parts:
            if self._estimate_tokens(result + "\n" + part) <= self.max_tokens:
                result += "\n" + part
            else:
                # Truncate this section
                remaining = self.max_chars - len(result)
                if remaining > 100:
                    result += "\n" + part[:remaining] + "\n[...truncated]"
                break

        return result

    def _hard_truncate(
        self, text: str, priority_keywords: List[str]
    ) -> str:
        """Last-resort truncation to fit within limits."""
        if len(text) <= self.max_chars:
            return text

        # Keep the beginning and add a truncation marker
        keep = self.max_chars - 50
        return text[:keep] + "\n\n[...content truncated to fit token limit]"
