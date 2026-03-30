"""
GetNexova Checkpoint Manager
===============================
Saves scan state between phases so crashed or interrupted
scans can be resumed from the last completed phase.
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("getnexova.checkpoint")


@dataclass
class CheckpointData:
    """Serializable scan state."""
    session_id: str
    target: str
    mode: str
    current_phase: int = 0
    completed_phases: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    live_hosts: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    findings_count: int = 0
    findings_file: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    elapsed_seconds: float = 0.0


class CheckpointManager:
    """
    Manages scan checkpoints for resume capability.

    Saves state after each completed phase. On resume,
    loads the last checkpoint and skips completed phases.
    """

    def __init__(self, workspace: Path, session_id: str):
        self.workspace = workspace
        self.session_id = session_id
        self.checkpoint_dir = workspace / "checkpoints"
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._checkpoint_file = self.checkpoint_dir / f"{session_id}.json"
        self._findings_file = self.checkpoint_dir / f"{session_id}_findings.jsonl"
        self._start_time = time.time()
        self._data: Optional[CheckpointData] = None

    def save(
        self,
        target: str,
        mode: str,
        phase: int,
        phase_name: str,
        subdomains: Optional[List[str]] = None,
        live_hosts: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
        findings_count: int = 0,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Save a checkpoint after completing a phase."""
        if self._data is None:
            self._data = CheckpointData(
                session_id=self.session_id,
                target=target,
                mode=mode,
            )

        self._data.current_phase = phase
        if phase_name not in self._data.completed_phases:
            self._data.completed_phases.append(phase_name)
        if subdomains is not None:
            self._data.subdomains = subdomains
        if live_hosts is not None:
            self._data.live_hosts = live_hosts
        if urls is not None:
            self._data.urls = urls
        self._data.findings_count = findings_count
        self._data.findings_file = str(self._findings_file)
        self._data.context = context or self._data.context
        self._data.timestamp = time.time()
        self._data.elapsed_seconds = time.time() - self._start_time

        try:
            with open(self._checkpoint_file, "w") as f:
                json.dump(asdict(self._data), f, indent=2)
            logger.debug(
                f"Checkpoint saved: phase {phase} ({phase_name})"
            )
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")

    def save_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Append findings to the checkpoint findings file."""
        try:
            with open(self._findings_file, "a") as f:
                for finding in findings:
                    f.write(json.dumps(finding) + "\n")
        except Exception as e:
            logger.error(f"Failed to save findings checkpoint: {e}")

    def load(self, target: str) -> Optional[CheckpointData]:
        """
        Load the most recent checkpoint for a target.

        Args:
            target: Target domain to find checkpoint for

        Returns:
            CheckpointData if found, None otherwise
        """
        # Search for matching checkpoint
        for cp_file in sorted(
            self.checkpoint_dir.glob("getnexova_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            try:
                with open(cp_file, "r") as f:
                    data = json.load(f)
                if data.get("target") == target:
                    checkpoint = CheckpointData(**data)
                    logger.info(
                        f"Checkpoint found: phase {checkpoint.current_phase}, "
                        f"{len(checkpoint.completed_phases)} phases completed"
                    )
                    self._data = checkpoint
                    self._checkpoint_file = cp_file
                    return checkpoint
            except Exception:
                continue
        return None

    def load_findings(self) -> List[Dict[str, Any]]:
        """Load findings from checkpoint file."""
        findings = []
        if self._findings_file.exists():
            try:
                with open(self._findings_file, "r") as f:
                    for line in f:
                        if line.strip():
                            findings.append(json.loads(line))
            except Exception as e:
                logger.error(f"Failed to load checkpoint findings: {e}")
        return findings

    def should_skip_phase(self, phase_name: str) -> bool:
        """Check if a phase was already completed in a previous run."""
        if self._data is None:
            return False
        return phase_name in self._data.completed_phases

    def get_resume_info(self) -> Dict[str, Any]:
        """Get info about what would be resumed."""
        if self._data is None:
            return {"resumable": False}
        return {
            "resumable": True,
            "target": self._data.target,
            "mode": self._data.mode,
            "completed_phases": self._data.completed_phases,
            "current_phase": self._data.current_phase,
            "findings_count": self._data.findings_count,
            "elapsed_so_far": round(self._data.elapsed_seconds, 1),
        }

    def clear(self) -> None:
        """Delete checkpoint files for current session."""
        for f in [self._checkpoint_file, self._findings_file]:
            try:
                if f.exists():
                    f.unlink()
            except Exception:
                pass
        self._data = None

    def clear_all(self, target: Optional[str] = None) -> int:
        """Clear all checkpoints, optionally filtered by target."""
        removed = 0
        for cp_file in self.checkpoint_dir.glob("getnexova_*.json"):
            try:
                if target:
                    with open(cp_file, "r") as f:
                        data = json.load(f)
                    if data.get("target") != target:
                        continue
                cp_file.unlink()
                # Also remove findings file
                findings_file = cp_file.with_suffix("").with_name(
                    cp_file.stem + "_findings.jsonl"
                )
                if findings_file.exists():
                    findings_file.unlink()
                removed += 1
            except Exception:
                continue
        return removed
