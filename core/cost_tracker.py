"""
GetNexova Cost Tracker
=======================
Tracks LLM API costs across runs, enforces budget limits,
and persists cost data for monthly tracking.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger("getnexova.cost_tracker")


@dataclass
class APICall:
    """Record of a single API call."""
    timestamp: str
    model: str
    input_tokens: int
    output_tokens: int
    cost: float
    task_type: str
    success: bool
    latency_ms: float


class CostTracker:
    """
    Tracks and enforces LLM API cost budgets.

    Features:
    - Per-run and per-month budget limits
    - Cost history persistence
    - Model usage statistics
    """

    def __init__(
        self,
        max_cost_per_run: float = 5.0,
        max_cost_per_month: float = 50.0,
        cost_file: Optional[Path] = None,
    ):
        self.max_cost_per_run = max_cost_per_run
        self.max_cost_per_month = max_cost_per_month
        self.cost_file = cost_file or Path("data/cost_history.jsonl")
        self.run_cost: float = 0.0
        self.run_calls: List[APICall] = []
        self._month_cost: Optional[float] = None

    def record_call(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost: float,
        task_type: str,
        success: bool,
        latency_ms: float,
    ) -> None:
        """Record an API call and update running totals."""
        call = APICall(
            timestamp=datetime.now(timezone.utc).isoformat(),
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost,
            task_type=task_type,
            success=success,
            latency_ms=latency_ms,
        )
        self.run_calls.append(call)
        self.run_cost += cost

        # Persist to file
        self._persist_call(call)

        logger.debug(
            f"API call: model={model}, cost=${cost:.4f}, "
            f"total_run=${self.run_cost:.4f}"
        )

    def can_afford(self, estimated_cost: float = 0.01) -> bool:
        """Check if budget allows another API call."""
        if self.run_cost + estimated_cost > self.max_cost_per_run:
            logger.warning(
                f"Run budget exceeded: ${self.run_cost:.2f} / "
                f"${self.max_cost_per_run:.2f}"
            )
            return False

        month_cost = self.get_month_cost()
        if month_cost + estimated_cost > self.max_cost_per_month:
            logger.warning(
                f"Monthly budget exceeded: ${month_cost:.2f} / "
                f"${self.max_cost_per_month:.2f}"
            )
            return False

        return True

    def get_month_cost(self) -> float:
        """Calculate total cost for the current month."""
        if self._month_cost is not None:
            return self._month_cost + self.run_cost

        total = 0.0
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")

        if self.cost_file.exists():
            try:
                with open(self.cost_file, "r") as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            if entry.get("timestamp", "").startswith(current_month):
                                total += entry.get("cost", 0.0)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.error(f"Failed to read cost history: {e}")

        self._month_cost = total
        return total + self.run_cost

    def _persist_call(self, call: APICall) -> None:
        """Append call record to cost history file."""
        try:
            self.cost_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cost_file, "a") as f:
                f.write(json.dumps({
                    "timestamp": call.timestamp,
                    "model": call.model,
                    "input_tokens": call.input_tokens,
                    "output_tokens": call.output_tokens,
                    "cost": call.cost,
                    "task_type": call.task_type,
                    "success": call.success,
                    "latency_ms": call.latency_ms,
                }) + "\n")
        except Exception as e:
            logger.error(f"Failed to persist cost data: {e}")

    def get_run_summary(self) -> Dict:
        """Get summary statistics for the current run."""
        if not self.run_calls:
            return {"total_cost": 0, "total_calls": 0}

        models_used: Dict[str, int] = {}
        tasks: Dict[str, int] = {}
        total_tokens = 0

        for call in self.run_calls:
            models_used[call.model] = models_used.get(call.model, 0) + 1
            tasks[call.task_type] = tasks.get(call.task_type, 0) + 1
            total_tokens += call.input_tokens + call.output_tokens

        return {
            "total_cost": round(self.run_cost, 4),
            "total_calls": len(self.run_calls),
            "total_tokens": total_tokens,
            "models_used": models_used,
            "tasks": tasks,
            "successful": sum(1 for c in self.run_calls if c.success),
            "failed": sum(1 for c in self.run_calls if not c.success),
        }
