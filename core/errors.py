"""
GetNexova Error Hierarchy
==========================
Structured error types with severity levels, automatic aggregation,
and recovery hints. Enables graceful degradation across the pipeline.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("getnexova.errors")


class ErrorSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GetNexovaError(Exception):
    """Base error for all GetNexova exceptions."""
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    recoverable: bool = True
    hint: str = ""

    def __init__(self, message: str, hint: str = "", context: Optional[Dict] = None):
        super().__init__(message)
        self.hint = hint or self.__class__.hint
        self.context = context or {}
        self.timestamp = time.time()


class CriticalError(GetNexovaError):
    """Unrecoverable error — pipeline must stop."""
    severity = ErrorSeverity.CRITICAL
    recoverable = False


class RecoverableError(GetNexovaError):
    """Error that can be worked around — phase skipped."""
    severity = ErrorSeverity.MEDIUM
    recoverable = True


class RateLimitError(RecoverableError):
    """API or target rate limit hit."""
    hint = "Wait and retry, or reduce concurrency"


class StorageError(GetNexovaError):
    """Database or file system error."""
    severity = ErrorSeverity.HIGH
    hint = "Check disk space and permissions"


class ToolError(RecoverableError):
    """External tool execution failure."""
    hint = "Check tool installation with --health-check"


class AIError(RecoverableError):
    """LLM call failure."""
    hint = "Check API keys and budget limits"


class ScopeError(CriticalError):
    """Target outside authorized scope."""
    hint = "Verify target is within the bug bounty program scope"


class AuthError(RecoverableError):
    """Authentication failure."""
    hint = "Check auth tokens/cookies or login credentials"


class NetworkError(RecoverableError):
    """Network connectivity issue."""
    hint = "Check internet connection and DNS"


@dataclass
class ErrorRecord:
    """Single recorded error with metadata."""
    error_type: str
    message: str
    severity: str
    recoverable: bool
    phase: str
    tool: str
    timestamp: float
    hint: str
    context: Dict[str, Any] = field(default_factory=dict)


class ErrorAggregator:
    """
    Collects and categorizes all errors during a scan run.
    Provides summary statistics and exportable reports.
    """

    def __init__(self):
        self.errors: List[ErrorRecord] = []
        self._suppressed: Dict[str, int] = {}

    def record(
        self,
        error: Exception,
        phase: str = "unknown",
        tool: str = "unknown",
        suppress_duplicates: bool = True,
    ) -> None:
        """Record an error occurrence."""
        if isinstance(error, GetNexovaError):
            severity = error.severity.value
            recoverable = error.recoverable
            hint = error.hint
            context = error.context
        else:
            severity = "medium"
            recoverable = True
            hint = ""
            context = {}

        error_key = f"{type(error).__name__}:{str(error)[:100]}"

        if suppress_duplicates and error_key in self._suppressed:
            self._suppressed[error_key] += 1
            return

        self._suppressed[error_key] = 1

        record = ErrorRecord(
            error_type=type(error).__name__,
            message=str(error)[:500],
            severity=severity,
            recoverable=recoverable,
            phase=phase,
            tool=tool,
            timestamp=time.time(),
            hint=hint,
            context=context,
        )
        self.errors.append(record)

        log_method = logger.error if severity in ("high", "critical") else logger.warning
        log_method(f"[{phase}/{tool}] {type(error).__name__}: {error}")

    def get_summary(self) -> Dict[str, Any]:
        """Get error summary statistics."""
        by_severity: Dict[str, int] = {}
        by_phase: Dict[str, int] = {}
        by_type: Dict[str, int] = {}

        for err in self.errors:
            by_severity[err.severity] = by_severity.get(err.severity, 0) + 1
            by_phase[err.phase] = by_phase.get(err.phase, 0) + 1
            by_type[err.error_type] = by_type.get(err.error_type, 0) + 1

        suppressed_total = sum(
            v - 1 for v in self._suppressed.values() if v > 1
        )

        return {
            "total_errors": len(self.errors),
            "suppressed_duplicates": suppressed_total,
            "by_severity": by_severity,
            "by_phase": by_phase,
            "by_type": by_type,
            "critical_count": by_severity.get("critical", 0),
            "has_unrecoverable": any(
                not e.recoverable for e in self.errors
            ),
        }

    def get_hints(self) -> List[str]:
        """Get unique recovery hints from all errors."""
        return list(set(e.hint for e in self.errors if e.hint))

    def clear(self) -> None:
        """Reset the aggregator."""
        self.errors.clear()
        self._suppressed.clear()


# Global singleton
_aggregator: Optional[ErrorAggregator] = None


def get_error_aggregator() -> ErrorAggregator:
    global _aggregator
    if _aggregator is None:
        _aggregator = ErrorAggregator()
    return _aggregator


def reset_error_aggregator() -> None:
    global _aggregator
    _aggregator = ErrorAggregator()


def safe_async(phase: str = "unknown", tool: str = "unknown"):
    """Decorator that catches errors and records them without crashing."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except CriticalError:
                raise  # Critical errors must propagate
            except GetNexovaError as e:
                get_error_aggregator().record(e, phase=phase, tool=tool)
                return None
            except Exception as e:
                get_error_aggregator().record(e, phase=phase, tool=tool)
                return None
        return wrapper
    return decorator
