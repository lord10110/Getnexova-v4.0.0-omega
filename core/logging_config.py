"""
GetNexova Logging Module
=========================
Structured logging with file rotation, JSON output for machines,
and rich console output for humans.
"""

import logging
import logging.handlers
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for machine-readable logs."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_data"):
            log_entry["data"] = record.extra_data
        return json.dumps(log_entry)


class ColorFormatter(logging.Formatter):
    """Colored console formatter for human-readable output."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[1;31m", # Bold Red
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = f"{color}[{timestamp}] {record.levelname:8s}{self.RESET}"
        name = f"\033[90m{record.name}\033[0m"
        return f"{prefix} {name} → {record.getMessage()}"


def setup_logging(
    log_dir: Optional[Path] = None,
    level: int = logging.INFO,
    json_logs: bool = True,
    console: bool = True,
) -> logging.Logger:
    """
    Configure the root GetNexova logger.

    Args:
        log_dir: Directory for log files
        level: Logging level
        json_logs: Enable JSON log file output
        console: Enable console output

    Returns:
        Root logger for the project
    """
    root_logger = logging.getLogger("getnexova")
    root_logger.setLevel(level)
    root_logger.handlers.clear()

    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(ColorFormatter())
        root_logger.addHandler(console_handler)

    if json_logs and log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"getnexova_{datetime.now().strftime('%Y%m%d')}.jsonl"

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

    # Error-only log
    if log_dir:
        error_file = log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(error_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the getnexova namespace."""
    return logging.getLogger(f"getnexova.{name}")
