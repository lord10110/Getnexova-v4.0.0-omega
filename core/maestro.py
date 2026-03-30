"""
GetNexova Maestro Resource Manager
====================================
Live system resource monitoring with automatic throttling.
Prevents scans from overwhelming the host machine by
adjusting concurrency based on CPU, RAM, and disk usage.
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional, List, Callable, Dict, Any

logger = logging.getLogger("getnexova.maestro")


@dataclass
class SystemState:
    """Current system resource snapshot."""
    cpu_percent: float = 0.0
    ram_percent: float = 0.0
    ram_available_mb: float = 0.0
    disk_percent: float = 0.0
    load_avg_1m: float = 0.0
    timestamp: float = 0.0

    @property
    def healthy(self) -> bool:
        return self.cpu_percent < 85 and self.ram_percent < 90

    @property
    def critical(self) -> bool:
        return self.cpu_percent > 95 or self.ram_percent > 95


@dataclass
class MaestroConfig:
    """Configuration for the resource manager."""
    check_interval: float = 5.0          # seconds between checks
    cpu_warning: float = 75.0            # % CPU to start throttling
    cpu_critical: float = 90.0           # % CPU to pause new tasks
    ram_warning: float = 80.0            # % RAM warning
    ram_critical: float = 92.0           # % RAM to pause
    min_disk_mb: float = 500.0           # minimum free disk space
    max_concurrent_default: int = 5      # default concurrency
    min_concurrent: int = 1              # minimum even under pressure
    cooldown_seconds: float = 10.0       # pause duration when critical


class MaestroResourceManager:
    """
    Monitors system resources and dynamically adjusts scan concurrency.

    Features:
    - Background monitoring thread
    - Automatic concurrency scaling
    - Alert history for reporting
    - Graceful pause/resume when resources are critical
    """

    def __init__(self, config: Optional[MaestroConfig] = None):
        self.config = config or MaestroConfig()
        self._state = SystemState()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._alerts: List[Dict[str, Any]] = []
        self._current_concurrency = self.config.max_concurrent_default
        self._paused = False
        self._psutil_available = False

        try:
            import psutil
            self._psutil_available = True
        except ImportError:
            logger.info("psutil not installed — Maestro using basic monitoring")

    @property
    def state(self) -> SystemState:
        return self._state

    @property
    def alerts(self) -> List[Dict[str, Any]]:
        return list(self._alerts)

    @property
    def recommended_concurrency(self) -> int:
        return self._current_concurrency

    @property
    def is_paused(self) -> bool:
        return self._paused

    async def start(self) -> None:
        """Start background resource monitoring."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("Maestro resource monitor started")

    async def stop(self) -> None:
        """Stop background monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Maestro resource monitor stopped")

    def snapshot(self) -> SystemState:
        """Take an immediate resource snapshot."""
        self._update_state()
        return self._state

    async def wait_if_needed(self) -> None:
        """Block if resources are critical until they recover."""
        if not self._paused:
            return
        logger.warning("Maestro: waiting for resources to recover...")
        while self._paused and self._running:
            await asyncio.sleep(2.0)
        logger.info("Maestro: resources recovered, resuming")

    async def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                self._update_state()
                self._evaluate()
                await asyncio.sleep(self.config.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Maestro monitor error: {e}")
                await asyncio.sleep(self.config.check_interval)

    def _update_state(self) -> None:
        """Update system state from OS metrics."""
        self._state.timestamp = time.time()

        if self._psutil_available:
            import psutil
            self._state.cpu_percent = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            self._state.ram_percent = mem.percent
            self._state.ram_available_mb = mem.available / (1024 * 1024)
            try:
                disk = psutil.disk_usage("/")
                self._state.disk_percent = disk.percent
            except Exception:
                pass
        else:
            # Fallback: parse /proc on Linux
            try:
                with open("/proc/loadavg", "r") as f:
                    parts = f.read().strip().split()
                    self._state.load_avg_1m = float(parts[0])
                    cpu_count = os.cpu_count() or 1
                    self._state.cpu_percent = min(
                        (self._state.load_avg_1m / cpu_count) * 100, 100
                    )
            except Exception:
                pass

            try:
                with open("/proc/meminfo", "r") as f:
                    lines = f.readlines()
                mem_info = {}
                for line in lines[:10]:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = int(parts[1].strip().split()[0])
                        mem_info[key] = val
                total = mem_info.get("MemTotal", 1)
                available = mem_info.get("MemAvailable", total)
                self._state.ram_percent = ((total - available) / total) * 100
                self._state.ram_available_mb = available / 1024
            except Exception:
                pass

    def _evaluate(self) -> None:
        """Evaluate resource state and adjust concurrency."""
        cfg = self.config
        s = self._state

        # Critical state — pause
        if s.cpu_percent > cfg.cpu_critical or s.ram_percent > cfg.ram_critical:
            if not self._paused:
                self._paused = True
                self._current_concurrency = cfg.min_concurrent
                self._add_alert(
                    "critical",
                    f"Resources critical: CPU={s.cpu_percent:.0f}% RAM={s.ram_percent:.0f}%"
                )
            return

        # Recover from pause
        if self._paused:
            if s.cpu_percent < cfg.cpu_warning and s.ram_percent < cfg.ram_warning:
                self._paused = False
                self._current_concurrency = cfg.max_concurrent_default
                self._add_alert("info", "Resources recovered, resuming full speed")
            return

        # Warning — reduce concurrency
        if s.cpu_percent > cfg.cpu_warning or s.ram_percent > cfg.ram_warning:
            pressure = max(
                s.cpu_percent / 100.0,
                s.ram_percent / 100.0,
            )
            new_conc = max(
                cfg.min_concurrent,
                int(cfg.max_concurrent_default * (1.0 - pressure + 0.3)),
            )
            if new_conc != self._current_concurrency:
                self._current_concurrency = new_conc
                self._add_alert(
                    "warning",
                    f"Throttling to {new_conc} concurrent (CPU={s.cpu_percent:.0f}%)"
                )
        else:
            self._current_concurrency = cfg.max_concurrent_default

    def _add_alert(self, level: str, message: str) -> None:
        """Add an alert to history."""
        alert = {
            "level": level,
            "message": message,
            "timestamp": time.time(),
            "state": {
                "cpu": round(self._state.cpu_percent, 1),
                "ram": round(self._state.ram_percent, 1),
            },
        }
        self._alerts.append(alert)
        log_fn = getattr(logger, level if level != "critical" else "error")
        log_fn(f"Maestro: {message}")

    def get_summary(self) -> Dict[str, Any]:
        """Get Maestro summary for reports."""
        return {
            "current_state": {
                "cpu_percent": round(self._state.cpu_percent, 1),
                "ram_percent": round(self._state.ram_percent, 1),
                "ram_available_mb": round(self._state.ram_available_mb, 0),
            },
            "recommended_concurrency": self._current_concurrency,
            "is_paused": self._paused,
            "total_alerts": len(self._alerts),
            "alerts": self._alerts[-10:],  # Last 10
        }
