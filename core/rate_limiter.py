"""
GetNexova Adaptive Rate Limiter
=================================
Per-domain request throttling that adapts based on target
response patterns. Prevents overwhelming targets and avoids
getting blocked by WAFs.
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger("getnexova.rate_limiter")


@dataclass
class DomainState:
    """Rate limiting state for a single domain."""
    requests_sent: int = 0
    last_request_time: float = 0.0
    current_rps: float = 2.0
    consecutive_errors: int = 0
    consecutive_429s: int = 0
    backoff_until: float = 0.0
    total_wait_time: float = 0.0


class AdaptiveRateLimiter:
    """
    Adaptive per-domain rate limiter.

    Features:
    - Per-domain tracking (different limits for different targets)
    - Automatic backoff on 429/503 responses
    - Gradual ramp-up after backoff
    - Concurrency semaphore for parallel operations
    - Statistics for reporting
    """

    def __init__(
        self,
        default_rps: float = 2.0,
        max_rps: float = 10.0,
        min_rps: float = 0.2,
        max_concurrent: int = 10,
    ):
        self.default_rps = default_rps
        self.max_rps = max_rps
        self.min_rps = min_rps
        self._domains: Dict[str, DomainState] = defaultdict(
            lambda: DomainState(current_rps=default_rps)
        )
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._global_lock = asyncio.Lock()

    async def acquire(self, domain: str) -> None:
        """
        Wait until it's safe to make a request to this domain.

        Blocks if:
        - Domain is in backoff period
        - Requests are too frequent
        - Global concurrency limit reached
        """
        await self._semaphore.acquire()

        state = self._domains[domain]
        now = time.time()

        # Check backoff
        if state.backoff_until > now:
            wait = state.backoff_until - now
            logger.debug(f"Rate limiter: backing off {domain} for {wait:.1f}s")
            state.total_wait_time += wait
            await asyncio.sleep(wait)

        # Enforce rate limit
        if state.last_request_time > 0:
            min_interval = 1.0 / state.current_rps
            elapsed = now - state.last_request_time
            if elapsed < min_interval:
                wait = min_interval - elapsed
                state.total_wait_time += wait
                await asyncio.sleep(wait)

        state.last_request_time = time.time()
        state.requests_sent += 1

    def release(self, domain: str) -> None:
        """Release the semaphore after request completes."""
        self._semaphore.release()

    def report_success(self, domain: str) -> None:
        """Report a successful request — may increase rate."""
        state = self._domains[domain]
        state.consecutive_errors = 0
        state.consecutive_429s = 0

        # Gradually increase rate after sustained success
        if state.requests_sent % 20 == 0 and state.current_rps < self.max_rps:
            state.current_rps = min(state.current_rps * 1.1, self.max_rps)

    def report_error(self, domain: str, status_code: int = 0) -> None:
        """Report a failed request — triggers backoff."""
        state = self._domains[domain]
        state.consecutive_errors += 1

        if status_code == 429 or status_code == 503:
            state.consecutive_429s += 1
            # Exponential backoff: 5s, 10s, 20s, 40s, max 120s
            backoff = min(5 * (2 ** state.consecutive_429s), 120)
            state.backoff_until = time.time() + backoff
            state.current_rps = max(state.current_rps * 0.5, self.min_rps)
            logger.warning(
                f"Rate limit hit on {domain}: backing off {backoff}s, "
                f"reducing to {state.current_rps:.1f} rps"
            )
        elif state.consecutive_errors >= 3:
            state.current_rps = max(state.current_rps * 0.7, self.min_rps)
            state.backoff_until = time.time() + 5
            logger.warning(f"Multiple errors on {domain}, slowing down")

    def get_stats(self) -> Dict[str, dict]:
        """Get rate limiting statistics per domain."""
        stats = {}
        for domain, state in self._domains.items():
            stats[domain] = {
                "requests_sent": state.requests_sent,
                "current_rps": round(state.current_rps, 2),
                "total_wait_seconds": round(state.total_wait_time, 1),
                "consecutive_errors": state.consecutive_errors,
                "in_backoff": state.backoff_until > time.time(),
            }
        return stats
