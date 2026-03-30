"""
GetNexova Parallel Executor
==============================
High-level parallel execution manager with resource-aware
scheduling, error isolation, and progress tracking.
"""

import asyncio
import logging
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional, TypeVar

logger = logging.getLogger("getnexova.parallel")

T = TypeVar("T")


class ParallelExecutor:
    """
    Executes async tasks in parallel with concurrency control,
    error isolation, and optional integration with MaestroResourceManager.
    """

    def __init__(
        self,
        max_workers: int = 4,
        maestro: Optional[Any] = None,
    ):
        self.max_workers = max_workers
        self.maestro = maestro
        self._semaphore = asyncio.Semaphore(max_workers)
        self._completed = 0
        self._failed = 0
        self._total = 0

    async def run_all(
        self,
        tasks: List[Callable[[], Coroutine]],
        description: str = "tasks",
    ) -> List[Any]:
        """
        Execute a list of async callables in parallel.

        Args:
            tasks: List of zero-argument async callables
            description: Description for logging

        Returns:
            List of results (None for failed tasks)
        """
        self._total = len(tasks)
        self._completed = 0
        self._failed = 0

        if not tasks:
            return []

        # Adjust concurrency based on Maestro if available
        if self.maestro:
            conc = self.maestro.recommended_concurrency
            self._semaphore = asyncio.Semaphore(min(conc, self.max_workers))

        logger.info(f"Executing {len(tasks)} {description} in parallel "
                     f"(max {self._semaphore._value} workers)")

        async def _wrapped(idx: int, task: Callable) -> tuple:
            async with self._semaphore:
                # Wait if Maestro says resources are critical
                if self.maestro:
                    await self.maestro.wait_if_needed()
                try:
                    result = await task()
                    self._completed += 1
                    return idx, result
                except Exception as e:
                    self._failed += 1
                    logger.warning(f"Parallel task {idx} failed: {e}")
                    return idx, None

        results_tuples = await asyncio.gather(
            *[_wrapped(i, t) for i, t in enumerate(tasks)],
            return_exceptions=False,
        )

        # Reconstruct ordered results
        results = [None] * len(tasks)
        for idx, result in results_tuples:
            results[idx] = result

        logger.info(
            f"Parallel execution complete: {self._completed} ok, "
            f"{self._failed} failed out of {self._total}"
        )
        return results

    async def map_async(
        self,
        fn: Callable,
        items: List[Any],
        description: str = "items",
    ) -> List[Any]:
        """
        Apply an async function to each item in parallel.

        Like asyncio.gather but with concurrency limits.
        """
        tasks = [lambda item=item: fn(item) for item in items]
        return await self.run_all(tasks, description)

    def get_stats(self) -> Dict[str, int]:
        return {
            "total": self._total,
            "completed": self._completed,
            "failed": self._failed,
        }
