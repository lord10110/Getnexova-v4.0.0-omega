"""
GetNexova ClawTeam Integration
=================================
Distributed agent system that dispatches scanning tasks to the
advanced tools Docker container via its REST API.

Supports both aiohttp (preferred) and urllib (fallback).
"""

import json
import logging
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger("getnexova.clawteam")

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

if not AIOHTTP_AVAILABLE:
    from urllib.request import Request, urlopen
    from urllib.error import URLError

ALLOWED_TOOLS = {
    "nmap", "masscan", "dnsrecon", "dnsenum",
    "nikto", "wapiti", "wpscan",
    "gitleaks", "semgrep", "searchsploit",
    "subfinder", "httpx", "nuclei", "dalfox",
}
FORBIDDEN_CHARS = set(";|&`$(){}[]\\'\"\n\r")


@dataclass
class ClawTeamConfig:
    enabled: bool = False
    api_url: str = "http://advanced-tools:5050"
    default_timeout: int = 300
    max_timeout: int = 900
    daily_budget_usd: float = 10.0
    retry_on_failure: bool = True
    max_retries: int = 2


class ClawTeamManager:
    def __init__(self, config: Optional[ClawTeamConfig] = None, workspace: Optional[Path] = None):
        self.config = config or ClawTeamConfig()
        self.workspace = workspace
        self._api_url = self.config.api_url.rstrip("/")
        self._available = False
        self._stats: Dict[str, Any] = {"dispatched": 0, "succeeded": 0, "failed": 0, "timed_out": 0, "tools_used": {}}

    @property
    def is_available(self) -> bool:
        return self.config.enabled and self._available

    async def initialize(self) -> bool:
        if not self.config.enabled:
            return False
        self._available = await self.health_check()
        if self._available:
            logger.info("ClawTeam advanced tools container is available")
        else:
            logger.warning("ClawTeam container not reachable — deep scan tools will be skipped")
        return self._available

    async def health_check(self) -> bool:
        if not self.config.enabled:
            return False
        try:
            result = await self._async_get(f"{self._api_url}/health")
            if result:
                return json.loads(result).get("status") == "ok"
        except Exception:
            pass
        return False

    async def dispatch_advanced_tool(self, tool: str, args: List[str], timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
        if not self.config.enabled:
            return None
        if tool not in ALLOWED_TOOLS:
            logger.error(f"Tool '{tool}' not in allowed list")
            return None

        safe_args = [a for a in args if not any(c in a for c in FORBIDDEN_CHARS)]
        effective_timeout = min(timeout or self.config.default_timeout, self.config.max_timeout)
        payload = {"tool": tool, "args": safe_args, "timeout": effective_timeout}

        self._stats["dispatched"] += 1
        self._stats["tools_used"][tool] = self._stats["tools_used"].get(tool, 0) + 1

        max_attempts = self.config.max_retries + 1 if self.config.retry_on_failure else 1
        for attempt in range(max_attempts):
            try:
                result = await self._async_post(f"{self._api_url}/run", payload, timeout=effective_timeout + 30)
                if result:
                    data = json.loads(result)
                    if data.get("timed_out"):
                        self._stats["timed_out"] += 1
                    else:
                        self._stats["succeeded"] += 1
                    return data
            except Exception as e:
                logger.warning(f"ClawTeam dispatch attempt {attempt+1}/{max_attempts} for {tool}: {e}")
                if attempt < max_attempts - 1:
                    await asyncio.sleep(2 * (attempt + 1))

        self._stats["failed"] += 1
        return None

    async def list_available_tools(self) -> Dict[str, Any]:
        if not self.config.enabled:
            return {}
        try:
            result = await self._async_get(f"{self._api_url}/tools")
            if result:
                return json.loads(result).get("tools", {})
        except Exception:
            pass
        return {}

    async def _async_get(self, url: str) -> Optional[str]:
        if AIOHTTP_AVAILABLE:
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        return await r.text()
            except Exception:
                return None
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._sync_get, url)

    async def _async_post(self, url: str, payload: Dict, timeout: int = 300) -> Optional[str]:
        if AIOHTTP_AVAILABLE:
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
                    async with s.post(url, json=payload) as r:
                        return await r.text()
            except asyncio.TimeoutError:
                return None
            except Exception:
                return None
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._sync_post, url, json.dumps(payload).encode(), timeout)

    @staticmethod
    def _sync_get(url: str) -> Optional[str]:
        try:
            req = Request(url, method="GET")
            with urlopen(req, timeout=10) as resp:
                return resp.read().decode("utf-8")
        except Exception:
            return None

    @staticmethod
    def _sync_post(url: str, payload: bytes, timeout: int = 300) -> Optional[str]:
        try:
            req = Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except Exception as e:
            logger.error(f"ClawTeam POST failed: {e}")
            return None

    def get_summary(self) -> Dict[str, Any]:
        return {"enabled": self.config.enabled, "available": self._available, "stats": dict(self._stats)}

    async def close(self) -> None:
        pass
