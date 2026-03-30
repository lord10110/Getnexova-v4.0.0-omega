"""
GetNexova Screenshot Capture
===============================
Captures screenshots of vulnerable endpoints for evidence.
Supports gowitness (preferred) or headless Chrome fallback.

Screenshots dramatically improve bug bounty report acceptance.
"""

import asyncio
import logging
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any

from core.tool_health import is_tool_available

logger = logging.getLogger("getnexova.screenshots")


class ScreenshotCapture:
    """
    Captures screenshots of URLs for visual evidence.

    Priority:
    1. gowitness (lightweight, purpose-built)
    2. chromium --headless (fallback)
    """

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir / "screenshots"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._tool = self._detect_tool()
        self._captured: List[Dict[str, str]] = []

    def _detect_tool(self) -> Optional[str]:
        """Detect which screenshot tool is available."""
        if shutil.which("gowitness"):
            logger.info("Screenshot tool: gowitness")
            return "gowitness"
        for chrome in ["chromium", "chromium-browser", "google-chrome", "chrome"]:
            if shutil.which(chrome):
                logger.info(f"Screenshot tool: {chrome}")
                return chrome
        logger.warning("No screenshot tool available (install gowitness)")
        return None

    @property
    def is_available(self) -> bool:
        return self._tool is not None

    async def capture_url(self, url: str, label: str = "") -> Optional[str]:
        """
        Capture a screenshot of a single URL.

        Returns the file path of the screenshot, or None on failure.
        """
        if not self._tool:
            return None

        # Generate safe filename
        safe_name = (
            url.replace("https://", "").replace("http://", "")
            .replace("/", "_").replace("?", "_").replace("&", "_")
            .replace(":", "_")[:80]
        )
        if label:
            safe_name = f"{label}_{safe_name}"
        output_file = self.output_dir / f"{safe_name}.png"

        try:
            if self._tool == "gowitness":
                proc = await asyncio.create_subprocess_exec(
                    "gowitness", "single", url,
                    "--screenshot-path", str(self.output_dir),
                    "--disable-logging",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.communicate(), timeout=30)
                # gowitness names files by URL hash — find the latest
                screenshots = sorted(
                    self.output_dir.glob("*.png"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if screenshots:
                    latest = screenshots[0]
                    if latest != output_file:
                        latest.rename(output_file)
            else:
                # Headless Chrome
                proc = await asyncio.create_subprocess_exec(
                    self._tool,
                    "--headless", "--disable-gpu", "--no-sandbox",
                    f"--screenshot={output_file}",
                    "--window-size=1280,1024",
                    f"--virtual-time-budget=5000",
                    url,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.communicate(), timeout=30)

            if output_file.exists():
                self._captured.append({
                    "url": url,
                    "file": str(output_file),
                    "label": label,
                })
                logger.debug(f"Screenshot captured: {url}")
                return str(output_file)

        except asyncio.TimeoutError:
            logger.warning(f"Screenshot timed out: {url}")
        except Exception as e:
            logger.warning(f"Screenshot failed for {url}: {e}")

        return None

    async def capture_findings(
        self,
        findings: List[Dict[str, Any]],
        max_screenshots: int = 20,
    ) -> Dict[str, str]:
        """
        Capture screenshots for validated findings.

        Returns dict of finding_id → screenshot_path.
        """
        if not self._tool:
            logger.info("No screenshot tool — skipping captures")
            return {}

        result: Dict[str, str] = {}
        count = 0

        # Prioritize by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "low"), 4),
        )

        sem = asyncio.Semaphore(3)  # Max 3 concurrent screenshots

        for finding in sorted_findings:
            if count >= max_screenshots:
                break

            url = finding.get("url") or finding.get("target", "")
            if not url or not url.startswith("http"):
                continue

            fid = finding.get("id", f"finding-{count}")
            async with sem:
                path = await self.capture_url(url, label=fid)
                if path:
                    result[fid] = path
                    count += 1

        logger.info(f"Captured {len(result)} screenshots for findings")
        return result

    async def capture_batch(
        self, urls: List[str], label_prefix: str = "scan"
    ) -> int:
        """Capture screenshots for a batch of URLs using gowitness bulk."""
        if self._tool != "gowitness":
            # Fall back to individual captures
            count = 0
            for url in urls[:20]:
                if await self.capture_url(url, f"{label_prefix}_{count}"):
                    count += 1
            return count

        # Use gowitness file mode for bulk capture
        url_file = self.output_dir.parent / "screenshot_urls.txt"
        url_file.write_text("\n".join(urls[:50]) + "\n")

        try:
            proc = await asyncio.create_subprocess_exec(
                "gowitness", "file",
                "-f", str(url_file),
                "--screenshot-path", str(self.output_dir),
                "--disable-logging",
                "--threads", "3",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)

            captured = list(self.output_dir.glob("*.png"))
            logger.info(f"Bulk screenshot: {len(captured)} captures")
            return len(captured)

        except asyncio.TimeoutError:
            logger.warning("Bulk screenshot timed out")
        except Exception as e:
            logger.error(f"Bulk screenshot error: {e}")

        return 0

    def get_summary(self) -> Dict[str, Any]:
        return {
            "tool": self._tool or "none",
            "available": self.is_available,
            "captured": len(self._captured),
            "output_dir": str(self.output_dir),
        }
