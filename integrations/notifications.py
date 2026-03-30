"""
GetNexova Notification System
===============================
Multi-channel notification dispatch for scan events.
Supports Discord webhooks, Slack webhooks, and Telegram bots.
"""

import json
import logging
import asyncio
from typing import Optional, Dict, Any, List
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger("getnexova.notifications")


class NotificationDispatcher:
    """
    Sends notifications about scan events to configured channels.

    Supports:
    - Discord webhooks
    - Slack webhooks
    - Telegram bot API
    """

    def __init__(
        self,
        discord_webhook: Optional[str] = None,
        slack_webhook: Optional[str] = None,
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
        notify_on: Optional[List[str]] = None,
    ):
        self.discord_webhook = discord_webhook
        self.slack_webhook = slack_webhook
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.notify_on = notify_on or ["critical", "high", "scan_complete", "error"]
        self._enabled = any([discord_webhook, slack_webhook, telegram_token])

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    async def notify(
        self,
        event_type: str,
        title: str,
        message: str,
        severity: str = "info",
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Send a notification to all configured channels.

        Args:
            event_type: Type of event (critical, high, scan_complete, error)
            title: Notification title
            message: Notification body
            severity: Severity level for coloring
            data: Additional structured data
        """
        if not self._enabled:
            return
        if event_type not in self.notify_on:
            return

        tasks = []
        if self.discord_webhook:
            tasks.append(self._send_discord(title, message, severity, data))
        if self.slack_webhook:
            tasks.append(self._send_slack(title, message, severity, data))
        if self.telegram_token and self.telegram_chat_id:
            tasks.append(self._send_telegram(title, message, data))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Notification failed: {result}")

    async def _send_discord(
        self,
        title: str,
        message: str,
        severity: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Send Discord webhook notification."""
        colors = {
            "critical": 0xDC2626,
            "high": 0xEA580C,
            "medium": 0xD97706,
            "low": 0x2563EB,
            "info": 0x6B7280,
        }

        embed = {
            "title": f"🔍 GetNexova: {title}",
            "description": message[:2000],
            "color": colors.get(severity, 0x6B7280),
            "footer": {"text": "GetNexova v4.0.0 OMEGA"},
        }

        if data:
            embed["fields"] = [
                {"name": k, "value": str(v)[:200], "inline": True}
                for k, v in list(data.items())[:5]
            ]

        payload = json.dumps({"embeds": [embed]}).encode("utf-8")
        await self._http_post(self.discord_webhook, payload)

    async def _send_slack(
        self,
        title: str,
        message: str,
        severity: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Send Slack webhook notification."""
        emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji.get(severity, '🔍')} GetNexova: {title}",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message[:2000]},
            },
        ]

        payload = json.dumps({"blocks": blocks}).encode("utf-8")
        await self._http_post(self.slack_webhook, payload)

    async def _send_telegram(
        self,
        title: str,
        message: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Send Telegram bot notification."""
        text = f"*🔍 GetNexova: {title}*\n\n{message}"
        if data:
            text += "\n\n" + "\n".join(
                f"• *{k}*: {v}" for k, v in list(data.items())[:5]
            )

        url = (
            f"https://api.telegram.org/bot{self.telegram_token}/"
            f"sendMessage"
        )
        payload = json.dumps({
            "chat_id": self.telegram_chat_id,
            "text": text[:4000],
            "parse_mode": "Markdown",
        }).encode("utf-8")
        await self._http_post(url, payload)

    async def _http_post(self, url: str, payload: bytes) -> None:
        """Send HTTP POST request (async wrapper around urllib)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sync_post, url, payload)

    @staticmethod
    def _sync_post(url: str, payload: bytes) -> None:
        """Synchronous HTTP POST."""
        try:
            req = Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                if resp.status >= 400:
                    logger.warning(f"Notification HTTP {resp.status}")
        except URLError as e:
            logger.error(f"Notification request failed: {e}")
        except Exception as e:
            logger.error(f"Notification error: {e}")
