"""
GetNexova Auth Handler
========================
Manages authentication for scanning targets that require
login sessions. Supports token-based, cookie-based, and
form-based authentication.
"""

import logging
import json
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any

logger = logging.getLogger("getnexova.auth")


@dataclass
class AuthConfig:
    """Authentication configuration for a target."""
    auth_token: str = ""
    auth_cookies: str = ""       # "name1=val1; name2=val2"
    login_url: str = ""
    login_user: str = ""
    login_pass: str = ""
    custom_headers: Dict[str, str] = field(default_factory=dict)
    bearer_prefix: str = "Bearer"


class AuthHandler:
    """
    Manages authentication state for scanner tools.

    Provides headers and cookies for authenticated scanning,
    handles session refresh, and injects auth into tool commands.
    """

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self._session_cookies: Dict[str, str] = {}
        self._session_token: str = ""
        self._authenticated = False

    @property
    def is_configured(self) -> bool:
        """Check if any auth method is configured."""
        c = self.config
        return bool(c.auth_token or c.auth_cookies or c.login_url)

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    def setup(
        self,
        token: str = "",
        cookies: str = "",
        login_url: str = "",
        username: str = "",
        password: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Configure authentication parameters."""
        self.config = AuthConfig(
            auth_token=token,
            auth_cookies=cookies,
            login_url=login_url,
            login_user=username,
            login_pass=password,
            custom_headers=headers or {},
        )

        if token:
            self._session_token = token
            self._authenticated = True
            logger.info("Auth configured: token-based")
        elif cookies:
            self._parse_cookies(cookies)
            self._authenticated = True
            logger.info("Auth configured: cookie-based")
        elif login_url:
            logger.info("Auth configured: form-based (login required)")

    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for HTTP requests."""
        headers = dict(self.config.custom_headers)

        if self._session_token:
            prefix = self.config.bearer_prefix
            headers["Authorization"] = f"{prefix} {self._session_token}"

        if self._session_cookies:
            cookie_str = "; ".join(
                f"{k}={v}" for k, v in self._session_cookies.items()
            )
            headers["Cookie"] = cookie_str

        return headers

    def get_cookie_string(self) -> str:
        """Get cookies as a single string for CLI tools."""
        if self._session_cookies:
            return "; ".join(
                f"{k}={v}" for k, v in self._session_cookies.items()
            )
        return self.config.auth_cookies

    def inject_into_command(self, cmd: List[str], tool: str) -> List[str]:
        """
        Inject auth parameters into a tool's command line.

        Different tools accept auth in different ways:
        - nuclei: -H "Cookie: ..."
        - httpx: -H "Cookie: ..."
        - dalfox: --cookie "..."
        - nikto: -id user:pass
        - wpscan: --cookie "..."
        """
        headers = self.get_headers()
        cookies = self.get_cookie_string()

        if not headers and not cookies:
            return cmd

        if tool in ("nuclei", "httpx"):
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        elif tool == "dalfox":
            if cookies:
                cmd.extend(["--cookie", cookies])
            if "Authorization" in headers:
                cmd.extend(["-H", f"Authorization: {headers['Authorization']}"])
        elif tool == "nikto":
            if self.config.login_user and self.config.login_pass:
                cmd.extend(["-id", f"{self.config.login_user}:{self.config.login_pass}"])
        elif tool == "wpscan":
            if cookies:
                cmd.extend(["--cookie", cookies])
        elif tool == "nmap":
            # nmap doesn't use HTTP auth directly
            pass
        else:
            # Generic: add headers for any tool that supports -H
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

        return cmd

    def _parse_cookies(self, cookie_string: str) -> None:
        """Parse a cookie string into key-value pairs."""
        self._session_cookies.clear()
        for part in cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                self._session_cookies[key.strip()] = value.strip()

    def get_summary(self) -> Dict[str, Any]:
        """Get auth summary for reporting (redacted)."""
        return {
            "configured": self.is_configured,
            "authenticated": self._authenticated,
            "method": (
                "token" if self._session_token else
                "cookie" if self._session_cookies else
                "form" if self.config.login_url else
                "none"
            ),
            "has_custom_headers": bool(self.config.custom_headers),
        }
