"""
GetNexova Configuration Module
===============================
Centralized configuration management with environment variable support,
validation, and sensible defaults.
"""

import os
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any

logger = logging.getLogger("getnexova.config")

# ─── Project Paths ────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
PLUGINS_DIR = BASE_DIR / "plugins"
SKILLS_DIR = BASE_DIR / "skills"
AGENTS_DEF_DIR = BASE_DIR / "agents_definitions"
MEMORY_DIR = BASE_DIR / "memory" / "store"
KNOWLEDGE_DB = DATA_DIR / "knowledge.db"

# Ensure critical dirs exist
for d in [DATA_DIR, REPORTS_DIR, LOGS_DIR, MEMORY_DIR]:
    d.mkdir(parents=True, exist_ok=True)


@dataclass
class LLMConfig:
    """Configuration for the unified LLM engine."""
    # Free-tier models (tried first)
    free_models: List[str] = field(default_factory=lambda: [
        "groq/llama-3.1-70b-versatile",
        "gemini/gemini-2.0-flash",
    ])
    # Paid models (used if free fail and budget permits)
    paid_models: List[str] = field(default_factory=lambda: [
        "anthropic/claude-sonnet-4-20250514",
    ])
    # Local fallback
    local_models: List[str] = field(default_factory=lambda: [
        "ollama/llama3.1",
        "ollama/mistral",
    ])
    # Budget limits
    max_cost_per_run: float = 5.0
    max_cost_per_month: float = 50.0
    # Retry settings
    max_retries: int = 3
    retry_delay: float = 2.0
    # Token limits
    max_input_tokens: int = 8000
    max_output_tokens: int = 4096
    # Temperature defaults per task
    temperatures: Dict[str, float] = field(default_factory=lambda: {
        "classify": 0.1,
        "cvss": 0.0,
        "chain": 0.3,
        "report": 0.2,
        "analysis": 0.2,
        "planning": 0.4,
    })


@dataclass
class ScanConfig:
    """Configuration for scanning modes and tool parameters."""
    mode: str = "standard"  # quick | standard | deep
    max_concurrent_scans: int = 5
    timeout_per_tool: int = 300  # seconds
    # Recon settings
    subdomain_wordlist: str = "/usr/share/wordlists/subdomains-top1million-5000.txt"
    # Nmap settings (deep mode)
    nmap_flags: str = "-sV -sC -T4"
    # Rate limiting
    requests_per_second: int = 10
    # Scope enforcement
    scope_strict: bool = True


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    format: str = "html"  # html | json | markdown | all
    include_pocs: bool = True
    include_screenshots: bool = True
    template_dir: Path = field(default_factory=lambda: BASE_DIR / "reports" / "templates")
    output_dir: Path = field(default_factory=lambda: REPORTS_DIR)


@dataclass
class NotificationConfig:
    """Notification channel settings."""
    discord_webhook: Optional[str] = None
    slack_webhook: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    notify_on: List[str] = field(default_factory=lambda: [
        "critical", "high", "scan_complete", "error"
    ])


@dataclass
class DockerConfig:
    """Docker and microservices configuration."""
    advanced_tools_url: str = "http://advanced-tools:5050"
    advanced_tools_enabled: bool = False
    network_name: str = "getnexova-net"


@dataclass
class SecurityConfig:
    """Security and encryption settings."""
    encryption_key_file: str = ".nexova_key"
    knowledge_encrypted: bool = True
    scope_enforcement: bool = True
    # Tools that are ALLOWED in the advanced container
    allowed_tools: List[str] = field(default_factory=lambda: [
        "nmap", "dnsrecon", "dnsenum", "nikto", "wapiti",
        "gitleaks", "semgrep", "wpscan", "subfinder",
        "httpx", "nuclei", "dalfox",
    ])


class GetNexovaConfig:
    """
    Master configuration object that aggregates all sub-configs
    and loads from environment variables / config files.
    """

    def __init__(self, config_file: Optional[str] = None):
        self.llm = LLMConfig()
        self.scan = ScanConfig()
        self.report = ReportConfig()
        self.notification = NotificationConfig()
        self.docker = DockerConfig()
        self.security = SecurityConfig()
        self._load_env()
        if config_file:
            self._load_file(config_file)

    def _load_env(self) -> None:
        """Load configuration from environment variables."""
        # LLM API keys
        self.groq_api_key = os.getenv("GROQ_API_KEY", "")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

        # Scan mode
        mode = os.getenv("NEXOVA_MODE", "standard")
        if mode in ("quick", "standard", "deep"):
            self.scan.mode = mode

        # Notifications
        self.notification.discord_webhook = os.getenv("DISCORD_WEBHOOK")
        self.notification.slack_webhook = os.getenv("SLACK_WEBHOOK")
        self.notification.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.notification.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")

        # Docker
        self.docker.advanced_tools_url = os.getenv(
            "ADVANCED_TOOLS_URL", self.docker.advanced_tools_url
        )
        self.docker.advanced_tools_enabled = os.getenv(
            "ADVANCED_TOOLS_ENABLED", "false"
        ).lower() == "true"

        # Budget
        max_cost = os.getenv("MAX_COST_PER_RUN")
        if max_cost:
            try:
                self.llm.max_cost_per_run = float(max_cost)
            except ValueError:
                pass

    def _load_file(self, path: str) -> None:
        """Load configuration overrides from a JSON file."""
        config_path = Path(path)
        if not config_path.exists():
            logger.warning(f"Config file not found: {path}")
            return
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
            # Apply overrides
            for section_name, section_data in data.items():
                section = getattr(self, section_name, None)
                if section and isinstance(section_data, dict):
                    for key, value in section_data.items():
                        if hasattr(section, key):
                            setattr(section, key, value)
            logger.info(f"Loaded config from {path}")
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize config to dictionary (redacting secrets)."""
        from dataclasses import asdict
        result = {
            "llm": asdict(self.llm),
            "scan": asdict(self.scan),
            "report": {k: str(v) if isinstance(v, Path) else v
                       for k, v in asdict(self.report).items()},
            "notification": {
                k: ("***" if v and "token" in k.lower() else v)
                for k, v in asdict(self.notification).items()
            },
            "docker": asdict(self.docker),
        }
        return result
