"""
GetNexova Tool Health Gate
===========================
Checks availability of all required external tools at startup.
Supports graceful degradation - missing tools trigger warnings,
not failures. Phases that depend on unavailable tools are skipped.
"""

import shutil
import subprocess
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger("getnexova.tool_health")


class ToolCategory(Enum):
    """Categories for grouping tools by function."""
    RECON = "reconnaissance"
    SCANNING = "scanning"
    WEB_SCAN = "web_scanning"
    CODE_ANALYSIS = "code_analysis"
    NETWORK = "network"
    UTILITY = "utility"


@dataclass
class ToolInfo:
    """Information about an external tool."""
    name: str
    category: ToolCategory
    required: bool = False  # If True, scan cannot proceed without it
    check_command: Optional[str] = None  # Command to verify tool works
    version_flag: str = "--version"
    description: str = ""
    install_hint: str = ""


# ─── Tool Registry ───────────────────────────────────────────────────
TOOL_REGISTRY: List[ToolInfo] = [
    # Core recon tools (required for basic operation)
    ToolInfo("subfinder", ToolCategory.RECON, required=True,
             description="Subdomain discovery",
             install_hint="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ToolInfo("httpx", ToolCategory.RECON, required=True,
             description="HTTP probing",
             install_hint="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ToolInfo("nuclei", ToolCategory.SCANNING, required=True,
             description="Template-based vulnerability scanner",
             install_hint="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),

    # Web scanning tools (optional, enhance coverage)
    ToolInfo("dalfox", ToolCategory.WEB_SCAN,
             description="XSS scanner",
             install_hint="go install github.com/hahwul/dalfox/v2@latest"),
    ToolInfo("nikto", ToolCategory.WEB_SCAN,
             check_command="nikto -Version",
             description="Web server scanner",
             install_hint="apt install nikto"),
    ToolInfo("wapiti", ToolCategory.WEB_SCAN,
             description="Web application vulnerability scanner",
             install_hint="pip install wapiti3"),

    # Network tools (deep mode)
    ToolInfo("nmap", ToolCategory.NETWORK,
             description="Network scanner and service detection",
             install_hint="apt install nmap"),
    ToolInfo("dnsrecon", ToolCategory.NETWORK,
             description="DNS enumeration",
             install_hint="pip install dnsrecon"),
    ToolInfo("dnsenum", ToolCategory.NETWORK,
             description="DNS enumeration",
             install_hint="apt install dnsenum"),

    # Code analysis
    ToolInfo("gitleaks", ToolCategory.CODE_ANALYSIS,
             description="Secret detection in git repos",
             install_hint="go install github.com/gitleaks/gitleaks/v8@latest"),
    ToolInfo("semgrep", ToolCategory.CODE_ANALYSIS,
             description="Static analysis for code patterns",
             install_hint="pip install semgrep"),

    # WordPress
    ToolInfo("wpscan", ToolCategory.WEB_SCAN,
             description="WordPress security scanner",
             install_hint="gem install wpscan"),

    # Utilities
    ToolInfo("jq", ToolCategory.UTILITY,
             description="JSON processor",
             install_hint="apt install jq"),
    ToolInfo("curl", ToolCategory.UTILITY, required=True,
             description="HTTP client",
             install_hint="apt install curl"),
]


@dataclass
class HealthReport:
    """Results of the tool health check."""
    available: Dict[str, str] = field(default_factory=dict)     # tool -> version
    missing: Dict[str, ToolInfo] = field(default_factory=dict)  # tool -> info
    errors: Dict[str, str] = field(default_factory=dict)        # tool -> error msg
    critical_missing: List[str] = field(default_factory=list)   # required but missing

    @property
    def healthy(self) -> bool:
        """True if all required tools are available."""
        return len(self.critical_missing) == 0

    @property
    def available_categories(self) -> Dict[ToolCategory, List[str]]:
        """Group available tools by category."""
        result: Dict[ToolCategory, List[str]] = {}
        for tool_name in self.available:
            for t in TOOL_REGISTRY:
                if t.name == tool_name:
                    result.setdefault(t.category, []).append(tool_name)
                    break
        return result

    def summary(self) -> str:
        """Generate a human-readable health summary."""
        lines = [
            f"╔══════════════════════════════════════════╗",
            f"║     GetNexova Tool Health Report         ║",
            f"╠══════════════════════════════════════════╣",
            f"║  Available: {len(self.available):3d}  │  Missing: {len(self.missing):3d}       ║",
        ]
        if self.critical_missing:
            lines.append(f"║  ⚠ CRITICAL MISSING: {', '.join(self.critical_missing):<17s} ║")
        lines.append(f"╚══════════════════════════════════════════╝")
        return "\n".join(lines)


def _check_tool(tool: ToolInfo) -> Tuple[bool, str]:
    """
    Check if a tool is available and get its version.

    Returns:
        Tuple of (available, version_or_error)
    """
    # First check if binary exists in PATH
    path = shutil.which(tool.name)
    if not path:
        return False, "not found in PATH"

    # Try to get version
    try:
        cmd = tool.check_command or f"{tool.name} {tool.version_flag}"
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=10,
        )
        version_output = (result.stdout or result.stderr).strip()
        # Extract first line as version
        version = version_output.split("\n")[0][:80] if version_output else "unknown"
        return True, version
    except subprocess.TimeoutExpired:
        return True, "timeout (but binary exists)"
    except Exception as e:
        return True, f"exists but version check failed: {e}"


def check_all_tools(
    extra_tools: Optional[List[ToolInfo]] = None,
) -> HealthReport:
    """
    Run health checks on all registered tools.

    Args:
        extra_tools: Additional tools to check beyond the registry

    Returns:
        HealthReport with results
    """
    report = HealthReport()
    tools_to_check = list(TOOL_REGISTRY)
    if extra_tools:
        tools_to_check.extend(extra_tools)

    for tool in tools_to_check:
        available, info = _check_tool(tool)
        if available:
            report.available[tool.name] = info
            logger.debug(f"✓ {tool.name}: {info}")
        else:
            report.missing[tool.name] = tool
            if tool.required:
                report.critical_missing.append(tool.name)
                logger.error(f"✗ {tool.name} (REQUIRED): {info}")
            else:
                logger.warning(f"✗ {tool.name}: {info} → install: {tool.install_hint}")

    return report


def is_tool_available(tool_name: str, report: Optional[HealthReport] = None) -> bool:
    """Quick check if a specific tool is available."""
    if report:
        return tool_name in report.available
    return shutil.which(tool_name) is not None


def get_available_tools_for_category(
    category: ToolCategory,
    report: HealthReport,
) -> List[str]:
    """Get list of available tools for a given category."""
    return report.available_categories.get(category, [])
