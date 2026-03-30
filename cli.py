#!/usr/bin/env python3
"""
GetNexova CLI Entry Point
===========================
Command-line interface for the GetNexova bug bounty automation platform.

Usage:
    nexova -t target.com --mode standard
    nexova -t target.com --mode deep --report-format html
    nexova -t target.com --mode quick --no-ai
    nexova --health-check
    nexova --stats
"""

import argparse
import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import GetNexovaConfig
from core import __version__, __codename__, __project__


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="nexova",
        description=(
            f"{__project__} v{__version__} {__codename__} — "
            f"Bug Bounty Automation Platform"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nexova -t example.com                     Standard scan
  nexova -t example.com --mode deep         Deep scan with advanced tools
  nexova -t example.com --mode quick        Quick surface scan
  nexova -t example.com --no-ai             Tools only, no AI analysis
  nexova -t example.com --exclude staging   Exclude subdomains
  nexova --health-check                     Check tool availability
  nexova --stats                            Show knowledge base stats

Environment Variables:
  GROQ_API_KEY          Groq API key (free tier)
  GEMINI_API_KEY        Google Gemini API key (free tier)
  ANTHROPIC_API_KEY     Anthropic API key (paid tier)
  OLLAMA_BASE_URL       Ollama server URL (default: http://localhost:11434)
  DISCORD_WEBHOOK       Discord notification webhook URL
  SLACK_WEBHOOK         Slack notification webhook URL
  TELEGRAM_BOT_TOKEN    Telegram bot token
  TELEGRAM_CHAT_ID      Telegram chat ID
  MAX_COST_PER_RUN      Maximum LLM cost per run in USD (default: 5.0)
        """,
    )

    # Target
    parser.add_argument(
        "-t", "--target",
        help="Target domain to scan",
    )

    # Scan mode
    parser.add_argument(
        "--mode",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Scan mode: quick (fast), standard (thorough), deep (comprehensive)",
    )

    # AI options
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI analysis (tools only)",
    )

    # Report options
    parser.add_argument(
        "--report-format",
        choices=["html", "markdown", "json", "all"],
        default="all",
        help="Report output format (default: all)",
    )

    # Scope options
    parser.add_argument(
        "--exclude",
        nargs="*",
        help="Domains to exclude from scope",
    )
    parser.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Do not include subdomains in scope",
    )

    # Configuration
    parser.add_argument(
        "--config",
        help="Path to JSON configuration file",
    )
    parser.add_argument(
        "--max-cost",
        type=float,
        help="Maximum LLM cost for this run (USD)",
    )

    # Utility commands
    parser.add_argument(
        "--health-check",
        action="store_true",
        help="Check tool availability and exit",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show knowledge base statistics and exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__project__} v{__version__} {__codename__}",
    )

    # Authentication
    parser.add_argument(
        "--auth-token",
        default="",
        help="Bearer token for authenticated scanning",
    )
    parser.add_argument(
        "--auth-cookies",
        default="",
        help='Cookies for authenticated scanning (e.g. "session=abc; csrf=xyz")',
    )

    # Resume
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last checkpoint for this target",
    )

    # Advanced
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout per tool in seconds (default: 300)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="Max concurrent tool executions (default: 3)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug output",
    )

    return parser.parse_args()


async def run_health_check() -> None:
    """Run tool health check and display results."""
    from core.tool_health import check_all_tools

    print(f"\n{__project__} v{__version__} — Tool Health Check\n")
    report = check_all_tools()
    print(report.summary())

    print("\n✓ Available tools:")
    for tool, version in sorted(report.available.items()):
        print(f"  ✅ {tool:<20s} {version[:60]}")

    if report.missing:
        print("\n✗ Missing tools:")
        for tool, info in sorted(report.missing.items()):
            marker = "🔴 REQUIRED" if info.required else "⚠️  optional"
            print(f"  {marker} {tool:<20s} → {info.install_hint}")


async def run_stats() -> None:
    """Show knowledge base statistics."""
    from memory.knowledge_base import KnowledgeBase
    from core.config import DATA_DIR

    kb = KnowledgeBase(db_path=DATA_DIR / "knowledge.db")
    stats = kb.get_statistics()

    print(f"\n{__project__} v{__version__} — Knowledge Base Stats\n")
    print(f"  Total scans:     {stats['total_scans']}")
    print(f"  Total findings:  {stats['total_findings']}")
    print(f"  Validated:       {stats['validated_findings']}")
    print(f"  Targets scanned: {stats['total_targets']}")

    if stats['severity_distribution']:
        print(f"\n  Severity distribution:")
        for sev, count in sorted(stats['severity_distribution'].items()):
            print(f"    {sev:<12s} {count}")


async def main() -> None:
    """Main entry point."""
    args = parse_args()

    # Utility commands
    if args.health_check:
        await run_health_check()
        return

    if args.stats:
        await run_stats()
        return

    # Target is required for scanning
    if not args.target:
        print(f"Error: --target / -t is required for scanning")
        print(f"Use --help for usage information")
        sys.exit(1)

    # Build config
    config = GetNexovaConfig(config_file=args.config)
    config.scan.mode = args.mode
    config.scan.timeout_per_tool = args.timeout
    config.scan.max_concurrent_scans = args.concurrency

    if args.max_cost:
        config.llm.max_cost_per_run = args.max_cost

    # Run pipeline
    from nexova import GetNexova

    engine = GetNexova(config=config)
    result = await engine.run(
        target=args.target,
        mode=args.mode,
        exclude_domains=args.exclude,
        no_ai=args.no_ai,
        report_format=args.report_format,
        resume=args.resume,
        auth_token=args.auth_token,
        auth_cookies=args.auth_cookies,
    )

    # Exit code based on findings
    if result.errors:
        sys.exit(2)
    elif result.severity_summary.get("critical", 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
