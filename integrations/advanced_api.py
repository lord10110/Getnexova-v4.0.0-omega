"""
GetNexova Advanced Tools API Server
=====================================
Flask-based REST API that runs inside the advanced tools container.
Exposes whitelisted security tools via a /run endpoint.
"""

import subprocess
import shutil
import json
import os
import logging
from typing import Dict, Any, List

from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("advanced-api")

# ─── Tool Whitelist ───────────────────────────────────────────────────
# Only these tools can be executed via the API
ALLOWED_TOOLS: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "binary": "nmap",
        "max_timeout": 900,
        "description": "Network scanner and service detection",
    },
    "dnsrecon": {
        "binary": "dnsrecon",
        "max_timeout": 300,
        "description": "DNS enumeration",
    },
    "dnsenum": {
        "binary": "dnsenum",
        "max_timeout": 300,
        "description": "DNS enumeration",
    },
    "nikto": {
        "binary": "nikto",
        "max_timeout": 600,
        "description": "Web server vulnerability scanner",
    },
    "wapiti": {
        "binary": "wapiti",
        "max_timeout": 600,
        "description": "Web application vulnerability scanner",
    },
    "gitleaks": {
        "binary": "gitleaks",
        "max_timeout": 300,
        "description": "Secret and credential detection",
    },
    "semgrep": {
        "binary": "semgrep",
        "max_timeout": 300,
        "description": "Static code analysis",
    },
    "wpscan": {
        "binary": "wpscan",
        "max_timeout": 300,
        "description": "WordPress security scanner",
    },
    "subfinder": {
        "binary": "subfinder",
        "max_timeout": 300,
        "description": "Subdomain discovery",
    },
    "httpx": {
        "binary": "httpx",
        "max_timeout": 300,
        "description": "HTTP probing and analysis",
    },
    "nuclei": {
        "binary": "nuclei",
        "max_timeout": 600,
        "description": "Template-based vulnerability scanner",
    },
}

# Characters forbidden in arguments to prevent injection
FORBIDDEN_CHARS = set(";|&`$(){}[]\\'\"\n\r")


def sanitize_args(args: List[str]) -> List[str]:
    """Remove arguments containing dangerous characters."""
    safe = []
    for arg in args:
        if any(c in arg for c in FORBIDDEN_CHARS):
            logger.warning(f"Blocked suspicious argument: {arg[:50]}")
            continue
        safe.append(arg)
    return safe


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "service": "getnexova-advanced-tools"})


@app.route("/tools", methods=["GET"])
def list_tools():
    """List available tools and their status."""
    tools = {}
    for name, info in ALLOWED_TOOLS.items():
        binary = info["binary"]
        available = shutil.which(binary) is not None
        tools[name] = {
            "available": available,
            "description": info["description"],
        }
    return jsonify({"tools": tools})


@app.route("/run", methods=["POST"])
def run_tool():
    """
    Execute a whitelisted tool with given arguments.

    Request body:
        {
            "tool": "nmap",
            "args": ["-sV", "-T4", "example.com"],
            "timeout": 300
        }

    Response:
        {
            "tool": "nmap",
            "exit_code": 0,
            "output": "...",
            "errors": "...",
            "timed_out": false
        }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    tool_name = data.get("tool", "")
    args = data.get("args", [])
    timeout = min(data.get("timeout", 300), 900)  # Max 15 minutes

    # Validate tool
    if tool_name not in ALLOWED_TOOLS:
        return jsonify({
            "error": f"Tool '{tool_name}' is not allowed",
            "allowed_tools": list(ALLOWED_TOOLS.keys()),
        }), 403

    tool_info = ALLOWED_TOOLS[tool_name]
    binary = tool_info["binary"]

    # Check tool exists
    if not shutil.which(binary):
        return jsonify({
            "error": f"Tool '{tool_name}' is not installed",
        }), 503

    # Sanitize arguments
    safe_args = sanitize_args(args)

    # Enforce max timeout
    timeout = min(timeout, tool_info["max_timeout"])

    # Execute
    cmd = [binary] + safe_args
    logger.info(f"Executing: {' '.join(cmd[:10])}... (timeout={timeout}s)")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return jsonify({
            "tool": tool_name,
            "exit_code": result.returncode,
            "output": result.stdout[:50000],  # Limit output size
            "errors": result.stderr[:5000],
            "timed_out": False,
        })
    except subprocess.TimeoutExpired:
        return jsonify({
            "tool": tool_name,
            "exit_code": -1,
            "output": "",
            "errors": f"Timed out after {timeout}s",
            "timed_out": True,
        }), 408
    except Exception as e:
        logger.error(f"Execution error: {e}")
        return jsonify({
            "tool": tool_name,
            "exit_code": -1,
            "output": "",
            "errors": str(e),
            "timed_out": False,
        }), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5050"))
    app.run(host="0.0.0.0", port=port, debug=False)
