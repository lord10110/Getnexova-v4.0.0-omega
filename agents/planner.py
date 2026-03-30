"""
GetNexova Planner Agent
========================
Creates optimized reconnaissance and scanning plans based on
target type, scan mode, and available tools.
"""

import json
import logging
from typing import Dict, Any, List, Optional

from agents.agent_loader import load_agent_def
from agents.ai_engine import AIEngine, PromptBuilder
from core.tool_health import HealthReport

logger = logging.getLogger("getnexova.planner")


class PlannerAgent:
    """
    Plans reconnaissance and scanning phases.

    Considers available tools, scan mode, and target characteristics
    to build an optimal execution plan.
    """

    def __init__(self, ai_engine: AIEngine, health_report: HealthReport):
        self.ai = ai_engine
        self.health = health_report
        self.definition = load_agent_def("planner")
        self._default_plans = self._get_default_plans()

    async def create_plan(
        self,
        target: str,
        mode: str = "standard",
    ) -> Dict[str, Any]:
        """
        Create a scanning plan for the target.

        Args:
            target: Target domain or URL
            mode: Scan mode (quick/standard/deep)

        Returns:
            Execution plan with phases, tools, and ordering
        """
        available_tools = list(self.health.available.keys())

        # Try AI-powered planning first
        try:
            prompt = PromptBuilder.plan_recon(target, mode, available_tools)
            system_prompt = self.definition.soul or (
                "You are a bug bounty reconnaissance planner. "
                "Create efficient, thorough plans that maximize coverage "
                "while respecting rate limits and scope boundaries."
            )
            response = await self.ai.call(
                prompt=prompt,
                task_type="planning",
                system_prompt=system_prompt,
                json_mode=True,
            )
            if response:
                plan = json.loads(response)
                plan = self._validate_plan(plan, available_tools)
                logger.info(
                    f"AI plan created: {len(plan.get('phases', []))} phases, "
                    f"~{plan.get('total_estimated_time_minutes', '?')} min"
                )
                return plan
        except Exception as e:
            logger.warning(f"AI planning failed, using default plan: {e}")

        # Fallback to default plan
        return self._default_plans.get(mode, self._default_plans["standard"])

    def _validate_plan(
        self, plan: Dict[str, Any], available_tools: List[str]
    ) -> Dict[str, Any]:
        """Validate plan and remove phases requiring unavailable tools."""
        validated_phases = []
        for phase in plan.get("phases", []):
            phase_tools = phase.get("tools", [])
            # Keep phase if at least one tool is available
            available_phase_tools = [
                t for t in phase_tools if t in available_tools
            ]
            if available_phase_tools:
                phase["tools"] = available_phase_tools
                validated_phases.append(phase)
            else:
                logger.info(
                    f"Skipping phase '{phase.get('name')}' - "
                    f"no available tools: {phase_tools}"
                )
        plan["phases"] = validated_phases
        return plan

    def _get_default_plans(self) -> Dict[str, Dict[str, Any]]:
        """Get hardcoded fallback plans for each mode."""
        return {
            "quick": {
                "phases": [
                    {
                        "name": "subdomain_enum",
                        "tools": ["subfinder"],
                        "priority": 1,
                        "estimated_time_minutes": 3,
                        "depends_on": None,
                    },
                    {
                        "name": "http_probing",
                        "tools": ["httpx"],
                        "priority": 2,
                        "estimated_time_minutes": 2,
                        "depends_on": "subdomain_enum",
                    },
                ],
                "total_estimated_time_minutes": 5,
            },
            "standard": {
                "phases": [
                    {
                        "name": "subdomain_enum",
                        "tools": ["subfinder"],
                        "priority": 1,
                        "estimated_time_minutes": 5,
                        "depends_on": None,
                    },
                    {
                        "name": "http_probing",
                        "tools": ["httpx"],
                        "priority": 2,
                        "estimated_time_minutes": 3,
                        "depends_on": "subdomain_enum",
                    },
                    {
                        "name": "vulnerability_scan",
                        "tools": ["nuclei"],
                        "priority": 3,
                        "estimated_time_minutes": 15,
                        "depends_on": "http_probing",
                    },
                    {
                        "name": "xss_scan",
                        "tools": ["dalfox"],
                        "priority": 4,
                        "estimated_time_minutes": 10,
                        "depends_on": "http_probing",
                    },
                ],
                "total_estimated_time_minutes": 33,
            },
            "deep": {
                "phases": [
                    {
                        "name": "subdomain_enum",
                        "tools": ["subfinder"],
                        "priority": 1,
                        "estimated_time_minutes": 5,
                        "depends_on": None,
                    },
                    {
                        "name": "dns_enum",
                        "tools": ["dnsrecon", "dnsenum"],
                        "priority": 1,
                        "estimated_time_minutes": 10,
                        "depends_on": None,
                    },
                    {
                        "name": "http_probing",
                        "tools": ["httpx"],
                        "priority": 2,
                        "estimated_time_minutes": 5,
                        "depends_on": "subdomain_enum",
                    },
                    {
                        "name": "network_scan",
                        "tools": ["nmap"],
                        "priority": 3,
                        "estimated_time_minutes": 20,
                        "depends_on": "http_probing",
                    },
                    {
                        "name": "vulnerability_scan",
                        "tools": ["nuclei"],
                        "priority": 3,
                        "estimated_time_minutes": 20,
                        "depends_on": "http_probing",
                    },
                    {
                        "name": "web_scan",
                        "tools": ["nikto", "wapiti"],
                        "priority": 4,
                        "estimated_time_minutes": 15,
                        "depends_on": "http_probing",
                    },
                    {
                        "name": "xss_scan",
                        "tools": ["dalfox"],
                        "priority": 4,
                        "estimated_time_minutes": 10,
                        "depends_on": "http_probing",
                    },
                    {
                        "name": "code_analysis",
                        "tools": ["gitleaks", "semgrep"],
                        "priority": 5,
                        "estimated_time_minutes": 10,
                        "depends_on": None,
                    },
                ],
                "total_estimated_time_minutes": 95,
            },
        }
