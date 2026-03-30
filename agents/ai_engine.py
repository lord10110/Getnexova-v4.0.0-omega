"""
GetNexova Unified AI Engine
=============================
Single LLM interface using LiteLLM for provider-agnostic calls.
Implements a tiered fallback strategy:
  1. Free models (Groq, Gemini)
  2. Paid models (Claude) - only if budget permits
  3. Local models (Ollama) - always available fallback

All AI prompts use structured, step-by-step instructions
for professional, actionable output.
"""

import asyncio
import logging
import time
import os
from typing import Optional, Dict, Any, List

logger = logging.getLogger("getnexova.ai_engine")

# LiteLLM import with graceful fallback
try:
    import litellm
    litellm.set_verbose = False
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False
    logger.warning("litellm not installed - AI features will be limited")

from core.config import GetNexovaConfig, LLMConfig
from core.cost_tracker import CostTracker


class AIEngine:
    """
    Unified AI engine for all LLM interactions in GetNexova.

    Uses LiteLLM for provider-agnostic API calls with automatic
    fallback through free → paid → local model tiers.
    """

    def __init__(self, config: GetNexovaConfig):
        self.config = config
        self.llm_config = config.llm
        self.cost_tracker = CostTracker(
            max_cost_per_run=config.llm.max_cost_per_run,
            max_cost_per_month=config.llm.max_cost_per_month,
        )
        self._setup_api_keys()
        self._call_count = 0
        self._total_latency = 0.0

    def _setup_api_keys(self) -> None:
        """Configure API keys for LiteLLM from environment."""
        if self.config.groq_api_key:
            os.environ["GROQ_API_KEY"] = self.config.groq_api_key
        if self.config.gemini_api_key:
            os.environ["GEMINI_API_KEY"] = self.config.gemini_api_key
        if self.config.anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = self.config.anthropic_api_key
        if self.config.ollama_base_url:
            os.environ["OLLAMA_API_BASE"] = self.config.ollama_base_url

    async def call(
        self,
        prompt: str,
        task_type: str = "analysis",
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        force_model: Optional[str] = None,
        json_mode: bool = False,
    ) -> Optional[str]:
        """
        Make a unified LLM call with automatic fallback.

        Args:
            prompt: The user/task prompt
            task_type: Type of task (for temperature selection and tracking)
            system_prompt: Optional system-level instructions
            temperature: Override temperature (uses task default if None)
            max_tokens: Override max output tokens
            force_model: Skip fallback, use this specific model
            json_mode: Request JSON response format

        Returns:
            Model response text, or None if all models fail
        """
        if not LITELLM_AVAILABLE:
            logger.error("LiteLLM not available - cannot make AI calls")
            return None

        temp = temperature or self.llm_config.temperatures.get(task_type, 0.2)
        tokens = max_tokens or self.llm_config.max_output_tokens

        # Build model list in priority order
        if force_model:
            models_to_try = [force_model]
        else:
            models_to_try = self._build_model_priority()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        last_error = None
        for model in models_to_try:
            # Budget check for paid models
            if self._is_paid_model(model) and not self.cost_tracker.can_afford():
                logger.info(f"Skipping paid model {model} - budget limit reached")
                continue

            try:
                result = await self._call_llm(
                    model=model,
                    messages=messages,
                    temperature=temp,
                    max_tokens=tokens,
                    task_type=task_type,
                    json_mode=json_mode,
                )
                if result:
                    return result
            except Exception as e:
                last_error = e
                logger.warning(f"Model {model} failed: {e}")
                continue

        logger.error(f"All models failed. Last error: {last_error}")
        return None

    async def _call_llm(
        self,
        model: str,
        messages: List[Dict],
        temperature: float,
        max_tokens: int,
        task_type: str,
        json_mode: bool = False,
    ) -> Optional[str]:
        """
        Execute a single LLM call via LiteLLM with retries.

        Returns:
            Response text or None on failure
        """
        start_time = time.time()

        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        for attempt in range(self.llm_config.max_retries):
            try:
                response = await litellm.acompletion(**kwargs)

                # Extract response text
                content = response.choices[0].message.content
                if not content:
                    continue

                # Track costs
                latency_ms = (time.time() - start_time) * 1000
                input_tokens = response.usage.prompt_tokens if response.usage else 0
                output_tokens = response.usage.completion_tokens if response.usage else 0

                # Get cost from litellm
                try:
                    cost = litellm.completion_cost(
                        completion_response=response
                    )
                except Exception:
                    cost = 0.0

                self.cost_tracker.record_call(
                    model=model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cost=cost,
                    task_type=task_type,
                    success=True,
                    latency_ms=latency_ms,
                )

                self._call_count += 1
                self._total_latency += latency_ms

                logger.debug(
                    f"LLM call success: model={model}, "
                    f"tokens={input_tokens}+{output_tokens}, "
                    f"cost=${cost:.4f}, latency={latency_ms:.0f}ms"
                )

                return content.strip()

            except Exception as e:
                wait = self.llm_config.retry_delay * (attempt + 1)
                logger.warning(
                    f"LLM call attempt {attempt + 1}/{self.llm_config.max_retries} "
                    f"failed for {model}: {e}. Retrying in {wait}s..."
                )
                if attempt < self.llm_config.max_retries - 1:
                    await asyncio.sleep(wait)

        # All retries exhausted
        self.cost_tracker.record_call(
            model=model,
            input_tokens=0,
            output_tokens=0,
            cost=0.0,
            task_type=task_type,
            success=False,
            latency_ms=(time.time() - start_time) * 1000,
        )
        return None

    def _build_model_priority(self) -> List[str]:
        """Build ordered list of models to try."""
        models = []
        models.extend(self.llm_config.free_models)
        models.extend(self.llm_config.paid_models)
        models.extend(self.llm_config.local_models)
        return models

    @staticmethod
    def _is_paid_model(model: str) -> bool:
        """Check if a model incurs API costs."""
        paid_prefixes = ["anthropic/", "openai/", "claude"]
        return any(model.startswith(p) for p in paid_prefixes)

    def get_stats(self) -> Dict:
        """Get engine statistics for the current run."""
        return {
            "total_calls": self._call_count,
            "avg_latency_ms": (
                self._total_latency / self._call_count
                if self._call_count > 0 else 0
            ),
            "cost_summary": self.cost_tracker.get_run_summary(),
        }


# ─── Structured Prompt Builders ──────────────────────────────────────

class PromptBuilder:
    """
    Builds structured, step-by-step prompts for specific AI tasks.
    Follows best practices from security research and AI prompting.
    """

    @staticmethod
    def classify_vulnerability(finding: Dict[str, Any]) -> str:
        """Build a structured classification prompt."""
        return f"""You are an expert vulnerability analyst for bug bounty programs.

## Task
Classify the following security finding with precision.

## Finding Details
- Tool: {finding.get('tool', 'unknown')}
- Type: {finding.get('type', 'unknown')}
- Target: {finding.get('target', 'unknown')}
- Evidence: {finding.get('evidence', 'none')[:500]}
- Raw Output: {finding.get('raw_output', 'none')[:1000]}

## Instructions
1. Determine if this is a TRUE vulnerability or a FALSE POSITIVE.
2. If true, classify the vulnerability type (e.g., XSS, SQLi, SSRF, IDOR, etc.).
3. Assess exploitability in a real-world bug bounty context.
4. Consider the business impact on the target organization.

## Response Format (JSON)
{{
    "is_valid": true/false,
    "confidence": 0.0-1.0,
    "vulnerability_type": "specific type",
    "severity": "critical/high/medium/low/info",
    "reasoning": "detailed explanation",
    "false_positive_indicators": ["list of concerns if any"],
    "recommendations": ["actionable next steps"]
}}"""

    @staticmethod
    def score_cvss(finding: Dict[str, Any]) -> str:
        """Build a CVSS scoring prompt."""
        return f"""You are a CVSS v3.1 scoring expert.

## Task
Calculate an accurate CVSS v3.1 score for this vulnerability.

## Vulnerability Details
- Type: {finding.get('vulnerability_type', 'unknown')}
- Target: {finding.get('target', 'unknown')}
- Evidence: {finding.get('evidence', 'none')[:500]}
- Context: {finding.get('context', 'web application')}

## Instructions
1. Evaluate each CVSS v3.1 base metric carefully.
2. Consider the attack vector, complexity, privileges required.
3. Assess confidentiality, integrity, and availability impact.
4. Calculate the final score mathematically.

## Response Format (JSON)
{{
    "cvss_vector": "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X",
    "cvss_score": 0.0,
    "severity_rating": "critical/high/medium/low/none",
    "metric_justification": {{
        "attack_vector": "explanation",
        "attack_complexity": "explanation",
        "privileges_required": "explanation",
        "user_interaction": "explanation",
        "scope": "explanation",
        "confidentiality": "explanation",
        "integrity": "explanation",
        "availability": "explanation"
    }}
}}"""

    @staticmethod
    def analyze_chain(findings: List[Dict[str, Any]]) -> str:
        """Build a vulnerability chain analysis prompt."""
        findings_summary = "\n".join(
            f"  {i+1}. [{f.get('severity', '?')}] {f.get('vulnerability_type', '?')} "
            f"at {f.get('target', '?')}"
            for i, f in enumerate(findings[:20])
        )
        return f"""You are an expert at identifying vulnerability chains in bug bounty programs.

## Task
Analyze these findings to identify potential attack chains where
combining multiple low/medium findings creates a high/critical impact.

## Findings
{findings_summary}

## Instructions
1. Look for logical connections between findings.
2. Identify chains where one vulnerability enables or amplifies another.
3. Consider common patterns: SSRF→internal access, XSS→account takeover,
   IDOR+info-leak→privilege escalation.
4. Rate the combined chain severity (often higher than individual findings).

## Response Format (JSON)
{{
    "chains": [
        {{
            "name": "descriptive chain name",
            "steps": ["finding 1 enables...", "finding 2 allows..."],
            "combined_severity": "critical/high/medium",
            "combined_cvss": 0.0,
            "impact": "business impact description",
            "likelihood": "high/medium/low"
        }}
    ],
    "standalone_notable": ["indices of significant standalone findings"]
}}"""

    @staticmethod
    def generate_report(
        target: str,
        findings: List[Dict[str, Any]],
        chains: List[Dict[str, Any]],
    ) -> str:
        """Build a professional report generation prompt."""
        findings_text = "\n".join(
            f"  - [{f.get('severity', '?')}] {f.get('vulnerability_type', '?')}: "
            f"{f.get('target', '?')}"
            for f in findings[:30]
        )
        chains_text = "\n".join(
            f"  - {c.get('name', '?')} (severity: {c.get('combined_severity', '?')})"
            for c in chains[:10]
        )
        return f"""You are writing a professional bug bounty report for submission.

## Task
Generate a clear, professional vulnerability report suitable for
submission to a bug bounty platform (Intigriti, YesWeHack, HackerOne).

## Target
{target}

## Validated Findings
{findings_text}

## Attack Chains
{chains_text}

## Report Requirements
1. Executive summary (2-3 sentences, business impact focus).
2. For each finding:
   - Clear title following platform conventions
   - Step-by-step reproduction instructions
   - Impact assessment with business context
   - CVSS score and vector
   - Remediation recommendations
3. For chains: explain the full attack scenario end-to-end.
4. Use professional, factual language. No speculation.

## Response Format
Generate the report in Markdown format, structured for direct
platform submission. Include PoC code blocks where applicable."""

    @staticmethod
    def plan_recon(target: str, mode: str, available_tools: List[str]) -> str:
        """Build a reconnaissance planning prompt."""
        tools_list = ", ".join(available_tools)
        return f"""You are a reconnaissance planning expert for bug bounty programs.

## Task
Create an optimal reconnaissance plan for the target.

## Target
{target}

## Scan Mode
{mode} (quick=fast surface scan, standard=thorough, deep=comprehensive)

## Available Tools
{tools_list}

## Instructions
1. Prioritize tools and phases based on the scan mode.
2. For "quick": focus on subdomain enumeration + HTTP probing only.
3. For "standard": add vulnerability scanning and content discovery.
4. For "deep": include network scanning, code analysis, and thorough enumeration.
5. Consider tool dependencies (e.g., httpx needs subdomain list first).

## Response Format (JSON)
{{
    "phases": [
        {{
            "name": "phase name",
            "tools": ["tool1", "tool2"],
            "priority": 1,
            "estimated_time_minutes": 5,
            "depends_on": ["previous phase name or null"]
        }}
    ],
    "total_estimated_time_minutes": 30,
    "notes": "any important considerations"
}}"""
