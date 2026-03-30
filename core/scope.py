"""
GetNexova Scope Enforcer
=========================
Ensures all scanning activities remain within the authorized
scope defined by the bug bounty program. Critical for responsible
security research.
"""

import re
import logging
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Optional, Set

logger = logging.getLogger("getnexova.scope")


@dataclass
class ScopeRule:
    """A single scope inclusion or exclusion rule."""
    pattern: str
    rule_type: str  # "domain", "ip", "cidr", "url_pattern"
    include: bool = True  # True = in scope, False = excluded


@dataclass
class ProgramScope:
    """
    Defines the authorized scope for a bug bounty program.
    All targets must be validated against this before scanning.
    """
    program_name: str
    includes: List[ScopeRule] = field(default_factory=list)
    excludes: List[ScopeRule] = field(default_factory=list)
    _domain_cache: Set[str] = field(default_factory=set, repr=False)

    def add_domain(self, domain: str, include: bool = True) -> None:
        """Add a domain pattern to scope."""
        rule = ScopeRule(pattern=domain, rule_type="domain", include=include)
        if include:
            self.includes.append(rule)
        else:
            self.excludes.append(rule)

    def add_cidr(self, cidr: str, include: bool = True) -> None:
        """Add a CIDR range to scope."""
        rule = ScopeRule(pattern=cidr, rule_type="cidr", include=include)
        if include:
            self.includes.append(rule)
        else:
            self.excludes.append(rule)


class ScopeEnforcer:
    """
    Validates targets against program scope before any scanning.
    Thread-safe and cacheable for performance.
    """

    def __init__(self, scope: ProgramScope, strict: bool = True):
        self.scope = scope
        self.strict = strict
        self._validated_cache: Set[str] = set()
        self._rejected_cache: Set[str] = set()

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target (domain, URL, or IP) is within scope.

        Args:
            target: The target to validate

        Returns:
            True if target is within authorized scope
        """
        # Cache check
        if target in self._validated_cache:
            return True
        if target in self._rejected_cache:
            return False

        result = self._evaluate(target)
        if result:
            self._validated_cache.add(target)
        else:
            self._rejected_cache.add(target)
            logger.warning(f"⛔ Target out of scope: {target}")

        return result

    def _evaluate(self, target: str) -> bool:
        """Evaluate a target against all scope rules."""
        # Extract domain from URL if needed
        domain = self._extract_domain(target)
        ip_addr = self._try_parse_ip(target)

        # Check excludes first (excludes always win)
        for rule in self.scope.excludes:
            if self._matches_rule(rule, domain, ip_addr, target):
                return False

        # Check includes
        for rule in self.scope.includes:
            if self._matches_rule(rule, domain, ip_addr, target):
                return True

        # If strict mode, deny by default
        if self.strict:
            return False

        return True

    def _matches_rule(
        self,
        rule: ScopeRule,
        domain: Optional[str],
        ip_addr: Optional[str],
        raw_target: str,
    ) -> bool:
        """Check if a target matches a specific scope rule."""
        if rule.rule_type == "domain" and domain:
            return self._domain_matches(domain, rule.pattern)
        elif rule.rule_type == "cidr" and ip_addr:
            return self._ip_in_cidr(ip_addr, rule.pattern)
        elif rule.rule_type == "ip" and ip_addr:
            return ip_addr == rule.pattern
        elif rule.rule_type == "url_pattern":
            return bool(re.match(rule.pattern, raw_target))
        return False

    @staticmethod
    def _domain_matches(target_domain: str, pattern: str) -> bool:
        """Check domain match with wildcard support."""
        target_domain = target_domain.lower().strip(".")
        pattern = pattern.lower().strip(".")

        # Exact match
        if target_domain == pattern:
            return True

        # Wildcard: *.example.com matches sub.example.com
        if pattern.startswith("*."):
            base = pattern[2:]
            return (target_domain == base or
                    target_domain.endswith(f".{base}"))

        # Subdomain match: example.com matches sub.example.com
        return target_domain.endswith(f".{pattern}")

    @staticmethod
    def _ip_in_cidr(ip_str: str, cidr: str) -> bool:
        """Check if IP is within a CIDR range."""
        try:
            return ip_address(ip_str) in ip_network(cidr, strict=False)
        except ValueError:
            return False

    @staticmethod
    def _extract_domain(target: str) -> Optional[str]:
        """Extract domain from URL or return raw domain."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname
        # Remove port if present
        if ":" in target:
            target = target.split(":")[0]
        return target if target and not target.replace(".", "").isdigit() else None

    @staticmethod
    def _try_parse_ip(target: str) -> Optional[str]:
        """Try to parse target as an IP address."""
        clean = target.split("://")[-1].split("/")[0].split(":")[0]
        try:
            ip_address(clean)
            return clean
        except ValueError:
            return None

    def validate_targets(self, targets: List[str]) -> tuple:
        """
        Validate a list of targets and return (valid, invalid) lists.
        """
        valid = []
        invalid = []
        for target in targets:
            if self.is_in_scope(target):
                valid.append(target)
            else:
                invalid.append(target)
        if invalid:
            logger.warning(
                f"Scope check: {len(valid)} valid, {len(invalid)} rejected"
            )
        return valid, invalid
