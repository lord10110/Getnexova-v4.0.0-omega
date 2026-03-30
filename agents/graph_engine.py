"""
GetNexova Graph Chain Engine
===============================
Builds a vulnerability relationship graph and discovers
attack chains using pathfinding algorithms.

Nodes = individual findings
Edges = logical relationships (enables, amplifies, leads_to)
Chains = paths through the graph representing multi-step attacks
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("getnexova.graph_engine")


@dataclass
class VulnNode:
    """A node in the vulnerability graph."""
    finding_id: str
    vulnerability_type: str
    target: str
    severity: str
    cvss_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnEdge:
    """An edge connecting two vulnerability nodes."""
    source_id: str
    target_id: str
    relationship: str  # enables, amplifies, leads_to, combined_with
    confidence: float = 0.5
    description: str = ""


@dataclass
class AttackChain:
    """A discovered attack chain (path through the graph)."""
    name: str
    steps: List[str]
    finding_ids: List[str]
    combined_severity: str
    combined_cvss: float
    impact: str
    confidence: float
    description: str = ""


# Predefined vulnerability relationship rules
RELATIONSHIP_RULES = [
    # (source_type_pattern, target_type_pattern, relationship, confidence, description)
    ("ssrf", "internal", "enables", 0.8,
     "SSRF enables access to internal services"),
    ("ssrf", "credential", "leads_to", 0.7,
     "SSRF can lead to credential exposure via cloud metadata"),
    ("xss", "csrf", "amplifies", 0.6,
     "XSS can bypass CSRF protections"),
    ("xss", "session", "leads_to", 0.7,
     "XSS enables session hijacking"),
    ("xss", "account", "leads_to", 0.6,
     "XSS can lead to account takeover"),
    ("sqli", "data", "leads_to", 0.9,
     "SQL injection leads to data exfiltration"),
    ("sqli", "rce", "enables", 0.5,
     "SQL injection may enable RCE via xp_cmdshell/LOAD_FILE"),
    ("idor", "data", "leads_to", 0.8,
     "IDOR leads to unauthorized data access"),
    ("idor", "privilege", "enables", 0.6,
     "IDOR may enable privilege escalation"),
    ("open redirect", "phishing", "enables", 0.7,
     "Open redirect enables phishing attacks"),
    ("open redirect", "oauth", "amplifies", 0.8,
     "Open redirect amplifies OAuth token theft"),
    ("info", "credential", "enables", 0.5,
     "Information disclosure may reveal credentials"),
    ("directory", "info", "enables", 0.6,
     "Directory listing enables information gathering"),
    ("csp", "xss", "amplifies", 0.7,
     "Missing CSP amplifies XSS impact"),
    ("cors", "data", "enables", 0.6,
     "CORS misconfiguration enables cross-origin data theft"),
    ("race", "payment", "leads_to", 0.7,
     "Race condition in payment leads to financial impact"),
    ("credential", "account", "leads_to", 0.9,
     "Exposed credentials lead to account takeover"),
    ("rce", "full", "leads_to", 0.95,
     "RCE leads to full system compromise"),
    ("ssti", "rce", "leads_to", 0.9,
     "SSTI often leads to remote code execution"),
]


class GraphChainEngine:
    """
    Builds and analyzes vulnerability relationship graphs.

    Uses predefined relationship rules and optional AI analysis
    to discover attack chains that combine multiple findings
    into higher-impact scenarios.
    """

    def __init__(self):
        self._nodes: Dict[str, VulnNode] = {}
        self._edges: List[VulnEdge] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)
        self._chains: List[AttackChain] = []

    def build_graph(self, findings: List[Dict[str, Any]]) -> int:
        """
        Build the vulnerability graph from findings.

        Returns number of edges discovered.
        """
        self._nodes.clear()
        self._edges.clear()
        self._adjacency.clear()

        # Add nodes
        for f in findings:
            fid = f.get("id", "")
            if not fid:
                continue
            self._nodes[fid] = VulnNode(
                finding_id=fid,
                vulnerability_type=f.get("vulnerability_type", ""),
                target=f.get("target", ""),
                severity=f.get("severity", "info"),
                cvss_score=f.get("cvss_score", 0.0),
                metadata=f.get("metadata", {}),
            )

        # Discover edges using relationship rules
        node_list = list(self._nodes.values())
        for i, src in enumerate(node_list):
            for j, dst in enumerate(node_list):
                if i == j:
                    continue
                edge = self._check_relationship(src, dst)
                if edge:
                    self._edges.append(edge)
                    self._adjacency[src.finding_id].append(dst.finding_id)

        logger.info(
            f"Graph built: {len(self._nodes)} nodes, {len(self._edges)} edges"
        )
        return len(self._edges)

    def find_chains(self, max_depth: int = 5) -> List[AttackChain]:
        """
        Discover attack chains by traversing the graph.

        Uses DFS to find all paths of length 2+ that represent
        multi-step attack scenarios.
        """
        self._chains.clear()

        for start_id in self._nodes:
            paths = self._dfs_paths(start_id, max_depth)
            for path in paths:
                if len(path) >= 2:
                    chain = self._path_to_chain(path)
                    if chain:
                        self._chains.append(chain)

        # Deduplicate and rank chains
        self._chains = self._deduplicate_chains(self._chains)
        self._chains.sort(key=lambda c: c.combined_cvss, reverse=True)

        logger.info(f"Found {len(self._chains)} attack chains")
        return self._chains

    def _check_relationship(
        self, src: VulnNode, dst: VulnNode
    ) -> Optional[VulnEdge]:
        """Check if two findings have a relationship based on rules."""
        src_type = src.vulnerability_type.lower()
        dst_type = dst.vulnerability_type.lower()

        for src_pattern, dst_pattern, rel, conf, desc in RELATIONSHIP_RULES:
            if src_pattern in src_type and dst_pattern in dst_type:
                # Boost confidence if same target
                if src.target == dst.target:
                    conf = min(conf + 0.1, 1.0)

                return VulnEdge(
                    source_id=src.finding_id,
                    target_id=dst.finding_id,
                    relationship=rel,
                    confidence=conf,
                    description=desc,
                )
        return None

    def _dfs_paths(
        self, start: str, max_depth: int
    ) -> List[List[str]]:
        """Find all paths from start node using DFS."""
        paths = []

        def _dfs(current: str, path: List[str], visited: Set[str]):
            if len(path) > max_depth:
                return
            if len(path) >= 2:
                paths.append(list(path))
            for neighbor in self._adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    _dfs(neighbor, path, visited)
                    path.pop()
                    visited.discard(neighbor)

        _dfs(start, [start], {start})
        return paths

    def _path_to_chain(self, path: List[str]) -> Optional[AttackChain]:
        """Convert a graph path to an AttackChain object."""
        if len(path) < 2:
            return None

        nodes = [self._nodes[pid] for pid in path if pid in self._nodes]
        if len(nodes) < 2:
            return None

        # Build chain description
        steps = []
        for i in range(len(nodes) - 1):
            src = nodes[i]
            dst = nodes[i + 1]
            # Find the edge
            edge_desc = ""
            for edge in self._edges:
                if edge.source_id == src.finding_id and edge.target_id == dst.finding_id:
                    edge_desc = edge.description
                    break
            steps.append(
                f"{src.vulnerability_type} → {dst.vulnerability_type}"
                + (f" ({edge_desc})" if edge_desc else "")
            )

        # Calculate combined severity
        severity_scores = {
            "critical": 9.5, "high": 7.5, "medium": 5.0,
            "low": 2.5, "info": 0.5,
        }
        max_individual = max(
            severity_scores.get(n.severity, 0) for n in nodes
        )
        # Chain amplification: chains are typically more severe than individual findings
        combined_cvss = min(max_individual + len(nodes) * 0.5, 10.0)

        combined_severity = (
            "critical" if combined_cvss >= 9.0 else
            "high" if combined_cvss >= 7.0 else
            "medium" if combined_cvss >= 4.0 else "low"
        )

        # Chain name
        first_type = nodes[0].vulnerability_type.split("(")[0].strip()
        last_type = nodes[-1].vulnerability_type.split("(")[0].strip()
        name = f"{first_type} → {last_type}"

        return AttackChain(
            name=name,
            steps=steps,
            finding_ids=path,
            combined_severity=combined_severity,
            combined_cvss=round(combined_cvss, 1),
            impact=f"Multi-step attack combining {len(nodes)} vulnerabilities",
            confidence=0.5 + (0.1 * min(len(nodes), 4)),
            description=f"Chain: {' → '.join(n.vulnerability_type[:30] for n in nodes)}",
        )

    def _deduplicate_chains(
        self, chains: List[AttackChain]
    ) -> List[AttackChain]:
        """Remove duplicate or subset chains."""
        seen_sigs: Set[str] = set()
        unique = []
        for chain in chains:
            sig = "|".join(sorted(chain.finding_ids))
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                unique.append(chain)
        return unique

    def get_chains_as_dicts(self) -> List[Dict[str, Any]]:
        """Get chains as serializable dictionaries."""
        return [
            {
                "name": c.name,
                "steps": c.steps,
                "finding_ids": c.finding_ids,
                "combined_severity": c.combined_severity,
                "combined_cvss": c.combined_cvss,
                "impact": c.impact,
                "confidence": c.confidence,
                "description": c.description,
            }
            for c in self._chains
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get graph analysis summary."""
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "chains_found": len(self._chains),
            "max_chain_length": max(
                (len(c.finding_ids) for c in self._chains), default=0
            ),
            "highest_chain_cvss": max(
                (c.combined_cvss for c in self._chains), default=0
            ),
        }
