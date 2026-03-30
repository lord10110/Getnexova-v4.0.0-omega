"""
GetNexova Agent Definition Loader
===================================
Loads agent definitions from YAML + SOUL.md files following
the GitAgent standard. Each agent has identity, personality,
model preferences, and skill definitions.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("getnexova.agent_loader")

# Try to import yaml, fall back to basic parsing
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.warning("PyYAML not installed - using basic agent config")


@dataclass
class AgentDefinition:
    """Parsed agent definition from YAML + SOUL.md."""
    name: str
    version: str = "1.0.0"
    description: str = ""
    role: str = ""
    model_preferences: list = field(default_factory=list)
    skills: list = field(default_factory=list)
    tools: list = field(default_factory=list)
    soul: str = ""  # Content from SOUL.md
    parameters: Dict[str, Any] = field(default_factory=dict)


def load_agent_def(
    agent_name: str,
    agents_dir: Optional[Path] = None,
) -> AgentDefinition:
    """
    Load an agent definition from its directory.

    Expected structure:
        agents_definitions/
            {agent_name}/
                agent.yaml
                SOUL.md

    Args:
        agent_name: Name of the agent (matches directory name)
        agents_dir: Path to agents_definitions/ directory

    Returns:
        AgentDefinition with parsed data
    """
    if agents_dir is None:
        agents_dir = Path(__file__).parent.parent / "agents_definitions"

    agent_dir = agents_dir / agent_name

    if not agent_dir.exists():
        logger.warning(f"Agent definition not found: {agent_dir}")
        return AgentDefinition(name=agent_name)

    definition = AgentDefinition(name=agent_name)

    # Load agent.yaml
    yaml_path = agent_dir / "agent.yaml"
    if yaml_path.exists():
        definition = _load_yaml(yaml_path, definition)

    # Load SOUL.md
    soul_path = agent_dir / "SOUL.md"
    if soul_path.exists():
        try:
            definition.soul = soul_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to read SOUL.md for {agent_name}: {e}")

    logger.debug(f"Loaded agent definition: {agent_name} v{definition.version}")
    return definition


def _load_yaml(path: Path, definition: AgentDefinition) -> AgentDefinition:
    """Parse agent.yaml file into AgentDefinition."""
    try:
        content = path.read_text(encoding="utf-8")

        if YAML_AVAILABLE:
            data = yaml.safe_load(content)
        else:
            data = _basic_yaml_parse(content)

        if not isinstance(data, dict):
            return definition

        definition.name = data.get("name", definition.name)
        definition.version = data.get("version", definition.version)
        definition.description = data.get("description", definition.description)
        definition.role = data.get("role", definition.role)
        definition.model_preferences = data.get("model_preferences", [])
        definition.skills = data.get("skills", [])
        definition.tools = data.get("tools", [])
        definition.parameters = data.get("parameters", {})

        return definition

    except Exception as e:
        logger.error(f"Failed to parse agent.yaml at {path}: {e}")
        return definition


def _basic_yaml_parse(content: str) -> Dict[str, Any]:
    """
    Very basic YAML-like parser for when PyYAML is not available.
    Handles simple key: value pairs and lists.
    """
    result: Dict[str, Any] = {}
    current_list_key = None
    current_list: list = []

    for line in content.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # List item
        if stripped.startswith("- ") and current_list_key:
            current_list.append(stripped[2:].strip().strip('"').strip("'"))
            continue

        # Save previous list
        if current_list_key and current_list:
            result[current_list_key] = current_list
            current_list = []
            current_list_key = None

        # Key: value pair
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if not value:
                # This might be a list header
                current_list_key = key
            else:
                result[key] = value

    # Save final list
    if current_list_key and current_list:
        result[current_list_key] = current_list

    return result


def get_all_agents(agents_dir: Optional[Path] = None) -> Dict[str, AgentDefinition]:
    """Load all agent definitions from the agents directory."""
    if agents_dir is None:
        agents_dir = Path(__file__).parent.parent / "agents_definitions"

    agents = {}
    if not agents_dir.exists():
        return agents

    for agent_path in agents_dir.iterdir():
        if agent_path.is_dir() and not agent_path.name.startswith("."):
            agents[agent_path.name] = load_agent_def(
                agent_path.name, agents_dir
            )

    return agents
