# Agent Definitions Guide

## Overview

GetNexova uses the **GitAgent** standard for defining AI agent identities. Each agent has a dedicated folder under `agents_definitions/` containing two files:

- `agent.yaml` — Technical configuration
- `SOUL.md` — Identity and behavioral principles

## Directory Structure

```
agents_definitions/
├── planner/
│   ├── agent.yaml
│   └── SOUL.md
├── researcher/
│   ├── agent.yaml
│   └── SOUL.md
├── scanner/
│   ├── agent.yaml
│   └── SOUL.md
├── reporter/
│   ├── agent.yaml
│   └── SOUL.md
├── orchestrator/
│   ├── agent.yaml
│   └── SOUL.md
└── graph_engine/
    ├── agent.yaml
    └── SOUL.md
```

## agent.yaml Format

```yaml
name: AgentName
version: "1.0.0"
description: "What this agent does"
role: "agent_role_identifier"
model_preferences:
  - "groq/llama-3.1-70b-versatile"    # First choice
  - "gemini/gemini-2.0-flash"          # Fallback
skills:
  - "skill_name_1"
  - "skill_name_2"
tools:
  - "external_tool_1"
  - "external_tool_2"
parameters:
  custom_param: value
  another_param: 42
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Display name of the agent |
| `version` | string | Semantic version |
| `description` | string | What the agent does |
| `role` | string | Role identifier for internal routing |
| `model_preferences` | list | Ordered LLM model preferences |
| `skills` | list | Capabilities this agent has |
| `tools` | list | External tools this agent can use |
| `parameters` | dict | Custom configuration parameters |

## SOUL.md Format

The SOUL.md file defines the agent's identity, personality, and behavioral principles. It is used as the system prompt when the agent makes LLM calls.

```markdown
# Agent Name Identity

## Who You Are
Description of the agent's role and expertise.

## Your Principles
1. **Principle Name**: Explanation
2. **Another Principle**: Explanation

## Your Personality
- Trait 1
- Trait 2
- Trait 3
```

## Customization

### Adding a New Agent

1. Create a folder: `agents_definitions/my_agent/`
2. Create `agent.yaml` with configuration
3. Create `SOUL.md` with identity
4. Create the Python agent class in `agents/my_agent.py`
5. Load the definition: `defn = load_agent_def("my_agent")`

### Modifying Existing Agents

Edit the YAML or SOUL.md files directly. Changes take effect on the next run — no code changes needed for personality or model preference adjustments.

### Model Preferences

The `model_preferences` list determines which LLM model the agent prefers. The AI engine will try these first before falling through to the global model priority chain.

Available model formats (via LiteLLM):
- `groq/llama-3.1-70b-versatile` (free)
- `gemini/gemini-2.0-flash` (free)
- `anthropic/claude-sonnet-4-20250514` (paid)
- `ollama/llama3.1` (local)
- `ollama/mistral` (local)
