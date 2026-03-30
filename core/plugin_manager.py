"""
GetNexova Plugin Manager
==========================
Extensible plugin system that allows adding custom scanners,
validators, and reporters without modifying core code.

Plugin Structure:
    plugins/
        my_plugin/
            plugin.json     # Metadata
            scanner.py      # Plugin code
"""

import json
import importlib.util
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field

logger = logging.getLogger("getnexova.plugins")


@dataclass
class PluginInfo:
    """Plugin metadata from plugin.json."""
    name: str
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    hook: str = "scanner"    # scanner | validator | reporter | post_scan
    entry_point: str = "scanner.py"
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)


class PluginManager:
    """
    Manages plugin discovery, loading, and execution.

    Plugins are Python modules that implement specific hook
    interfaces (scanner, validator, reporter, post_scan).
    """

    def __init__(self, plugins_dir: Path):
        self.plugins_dir = plugins_dir
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self._plugins: Dict[str, PluginInfo] = {}
        self._loaded: Dict[str, Any] = {}  # name -> module
        self._hooks: Dict[str, List[Callable]] = {
            "scanner": [],
            "validator": [],
            "reporter": [],
            "post_scan": [],
            "pre_scan": [],
        }

    def discover(self) -> int:
        """Discover plugins in the plugins directory."""
        count = 0
        for plugin_dir in self.plugins_dir.iterdir():
            if not plugin_dir.is_dir() or plugin_dir.name.startswith("."):
                continue
            metadata_file = plugin_dir / "plugin.json"
            if not metadata_file.exists():
                continue
            try:
                with open(metadata_file, "r") as f:
                    data = json.load(f)
                info = PluginInfo(
                    name=data.get("name", plugin_dir.name),
                    version=data.get("version", "1.0.0"),
                    description=data.get("description", ""),
                    author=data.get("author", ""),
                    hook=data.get("hook", "scanner"),
                    entry_point=data.get("entry_point", "scanner.py"),
                    enabled=data.get("enabled", True),
                    config=data.get("config", {}),
                )
                self._plugins[info.name] = info
                count += 1
                logger.debug(f"Discovered plugin: {info.name} v{info.version}")
            except Exception as e:
                logger.warning(f"Failed to load plugin metadata from {plugin_dir}: {e}")
        logger.info(f"Discovered {count} plugins")
        return count

    def load_all(self) -> int:
        """Load all enabled plugins."""
        loaded = 0
        for name, info in self._plugins.items():
            if not info.enabled:
                continue
            if self._load_plugin(name, info):
                loaded += 1
        logger.info(f"Loaded {loaded}/{len(self._plugins)} plugins")
        return loaded

    def _load_plugin(self, name: str, info: PluginInfo) -> bool:
        """Load a single plugin module."""
        plugin_dir = self.plugins_dir / name
        entry_file = plugin_dir / info.entry_point

        if not entry_file.exists():
            logger.warning(f"Plugin entry point not found: {entry_file}")
            return False

        try:
            spec = importlib.util.spec_from_file_location(
                f"getnexova.plugins.{name}", str(entry_file)
            )
            if not spec or not spec.loader:
                return False
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            self._loaded[name] = module

            # Register hooks
            hook = info.hook
            if hook in self._hooks:
                run_fn = getattr(module, "run", None)
                if callable(run_fn):
                    self._hooks[hook].append(run_fn)

            logger.info(f"Loaded plugin: {name} (hook={hook})")
            return True
        except Exception as e:
            logger.error(f"Failed to load plugin {name}: {e}")
            return False

    async def run_hook(
        self,
        hook: str,
        context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Execute all plugins registered for a specific hook.

        Args:
            hook: Hook name (scanner, validator, etc.)
            context: Data passed to each plugin

        Returns:
            Combined results from all plugins
        """
        results = []
        for fn in self._hooks.get(hook, []):
            try:
                import asyncio
                if asyncio.iscoroutinefunction(fn):
                    result = await fn(context)
                else:
                    result = fn(context)
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, dict):
                    results.append(result)
            except Exception as e:
                logger.error(f"Plugin hook {hook} error: {e}")
        return results

    def get_summary(self) -> Dict[str, Any]:
        """Get plugin system summary."""
        return {
            "discovered": len(self._plugins),
            "loaded": len(self._loaded),
            "plugins": {
                name: {
                    "version": info.version,
                    "hook": info.hook,
                    "enabled": info.enabled,
                    "loaded": name in self._loaded,
                }
                for name, info in self._plugins.items()
            },
        }
