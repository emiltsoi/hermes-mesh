"""Hermes Mesh plugin entry point.

This root __init__.py is loaded by the Hermes PluginManager; it re-exports
the register function and helpers from the hermes_mesh package.
"""
from __future__ import annotations

import sys
from pathlib import Path

if __package__:
    # Loaded as part of the hermes_plugins.<slug> namespace package
    from .hermes_mesh import check_requirements, register, validate_config  # type: ignore[import]
else:
    # Standalone import (tests, direct execution)
    sys.path.insert(0, str(Path(__file__).parent))
    from hermes_mesh import check_requirements, register, validate_config  # type: ignore[import]

__all__ = ["register", "check_requirements", "validate_config"]
