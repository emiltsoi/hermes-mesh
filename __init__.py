"""Directory-plugin entry point for hermes-mesh.

Hermes loads a directory plugin by importing the plugin DIRECTORY itself as a
package (``hermes_plugins.<slug>``) and calling ``register(ctx)`` on the result —
see ``hermes_cli/plugins_loader.py::_load_directory_module``, which raises
``FileNotFoundError: No __init__.py in <plugin dir>`` when this file is absent.

That is why this module exists. The implementation lives in the nested
``hermes_mesh`` package (src layout), so we re-export ``register`` from it. The
nested package uses only relative imports, so it resolves correctly under the
loader's synthetic parent name; nothing has to be importable as a bare
top-level ``hermes_mesh`` from site-packages.

Without this file the plugin fails to load, the ``mesh`` platform is never
registered (``Platform('mesh')`` raises ValueError), and no mesh adapter binds a
port — the failure is logged as a warning and the gateway boots on regardless
(2026-09-26).
"""
from .hermes_mesh import register

__all__ = ["register"]
