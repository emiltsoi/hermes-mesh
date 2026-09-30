"""Directory-plugin entry point for hermes-mesh.

Hermes loads a directory plugin by importing the plugin DIRECTORY itself as a
package (``hermes_plugins.<slug>``) and calling ``register(ctx)`` on the result —
see ``hermes_cli/plugins_loader.py::_load_directory_module``, which raises
``FileNotFoundError: No __init__.py in <plugin dir>`` when this file is absent.

That is why this module exists. The implementation lives in the nested
``hermes_mesh`` package beside this file, so we re-export ``register`` from it.

THE BRANCH BELOW DISPATCHES ON ``__package__``, NOT ON A CAUGHT EXCEPTION.
This file is imported in two contexts and the import STYLE has to follow:

  1. AS A PACKAGE — the real purpose. The loader imports the directory as
     ``hermes_plugins.<slug>``, so ``__package__`` is set and the relative import
     resolves correctly under the loader's synthetic parent name.
  2. STANDALONE, WITH NO PACKAGE — the file imported under the bare name
     ``__init__``. A relative import then has no anchor and raises
     ``ImportError: attempted relative import with no known parent package``.
     pytest reaches this path on its own: a directory holding ``__init__.py`` is
     collected as a ``Package``, and ``Package.collect()`` calls
     ``importtestmodule(self.path / "__init__.py")``. That single line took the
     whole suite down — 171 setup errors, introduced 2026-09-26 by the commit
     that added this file, cleared 2026-09-30.

Why branch on ``__package__`` instead of ``try: from .hermes_mesh import register
/ except ImportError:``? An exception-based fallback also catches a genuine
ImportError raised INSIDE ``hermes_mesh``, then silently retries the absolute
path — which can resolve to a DIFFERENT tree that happens to be on ``sys.path``,
masking real breakage. Branching on the module's own context means a real failure
inside ``hermes_mesh`` propagates unchanged in both contexts.

Without this file the plugin fails to load, the ``mesh`` platform is never
registered (``Platform('mesh')`` raises ValueError), and no mesh adapter binds a
port — the failure is logged as a warning and the gateway boots on regardless
(2026-09-26). Do not delete it to make a test runner happy; fix the import style.
"""
if __package__:
    from .hermes_mesh import register
else:
    from hermes_mesh import register

__all__ = ["register"]
