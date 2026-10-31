"""The manifest and the package metadata must not disagree.

Hotaru found this on the canary: ``plugin.yaml`` said 0.1.11 while ``pyproject.toml`` said 0.1.28 —
stale across seventeen version increments, because nothing compared them. Hermes discovers a
directory plugin by its ``plugin.yaml``, so that number is what an operator, an audit, or a future
decision reads. Two sources of truth with no test between them is the defect; this is the test.
"""
import pathlib
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def _manifest_version() -> str:
    for line in (ROOT / "plugin.yaml").read_text().splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip().strip('"').strip("'")
    raise AssertionError("plugin.yaml has no version: line")


def test_manifest_matches_package_version():
    assert _manifest_version() == _pyproject_version(), (
        f"plugin.yaml says {_manifest_version()!r}, pyproject says {_pyproject_version()!r} — "
        "the manifest is what the loader reads")
