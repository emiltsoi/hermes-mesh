"""The build stamp: what this process was installed from.

Four properties, each with a leg that can fail:

  AC-1  a provisioned BUILD is read, and its sha matches the pin the wave declared
  AC-2  the read comes from Path(__file__).parent, not from the newest directory on disk
  AC-3  asking twice, with the file changed between the asks, follows the file
  AC-4  an absent BUILD returns EXACTLY {"present": False} — no sha, no fabrication

The pin is not hardcoded: it is the commit this wave declared, which does not exist
when the test is written. It arrives through BUILD_STAMP_PIN, and the absence of that
variable is a legitimate skip rather than a pass — a test that silently asserts
nothing is the defect this file exists to avoid.
"""
import json
import os
import pathlib
import textwrap

import pytest

import hermes_mesh


def _write_build(directory: pathlib.Path, *, sha: str, describe: str = "v-test",
                 installed_at: str = "2026-11-19T00:00:00Z") -> pathlib.Path:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = directory / "BUILD"
    stamp.write_text(
        textwrap.dedent(
            f"""\
            sha={sha}
            describe={describe}
            installed_at={installed_at}
            """
        ),
        encoding="utf-8",
    )
    return stamp


@pytest.fixture()
def package_dir(tmp_path, monkeypatch):
    """Point the package's ``__file__`` at a fixture directory.

    Monkeypatched rather than copied: a copy tests a copy, and the property under
    test is that the reader follows the real module's own location.
    """
    original = hermes_mesh.__file__
    monkeypatch.setattr(hermes_mesh, "__file__", str(tmp_path / "__init__.py"))
    yield tmp_path
    hermes_mesh.__file__ = original


# AC-1 ------------------------------------------------------------------------

class _Ctx:
    """The minimum a plugin needs from the registration context."""

    def __init__(self):
        self.tools = {}

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = handler

    def register_platform(self, *a, **k):
        pass


def _registered_health():
    """The ``mesh_health`` a consumer actually calls, as registered.

    Tested through ``register()`` rather than through the internal function, because
    the internal function differs between base and head and the property under test
    is what the TOOL returns. A leg that needs a symbol the base does not have fails
    with AttributeError and never names the missing key it was written to name.
    """
    ctx = _Ctx()
    hermes_mesh.register(ctx)
    handler = ctx.tools["mesh_health"]
    return json.loads(handler({}))


def test_build_stamp_is_read_and_names_the_declared_pin(package_dir):
    """HEAD leg. The sha returned must be the pin the wave declared in writing."""
    pin = os.environ.get("BUILD_STAMP_PIN", "").strip()
    if not pin:
        pytest.skip("BUILD_STAMP_PIN not set — this leg cannot assert a pin it was not given")

    _write_build(package_dir, sha=pin)
    stamp = hermes_mesh.read_build_stamp()

    assert stamp["present"] is True
    assert stamp["sha"] == pin


def test_registered_tool_reports_build(package_dir):
    """The key this wave adds, observed where a consumer observes it.

    This is the leg that runs on BOTH trees: on base the registered handler returns
    ``{status, metrics}`` and the assertion names ``build`` as absent; on head it is
    present. That is what makes it red-first rather than merely new.
    """
    _write_build(package_dir, sha="e" * 40)
    result = _registered_health()

    assert "build" in result, f"build absent from mesh_health; keys were {sorted(result)}"
    assert result["build"]["sha"] == "e" * 40
    # additive, not a replacement — the pre-existing keys must survive
    assert "status" in result
    assert "metrics" in result



# AC-2 ------------------------------------------------------------------------

def test_read_follows_module_location_not_the_newest_directory(tmp_path, monkeypatch):
    """The decoy is NEWEST and carries a DIFFERENT sha.

    A reader that globs for the newest directory on disk reports the decoy. A reader
    that uses ``Path(__file__).parent`` reports the true stamp. The decoy's sha
    differs so a kill can only come from fabrication — if both carried the same sha
    the mutant would survive while looking correct.
    """
    true_dir = tmp_path / "true_build"
    decoy_dir = tmp_path / "decoy_build"
    _write_build(true_dir, sha="a" * 40)
    _write_build(decoy_dir, sha="b" * 40)

    # The decoy must be strictly newest. Two files inside one filesystem timestamp
    # tick are neither newest, so mtime is pinned explicitly rather than left to
    # write order.
    newer = (true_dir / "BUILD").stat().st_mtime + 3600
    os.utime(decoy_dir / "BUILD", (newer, newer))

    monkeypatch.setattr(hermes_mesh, "__file__", str(true_dir / "__init__.py"))
    stamp = hermes_mesh.read_build_stamp()

    assert stamp["sha"] == "a" * 40, (
        "read reported the decoy's sha — the reader is globbing by recency, "
        f"not following __file__ (got {stamp.get('sha')!r})"
    )


# AC-3 ------------------------------------------------------------------------

def test_second_ask_follows_the_file_it_read_between_asks(package_dir):
    """The wave's central property: ask twice, change the world between, answer follows.

    A second answer identical to the first is indistinguishable from never having
    re-read — the same shape as a check that cannot tell "nothing there" from
    "did not look".
    """
    _write_build(package_dir, sha="1" * 40)
    first = hermes_mesh.read_build_stamp()

    _write_build(package_dir, sha="2" * 40)
    second = hermes_mesh.read_build_stamp()

    assert first["sha"] == "1" * 40
    assert second["sha"] == "2" * 40, (
        "second answer repeated the first — the stamp is cached, so the process "
        "reports what it read at boot rather than what is installed now"
    )
    assert second["sha"] != first["sha"]


# AC-4 ------------------------------------------------------------------------

def test_absent_stamp_returns_exactly_present_false(package_dir):
    """No file, no sha. EXACTLY one key — an implementation returning empty strings
    passes a "no sha" reading while still contradicting the intent."""
    assert hermes_mesh.read_build_stamp() == {"present": False}


def test_stamp_returning_to_disk_is_seen_again(package_dir):
    """The restore is part of the property: a seat left stampless is indistinguishable
    from an install that forgot."""
    stamp = _write_build(package_dir, sha="c" * 40)
    assert hermes_mesh.read_build_stamp()["present"] is True

    stamp.rename(package_dir / "BUILD.absent")
    assert hermes_mesh.read_build_stamp() == {"present": False}

    (package_dir / "BUILD.absent").rename(stamp)
    restored = hermes_mesh.read_build_stamp()
    assert restored["present"] is True
    assert restored["sha"] == "c" * 40


def test_stamp_without_a_sha_is_absent_rather_than_guessed(package_dir):
    """A malformed stamp is not a licence to invent a sha."""
    (package_dir / "BUILD").write_text("describe=v-test\n", encoding="utf-8")
    assert hermes_mesh.read_build_stamp() == {"present": False}


# the handler -----------------------------------------------------------------

def test_mesh_health_carries_the_build_key(package_dir):
    """mesh_health returns status, metrics AND build — the key this wave adds."""
    _write_build(package_dir, sha="d" * 40)
    result = hermes_mesh._mesh_health_with_build({})

    assert "build" in result
    assert result["build"]["sha"] == "d" * 40
    # the pre-existing keys survive; this is additive, not a replacement
    assert "status" in result and "metrics" in result
