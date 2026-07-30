import os
import sys

# Make the lightweight gateway stubs available for tests so hermes-mesh tests
# can run without the full hermes-agent core checkout.
_STUBS_DIR = os.path.join(os.path.dirname(__file__), "stubs")
if _STUBS_DIR not in sys.path:
    sys.path.append(_STUBS_DIR)


import pytest
import shutil
import tempfile


@pytest.fixture(autouse=True)
def _temp_hermes_home():
    """Use a fresh HERMES_HOME for every test so local config does not pollute."""
    orig = os.environ.get("HERMES_HOME")
    tmp = tempfile.mkdtemp()
    os.environ["HERMES_HOME"] = tmp
    yield
    if orig is None:
        os.environ.pop("HERMES_HOME", None)
    else:
        os.environ["HERMES_HOME"] = orig
    shutil.rmtree(tmp, ignore_errors=True)
