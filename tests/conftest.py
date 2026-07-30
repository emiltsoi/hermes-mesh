import os
import sys

# Make the lightweight gateway stubs available for tests so hermes-mesh tests
# can run without the full hermes-agent core checkout.
_STUBS_DIR = os.path.join(os.path.dirname(__file__), "stubs")
if _STUBS_DIR not in sys.path:
    sys.path.append(_STUBS_DIR)
