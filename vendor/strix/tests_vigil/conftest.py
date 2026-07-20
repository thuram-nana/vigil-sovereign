"""Put the vendored Strix package on the path for the VIGIL-added tests."""

import pathlib
import sys

_STRIX_ROOT = pathlib.Path(__file__).resolve().parent.parent  # vendor/strix
if str(_STRIX_ROOT) not in sys.path:
    sys.path.insert(0, str(_STRIX_ROOT))
