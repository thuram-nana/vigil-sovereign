"""Make ``vigil_integration`` importable when pytest runs from the integration dir or repo root."""

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
