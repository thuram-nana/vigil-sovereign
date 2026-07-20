"""Make ``vigil_gateway`` importable when pytest is invoked from the gateway dir or repo root."""

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
