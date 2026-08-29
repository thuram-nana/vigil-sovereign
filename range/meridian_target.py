#!/usr/bin/env python3
"""Standalone launcher for the MERIDIAN loopback TARGET (registered in tools/livefire/range_targets.json).

The generic range harness (`tools/livefire/range.sh`) starts a process target as `python3 <script> --port
… --logdir … --pidfile …`. That bare invocation cannot resolve the package's relative imports, so this thin
wrapper puts `range/` on sys.path and hands off to the package entry point. `target up` is the normal way to
run the range (target + Range Control); this file exists only so the uniform harness can bring MERIDIAN up
as one more loopback target.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # so `import vigil_range` resolves uninstalled

from vigil_range.meridian.__main__ import main  # noqa: E402  (path shim must precede the import)

if __name__ == "__main__":
    main()
