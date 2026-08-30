"""Run MERIDIAN as a single loopback TARGET (no Range Control cockpit).

This is the entry point registered in tools/livefire/range_targets.json, so the generic loopback-range
harness (`tools/livefire/range.sh`) can start MERIDIAN the same way it starts vulnapp:

    python3 -m vigil_range.meridian --port 19010 --logdir <dir> --pidfile <f> [--safe]

`--safe` serves the HARDENED twin (every planted sink neutralized) — the negative-control convention the
range uses. `target up` (the full experience, with Range Control) is the normal way to run the range.
"""

from __future__ import annotations

import argparse
import atexit
import os

from .app import serve
from .config import DEFAULT_TARGET_PORT, Config


def _remove_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(prog="vigil_range.meridian")
    ap.add_argument("--port", type=int, default=DEFAULT_TARGET_PORT)
    ap.add_argument("--logdir", default=None, help="state/log dir (default ./.target-live)")
    ap.add_argument("--pidfile", default="", help="write this pid here; removed on exit (range.sh teardown)")
    ap.add_argument("--safe", action="store_true", help="serve the HARDENED twin (sinks neutralized)")
    args = ap.parse_args()

    base = args.logdir or os.path.join(os.getcwd(), ".target-live")
    config = Config(base_dir=base, target_port=args.port)
    config.ensure_dirs()

    if args.pidfile:
        os.makedirs(os.path.dirname(os.path.abspath(args.pidfile)) or ".", exist_ok=True)
        with open(args.pidfile, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))
        atexit.register(lambda: _remove_quietly(args.pidfile))

    mode = "HARDENED (--safe)" if args.safe else "VULNERABLE"
    print(f"MERIDIAN target [{mode}] on http://127.0.0.1:{args.port}/  logs={config.logs_dir}", flush=True)
    serve(config, hardened=args.safe, block=True, control=False)


if __name__ == "__main__":
    main()
