"""
api.cli — ``python3 -m framework.v2 api``.

Starts the loopback external API daemon and blocks. DEFAULT-SAFE: the daemon does not
exist until the operator runs this command, and it binds loopback only. Every action it
exposes runs through the same fail-closed gate chain as a local action; the read
surface issues no traffic.
"""

from __future__ import annotations

import argparse

from .server import serve


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 api",
        description="Loopback, gated external API — enumerate/read (safe core) and drive "
                    "GATED actions (every action through the same fail-closed gate chain as "
                    "local). Off unless started; binds loopback only.",
    )
    parser.add_argument("--port", type=int, default=8799, help="Loopback port (default 8799).")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind host — loopback only (default 127.0.0.1).")
    args = parser.parse_args(argv)

    try:
        httpd = serve(host=args.host, port=args.port)
    except ValueError as e:
        print(f"api refused to start: {e}")
        return 2
    except OSError as e:
        print(f"api could not bind {args.host}:{args.port}: {e}")
        return 2

    base = f"http://{args.host}:{args.port}{'/api/v1'}"
    print("\n  ┌──────────────────────────────────────────────────────────┐", flush=True)
    print("  │  CRUCIBLE gated API is running (loopback, on-host only):  │", flush=True)
    print(f"  │      {base:<51s} │", flush=True)
    print("  │  READ: GET /status /engagements /worldmodel/<run> ...     │", flush=True)
    print("  │  ACT : POST /tool/invoke /import  (through the gate chain)│", flush=True)
    print("  │  (open it ON THIS MACHINE. Ctrl-C stops.)                 │", flush=True)
    print("  └──────────────────────────────────────────────────────────┘\n", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\napi stopped.")
    finally:
        httpd.server_close()
    return 0
