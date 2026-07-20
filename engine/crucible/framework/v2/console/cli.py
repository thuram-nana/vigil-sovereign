"""
console.cli — `python3 -m framework.v2 console`.

Starts the loopback Ops Console and blocks. Read-only and on-host by design; it
neither issues outbound traffic nor touches the scan/engage hot path.
"""

from __future__ import annotations

import argparse

from .server import serve


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 console",
        description="Loopback, read-only operator console (a UI over the artifacts the "
                    "framework already writes; it never touches the scan hot path).",
    )
    parser.add_argument("--port", type=int, default=8787, help="Loopback port (default 8787).")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind host — loopback only (default 127.0.0.1).")
    parser.add_argument("--open", action="store_true",
                        help="Open the console in a browser after starting.")
    args = parser.parse_args(argv)

    try:
        httpd = serve(host=args.host, port=args.port)
    except ValueError as e:
        print(f"console refused to start: {e}")
        return 2
    except OSError as e:
        print(f"console could not bind {args.host}:{args.port}: {e}")
        return 2

    url = f"http://{args.host}:{args.port}/"
    # flush so the URL is visible immediately even under nohup / a pipe (not a tty)
    print("\n  ┌─────────────────────────────────────────────────────────┐", flush=True)
    print("  │  CRUCIBLE Ops Console is running — open in a browser:    │", flush=True)
    print(f"  │      {url:<50s} │", flush=True)
    print("  │  (loopback-only: open it ON THIS MACHINE. Ctrl-C stops.)│", flush=True)
    print("  └─────────────────────────────────────────────────────────┘\n", flush=True)
    if args.open:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass  # a missing/failed browser must never stop the server from serving
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nconsole stopped.")
    finally:
        httpd.server_close()
    return 0
