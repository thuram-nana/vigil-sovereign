"""
aegis.demo_app — hold the bundled labelled benchmark app open on a FIXED port so a
defender has a ready-made *upstream* to sit ``aegis gateway`` in front of when trying
AEGIS out (QUICKSTART step b). Run it directly:

    python3 -m framework.v2.aegis.demo_app --host 127.0.0.1 --port 3000

It reuses :class:`framework.v2.eval.benchmark_app.BenchmarkHandler` — the same self-
contained, deliberately-vulnerable target the benchmark scores against — but binds a
FIXED host/port (the benchmark's own :func:`serve` binds an ephemeral port, which the
gateway cannot be pointed at ahead of time). Everything is loopback by default; it
sends no traffic and reaches nothing external.

Additive and OFF the gate path: this module is never imported by the scanner / engage /
benchmark flow, so it cannot perturb ``make gate``. It only imports the benchmark handler
that already exists.

This is a DELIBERATELY-VULNERABLE app — run it on loopback (or an isolated network) as a
demo target only; never expose it.
"""

from __future__ import annotations

import argparse
import sys
from http.server import ThreadingHTTPServer

from ..eval.benchmark_app import BenchmarkHandler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2.aegis.demo_app",
        description="Serve the bundled deliberately-vulnerable benchmark app on a fixed "
                    "port — a ready-made upstream for `aegis gateway` to protect.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind host (default loopback; use 0.0.0.0 inside a container)")
    parser.add_argument("--port", type=int, default=3000, help="listen port (default 3000)")
    args = parser.parse_args(argv)

    httpd = ThreadingHTTPServer((args.host, args.port), BenchmarkHandler)
    httpd.daemon_threads = True
    sys.stderr.write(
        f"benchmark app (bundled, DELIBERATELY-VULNERABLE demo target) "
        f"http://{args.host}:{args.port}  — point `aegis gateway --upstream` here\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
