"""`target` — the VIGIL cyber-range launcher.

  target up [app] [--hardened] [--port N] [--control-port N] [--base-dir D] [--no-browser]
  target down [app]
  target status [app]
  target harden on|off        # flip the vuln/hardened mode live (no restart)
  target seed [app]           # (re)build the synthetic database
  target charter [app]        # print the engagement charter that authorizes VIGIL against this range
"""

from __future__ import annotations

import argparse
import os
import sys

from . import apps, launcher
from .meridian import config as cfg


def _find_charter(app_name: str) -> str | None:
    """Walk up from CWD looking for targets/<app>/charter.md (the committed authorization doc)."""
    here = os.getcwd()
    while True:
        candidate = os.path.join(here, "targets", app_name, "charter.md")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


def _cmd_up(args: argparse.Namespace) -> int:
    return launcher.run_up(
        args.app, base_dir=args.base_dir, host=args.host, target_port=args.port,
        control_port=args.control_port, hardened=args.hardened, no_browser=args.no_browser,
    )


def _cmd_down(args: argparse.Namespace) -> int:
    return launcher.run_down(args.app, base_dir=args.base_dir)


def _cmd_status(args: argparse.Namespace) -> int:
    return launcher.run_status(args.app, base_dir=args.base_dir)


def _cmd_harden(args: argparse.Namespace) -> int:
    base = args.base_dir or cfg.default_base_dir()
    want = cfg.MODE_HARDENED if args.state == "on" else cfg.MODE_VULN
    written = cfg.write_mode(base, want)
    running = ""
    from .launcher import _pid_alive, _read_pidfile  # local: process-control helpers
    pid = _read_pidfile(cfg.Config(base_dir=base).pidfile)
    if pid and _pid_alive(pid):
        running = " (applied live to the running range)"
    print(f"mode → {written}{running}")
    return 0


def _cmd_seed(args: argparse.Namespace) -> int:
    base = args.base_dir or cfg.default_base_dir()
    try:
        from .meridian import db  # type: ignore[attr-defined]
    except ImportError:
        print("synthetic database seeding is added in the S1 build slice; "
              "the range currently builds its DB on `target up`.")
        return 0
    db.reseed(cfg.Config(base_dir=base))
    print("synthetic database rebuilt.")
    return 0


def _cmd_charter(args: argparse.Namespace) -> int:
    path = _find_charter(args.app)
    if path is None:
        print(f"no charter found for '{args.app}' (expected targets/{args.app}/charter.md under the repo).",
              file=sys.stderr)
        return 1
    print(f"# charter: {path}\n")
    with open(path, encoding="utf-8") as fh:
        sys.stdout.write(fh.read())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="target", description="VIGIL cyber-range launcher (loopback lab).")
    sub = p.add_subparsers(dest="command", required=True)

    def _add_app(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("app", nargs="?", default=apps.DEFAULT_APP, help="range app (default: meridian)")
        sp.add_argument("--base-dir", default=None, help="state dir (default: ./.target-live)")

    pu = sub.add_parser("up", help="bring the range up (loopback only)")
    _add_app(pu)
    pu.add_argument("--host", default="127.0.0.1", help="bind host (loopback only; default 127.0.0.1)")
    pu.add_argument("--port", type=int, default=None, help="target portal port (default 19010)")
    pu.add_argument("--control-port", type=int, default=None, help="range control port (default 19011)")
    pu.add_argument("--hardened", action="store_true", help="start in HARDENED mode (sinks neutralized)")
    pu.add_argument("--no-browser", action="store_true", help="do not open a browser")
    pu.set_defaults(func=_cmd_up)

    pd = sub.add_parser("down", help="stop a running range")
    _add_app(pd)
    pd.set_defaults(func=_cmd_down)

    ps = sub.add_parser("status", help="show range status")
    _add_app(ps)
    ps.set_defaults(func=_cmd_status)

    ph = sub.add_parser("harden", help="flip vuln/hardened mode live")
    ph.add_argument("state", choices=["on", "off"], help="on = hardened, off = vulnerable")
    ph.add_argument("--base-dir", default=None)
    ph.set_defaults(func=_cmd_harden)

    pseed = sub.add_parser("seed", help="(re)build the synthetic database")
    _add_app(pseed)
    pseed.set_defaults(func=_cmd_seed)

    pc = sub.add_parser("charter", help="print the engagement charter authorizing VIGIL against this range")
    pc.add_argument("app", nargs="?", default=apps.DEFAULT_APP)
    pc.set_defaults(func=_cmd_charter)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
