"""
CLI entry point for v2. Invoke with:

    python3 -m framework.v2 <subcommand> [args...]

Subcommands are registered explicitly here so the operator sees the
full surface in one read. New subcommands appear in `_DISPATCH` only;
the dispatch table is the contract.
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable

from .common import logging as v2log
from .common.errors import CrucibleError


def _intake(argv: list[str]) -> int:
    from .intake import cli as intake_cli
    return intake_cli.main(argv)


def _memory(argv: list[str]) -> int:
    from .memory import cli as memory_cli
    return memory_cli.main(argv)


def _kernel(argv: list[str]) -> int:
    from .kernel import cli as kernel_cli
    return kernel_cli.main(argv)


def _entitlement(argv: list[str]) -> int:
    from .entitlement import cli as entitlement_cli
    return entitlement_cli.main(argv)


def _eval(argv: list[str]) -> int:
    from .eval import cli as eval_cli
    return eval_cli.main(argv)


def _improve(argv: list[str]) -> int:
    from .improve import cli as improve_cli
    return improve_cli.main(argv)


def _status(argv: list[str]) -> int:
    """One-shot environment summary: which backends are reachable, which
    paths resolve, which optional deps are installed."""
    from .common import paths
    from .kernel import backends as backends_pkg

    print("CRUCIBLE v2 status")
    print("------------------")
    try:
        root = paths.crucible_root()
        print(f"  CRUCIBLE_ROOT     : {root}")
    except CrucibleError as e:
        print(f"  CRUCIBLE_ROOT     : ERROR — {e}")
        return 2

    print(f"  v2 root           : {paths.v2_root()}")
    print(f"  memory db         : {paths.memory_db()}")
    print(f"  dryrun dir        : {paths.dryrun_dir()}")
    print()
    print("  LLM backends      :")
    for name, available, note in backends_pkg.probe_all():
        mark = "✓" if available else "·"
        print(f"    {mark} {name:<10s} {note}")
    print()
    return 0


_DISPATCH: dict[str, Callable[[list[str]], int]] = {
    "intake": _intake,
    "memory": _memory,
    "kernel": _kernel,
    "entitlement": _entitlement,
    "eval": _eval,
    "improve": _improve,
    "status": _status,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2",
        description="CRUCIBLE v2 — see framework/v2/README.md",
        add_help=False,
    )
    parser.add_argument("subcommand", nargs="?", choices=sorted(_DISPATCH.keys()))
    parser.add_argument("-h", "--help", action="store_true")

    args, rest = parser.parse_known_args(argv)

    if args.help or args.subcommand is None:
        parser.print_help()
        print("\nSubcommands:")
        for name in sorted(_DISPATCH.keys()):
            print(f"  {name}")
        print("\nRun `python3 -m framework.v2 <subcommand> --help` for details.")
        return 0 if args.help else 2

    log = v2log.get_logger(__name__)
    log.info("v2.cli.start", subcommand=args.subcommand, args=rest)
    try:
        rc = _DISPATCH[args.subcommand](rest)
    except CrucibleError as e:
        log.error("v2.cli.crucible_error", error_type=type(e).__name__, error=str(e))
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        log.warning("v2.cli.interrupted")
        return 130
    log.info("v2.cli.done", subcommand=args.subcommand, rc=rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
