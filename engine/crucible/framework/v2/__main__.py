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


def _intel(argv: list[str]) -> int:
    from .intel import cli as intel_cli
    return intel_cli.main(argv)


def _knowledge(argv: list[str]) -> int:
    from .knowledge_engine import cli as knowledge_cli
    return knowledge_cli.main(argv)


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


def _defender(argv: list[str]) -> int:
    from .defender import cli as defender_cli
    return defender_cli.main(argv)


def _analysis(argv: list[str]) -> int:
    from .analysis import cli as analysis_cli
    return analysis_cli.main(argv)


def _authority(argv: list[str]) -> int:
    from .authority import cli as authority_cli
    return authority_cli.main(argv)


def _socialdefense(argv: list[str]) -> int:
    from .socialdefense import cli as socialdefense_cli
    return socialdefense_cli.main(argv)


def _scan(argv: list[str]) -> int:
    from .scanner import cli as scanner_cli
    return scanner_cli.main(argv)


def _engage(argv: list[str]) -> int:
    from . import engage as engage_mod
    return engage_mod.main(argv)


def _plan(argv: list[str]) -> int:
    # READ-ONLY planner projection over a prior `engage --spine` engagement's world-model. LAZY
    # import — nothing under plan/planner is imported until this subcommand runs, so the scan/engage/
    # benchmark gate path never touches it. Sends no traffic, drives no tools.
    from . import plan as plan_mod
    return plan_mod.main(argv)


def _collaborator(argv: list[str]) -> int:
    from .verify import collaborator_cli
    return collaborator_cli.main(argv)


def _benchmark(argv: list[str]) -> int:
    from .eval import benchmark_run
    return benchmark_run.main(argv)


def _console(argv: list[str]) -> int:
    from .console import cli as console_cli
    return console_cli.main(argv)


def _api(argv: list[str]) -> int:
    from .api import cli as api_cli
    return api_cli.main(argv)


def _imports(argv: list[str]) -> int:
    from .imports import cli as imports_cli
    return imports_cli.main(argv)


def _verify(argv: list[str]) -> int:
    from .verify import reverify
    return reverify.main(argv)


def _drift(argv: list[str]) -> int:
    # Continuous drift: diff the oracle-CONFIRMED fact set between two runs (re-firing each
    # run's retained certs). Pure, offline, deterministic — reuses verify.reverify.
    from .verify import drift as drift_mod
    return drift_mod.main(argv)


def _capabilities(argv: list[str]) -> int:
    from .plugins import cli as plugins_cli
    return plugins_cli.main(argv)


def _aegis(argv: list[str]) -> int:
    # AEGIS (the DEFENSIVE dual). LAZY import — nothing under aegis/ is imported until this
    # subcommand actually runs, so the scan/engage/benchmark gate path never touches it and
    # `make gate` stays byte-identical.
    from .aegis import cli as aegis_cli
    return aegis_cli.main(argv)


def _evidence(argv: list[str]) -> int:
    from .evidence import cli as evidence_cli
    return evidence_cli.main(argv)


def _mcp(argv: list[str]) -> int:
    from .mcp import cli as mcp_cli
    return mcp_cli.main(argv)


def _report(argv: list[str]) -> int:
    from .report import cli as report_cli
    return report_cli.main(argv)


def _attack_paths(argv: list[str]) -> int:
    # READ-ONLY graph-theoretic triage over the asset topology projected from the signed
    # spine: shortest attack path, chokepoint ranking, reachability-bounded blast radius.
    # LAZY import — nothing under worldmodel is loaded until this subcommand runs, so the
    # scan/engage/benchmark gate path never touches it. Sends no traffic; mutates nothing.
    from .worldmodel import attack_paths as attack_paths_mod
    return attack_paths_mod.main(argv)


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

    # X6 — surface the runtime governance state PROMINENTLY (not just a log line), so an operator
    # sees at a glance whether the sovereignty tier is sealed and whether capability entitlement
    # is actually enforced or the deployment is running UNGOVERNED.
    print("  Governance        :")
    try:
        from .kernel import sovereignty
        pol = sovereignty.current()
        sealed = " [SEALED]" if sovereignty.is_sealed() else " (unsealed — env-mutable)"
        print(f"    sovereignty tier : {pol.tier.name}{sealed}")
    except Exception as e:  # noqa: BLE001 — status must never crash on one subsystem
        print(f"    sovereignty tier : ERROR — {type(e).__name__}: {e}")
    try:
        from .entitlement.policy import EntitlementPolicy
        ent = EntitlementPolicy.from_provisioned()
        if ent.enforced:
            tier = ent.granted_tier.name if ent.granted_tier else "—"
            print(f"    entitlement      : ENFORCED (granted tier {tier})")
        else:
            print(f"    entitlement      : ⚠ UNGOVERNED — {ent.explain()}")
            print("                       exploitation runs unentitled; provision a trust root and set")
            print("                       CRUCIBLE_ENTITLEMENT_ENFORCED to govern it.")
    except Exception as e:  # noqa: BLE001
        print(f"    entitlement      : ERROR — {type(e).__name__}: {e}")
    print()
    return 0


_DISPATCH: dict[str, Callable[[list[str]], int]] = {
    "intake": _intake,
    "memory": _memory,
    "intel": _intel,
    "knowledge": _knowledge,
    "kernel": _kernel,
    "entitlement": _entitlement,
    "eval": _eval,
    "improve": _improve,
    "defender": _defender,
    "analysis": _analysis,
    "authority": _authority,
    "socialdefense": _socialdefense,
    "scan": _scan,
    "engage": _engage,
    "plan": _plan,
    "verify": _verify,
    "drift": _drift,
    "capabilities": _capabilities,
    "aegis": _aegis,
    "evidence": _evidence,
    "report": _report,
    "attack-paths": _attack_paths,
    "collaborator": _collaborator,
    "benchmark": _benchmark,
    "console": _console,
    "mcp": _mcp,
    "api": _api,
    "imports": _imports,
    "status": _status,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # At-rest protection (X2): latch an owner-only umask before anything writes to
    # disk, so every secret / integrity store / captured-evidence file this process
    # (and any child it spawns) creates is 0600 and every directory 0700. Only ever
    # tightens; never loosens a stricter ambient umask.
    from .common import paths as _paths
    _paths.tighten_umask()

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
