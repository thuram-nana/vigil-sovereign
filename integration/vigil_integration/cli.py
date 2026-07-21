"""
vigil — the unified command line for the sovereign engine (VIGIL-LIVE WS-2).

One entry point over the whole fused system:

  * ``vigil engage <url>``        — run the attestation-first OODA loop against a loopback target,
                                    routing every action through the real gate and every claimed
                                    exploit through the real oracle; prints an honest fact/lead report.
  * ``vigil ledger who``          — replay the always-on usage-attestation ledger (WS-6): WHO used the
    ``vigil ledger when``           tool, WHEN, against WHAT — non-repudiably, after verifying the chain.
  * ``vigil verify-ledger``       — verify the ledger's signatures + hash-chain (fail-closed).
  * ``vigil provision --slug S``  — mint + sign a CRUCIBLE authority for a loopback slug.

Fail-closed and honest: a keyless engagement (no ``ANTHROPIC_API_KEY``, no ``--replay``) still attests
first and then completes with nothing proposed — it never fabricates activity. Exit code is non-zero on
a refused engagement or a failed ledger verification.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence


def _cmd_provision(args: argparse.Namespace) -> int:
    from .live.wiring import provision_authority
    scope = [s.strip() for s in str(args.scope).split(",") if s.strip()]
    prov = provision_authority(slug=args.slug, scope=scope, environment=args.environment,
                               duration_hours=args.hours, max_actions=args.max_actions)
    print(f"provisioned signed authority for {prov.slug!r}")
    print(f"  scope         : {', '.join(scope)}")
    print(f"  authority_path: {prov.authority_path}")
    print(f"  key_fingerprint (public): {prov.keypair.public_key_b64[:16]}…")
    return 0


def _cmd_engage(args: argparse.Namespace) -> int:
    from .live.think_claude import ReplayThinker
    from .live.wiring import EngineConfig, build_engine

    replay = None
    if args.replay:
        decisions = json.loads(Path(args.replay).read_text(encoding="utf-8"))
        replay = ReplayThinker(decisions)

    cfg = EngineConfig(
        slug=args.slug, base_dir=args.base_dir, replay=replay, api_key=None,
        access_log=args.access_log, auth_log=args.auth_log, conn_log=args.conn_log,
        max_iterations=args.max_iterations, owner_approves_offense=args.approve_offense,
    )
    engine = build_engine(cfg)
    report = engine.engage(args.url, objective=args.objective)

    print(f"=== vigil engage {args.url} (slug={report.slug}) ===")
    if report.refused:
        print(f"REFUSED (fail-closed): {report.refusal_reason}")
        return 2
    print(f"attestation      : {report.attestation_ref or '(none)'}")
    print(f"iterations       : {report.iterations}   decisions: {', '.join(report.decisions) or '-'}")
    print(f"tool calls       : {len(report.tool_calls)}  "
          f"(ran={sum(1 for t in report.tool_calls if t.outcome == 'ran')}, "
          f"denied={len(report.denied_edges)})")
    print(f"FACTS (oracle-confirmed, signed): {report.fact_count}")
    for f in report.facts:
        print(f"    • [{f.bug_class or '?'}] {f.title or f.ref}  ⇒ evidence={f.evidence_ref[:24]}…")
    print(f"LEADS (proposals, unconfirmed)  : {len(report.leads)}")
    print(f"detection mirror : facts={report.detection_facts}  leads={report.detection_leads}")
    print(f"checkpoints      : {len(report.checkpoints)}")
    if report.paused:
        print(f"paused           : {report.paused}")
    return 0


def _load_and_verify_ledger(path: str, *, base_dir: str) -> tuple[list, object]:
    from .attestation.identity import operator_key_resolver
    from .attestation.ledger import read_ledger, verify_ledger
    records = read_ledger(path)
    resolver = operator_key_resolver(keypair_path=str(Path(base_dir) / "operator.key"))
    verification = verify_ledger(records, resolve_key=resolver)
    return records, verification


def _cmd_ledger(args: argparse.Namespace) -> int:
    from .attestation.ledger import ledger_when, ledger_who
    records, verification = _load_and_verify_ledger(args.path, base_dir=args.base_dir)
    if not getattr(verification, "ok", False):
        print(f"LEDGER VERIFICATION FAILED (fail-closed): {getattr(verification, 'reason', '?')}")
        return 3
    if args.which == "who":
        print(f"=== usage ledger — WHO ({len(records)} records, chain verified) ===")
        for w in ledger_who(records):
            op = getattr(w, "operator", None)
            fp = str(getattr(op, "key_fingerprint", "") or "")
            print(f"  seq={getattr(w, 'seq', '?')}  os={getattr(op, 'os_login', '?') or '-'}  "
                  f"git={getattr(op, 'git_name', '?') or '-'}  host={getattr(op, 'hostname', '?') or '-'}  "
                  f"key={fp[:16] + '…' if fp else '-'}  did={getattr(w, 'action', '?') or '-'} "
                  f"→ {getattr(w, 'target', '?') or '-'}  (phase={getattr(w, 'phase', '?') or '-'})")
    else:
        print(f"=== usage ledger — WHEN ({len(records)} records, chain verified) ===")
        for e in ledger_when(records):
            anchored = "TPM-anchored" if getattr(e, "grounded", False) else "software-chain"
            print(f"  seq={getattr(e, 'seq', '?')}  at={getattr(e, 'at', '?')}  "
                  f"monotonic={getattr(e, 'monotonic', '?')}  ({anchored})")
    return 0


def _cmd_verify_ledger(args: argparse.Namespace) -> int:
    records, verification = _load_and_verify_ledger(args.path, base_dir=args.base_dir)
    ok = getattr(verification, "ok", False)
    print(f"ledger: {len(records)} records — {'VERIFIED' if ok else 'FAILED'}: "
          f"{getattr(verification, 'reason', '')}")
    return 0 if ok else 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vigil", description="the VIGIL sovereign engine")
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("engage", help="run an engagement against a loopback target")
    pe.add_argument("url")
    pe.add_argument("--slug", default="loopback")
    pe.add_argument("--objective", default="")
    pe.add_argument("--base-dir", default=".vigil-live")
    pe.add_argument("--replay", default="", help="a JSON file of scripted decisions (keyless-live)")
    pe.add_argument("--access-log", default="")
    pe.add_argument("--auth-log", default="")
    pe.add_argument("--conn-log", default="")
    pe.add_argument("--max-iterations", type=int, default=12)
    pe.add_argument("--approve-offense", action="store_true",
                    help="the operator's standing approval to run queued offense tools against their "
                         "own chartered loopback (the human leg of the conjunctive gate; scope still enforced)")
    pe.set_defaults(func=_cmd_engage)

    pl = sub.add_parser("ledger", help="query the usage-attestation ledger (who/when)")
    pl.add_argument("which", choices=("who", "when"))
    pl.add_argument("--path", default=".vigil-live/usage-ledger.jsonl")
    pl.add_argument("--base-dir", default=".vigil-live")
    pl.set_defaults(func=_cmd_ledger)

    pv = sub.add_parser("verify-ledger", help="verify the usage-attestation ledger integrity")
    pv.add_argument("--path", default=".vigil-live/usage-ledger.jsonl")
    pv.add_argument("--base-dir", default=".vigil-live")
    pv.set_defaults(func=_cmd_verify_ledger)

    pp = sub.add_parser("provision", help="mint + sign a CRUCIBLE authority for a loopback slug")
    pp.add_argument("--slug", default="loopback")
    pp.add_argument("--scope", default="127.0.0.1", help="comma-separated LITERAL hosts (no CIDR)")
    pp.add_argument("--environment", default="twin")
    pp.add_argument("--hours", type=float, default=8.0)
    pp.add_argument("--max-actions", type=int, default=1000)
    pp.set_defaults(func=_cmd_provision)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # noqa: BLE001 — the CLI surfaces a clean error, never a traceback dump
        print(f"vigil: error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
