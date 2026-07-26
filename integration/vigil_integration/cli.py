"""
vigil — the unified command line for the sovereign engine (VIGIL-LIVE WS-2).

One entry point over the whole fused system. NATIVE verbs (handled in-process, offense-side):

  * ``vigil engage <url>``        — run the attestation-first OODA loop against a loopback target,
                                    routing every action through the real gate and every claimed
                                    exploit through the real oracle; prints an honest fact/lead report.
                                    This is THE engage — the raw CRUCIBLE loop is ``vigil crucible engage``.
  * ``vigil ledger who``          — replay the always-on usage-attestation ledger (WS-6): WHO used the
    ``vigil ledger when``           tool, WHEN, against WHAT — non-repudiably, after verifying the chain.
  * ``vigil verify-ledger``       — verify the ledger's signatures + hash-chain (fail-closed).
  * ``vigil provision --slug S``  — mint + sign a CRUCIBLE authority for a loopback slug.
  * ``vigil detect --access-log`` — run the Detection Mirror (defensive oracle plane) over log files;
                                    each fire is certificate-re-verified before it counts as a FACT.
                                    (Distinct from ``vigil aegis detect`` — the AEGIS-app firewall verdict.)
  * ``vigil up`` / ``vigil down``  — bring the WHOLE unified UI up at ONE origin behind a self-contained
                                    reverse proxy (federating the two trust planes), and stop it. EXEC-
                                    ONLY: spawns the three backends in their own venvs; imports no
                                    framework/strix/sigil (the two trust domains never co-load here).

SUBSYSTEM verbs (S1 control plane — forwarded to the subsystem's own console-script, EXEC'd in its OWN
environment so the two trust domains are never co-loaded in one interpreter):

  * ``vigil sigil …``    → the sovereign personal core (``.venv-sovereign``; holds the owner key)
  * ``vigil crucible …`` → the raw CRUCIBLE offense arsenal (``.venv-offense``; keyless)
  * ``vigil aegis …``    → the defensive dual (detect / gateway / demo)
  * ``vigil strix …``    → the agent body
  * ``vigil gateway …``  → the host egress gate

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
    from vigil_core.vault import Vault
    from .live.wiring import provision_authority
    scope = [s.strip() for s in str(args.scope).split(",") if s.strip()]
    # Persist a STABLE governance key under --base-dir (sealed under its vault when provisioned), so a later
    # `vigil engage --base-dir <same>` reuses the SAME anchor-1 signer and one owner delegation covers it (S7).
    prov = provision_authority(slug=args.slug, scope=scope, environment=args.environment,
                               duration_hours=args.hours, max_actions=args.max_actions,
                               base_dir=args.base_dir, vault=Vault(Path(args.base_dir) / "vault"))
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

    scope = [s.strip() for s in str(getattr(args, "scope", "") or "").split(",") if s.strip()]
    cfg = EngineConfig(
        slug=args.slug, base_dir=args.base_dir, replay=replay, api_key=None,
        scope=tuple(scope) or ("127.0.0.1",),   # --scope is signed into the authority + enforced end-to-end
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


def _cmd_verify(args: argparse.Namespace) -> int:
    """S5b: the boundary-safe per-segment verification VIEW over the offense spine. Reads only PUBLIC keys +
    inert bytes; establishes the OWNER TIE for the offense spine by CONSUMING an owner-signed offense-spine
    delegation (OFFENSE_SPINE_ROLE — this is that role's first live consumer). The sovereign spine is verified
    separately (`vigil sigil verify`): a single process cannot co-load both trust domains (the two-env
    boundary). Exit 3 iff any present segment FAILS integrity; absent/unverifiable segments are not failures."""
    import time

    from .live.spine_verify import FAILED, verify_offense_home
    delegation = None
    if args.delegation:
        try:
            from vigil_core.delegation import DelegationCert
            delegation = DelegationCert.model_validate_json(
                Path(args.delegation).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 — an unreadable/invalid cert → refuse (no forged owner tie)
            print(f"delegation: could not load {args.delegation!r}: {exc}")
            return 2
    verdicts = verify_offense_home(
        args.base_dir, owner_pubkey=(args.owner_pubkey or None), delegation=delegation,
        now=int(time.time()), scope=args.scope, slug=(args.slug or None))
    print(f"=== vigil verify — offense segments under {args.base_dir} ===")
    print("(the sovereign spine is verified separately: `vigil sigil verify`)")
    failed = 0
    for v in verdicts:
        tie = "owner-rooted" if v.owner_rooted else "not-owner-rooted"
        mark = {"verified": "OK  ", "failed": "FAIL", "absent": "--  ",
                "unverifiable": "??  "}.get(v.status, "??  ")
        if v.status == FAILED:
            failed += 1
        print(f"  [{mark}] {v.segment:<26} {v.status:<13} {tie:<16} {v.detail}")
    print(f"--- {failed} segment(s) FAILED integrity ---" if failed
          else "--- all present segments verified ---")
    return 3 if failed else 0


def _cmd_identity(args: argparse.Namespace) -> int:
    """S7b — export the offense side's STABLE identity PUBLIC keys (spine + governance) as inert JSON, so the
    owner (sovereign side) can mint an owner-signed delegation over them (`sigil delegate-offense`). Writes
    ONLY public keys — never a private key crosses. The offense side loads-or-provisions its own stable keys
    here (unsealing via its vault), so this is the first step of the owner-tie ceremony."""
    import json

    from vigil_core.vault import Vault
    from .live.governance_identity import DEFAULT_GOVERNANCE_KEY_FILE, load_or_create_governance_keypair
    from .live.spine_identity import DEFAULT_SPINE_KEY_FILE, SPINE_KEY_ID, load_or_create_spine_keypair
    from .live.wiring import DEFAULT_KEY_ID
    base = Path(args.base_dir)
    base.mkdir(parents=True, exist_ok=True)
    vault = Vault(base / "vault")
    spine = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=vault)
    gov = load_or_create_governance_keypair(path=str(base / DEFAULT_GOVERNANCE_KEY_FILE), vault=vault)
    identity = {
        "schema": 1,
        # key_ids the delegation authorizers use. The governance authorizer MUST match the anchor-1 finding
        # signer's key_id (DEFAULT_KEY_ID). The spine authorizer uses SPINE_KEY_ID: the checkpoint spine and
        # ExecRecords verify by PUBKEY (they carry no key_id), but the DETECTION cert stamps a key_id and the
        # seam matches it by key_id — S7c set that to SPINE_KEY_ID so a detection FACT matches this authorizer.
        "spine": {"key_id": SPINE_KEY_ID, "public_key_b64": spine.public_key_b64},
        "governance": {"key_id": DEFAULT_KEY_ID, "public_key_b64": gov.public_key_b64},
    }
    out = base / "offense-identity.json"
    out.write_text(json.dumps(identity, indent=2, sort_keys=True), encoding="utf-8")
    print(f"offense identity exported (PUBLIC keys only) → {out}")
    print(f"  spine      : {spine.public_key_b64[:16]}…  (key_id {SPINE_KEY_ID!r})")
    print(f"  governance : {gov.public_key_b64[:16]}…  (key_id {DEFAULT_KEY_ID!r})")
    print("next (sovereign side): sigil delegate-offense "
          f"--offense-identity {out} --scope <slug> --hours <N>")
    print("NOTE: transport this file to the owner over an AUTHENTICATED channel (or confirm the pubkey "
          "fingerprints out-of-band) — a swapped file would get an attacker's key owner-blessed.")
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    """Run the Detection Mirror standalone over log files (unification S3) — the DEFENSIVE oracle plane
    surfaced as a first-class `vigil` verb (previously reachable only INSIDE `vigil engage`). Each fire is
    re-verified (its certificate re-runs the named detection oracle over the embedded evidence) before it
    counts as a FACT; unproven fires degrade to LEADs. Framework-free + offense-free (reads telemetry,
    wields nothing). Note: this is DISTINCT from `vigil aegis detect` (the AEGIS-the-app single
    TelemetryEnvelope firewall verdict) — this runs the log-plane oracle set over access/auth/conn logs."""
    from vigil_core import generate_keypair, sign
    from .detection.registry import detection_bug_classes, facts, leads, run_all_detections

    def _read(path: str) -> str:
        return Path(path).read_text(encoding="utf-8", errors="replace") if path else ""

    kp = generate_keypair()   # an ephemeral signer so a FACT-grade fire mints a re-verifiable certificate
    dets = run_all_detections(
        access_log=_read(args.access_log), conn_log=_read(args.conn_log), auth_log=_read(args.auth_log),
        signer=lambda msg: sign(kp.private_key_b64, msg), verify_key=kp.public_key_b64, key_id="vigil-detect")
    f, ll = facts(dets), leads(dets)
    print("=== vigil detect (detection mirror) ===")
    print(f"logs: access={args.access_log or '-'}  auth={args.auth_log or '-'}  conn={args.conn_log or '-'}")
    print(f"vocabulary: {len(detection_bug_classes())} declared detection classes")
    print(f"FACTS (oracle-proven, certificate re-verified): {len(f)}")
    for d in f:
        print(f"    • [{d.bug_class}] {getattr(d.finding, 'title', '') or d.summary}")
    print(f"LEADS (suspicions, non-blocking): {len(ll)}")
    for d in ll:
        print(f"    • [{d.bug_class}] {getattr(d.finding, 'title', '') or d.summary}")
    return 0


def _cmd_up(args: argparse.Namespace) -> int:
    """`vigil up` — bring the WHOLE unified UI up at ONE origin and federate the two trust planes
    behind a self-contained reverse proxy. EXEC-ONLY: it spawns the three backends (sigil cockpit,
    crucible console, crucible api) as separate OS processes in their OWN venvs (via dispatch) and
    serves the bundle itself — it imports NO framework/strix/sigil, so the two trust domains are never
    co-loaded in one interpreter. Binds loopback (or a private/tunnel IP); refuses a public bind."""
    from .uiproxy import run_up
    return run_up(host=args.host, port=args.port, domain=args.domain, base_dir=args.base_dir,
                  no_browser=args.no_browser)


def _cmd_down(args: argparse.Namespace) -> int:
    """`vigil down` — stop a running `vigil up` (terminate the backends + proxy tracked in the pids
    file). EXEC-ONLY: imports NO framework/strix/sigil."""
    from .uiproxy import run_down
    return run_down(base_dir=args.base_dir)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vigil", description="the VIGIL sovereign engine — one control plane over two isolated processes",
        epilog="subsystem verbs (forwarded to their own venv): sigil · crucible · aegis · strix · gateway  "
               "(e.g. `vigil sigil status`, `vigil crucible scan …`, `vigil aegis detect …`)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("engage", help="run an engagement against an owner-authorized target (loopback or remote)")
    pe.add_argument("url")
    pe.add_argument("--slug", default="loopback")
    pe.add_argument("--objective", default="")
    pe.add_argument("--scope", default="127.0.0.1",
                    help="comma-separated LITERAL hosts / *.wildcards the engagement is authorized for (no "
                         "CIDR); signed into the CRUCIBLE authority and enforced end-to-end. PREFER literal "
                         "hosts — a *.wildcard is a deliberate BROAD grant: it authorizes reaching whatever "
                         "public IP any matching subdomain currently resolves to (the metadata/LAN floor still "
                         "holds). Default 127.0.0.1")
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

    pver = sub.add_parser("verify", help="verify the offense spine segments (per-segment, owner-tie-aware)")
    pver.add_argument("--base-dir", default=".vigil-live")
    pver.add_argument("--slug", default="", help="verify only {slug}.spine (default: every *.spine)")
    pver.add_argument("--owner-pubkey", default="",
                      help="the pinned owner PUBLIC key (base64) — the trust anchor for the delegation")
    pver.add_argument("--delegation", default="",
                      help="a JSON file holding an owner-signed offense-spine DelegationCert (establishes the "
                           "owner tie; without it the spine is integrity-only, not owner-rooted)")
    pver.add_argument("--scope", default="*", help="the engagement scope the delegation must cover")
    pver.set_defaults(func=_cmd_verify)

    pp = sub.add_parser("provision", help="mint + sign a CRUCIBLE authority for a loopback slug")
    pp.add_argument("--slug", default="loopback")
    pp.add_argument("--scope", default="127.0.0.1", help="comma-separated LITERAL hosts (no CIDR)")
    pp.add_argument("--environment", default="twin")
    pp.add_argument("--hours", type=float, default=8.0)
    pp.add_argument("--max-actions", type=int, default=1000)
    pp.add_argument("--base-dir", default=".vigil-live",
                    help="engagement home for the STABLE governance key (shared with `vigil engage`)")
    pp.set_defaults(func=_cmd_provision)

    pid = sub.add_parser("identity",
                         help="export the offense stable identity PUBLIC keys (spine+governance) for owner delegation")
    pid.add_argument("--base-dir", default=".vigil-live")
    pid.set_defaults(func=_cmd_identity)

    pd = sub.add_parser("detect", help="run the Detection Mirror over log files (defensive oracle plane)")
    pd.add_argument("--access-log", default="", help="a CLF access log (edge/injection/recon oracles)")
    pd.add_argument("--auth-log", default="", help="an auth log (credential oracles)")
    pd.add_argument("--conn-log", default="", help="a connection/flow log (port-scan oracle)")
    pd.set_defaults(func=_cmd_detect)

    pu = sub.add_parser("up", help="bring the WHOLE unified UI up at one origin (self-contained reverse proxy)")
    pu.add_argument("--port", type=int, default=8770, help="the proxy port a browser points at (default 8770)")
    pu.add_argument("--host", default="127.0.0.1",
                    help="bind address for the proxy — loopback (default) or a PRIVATE/tunnel IP only; "
                         "a public/0.0.0.0 bind is refused (never-public). The three backends always "
                         "bind loopback; the proxy is the only human-facing listener.")
    pu.add_argument("--domain", default="",
                    help="the domain the browser reaches you by (hosted; TLS terminated by your edge "
                         "reverse proxy). An allowlist STRING, not a bind — front it with "
                         "deploy/reverse-proxy/vigil.Caddyfile. Sets the scheme to https.")
    pu.add_argument("--no-browser", action="store_true",
                    help="do not auto-open a browser (a browser is opened only for a loopback bind)")
    pu.add_argument("--base-dir", default=".vigil-live",
                    help="engagement home for the runtime serve dir (.vigil-live/ui/) + pids file")
    pu.set_defaults(func=_cmd_up)

    pdn = sub.add_parser("down", help="stop a running `vigil up` (backends + proxy)")
    pdn.add_argument("--base-dir", default=".vigil-live",
                     help="engagement home holding the ui/pids file written by `vigil up`")
    pdn.set_defaults(func=_cmd_down)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # S1 control plane: a subsystem verb forwards to that subsystem's console-script, EXEC'd in its OWN
    # venv (sovereign or offense) — a separate process in the correct trust domain, never co-loaded here.
    # This intercept runs BEFORE argparse so all remaining args (incl. the sub-CLI's own flags) pass through
    # opaquely. `dispatch` is pure-stdlib and imports no subsystem, so this path stays boundary-clean.
    from .dispatch import PASSTHROUGH_VERBS, dispatch
    if argv and argv[0] in PASSTHROUGH_VERBS:
        return dispatch(argv[0], argv[1:])
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # noqa: BLE001 — the CLI surfaces a clean error, never a traceback dump
        print(f"vigil: error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
