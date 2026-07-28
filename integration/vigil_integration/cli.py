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
  * ``vigil patch --finding-envelope|--from-spine`` — run the gated auto-patch ladder over a PROVENANCE-
                                    GROUNDED confirmed finding (signed envelope OR the engagement's signed
                                    spine — never raw JSON). Default is a non-destructive propose-only dry
                                    run; ``--apply-edits`` applies into a disposable clone; ``--open-pr`` (off
                                    by default) opens a gated PR under a provisioned m-of-n destruction quorum.
  * ``vigil provision-destruction`` — mint the m-of-n destruction quorum keys for ``vigil patch --open-pr``
                                    (prints the signing keys ONCE; writes the public trust root).
  * ``vigil authorize-destruction`` — sign ONE destructive action (from a ``vigil patch`` dry run) → the
                                    single-use, window-bounded signed authorization the PR leg consumes.
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


def _cmd_engage_instruct(args: argparse.Namespace) -> int:
    """Enqueue a mid-run, natural-language operator instruction for a live engagement `slug`. The running
    `vigil engage` folds it into its next think as ADVISORY context — it fires nothing (every action still
    passes the gate + approval; every exploit still needs the oracle), so this can neither run a tool nor
    relax scope. This is the "tell it what to include DURING a live engagement" path."""
    from .live.instructions import enqueue
    try:
        out = enqueue(args.slug, args.text, base=args.base_dir)
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    print(f"queued operator instruction #{out['seq']} for engagement '{out['slug']}' "
          f"(advisory — the running engage will fold it into its next reasoning step; every action it "
          f"prompts still waits for your approval).")
    return 0


def _cmd_engage(args: argparse.Namespace) -> int:
    from .live.think_claude import ReplayThinker
    from .live.wiring import EngineConfig, build_engine

    replay = None
    if args.replay:
        decisions = json.loads(Path(args.replay).read_text(encoding="utf-8"))
        replay = ReplayThinker(decisions)

    scope = [s.strip() for s in str(getattr(args, "scope", "") or "").split(",") if s.strip()]
    connect = [c.strip() for c in str(getattr(args, "connect", "") or "").split(",") if c.strip()]
    cfg = EngineConfig(
        slug=args.slug, session_id=str(getattr(args, "session", "") or ""),
        connections=tuple(connect),
        base_dir=args.base_dir, replay=replay, api_key=None,
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


def _cmd_patch(args: argparse.Namespace) -> int:
    """LAP-3b: run the gated auto-patch ladder over a PROVENANCE-GROUNDED confirmed finding.

    The driving finding is NEVER built from raw JSON (a raw ``TriageFinding`` is trivially forgeable). It comes
    from a signed inert envelope (``--finding-envelope`` — m-of-n governance, owner-delegated) or the
    engagement's OWN signed spine (``--from-spine`` — integrity-audited + rebuilt). Default is a NON-destructive
    dry run: propose (Claude) → clone → sandbox-build in a DISPOSABLE clone; the source is never touched and no
    PR is opened. ``--apply-edits`` applies the fix into the clone; ``--open-pr`` (off by default) opens a gated
    PR and needs a provisioned m-of-n destruction authorization + a ``GITHUB_TOKEN`` in the environment.
    """
    from .autopatch.loop import _derive_remediation_id
    from .live.codefix_runner import CodefixConfig, autopatch_live, file_backed_quorum
    from .live.think_claude import resolve_model
    from .live.trusted_finding import (
        TrustedFindingError,
        finding_from_envelope,
        finding_from_spine,
        load_destruction_authority,
        load_signed_authorization,
    )

    # (1) EXACTLY ONE trusted finding source. A raw-JSON finding is never accepted.
    if bool(args.finding_envelope) == bool(args.from_spine):
        print("vigil patch: choose EXACTLY ONE trusted finding source — --finding-envelope <signed.json> "
              "(owner-delegated m-of-n governance) OR --from-spine <slug> (the engagement's signed spine). "
              "A raw-JSON finding is never accepted.", file=sys.stderr)
        return 2
    slug = args.scope if args.finding_envelope else args.from_spine
    try:
        if args.finding_envelope:
            finding = finding_from_envelope(
                envelope_path=args.finding_envelope, owner_pubkey=args.owner_pubkey,
                delegation_path=args.delegation, scope=args.scope,
                target_repo=args.target_repo, target_branch=args.target_branch)
        else:
            finding = finding_from_spine(
                base_dir=args.base_dir, slug=args.from_spine, target_repo=args.target_repo,
                finding_ref=args.finding_ref, target_branch=args.target_branch)
    except TrustedFindingError as exc:
        print(f"vigil patch: REFUSED (fail-closed): {exc}", file=sys.stderr)
        return 2

    rid = _derive_remediation_id("", finding)
    action_id = f"pr-{rid}"
    provenance = ("signed envelope (m-of-n governance, owner-delegated)" if args.finding_envelope
                  else "signed offense spine (verified + rebuilt)")
    print(f"=== vigil patch — finding {finding.ref!r} [{finding.bug_class or '?'}] ===")
    print(f"provenance     : {provenance}")
    print(f"target_repo    : {finding.target_repo or '(none — pass --target-repo)'}")
    print(f"remediation_id : {rid}")
    print("PR authorization (sign THIS destructive action to enable --open-pr):")
    print(f"    action_id       : {action_id}")
    print(f"    engagement_slug : {slug}")
    print(f"    target          : {finding.target_repo}")
    print("    blast_class     : destructive")

    if not finding.target_repo:
        print("vigil patch: --target-repo is required (the local path or git URL to fix)", file=sys.stderr)
        return 2

    # (2) the PR-leg m-of-n quorum: DENY by default; only wired when --open-pr is fully provisioned. The
    #     single-use is durable + ATOMIC via the file-backed nonce ledger (one authorization → one PR).
    quorum = None
    if args.open_pr:
        from .live.destruction_provision import default_paths
        dp = default_paths(args.base_dir)
        # Auto-discover the provisioned quorum under --base-dir (from `vigil provision-destruction` +
        # `vigil authorize-destruction`); explicit flags override. The ledger dir is created on first use.
        trust_root = args.authority_trust_root or (dp["trust_root"] if Path(dp["trust_root"]).exists() else "")
        signed_path = args.signed_authorization or (dp["signed"] if Path(dp["signed"]).exists() else "")
        ledger = args.ledger or dp["ledger"]
        # provision-destruction's default owner id. Fail-closed: the mandatory id must be registered in the
        # trust root (DestructionAuthority validates that), and the owner's SIGNATURE must be present — so a
        # wrong default (e.g. a custom --owner-id) refuses rather than fails open. Operator-supplied (the
        # trusted caller), never the injectable agent.
        mandatory = args.mandatory_signer or ["owner"]
        missing = [n for n, v in (("--signed-authorization", signed_path),
                                  ("--authority-trust-root", trust_root)) if not v]
        if missing:
            print(f"vigil patch: --open-pr needs {', '.join(missing)} — run `vigil provision-destruction` then "
                  f"`vigil authorize-destruction` (they default under --base-dir {args.base_dir}), or pass the "
                  "flags explicitly. A GITHUB_TOKEN must also be set in the environment.", file=sys.stderr)
            return 2
        try:
            authority = load_destruction_authority(trust_root_path=trust_root, mandatory_signer_ids=mandatory)
            signed = load_signed_authorization(signed_path)
        except TrustedFindingError as exc:
            print(f"vigil patch: REFUSED (fail-closed): {exc}", file=sys.stderr)
            return 2
        quorum = file_backed_quorum(authority=authority, signed=signed, slug=slug, ledger_path=ledger)

    # (3) config + run the gated ladder. client=None ⇒ the coder is built from ANTHROPIC_API_KEY (env, never
    #     argv); apply_edits/pr_enabled are explicit opt-ins; the GitHub token is read from the child env only.
    cfg = CodefixConfig(
        target_repo=finding.target_repo, base_dir=args.repo_base_dir, target_branch=args.target_branch,
        apply_edits=bool(args.apply_edits), model=resolve_model(args.model),  # --model > Settings choice > default
        pr_enabled=bool(args.open_pr), pr_base=args.pr_base)
    result = autopatch_live(finding, config=cfg, client=None,
                            operator_present=bool(args.approve), quorum=quorum)

    print("--- result ---")
    print(f"status         : {result.status}")
    print(f"applied_paths  : {list(result.patched_paths) or '-'}")
    print(f"opened_pr      : {result.opened_pr}   pr_ref={result.pr_ref or '-'}")
    print(f"remediated     : {result.remediated}")
    if result.reason:
        print(f"reason         : {result.reason}")
    # Honest exit: non-zero only on an outright refusal (not-confirmed / gate deny). A propose-only or
    # applied-in-clone or opened-PR run is a success; a "no proposal" (e.g. no API key) is reported, not crashed.
    return 1 if str(result.status).startswith("refused") else 0


def _cmd_provision_destruction(args: argparse.Namespace) -> int:
    """Mint the m-of-n destruction quorum keys for `vigil patch --open-pr`. Prints each signer's PRIVATE key
    ONCE (paste the owner key into Settings; distribute co-signer keys to their holders) and writes the PUBLIC
    trust root under --base-dir. Off-by-default: nothing is armed until you also authorize AND pass --open-pr."""
    from .live.destruction_provision import default_paths, generate_authority, write_trust_root
    try:
        gen = generate_authority(threshold=args.threshold, worker_count=args.signers, owner_id=args.owner_id)
    except ValueError as exc:
        print(f"vigil provision-destruction: {exc}", file=sys.stderr)
        return 2
    tr_path = write_trust_root(args.base_dir, gen.trust_root_json)
    paths = default_paths(args.base_dir)
    print("=== vigil provision-destruction — m-of-n destruction quorum ===")
    print(f"threshold          : {gen.threshold}-of-{len(gen.private_keys)}   "
          f"mandatory signer(s): {', '.join(gen.mandatory_signer_ids)}")
    print(f"trust root (public): {tr_path}")
    print(f"nonce ledger       : {paths['ledger']}  (auto-created on first PR)")
    print()
    print("PRIVATE SIGNING KEYS — shown ONCE; NOT stored by this command. Save/distribute now:")
    for kid, priv in gen.private_keys:
        where = ("→ paste into Settings as VIGIL_DESTRUCTION_OWNER_KEY (or export it)"
                 if kid in gen.mandatory_signer_ids
                 else "→ hand to this co-signer; keep it OFF this machine for real separation of duties")
        print(f"    [{kid}] {priv}")
        print(f"          {where}")
    print()
    print("Then, per fix: (1) `vigil patch --finding-envelope … --target-repo R` (dry run → prints the action);")
    print("               (2) `vigil authorize-destruction --base-dir "
          f"{args.base_dir} --action-id … --slug … --target R`;")
    print("               (3) `vigil patch … --target-repo R --open-pr` (auto-discovers the signed authorization).")
    if gen.threshold == 1:
        print()
        print("NOTE: threshold=1 (solo) — whoever holds the owner key can authorize a PR. For separation of "
              "duties, re-run with `--signers N --threshold M` (M>1) and keep co-signer keys on other machines.")
    return 0


def _cmd_authorize_destruction(args: argparse.Namespace) -> int:
    """Sign ONE destructive action (from a `vigil patch` dry run) with the owner key (read from the
    VIGIL_DESTRUCTION_OWNER_KEY env / Settings — never argv) plus any --worker-key co-signers, producing the
    single-use, window-bounded signed-authorization.json that `vigil patch --open-pr` consumes."""
    import os
    import time

    from .live.destruction_provision import default_paths, fresh_nonce, load_worker_key_file, sign_action
    owner_priv = os.environ.get("VIGIL_DESTRUCTION_OWNER_KEY", "").strip()
    if not owner_priv:
        print("vigil authorize-destruction: no owner signing key — set VIGIL_DESTRUCTION_OWNER_KEY (paste it in "
              "Settings, or export it). Run `vigil provision-destruction` to mint one.", file=sys.stderr)
        return 2
    signers: list = [(args.owner_id, owner_priv)]
    for spec in (args.worker_key or []):
        try:
            signers.append(load_worker_key_file(spec))
        except ValueError as exc:
            print(f"vigil authorize-destruction: {exc}", file=sys.stderr)
            return 2
    try:
        doc = sign_action(action_id=args.action_id, engagement_slug=args.slug, target=args.target,
                          signer_private_keys=signers, now=time.time(), window_s=args.window_s,
                          nonce=fresh_nonce())
    except ValueError as exc:
        print(f"vigil authorize-destruction: {exc}", file=sys.stderr)
        return 2
    out = args.out or default_paths(args.base_dir)["signed"]
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)     # single-use auth → owner-only file
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(doc)
    print(f"=== vigil authorize-destruction — action {args.action_id!r} ===")
    print(f"signed by : {', '.join(kid for kid, _ in signers)}")
    print(f"window    : {int(args.window_s)}s  (single-use; within the 900s dead-man's-switch)")
    print(f"written   : {out}")
    print(f"Then: vigil patch … --base-dir {args.base_dir} --target-repo {args.target} --open-pr")
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


def _cmd_proof_export(args: argparse.Namespace) -> int:
    """`vigil proof-export` — assemble a CLIENT-VERIFIABLE proof bundle from a run's oracle-confirmed FACTs
    (Proof Studio C1). The bundle re-verifies OFFLINE with zero trust in VIGIL: `python -m framework.v2
    evidence verify --report reverifiable.json --bundle <out> --trust-root <out>/trust-root.json
    --evidence-root <out>/evidence` exits 0 iff every certificate's signature, oracle reproduction, bound raw
    bytes, and the chain/head all hold. Offense-side (bundle.py lazy-imports framework); the governance
    private key is only ever an in-process argument, never argv — only the public trust root is written."""
    import os

    from .proof.bundle import export_bundle

    run_dir = args.run_dir or os.environ.get("VIGIL_PROOF_RUN_DIR") or ""
    if not run_dir:
        print("proof-export: no run dir — pass --run-dir <abs> or set VIGIL_PROOF_RUN_DIR", file=sys.stderr)
        return 1
    if not Path(run_dir).is_dir():
        print(f"proof-export: run dir not found: {run_dir}", file=sys.stderr)
        return 1
    out = args.out or str(Path(run_dir) / "proof-bundle")
    res = export_bundle(run_dir=run_dir, out_dir=out, engagement_slug=(args.slug or "engagement"),
                        base_dir=(args.base_dir or None))
    if not res.get("ok"):
        print(f"proof-export: {res.get('error', 'export failed')}", file=sys.stderr)
        return 1
    print("=== vigil proof-export (client-verifiable proof bundle) ===")
    print(f"bundle:       {res['bundle']}")
    print(f"certificates: {res['certificates']} oracle-confirmed FACT(s)")
    print(f"trust-root fingerprint: {res.get('trust_root_fingerprint', '')}")
    print("  PUBLISH this fingerprint OUT-OF-BAND — the client pins it (--trust-root-fingerprint) so a "
          "bundle re-signed under another key is refused.")
    print(f"verify:       cd {res['bundle']} && {res['verify_cmd']}")
    return 0


def _cmd_up(args: argparse.Namespace) -> int:
    """`vigil up` — bring the WHOLE unified UI up at ONE origin and federate the two trust planes
    behind a self-contained reverse proxy. EXEC-ONLY: it spawns the three backends (sigil cockpit,
    crucible console, crucible api) as separate OS processes in their OWN venvs (via dispatch) and
    serves the bundle itself — it imports NO framework/strix/sigil, so the two trust domains are never
    co-loaded in one interpreter. Binds loopback (or a private/tunnel IP); refuses a public bind."""
    from .uiproxy import run_up
    return run_up(host=args.host, port=args.port, domain=args.domain, base_dir=args.base_dir,
                  no_browser=args.no_browser,
                  insecure_no_api_key=getattr(args, "insecure_no_api_key", False),
                  with_feed=getattr(args, "with_feed", False),
                  feed_slug=getattr(args, "feed_slug", ""),
                  feed_interval=getattr(args, "feed_interval", 3600),
                  with_voice=getattr(args, "with_voice", False),
                  with_gesture=getattr(args, "with_gesture", False))


def _cmd_down(args: argparse.Namespace) -> int:
    """`vigil down` — stop a running `vigil up` (terminate the backends + proxy tracked in the pids
    file). EXEC-ONLY: imports NO framework/strix/sigil."""
    from .uiproxy import run_down
    return run_down(base_dir=args.base_dir)


def _cmd_knowledge(args: argparse.Namespace) -> int:
    """`vigil knowledge sync|push|status` (K6) — the operator-gated `knowledge/` → GitHub sync.

    `sync` regenerates the committed knowledge manifest, SCANS knowledge/ for secrets (refuses the commit if
    any is found), then `git add knowledge/` + `git commit`. `push` is the SEPARATE, explicit outward act.
    Committing a file makes nothing a FACT (the graph counterparts stay intel/ungrounded). EXEC-ONLY: imports
    no framework/strix/sigil engine."""
    import json

    from . import knowledge_sync as ks

    def _emit(obj: dict) -> None:
        print(json.dumps(obj, indent=2, default=str))

    if args.knowledge_action == "status":
        _emit(ks.status())
        return 0
    if args.knowledge_action == "push":
        _emit(ks.push(dry_run=args.dry_run))
        return 0
    # sync
    res = ks.sync(message=args.message, dry_run=args.dry_run)
    if not res.get("ok"):
        print(f"vigil knowledge sync: REFUSED — {res.get('refused')}", file=sys.stderr)
        for relpath, name in res.get("secrets", []):
            print(f"  secret ({name}): {relpath}", file=sys.stderr)
        return 3
    _emit(res)
    return 0


def _cmd_learn_drain(args: argparse.Namespace) -> int:
    """`vigil learn-drain` — drain the sovereign→offense learn-grant spool (A2 keystone): verify each
    owner-signed ``learn_grant`` under the owner PUBLIC key, re-derive the lead from the OFFENSE intel, and
    run K3 deep-learn. Fail-closed; the offense per-slug kill-switch DEFERS a grant. Signature check is
    ``vigil_core``-only; ``deep_learn`` is lazy-imported inside the drain (this module imports no framework at
    module scope, so the two-env boundary holds)."""
    import json
    from pathlib import Path

    from . import learn_drain

    owner_pubkey = (args.owner_pubkey or "").strip()
    if not owner_pubkey:
        print("vigil learn-drain: --owner-pubkey is required (the sovereign owner PUBLIC key)", file=sys.stderr)
        return 2
    if args.skills_dir:
        skills_dir = Path(args.skills_dir)
    else:
        from . import knowledge_sync
        skills_dir = knowledge_sync.repo_root() / "knowledge" / "skills"
    watcher = learn_drain.LearnGrantWatcher(spool_dir=args.spool, owner_pubkey=owner_pubkey,
                                            skills_dir=skills_dir)
    if args.watch:
        print(f"  draining learn-grants from {args.spool}/incoming → K3 deep-learn "
              f"(skills → {skills_dir}); Ctrl-C to stop")
        try:
            watcher.watch(interval=args.interval)
        except KeyboardInterrupt:
            pass
        return 0
    print(json.dumps(watcher.drain(), indent=2))
    return 0


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
    pe.add_argument("--session", default="",
                    help="the SESSION this run belongs to (F3): the per-session knowledge-graph partition "
                         "key. Runs sharing a session accumulate + reuse each other's prior context; empty "
                         "falls back to the slug. A partition/organisation key only — it grants no authority.")
    pe.add_argument("--connect", default="",
                    help="comma-separated CONNECTED session ids (F4) whose graph partitions this run may "
                         "UNION as priors (a read-time scope; each prior stays origin-tagged + "
                         "non-authoritative). Pass the ids you connected in the Sessions screen. Empty = isolated.")
    pe.add_argument("--replay", default="", help="a JSON file of scripted decisions (keyless-live)")
    pe.add_argument("--access-log", default="")
    pe.add_argument("--auth-log", default="")
    pe.add_argument("--conn-log", default="")
    pe.add_argument("--max-iterations", type=int, default=12)
    pe.add_argument("--approve-offense", action="store_true",
                    help="the operator's standing approval to run queued offense tools against their "
                         "own chartered loopback (the human leg of the conjunctive gate; scope still enforced)")
    pe.set_defaults(func=_cmd_engage)

    pei = sub.add_parser("engage-instruct",
                         help="add a mid-run, natural-language instruction to a LIVE engagement (advisory; "
                              "the running engage folds it into its next reasoning step — every action it "
                              "prompts still waits for your approval)")
    pei.add_argument("slug", help="the engagement slug to steer (same --slug you gave `vigil engage`)")
    pei.add_argument("text", help="the instruction, e.g. \"also check the admin API for BOLA\"")
    pei.add_argument("--base-dir", default=".vigil-live")
    pei.set_defaults(func=_cmd_engage_instruct)

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

    ppatch = sub.add_parser(
        "patch", help="run the gated auto-patch ladder over a PROVENANCE-GROUNDED confirmed finding")
    # finding source (EXACTLY one) — a raw-JSON finding is never accepted
    ppatch.add_argument("--finding-envelope", default="",
                        help="a signed inert finding envelope (soundest): its m-of-n governance signature is "
                             "verified with vigil_core under an OWNER-signed delegation. Needs --owner-pubkey, "
                             "--delegation, --scope.")
    ppatch.add_argument("--from-spine", default="",
                        help="an engagement slug: rebuild a confirmed fact from {slug}.spine under --base-dir "
                             "after a fail-closed integrity audit. Use --finding-ref to disambiguate.")
    ppatch.add_argument("--owner-pubkey", default="",
                        help="the pinned owner PUBLIC key (base64) — the delegation trust anchor")
    ppatch.add_argument("--delegation", default="",
                        help="an owner-signed offense-governance DelegationCert JSON file")
    ppatch.add_argument("--scope", default="",
                        help="the engagement slug the envelope + delegation must cover")
    ppatch.add_argument("--finding-ref", default="",
                        help="pick this fact by ref (--from-spine, when the spine has >1 confirmed fact)")
    ppatch.add_argument("--base-dir", default=".vigil-live",
                        help="engagement home holding {slug}.spine + vault (--from-spine)")
    # target + workdir + coder
    ppatch.add_argument("--target-repo", default="",
                        help="the LOCAL path or git URL to fix (operator deployment choice; not part of the "
                             "signed finding)")
    ppatch.add_argument("--target-branch", default="")
    ppatch.add_argument("--repo-base-dir", default=".vigil-live/patch",
                        help="base dir for the DISPOSABLE clone/workdir (the source repo is never modified)")
    ppatch.add_argument("--model", default="",
                        help="the Claude coder model — overrides the model chosen in Settings; empty ⇒ use the "
                             "Settings choice (CRUCIBLE_ANTHROPIC_MODEL) or the current default. The API key is "
                             "read from ANTHROPIC_API_KEY env, never argv.")
    # legs — each an explicit opt-in; all off ⇒ a non-destructive propose-only dry run
    ppatch.add_argument("--apply-edits", action="store_true",
                        help="apply the proposed fix into the DISPOSABLE clone + sandbox-build (safe: the source "
                             "is never touched, no PR). Off (default) ⇒ propose-only.")
    ppatch.add_argument("--approve", action="store_true",
                        help="the operator's standing approval for the reversible local legs (clone/edit in the "
                             "disposable clone)")
    ppatch.add_argument("--open-pr", action="store_true",
                        help="OFF by default. Open a gated PR — requires --signed-authorization, "
                             "--authority-trust-root, --mandatory-signer (>=1, incl. the owner), --ledger, and a "
                             "GITHUB_TOKEN in the environment.")
    ppatch.add_argument("--signed-authorization", default="",
                        help="the m-of-n SignedDestructionAuthorization JSON (--open-pr)")
    ppatch.add_argument("--authority-trust-root", default="",
                        help="the destruction TrustRoot JSON (--open-pr)")
    ppatch.add_argument("--mandatory-signer", action="append", default=[],
                        help="a MANDATORY signer key_id (repeatable; MUST include the owner) (--open-pr)")
    ppatch.add_argument("--ledger", default="",
                        help="the durable single-use nonce ledger DIRECTORY (--open-pr; one authorization → one PR)")
    ppatch.add_argument("--pr-base", default="", help="the PR base branch (default: the repo's default branch)")
    ppatch.set_defaults(func=_cmd_patch)

    pprov = sub.add_parser(
        "provision-destruction",
        help="mint the m-of-n destruction quorum keys for `vigil patch --open-pr` (prints keys ONCE)")
    pprov.add_argument("--base-dir", default=".vigil-live",
                       help="where the PUBLIC trust root + nonce ledger live (shared with `vigil patch`)")
    pprov.add_argument("--threshold", type=int, default=1,
                       help="m in m-of-n — how many signers must sign (default 1 = solo owner)")
    pprov.add_argument("--signers", type=int, default=0,
                       help="number of ADDITIONAL co-signer keys beyond the owner (default 0). Use >0 with "
                            "--threshold >1 and keep co-signer keys off this machine for separation of duties")
    pprov.add_argument("--owner-id", default="owner", help="the mandatory owner signer's key id")
    pprov.set_defaults(func=_cmd_provision_destruction)

    pauth = sub.add_parser(
        "authorize-destruction",
        help="sign ONE destructive action (from a `vigil patch` dry run) → the single-use signed authorization")
    pauth.add_argument("--action-id", required=True, help="the pr-<remediation_id> printed by the dry run")
    pauth.add_argument("--slug", required=True, help="the engagement_slug printed by the dry run")
    pauth.add_argument("--target", required=True, help="the target repo printed by the dry run (must match)")
    pauth.add_argument("--base-dir", default=".vigil-live", help="where to write signed-authorization.json")
    pauth.add_argument("--out", default="", help="output path (default: <base-dir>/signed-authorization.json)")
    pauth.add_argument("--owner-id", default="owner", help="the owner signer's key id (matches provisioning)")
    pauth.add_argument("--window-s", type=float, default=600.0,
                       help="validity window in seconds (single-use; total window must stay ≤900s)")
    pauth.add_argument("--worker-key", action="append", default=[],
                       help="a co-signer as key_id=/path/to/keyfile (repeatable; read from FILE, never argv). "
                            "The owner key comes from VIGIL_DESTRUCTION_OWNER_KEY.")
    pauth.set_defaults(func=_cmd_authorize_destruction)

    ppe = sub.add_parser("proof-export",
                         help="assemble a client-verifiable proof bundle from a run's oracle-confirmed FACTs "
                              "(offline, zero-trust re-verify)")
    ppe.add_argument("--run-dir", default="", help="the run dir to export (else $VIGIL_PROOF_RUN_DIR)")
    ppe.add_argument("--out", default="", help="output bundle dir (default <run-dir>/proof-bundle)")
    ppe.add_argument("--slug", default="engagement", help="engagement slug stamped into the certificates")
    ppe.add_argument("--base-dir", default="", help="governance-key home (stable signer); default = run dir")
    ppe.set_defaults(func=_cmd_proof_export)

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
    pu.add_argument("--insecure-no-api-key", action="store_true",
                    help="with --domain, proceed even if CRUCIBLE_API_KEY is unset — ONLY if your edge "
                         "proxy adds authentication (otherwise the gated offense api is internet-exposed)")
    pu.add_argument("--base-dir", default=".vigil-live",
                    help="engagement home for the runtime serve dir (.vigil-live/ui/) + pids file")
    pu.add_argument("--with-feed", action="store_true",
                    help="also run the recurring vuln-intel feed (NVD/OSV/CISA-KEV) as a gated sidecar. "
                         "OFF by default (recurring LIVE egress); needs --feed-slug. Honors that slug's "
                         "kill-switch every tick. Everything minted is an intel LEAD, never a fact.")
    pu.add_argument("--feed-slug", default="",
                    help="with --with-feed: the engagement store the feed persists into (and the Knowledge "
                         "screen reads). Required to actually start the feed.")
    pu.add_argument("--feed-interval", type=int, default=3600,
                    help="with --with-feed: seconds between feed refreshes (default 3600)")
    pu.add_argument("--with-voice", action="store_true",
                    help="also run SIGIL voice-nav (S2): a long-running `sigil voice --mic` producer of the "
                         "`sigil.nav` the HUD channel carries. OFF by default (needs a mic). A1 signal — "
                         "navigates a KNOWN in-app screen only, injects nothing into the OS.")
    pu.add_argument("--with-gesture", action="store_true",
                    help="also enable gesture NAV-MODE (S3): flips the latch ON so an owner-armed PHONE "
                         "gesture session navigates the UI. OFF by default. A1 signal, injects nothing.")
    pu.set_defaults(func=_cmd_up)

    pdn = sub.add_parser("down", help="stop a running `vigil up` (backends + proxy)")
    pdn.add_argument("--base-dir", default=".vigil-live",
                     help="engagement home holding the ui/pids file written by `vigil up`")
    pdn.set_defaults(func=_cmd_down)

    pk = sub.add_parser("knowledge", help="operator-gated sync of the living knowledge/ folder to git "
                                          "(regenerate + secret-scan + commit; push is separate). NB: the "
                                          "deep-learn / self-evolve verbs are `vigil crucible knowledge "
                                          "draft|learn|skills|evolve` (offense engine), a DIFFERENT surface.")
    pk.add_argument("knowledge_action", choices=["sync", "push", "status"],
                    help="sync = regenerate+scan+commit knowledge/ · push = git push · status = what would commit")
    pk.add_argument("-m", "--message", default="", help="commit message for `sync`")
    pk.add_argument("--dry-run", action="store_true", dest="dry_run",
                    help="show the git plan without committing/pushing")
    pk.set_defaults(func=_cmd_knowledge)

    pld = sub.add_parser("learn-drain",
                         help="drain the sovereign→offense learn-grant spool: verify each owner-signed grant "
                              "and run K3 deep-learn (the K2b→K3 bridge; fail-closed, kill-switch-deferred)")
    pld.add_argument("--spool", required=True, help="the learn-grant spool dir (its incoming/ is drained)")
    pld.add_argument("--owner-pubkey", required=True, help="the sovereign owner PUBLIC key (base64)")
    pld.add_argument("--skills-dir", default="",
                     help="where deep-learn writes FIND/DETECT/PREVENT skills (default: <repo>/knowledge/skills)")
    pld.add_argument("--watch", action="store_true", help="keep draining as new grants arrive; Ctrl-C to stop")
    pld.add_argument("--interval", type=float, default=2.0, help="(watch) seconds between drains")
    pld.set_defaults(func=_cmd_learn_drain)

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
