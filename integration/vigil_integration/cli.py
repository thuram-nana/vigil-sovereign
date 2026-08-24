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
  * ``vigil posture attest|verify|endpoint`` — mint + sign a Certificate of Non-Exploitability from a live
                                    loopback coverage scan, re-verify a bundle OFFLINE via its own shipped
                                    VIGIL-free verifier, or serve the signed bundle read-only to a
                                    counterparty (loopback/tunnel-bound; default port 8788, off the
                                    console's 8787).
  * ``vigil patch --finding-envelope|--from-spine`` — run the gated auto-patch ladder over a PROVENANCE-
                                    GROUNDED confirmed finding (signed envelope OR the engagement's signed
                                    spine — never raw JSON). Default is a non-destructive propose-only dry
                                    run; ``--apply-edits`` applies into a disposable clone; ``--open-pr`` (off
                                    by default) opens a gated PR under a provisioned m-of-n destruction quorum;
                                    ``--verify-base-url`` (off by default) DELEGATES fix-verification to the
                                    same four-state prove machinery ``vigil remediate --prove`` drives, against
                                    the operator's PATCHED redeployment, so a signed ``remediated`` can be
                                    earned instead of an unverified proposal.
  * ``vigil provision-destruction`` — mint the m-of-n destruction quorum keys for ``vigil patch --open-pr``
                                    (prints the signing keys ONCE; writes the public trust root).
  * ``vigil authorize-destruction`` — sign ONE destructive action (from a ``vigil patch`` dry run) → the
                                    single-use, window-bounded signed authorization the PR leg consumes.
  * ``vigil up`` / ``vigil down``  — bring the WHOLE unified UI up at ONE origin behind a self-contained
                                    reverse proxy (federating the two trust planes), and stop it. EXEC-
                                    ONLY: spawns the three backends in their own venvs; imports no
                                    framework/strix/sigil (the two trust domains never co-load here).
  * ``vigil backup`` / ``vigil restore`` — off-box backup/restore of BOTH planes. Writes TWO SEPARATE
                                    passphrase-encrypted files (offense in-venv + sovereign via a
                                    ``.venv-sovereign/bin/sigil`` SUBPROCESS) — NEVER a merged archive, which
                                    would make one process hold both plane secrets (a FATAL-2 breach). Restore
                                    verifies each part's MANIFEST sha256 before invoking either leg and
                                    re-verifies the restored offense spine + evidence chain.
  * ``vigil upgrade``             — automated, crash-safe data migration of the sovereign spine:
                                    verify -> backup -> verify(backup) -> migrate -> verify -> report,
                                    ROLLING BACK to the verified backup on ANY failure (never a half-migrated
                                    store). EXECs ``.venv-sovereign/bin/sigil upgrade`` in its own venv; the
                                    sovereign startup itself refuses to run degraded on an un-migrated store.

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
import os
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
    # W9-4b: the opt-in refuse-to-start PRODUCTION gate. Checked FIRST — before the engine wiring is even
    # imported — so a refused production run neither loads the engine nor sends any traffic. INERT unless
    # VIGIL_POSTURE=production, so a normal engage is byte-identical to before.
    _gate = _enforce_production_gate("engage")
    if _gate is not None:
        return _gate
    from .live.think_claude import ReplayThinker
    from .live.wiring import EngineConfig, build_engine

    replay = None
    if args.replay:
        decisions = json.loads(Path(args.replay).read_text(encoding="utf-8"))
        replay = ReplayThinker(decisions)

    scope = [s.strip() for s in str(getattr(args, "scope", "") or "").split(",") if s.strip()]
    connect = [c.strip() for c in str(getattr(args, "connect", "") or "").split(",") if c.strip()]
    # --brain hexstrike: drive `think` with the homegrown, drift-free, propose-only decision brain instead
    # of the Claude/replay path. The gate + governed executor + oracle are unchanged (the brain proposes;
    # the engine gates; the oracle confirms). Import is local so a non-brain engage pulls nothing extra.
    brain = None
    if str(getattr(args, "brain", "") or "").strip().lower() == "hexstrike":
        from .brains.engine_think import BrainThink
        from .brains.hexstrike_brain import HexstrikeBrain
        from .brains.profile_observations import collect_engage_observations
        # The planner objective is --brain-objective (a closed enum), NOT --objective. --objective is the
        # engagement's free-text goal, which is recorded with the run and does not steer it; feeding it to
        # the planner meant one flag carried two incompatible meanings, and its "" default silently built
        # the SHORT plan while labelling it comprehensive.
        #
        # H3 — feed the profile from VERIFIED, PROVENANCED observations instead of leaving it empty. The
        # feed assembles VIGIL-owned observations available at engage-start (the signed-authority scope's
        # literal IPs + a normalized observations sidecar) and reduces them to analyze_target's kwargs.
        # Fail-soft: with no sources it returns all-empty kwargs, so a plain --brain engage proposes the
        # same chain as before (only the profile is now honest unknowns, never a fabricated risk).
        observations = collect_engage_observations(
            slug=args.slug, base_dir=args.base_dir, scope=scope,
            sidecar_path=(getattr(args, "brain_observations", "") or None))
        brain = BrainThink(HexstrikeBrain(), target=args.url,
                           objective=getattr(args, "brain_objective", None),
                           observations=observations)
    # GAP-1 — the per-session model sovereignty pick. --backend (LOCAL) and --model (CLOUD) are mutually
    # exclusive: a local backend routes think through the loopback-enforced provider with no cloud failover,
    # so simultaneously naming a cloud model string is contradictory. Fail-closed on the contradiction rather
    # than silently preferring one (which could be the cloud one — an egress the operator did not intend).
    pick_model = str(getattr(args, "model", "") or "").strip()
    pick_backend = str(getattr(args, "backend", "") or "").strip()
    if pick_model and pick_backend:
        print("vigil engage: --model (a cloud model) and --backend (a local backend) are mutually "
              "exclusive — pass exactly one.", file=sys.stderr)
        return 2
    if pick_backend:
        # --backend is LOCAL-intent only. Refuse an unrecognised name rather than let the engine fall to the
        # tier-gated cloud path (a silent cloud egress the operator did not intend — closes the "backend-name
        # list drift" hole). A recognised local backend routes through the loopback-enforced provider.
        from .live.think_claude import is_local_backend  # local import: pure fn, no heavy deps
        if not is_local_backend(pick_backend):
            print(f"vigil engage: --backend {pick_backend!r} is not a recognised LOCAL model backend "
                  f"(ollama / vllm / llama-cpp / tgi / self-hosted). A local pick must never fall back to a "
                  f"cloud model, so this is refused rather than run on cloud.", file=sys.stderr)
            return 2
    cfg = EngineConfig(
        slug=args.slug, session_id=str(getattr(args, "session", "") or ""),
        connections=tuple(connect),
        base_dir=args.base_dir, replay=replay, api_key=None, brain=brain,
        model=(pick_model or None), backend=(pick_backend or None),
        scope=tuple(scope) or ("127.0.0.1",),   # --scope is signed into the authority + enforced end-to-end
        access_log=args.access_log, auth_log=args.auth_log, conn_log=args.conn_log,
        max_iterations=args.max_iterations, owner_approves_offense=args.approve_offense,
        brain_execute_via_body=bool(getattr(args, "brain_execute_via_body", False)),
    )
    engine = build_engine(cfg)
    report = engine.engage(args.url, objective=args.objective, resume=bool(getattr(args, "resume", False)))

    print(f"=== vigil engage {args.url} (slug={report.slug}){' [RESUMED]' if report.resumed else ''} ===")
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

    LIVE FIX-VERIFICATION (GAP B, opt-in). Without ``--verify-base-url`` no fix-verification oracle is wired,
    so ``remediated`` stays False and the PR opens as an unverified PROPOSAL (byte-identical to before). With
    it, verification is DELEGATED to the SAME machinery ``vigil remediate --prove`` drives — there is
    deliberately NO second, weaker verification path: ``prove_remediation`` over a ``LiveHttpAdapter``, with
    its LIVE positive control through the injectable param, its per-run freshness challenge that MUST be
    echoed in the judged bytes (the ``F1_TARGET_ECHOES`` floor), the protocol-required silent trials and a
    SIGNED four-state certificate. ``REMEDIATED`` (and only a certificate that independently re-verifies)
    becomes a silent ``FixVerdict`` → ``remediated``; ``STILL_VULNERABLE`` becomes a firing one;
    ``INCONCLUSIVE`` / ``REFUSED`` RAISE, so ``verify_patch`` yields ``unverified``. Every case the oracle
    cannot even be BUILT for REFUSES before anything is patched (see ``_build_patch_fix_oracle``).

    WHAT A ``remediated`` FROM THIS PATH MEANS — EXACTLY, AND NO MORE. The ``F1_TARGET_ECHOES`` floor
    establishes RESPONSIVENESS / FRESHNESS ONLY: SOME HTTP responder at ``--verify-base-url`` returned THIS
    run's nonce in the bytes the oracle judged. It does NOT establish that the responder was the application,
    and it does NOT establish that the request reached the vulnerable endpoint. The claim earned here is
    therefore exactly: "the ORIGINAL oracle did NOT fire over freshly captured bytes from the host the
    operator nominated" — nothing about which component produced those bytes. What the floor DOES rule out is
    the NON-echoing answered response (a static 403 block page, a 404 that reflects nothing): that is
    INCONCLUSIVE → ``unverified``, never a fix. KNOWN RESIDUAL, not closed: an ECHOING but unrelated responder
    — an echoing 404, a block page that reflects the request URI/query, or a different service on that host —
    satisfies F1 while the exploit never reaches the app, and its silence IS minted as ``remediated``. The
    operator excludes it by pointing ``--verify-base-url`` at the REAL application.

    WITHOUT ``--open-pr``, NOTHING IS VERIFIED — and the run says so instead of refusing. The ladder verifies
    at step (6), strictly AFTER the PR leg, so a run without ``--open-pr`` stops at the PR gate and the oracle
    is never consulted. What actually happens: the oracle is still BUILT and validated up front (so channel /
    positive-control / scope diagnostics are reachable without provisioning the PR quorum), a
    ``verify_status : WILL NOT RUN`` notice is printed on stdout beside the ``verify_target`` line (and as a
    warning on stderr), the run PROCEEDS through the ladder to the PR gate, and the strict exit code below
    makes the run a FAILURE rather than a silent success. It is NOT refused up front.

    EXIT CODE: when verification is requested, only a signed ``remediated`` exits 0 —
    ``opened-pr-still-vulnerable`` / ``opened-pr-unverified`` / a run that never reached verification exit
    non-zero, so a script cannot read "did not refuse" as "fixed".

    ``--finding-ref`` never redirects the verification lookup: with ``--verify-base-url``, a non-empty
    ``--finding-ref`` that differs from the trusted finding's OWN ref is REFUSED (another finding's retained
    positive control must never mint a remediation attributed to this one).

    HONEST LIMIT: the re-drive proves only that the ORIGINAL oracle did not fire over fresh,
    challenge-echoing bytes captured from ``--verify-base-url`` (see above for what that does and does not
    establish about WHO answered). That this deployment actually carries THIS run's patch is the operator's
    assertion — the disposable sandbox clone is not cryptographically bound to the running service, and the
    signed certificate binds the silent oracle context, not the applied diff. The silent case's other
    residuals (a payload-discriminating WAF, a param-stripping edge in front of an echoing gateway) are
    ``LiveHttpAdapter``'s, inherited unchanged — see ``_build_patch_fix_oracle``.
    SIDE EFFECT: a run that actually reaches verification (re)provisions — OVERWRITING — the engagement's
    signed CRUCIBLE authority for the slug, scoped to the verification host (as ``vigil remediate`` does).
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

    # (3) OPT-IN LIVE FIX-VERIFICATION (GAP B). Without --verify-base-url this stays None and the run is
    #     BYTE-IDENTICAL to before: `remediated` stays False and a PR (if any) opens as an unverified PROPOSAL.
    #     With it, verification is DELEGATED to the four-state `vigil remediate --prove` machinery (live
    #     positive control + freshness echo + signed certificate); there is no second, weaker path. Every
    #     case the oracle cannot even be BUILT for REFUSES here (nothing is patched).
    verify_oracle = None
    if str(getattr(args, "verify_base_url", "") or "").strip():
        # --finding-ref must NEVER redirect which retained positive control drives the verification: the
        # oracle is built for the TRUSTED finding, so an operator-supplied ref that disagrees with that
        # finding's own ref is a REFUSAL, not an override (else finding B's retained control + exploit could
        # mint a signed remediation attributed to finding A).
        ref_why = _finding_ref_override_refusal(finding, getattr(args, "finding_ref", ""))
        if ref_why:
            print(f"vigil patch: fix-verification REFUSED (fail-closed): {ref_why}", file=sys.stderr)
            return 2
        verify_oracle, vwhy = _build_patch_fix_oracle(
            finding=finding, slug=slug, base_dir=args.base_dir,
            run_dir=(str(getattr(args, "verify_run_dir", "") or "") or args.base_dir),
            verify_base_url=args.verify_base_url)
        if verify_oracle is None:
            print(f"vigil patch: fix-verification REFUSED (fail-closed): {vwhy}", file=sys.stderr)
            return 2
        print(f"verify_target  : {args.verify_base_url}   (delegated to the four-state `remediate --prove` "
              f"machinery; 'remediated' only on a REMEDIATED certificate that re-verifies)")
        # The oracle is BUILT and sound (channel, positive control, reconstructed exploit and charter scope
        # all check out — validated FIRST so those diagnostics are reachable without provisioning the PR
        # quorum). But the ladder VERIFIES AT STEP (6), strictly AFTER the PR leg (autopatch/loop.py): without
        # --open-pr the run stops at the PR gate ("pr-denied") and the oracle is NEVER consulted. The run
        # PROCEEDS anyway (so the dry run keeps its normal value) and says so HERE, on stdout, immediately
        # under verify_target — the two lines cannot be read apart — and the strict exit code below makes it
        # a failure rather than a silent success.
        if not bool(getattr(args, "open_pr", False)):
            _no_verify = ("verify_status  : WILL NOT RUN — the gated ladder verifies at step (6), AFTER the "
                          "PR leg, so without --open-pr this run stops at the PR gate and NOTHING is "
                          "verified. The run continues, but its exit code will be NON-ZERO because a "
                          "verified result was requested and none was produced. Re-run with --open-pr "
                          "(provisioned m-of-n destruction authorization + a GITHUB_TOKEN) to earn a signed "
                          "`remediated`.")
            print(_no_verify)
            print(f"vigil patch: WARNING — {_no_verify}", file=sys.stderr)

    # (4) config + run the gated ladder. client=None ⇒ the coder is built from ANTHROPIC_API_KEY (env, never
    #     argv); apply_edits/pr_enabled are explicit opt-ins; the GitHub token is read from the child env only.
    cfg = CodefixConfig(
        target_repo=finding.target_repo, base_dir=args.repo_base_dir, target_branch=args.target_branch,
        apply_edits=bool(args.apply_edits), model=resolve_model(args.model),  # --model > Settings choice > default
        pr_enabled=bool(args.open_pr), pr_base=args.pr_base)
    result = autopatch_live(finding, config=cfg, client=None, operator_present=bool(args.approve),
                            quorum=quorum, verify_oracle=verify_oracle)

    print("--- result ---")
    print(f"status         : {result.status}")
    print(f"applied_paths  : {list(result.patched_paths) or '-'}")
    print(f"opened_pr      : {result.opened_pr}   pr_ref={result.pr_ref or '-'}")
    print(f"remediated     : {result.remediated}")
    if verify_oracle is not None:
        print(f"verification   : {getattr(result.verification, 'status', '(none)')}")
    if result.reason:
        print(f"reason         : {result.reason}")
    # Honest exit. Without verification requested: non-zero only on an outright refusal (not-confirmed / gate
    # deny) — a propose-only or applied-in-clone or opened-PR run is a success and a "no proposal" (e.g. no API
    # key) is reported, not crashed. WITH --verify-base-url the caller asked "is it actually fixed?", so ONLY a
    # signed `remediated` is success: `opened-pr-still-vulnerable` and `opened-pr-unverified` MUST exit non-zero,
    # or `vigil patch --verify-base-url ... && echo fixed` would print "fixed" for a STILL-VULNERABLE target.
    if str(result.status).startswith("refused"):
        return 1
    if verify_oracle is not None and not bool(result.remediated):
        return 1
    return 0


def _remediate_safe_ref(ref: str) -> str:
    """A filesystem-safe slug of a finding ref for the certificate filename (never a path-traversal)."""
    s = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in str(ref or "finding"))
    s = s.strip("._") or "finding"
    return s[:80]


def _match_reverifiable_entry(entries: "list[dict]", ref: str, finding_ref: str) -> "Optional[dict]":
    """Pick the retained re-verifiable entry that belongs to THIS finding, by ``check_id`` == the KNOWN finding
    ref (explicit ``--finding-ref`` or the trusted finding's own ref). When a ref is known, an EXACT match is
    REQUIRED: no match ⇒ None (the caller refuses honestly) — the single-entry "sole entry" convenience must
    NEVER override a known ref, or a REMEDIATED for finding A could be minted from finding B's retained
    positive control + exploit (a false-negative on a live-vulnerable finding). The sole-entry fallback is
    reachable ONLY when NO ref is known at all; the CLI path never hits it because ``_cmd_remediate`` REFUSES an
    empty finding ref before calling here (the invariant is ENFORCED, not assumed)."""
    if not entries:
        return None
    want = str(finding_ref or "").strip() or str(ref or "").strip()
    if want:
        for e in entries:
            if isinstance(e, dict) and str(e.get("check_id") or "") == want:
                return e
        return None   # a KNOWN ref that matches nothing → refuse; never substitute another finding's control
    if len(entries) == 1 and isinstance(entries[0], dict):
        return entries[0]
    return None


def _finding_ref_override_refusal(finding: Any, finding_ref: str) -> str:
    """Refuse a ``--finding-ref`` that OVERRIDES the trusted finding's own ref. Returns a refusal reason, or
    ``""`` when there is no conflict (an empty ref, or one naming this same finding).

    ``--finding-ref`` exists to DISAMBIGUATE which confirmed fact to drive, and on the ``--from-spine`` path
    it does exactly that (the spine load selects by it, so the two always agree). On the
    ``--finding-envelope`` path the trusted finding's ref comes from the SIGNED certificate and the flag is
    not consulted — so passing it on to select the RETAINED re-verifiable material would let finding B's
    positive control + exploit drive a result attributed to finding A. Fail-closed: refuse the disagreement
    outright rather than silently pick either side."""
    want = str(finding_ref or "").strip()
    own = str(getattr(finding, "ref", "") or "").strip()
    if want and want != own:
        return (f"--finding-ref {want!r} does not match the trusted finding's own ref {own!r}. The retained "
                f"positive control is selected by the TRUSTED finding's ref ONLY — another finding's retained "
                f"control + exploit must never drive a result attributed to this one (fail-closed).")
    return ""


# The query param the live re-drive carries the per-run freshness challenge on (all three re-drive verbs).
# It MUST NOT collide with the finding's own injectable param — see `_nonce_param_collision_refusal`.
_REDRIVE_NONCE_PARAM = "rc"


def _nonce_param_collision_refusal(param: str, nonce_param: str = _REDRIVE_NONCE_PARAM) -> str:
    """Refuse a finding whose INJECTABLE param IS the freshness-challenge param. Returns a reason, or ``""``.

    The live re-drive puts the exploit on ``param`` and the per-run challenge on a SEPARATE ``nonce_param``
    (``rc``). If a finding's own injectable param is literally ``rc``, the two COLLIDE when the adapter builds
    the re-drive URL and the challenge OVERWRITES the exploit payload: the exploit is never sent, so oracle
    silence says nothing about a fix — yet that silence would be minted as a signed remediation over a
    STILL-VULNERABLE target. ``LiveHttpAdapter`` / ``DifferentialHttpAdapter`` also refuse this at
    construction (so every caller inherits the guard); this pre-flight makes the CLI refuse EARLIER still —
    before the ladder runs and before any request is sent to the target — with a message that says why."""
    p = str(param or "").strip()
    if p and p == str(nonce_param or "").strip():
        return (f"the finding's injectable param is {p!r}, which is also the param the live re-drive carries "
                f"the per-run freshness challenge on. They would collide: the challenge would OVERWRITE the "
                f"exploit payload, so the exploit would never be sent and a silent oracle would say nothing "
                f"about the fix — yet that silence would be minted as a remediation over a still-vulnerable "
                f"target. Refusing (fail-closed).")
    return ""


def _reconstruct_exploit_request(finding: Any, entry: dict) -> "tuple[Optional[dict], str]":
    """Reconstruct the ORIGINAL exploit request ``(endpoint_path, param, payload)`` from the RETAINED,
    provenance-grounded finding + its re-verifiable entry — never fabricated. Sources, in order:

      * ``payload``      ← the entry's retained decoded request value (``oracle_context.request_payload``),
                           the request-side field the FindingContext carries; without it the exploit value
                           was not retained and we cannot honestly re-drive → an honest error.
      * ``param``        ← ``oracle_context.payload_param`` (the named insertion point that rides on the
                           certificate), else the entry's ``insertion_point`` when it is a bare token.
      * ``endpoint_path``← an explicit retained path (``oracle_context.requested_path`` / ``endpoint``),
                           else the ``insertion_point`` when it is path-like, else the finding target's path.

    Returns ``(spec, "")`` on success or ``(None, why)`` when the retained data is insufficient (fail-closed:
    we refuse rather than guess a payload/param/endpoint the finding never recorded)."""
    from urllib.parse import urlsplit

    octx = entry.get("oracle_context") if isinstance(entry.get("oracle_context"), dict) else {}
    insertion = str(entry.get("insertion_point") or "").strip()
    ftarget = str(getattr(finding, "target", "") or "").strip()

    payload = str(octx.get("request_payload") or "").strip()

    param = str(octx.get("payload_param") or "").strip()
    if not param and insertion and not insertion.startswith("/") and "://" not in insertion:
        param = insertion

    endpoint = ""
    for k in ("requested_path", "endpoint_path", "endpoint"):
        v = octx.get(k)
        if isinstance(v, str) and v.strip():
            endpoint = v.strip()
            break
    if not endpoint:
        if insertion.startswith("/"):
            endpoint = insertion
        elif "://" in insertion:
            endpoint = urlsplit(insertion).path or ""
    if not endpoint and ftarget:
        endpoint = urlsplit(ftarget).path if "://" in ftarget else (ftarget if ftarget.startswith("/") else "")
    # Hygiene (defense-in-depth): an absolute-URL endpoint is reduced to its PATH so it can never carry a host
    # (the adapter's path-concat already neutralizes host, and the charter scope gate bounds it — this makes the
    # intent explicit at the source rather than relying on a downstream accident).
    if "://" in endpoint:
        endpoint = urlsplit(endpoint).path or ""

    missing = [name for name, val in
               (("endpoint_path", endpoint), ("param", param), ("payload", payload)) if not val]
    if missing:
        return None, (
            f"the retained finding data is insufficient to reconstruct the exploit request (missing: "
            f"{', '.join(missing)}). The re-verifiable entry must carry the decoded request value "
            f"(oracle_context.request_payload), the insertion point (payload_param / insertion_point), and a "
            f"reconstructable endpoint — refusing to fabricate one (fail-closed).")
    return {"endpoint_path": endpoint, "param": param, "payload": payload}, ""


# The ONE oracle family the live fix-verification re-drive genuinely supports (GAP B). It is the same family
# `vigil remediate --prove` re-drives: a response-side error signature. Any other channel is REFUSED rather
# than mis-driven — see `_build_patch_fix_oracle`.
_PATCH_VERIFY_CHANNEL = "error_signature"


def _build_patch_fix_oracle(*, finding: Any, slug: str, base_dir: str, run_dir: str,
                            verify_base_url: str) -> "tuple[Optional[Any], str]":
    """GAP B — build the LIVE fix-verification oracle ``vigil patch`` threads into ``autopatch_live``.

    Returns ``(oracle, "")`` or ``(None, why)``. It is the ONLY way ``vigil patch`` can mint ``remediated``,
    and every gate is fail-closed: a wrong 'remediated' is worse than no verification at all, so each check
    REFUSES (the caller exits non-zero, patching nothing) rather than degrade into a weaker claim.

    THERE IS NO SECOND, WEAKER VERIFICATION PATH. The returned callable does not adjudicate anything itself:
    it DELEGATES to the SAME rigorous machinery ``vigil remediate --prove`` drives — ``LiveHttpAdapter``
    (whose ``run_positive_control`` issues a LIVE benign, challenge-bearing probe through the SAME injectable
    param this run) + ``prove_remediation`` (the four-state protocol: authorization / proof-of-possession →
    identity policy match → a positive control that must be BOTH live (the target ANSWERED that probe this
    run) AND capable (the retained firing bytes still FIRE the same oracle here) → per-trial ``nonce_echoed``
    freshness at or above the ``F1_TARGET_ECHOES`` floor → the protocol-required silent trials → identity
    continuity → a SIGNED four-state certificate). Its verdict is then ADAPTED to the ``FixVerdict``
    ``verify_patch`` reads:

      * ``REMEDIATED``       → ``FixVerdict(fired=False, cert=<the signed prove-certificate ref>)`` — and only
                               after that certificate INDEPENDENTLY re-verifies (``verify_prove_certificate``);
      * ``STILL_VULNERABLE`` → ``FixVerdict(fired=True)``;
      * ``INCONCLUSIVE`` / ``REFUSED`` → RAISE, which ``verify_patch`` maps to ``unverified``.

    WHAT THE FRESHNESS FLOOR ACTUALLY BUYS — stated narrowly, because it is the single most over-claimable
    link on this path. ``F1_TARGET_ECHOES`` proves RESPONSIVENESS / FRESHNESS ONLY: SOME HTTP responder at
    ``--verify-base-url`` returned THIS run's nonce in the bytes the oracle judged. It does NOT prove the
    responder was the application, and it does NOT prove the request reached the vulnerable endpoint. It
    closes exactly ONE hole a locally-re-executed positive control leaves open — the NON-ECHOING answered
    response (a static 404, a WAF block page, a login redirect, the wrong path, an unrelated silent service):
    that yields INCONCLUSIVE/``freshness_echo_missing``, this oracle RAISES, and the run is ``unverified``,
    never a signed remediation. It does NOT close the ECHOING case. A responder that reflects the request URI
    or query — an echoing 404, a block page that prints what it blocked, a different service on that host —
    satisfies F1 while the exploit never reaches the app, and its silence IS minted as ``remediated``. That is
    a KNOWN RESIDUAL, not a closed case; the operator excludes it by pointing ``--verify-base-url`` at the
    REAL application. Accordingly the claim a certificate from this path earns is: "the ORIGINAL oracle did
    NOT fire over freshly captured bytes from the host the operator nominated" — NOT "the vulnerable endpoint
    was exercised and is fixed".

    WHICH GATES ARE LOAD-BEARING ON THIS PATH (and which only look like they are — do not lead with those).
    LOAD-BEARING here, in the order they can stop a wrong ``remediated``: (1) CLASS CERTIFIABILITY — a
    bug_class whose oracle family silence is not a SOUND negative never reaches REMEDIATED (``prove_driver``'s
    fail-closed ``certifiable_by_silence`` allowlist); (2) the request BUDGET / rate limit, which bounds the
    trials and turns an interrupted run INCONCLUSIVE; (3) the LIVE CONTROL — the host ANSWERED a benign,
    challenge-bearing probe through the same injectable param THIS run — together with its harness-capability
    twin (the retained firing bytes still fire the same oracle in this build); (4) the FRESHNESS ECHO floor
    (responsiveness only — see above); (5) the protocol-required count of SILENT trials; (6) the MINT plus the
    INDEPENDENT ``verify_prove_certificate`` re-check before this oracle reports a fix at all. NOT
    load-bearing here, despite being part of the protocol: the AUTHORIZATION / PROOF-OF-POSSESSION /
    IDENTITY-POLICY links. The owner key, the wielder keypair, the identity attestation and the capability are
    all MINTED INSIDE this same closure and then verified against themselves, so on this path they are
    checked against this run's own inputs and carry no independent assurance of anything HERE; their value is
    realised when SOMEONE ELSE verifies the emitted certificate against an independently pinned owner key.
    Identity CONTINUITY is real for an HTTPS target (the observed leaf-key SPKI must not change mid-run) and
    VACUOUS for a plain-HTTP one, whose identity sample is the configured host string — though each re-sample
    still issues a gated request, so a mid-run GATE refusal is surfaced either way.

    The pre-flight chain below runs BEFORE the ladder (so a diagnosis costs no model call, clone or apply):

      1. the finding must have an addressable ``ref`` — else its retained material cannot be matched by
         ``check_id`` and another finding's positive control could be substituted;
      2. ``--verify-base-url`` must be an http(s) URL with a host;
      3. the RETAINED re-verifiable entry for THIS finding — matched STRICTLY on the trusted finding's OWN
         ``ref`` (``_match_reverifiable_entry``; exact ``check_id``, never a sole-entry substitution, and
         never an operator-supplied ``--finding-ref`` override — the caller refuses a mismatch outright);
      4. CHANNEL GUARD — only ``error_signature`` is re-drivable today. Refusing is better than mis-driving a
         different oracle family over bytes that family never reads (a vacuous non-fire looks like silence);
      5. the retained firing ``oracle_context`` (the positive control) must be PRESENT and must still make the
         ORIGINAL oracle fire when re-executed HERE. This is an OFFLINE harness pre-check only: it proves the
         retained bytes still fire the oracle in this build, and it establishes NOTHING about the live target.
         The LIVE control + the freshness echo (both inside ``prove_remediation``) are what establish that the
         probe reached the deployment; this check just refuses an obviously-broken harness early;
      6. the exploit request is RECONSTRUCTED from the retained material (``_reconstruct_exploit_request``),
         never fabricated;
      6b. NONCE-PARAM COLLISION — the reconstructed injectable ``param`` must NOT be the param the re-drive
         carries the freshness challenge on (``_REDRIVE_NONCE_PARAM``). On a collision the challenge
         OVERWRITES the exploit payload in the re-drive URL: the exploit is never sent, so oracle silence
         would say nothing about a fix — and would be minted as a remediation over a still-vulnerable target.
         (``LiveHttpAdapter`` refuses the same collision at construction; this refuses it earlier and says
         why.);
      7. SCOPE — the verification target is validated by CRUCIBLE's own ``validate_action`` charter/scope gate
         (a pure pre-flight, no I/O) before any executor exists, and every re-drive request then goes through
         the gated ``HttpExecutor`` for ``slug`` (authority / kill-switch / scope / budget / rate-limit). No
         new ungated egress path is opened.

    TRUST NOTE (honest, mirroring ``_cmd_remediate``): the driving FINDING is provenance-grounded (signed
    spine / owner-delegated envelope), but the retained re-verifiable material read here
    (``<run_dir>/proofs/reverifiable.json`` — the original firing ``oracle_context`` used as the positive
    control, plus the channel / insertion point) is UNSIGNED LOCAL RUN OUTPUT, trusted AS SUCH. In the
    owner-operated model it is the operator's own run output; do not point ``--verify-run-dir`` at another
    engagement's ``proofs/``. It is matched to the finding by ``check_id`` (exact, fail-closed).

    SIDE EFFECT (disclosed, not silent): when the returned oracle is actually CONSULTED (only on a run that
    reaches the ladder's step (6)), it calls ``provision_authority`` for ``slug`` scoped to the verification
    host — persisting a freshly signed CRUCIBLE authority via ``save_signed_authority`` and thereby
    OVERWRITING any existing signed authority for that slug, exactly as ``vigil remediate --prove`` does.
    Building the oracle, and every refusal above, writes nothing.

    HONEST LIMITS (stated where they are created, not hidden). (a) The re-drive exercises the LIVE DEPLOYMENT
    the operator points ``--verify-base-url`` at. That the deployment actually carries the patch this run
    proposed is the OPERATOR's assertion — the sandbox ``patched_build`` ref is not cryptographically bound to
    the running service (the ladder's ``patched_build`` argument is deliberately unused here). (b) The
    silent-case residuals are exactly ``LiveHttpAdapter``'s, inherited unchanged and not re-argued here: an F1
    remediation does not distinguish a payload-discriminating WAF (one that blocks the exploit's
    metacharacters while still answering and echoing) or a param-stripping edge in front of an echoing
    gateway from a real fix; ruling those out needs a matched-decoy differential or the OOB Tier-2, both
    deferred. (c) The ECHOING-responder residual stated above: F1 does not attribute the echo to the
    application. The oracle proves only that the ORIGINAL oracle did not fire over fresh, challenge-echoing
    bytes captured from the nominated host, and nothing more.
    """
    from urllib.parse import urlsplit

    ref = str(getattr(finding, "ref", "") or "").strip()
    if not ref:
        return None, ("the trusted finding has no addressable ref — its retained re-verifiable proof material "
                      "cannot be matched by check_id (refusing rather than risk verifying against another "
                      "finding's positive control; fail-closed).")

    target = str(verify_base_url or "").strip()
    host = urlsplit(target).hostname or ""
    if not (target.startswith(("http://", "https://")) and host):
        return None, ("--verify-base-url must be an http(s) URL with a host, e.g. http://127.0.0.1:8080 — the "
                      "PATCHED, REDEPLOYED service to re-drive the original exploit against (and it MUST be "
                      "authorized in the engagement charter scope).")

    # (3) the RETAINED re-verifiable proof material for THIS finding. Matched on the TRUSTED finding's own ref
    #     ONLY — an operator-supplied --finding-ref can never redirect this lookup at another finding's entry.
    from .proof.run import read_reverifiable
    entries = read_reverifiable(run_dir).get("active_findings", [])
    entry = _match_reverifiable_entry(entries, ref, "")
    if entry is None:
        return None, (f"no retained re-verifiable proof material for finding {ref!r} under "
                      f"{run_dir}/proofs/reverifiable.json (found {len(entries)} entr(y/ies)). The engagement "
                      f"persists the original firing oracle_context there — run it first, or point "
                      f"--verify-run-dir at the run that produced this finding. That retained material is "
                      f"UNSIGNED local run output, trusted as such (see the TRUST NOTE).")

    # (4) CHANNEL GUARD — the live re-drive genuinely supports ONE oracle family. Never mis-drive another.
    channel = str(entry.get("channel") or "")
    if channel != _PATCH_VERIFY_CHANNEL:
        return None, (f"finding {ref!r} was confirmed on the {channel or '?'!r} channel; the live fix-"
                      f"verification re-drive currently supports ONLY the {_PATCH_VERIFY_CHANNEL} channel "
                      f"(error_based_sqli). Refusing rather than mis-driving a different oracle family "
                      f"(fail-closed).")
    bug_class = str(entry.get("bug_class") or "error_based_sqli")

    # (5) the POSITIVE CONTROL, offline harness pre-check: present, and it still fires the original oracle in
    #     THIS build. It says nothing about the live target — the LIVE control + the freshness echo inside
    #     `prove_remediation` do that. This only refuses an obviously broken harness before the ladder starts.
    original_firing_context = entry.get("oracle_context")
    if not (isinstance(original_firing_context, dict) and original_firing_context):
        return None, (f"finding {ref!r} has no retained firing oracle_context (the positive control) — the "
                      f"live prove-run could not confirm the harness re-fires it, so silence on the patched "
                      f"deployment could not be distinguished from a broken probe. Refusing.")
    from framework.v2.verify.reverify import reverify_context      # lazy — FATAL-2
    try:
        control = reverify_context(dict(original_firing_context), bug_class=bug_class, ref=ref)
    except Exception as exc:  # noqa: BLE001 — a control we cannot re-execute proves nothing (fail-closed)
        return None, (f"the retained positive control for {ref!r} could not be re-executed ({exc}) — a silent "
                      f"re-drive could not be distinguished from a broken probe. Refusing.")
    if not getattr(control, "reproduced", False):
        return None, (f"the retained positive control for {ref!r} does NOT re-fire the {bug_class} oracle, so a "
                      f"SILENT re-drive would prove nothing (a broken probe looks exactly the same). Refusing.")

    # (6) the ORIGINAL exploit request, reconstructed from retained data — never fabricated.
    spec, why = _reconstruct_exploit_request(finding, entry)
    if spec is None:
        return None, why

    # (6b) NONCE-PARAM COLLISION — refuse a finding whose injectable param IS the challenge param, BEFORE the
    #      ladder runs. A collision silently drops the exploit payload, so oracle silence would say nothing.
    collision = _nonce_param_collision_refusal(spec["param"])
    if collision:
        return None, collision

    # (7) SCOPE — CRUCIBLE's own charter/scope gate, pure pre-flight (no I/O), before an executor exists. The
    #     gated executor re-runs this same chain per request with its resolved posture; it stays the authority.
    from framework.v2.agents.scope_gate import validate_action     # lazy — FATAL-2
    decision = validate_action(slug=slug, method="GET", target_url=target)
    if not getattr(decision, "allowed", False):
        return None, (f"the verification target {target!r} is NOT authorized under the engagement charter for "
                      f"{slug!r} ({getattr(decision, 'refusal_kind', '?')}): {getattr(decision, 'reason', '')} "
                      f"— refusing (fail-closed; `vigil patch` opens no ungated egress path).")

    evidence_ref = str(getattr(finding, "evidence_ref", "") or "")

    def verify_oracle(_request: Any, _patched_build: Any) -> Any:
        """The ``Callable[[request, patched_build], FixVerdict]`` the ladder consults at step (6). It runs the
        FULL ``vigil remediate --prove`` protocol against ``--verify-base-url`` and ADAPTS the four-state
        verdict; it makes no independent judgement of its own. ``_request`` / ``_patched_build`` are
        deliberately unused: the exploit re-driven is the ORIGINAL one reconstructed from the retained,
        provenance-grounded material, and the sandbox build ref is not bound to the running deployment."""
        import hashlib
        import secrets
        import time as _time

        from vigil_core import (
            generate_keypair, identity_digest, prove_wielder, sign_capability, sign_identity_attestation)
        from vigil_core.vault import Vault
        from framework.v2.agents import HttpExecutor                 # lazy — FATAL-2

        from .live.wiring import provision_authority
        from .remediation.fix_oracle import FixVerdict
        from .remediation.live_adapter import LiveHttpAdapter
        from .remediation.prove_driver import ProvePolicy, State, prove_remediation, verify_prove_certificate

        # The STABLE governance key under --base-dir signs the prove-certificate (same composition as the
        # prove verb); provisioning the signed authority first means the executor's authority gate has it.
        # DISCLOSED SIDE EFFECT: this OVERWRITES the engagement's signed CRUCIBLE authority for `slug`.
        prov = provision_authority(slug=slug, scope=[host], base_dir=base_dir,
                                   vault=Vault(Path(base_dir) / "vault"))
        owner = prov.keypair
        wielder = generate_keypair()
        now = int(_time.time())
        not_after = now + 3600
        ident = sign_identity_attestation(owner, engagement=slug, policy={"host": [host]},
                                          not_after=not_after)
        cap = sign_capability(owner, engagement=slug, identity_digest=identity_digest(ident),
                              class_allowlist=[bug_class], not_before=0, not_after=not_after,
                              rate_limit=16, revocation_id=f"rev-{ref}", audience=wielder.public_key_b64)
        # FRESH per-run inputs (the signed math forbids a wallclock/rng read; these are INPUTS the caller
        # mints). Minted HERE, at verification time, not when the oracle was built.
        pop_challenge = secrets.token_hex(16)
        freshness_nonce = secrets.token_hex(16)
        run_id = "patch-verify-" + secrets.token_hex(8)
        wproof = prove_wielder(wielder, challenge=pop_challenge, capability=cap)

        executor = HttpExecutor(engagement_slug=slug, base_url=target, prompt_callback=lambda *_a: False)
        adapter = LiveHttpAdapter(
            executor=executor, base_url=target, endpoint_path=spec["endpoint_path"], param=spec["param"],
            payload=spec["payload"], nonce_param=_REDRIVE_NONCE_PARAM,
            original_firing_context=dict(original_firing_context), bug_class=bug_class)

        out = prove_remediation(
            adapter=adapter, identity=ident, capability=cap, wielder_proof=wproof,
            trusted_owner_pubkey=owner.public_key_b64, engagement=slug, finding_id=ref,
            original_certificate_digest=evidence_ref, signers=prov.signers, now=now, run_id=run_id,
            pop_challenge=pop_challenge, freshness_nonce=freshness_nonce, policy=ProvePolicy())

        # Persist the SIGNED certificate for EVERY state (an INCONCLUSIVE/REFUSED reason cannot be stripped
        # and re-read as success), then report the four-state verdict honestly on stdout.
        proofs_dir = Path(base_dir) / "proofs"
        proofs_dir.mkdir(parents=True, exist_ok=True)
        cert_path = proofs_dir / f"patch-verify-prove-{_remediate_safe_ref(ref)}.json"
        cert_body = json.dumps(out.certificate, indent=2, sort_keys=True)
        cert_path.write_text(cert_body, encoding="utf-8")
        print(f"verify_state   : {out.state}   reason={out.reason_code}  "
              f"trials(attempted={out.trials_attempted} valid={out.trials_valid}) F{out.achieved_freshness}")
        print(f"verify_cert    : {cert_path}")
        print(f"verify_detail  : {out.detail}")

        if out.state == State.STILL_VULNERABLE:
            return FixVerdict(fired=True,
                              reason=f"the ORIGINAL exploit oracle FIRED over fresh evidence: {out.detail}")
        if out.state != State.REMEDIATED:
            # INCONCLUSIVE (testing occurred, the negative claim was NOT earned — e.g. the target answered but
            # never echoed this run's freshness challenge, so reachability of the vulnerable endpoint was
            # never established) or REFUSED (testing must not begin). `verify_patch` maps a raise to
            # 'unverified'. Never a fix (fail-closed).
            raise ValueError(f"live fix-verification did not earn a remediation: {out.state}/"
                             f"{out.reason_code} — {out.detail} (certificate: {cert_path})")
        ok, vwhy = verify_prove_certificate(
            out.certificate, signer_pubkeys={prov.signers[0][0]: owner.public_key_b64})
        if not ok:
            raise ValueError(f"the REMEDIATED prove-certificate did NOT independently re-verify ({vwhy}) — "
                             f"refusing to report a fix (fail-closed; certificate: {cert_path})")
        digest = "sha256:" + hashlib.sha256(cert_body.encode("utf-8")).hexdigest()
        return FixVerdict(
            fired=False, cert=f"prove-cert:{digest[7:31]}:{cert_path}", context_digest=digest,
            reason=("the ORIGINAL exploit oracle went SILENT across the protocol-required fresh trials; the "
                    "signed four-state prove-certificate independently re-verifies"))

    return verify_oracle, ""


def _cmd_remediate(args: argparse.Namespace) -> int:
    """VF-1a — ``vigil remediate --prove``: run the FOUR-STATE live remediation proof over a PROVENANCE-
    GROUNDED confirmed finding and emit a signed prove-certificate.

    The driving finding is NEVER built from raw JSON (mirrors ``vigil patch``): it comes from the engagement's
    OWN signed spine (``--from-spine <slug>`` [+ ``--finding-ref``]) or a signed inert envelope
    (``--finding-envelope`` — owner-delegated m-of-n governance). The retained ORIGINAL firing
    ``oracle_context`` (the positive control) and the exploit's channel / insertion point come from the run's
    re-verifiable proof material (``proofs/reverifiable.json``); the exploit request is RECONSTRUCTED from
    that retained data, never fabricated.

    The re-drive runs the ORIGINAL exploit against the LIVE ``--target-base-url`` (which MUST be authorized in
    the engagement charter scope) through CRUCIBLE's gated ``HttpExecutor`` and classifies the FRESH result:

        REMEDIATED · STILL_VULNERABLE · INCONCLUSIVE · REFUSED

    Only ``--prove`` mode exists (downgrade resistance — no weaker/unsigned mode). Identity + capability +
    proof-of-possession are composed from a provisioned governance authority exactly as the merged live
    adapter does; the caller mints FRESH run_id / pop_challenge / freshness_nonce (inputs, not signed math).
    Exit: 0 REMEDIATED · 1 STILL_VULNERABLE · 2 INCONCLUSIVE · 3 REFUSED · 2 for a pre-flight refusal. Never
    prints "fixed" for anything but a REMEDIATED that ALSO independently re-verifies. FATAL-2: every
    framework-touching import is function-local.

    TRUST NOTE (honest): the driving FINDING is provenance-grounded (signed spine / owner-delegated envelope),
    but the retained re-verifiable material (``proofs/reverifiable.json`` — the original firing oracle_context
    that serves as the positive control, plus the channel / insertion point) is trusted AS LOCAL, unsigned
    material. In the owner-operated model that is the operator's own run output; do not point ``--run-dir`` at
    another engagement's ``proofs/``. The entry is matched to the finding by ``check_id`` (exact, fail-closed —
    a mismatch refuses; the positive control of a DIFFERENT finding is never substituted).
    """
    import secrets
    import time as _time
    from urllib.parse import urlsplit

    # (0) DOWNGRADE RESISTANCE — only the signed, four-state prove mode exists. No silent weaker mode.
    if not getattr(args, "prove", False):
        print("vigil remediate: only --prove mode is supported (a signed, four-state LIVE remediation proof). "
              "Re-run with --prove. There is deliberately no weaker/unsigned mode (downgrade resistance).",
              file=sys.stderr)
        return 2

    # (1) EXACTLY ONE trusted finding source (mirrors `vigil patch`). A raw-JSON finding is never accepted.
    from .live.trusted_finding import TrustedFindingError, finding_from_envelope, finding_from_spine
    if bool(args.finding_envelope) == bool(args.from_spine):
        print("vigil remediate: choose EXACTLY ONE trusted finding source — --finding-envelope <signed.json> "
              "(owner-delegated m-of-n governance) OR --from-spine <slug> (the engagement's signed spine). "
              "A raw-JSON finding is never accepted.", file=sys.stderr)
        return 2
    # The engagement slug is the charter the HttpExecutor scope gate keys off: --scope for the envelope path,
    # the spine slug for the spine path (mirrors _cmd_patch).
    slug = str((args.scope if args.finding_envelope else args.from_spine) or "").strip()
    if not slug:
        print("vigil remediate: an engagement slug is required — --scope <slug> (with --finding-envelope) or "
              "--from-spine <slug>. It is the charter the live target must be authorized under.", file=sys.stderr)
        return 2
    try:
        if args.finding_envelope:
            finding = finding_from_envelope(
                envelope_path=args.finding_envelope, owner_pubkey=args.owner_pubkey,
                delegation_path=args.delegation, scope=args.scope, target_repo="")
        else:
            finding = finding_from_spine(
                base_dir=args.base_dir, slug=args.from_spine, target_repo="", finding_ref=args.finding_ref)
    except TrustedFindingError as exc:
        print(f"vigil remediate: REFUSED (fail-closed): {exc}", file=sys.stderr)
        return 2

    # A confirmed fact MUST be addressable by a non-empty ref — else the reverifiable entry cannot be matched
    # by check_id and the sole-entry fallback could substitute ANOTHER finding's positive control. Enforce it
    # here so `_match_reverifiable_entry`'s known-ref path always applies (making its docstring invariant true).
    if not str(getattr(finding, "ref", "") or "").strip():
        print("vigil remediate: the trusted finding has no addressable ref — cannot match its retained "
              "re-verifiable proof material by check_id (refusing rather than risk substituting another "
              "finding's positive control; fail-closed).", file=sys.stderr)
        return 2
    # ...and a --finding-ref that DISAGREES with that ref is refused, never honoured: on the envelope path the
    # trusted ref comes from the SIGNED certificate and the flag is not consulted, so letting it choose the
    # retained entry would drive finding B's positive control + exploit under finding A's name.
    ref_why = _finding_ref_override_refusal(finding, getattr(args, "finding_ref", ""))
    if ref_why:
        print(f"vigil remediate: REFUSED (fail-closed): {ref_why}", file=sys.stderr)
        return 2

    # (2) The RETAINED re-verifiable proof material for THIS finding: the positive control (original firing
    #     oracle_context) + the confirmed channel + the insertion point the exploit rode.
    from .proof.run import read_reverifiable
    run_dir = str(getattr(args, "run_dir", "") or "") or args.base_dir
    entries = read_reverifiable(run_dir).get("active_findings", [])
    entry = _match_reverifiable_entry(entries, finding.ref, "")
    if entry is None:
        print(f"vigil remediate: no retained re-verifiable proof material for finding {finding.ref!r} under "
              f"{run_dir}/proofs/reverifiable.json (found {len(entries)} entr(y/ies)). The engagement persists "
              f"the original firing oracle_context there — run it first, or point --run-dir at the run that "
              f"produced this finding. That retained material is UNSIGNED local run output, trusted as such "
              f"(see the TRUST NOTE). --finding-ref only picks WHICH FACT to load from the spine; it can "
              f"never redirect this lookup.", file=sys.stderr)
        return 2

    channel = str(entry.get("channel") or "")
    if channel != "error_signature":
        print(f"vigil remediate: finding {finding.ref!r} was confirmed on the {channel or '?'!r} channel; this "
              f"prove-mode live re-drive currently supports ONLY the error_signature channel (error_based_sqli). "
              f"Refusing rather than mis-driving a different oracle family (fail-closed).", file=sys.stderr)
        return 2
    bug_class = str(entry.get("bug_class") or "error_based_sqli")
    original_firing_context = entry.get("oracle_context")
    if not (isinstance(original_firing_context, dict) and original_firing_context):
        print(f"vigil remediate: finding {finding.ref!r} has no retained firing oracle_context (the positive "
              f"control) — silence on the patched build could not be distinguished from a broken probe. Refusing.",
              file=sys.stderr)
        return 2

    # (3) Reconstruct the ORIGINAL exploit request from the retained finding + insertion point (never faked).
    spec, why = _reconstruct_exploit_request(finding, entry)
    if spec is None:
        print(f"vigil remediate: {why}", file=sys.stderr)
        return 2
    collision = _nonce_param_collision_refusal(spec["param"])
    if collision:
        print(f"vigil remediate: REFUSED (fail-closed): {collision}", file=sys.stderr)
        return 2

    target_base_url = str(args.target_base_url or "").strip()
    host = urlsplit(target_base_url).hostname or ""
    if not (target_base_url.startswith(("http://", "https://")) and host):
        print("vigil remediate: --target-base-url must be an http(s) URL with a host, e.g. "
              "http://127.0.0.1:8080 (and it MUST be authorized in the engagement charter scope).",
              file=sys.stderr)
        return 2

    # (4) Build the gated executor + the live adapter (framework import is function-local — FATAL-2).
    from vigil_core import (
        generate_keypair, identity_digest, prove_wielder, sign_capability, sign_identity_attestation)
    from vigil_core.vault import Vault
    from framework.v2.agents import HttpExecutor

    from .live.wiring import provision_authority
    from .remediation.live_adapter import LiveHttpAdapter
    from .remediation.prove_driver import ProvePolicy, State, prove_remediation, verify_prove_certificate

    executor = HttpExecutor(engagement_slug=slug, base_url=target_base_url,
                            prompt_callback=lambda *_a: False)
    adapter = LiveHttpAdapter(
        executor=executor, base_url=target_base_url, endpoint_path=spec["endpoint_path"],
        param=spec["param"], payload=spec["payload"], nonce_param=_REDRIVE_NONCE_PARAM,
        original_firing_context=dict(original_firing_context), bug_class=bug_class)

    # (5) Provision identity + capability + wielder proof — the SAME composition the merged live adapter uses.
    #     The governance key is loaded-or-provisioned STABLE under --base-dir (sealed under its vault), so the
    #     prove-certificate is signed by a reproducible key an external verifier can pin.
    prov = provision_authority(slug=slug, scope=[host], base_dir=args.base_dir,
                               vault=Vault(Path(args.base_dir) / "vault"))
    owner = prov.keypair
    wielder = generate_keypair()
    now = int(_time.time())
    not_after = now + 3600
    ident = sign_identity_attestation(owner, engagement=slug, policy={"host": [host]}, not_after=not_after)
    cap = sign_capability(owner, engagement=slug, identity_digest=identity_digest(ident),
                          class_allowlist=[bug_class], not_before=0, not_after=not_after,
                          rate_limit=16, revocation_id=f"rev-{finding.ref}",
                          audience=wielder.public_key_b64)
    # FRESH per-run values — the CALLER's responsibility. The signed math forbids Date.now()/rng, but MINTING
    # these inputs with secrets/uuid is correct and expected (they are inputs, not the signed computation).
    pop_challenge = secrets.token_hex(16)
    freshness_nonce = secrets.token_hex(16)
    run_id = "remediate-" + secrets.token_hex(8)
    wproof = prove_wielder(wielder, challenge=pop_challenge, capability=cap)

    out = prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wproof,
        trusted_owner_pubkey=owner.public_key_b64, engagement=slug, finding_id=finding.ref,
        original_certificate_digest=str(finding.evidence_ref or ""), signers=prov.signers,
        now=now, run_id=run_id, pop_challenge=pop_challenge, freshness_nonce=freshness_nonce,
        policy=ProvePolicy())

    # (6) Honest four-state summary — never "fixed" for anything but a re-verifying REMEDIATED.
    provenance = ("signed envelope (m-of-n governance, owner-delegated)" if args.finding_envelope
                  else "signed offense spine (verified + rebuilt)")
    print(f"=== vigil remediate --prove — finding {finding.ref!r} [{bug_class}] ===")
    print(f"provenance        : {provenance}")
    print(f"target            : {target_base_url}   (endpoint={spec['endpoint_path']} param={spec['param']})")
    print(f"STATE             : {out.state}")
    print(f"reason_code       : {out.reason_code}")
    print(f"trials            : attempted={out.trials_attempted} valid={out.trials_valid}")
    print(f"achieved_freshness: F{out.achieved_freshness}")
    print(f"detail            : {out.detail}")

    # (7) Persist the signed prove-certificate + re-verify it INLINE (offline, fail-closed).
    proofs_dir = Path(args.base_dir) / "proofs"
    proofs_dir.mkdir(parents=True, exist_ok=True)
    cert_path = proofs_dir / f"remediation-prove-{_remediate_safe_ref(finding.ref)}.json"
    cert_path.write_text(json.dumps(out.certificate, indent=2, sort_keys=True), encoding="utf-8")
    print(f"certificate       : {cert_path}")
    pubkeys = {prov.signers[0][0]: owner.public_key_b64}
    ok, verify_why = verify_prove_certificate(out.certificate, signer_pubkeys=pubkeys)
    print(f"re-verify         : {'OK' if ok else 'FAILED'} — {verify_why}")

    if out.state == State.REMEDIATED and not ok:
        # A REMEDIATED cert that does not independently re-verify is not honestly a fix (fail-closed).
        print("vigil remediate: a REMEDIATED certificate did NOT independently re-verify — refusing to report "
              "success (fail-closed).", file=sys.stderr)
        return 3
    return {State.REMEDIATED: 0, State.STILL_VULNERABLE: 1,
            State.INCONCLUSIVE: 2, State.REFUSED: 3}.get(out.state, 4)


def _cmd_reprove(args: argparse.Namespace) -> int:
    """TRUTHENOVATION A2 — ``vigil reprove``: the CONTINUOUS RE-PROOF SERVICE.

    Makes "continuously re-proven" an operating property *once its systemd timer is enabled on a host* —
    until then this is the deployable re-proof loop (a capability), not a running deployment. It builds the SAME
    provenance-grounded re-proof target ``vigil remediate --prove`` builds (a signed spine / owner-delegated
    envelope finding, its retained firing ``oracle_context`` as the positive control, the original exploit
    reconstructed from the retained material), then LOOPS it on a cadence: each cycle re-fires the exploit
    against the live ``--target-base-url`` through the gated CRUCIBLE executor, APPENDS a signed four-state
    tick to the continuous attestation log, and has a witness time-co-sign the new head.

      * ``--once``          — run ONE cycle and exit (the systemd oneshot the timer fires).
      * ``--cycles N``      — run N cycles then exit.
      * ``--interval SECS`` — the cadence between cycles for a long-running ``--cycles``/forever daemon.
      * neither ``--once`` nor ``--cycles`` ⇒ run FOREVER on ``--interval`` (the ``--interval`` daemon).

    Reuses the ONE provisioned governance authority for signing (no new key). Witnessing defaults to a
    STABLE self-witness persisted under ``--base-dir`` (threshold==1) — an HONEST time-stamp, NOT an
    independence proof (VF-1c: at threshold==1 equivocation is detectable, not prevented; deploy independent
    witnesses for the stronger guarantee). Exit 0 iff every scheduled cycle appended a tick and the whole
    series re-verifies. FATAL-2: every framework-touching import is function-local.

    HONEST RESIDUAL (printed, never overclaimed): freshness is only as current as the last cadence fire; the
    loop re-fires the RETAINED corpus (soundness bounded to what was retained); the target must be reachable.
    """
    import time as _time
    from urllib.parse import urlsplit

    # (1) EXACTLY ONE trusted finding source (mirrors `vigil remediate` / `vigil patch`).
    from .live.trusted_finding import TrustedFindingError, finding_from_envelope, finding_from_spine
    if bool(args.finding_envelope) == bool(args.from_spine):
        print("vigil reprove: choose EXACTLY ONE trusted finding source — --finding-envelope <signed.json> "
              "OR --from-spine <slug>. A raw-JSON finding is never accepted.", file=sys.stderr)
        return 2
    slug = str((args.scope if args.finding_envelope else args.from_spine) or "").strip()
    if not slug:
        print("vigil reprove: an engagement slug is required — --scope <slug> (with --finding-envelope) or "
              "--from-spine <slug>. It is the charter the live target must be authorized under.", file=sys.stderr)
        return 2
    try:
        if args.finding_envelope:
            finding = finding_from_envelope(
                envelope_path=args.finding_envelope, owner_pubkey=args.owner_pubkey,
                delegation_path=args.delegation, scope=args.scope, target_repo="")
        else:
            finding = finding_from_spine(
                base_dir=args.base_dir, slug=args.from_spine, target_repo="", finding_ref=args.finding_ref)
    except TrustedFindingError as exc:
        print(f"vigil reprove: REFUSED (fail-closed): {exc}", file=sys.stderr)
        return 2
    if not str(getattr(finding, "ref", "") or "").strip():
        print("vigil reprove: the trusted finding has no addressable ref — cannot match its retained "
              "re-verifiable proof material by check_id (fail-closed).", file=sys.stderr)
        return 2
    ref_why = _finding_ref_override_refusal(finding, getattr(args, "finding_ref", ""))
    if ref_why:
        print(f"vigil reprove: REFUSED (fail-closed): {ref_why}", file=sys.stderr)
        return 2

    # (2) The RETAINED re-verifiable proof material (positive control + channel + insertion point).
    from .proof.run import read_reverifiable
    run_dir = str(getattr(args, "run_dir", "") or "") or args.base_dir
    entries = read_reverifiable(run_dir).get("active_findings", [])
    entry = _match_reverifiable_entry(entries, finding.ref, "")
    if entry is None:
        print(f"vigil reprove: no retained re-verifiable proof material for finding {finding.ref!r} under "
              f"{run_dir}/proofs/reverifiable.json — run the engagement first, or point --run-dir at the run "
              f"that produced this finding. That retained material is UNSIGNED local run output, trusted as "
              f"such (see the TRUST NOTE). --finding-ref only picks WHICH FACT to load from the spine; it "
              f"can never redirect this lookup.", file=sys.stderr)
        return 2
    channel = str(entry.get("channel") or "")
    if channel != "error_signature":
        print(f"vigil reprove: finding {finding.ref!r} was confirmed on the {channel or '?'!r} channel; this "
              f"re-proof loop currently supports ONLY the error_signature channel (error_based_sqli). "
              f"Refusing (fail-closed).", file=sys.stderr)
        return 2
    bug_class = str(entry.get("bug_class") or "error_based_sqli")
    original_firing_context = entry.get("oracle_context")
    if not (isinstance(original_firing_context, dict) and original_firing_context):
        print(f"vigil reprove: finding {finding.ref!r} has no retained firing oracle_context (the positive "
              f"control). Refusing (fail-closed).", file=sys.stderr)
        return 2

    # (3) Reconstruct the ORIGINAL exploit request from the retained finding + insertion point (never faked).
    spec, why = _reconstruct_exploit_request(finding, entry)
    if spec is None:
        print(f"vigil reprove: {why}", file=sys.stderr)
        return 2
    collision = _nonce_param_collision_refusal(spec["param"])
    if collision:
        print(f"vigil reprove: REFUSED (fail-closed): {collision}", file=sys.stderr)
        return 2
    target_base_url = str(args.target_base_url or "").strip()
    host = urlsplit(target_base_url).hostname or ""
    if not (target_base_url.startswith(("http://", "https://")) and host):
        print("vigil reprove: --target-base-url must be an http(s) URL with a host authorized in the "
              "engagement charter scope.", file=sys.stderr)
        return 2

    # (4) Cadence: --once ⇒ 1; --cycles N ⇒ N; else forever. --interval bounds the between-cycle sleep.
    cycles: Optional[int]
    if args.once:
        cycles = 1
    elif args.cycles is not None:
        cycles = int(args.cycles)
        if cycles < 1:
            print("vigil reprove: --cycles must be >= 1.", file=sys.stderr)
            return 2
    else:
        cycles = None                       # the --interval daemon (runs forever)
    interval = float(args.interval)

    # (5) Provision the ONE governance authority (stable, sealed under --base-dir; NO new signing key) + a
    #     stable self-witness key. FATAL-2: framework imports are function-local here.
    from vigil_core import AuthorizerKey, TrustRoot
    from vigil_core.keystore import load_or_create_sealed_keypair
    from vigil_core.vault import Vault
    from framework.v2.agents import HttpExecutor

    from .live.wiring import provision_authority
    from .remediation.attestation_log import verify_log
    from .remediation.attestation_witness import verify_timed_witnessed_checkpoint
    from .remediation.live_adapter import LiveHttpAdapter
    from .remediation.reprove import (
        ReproveConfig, ReproveTick, build_live_prove_target, load_witnessed, run_reprove,
    )

    vault = Vault(Path(args.base_dir) / "vault")
    prov = provision_authority(slug=slug, scope=[host], base_dir=args.base_dir, vault=vault)
    signer_pubkeys = {prov.signers[0][0]: prov.keypair.public_key_b64}
    witness_kp = load_or_create_sealed_keypair(
        path=str(Path(args.base_dir) / "reprove-witness.key"),
        context=b"vigil-reprove-self-witness-v1\x00", vault=vault)
    witness_key_id = "reprove-self"
    witness_trust_root = TrustRoot(
        threshold=1, authorizers=[AuthorizerKey(
            key_id=witness_key_id, name="reprove self-witness", public_key_b64=witness_kp.public_key_b64)])

    log_dir = str(args.log_dir or (Path(args.base_dir) / "attestation-log"))

    def _adapter_factory():
        # A FRESH gated adapter each cycle so each re-proof captures fresh wire bytes. The HttpExecutor's own
        # charter/scope/kill-switch chain admits ONLY the chartered host — this opens no new egress path.
        executor = HttpExecutor(engagement_slug=slug, base_url=target_base_url,
                                prompt_callback=lambda *_a: False)
        return LiveHttpAdapter(
            executor=executor, base_url=target_base_url, endpoint_path=spec["endpoint_path"],
            param=spec["param"], payload=spec["payload"], nonce_param=_REDRIVE_NONCE_PARAM,
            original_firing_context=dict(original_firing_context), bug_class=bug_class)

    target = build_live_prove_target(
        finding_id=finding.ref, engagement=slug, prov=prov, scope_host=host,
        adapter_factory=_adapter_factory, bug_class=bug_class,
        original_certificate_digest=str(finding.evidence_ref or ""))
    cfg = ReproveConfig(
        log_dir=log_dir, engagement_slug=slug, signers=prov.signers, trust_root=prov.trust_root,
        signer_pubkeys=signer_pubkeys, corpus=[target], witnesses=[(witness_kp, witness_key_id)],
        gov_signer=prov.keypair)   # C-S5: sign the durable attestation-log floor with the governance key

    print(f"=== vigil reprove — continuous re-proof of finding {finding.ref!r} [{bug_class}] ===")
    print(f"target            : {target_base_url}   (endpoint={spec['endpoint_path']} param={spec['param']})")
    print(f"attestation log   : {log_dir}")
    print(f"cadence           : " + ("--once (1 cycle)" if args.once else
                                     f"{cycles} cycles" if cycles is not None else "forever")
          + f" (interval={interval}s)")
    print("witness           : STABLE self-witness (threshold==1) — an honest time-stamp, NOT independence")
    print("HONEST RESIDUAL   : freshness = last cadence fire; re-fires the RETAINED corpus; target must be "
          "reachable")

    def _on_cycle(i: int, cticks: "list[ReproveTick]") -> None:
        for t in cticks:
            twhen = "witnessed" if t.witnessed is not None else "UN-witnessed"
            print(f"  cycle {i}: tick seq={t.append.seq} state={t.append.state} "
                  f"label={t.append.series[-1].label if t.append.series else '?'} ({twhen})", flush=True)

    # (6) Run the loop. real clock + real sleep + UNPREDICTABLE (default secrets) freshness nonces.
    try:
        res = run_reprove(cfg, cycles=cycles, interval=interval, sleep=_time.sleep,
                          clock=lambda: int(_time.time()), on_cycle=_on_cycle)
    except KeyboardInterrupt:                # the daemon was asked to stop — a clean exit, not a failure
        print("vigil reprove: interrupted — stopping the re-proof loop.", file=sys.stderr)
        return 0
    except Exception as exc:                 # noqa: BLE001 — a cycle could not honestly re-prove (unreachable/…)
        print(f"vigil reprove: a re-proof cycle failed (fail-closed, nothing faked): {exc}", file=sys.stderr)
        return 1

    # (7) Bounded runs re-verify the whole series + every witnessed checkpoint before reporting success.
    if cycles is not None:
        ok, reason, series = verify_log(log_dir, trust_root=prov.trust_root, signer_pubkeys=signer_pubkeys)
        print(f"verify_log        : {'OK' if ok else 'FAILED'} — {reason}")
        if not ok:
            return 1
        persisted = load_witnessed(log_dir)
        wall_ok = True
        for twc in persisted:
            wok, _T, _wr = verify_timed_witnessed_checkpoint(twc, witness_trust_root=witness_trust_root)
            wall_ok = wall_ok and wok
        print(f"witnessed heads   : {len(persisted)} persisted, "
              f"{'all verify' if wall_ok else 'A CHECKPOINT FAILED'}")
        print(f"appended this run : {len(res.ticks)} tick(s); series length now {len(series)}")
        if not wall_ok:
            return 1
    return 0


def _cmd_witness(args: argparse.Namespace) -> int:
    """TRUTHENOVATION A3 — the DEPLOYABLE witness co-sign service. `serve` runs ONE witness process on
    loopback (its own persistent key + tracked tip) that co-signs an append-only checkpoint series or
    REFUSES a fork (ConsistencyError → 409); `submit` fans a checkpoint out to N witness endpoints, gathers
    the timed co-signatures, and surfaces every refusal (the anti-equivocation signal, never swallowed). This
    lands the co-sign TRANSPORT that was deferred (apps/sigil/spine/witness.py:37-39): N independently-keyed
    witness PROCESSES co-sign a real series and a third party can run one. Sovereign-safe (vigil_core +
    stdlib only — never co-loads the offense engine). HONEST: a CAPABILITY (built + shippable + local-deploy-
    proven), NOT witnessed-by-independent-parties-in-production; genuine independence needs third-party
    operators (distinct keys != distinct operators)."""
    from .witness_service import build_parser as _witness_parser
    # Delegate to the standalone witness parser so `vigil witness …` and `python -m
    # vigil_integration.witness_service …` are the SAME surface (one arg contract, no drift).
    sub_argv = list(getattr(args, "witness_argv", []) or [])
    parsed = _witness_parser().parse_args(sub_argv)
    return int(parsed.func(parsed))


def _cmd_floor_witness(args: argparse.Namespace) -> int:
    """C-S4 offense parity — anchor the offense anti-rollback HIGH-WATER floor to a RETAINED, off-box
    witnessed checkpoint. `witness` emits + persists it off-box; `verify-witnessed` REQUIRES the local
    head+floor to be consistent with the HIGHEST retained one (catches a same-host head+floor co-rewrite /
    a floor stripped below a witnessed height — the residual the LOCAL floor cannot catch).

    FATAL-2: signs with the offense GOVERNANCE key (never an owner key); imports NO framework/sigil."""
    from pathlib import Path

    from vigil_core import SignedChainHead
    from vigil_core.highwater import HighWaterError, load_highwater
    from vigil_core.vault import Vault

    from . import floor_witness as FW
    from . import witnessed_anchor as WA
    from .live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, load_or_create_governance_keypair)

    log_dir = Path(args.log_dir)
    head_p = log_dir / "head.json"
    hw_p = log_dir / "highwater.json"
    if not head_p.exists():
        print(f"vigil floor: no offense head at {head_p} (nothing to anchor)", file=sys.stderr)
        return 2
    try:
        head = SignedChainHead.model_validate_json(head_p.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — a corrupt head is surfaced, never treated as clean
        print(f"vigil floor: offense head unreadable (possible tamper): {e}", file=sys.stderr)
        return 2
    try:
        hw = load_highwater(hw_p)                      # normalised {entry_count,last_seq} or None
    except HighWaterError as e:
        print(f"vigil floor: high-water floor unreadable (possible tamper): {e}", file=sys.stderr)
        return 2

    base = Path(args.base_dir)
    vault = Vault(base / "vault")
    gov = load_or_create_governance_keypair(path=str(base / DEFAULT_GOVERNANCE_KEY_FILE), vault=vault)
    trust_root = FW.offense_witness_trust_root(gov.public_key_b64)

    if args.action == "witness":
        if not args.retain:
            print("!! `vigil floor witness` needs --retain <path> (the OFF-BOX path a verifier keeps)",
                  file=sys.stderr)
            return 2
        import time as _time
        retain_path = Path(args.retain)

        def _emit(now):
            # W7-5: RE-READ head + high-water each cycle (the spine advances between emits), so a scheduled
            # emitter always witnesses the CURRENT head and pushes a FRESH off-box anchor.
            h = SignedChainHead.model_validate_json(head_p.read_text(encoding="utf-8"))
            w = load_highwater(hw_p)
            return FW.emit_highwater_witness(h, w, [FW.offense_governance_witness(gov)],
                                             retain_path=retain_path, scope=args.scope, now=now)

        if getattr(args, "watch", False):
            hb = Path(args.heartbeat) if args.heartbeat else None
            summary = WA.run_checkpoint_monitor(_emit, retain_path=retain_path, cycles=args.cycles,
                                                interval=args.interval, heartbeat_path=hb)
            print(f"offense witnessed-checkpoint scheduler: {summary['emits']} emit(s), "
                  f"{summary['errors']} error(s) over {summary['cycles_run']} cycle(s) -> {retain_path}")
            print(f"guarantee: {FW.offense_guarantee_label(trust_root)}")
            return 0 if summary["errors"] == 0 else 1
        try:
            wc = _emit(int(_time.time()))
        except (FW.OffenseFloorWitnessError, WA.AnchorError) as e:
            print(f"!! offense floor witness failed: {e}", file=sys.stderr)
            return 1
        print(f"offense high-water witnessed + retained: {args.retain} (count {wc.checkpoint.entry_count}, "
              f"last_seq {wc.checkpoint.last_seq}, {len(wc.witness_signatures)} governance sig(s))")
        print("RETAIN THIS OFF-BOX — a copy kept only under --base-dir is rolled back WITH the spine.")
        print(f"guarantee: {FW.offense_guarantee_label(trust_root)}")
        return 0
    # verify-witnessed
    if not args.external:
        print("!! `vigil floor verify-witnessed` needs --external <path> (repeatable) — the OFF-BOX "
              "retained witnessed checkpoint(s)", file=sys.stderr)
        return 2
    import time as _time
    sources = [sys.stdin.read() if x == "-" else Path(x).read_text() for x in args.external]
    ok, msg, _label = FW.verify_highwater_against_witnessed(head, hw, sources, scope=args.scope,
                                                            trust_root=trust_root, now=_time.time())
    print(("offense floor anti-rollback OK: " if ok else "offense floor anti-rollback FAIL: ") + msg)
    if ok:
        # HONEST NUDGE: this is the LIGHT height/fork-at-height anchor. It proves no rollback below the
        # witnessed height and no fork AT it, but NOT that the pruned PREFIX is byte-identical — a history
        # forked below the witnessed height and then RE-GROWN above it passes here. Full pruned-prefix
        # byte-identity needs the retained checkpoint's entries compared out-of-band (ADR 0007 §Non-goals).
        print("   note: LIGHT anchor (height + fork-AT-height only) — does NOT prove pruned-PREFIX "
              "byte-identity; a fork-then-extend above this height is not caught here (see ADR 0007).")
    return 0 if ok else 2


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

    from .live.destruction_provision import (
        AuthorizationExistsError,
        default_paths,
        fresh_nonce,
        load_worker_key_file,
        sign_action,
        write_single_use_authorization,
    )
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
    try:
        # O_EXCL, not O_TRUNC: a SECOND authorize-destruction to the same path must FAIL rather than silently
        # clobber a still-unspent single-use token (a TOCTOU/reuse hole — same class as the LAP nonce ledger).
        write_single_use_authorization(out, doc)
    except AuthorizationExistsError as exc:
        print(f"vigil authorize-destruction: {exc}", file=sys.stderr)
        return 2
    print(f"=== vigil authorize-destruction — action {args.action_id!r} ===")
    print(f"signed by : {', '.join(kid for kid, _ in signers)}")
    print(f"window    : {int(args.window_s)}s  (single-use; within the 900s dead-man's-switch)")
    print(f"written   : {out}")
    print(f"Then: vigil patch … --base-dir {args.base_dir} --target-repo {args.target} --open-pr")
    return 0


def _cmd_enroll_cosigner(args: argparse.Namespace) -> int:
    """W9-5 PHASE 1 — run on the CO-SIGNER's (or owner's) OWN host. Generate this signer's destruction key
    LOCALLY and emit a PUBLIC enrolment request (public key + proof-of-possession). The PRIVATE key is
    written 0600 on THIS host and never leaves it; only the enrolment request travels to the minting box."""
    from pathlib import Path

    from .live.destruction_provision import build_enrollment, write_cosigner_private_key

    kid = str(args.key_id or "").strip()
    if not kid:
        print("vigil enroll-cosigner: --key-id is required", file=sys.stderr)
        return 2
    try:
        priv, doc = build_enrollment(key_id=kid, name=args.name)
    except ValueError as exc:
        print(f"vigil enroll-cosigner: {exc}", file=sys.stderr)
        return 2
    key_out = args.key_out or f"{kid}.destruction.key"
    enroll_out = args.out or f"{kid}.enrollment.json"
    try:
        write_cosigner_private_key(key_out, priv)
    except ValueError as exc:
        print(f"vigil enroll-cosigner: {exc}", file=sys.stderr)
        return 2
    Path(enroll_out).parent.mkdir(parents=True, exist_ok=True)
    Path(enroll_out).write_text(doc, encoding="utf-8")
    print("=== vigil enroll-cosigner — per-host destruction key generation (W9-5) ===")
    print(f"key_id            : {kid}")
    print(f"PRIVATE key (0600): {key_out}   <- KEEP ON THIS HOST; NEVER send it to the minting box")
    print(f"enrolment request : {enroll_out}   <- PUBLIC (pubkey + proof-of-possession); send THIS to the minting box")
    print()
    if kid == str(args.owner_id or "owner").strip():
        print("This is the OWNER key. Export its contents where you sign from:")
        print(f"    export VIGIL_DESTRUCTION_OWNER_KEY=\"$(cat {key_out})\"   # then `vigil sign-destruction`")
    else:
        print("At authorize time, sign the shared request on THIS host with this key:")
        print(f"    vigil sign-destruction --request authorization-request.json --key-id {kid} --key-file {key_out}")
    print()
    print("The minting box assembles the quorum from the PUBLIC enrolment requests only:")
    print("    vigil assemble-destruction --enrollment "
          f"{kid}={enroll_out} --enrollment <owner=...> --threshold M --base-dir .vigil-live")
    return 0


def _cmd_assemble_destruction(args: argparse.Namespace) -> int:
    """W9-5 PHASE 2 — run on the MINTING box. Assemble the m-of-n destruction trust root from PUBLIC enrolment
    requests. Verifies every proof-of-possession, refuses duplicate/forged keys, and — under the production
    posture — refuses anything that is not a genuine multi-signer quorum. No private key is ever on this box."""
    from pathlib import Path

    from .live.destruction_provision import assemble_authority, write_trust_root

    enrollments: list = []
    for spec in (args.enrollment or []):
        s_spec = str(spec or "")
        if "=" not in s_spec:
            print(f"vigil assemble-destruction: --enrollment must be key_id=/path/to/enrollment.json, "
                  f"got {spec!r}", file=sys.stderr)
            return 2
        kid, path = s_spec.split("=", 1)
        try:
            doc = Path(path.strip()).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"vigil assemble-destruction: could not read enrolment {kid.strip()!r}: {exc}", file=sys.stderr)
            return 2
        enrollments.append((kid.strip(), doc))
    if not enrollments:
        print("vigil assemble-destruction: at least one --enrollment key_id=path is required", file=sys.stderr)
        return 2
    try:
        gen = assemble_authority(enrollments=enrollments, threshold=args.threshold, owner_id=args.owner_id)
    except ValueError as exc:
        print(f"vigil assemble-destruction: {exc}", file=sys.stderr)
        return 2
    tr_path = write_trust_root(args.base_dir, gen.trust_root_json)
    print("=== vigil assemble-destruction — m-of-n quorum from per-host enrolments (W9-5) ===")
    print(f"threshold          : {gen.threshold}-of-{len(enrollments)}   "
          f"mandatory signer(s): {', '.join(gen.mandatory_signer_ids)}")
    print(f"trust root (public): {tr_path}")
    print("NO private keys were read or written here — each signer's key stays on its own host.")
    print()
    print("Per fix (per-host signing keeps keys apart at AUTHORIZE time too):")
    print("  (1) coordinator: vigil request-destruction --action-id pr-... --slug ... --target R "
          f"--base-dir {args.base_dir}")
    print("  (2) each signer: vigil sign-destruction --request <request.json> --key-id <id> --key-file <key> "
          "(owner: VIGIL_DESTRUCTION_OWNER_KEY)")
    print(f"  (3) coordinator: vigil combine-destruction --request <request.json> --signature id=sig.json ... "
          f"--base-dir {args.base_dir}")
    print(f"  (4) vigil patch ... --target-repo R --open-pr   (auto-discovers under {args.base_dir})")
    return 0


def _cmd_request_destruction(args: argparse.Namespace) -> int:
    """W9-5 coordinator step — mint the SHARED, unsigned destruction authorization (one nonce + bounded
    window) each signer will sign detached on their own host. Written O_EXCL (single-use slot)."""
    import time

    from .live.destruction_provision import (
        AuthorizationExistsError,
        build_authorization_request,
        default_paths,
        fresh_nonce,
        write_single_use_authorization,
    )

    try:
        req = build_authorization_request(action_id=args.action_id, engagement_slug=args.slug,
                                          target=args.target, now=time.time(), window_s=args.window_s,
                                          nonce=fresh_nonce())
    except ValueError as exc:
        print(f"vigil request-destruction: {exc}", file=sys.stderr)
        return 2
    out = args.out or default_paths(args.base_dir)["signed"].replace("signed-authorization.json",
                                                                     "authorization-request.json")
    try:
        write_single_use_authorization(out, req)
    except AuthorizationExistsError as exc:
        print(f"vigil request-destruction: {exc}", file=sys.stderr)
        return 2
    print("=== vigil request-destruction — shared unsigned authorization (W9-5) ===")
    print(f"action    : {args.action_id!r}  slug={args.slug!r}  target={args.target!r}")
    print(f"window    : {int(args.window_s)}s  (single-use nonce; within the 900s dead-man's-switch)")
    print(f"written   : {out}")
    print("Distribute this file to EACH signer host; each runs `vigil sign-destruction` with their own key.")
    return 0


def _cmd_sign_destruction(args: argparse.Namespace) -> int:
    """W9-5 per-signer step — run on the signer's OWN host. Sign the shared request DETACHED with THIS host's
    key (owner from VIGIL_DESTRUCTION_OWNER_KEY, a co-signer from --key-file) and write {key_id, signature}.
    The private key never leaves this host; only the detached signature returns to the coordinator."""
    import os
    from pathlib import Path

    from .live.destruction_provision import load_worker_key_file, sign_request_detached

    try:
        request_json = Path(args.request).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"vigil sign-destruction: could not read --request: {exc}", file=sys.stderr)
        return 2
    kid = str(args.key_id or "").strip()
    if not kid:
        print("vigil sign-destruction: --key-id is required", file=sys.stderr)
        return 2
    if args.key_file:
        try:
            _kid, priv = load_worker_key_file(f"{kid}={args.key_file}")
        except ValueError as exc:
            print(f"vigil sign-destruction: {exc}", file=sys.stderr)
            return 2
    else:
        priv = os.environ.get("VIGIL_DESTRUCTION_OWNER_KEY", "").strip()
        if not priv:
            print("vigil sign-destruction: no key — pass --key-file, or export VIGIL_DESTRUCTION_OWNER_KEY "
                  "for the owner (never argv).", file=sys.stderr)
            return 2
    try:
        sig = sign_request_detached(request_json=request_json, key_id=kid, private_key_b64=priv)
    except ValueError as exc:
        print(f"vigil sign-destruction: {exc}", file=sys.stderr)
        return 2
    out = args.out or f"{kid}.sig.json"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(sig, encoding="utf-8")
    print("=== vigil sign-destruction — detached signature (W9-5) ===")
    print(f"key_id    : {kid}")
    print(f"written   : {out}   <- return THIS to the coordinator (public; no private material)")
    return 0


def _cmd_combine_destruction(args: argparse.Namespace) -> int:
    """W9-5 coordinator step — combine per-host DETACHED signatures over the shared request into the
    single-use signed-authorization.json the PR leg consumes (written O_EXCL). The signatures are re-verified
    by the gate, not trusted here."""
    from pathlib import Path

    from .live.destruction_provision import (
        AuthorizationExistsError,
        combine_authorization,
        default_paths,
        write_single_use_authorization,
    )

    try:
        request_json = Path(args.request).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"vigil combine-destruction: could not read --request: {exc}", file=sys.stderr)
        return 2
    sigs: list = []
    for spec in (args.signature or []):
        s_spec = str(spec or "")
        path = s_spec.split("=", 1)[1] if "=" in s_spec else s_spec
        try:
            sigs.append(Path(path.strip()).read_text(encoding="utf-8"))
        except OSError as exc:
            print(f"vigil combine-destruction: could not read signature {spec!r}: {exc}", file=sys.stderr)
            return 2
    try:
        doc = combine_authorization(request_json=request_json, detached_signatures=sigs)
    except ValueError as exc:
        print(f"vigil combine-destruction: {exc}", file=sys.stderr)
        return 2
    out = args.out or default_paths(args.base_dir)["signed"]
    try:
        write_single_use_authorization(out, doc)
    except AuthorizationExistsError as exc:
        print(f"vigil combine-destruction: {exc}", file=sys.stderr)
        return 2
    print("=== vigil combine-destruction — single-use signed authorization (W9-5) ===")
    print(f"signatures: {len(sigs)}")
    print(f"written   : {out}")
    print(f"Then: vigil patch ... --base-dir {args.base_dir} --target-repo {args.target or '<repo>'} --open-pr")
    return 0


def _cmd_approve_provision(args: argparse.Namespace) -> int:
    """Mint + persist the OWNER approval AUTHORITY (VIGIL A2). Prints the owner PRIVATE key ONCE (never
    stored) — export it as VIGIL_APPROVAL_OWNER_KEY to sign approvals; the PUBLIC key is persisted under
    --base-dir so the offense engine + the Strix gate default to PER-ACTION owner approval for offense tools."""
    from .live.approval_broker import authority_path, provision_authority_material

    existing = authority_path(args.base_dir)
    if existing.exists() and not args.force:
        print(f"vigil approve provision-authority: an authority already exists at {existing}. Re-provisioning "
              "ROTATES the owner key and invalidates any tokens signed by the old key — pass --force to do it.",
              file=sys.stderr)
        return 2
    path, _pub, priv = provision_authority_material(args.base_dir, key_id=args.key_id)
    print("=== vigil approve provision-authority — per-action owner approval ===")
    print(f"authority (public): {path}")
    print(f"owner key_id      : {args.key_id}")
    print()
    print("OWNER PRIVATE KEY — shown ONCE; NOT stored by this command. Save it now:")
    print(f"    {priv}")
    print("    → export as VIGIL_APPROVAL_OWNER_KEY in the terminal you sign from; then `vigil approve sign`.")
    print()
    print("Offense tools now default to PER-ACTION approval: each queued tool call must be signed with")
    print(f"    vigil approve sign --base-dir {args.base_dir} --request-id <id>   (see `vigil approve list`).")
    return 0


def _cmd_approve_list(args: argparse.Namespace) -> int:
    """List the pending per-action approval requests an offense run has published (each is public-safe — no
    secret). The owner signs one with `vigil approve sign`."""
    from .live.approval_broker import approvals_root, list_pending

    pend = list_pending(approvals_root(args.base_dir))
    if not pend:
        print("(no pending approval requests)")
        return 0
    print(f"=== pending per-action approvals ({len(pend)}) — {approvals_root(args.base_dir)} ===")
    for r in pend:
        print(f"  request_id : {r.request_id}")
        print(f"    tool     : {r.tool_name}")
        print(f"    target   : {r.target}")
        print(f"    args     : {r.args_preview}")
        print(f"    created  : {r.created_at_iso}")
        print(f"    sign     : vigil approve sign --base-dir {args.base_dir} --request-id {r.request_id}")
    return 0


def _cmd_approve_sign(args: argparse.Namespace) -> int:
    """Sign ONE pending action with the owner key (read from VIGIL_APPROVAL_OWNER_KEY — never argv), minting a
    single-use, action-bound, window-bounded token the offense worker spends ONCE. A CRUCIBLE deny is never
    widened — a token only satisfies the WARDEN human leg for an in-envelope (queued) action."""
    import os
    import time

    from vigil_core.key_backend import (
        BACKEND_ENV, HardwareKeyUnavailable, KeyBackendError, select_owner_backend,
    )

    from .live.approval_broker import approvals_root, list_pending, load_authority, write_signed_token
    from .live.approval_token import DEFAULT_POLICY, ApprovalAction, mint_token

    owner_priv = os.environ.get("VIGIL_APPROVAL_OWNER_KEY", "").strip()
    backend_kind = os.environ.get(BACKEND_ENV, "").strip().lower()
    # Default (file) backend with no key: keep the exact original operator guidance.
    if backend_kind in ("", "file") and not owner_priv:
        print("vigil approve sign: no owner signing key — set VIGIL_APPROVAL_OWNER_KEY (run "
              "`vigil approve provision-authority`).", file=sys.stderr)
        return 2
    # W9-6: the owner key may live in a hardware (PKCS#11) token that signs so the private material never
    # enters this process. FAIL CLOSED — a selected-but-absent token REFUSES here; it never signs with a
    # file key (that would defeat holding the key off the box).
    try:
        backend = select_owner_backend(file_private_key_b64=(owner_priv or None))
    except HardwareKeyUnavailable as exc:
        print(f"vigil approve sign: hardware owner-key backend unavailable — {exc}", file=sys.stderr)
        return 2
    except KeyBackendError as exc:
        print(f"vigil approve sign: {exc}", file=sys.stderr)
        return 2
    root = approvals_root(args.base_dir)
    match = next((r for r in list_pending(root) if r.request_id == args.request_id), None)
    if match is None:
        print(f"vigil approve sign: no pending request {args.request_id!r} under {root}", file=sys.stderr)
        return 2
    auth = load_authority(args.base_dir)
    if auth is not None and auth.owner_key_id != args.key_id:
        print(f"vigil approve sign: WARNING key_id {args.key_id!r} != pinned authority {auth.owner_key_id!r}; "
              "the offense verifier will REJECT this token (key pin).", file=sys.stderr)
    ttl = max(1.0, min(float(args.ttl), DEFAULT_POLICY.max_token_lifetime))
    now = time.time()
    action = ApprovalAction(match.tool_name, match.target, match.action_digest)
    token = mint_token(action, signer=backend.sign, key_id=args.key_id,
                       nonce=match.nonce, not_before=now, not_after=now + ttl)
    path = write_signed_token(root, match.request_id, token)
    print(f"=== vigil approve sign — {args.request_id} ({match.tool_name} @ {match.target}) "
          f"[owner-key backend: {backend.name}] ===")
    print(f"signed by : {args.key_id}   window: {int(ttl)}s (single-use; within the 900s dead-man's-switch)")
    print(f"written   : {path}")
    print("The offense worker spends this token ONCE the next time it authorizes that exact action.")
    return 0


def _load_and_verify_ledger(path: str, *, base_dir: str) -> tuple[list, object]:
    from .attestation.identity import operator_key_resolver
    from .attestation.ledger import LedgerVerification, read_ledger, verify_ledger
    # Fail-closed on an ABSENT ledger FILE. ``read_ledger`` returns ``[]`` for a MISSING file exactly as it
    # does for a present-but-empty one, and ``verify_ledger([])`` is vacuously ``ok`` — so a DELETED (or
    # never-written) ledger would otherwise report "0 records — VERIFIED", i.e. a wiped audit trail would
    # certify clean. A missing file is NOT a verified-clean state; it is an evidence-integrity failure. Only
    # the ABSENT case fails here: a present-but-empty ledger is a distinct, legitimate fresh state (the file
    # is created on the first durable append) and still verifies vacuously.
    if not Path(path).is_file():
        return [], LedgerVerification(
            False,
            f"usage-attestation ledger file is ABSENT ({path}) — the always-on ledger was never written "
            "or was deleted; refusing to report VERIFIED (fail-closed). A present-but-empty ledger is a "
            "distinct, legitimate fresh state.",
        )
    records = read_ledger(path)
    resolver = operator_key_resolver(keypair_path=str(Path(base_dir) / "operator.key"))
    # W10-4 #476: consult the durable OUT-OF-BASE head/count pin. Internal consistency alone cannot catch a
    # TRUNCATED tail / partial wipe (a valid prefix is itself consistent), so when a durable pin persisted
    # out-of-band exists, pin ``expected_head``/``expected_count`` → a dropped tail FAILS closed. When NO pin
    # exists (fresh / legacy / lost), behave exactly as #558 (present ledger verifies on internal
    # consistency) and REPORT "unpinned" — never imply truncation protection we do not have. A pin that
    # DISAGREES with a present ledger is the whole point: it fails closed.
    import dataclasses

    from .attestation import head_pin as _head_pin
    pin = _head_pin.read_head_pin(path)
    if pin is not None:
        verification = verify_ledger(records, resolve_key=resolver,
                                     expected_head=pin.head, expected_count=pin.count)
        note = " [durable head anchor pinned]"
    else:
        verification = verify_ledger(records, resolve_key=resolver)
        note = (" [UNPINNED (no durable head anchor) — internal consistency only; a truncated tail / wipe "
                "is NOT detectable here]")
    try:
        verification = dataclasses.replace(verification, reason=str(verification.reason) + note)
    except Exception:  # noqa: BLE001 — annotation is cosmetic; never let it change the ok/fail verdict
        pass
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
            # ``grounded`` is a STRING sentinel ("tpm" | "software"; MonotonicAnchor default "software"),
            # never a bool — it must be compared to the exact hardware value. A truthiness test rendered
            # "TPM-anchored" for EVERY record (a non-empty string is truthy), manufacturing hardware
            # provenance for pure software-counter entries; only ``== "tpm"`` is hardware-anchored.
            anchored = "TPM-anchored" if getattr(e, "grounded", "") == "tpm" else "software-chain"
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

    def _load_delegation(path: str):
        from vigil_core.delegation import DelegationCert
        return DelegationCert.model_validate_json(Path(path).read_text(encoding="utf-8"))

    delegation = governance_delegation = None
    try:
        if args.delegation:
            delegation = _load_delegation(args.delegation)
        if getattr(args, "governance_delegation", ""):
            governance_delegation = _load_delegation(args.governance_delegation)
    except Exception as exc:  # noqa: BLE001 — an unreadable/invalid cert → refuse (no forged owner tie)
        print(f"delegation: could not load a delegation cert: {exc}")
        return 2
    verdicts = verify_offense_home(
        args.base_dir, owner_pubkey=(args.owner_pubkey or None), delegation=delegation,
        governance_delegation=governance_delegation,
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


def _cmd_dossier(args: argparse.Namespace) -> int:
    """`vigil dossier` — compile EVERYTHING a run produced into ONE self-contained, tamper-evident ``.zip``
    the operator can hand to anyone: the three human reports, the JSON/SARIF exports, the offline-verifiable
    proof bundle, the secret-scrubbed engagement log, the governance-signed spine chain, any drift record, and
    a readable ``index.html`` — plus a ``MANIFEST.json`` of sha256s and (when a governance signer is
    resolvable) an m-of-n signature over the manifest + a ``TRUST-ROOT-FINGERPRINT.txt``. Offense-side
    (``report.dossier`` reuses the report renderers + lazy-imports the proof bundle); deterministic and
    path-safe (every entry confined, symlinks never followed).

    With ``--session <id>`` it instead packages a whole SESSION (its run(s) + chat transcript + the
    per-session graph partition pointer + the open threads) into ONE signed handoff zip — see
    ``_cmd_session_dossier``."""
    import os

    if getattr(args, "session", ""):
        return _cmd_session_dossier(args)

    from framework.v2.report.dossier import build_dossier

    run_dir = args.run_dir or os.environ.get("VIGIL_PROOF_RUN_DIR") or ""
    if not run_dir:
        print("dossier: no run dir — pass --run-dir <abs> or set VIGIL_PROOF_RUN_DIR", file=sys.stderr)
        return 1
    if not Path(run_dir).is_dir():
        print(f"dossier: run dir not found: {run_dir}", file=sys.stderr)
        return 1
    out = args.out or str(Path(run_dir) / "dossier.zip")
    # The governed terminal transcript is a session-global signed log, so it lives OUTSIDE the run dir: take
    # an explicit --terminal-history, else default to a terminal-history.jsonl sitting next to the run.
    term_hist = getattr(args, "terminal_history", None)
    if not term_hist:
        default_hist = Path(run_dir) / "terminal-history.jsonl"
        term_hist = str(default_hist) if default_hist.is_file() else None
    # Stamp the build time by default: a document handed to a regulator that cannot say when it
    # was produced is weaker than one that can. --timestamp pins an explicit value and
    # --no-timestamp restores the byte-reproducible build for anyone comparing two archives.
    stamp = (args.timestamp or "").strip()
    if not stamp and not getattr(args, "no_timestamp", False):
        from datetime import datetime, timezone
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = build_dossier(run_dir=run_dir, out_zip=out, engagement_slug=(args.slug or "engagement"),
                        base_dir=(args.base_dir or None), generated_at=(stamp or None),
                        terminal_history=(term_hist or None), label=(args.label or None))
    if not res.get("ok"):
        print(f"dossier: {res.get('error', 'build failed')}", file=sys.stderr)
        return 1
    leads = res.get("leads")
    print("=== vigil dossier (one-click, tamper-evident run archive) ===")
    print(f"dossier:      {res['dossier']}")
    if res.get("label"):
        print(f"label:        {res['label']}")
    if res.get("case_file"):
        print(f"case file:    {len(res['case_file'])} plain-English document(s) — open "
              f"<unzipped>/00-START-HERE.html")
    print(f"entries:      {res['entries']}  (facts={res['facts']}"
          + (f", leads={leads}" if leads is not None else "") + ")")
    print(f"integrity:    MANIFEST.json sha256={res['manifest_sha256']}")
    if res.get("signed"):
        print(f"authenticity: SIGNED — trust-root fingerprint {res.get('trust_root_fingerprint', '')}")
        print("  PUBLISH this fingerprint OUT-OF-BAND so the dossier's authenticity is pinnable.")
    else:
        print("authenticity: UNSIGNED — integrity-checkable (hashes) but no governance signature "
              "(no signer resolvable).")
    if res.get("proof_bundle"):
        print(f"verify facts: cd <unzipped>/proof-bundle && {res.get('verify_cmd', '')}")
    else:
        print("verify facts: (no offline proof bundle — this run produced no oracle-confirmed FACT)")
    for note in res.get("notes", []):
        print(f"  note: {note}")
    return 0


def _cmd_session_dossier(args: argparse.Namespace) -> int:
    """`vigil dossier --session <id>` — package a whole SESSION into ONE signed handoff zip: each of its
    run(s) (as an independently re-verifiable ``runs/<run>/dossier.zip``), the chat transcript, the
    per-session graph partition pointer (B2 — a pure ONE-WAY projection of the signed spine), and the open
    (unfinished) threads. It resolves the session via the console registry, projects the graph from the spine,
    and reuses ``report.dossier.build_session_dossier``. Framework imports stay LAZY (FATAL-2)."""
    import os

    from framework.v2.console import actions, sessions
    from framework.v2.report.dossier import build_session_dossier

    try:
        got = sessions.get_session(args.session)          # raises ValueError on an unsafe id
    except ValueError as e:
        print(f"dossier: unsafe session id: {e}", file=sys.stderr)
        return 1
    if got.get("error"):
        print(f"dossier: {got['error']}", file=sys.stderr)
        return 1
    sess = got["session"]
    sid = sess["id"]

    # resolve the session's runs → run dirs; each run id is re-validated by the console traversal guard, so a
    # tampered/legacy unsafe id is DROPPED (never turned into a path). Missing dirs are noted by the builder.
    run_dirs: list[str] = []
    for rid in (sess.get("run_ids", []) or []):
        try:
            run_dirs.append(str(actions.run_dir(str(rid))))
        except ValueError:
            continue

    # W16-STD-6(c): resolve to an ABSOLUTE path so a dossier built from a different CWD still reads the
    # SAME session store (a relative ``.vigil-live`` used to follow the CWD around).
    from .live.instructions import resolve_live_dir
    live_dir = resolve_live_dir()
    chat_path = live_dir / "chats" / (sid + ".jsonl")
    chat_transcript = str(chat_path) if chat_path.is_file() else None

    # B2: project the per-session graph partition from the spine, then take its read view (pointer + counts).
    graph = sessions.session_graph(sid)                   # {"partition","nodes","edges"} — one-way projection
    threads = sessions.open_threads(sid)                  # unfinished lines of work (advisory)

    slug = args.slug if (args.slug and args.slug != "engagement") else (sess.get("slug") or "engagement")
    out = args.out or str(live_dir / "sessions" / sid / "dossier.zip")

    res = build_session_dossier(
        session_id=sid, run_dirs=run_dirs, out_zip=out, engagement_slug=slug,
        base_dir=(args.base_dir or None), generated_at=(args.timestamp or None),
        session_meta=sess, chat_transcript=chat_transcript, graph=graph, open_threads=threads,
        terminal_history=(getattr(args, "terminal_history", None) or None))
    if not res.get("ok"):
        print(f"dossier: {res.get('error', 'session handoff build failed')}", file=sys.stderr)
        return 1
    print("=== vigil dossier --session (one-click, tamper-evident SESSION handoff) ===")
    print(f"dossier:      {res['dossier']}")
    print(f"session:      {res['session_id']}  ({res['runs']} run(s), {res['facts']} oracle-confirmed FACT(s))")
    print(f"graph:        partition {res['session_id']} = {res.get('graph_nodes')} node(s) "
          "(pure one-way spine projection; authorizes nothing)")
    print(f"open threads: {res['open_threads']}")
    print(f"integrity:    MANIFEST.json sha256={res['manifest_sha256']}")
    if res.get("signed"):
        print(f"authenticity: SIGNED — trust-root fingerprint {res.get('trust_root_fingerprint', '')}")
        print("  PUBLISH this fingerprint OUT-OF-BAND so the handoff's authenticity is pinnable.")
    else:
        print("authenticity: UNSIGNED — integrity-checkable (hashes) but no governance signature "
              "(no signer resolvable).")
    print("verify runs:  unzip → each runs/<run>/dossier.zip is independently offline-re-verifiable")
    for note in res.get("notes", []):
        print(f"  note: {note}")
    return 0


def _enforce_production_gate(action: str) -> "int | None":
    """W9-4b — the opt-in refuse-to-start PRODUCTION gate. When VIGIL_POSTURE=production (or `prod`), a start
    path (`vigil up` / `vigil engage`) REFUSES to run unless all five production preconditions hold (vault
    SEALED, sovereignty non-PERMISSIVE, entitlement ACTIVE, backups ON, charter PRESENT). Prints ONE line per
    unmet precondition naming the failing control and returns 2. INERT otherwise — returns None so the caller
    proceeds byte-identically to before (the additive, opt-in contract). EXEC-ONLY: `doctor` is pure-stdlib
    (no framework/strix/sigil), so this stays on the boundary-safe path both start verbs already run on."""
    import pathlib
    from . import doctor as _doctor
    repo = pathlib.Path(__file__).resolve().parents[2]
    result = _doctor.evaluate_production_gate(repo)
    if result["ok"]:
        return None
    print(_doctor.production_gate_message(result, action=action), file=sys.stderr)
    return 2


def _cmd_up(args: argparse.Namespace) -> int:
    """`vigil up` — bring the WHOLE unified UI up at ONE origin and federate the two trust planes
    behind a self-contained reverse proxy. EXEC-ONLY: it spawns the three backends (sigil cockpit,
    crucible console, crucible api) as separate OS processes in their OWN venvs (via dispatch) and
    serves the bundle itself — it imports NO framework/strix/sigil, so the two trust domains are never
    co-loaded in one interpreter. Binds loopback (or a private/tunnel IP); refuses a public bind."""
    # W9-4b: refuse to start when VIGIL_POSTURE=production and any production precondition is unmet. INERT
    # (returns None, falls through) when the posture is not production — behaviour unchanged. Runs BEFORE any
    # docker bring-up / process spawn so a refused production run touches nothing.
    _gate = _enforce_production_gate("up")
    if _gate is not None:
        return _gate
    if getattr(args, "services", False):
        # Optional docker preflight: create the egress-gateway + root services (qdrant) if none exist
        # (idempotent). Both helpers are pure-stdlib, so this stays on the boundary-safe path. The two legs
        # are handled DIFFERENTLY: the egress-gate leg FAILS CLOSED (below); the root-services leg (qdrant/
        # neo4j/otel — not security-critical) stays best-effort so a docker hiccup there never blocks the UI.
        import json as _json
        import pathlib as _pl
        _repo = _pl.Path(__file__).resolve().parents[2]
        # THE EGRESS-GATE LEG FAILS CLOSED (W0-6 / #401). `--services` brings up the gateway topology whose
        # whole purpose is to gate the Strix sandbox's egress; if that bring-up FAILS and we continued, the
        # sandbox would run on Docker's default bridge with a default route to the operator LAN / a third
        # party / 169.254.169.254 — the gateway/README FATAL-1. A SILENT downgrade from gated to ungated is
        # the worst outcome, so a gateway bring-up failure ABORTS the run with a loud error UNLESS the
        # operator EXPLICITLY opts into ungated egress with --allow-ungated-egress (loud warning, continues).
        try:
            from vigil_gateway.docker import SandboxNetworking, PROXY_TOKEN_RELPATH, mint_proxy_token
            # sx-s2: hand the gateway its two compose-interpolation values at bring-up. (1) The signed-charter
            # slug (its L7 scope source) — from --charter-slug or the ambient env; unset still fail-closes the
            # gateway (no scope ⇒ no gate), now settable instead of a hardcoded empty literal that could never
            # come up. (2) A freshly MINTED short-lived proxy token, persisted so the Strix launch pre-flight
            # reads the SAME secret for the sandbox's Caido to present — the two ends can never drift, and a
            # mint failure simply leaves the proxy on its prior no-client-auth posture (never a deadlock).
            _slug = getattr(args, "charter_slug", "") or os.environ.get("VIGIL_GATEWAY_CHARTER_SLUG", "")
            _extra_env: dict = {}
            if _slug:
                _extra_env["VIGIL_GATEWAY_CHARTER_SLUG"] = _slug
            _tok = mint_proxy_token(_repo / PROXY_TOKEN_RELPATH)
            if _tok:
                _extra_env["VIGIL_GATEWAY_PROXY_TOKEN"] = _tok
            _res = SandboxNetworking().compose_up(
                _repo / "infra" / "docker" / "docker-compose.yml", build=True, context_dir=_repo / "gateway",
                extra_env=_extra_env)
            # A clean compose_up (exit 0) is NOT proof the gate is UP. `docker compose up -d` returns 0 as
            # soon as the container is CREATED, but the gateway proxy fails closed on a missing/bad charter
            # scope and can exit on the spot — leaving an exit-0-but-DEAD container. Trust the state in hand,
            # not the exit code: anything other than a RUNNING gateway is a bring-up FAILURE and MUST take the
            # SAME fail-closed branch below — continuing past a dead gateway runs the sandbox ungated exactly
            # as a raised bring-up would (the FATAL-1 silent downgrade this whole leg exists to prevent).
            if str(_res.get("gateway")) != "running":
                raise RuntimeError(
                    f"gateway container is not running (state={_res.get('gateway')!r}); `docker compose up -d` "
                    "returned 0 but the gateway proxy is not up (a missing/bad charter scope fails it closed)")
            print(f"vigil up: gateway topology up ({_json.dumps(_res)})")
        except Exception as _e:  # noqa: BLE001
            if not getattr(args, "allow_ungated_egress", False):
                print(f"vigil up: REFUSED (fail-closed) — the egress gate did not come up: {_e}\n"
                      "  Continuing would run the sandbox UNGATED (a default route to the operator LAN / a "
                      "third party / 169.254.169.254 — FATAL-1). Refusing to bring the UI up.\n"
                      "  Fix the gateway bring-up (see `vigil doctor` / `vigil services up`), or, if you "
                      "accept UNGATED egress for this run, re-run with --allow-ungated-egress.",
                      file=sys.stderr)
                return 2
            print(f"vigil up: WARNING — egress gate did NOT come up ({_e}); continuing UNGATED because "
                  "--allow-ungated-egress was set. Sandbox egress is NOT gated (FATAL-1 accepted).",
                  file=sys.stderr)
        try:
            # ABSOLUTE import (not relative `.services`) to keep the `_cmd_up` boundary rule intact —
            # it may relative-import ONLY `.uiproxy`; a pure-stdlib sibling helper comes in by absolute
            # path, exactly like `vigil_gateway.docker` above (test_up_down_verbs_import_no_trust_domain).
            from vigil_integration.services import DEFAULT_SERVICES, RootServices
            _sres = RootServices(_repo).up(list(DEFAULT_SERVICES))
            print(f"vigil up: services up ({_json.dumps(_sres)})")
        except Exception as _e:  # noqa: BLE001
            print(f"vigil up: root services preflight skipped — {_e}", file=sys.stderr)
    from .uiproxy import run_up
    return run_up(host=args.host, port=args.port, domain=args.domain, base_dir=args.base_dir,
                  no_browser=args.no_browser,
                  insecure_no_api_key=getattr(args, "insecure_no_api_key", False),
                  with_feed=getattr(args, "with_feed", False),
                  feed_slug=getattr(args, "feed_slug", ""),
                  feed_interval=getattr(args, "feed_interval", 3600),
                  with_voice=getattr(args, "with_voice", False),
                  with_gesture=getattr(args, "with_gesture", False),
                  with_telemetry=getattr(args, "with_telemetry", False),
                  telemetry_interval=getattr(args, "telemetry_interval", 15),
                  proxy_only=getattr(args, "proxy_only", False),
                  sovereign_addr=getattr(args, "sovereign_addr", ""),
                  offense_console_addr=getattr(args, "offense_console_addr", ""),
                  offense_api_addr=getattr(args, "offense_api_addr", ""))


def _cmd_services(args: argparse.Namespace) -> int:
    """`vigil services {up,status,down,render}` — the docker bring-up for the egress-gateway topology:
    create the sandbox+egress networks and the gateway container IF NONE EXIST (idempotent, re-runnable).
    EXEC-ONLY: imports vigil_gateway.docker (pure-stdlib), never framework/strix/sigil, so it stays on the
    same boundary-safe path `vigil up` uses."""
    import json
    import pathlib
    try:
        from vigil_gateway.docker import SandboxNetworking
    except ImportError:
        print("vigil services needs the gateway package importable (add gateway/ to PYTHONPATH, or "
              "`pip install vigil-gateway`).", file=sys.stderr)
        return 2
    net = SandboxNetworking()
    repo = pathlib.Path(__file__).resolve().parents[2]
    gw_dir = repo / "gateway"
    compose = (pathlib.Path(args.compose).expanduser() if getattr(args, "compose", "")
               else repo / "infra" / "docker" / "docker-compose.yml")

    from .services import DEFAULT_SERVICES, RootServices
    root = RootServices(repo)

    def _selected_root() -> list[str]:
        if getattr(args, "all", False):
            return ["qdrant", "neo4j", "otel-collector"]
        sel = list(DEFAULT_SERVICES)                              # qdrant by default
        if getattr(args, "with_graph", False):
            sel.append("neo4j")
        if getattr(args, "with_observability", False):
            sel.append("otel-collector")
        return sel

    action = args.services_action
    if action == "render":
        out = pathlib.Path(args.out).expanduser() if getattr(args, "out", "") else compose
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(net.render_compose(charter_slug=getattr(args, "charter_slug", "") or ""), encoding="utf-8")
        print(f"wrote {out}")
        return 0
    try:
        if action == "status":
            print(json.dumps({"gateway": net.status(), "services": root.status()}, indent=2))
            return 0
        if action == "down":
            net.compose_down(compose)
            root.down(["qdrant", "neo4j", "otel-collector"])
            print("gateway + services stopped (networks left in place)")
            return 0
        # up — create ONLY what is missing (idempotent): the gateway topology + the root services.
        # sx-s2: supply the gateway's signed-charter slug (its L7 scope) and a freshly MINTED short-lived
        # proxy token, persisted for the Strix launch pre-flight to read back (see the identical wiring in
        # `vigil up --services`). Slug unset ⇒ the gateway still fail-closes; mint failure ⇒ no client auth.
        from vigil_gateway.docker import PROXY_TOKEN_RELPATH, mint_proxy_token
        slug = getattr(args, "charter_slug", "") or os.environ.get("VIGIL_GATEWAY_CHARTER_SLUG", "")
        extra_env: dict = {}
        if slug:
            extra_env["VIGIL_GATEWAY_CHARTER_SLUG"] = slug
        tok = mint_proxy_token(repo / PROXY_TOKEN_RELPATH)
        if tok:
            extra_env["VIGIL_GATEWAY_PROXY_TOKEN"] = tok
        result = {"gateway": net.compose_up(compose, build=not getattr(args, "no_build", False),
                                            context_dir=gw_dir, extra_env=extra_env)}
        result["services"] = root.up(_selected_root())
        print(json.dumps(result, indent=2))
        return 0
    except (RuntimeError, OSError) as e:
        print(f"vigil services {action}: {e}", file=sys.stderr)
        return 1


def _cmd_doctor(args: argparse.Namespace) -> int:
    """`vigil doctor` — a read-only preflight/health report: prerequisites (binaries, both venvs, writable
    dirs), the UI ports (free or already in use), and which docker services are up (create the missing ones
    with `vigil services up`). Exits non-zero only on a HARD prerequisite gap. EXEC-ONLY: pure-stdlib."""
    import json
    import pathlib
    from . import doctor as _doctor
    repo = pathlib.Path(__file__).resolve().parents[2]
    report = _doctor.collect(repo)
    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, default=str))
    else:
        print(_doctor.render(report))
    return 0 if report.get("ok") else 1


def _cmd_verify_integrity(args: argparse.Namespace) -> int:
    """`vigil verify-integrity` (W6-7) — continuously verify the property the product exists to guarantee:
    the spine hash-chain / attestation. One audit by default (chain integrity, signed-head freshness, the
    anti-rollback floor, clock skew, vault/key state, disk); `--watch` runs it on a cadence and raises an
    alarm on any integrity failure. Exits non-zero on a violation. EXEC-ONLY + boundary-safe: reads inert
    on-disk bytes and imports only `vigil_core` — never framework/strix/sigil."""
    from . import integrity_verifier as _iv
    home = (Path(args.home).expanduser() if args.home
            else Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil"))))
    sink = _iv.AlarmSink(log_path=_iv._default_alarm_log(home))
    if args.watch:
        summary = _iv.run_integrity_monitor(home, cycles=args.cycles, interval=args.interval, sink=sink)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary.get("last_ok") else 1
    report = _iv.run_integrity_once(home, sink=sink)
    if getattr(args, "json", False):
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"integrity audit of {report.home} — {'OK' if report.ok else 'FAILED'}")
        for c in report.checks:
            mark = {"ok": "OK ", "fail": "!! ", "warn": ".. ", "absent": "-- ",
                    "unknown": "?? "}.get(c.status, "?? ")
            print(f"  {mark}{c.check}: {c.status} — {c.detail}")
    return 0 if report.ok else 1


def _cmd_alerts(args: argparse.Namespace) -> int:
    """`vigil alerts` (W8-1) — heartbeat STALENESS ALARMS for every HA/scheduled unit. Enumerates the unit
    registry and, for each watched unit, alarms when its heartbeat is absent (fail-closed), stale (the timer
    stopped firing) or records a failed last run. Alerts are PUSH-based (webhook / exec from the env) with a
    durable local log and a delivery DEAD-MAN. `--status` is read-only. Exits non-zero on any alarm. EXEC-ONLY
    + boundary-safe: reads/writes inert on-disk JSON and imports only `vigil_core` — never framework/sigil."""
    from . import unit_alerts as _ua
    return _ua.cmd_alerts(state_dir=args.state_dir, watch=args.watch, cycles=args.cycles,
                          interval=args.interval, status_only=args.status_only,
                          require_push=args.require_push, as_json=getattr(args, "json", False))


def _cmd_unit_heartbeat(args: argparse.Namespace) -> int:
    """`vigil unit-heartbeat <unit> --result ${SERVICE_RESULT}` (W8-1) — the systemd ExecStopPost hook each
    scheduled unit runs to record that it ran and whether it succeeded. Boundary-safe: writes one inert JSON
    heartbeat; imports only `vigil_core`."""
    from . import unit_alerts as _ua
    ok: Optional[bool] = None
    if getattr(args, "ok", False):
        ok = True
    elif getattr(args, "failed", False):
        ok = False
    return _ua.cmd_unit_heartbeat(args.unit, result=args.result or "", ok=ok, state_dir=args.state_dir,
                                  detail=args.detail or "")


def _cmd_telemetry(args: argparse.Namespace) -> int:
    """`vigil telemetry --out <path> [--interval N] [--once]` — the G2 live assurance/metrics collector: a
    read-only, one-way projection of the signed spine into a fact/lead/refusal/tool snapshot. Started for the
    operator by `vigil up --with-telemetry`; runnable standalone. Fail-soft (no spine → an honest empty
    snapshot). The blackboard is lazy-imported inside the collector (no framework import at CLI load)."""
    from .telemetry import run_collector
    return run_collector(out=args.out, interval=args.interval, once=args.once)


def _cmd_down(args: argparse.Namespace) -> int:
    """`vigil down` — CONTAIN a running `vigil up`: stop-and-disable the `vigil-command` systemd user
    unit (so `Restart=always` cannot restore it) and terminate the backends + proxy tracked in the pids
    file. EXEC-ONLY: imports NO framework/strix/sigil (containment is subprocess `systemctl` only)."""
    from .uiproxy import run_down
    return run_down(base_dir=args.base_dir)


def _cmd_upgrade(args: argparse.Namespace) -> int:
    """`vigil upgrade` (W5-5, #449) — run the automated, crash-safe SOVEREIGN data migration:
    verify -> backup -> verify -> migrate -> verify -> report, ROLLING BACK to the verified backup on any
    failure. The sovereign spine holds the owner key, so this NEVER runs in this offense process: it EXECs
    ``.venv-sovereign/bin/sigil upgrade`` in its OWN venv (FATAL-2 — the two trust domains never co-load
    here), passing ``--check`` / ``--no-backup`` through verbatim. Returns the sovereign leg's exit code
    (0 ok; 3 = migration needed under --check; 2 = refused/failed-and-rolled-back)."""
    from .dispatch import dispatch
    forwarded: list[str] = ["upgrade"]
    if getattr(args, "check", False):
        forwarded.append("--check")
    if getattr(args, "no_backup", False):
        forwarded.append("--no-backup")
    return dispatch("sigil", forwarded)


def _trip_all_killswitches(*, reason: str) -> list[str]:
    """Trip the persistent, fail-closed kill-switch for EVERY engagement the offense engine knows, so
    every gated action is refused engine-wide (persistently, across restarts) until an operator
    deliberately clears each one. Slugs are enumerated from the offense authority directory.

    The `framework` import is function-local (the offense engine): this verb runs offense-side and never
    crosses into the sovereign core, so the two-env boundary holds. Returns the slugs actually tripped."""
    from framework.v2.authority.killswitch import KillSwitch
    from framework.v2.common import paths

    slugs: set[str] = set()
    adir = paths.authority_dir()
    if adir.is_dir():
        for f in adir.glob("*.authority.json"):
            slugs.add(f.name[: -len(".authority.json")])
        for f in adir.glob("*.halt"):                      # a slug that is ALREADY halted is re-affirmed
            slugs.add(f.name[: -len(".halt")])
    tripped: list[str] = []
    for slug in sorted(slugs):
        try:
            KillSwitch(slug).trip(reason)                  # idempotent: the first reason is preserved
            tripped.append(slug)
        except Exception as exc:  # noqa: BLE001 — one bad slug must never stop the rest of the panic
            print(f"  WARNING: could not trip kill-switch for {slug!r}: {exc}", file=sys.stderr)
    return tripped


def _cmd_panic(args: argparse.Namespace) -> int:
    """`vigil panic` — the emergency HARD-STOP (W10-5 #477, completed for the cadence sidecars in
    W10-5b #478). In order:

      1. Trip EVERY engagement's kill-switch (the gate-level stop): any in-flight or later-launched
         gated offense action is DENIED, persistently and fail-closed — even a process we do not track.
         This runs FIRST so a racing engagement is refused before we start killing anything.
      2. MASK + stop + disable the `vigil-command` unit, then STOP + DISABLE every cadence sidecar
         timer AND its oneshot service (reprove/posture/ha-mirror/backup-push re-drive the target or
         push data off-host; backup/backup-drill/integrity are local), reset each timer's
         `Persistent=` catch-up stamp so a re-enable does not replay the missed runs, stop every live
         `vigil-witness@` instance, kill the tracked processes, and VERIFY nothing is left active or
         enabled.

    Clearing is deliberately a separate operator act (a kill-switch clear, `systemctl --user unmask`
    for the command unit, and a re-enable of any sidecar timers you still want).
    See docs/runbooks/PANIC-AND-CONTAINMENT.md."""
    try:
        tripped = _trip_all_killswitches(reason=(args.reason or "vigil panic"))
        print(f"vigil panic: tripped {len(tripped)} kill-switch(es): "
              f"{', '.join(tripped) if tripped else '(no engagements found — gate already clear)'}")
    except Exception as exc:  # noqa: BLE001 — a broken engine import must NOT block the process hard-stop
        print(f"vigil panic: WARNING — could not trip kill-switches ({type(exc).__name__}: {exc}); "
              f"proceeding to kill processes + mask the unit anyway.", file=sys.stderr)
    # The process/unit containment runs REGARDLESS of the kill-switch outcome — a hard-stop must never be
    # blocked by an engine-side failure.
    from .uiproxy import run_panic
    rc = run_panic(base_dir=args.base_dir)
    print("vigil panic: hard-stop complete. The kill-switches stay tripped until you CLEAR each one, "
          "the command unit stays masked until `systemctl --user unmask vigil-command.service`, and "
          "the cadence sidecar timers stay disabled until you re-enable the ones you want. "
          "See docs/runbooks/PANIC-AND-CONTAINMENT.md.")
    return rc


def _cmd_emergency_stop(args: argparse.Namespace) -> int:
    """`vigil emergency-stop` (W13-6 #499) — deliberately enter RESTRICTED MODE: a safe landing state
    BETWEEN fully-operational and the `vigil panic` hard-stop.

    Unlike `vigil panic` (which ALSO masks the unit and kills the process/units), emergency-stop leaves
    the process UP so an operator can still DIAGNOSE and EXPORT EVIDENCE. It reuses the EXISTING
    machinery: it trips every engagement's kill-switch (so the already-existing conjunctive gate refuses
    every target-touching / mutating action, persistently and fail-closed) and records the transition on
    the hash-chained ledger (so entering/leaving is on the chain and survives a restart). Nothing
    destructive happens; read-only diagnosis/evidence/audit-export/authorization-repair stay available.

    `--leave` records a deliberate LEAVE transition (clearing the kill-switches themselves stays a
    separate, explicit authorization-repair act). `--status` prints the current mode."""
    from . import restricted_mode as rm

    base_dir = args.base_dir
    if getattr(args, "status", False):
        state = rm.current_state(base_dir)
        if state is None:
            print("vigil emergency-stop: mode=OPERATIONAL (never entered restricted mode)")
        else:
            print(f"vigil emergency-stop: mode={'RESTRICTED' if state.entered else 'OPERATIONAL'} "
                  f"(last: {state.action} trigger={state.trigger!r} at {state.at})")
        return 0
    if getattr(args, "leave", False):
        t = rm.leave_restricted_mode(base_dir=base_dir, reason=(args.reason or ""))
        print(f"vigil emergency-stop: recorded LEAVE on the chain (seq {t.seq}). NOTE: the kill-switches "
              "stay tripped until you CLEAR each one deliberately (authorization repair).")
        return 0
    t = rm.enter_restricted_mode(base_dir=base_dir, trigger="emergency_stop",
                                 reason=(args.reason or "vigil emergency-stop"))
    print(f"vigil emergency-stop: entered RESTRICTED MODE (seq {t.seq}). Target-touching / mutating "
          "actions are now REFUSED by the existing gate (kill-switches tripped). Diagnosis + evidence "
          "export remain available. Clearing is a deliberate operator act (`--leave` + a kill-switch clear).")
    return 0


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


def _terminal_next_seq(history_path: str) -> int:
    """The next append-only seq coordinate for the terminal history — the count of existing records. Total:
    an absent/unreadable history yields 0 (a fresh log)."""
    try:
        p = Path(history_path)
        if not p.is_file():
            return 0
        return sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        return 0


def _append_terminal_history(history_path: str, record: object) -> None:
    """Append the REDACTED, signed ``ExecRecord`` as one canonical-JSON line to the terminal history log (the
    console's ``terminal_history`` reads it back, read-only). The record is already redacted + signed by the
    executor — no raw secret lands here. Total: an append failure is swallowed (the command already ran and is
    represented in the returned result; the durable history is best-effort, never fatal)."""
    try:
        payload = record.model_dump(mode="json")  # type: ignore[attr-defined]
        line = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with open(history_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except (OSError, TypeError, ValueError, AttributeError):
        pass


def _cmd_terminal(args: argparse.Namespace) -> int:
    """`vigil terminal <command...>` — run a governed LOCAL read/inspect command through the SAME conjunctive
    gate + sealed spine signer the live engine uses (``build_terminal_runtime`` reuses the exact building
    blocks). ``execute_terminal`` parses + allowlist-validates the command (NO shell, argv list, LOCAL
    read/print binaries only), classifies ``terminal.run`` at WARDEN A2 (→ QUEUES under the A1 offense ceiling,
    never auto), runs it, and writes a signed, redacted ``ExecRecord``. ``--approve`` is the operator's
    approval (the SAME wiring approval path — ``_approval_gate``) that upgrades the A2 queue to allow.

    Fail-closed at every stage: an unbuildable gate/signer, no signer, or an off-allowlist command all yield a
    clean JSON refusal (``ran=false``), never a raise. Prints the ``ExecResult`` as JSON and returns 0 iff the
    command ran, else 2."""
    import time as _time

    from .live.executor import execute_terminal

    command = " ".join(args.command).strip()

    def _refuse(reason: str) -> int:
        print(json.dumps({"tool": "terminal.run", "ran": False, "outcome": "deny", "tier": "A2",
                          "reason": reason, "exit_code": None, "stdout": "", "stderr": "",
                          "record_id": None}, indent=2))
        return 2

    try:
        from .live.wiring import build_terminal_runtime
        rt = build_terminal_runtime(slug=str(getattr(args, "slug", "") or "loopback"), base_dir=args.base_dir)
    except Exception as e:  # noqa: BLE001 — an unbuildable gate/signer is a clean refusal, never a raise
        return _refuse(f"could not build the terminal gate/signer ({type(e).__name__}) — refused (fail-closed)")

    if rt.signer is None:
        return _refuse("no signer wired — refusing to run an unrecordable command (fail-closed)")

    # --approve is the operator's approval: execute under the approval gate (WARDEN human leg satisfied → the
    # A2 queue is upgraded to allow). Without it, the base gate QUEUES terminal.run and execute_terminal denies
    # at authorization — the command is prepared + gated but never run. W0-11: the approval gate is PER-ACTION
    # (single-use) — bind it to THIS exact command so ``--approve`` admits only the one command the operator
    # typed, never a blanket promote-all.
    if args.approve and rt.approval_gate is not None:
        from .live.approval_token import action_digest
        rt.standing.bind("terminal.run", "127.0.0.1",
                         action_digest("terminal.run", "127.0.0.1", {"command": command}))
    active_gate = rt.approval_gate if (args.approve and rt.approval_gate is not None) else rt.gate

    seq = _terminal_next_seq(rt.history_path)
    res = execute_terminal(
        command, "informational", gate=active_gate, view=rt.view, destructive_view=rt.destructive_view,
        signer=rt.signer, seq=seq, now=int(_time.time()),
    )

    record_id = None
    if res.ran and res.record is not None:
        record_id = res.record.record_id
        _append_terminal_history(rt.history_path, res.record)   # redacted + signed record — read-only history

    print(json.dumps({
        "tool": res.tool, "ran": bool(res.ran), "outcome": res.outcome, "tier": res.tier,
        "reason": res.reason, "exit_code": res.exit_code, "stdout": res.stdout, "stderr": res.stderr,
        "record_id": record_id,
    }, indent=2))
    return 0 if res.ran else 2


def _cmd_sandbox(args: argparse.Namespace) -> int:
    """`vigil sandbox <command...>` — run an ARBITRARY command inside the network-isolated, workspace-confined
    bwrap sandbox (``executor.execute_sandbox``), gated + signed exactly like ``vigil terminal`` (reusing
    ``build_terminal_runtime``'s conjunctive gate + sealed spine signer). ``sandbox.exec`` classifies WARDEN A3
    (→ QUEUES under the A1 offense ceiling, never auto); ``--approve`` upgrades the queue to allow. The command
    runs safe by KERNEL isolation — no network egress, writes confined to ``<base_dir>/sandbox-workspace`` — so
    it is the "do anything a local shell can" tier; a missing bwrap is a clean refusal (NO un-sandboxed
    fallback). Fail-closed at every stage. Prints the ``ExecResult`` as JSON; returns 0 iff the command ran."""
    import time as _time
    from pathlib import Path as _Path

    from .live.executor import execute_sandbox

    command = " ".join(args.command).strip()

    def _refuse(reason: str) -> int:
        print(json.dumps({"tool": "sandbox.exec", "ran": False, "outcome": "deny", "tier": "A3",
                          "reason": reason, "exit_code": None, "stdout": "", "stderr": "",
                          "record_id": None}, indent=2))
        return 2

    try:
        from .live.wiring import build_terminal_runtime
        rt = build_terminal_runtime(slug=str(getattr(args, "slug", "") or "loopback"), base_dir=args.base_dir)
    except Exception as e:  # noqa: BLE001 — an unbuildable gate/signer is a clean refusal, never a raise
        return _refuse(f"could not build the sandbox gate/signer ({type(e).__name__}) — refused (fail-closed)")
    if rt.signer is None:
        return _refuse("no signer wired — refusing to run an unrecordable command (fail-closed)")

    # D3: run in an explicit existing dir (a cloned codebase) when --workspace is given, else the default
    # sandbox-workspace. Either way it is the ONLY writable path bound into the no-net box.
    ws_arg = str(getattr(args, "workspace", "") or "").strip()
    if ws_arg:
        workspace = _Path(ws_arg)
        if not workspace.is_dir():
            return _refuse(f"--workspace {ws_arg!r} is not an existing directory — refused (fail-closed)")
    else:
        workspace = _Path(args.base_dir) / "sandbox-workspace"    # the ONLY writable path inside the box
        try:
            workspace.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return _refuse(f"could not create the sandbox workspace ({type(e).__name__}) — refused (fail-closed)")
    history = str(_Path(args.base_dir) / "sandbox-history.jsonl")

    # W0-11: the approval gate is PER-ACTION (single-use) — bind it to THIS exact command so ``--approve``
    # admits only the one command the operator typed, never a blanket promote-all.
    if args.approve and rt.approval_gate is not None:
        from .live.approval_token import action_digest
        rt.standing.bind("sandbox.exec", "127.0.0.1",
                         action_digest("sandbox.exec", "127.0.0.1", {"command": command}))
    active_gate = rt.approval_gate if (args.approve and rt.approval_gate is not None) else rt.gate
    seq = _terminal_next_seq(history)
    res = execute_sandbox(
        command, "informational", workspace=str(workspace), gate=active_gate, view=rt.view,
        destructive_view=rt.destructive_view, signer=rt.signer, seq=seq, now=int(_time.time()),
    )

    record_id = None
    if res.ran and res.record is not None:
        record_id = res.record.record_id
        _append_terminal_history(history, res.record)            # redacted + signed record — read-only history

    print(json.dumps({
        "tool": res.tool, "ran": bool(res.ran), "outcome": res.outcome, "tier": res.tier,
        "reason": res.reason, "exit_code": res.exit_code, "stdout": res.stdout, "stderr": res.stderr,
        "record_id": record_id,
    }, indent=2))
    return 0 if res.ran else 2


def _ensure_tools_on_path() -> None:
    """Put the repo root on sys.path so ``tools.backup.retention`` (a standalone stdlib helper, not part of
    either trust-plane package) imports. Idempotent."""
    root = str(Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)


def _resolve_crucible_root() -> Optional[Path]:
    """The CRUCIBLE root that holds ``.blackboard`` / ``.console/runs`` — from ``$CRUCIBLE_ROOT`` if it points
    at a real dir, else the in-repo ``engine/crucible/framework/v2``, else None (no CRUCIBLE proof state to
    capture). Framework-free (no import of ``framework.v2.common.paths``) so the backup verb stays light."""
    env = os.environ.get("CRUCIBLE_ROOT")
    if env:
        p = Path(env).expanduser()
        if p.is_dir():
            return p
    here = Path(__file__).resolve()
    for d in (here, *here.parents):
        cand = d / "engine" / "crucible" / "framework" / "v2"
        if cand.is_dir():
            return cand
    return None


def _orchestrator_passphrase(args: argparse.Namespace) -> str:
    """The two-plane backup passphrase: from ``$<passphrase_env>`` (unattended, default
    ``VIGIL_BACKUP_PASSPHRASE``) or an interactive prompt. NEVER read from argv (a passphrase on the command
    line leaks to ``ps``/history) and NEVER stored."""
    env_name = getattr(args, "passphrase_env", "") or "VIGIL_BACKUP_PASSPHRASE"
    pw = os.environ.get(env_name)
    if pw:
        return pw
    if sys.stdin is not None and sys.stdin.isatty():
        import getpass
        return getpass.getpass("backup passphrase: ")
    raise SystemExit(f"vigil: no backup passphrase — set ${env_name} (never passed on argv) or run interactively")


def _sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _plane_manifest(path: Path) -> dict:
    return {"file": path.name, "sha256": _sha256_file(path), "bytes": path.stat().st_size}


def _run_sovereign_leg(subcmd_args: list[str], pw: str) -> int:
    """EXEC the SOVEREIGN ``sigil`` console-script in its OWN venv (never imported here — the owner key never
    enters this offense process; FATAL-2). The child env is SCRUBBED exactly as ``dispatch.dispatch`` does
    (strip cross-domain PYTHONPATH/PYTHONHOME + the owner signing key ``VIGIL_DESTRUCTION_OWNER_KEY``), and the
    passphrase is injected via ``SIGIL_BACKUP_PASSPHRASE`` — NEVER on argv."""
    from . import dispatch
    try:
        sigil = dispatch.resolve("sigil")
    except dispatch.DispatchError as e:
        print(f"vigil: sovereign leg: {e}", file=sys.stderr)
        return 127
    if not sigil.exists():
        print(f"vigil: sovereign leg: the sovereign environment is not built ({sigil} missing) — "
              f"run envs/build_envs.sh, or use --offense-only.", file=sys.stderr)
        return 127
    child_env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    child_env.pop("VIGIL_DESTRUCTION_OWNER_KEY", None)      # a sovereign secret an offense child must not carry
    child_env["SIGIL_BACKUP_PASSPHRASE"] = pw               # passphrase via env, never argv
    import subprocess
    try:
        return subprocess.run([str(sigil), *subcmd_args], env=child_env).returncode
    except OSError as e:
        print(f"vigil: sovereign leg: cannot execute {sigil} ({e})", file=sys.stderr)
        return 127


def _cmd_backup(args: argparse.Namespace) -> int:
    """Two-plane off-box backup → TWO SEPARATE encrypted files under a timestamped dir, plus a MANIFEST.json.

    The offense leg (``offense.vglbk``) runs IN THIS venv; the sovereign leg (``sovereign.sglbk``) is a
    DISTINCT ``.venv-sovereign/bin/sigil`` SUBPROCESS. There is NEVER a merged single-file archive: a merged
    archive would require ONE process to hold BOTH planes' secrets at once — a FATAL-2 violation. The owner key
    never enters this process; the sovereign leg holds it in its own venv only. The passphrase reaches each leg
    via env/argument, never argv, and is never stored — lose it and the backups are unrecoverable by design.

    This writes a PORTABLE, passphrase-encrypted LOCAL backup. With ``--push <dest>`` it ALSO replicates the
    ENCRYPTED parts + MANIFEST off-HOST to a transport backend (ciphertext only — see tools/backup/transport)
    and then VERIFIES the copy AT THE DESTINATION (W7-4, #462): it re-reads the bytes that landed there and
    refuses a truncated/corrupted/tampered copy fail-closed (non-zero exit). Without ``--push`` the backup
    lives only on this host's disk.

    The orchestrator ``MANIFEST.json`` (the index of what the backup contains) is signed with the offense
    governance key and, on first use, that key is recorded to a HOST-LOCAL trust anchor (``~/.vigil/…``, outside
    the backup dir) together with a monotonic ``backup_seq``. That anchor is what makes the DEFAULT ``vigil
    restore`` on this host AUTHENTICATED (it pins this exact key) and rollback-resistant — not the bare
    signature alone. Rotating the governance key requires re-establishing the anchor with ``--reset-trust-
    anchor`` (a deliberate, logged step)."""
    import json
    import socket
    import time

    if getattr(args, "sovereign_only", False) and getattr(args, "offense_only", False):
        print("vigil backup: --sovereign-only and --offense-only are mutually exclusive", file=sys.stderr)
        return 2
    out_root = Path(getattr(args, "out", "") or (Path.home() / "vigil-backups"))
    pw = _orchestrator_passphrase(args)
    _ensure_tools_on_path()
    from tools.backup.retention import prune, timestamp_name

    subdir = out_root / timestamp_name()
    subdir.mkdir(parents=True, exist_ok=True)
    planes: dict = {}

    # TOFU trust anchor (W7-6 rework, PR #630). Read it UP FRONT so a governance-key ROTATION refuses BEFORE
    # we do a full backup, and so the manifest can carry the next monotonic backup_seq. The anchor lives
    # HOST-LOCAL (~/.vigil/…), outside the backup dir, so the reach-the-backup-at-rest attacker cannot touch
    # it. FATAL-2: `backup` is an offense-plane module (no sigil import at load); the import stays local.
    from .backup import (OffenseBackupError, default_trust_anchor_path, load_trust_anchor,
                         offense_governance_pubkey, record_backup_trust_anchor)
    anchor_path = default_trust_anchor_path()
    try:
        anchor = load_trust_anchor(anchor_path)
    except OffenseBackupError as e:
        print(f"vigil backup: {e}", file=sys.stderr)
        return 1
    reset_anchor = bool(getattr(args, "reset_trust_anchor", False))
    try:
        gov_pub = offense_governance_pubkey(args.base_dir)
    except Exception as e:  # noqa: BLE001 — a keystore/vault error is a fail-closed refusal, not a crash
        print(f"vigil backup: cannot load the offense governance key under {args.base_dir}: {e}",
              file=sys.stderr)
        return 1
    if anchor and anchor.get("governance_pubkey") != gov_pub and not reset_anchor:
        print(f"vigil backup: REFUSED — the recorded backup trust anchor ({anchor_path}) names a DIFFERENT "
              f"governance key ({str(anchor.get('governance_pubkey'))[:16]}…) than the one now signing "
              f"({gov_pub[:16]}…). This is a governance-key rotation or a different engine home. Re-establish "
              "the anchor deliberately with --reset-trust-anchor (a logged step) — refusing to overwrite the "
              "trust root silently.", file=sys.stderr)
        return 1
    next_seq = int(anchor.get("backup_seq", 0)) + 1 if anchor else 1

    if not getattr(args, "sovereign_only", False):
        from .backup import OffenseBackupError, create_offense_backup
        # Honor an EXPLICIT --crucible-root; fall back to auto-discovery ONLY when the flag is unset
        # (mirrors _cmd_restore — an explicit operator-supplied root must never be silently overridden by
        # discovery, which would back up a DIFFERENT crucible tree than the one requested).
        croot = getattr(args, "crucible_root", "") or None
        if croot is None:
            cr = _resolve_crucible_root()
            croot = str(cr) if cr else None
        off_dest = subdir / "offense.vglbk"
        try:
            res = create_offense_backup(off_dest, pw, base_dir=args.base_dir, crucible_root=croot)
        except OffenseBackupError as e:
            print(f"vigil backup: offense leg failed: {e}", file=sys.stderr)
            return 1
        planes["offense"] = _plane_manifest(off_dest)
        print(f"offense  → {off_dest}  ({res['files']} files, {res['secrets']} keys"
              + (f", crucible={croot}" if croot else "") + ")")

    if not getattr(args, "offense_only", False):
        sov_dest = subdir / "sovereign.sglbk"
        rc = _run_sovereign_leg(["backup", str(sov_dest)], pw)
        if rc != 0:
            print(f"vigil backup: sovereign leg failed (exit {rc})", file=sys.stderr)
            return 1
        planes["sovereign"] = _plane_manifest(sov_dest)
        print(f"sovereign → {sov_dest}")

    manifest = {
        "schema": 2, "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": socket.gethostname(), "planes": planes,
        # Monotonic freshness marker (from the host trust anchor, NOT the wallclock): restore refuses a backup
        # whose backup_seq is older than the latest recorded on this host — closing rollback-to-genuine-older,
        # which neither the signature nor the pin catches.
        "backup_seq": next_seq,
        "retention_hint": {"keep_days": args.keep_days, "keep_last": args.keep_last},
        "note": ("TWO SEPARATE encrypted files, one per plane — never a merged archive (a merged archive = "
                 "one process holding both plane secrets = FATAL-2). One passphrase per file; lose it → "
                 "unrecoverable by design."),
    }
    # Write the EXACT bytes we sign (write_bytes, not write_text — no newline translation), so the on-disk
    # MANIFEST.json is byte-identical to what MANIFEST.sig.json is computed over.
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    (subdir / "MANIFEST.json").write_bytes(manifest_bytes)
    # SIGN the orchestrator manifest with the offense governance key over DOMAIN-SEPARATED bytes (W7-6 #464 /
    # PR #630). FATAL-2: offense governance key only, never the owner key.
    from .backup import sign_orchestrator_manifest
    sig_doc = sign_orchestrator_manifest(manifest_bytes, base_dir=args.base_dir)
    (subdir / "MANIFEST.sig.json").write_text(json.dumps(sig_doc, indent=2, sort_keys=True), encoding="utf-8")
    print(f"manifest → {subdir / 'MANIFEST.json'}")
    # HONEST wording (MED-2): the sidecar is a signature, not authenticity by itself. Say what it is; the
    # trust-anchor line below is what actually makes the default restore authenticated.
    print(f"signature → {subdir / 'MANIFEST.sig.json'}  (offense-governance key {sig_doc['pubkey'][:16]}…, "
          "ed25519, domain-separated over the exact manifest bytes)")
    # Record/advance the host-local TOFU trust anchor AFTER the backup landed (a crash only ever leaves the
    # anchor lagging — fail-safe: it never refuses a genuine newer backup). This is what makes the DEFAULT
    # restore authenticated + rollback-resistant, per PR #630.
    try:
        ap, action = record_backup_trust_anchor(
            governance_pubkey=sig_doc["pubkey"], backup_seq=next_seq,
            manifest_sha256=sig_doc["manifest_sha256"], path=anchor_path, reset=reset_anchor)
    except OffenseBackupError as e:
        print(f"vigil backup: local backup OK, but the trust anchor could not be updated: {e}", file=sys.stderr)
        return 1
    _verb = {"established": "established (trust-on-first-use)", "advanced": "advanced",
             "rotated": "RE-ESTABLISHED after a deliberate key rotation"}.get(action, action)
    print(f"trust anchor → {ap} {_verb}; backup_seq={next_seq}. On THIS host, a default `vigil restore` now "
          f"PINS this governance key (authenticated) and refuses an older backup. To restore on ANOTHER host, "
          f"pass --expect-governance-pubkey {sig_doc['pubkey'][:16]}… (obtained out of band); an "
          "unauthenticated restore is refused under VIGIL_POSTURE=production.")
    print("KEEP THE PASSPHRASE SAFE — it is the ONLY key to these backups (never stored; lose it → unrecoverable).")

    # TRUE off-HOST transport (opt-in): after a SUCCESSFUL local backup, replicate the ENCRYPTED parts +
    # MANIFEST to a transport backend so a real second copy lives off the host. The parts are passphrase-
    # encrypted (scrypt AEAD) BEFORE they were written, so transport moves CIPHERTEXT only — the remote sees
    # no plaintext (its own security is the operator's responsibility). The local backup above already
    # succeeded and is untouched; a push failure surfaces without discarding it.
    push_dest = getattr(args, "push", "") or ""
    if push_dest:
        from tools.backup.transport import TransportError, get_transport
        # Push the signature sidecar too — without it the pushed copy would be an unsigned manifest that
        # `vigil restore` fails-closed on, making the off-host replica unrestorable (W7-6 #464).
        parts = ([subdir / info["file"] for info in planes.values()]
                 + [subdir / "MANIFEST.json", subdir / "MANIFEST.sig.json"])
        try:
            transport = get_transport(push_dest)
            pushed = transport.push(parts, subdir.name)
        except TransportError as e:
            print(f"vigil backup: local backup OK, but --push failed: {e}", file=sys.stderr)
            return 1
        print(f"pushed → {pushed['target']} ({len(pushed['files'])} encrypted part(s) + manifest; "
              f"ciphertext only, no plaintext leaves the host)")
        # DESTINATION-side integrity verification (W7-4, #462), fail-closed. Re-read the bytes AT THE
        # DESTINATION and confirm each matches the sha256 of exactly what we sent — NOT a second local
        # checksum. The transport hashes the remote copy's own bytes (a remote sha256sum over ssh, or a
        # byte-for-byte re-read of a mounted / rsync target). A truncated, corrupted, or tampered remote
        # copy is DETECTED here and the whole backup verb FAILS (exit 1) — which the vigil-backup-push
        # systemd unit's ExecStopPost heartbeat turns into a W8-1 (#467) failure alert. We never report an
        # off-host copy as good without proving it landed intact.
        expected = {p.name: _sha256_file(p) for p in parts}
        try:
            verified = transport.verify(subdir.name, expected)
        except TransportError as e:
            print(f"vigil backup: local backup OK, PUSH copied but DESTINATION INTEGRITY CHECK FAILED "
                  f"(fail-closed, off-host copy refused): {e}", file=sys.stderr)
            return 1
        print(f"verified → {len(verified['verified'])} file(s) hash-match at the destination "
              f"(re-read off-host, not a local checksum)")

    if getattr(args, "prune", False):
        deleted = prune(out_root, keep_days=args.keep_days, keep_last=args.keep_last)
        print(f"pruned {len(deleted)} old backup(s)"
              + (": " + ", ".join(p.name for p in deleted) if deleted else " (none outside the policy)"))
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    """Inverse of ``vigil backup``: VERIFY the MANIFEST.json GOVERNANCE SIGNATURE and then each plane part's
    manifest sha256 BEFORE invoking any leg, then restore the offense leg IN THIS venv and the sovereign leg as
    a ``sigil restore`` SUBPROCESS. Two encrypted files, never a merged archive — the same FATAL-2 boundary as
    backup.

    AUTHENTICITY (W7-6 rework, PR #630). An unsigned manifest is always refused. Beyond that, how the signature
    is trusted depends on what is known about the signing key:

    * DEFAULT, once a `vigil backup` has run on this host: the signature is PINNED against the governance key
      recorded in the host trust anchor (``~/.vigil/…``). A manifest re-signed under any other key is refused —
      this is an AUTHENTICATED restore.
    * ``--expect-governance-pubkey <b64>`` ALWAYS overrides the anchor: the signer must equal it.
    * NO anchor on this host (e.g. an off-host disaster recovery) and no pin: refused fail-closed under
      ``VIGIL_POSTURE=production`` (establish/confirm the anchor first, or pass the pin out of band); outside
      production it proceeds INTEGRITY-ONLY with a LOUD warning — integrity-only does NOT authenticate the
      signer, so an attacker who reached the backup could have re-signed it under their own key.

    ROLLBACK. When the anchor is present, a backup whose monotonic ``backup_seq`` is older than the latest
    recorded is refused (rollback to a genuine older signed backup, which the signature/pin do not catch);
    ``--allow-rollback`` overrides deliberately. A plane whose part is missing or sha256-mismatched refuses
    with a non-zero exit."""
    import json

    if getattr(args, "sovereign_only", False) and getattr(args, "offense_only", False):
        print("vigil restore: --sovereign-only and --offense-only are mutually exclusive", file=sys.stderr)
        return 2
    src = Path(args.src)
    if not src.is_dir():
        print(f"vigil restore: {src} is not a backup dir (expected a timestamped dir with MANIFEST.json)",
              file=sys.stderr)
        return 2
    try:
        manifest_bytes = (src / "MANIFEST.json").read_bytes()   # EXACT signed bytes — no newline translation
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, ValueError) as e:
        print(f"vigil restore: cannot read {src / 'MANIFEST.json'}: {e}", file=sys.stderr)
        return 2
    # FAIL-CLOSED: verify the orchestrator manifest's governance signature BEFORE trusting ANY value in it
    # (the file names + sha256s used below to locate and integrity-check every plane part). A missing sidecar
    # is an UNSIGNED manifest and is refused. AUTHENTICITY (PR #630): the DEFAULT pins the signature against the
    # host trust anchor's recorded governance key; an explicit --expect-governance-pubkey overrides; with no
    # anchor and no pin, production refuses fail-closed while non-production proceeds integrity-only + a loud
    # warning. The resolved pin is used for BOTH the orchestrator index AND the inner offense manifest.
    from .backup import (OffenseBackupError, check_backup_freshness, default_trust_anchor_path,
                         load_trust_anchor, resolve_manifest_pin, verify_orchestrator_manifest)
    from vigil_core.posture import is_production_posture
    try:
        sig_doc = json.loads((src / "MANIFEST.sig.json").read_bytes().decode("utf-8"))
    except (OSError, ValueError) as e:
        print(f"vigil restore: {src} has no verifiable MANIFEST.sig.json ({e}) — refusing to trust an "
              f"UNSIGNED manifest (W7-6). Re-fetch the backup from a source that carries its signature.",
              file=sys.stderr)
        return 2
    explicit_pin = getattr(args, "expect_governance_pubkey", "") or None
    anchor_path = default_trust_anchor_path()
    try:
        anchor = load_trust_anchor(anchor_path)
    except OffenseBackupError as e:
        print(f"vigil restore: {e}", file=sys.stderr)
        return 2
    try:
        expect_pub, pin_mode, pin_warning = resolve_manifest_pin(anchor, explicit_pin, is_production_posture())
    except OffenseBackupError as e:
        print(f"vigil restore: {e}", file=sys.stderr)
        return 2
    if pin_warning:
        print(f"vigil restore: {pin_warning}", file=sys.stderr)
    try:
        verify_orchestrator_manifest(manifest_bytes, sig_doc, expect_pubkey=expect_pub)
    except OffenseBackupError as e:
        print(f"vigil restore: {e}", file=sys.stderr)
        return 2
    # ROLLBACK RESISTANCE: refuse a backup older than the latest recorded in the anchor (unless --allow-rollback).
    try:
        roll_warning = check_backup_freshness(anchor, (manifest.get("backup_seq") if isinstance(manifest, dict)
                                                       else None), bool(getattr(args, "allow_rollback", False)))
    except OffenseBackupError as e:
        print(f"vigil restore: {e}", file=sys.stderr)
        return 2
    if roll_warning:
        print(f"vigil restore: {roll_warning}", file=sys.stderr)
    if pin_mode == "anchor":
        print(f"vigil restore: manifest AUTHENTICATED against the host trust anchor "
              f"(governance key {str(expect_pub)[:16]}…).", file=sys.stderr)
    elif pin_mode == "explicit":
        print(f"vigil restore: manifest AUTHENTICATED against --expect-governance-pubkey "
              f"({str(expect_pub)[:16]}…).", file=sys.stderr)
    planes = manifest.get("planes", {}) if isinstance(manifest, dict) else {}
    pw = _orchestrator_passphrase(args)

    def _verified_part(name: str):
        """(path or None, error-code). None path + 0 = plane absent from this backup; None + non-0 = a
        fail-closed refusal (missing/mismatched part)."""
        info = planes.get(name)
        if not isinstance(info, dict):
            return None, 0
        f = src / str(info.get("file", ""))
        if not f.is_file():
            print(f"vigil restore: {name} part {f} is missing — refusing", file=sys.stderr)
            return None, 2
        if _sha256_file(f) != info.get("sha256"):
            print(f"vigil restore: {name} part {f} sha256 mismatch (tamper) — refusing", file=sys.stderr)
            return None, 2
        return f, 0

    if not getattr(args, "sovereign_only", False):
        off, err = _verified_part("offense")
        if err:
            return err
        if off is None:
            print("vigil restore: no offense plane in this backup — skipping", file=sys.stderr)
        else:
            from .backup import OffenseBackupError, restore_offense_backup
            croot = getattr(args, "crucible_root", "") or None
            if croot is None:
                cr = _resolve_crucible_root()
                croot = str(cr) if cr else None
            # Pin the INNER offense manifest with the SAME resolved key as the orchestrator index (the anchor's
            # recorded key by default, an explicit --expect-governance-pubkey if given, or None in the
            # integrity-only non-production path) — one governance key, one pin, both manifests.
            try:
                res = restore_offense_backup(off, args.base_dir, pw, crucible_root=croot,
                                             expect_pubkey=expect_pub, force=getattr(args, "force", False))
            except OffenseBackupError as e:
                print(f"vigil restore: offense leg failed (nothing trusted): {e}", file=sys.stderr)
                return 1
            print(f"offense restored → base={res['new_base']} ({res['files']} files, {res['secrets']} keys, "
                  f"{res['bundles_verified']} evidence bundle(s) re-verified)")

    if not getattr(args, "offense_only", False):
        sov, err = _verified_part("sovereign")
        if err:
            return err
        if sov is None:
            print("vigil restore: no sovereign plane in this backup — skipping", file=sys.stderr)
        else:
            home = getattr(args, "sigil_home", "") or ""
            if not home:
                print("vigil restore: --sigil-home <fresh dir> is required to restore the sovereign plane",
                      file=sys.stderr)
                return 2
            sov_args = ["restore", str(sov), home]
            if getattr(args, "force", False):
                sov_args.append("--force")     # forward the non-empty-target override to the sovereign leg
            rc = _run_sovereign_leg(sov_args, pw)
            if rc != 0:
                print(f"vigil restore: sovereign leg failed (exit {rc})", file=sys.stderr)
                return 1
            print(f"sovereign restored → home={home}  (next: SIGIL_HOME={home} vigil sigil verify)")
    return 0


def _cmd_posture(args: argparse.Namespace) -> int:
    """``vigil posture <attest|verify|endpoint> …`` — the Certificate of Non-Exploitability verb.

    Forwards IN-PROCESS to the posture sub-CLI (offense side; every framework touch inside it stays
    function-local, and it never imports sigil — FATAL-2 holds). The sub-CLI owns its own argparse, so the
    sub-verb + its flags are captured verbatim as an ``argparse.REMAINDER`` and passed through untouched.
    This is what makes ``docs/TRUTHENOVATION.md``'s ``vigil posture attest|verify`` real; the same logic is
    also reachable as ``python -m vigil_integration.posture …``."""
    from .posture.cli import main as posture_main  # stdlib-only at import (framework stays function-local)
    return int(posture_main(list(args.posture_args or [])))


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
    pe.add_argument("--objective", default="",
                    help="free-text goal RECORDED with the engagement for your own record; it does not "
                         "steer the run. To choose how thorough the --brain planner is, use "
                         "--brain-objective.")
    pe.add_argument("--brain-objective", default="comprehensive", choices=("quick", "comprehensive"),
                    help="how thorough the --brain planner's proposed chain is (default: comprehensive). "
                         "Only meaningful with --brain. Distinct from --objective, which is the "
                         "engagement's recorded free-text goal.")
    pe.add_argument("--brain-observations", default="",
                    help="H3: path to a JSON sidecar of VERIFIED, PROVENANCED observations that seed the "
                         "--brain planner's target profile (rows of {kind, value, provenance, confidence}; "
                         "kinds: ip_address/open_port/service/tls/technology/repo_language/cms/"
                         "cloud_provider/container_orch/api_descriptor/target_type). Only meaningful with "
                         "--brain. Overrides VIGIL_BRAIN_OBSERVATIONS and the default "
                         "<base-dir>/<slug>/observations.json. Absent => the profile is honest unknowns.")
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
    pe.add_argument("--model", default="",
                    help="GAP-1 model sovereignty: an EXPLICIT cloud model string for the think step (e.g. "
                         "claude-sonnet-5). Overrides the ambient default; still sovereignty-tier-gated. "
                         "Mutually exclusive with --backend (a cloud model vs a local backend).")
    pe.add_argument("--backend", default="",
                    help="GAP-1 model sovereignty: a LOCAL think backend (ollama / self-hosted / vllm / "
                         "llama-cpp / tgi). The think step (and every fireteam member) routes through the "
                         "loopback-enforced provider with NO cloud failover — the prompt + source never "
                         "egress to a cloud model; an unreachable local backend REFUSES rather than falling "
                         "back to cloud. Choosing this is the 'nothing leaves this machine' guarantee.")
    pe.add_argument("--replay", default="", help="a JSON file of scripted decisions (keyless-live)")
    pe.add_argument("--access-log", default="")
    pe.add_argument("--auth-log", default="")
    pe.add_argument("--conn-log", default="")
    pe.add_argument("--max-iterations", type=int, default=12)
    pe.add_argument("--brain", default="", choices=("", "hexstrike"),
                    help="drive `think` with a homegrown propose-only decision brain (e.g. hexstrike) "
                         "instead of the Claude/replay path — gate + executor + oracle unchanged")
    pe.add_argument("--brain-execute-via-body", action="store_true",
                    help="H1x-1 (DEFAULT OFF): route a GATE-AUTHORIZED brain tool through the ONE canonical "
                         "HexstrikeAgentBody.execute instead of the governed executor. The gate is unchanged "
                         "(offense still queues; nuclei stays A2) and the FACT seam stays CLOSED — the body "
                         "runs with no runner, so it mints ZERO facts. Only meaningful with --brain hexstrike.")
    pe.add_argument("--approve-offense", action="store_true",
                    help="a SINGLE-USE standing approval to run ONE queued offense action against the "
                         "operator's own chartered loopback (the human leg of the conjunctive gate; scope "
                         "still enforced). It reduces autonomous auto-fire from EVERY queued action to "
                         "at-most-one per run — a second distinct queued action stays queued; it does NOT "
                         "mean nothing auto-fires (approve each action individually for that)")
    pe.add_argument("--resume", action="store_true",
                    help="continue this slug's engagement from its last SIGNED checkpoint (the same "
                         "{slug}.spine) instead of starting fresh — the network-failure / crash recovery "
                         "path. A COMPLETED run is a no-op. At-least-once: an iteration that ran a tool but "
                         "crashed before its checkpoint re-runs that tool on resume (re-gated + re-confirmed).")
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
    pver.add_argument("--governance-delegation", default="",
                      help="a JSON file holding an owner-signed OFFENSE_GOVERNANCE_ROLE DelegationCert — roots "
                           "the PERSISTED blackboard chain (spine-head.json/spine-chain.json); without it that "
                           "chain is honestly UNVERIFIABLE, not owner-rooted")
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
                        help="pick the FACT FROM THE SPINE by ref (--from-spine, when the spine has >1 "
                             "confirmed fact). It can NEVER redirect which retained re-verifiable entry "
                             "drives fix-verification (that is selected by the TRUSTED finding's OWN ref), "
                             "and a value that disagrees with the trusted finding's own ref is REFUSED "
                             "(fail-closed).")
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
    # LIVE FIX-VERIFICATION (GAP B) — OFF by default. Absent --verify-base-url the run is byte-identical to
    # before (no oracle ⇒ `remediated` stays False and the PR is an unverified PROPOSAL). BOTH flags are named
    # `--verify-*` deliberately, so no PRE-EXISTING argparse abbreviation changes meaning on the OFF path:
    # `--target-base-url` (the prove verb's name) would make the existing `--target-b…` prefix ambiguous, and
    # a bare `--run-dir` would make the existing `--r` prefix (--repo-base-dir) ambiguous. Semantics are
    # otherwise identical to `vigil remediate --prove` — the verification is literally delegated to it.
    ppatch.add_argument("--verify-base-url", default="",
                        help="OFF by default. The LIVE, PATCHED, REDEPLOYED service to re-drive the ORIGINAL "
                             "exploit against, e.g. http://127.0.0.1:8080 — it MUST be authorized in the "
                             "engagement charter scope (else REFUSED). Supplying it DELEGATES verification to "
                             "the same four-state `vigil remediate --prove` machinery (live positive control, "
                             "a freshness challenge that must be ECHOED in the judged bytes, the required "
                             "silent trials, a signed certificate): 'remediated' is minted ONLY on a "
                             "REMEDIATED certificate that independently re-verifies; STILL_VULNERABLE is a "
                             "firing verdict; INCONCLUSIVE/REFUSED yield 'unverified', never a fix. Supported "
                             "channel: error_signature (error_based_sqli) — any other confirmed channel "
                             "REFUSES rather than mis-drive another oracle family. NOTE: the ladder verifies "
                             "AFTER the PR leg, so without --open-pr nothing is verified (the run says so and "
                             "exits non-zero). SIDE EFFECT: a run that actually verifies (re)provisions — "
                             "OVERWRITING — this engagement's signed CRUCIBLE authority, scoped to the "
                             "verification host, exactly as `vigil remediate --prove` does. WHAT THE ECHO "
                             "ESTABLISHES: RESPONSIVENESS/FRESHNESS ONLY — that SOME responder on this host "
                             "returned this run's nonce in the judged bytes. NOT that it was your "
                             "application, NOT that the request reached the vulnerable endpoint. So a "
                             "'remediated' here means: the original oracle did not fire over freshly captured "
                             "bytes from the host you nominated. KNOWN RESIDUAL: an ECHOING but unrelated "
                             "responder (an echoing 404 or block page that reflects the query, another "
                             "service on this host) satisfies that floor while the exploit never reaches the "
                             "app — YOU exclude it by pointing this at the REAL application; a NON-echoing "
                             "responder is already 'unverified'. HONEST LIMITS: that the deployment carries "
                             "THIS run's patch is the operator's assertion, and a silent verdict inherits the "
                             "prove path's residuals (it does not distinguish a payload-discriminating WAF or "
                             "a param-stripping echoing edge from a real fix).")
    ppatch.add_argument("--verify-run-dir", default="",
                        help="the run dir holding proofs/reverifiable.json (the retained ORIGINAL firing "
                             "oracle_context = the positive control) for --verify-base-url; default = "
                             "--base-dir. TRUST NOTE (honest): that retained material is UNSIGNED LOCAL RUN "
                             "OUTPUT — the operator's own run output in the owner-operated model — and is "
                             "trusted as such; it is matched to the trusted finding by check_id (exact, "
                             "fail-closed). Do NOT point this at another engagement's proofs/.")
    ppatch.set_defaults(func=_cmd_patch)

    prem = sub.add_parser(
        "remediate",
        help="run the FOUR-STATE live remediation proof over a PROVENANCE-GROUNDED finding (--prove): re-drive "
             "the original exploit against the live target through the gated executor and print REMEDIATED / "
             "STILL_VULNERABLE / INCONCLUSIVE / REFUSED + write a signed prove-certificate")
    # only --prove mode exists (downgrade resistance): without it the verb refuses (no silent weaker mode)
    prem.add_argument("--prove", action="store_true",
                      help="run the signed, four-state LIVE remediation proof (REQUIRED — the only mode). There "
                           "is deliberately NO weaker/unsigned mode.")
    # finding source (EXACTLY one) — a raw-JSON finding is never accepted (mirrors `vigil patch`)
    prem.add_argument("--from-spine", default="",
                      help="an engagement slug: rebuild a confirmed fact from {slug}.spine under --base-dir "
                           "after a fail-closed integrity audit. Use --finding-ref to disambiguate.")
    prem.add_argument("--finding-envelope", default="",
                      help="a signed inert finding envelope: its m-of-n governance signature is verified with "
                           "vigil_core under an OWNER-signed delegation. Needs --owner-pubkey, --delegation, "
                           "--scope.")
    prem.add_argument("--owner-pubkey", default="",
                      help="the pinned owner PUBLIC key (base64) — the delegation trust anchor (--finding-envelope)")
    prem.add_argument("--delegation", default="",
                      help="an owner-signed offense-governance DelegationCert JSON file (--finding-envelope)")
    prem.add_argument("--scope", default="",
                      help="the engagement slug the envelope + delegation must cover (--finding-envelope); it is "
                           "also the charter the live target must be authorized under")
    prem.add_argument("--finding-ref", default="",
                      help="pick the FACT FROM THE SPINE by ref (--from-spine when the spine has >1 fact). "
                           "That is ALL it does: it can NEVER redirect which retained re-verifiable entry "
                           "drives the proof — that entry is selected by the TRUSTED finding's OWN ref — and "
                           "a value that disagrees with the trusted finding's own ref is REFUSED "
                           "(fail-closed), never honoured.")
    prem.add_argument("--base-dir", default=".vigil-live",
                      help="engagement home: holds {slug}.spine + vault + the STABLE governance key, and where "
                           "the prove-certificate is written (proofs/remediation-prove-<ref>.json)")
    prem.add_argument("--run-dir", default="",
                      help="the run dir holding proofs/reverifiable.json (the retained positive control); "
                           "default = --base-dir")
    prem.add_argument("--target-base-url", default="",
                      help="the LIVE target scheme+host(:port) to re-drive against, e.g. http://127.0.0.1:8080 "
                           "— MUST be authorized in the engagement charter scope (else REFUSED, fail-closed)")
    prem.set_defaults(func=_cmd_remediate)

    prr = sub.add_parser(
        "reprove",
        help="TRUTHENOVATION A2 — the CONTINUOUS RE-PROOF SERVICE: loop the four-state live re-proof over a "
             "provenance-grounded finding on a cadence, appending signed, witnessed ticks to the continuous "
             "attestation log so 'continuously re-proven' becomes an OPERATING property once its systemd "
             "timer is enabled on a host (until then: a deployable loop + oneshot/timer — a capability)")
    # cadence
    prr.add_argument("--once", action="store_true",
                     help="run ONE re-proof cycle and exit (the systemd oneshot the timer fires)")
    prr.add_argument("--cycles", type=int, default=None, metavar="N",
                     help="run N re-proof cycles then exit (bounded run; re-verifies the whole series at the end)")
    prr.add_argument("--interval", type=float, default=3600.0, metavar="SECS",
                     help="cadence between cycles (default 3600s); with neither --once nor --cycles the loop "
                          "runs FOREVER on this interval (the --interval daemon)")
    prr.add_argument("--log-dir", default="",
                     help="the continuous attestation log dir (default: <base-dir>/attestation-log)")
    # trusted finding source (EXACTLY one) — identical to `vigil remediate` (a raw-JSON finding is never taken)
    prr.add_argument("--from-spine", default="",
                     help="an engagement slug: rebuild a confirmed fact from {slug}.spine under --base-dir")
    prr.add_argument("--finding-envelope", default="",
                     help="a signed inert finding envelope (needs --owner-pubkey, --delegation, --scope)")
    prr.add_argument("--owner-pubkey", default="",
                     help="the pinned owner PUBLIC key (base64) — the delegation trust anchor (--finding-envelope)")
    prr.add_argument("--delegation", default="",
                     help="an owner-signed offense-governance DelegationCert JSON file (--finding-envelope)")
    prr.add_argument("--scope", default="",
                     help="the engagement slug the envelope + delegation must cover, and the charter the live "
                          "target must be authorized under (--finding-envelope)")
    prr.add_argument("--finding-ref", default="",
                     help="pick the FACT FROM THE SPINE by ref (--from-spine when the spine has >1 fact). It "
                          "can NEVER redirect which retained re-verifiable entry drives the proof (that is "
                          "selected by the TRUSTED finding's OWN ref), and a value that disagrees with the "
                          "trusted finding's own ref is REFUSED (fail-closed).")
    prr.add_argument("--base-dir", default=".vigil-live",
                     help="engagement home: holds {slug}.spine + vault + the STABLE governance key + the "
                          "self-witness key, and (by default) the attestation-log/ directory")
    prr.add_argument("--run-dir", default="",
                     help="the run dir holding proofs/reverifiable.json (the retained positive control); "
                          "default = --base-dir")
    prr.add_argument("--target-base-url", default="",
                     help="the LIVE target scheme+host(:port) to re-drive against each cycle — MUST be "
                          "authorized in the engagement charter scope (else REFUSED, fail-closed)")
    prr.set_defaults(func=_cmd_reprove)

    pw = sub.add_parser(
        "witness",
        help="TRUTHENOVATION A3 — the deployable loopback witness co-sign service: `witness serve --port P "
             "--key K` runs ONE independently-keyed witness process (co-signs an append-only checkpoint "
             "series, REFUSES a fork); `witness submit --endpoints … --checkpoint C` fans a checkpoint out to "
             "N witnesses + gathers the co-signatures (surfacing refusals). A third party can run a witness "
             "standalone. Sovereign-safe; NOT witnessed-by-independent-parties (a capability, not production).")
    pw.add_argument("witness_argv", nargs=argparse.REMAINDER,
                    help="serve --host --port --key [--key-id] | submit --endpoints --checkpoint [--out]")

    pfw = sub.add_parser(
        "floor",
        help="C-S4 offense anti-rollback floor <-> witnessed checkpoint anchor: `floor witness --log-dir D "
             "--retain P` emits+retains a GOVERNANCE-signed witnessed checkpoint OFF-BOX; `floor "
             "verify-witnessed --log-dir D --external P …` REQUIRES the local head+high-water floor to be "
             "at/above the HIGHEST retained one (catches a same-host head+floor co-rewrite / stripped floor).")
    pfw.add_argument("action", choices=["witness", "verify-witnessed"])
    pfw.add_argument("--log-dir", required=True,
                     help="offense attestation-log dir holding head.json + highwater.json")
    pfw.add_argument("--base-dir", default=".vigil-live",
                     help="offense engine home (holds the sealed offense GOVERNANCE key that co-signs)")
    pfw.add_argument("--scope", required=True, help="engagement slug the witnessed checkpoint is bound to")
    pfw.add_argument("--retain", default="",
                     help="(witness) OFF-BOX path to persist the witnessed checkpoint the verifier retains")
    pfw.add_argument("--external", action="append", default=[],
                     help="(verify-witnessed) an OFF-BOX retained witnessed checkpoint (path or '-'); "
                          "repeatable — the HIGHEST valid one anchors")
    pfw.add_argument("--watch", action="store_true",
                     help="(witness, W7-5) run the emitter on a CADENCE instead of once — re-emits + re-pushes "
                          "the off-box anchor each cycle so it never goes stale; alarms if it does. This is "
                          "what the vigil-checkpoint.timer runs (`--watch --cycles 1`).")
    pfw.add_argument("--interval", type=float, default=900.0,
                     help="(witness --watch) seconds between emit cycles (default 900 = 15 min)")
    pfw.add_argument("--cycles", type=int, default=0,
                     help="(witness --watch) number of cycles (0 = forever; the timer passes 1)")
    pfw.add_argument("--heartbeat", default="",
                     help="(witness --watch) path for the emitter dead-man heartbeat (default: alongside "
                          "--retain)")
    pfw.set_defaults(func=_cmd_floor_witness)
    pw.set_defaults(func=_cmd_witness)

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

    # W9-5 — SECURE per-host co-signer provisioning + production multi-signer default.
    penr = sub.add_parser(
        "enroll-cosigner",
        help="(W9-5) PHASE 1 on a signer's OWN host: generate its destruction key locally + emit a PUBLIC "
             "enrolment request (pubkey + proof-of-possession); the private key never leaves this host")
    penr.add_argument("--key-id", required=True, help="this signer's key id (e.g. owner, worker1)")
    penr.add_argument("--name", default="", help="human-readable signer name (default: the key id)")
    penr.add_argument("--key-out", default="",
                      help="path for the PRIVATE key (0600, O_EXCL; default <key-id>.destruction.key) — keep it here")
    penr.add_argument("--out", default="",
                      help="path for the PUBLIC enrolment request (default <key-id>.enrollment.json) — send this")
    penr.add_argument("--owner-id", default="owner",
                      help="which key id is the owner (only affects the printed hint)")
    penr.set_defaults(func=_cmd_enroll_cosigner)

    pasm = sub.add_parser(
        "assemble-destruction",
        help="(W9-5) PHASE 2 on the MINTING box: assemble the m-of-n trust root from PUBLIC enrolment requests "
             "(verifies every proof-of-possession; no private key on this box)")
    pasm.add_argument("--base-dir", default=".vigil-live",
                      help="where the PUBLIC trust root is written (shared with `vigil patch`)")
    pasm.add_argument("--enrollment", action="append", default=[],
                      help="a signer as key_id=/path/to/enrollment.json (repeatable; PUBLIC material only). "
                           "Must include the owner.")
    pasm.add_argument("--threshold", type=int, required=True,
                      help="m in m-of-n — how many signers must sign. Under VIGIL_POSTURE=production must be >=2")
    pasm.add_argument("--owner-id", default="owner", help="the mandatory owner signer's key id")
    pasm.set_defaults(func=_cmd_assemble_destruction)

    preq = sub.add_parser(
        "request-destruction",
        help="(W9-5) coordinator: mint the SHARED unsigned authorization each signer signs detached on its own host")
    preq.add_argument("--action-id", required=True, help="the pr-<remediation_id> printed by the dry run")
    preq.add_argument("--slug", required=True, help="the engagement_slug printed by the dry run")
    preq.add_argument("--target", required=True, help="the target repo printed by the dry run (must match)")
    preq.add_argument("--base-dir", default=".vigil-live", help="where authorization-request.json is written")
    preq.add_argument("--out", default="", help="output path (default: <base-dir>/authorization-request.json)")
    preq.add_argument("--window-s", type=float, default=600.0,
                      help="validity window in seconds (single-use; total window must stay <=900s)")
    preq.set_defaults(func=_cmd_request_destruction)

    psgn = sub.add_parser(
        "sign-destruction",
        help="(W9-5) per-signer on its OWN host: sign the shared request DETACHED with this host's key "
             "(owner via VIGIL_DESTRUCTION_OWNER_KEY, a co-signer via --key-file)")
    psgn.add_argument("--request", required=True, help="the authorization-request.json from `vigil request-destruction`")
    psgn.add_argument("--key-id", required=True, help="this signer's key id (must match its enrolment)")
    psgn.add_argument("--key-file", default="",
                      help="co-signer PRIVATE key file (read from FILE, never argv). Omit for the owner "
                           "(read from VIGIL_DESTRUCTION_OWNER_KEY).")
    psgn.add_argument("--out", default="", help="output path for the detached signature (default <key-id>.sig.json)")
    psgn.set_defaults(func=_cmd_sign_destruction)

    pcmb = sub.add_parser(
        "combine-destruction",
        help="(W9-5) coordinator: combine per-host detached signatures into the single-use signed authorization")
    pcmb.add_argument("--request", required=True, help="the same authorization-request.json the signers signed")
    pcmb.add_argument("--signature", action="append", default=[],
                      help="a detached signature file (repeatable; key_id=/path or just /path)")
    pcmb.add_argument("--base-dir", default=".vigil-live", help="where signed-authorization.json is written")
    pcmb.add_argument("--out", default="", help="output path (default: <base-dir>/signed-authorization.json)")
    pcmb.add_argument("--target", default="", help="(display only) the target repo, for the printed next-step")
    pcmb.set_defaults(func=_cmd_combine_destruction)

    # A2 — per-action owner approval for offense tools (the DEFAULT high-assurance path once an authority is
    # provisioned). Three sub-actions: provision-authority | list | sign.
    pap = sub.add_parser(
        "approve",
        help="per-action owner approval for offense tools (provision-authority | list | sign)")
    pap_sub = pap.add_subparsers(dest="approve_cmd", required=True)

    papp = pap_sub.add_parser("provision-authority",
                              help="mint + persist the owner approval authority (public key under --base-dir)")
    papp.add_argument("--base-dir", default=".vigil-live")
    papp.add_argument("--key-id", default="owner", help="the owner signer's key id")
    papp.add_argument("--force", action="store_true", help="re-provision (ROTATES the key; invalidates old tokens)")
    papp.set_defaults(func=_cmd_approve_provision)

    papl = pap_sub.add_parser("list", help="list pending per-action approval requests")
    papl.add_argument("--base-dir", default=".vigil-live")
    papl.set_defaults(func=_cmd_approve_list)

    paps = pap_sub.add_parser("sign", help="sign ONE pending action with the owner key (VIGIL_APPROVAL_OWNER_KEY)")
    paps.add_argument("--base-dir", default=".vigil-live")
    paps.add_argument("--request-id", required=True, help="the request_id from `vigil approve list`")
    paps.add_argument("--ttl", type=float, default=300.0,
                      help="validity window in seconds (single-use; capped at the 900s dead-man's-switch)")
    paps.add_argument("--key-id", default="owner", help="the owner signer's key id (must match provisioning)")
    paps.set_defaults(func=_cmd_approve_sign)

    ppe = sub.add_parser("proof-export",
                         help="assemble a client-verifiable proof bundle from a run's oracle-confirmed FACTs "
                              "(offline, zero-trust re-verify)")
    ppe.add_argument("--run-dir", default="", help="the run dir to export (else $VIGIL_PROOF_RUN_DIR)")
    ppe.add_argument("--out", default="", help="output bundle dir (default <run-dir>/proof-bundle)")
    ppe.add_argument("--slug", default="engagement", help="engagement slug stamped into the certificates")
    ppe.add_argument("--base-dir", default="", help="governance-key home (stable signer); default = run dir")
    ppe.set_defaults(func=_cmd_proof_export)

    pdo = sub.add_parser("dossier",
                         help="compile EVERYTHING a run produced into ONE self-contained, tamper-evident "
                              ".zip (reports + exports + offline proof bundle + scrubbed log + index.html); "
                              "or --session <id> to package a whole session's runs + chat + graph + threads")
    pdo.add_argument("--session", default="",
                     help="package a whole SESSION by id — its run(s) (each an independently re-verifiable "
                          "runs/<run>/dossier.zip), the chat transcript, the per-session graph partition "
                          "pointer, and the open threads — into ONE signed handoff zip (resolves via the "
                          "console session registry; ignores --run-dir)")
    pdo.add_argument("--run-dir", default="", help="the run dir to compile (else $VIGIL_PROOF_RUN_DIR)")
    pdo.add_argument("--out", default="", help="output .zip path (default <run-dir>/dossier.zip)")
    pdo.add_argument("--slug", default="engagement", help="engagement slug stamped into the dossier")
    pdo.add_argument("--label", default="",
                     help="a HUMAN title for the engagement (e.g. \"Ministry of Health — Q3 external "
                          "review\"), shown alongside the machine run id in the readable documents. "
                          "Presentation only: it never reaches a certificate or any signed claim about "
                          "a finding, so a re-labelled dossier still verifies. Default: the slug.")
    pdo.add_argument("--base-dir", default="", help="governance-key home (stable signer); default = run dir")
    pdo.add_argument("--terminal-history", default="",
                     help="OPTIONAL path to the governed terminal-history.jsonl (the operator's signed "
                          "terminal.run records) to include as logs/terminal-transcript.jsonl; default = a "
                          "terminal-history.jsonl next to the run dir if present")
    pdo.add_argument("--timestamp", default="",
                     help="pin the generation timestamp stamped into the readable documents "
                          "(default: the current time in UTC)")
    pdo.add_argument("--no-timestamp", action="store_true",
                     help="record NO generation time, for a byte-reproducible dossier (two builds "
                          "over the same run then produce an identical MANIFEST)")
    pdo.set_defaults(func=_cmd_dossier)

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
    pu.add_argument("--with-telemetry", action="store_true",
                    help="also run the live assurance/metrics collector (G2): a sidecar that tails the signed "
                         "spine and materializes a continuous fact/lead/refusal/tool snapshot the UI reads. "
                         "OFF by default. Read-only, loopback, no egress — a pure projection of the spine.")
    pu.add_argument("--telemetry-interval", type=int, default=15,
                    help="with --with-telemetry: seconds between spine snapshots (default 15)")
    pu.add_argument("--services", action="store_true",
                    help="also bring up the docker egress-gateway topology (create the networks + gateway "
                         "container if none exist; idempotent). The EGRESS-GATE leg fails CLOSED: if it does "
                         "not come up the run is REFUSED (no silent downgrade to ungated egress) unless you "
                         "pass --allow-ungated-egress. The root-services leg (qdrant/…) stays best-effort.")
    pu.add_argument("--allow-ungated-egress", action="store_true",
                    help="with --services: DOWNGRADE the egress gate from fail-closed to a loud warning — "
                         "if the gateway topology fails to come up, continue anyway with the sandbox UNGATED "
                         "(a default route to the operator LAN / a third party / 169.254.169.254 — FATAL-1). "
                         "Off by default; only pass it when you have accepted running without the egress gate.")
    pu.add_argument("--charter-slug", default="",
                    help="with --services: the signed-charter slug the egress gateway enforces as its L7 "
                         "scope. Falls back to $VIGIL_GATEWAY_CHARTER_SLUG. Unset ⇒ the gateway fail-closes "
                         "(no scope ⇒ no gate); set it to the active engagement's charter to gate real egress.")
    # ---- HA / clustering: a PROXY-ONLY read tier that federates to REMOTE backends -----------------
    pu.add_argument("--proxy-only", action="store_true",
                    help="run ONLY the reverse proxy — do NOT spawn the sovereign cockpit or the offense "
                         "backends. Federate to the REMOTE backends named by --sovereign-addr / "
                         "--offense-console-addr / --offense-api-addr. This is the HA read/proxy tier: N "
                         "stateless replicas in front of ONE central sovereign writer (a second cockpit "
                         "would be a second signed-spine writer = a fork). See docs/architecture/HA-PROFILE.md.")
    pu.add_argument("--sovereign-addr", default=os.environ.get("VIGIL_SOVEREIGN_ADDR", ""),
                    help="with --proxy-only: the sovereign cockpit host:port to federate /sovereign/* to "
                         "(default 127.0.0.1:8733; env VIGIL_SOVEREIGN_ADDR). A k8s Service name is fine, "
                         "e.g. vigil-sovereign:8733.")
    pu.add_argument("--offense-console-addr", default=os.environ.get("VIGIL_OFFENSE_CONSOLE_ADDR", ""),
                    help="with --proxy-only: the offense console host:port for the /offense/* read+SSE "
                         "plane (default 127.0.0.1:8787; env VIGIL_OFFENSE_CONSOLE_ADDR).")
    pu.add_argument("--offense-api-addr", default=os.environ.get("VIGIL_OFFENSE_API_ADDR", ""),
                    help="with --proxy-only: the offense gated-api host:port for /offense/api/v1/* "
                         "(default 127.0.0.1:8799; env VIGIL_OFFENSE_API_ADDR).")
    pu.set_defaults(func=_cmd_up)

    psvc = sub.add_parser("services",
                          help="docker bring-up: create the egress gateway + qdrant/neo4j/otel services IF "
                               "NONE EXIST (idempotent, re-runnable)")
    psvc_sub = psvc.add_subparsers(dest="services_action", required=True)
    psu = psvc_sub.add_parser("up", help="create/start the gateway + root services if absent (idempotent)")
    psu.add_argument("--compose", default="", help="gateway compose file (default infra/docker/docker-compose.yml)")
    psu.add_argument("--no-build", action="store_true", help="do not build the gateway image (assume it exists)")
    psu.add_argument("--charter-slug", default="",
                     help="the signed-charter slug the gateway enforces as its L7 scope (falls back to "
                          "$VIGIL_GATEWAY_CHARTER_SLUG; unset ⇒ the gateway fail-closes — no scope, no gate)")
    psu.add_argument("--with-graph", action="store_true", help="also bring up Neo4j (the knowledge graph)")
    psu.add_argument("--with-observability", action="store_true", help="also bring up the otel-collector")
    psu.add_argument("--all", action="store_true", help="bring up ALL services (gateway + qdrant + neo4j + otel)")
    pssg = psvc_sub.add_parser("status", help="show which networks / image / container already exist")
    pssg.add_argument("--compose", default="")
    psdn = psvc_sub.add_parser("down", help="stop + remove the gateway container (networks are left in place)")
    psdn.add_argument("--compose", default="")
    psr = psvc_sub.add_parser("render", help="(re)write the docker-compose file for the gateway topology")
    psr.add_argument("--out", default="", help="output path (default infra/docker/docker-compose.yml)")
    psr.add_argument("--charter-slug", default="", help="charter slug to bake into the compose scope")
    psvc.set_defaults(func=_cmd_services)

    pdoc = sub.add_parser("doctor",
                          help="read-only readiness report: prerequisites (binaries, both venvs, writable "
                               "dirs), UI ports, and which docker services are up (create the rest: `vigil "
                               "services up`). Exits non-zero on a hard prerequisite gap.")
    pdoc.add_argument("--json", action="store_true", help="emit the raw report as JSON")
    pdoc.set_defaults(func=_cmd_doctor)

    pvi = sub.add_parser("verify-integrity",
                         help="continuously verify the spine hash-chain integrity property (chain, "
                              "signed-head freshness, anti-rollback floor, clock skew). One audit by "
                              "default; --watch runs it on a cadence and alarms on failure. Exits non-zero "
                              "on any integrity violation.")
    pvi.add_argument("--home", default=None, help="spine home to verify (default: $SIGIL_HOME or ~/.sigil)")
    pvi.add_argument("--watch", action="store_true", help="run periodically instead of once")
    pvi.add_argument("--cycles", type=int, default=0, help="with --watch: cycles (0 = forever)")
    pvi.add_argument("--interval", type=float, default=300.0, help="with --watch: seconds between cycles")
    pvi.add_argument("--json", action="store_true", help="emit the report as JSON")
    pvi.set_defaults(func=_cmd_verify_integrity)

    pal = sub.add_parser("alerts",
                         help="heartbeat staleness alarms for every HA/scheduled unit (backup, off-host "
                              "push, recovery drill, HA mirror-sync, integrity, posture, reprove). Absent or "
                              "stale heartbeat => staleness alarm (fail-closed); a failed run => a failure "
                              "alarm. Push-based (VIGIL_ALERT_WEBHOOK_URL / VIGIL_ALERT_EXEC) with a durable "
                              "local log + delivery dead-man. --status is read-only; exits non-zero on alarm.")
    pal.add_argument("--state-dir", default=None,
                     help="heartbeat state dir (default: $VIGIL_ALERT_STATE_DIR or ~/.local/state/vigil/"
                          "unit-heartbeats)")
    pal.add_argument("--status", action="store_true", dest="status_only",
                     help="read-only: print each unit's current status, fire no alarms")
    pal.add_argument("--once", action="store_true", help="run exactly one cycle and exit (the default; the "
                     "systemd oneshot the timer fires makes it explicit)")
    pal.add_argument("--watch", action="store_true", help="run periodically instead of once")
    pal.add_argument("--cycles", type=int, default=0, help="with --watch: cycles (0 = forever)")
    pal.add_argument("--interval", type=float, default=300.0, help="with --watch: seconds between cycles")
    pal.add_argument("--require-push", action="store_true",
                     help="fail-closed: alarm if NO push destination is configured")
    pal.add_argument("--json", action="store_true", help="emit the summary/status as JSON")
    pal.set_defaults(func=_cmd_alerts)

    puh = sub.add_parser("unit-heartbeat",
                         help="record that a scheduled unit ran (systemd ExecStopPost hook). Reads "
                              "$SERVICE_RESULT from the env (success => ok); the alerts monitor reads it.")
    puh.add_argument("unit", help="the systemd unit id, e.g. vigil-backup.service (use %%n in the unit file)")
    puh.add_argument("--result", default="", help="systemd $SERVICE_RESULT (success => ok)")
    puh.add_argument("--ok", action="store_true", help="force ok (overrides --result)")
    puh.add_argument("--failed", action="store_true", help="force failed (overrides --result)")
    puh.add_argument("--detail", default="", help="optional free-text detail recorded in the heartbeat")
    puh.add_argument("--state-dir", default=None, help="heartbeat state dir (see `vigil alerts --help`)")
    puh.set_defaults(func=_cmd_unit_heartbeat)

    ptel = sub.add_parser("telemetry",
                          help="live assurance/metrics collector over the signed spine (G2): write a "
                               "fact/lead/refusal/tool snapshot to --out every --interval seconds (or --once). "
                               "Read-only projection; started for you by `vigil up --with-telemetry`.")
    ptel.add_argument("--out", required=True, help="snapshot JSON path (atomically rewritten each tick)")
    ptel.add_argument("--interval", type=float, default=15.0, help="seconds between snapshots (default 15)")
    ptel.add_argument("--once", action="store_true", help="write one snapshot and exit")
    ptel.set_defaults(func=_cmd_telemetry)

    pdn = sub.add_parser("down", help="CONTAIN a running `vigil up`: stop+disable the systemd unit so it "
                                      "does not restore, then kill the backends + proxy")
    pdn.add_argument("--base-dir", default=".vigil-live",
                     help="engagement home holding the ui/pids file written by `vigil up`")
    pdn.set_defaults(func=_cmd_down)

    pupg = sub.add_parser("upgrade", help="automated crash-safe data migration of the sovereign spine: "
                                          "backup -> verify -> migrate -> verify -> report, with ROLLBACK "
                                          "on any failure (runs `sigil upgrade` in the sovereign venv)")
    pupg.add_argument("--check", action="store_true",
                      help="only report whether a migration is needed (exit 3 if it is); mutate nothing")
    pupg.add_argument("--no-backup", dest="no_backup", action="store_true",
                      help="skip the backup+rollback frame (disposable store only; still refuses a "
                           "non-verifying spine)")
    pupg.set_defaults(func=_cmd_upgrade)

    ppan = sub.add_parser("panic", help="EMERGENCY HARD-STOP: trip every engagement's kill-switch (gate-"
                                        "level DENY, persistent) then mask+stop the command unit, "
                                        "stop+disable EVERY cadence sidecar timer/unit (no catch-up "
                                        "replay), kill the offense processes, and verify containment "
                                        "held. Clearing is a deliberate operator act.")
    ppan.add_argument("--base-dir", default=".vigil-live",
                      help="engagement home holding the ui/pids file written by `vigil up`")
    ppan.add_argument("--reason", default="",
                      help="reason recorded in every kill-switch (default: 'vigil panic')")
    ppan.set_defaults(func=_cmd_panic)

    pes = sub.add_parser("emergency-stop", help="enter RESTRICTED MODE — a safe landing state between "
                                               "fully-operational and `vigil panic`: trips every "
                                               "kill-switch (the existing gate then REFUSES every "
                                               "target-touching/mutating action) but leaves the process "
                                               "UP so diagnosis + evidence export still work. Recorded on "
                                               "the chain; survives restart.")
    pes.add_argument("--base-dir", default=".vigil-live",
                     help="engagement home holding the restricted-mode transitions ledger")
    pes.add_argument("--reason", default="", help="reason recorded on the chain and in each kill-switch")
    pes.add_argument("--leave", action="store_true",
                     help="record a deliberate LEAVE transition (clearing kill-switches stays separate)")
    pes.add_argument("--status", action="store_true", help="print the current mode and exit")
    pes.set_defaults(func=_cmd_emergency_stop)

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

    pt = sub.add_parser(
        "terminal",
        help="run a governed LOCAL read/inspect command through the gate (terminal.run classifies A2 → QUEUES "
             "for approval, never auto; --approve to run). Local, non-network, read-only allowlist only.")
    pt.add_argument("command", nargs="+",
                    help="the local read/inspect command (allowlisted binaries only: ls/cat/head/tail/grep/find/"
                         "stat/wc/… — no network, no writers, no interpreters). QUOTE a command that contains "
                         "dashes/flags so they aren't parsed as options, e.g. `vigil terminal \"find . -name x\" "
                         "--approve` (or put the options first: `vigil terminal --approve -- find . -name x`)")
    pt.add_argument("--approve", action="store_true",
                    help="operator approval — upgrade the A2 queue to allow (the SAME wiring approval path the "
                         "engine uses). Without it the command QUEUES and does not run.")
    pt.add_argument("--base-dir", default=".vigil-live",
                    help="engine home (holds the signed-authority gate + the sealed spine signer)")
    pt.add_argument("--slug", default="loopback", help="loopback engagement slug for the gate authority")
    pt.set_defaults(func=_cmd_terminal)

    psb = sub.add_parser(
        "sandbox",
        help="run an ARBITRARY command inside a network-isolated, workspace-confined bwrap sandbox "
             "(sandbox.exec classifies A3 → QUEUES for approval, never auto; --approve to run). Safe by KERNEL "
             "isolation: no network egress, writes confined to <base-dir>/sandbox-workspace. Needs bwrap.")
    psb.add_argument("command", nargs="+",
                     help="the command to run inside the sandbox (a full shell — pipes/redirects/subshells are "
                          "fine, it is isolated). QUOTE it so flags aren't parsed as options, e.g. "
                          "`vigil sandbox \"echo hi > out.txt; cat out.txt\" --approve`")
    psb.add_argument("--approve", action="store_true",
                     help="operator approval — upgrade the A3 queue to allow (the SAME wiring approval path). "
                          "Without it the command QUEUES and does not run.")
    psb.add_argument("--base-dir", default=".vigil-live",
                     help="engine home (holds the signed-authority gate + the sealed spine signer + the "
                          "sandbox-workspace)")
    psb.add_argument("--slug", default="loopback", help="loopback engagement slug for the gate authority")
    psb.add_argument("--workspace", default="",
                     help="run in THIS existing directory (e.g. a cloned codebase) instead of the default "
                          "<base-dir>/sandbox-workspace — still the ONLY writable path inside the no-net box "
                          "(D3: run a repo's tests). Must be an existing directory.")
    psb.set_defaults(func=_cmd_sandbox)

    pbk = sub.add_parser(
        "backup",
        help="off-box backup of BOTH planes → two SEPARATE encrypted files (offense in-venv + sovereign via a "
             "sigil subprocess; NEVER a merged archive — that would be a FATAL-2 boundary breach) + a MANIFEST")
    pbk.add_argument("--out", default="",
                     help="destination root for the timestamped backup dir (default: ~/vigil-backups)")
    pbk.add_argument("--base-dir", default=".vigil-live", help="offense engine home to back up")
    pbk.add_argument("--crucible-root", dest="crucible_root", default="",
                     help="CRUCIBLE root holding .blackboard/.console (default: $CRUCIBLE_ROOT or the in-repo v2)")
    grp = pbk.add_mutually_exclusive_group()
    grp.add_argument("--sovereign-only", dest="sovereign_only", action="store_true",
                     help="back up ONLY the sovereign plane (sigil subprocess)")
    grp.add_argument("--offense-only", dest="offense_only", action="store_true",
                     help="back up ONLY the offense plane (this venv)")
    pbk.add_argument("--push", default="",
                     help="TRUE off-HOST replication (opt-in): after a successful backup, copy the ENCRYPTED "
                          "parts + MANIFEST + its signature sidecar to a transport backend AND verify them at "
                          "the destination. A bare path or local:<path> uses the local-directory backend (a "
                          "mounted remote FS / removable disk / test dir); rsync:[user@]host:path or "
                          "rsync://host/module/path uses the real rsync backend (over ssh / an rsync daemon); "
                          "still-unbuilt schemes (scp://, s3://) error with the contract to implement. The push "
                          "then re-reads the copy AT THE DESTINATION and FAILS CLOSED (non-zero exit) if a "
                          "truncated/corrupted/tampered copy does not hash-match what was sent. Only ciphertext "
                          "is transported — no plaintext leaves the host. Needs network (run via "
                          "vigil-backup-push.service, PrivateNetwork=no), unlike the air-gapped local timer.")
    pbk.add_argument("--prune", action="store_true", help="after the backup, prune old backups per the policy")
    pbk.add_argument("--keep-days", dest="keep_days", type=int, default=None,
                     help="retention: keep backups within N days (with --prune)")
    pbk.add_argument("--keep-last", dest="keep_last", type=int, default=None,
                     help="retention: keep the last N backups (with --prune)")
    pbk.add_argument("--passphrase-env", dest="passphrase_env", default="VIGIL_BACKUP_PASSPHRASE",
                     help="env var holding the backup passphrase (never passed on argv; default "
                          "VIGIL_BACKUP_PASSPHRASE)")
    pbk.add_argument("--reset-trust-anchor", dest="reset_trust_anchor", action="store_true",
                     help="RE-ESTABLISH the host-local backup trust anchor under the CURRENT governance key. "
                          "Backup normally REFUSES when the recorded anchor names a different key (a rotation "
                          "or a different engine home); pass this — the deliberate, logged rotation step — to "
                          "adopt the new key as the trusted one. The monotonic backup_seq is preserved. After "
                          "a reset, a default restore on this host pins the NEW key.")
    pbk.set_defaults(func=_cmd_backup)

    prs = sub.add_parser(
        "restore",
        help="restore a two-plane `vigil backup` dir — refuses an UNSIGNED manifest, and AUTHENTICATES it by "
             "default against the host trust anchor (an explicit --expect-governance-pubkey overrides; with no "
             "anchor + no pin, production refuses fail-closed, non-production is integrity-only + a warning); "
             "refuses a rollback to an older backup; then verifies each plane part's sha256 before invoking "
             "either leg (fail-closed, two-file boundary; the sovereign leg is a sigil subprocess)")
    prs.add_argument("src", help="the timestamped backup dir (holding MANIFEST.json + MANIFEST.sig.json + the "
                                 "encrypted parts)")
    prs.add_argument("--base-dir", default=".vigil-live", help="offense base_dir to restore INTO (fresh)")
    prs.add_argument("--crucible-root", dest="crucible_root", default="",
                     help="CRUCIBLE root to restore .blackboard/.console into (default: $CRUCIBLE_ROOT or in-repo)")
    prs.add_argument("--sigil-home", dest="sigil_home", default="",
                     help="a FRESH SIGIL_HOME dir to restore the sovereign plane into (required for that leg)")
    prs.add_argument("--expect-governance-pubkey", dest="expect_governance_pubkey", default="",
                     help="out-of-band AUTHENTICITY pin: the expected offense-governance pubkey (base64). When "
                          "set it ALWAYS overrides the host trust anchor, and BOTH the orchestrator "
                          "MANIFEST.json signature AND the inner offense backup manifest MUST be signed by it — "
                          "else restore refuses. This is the way to authenticate an OFF-HOST recovery, where no "
                          "trust anchor exists locally. When it is NOT set, the DEFAULT is to pin against the "
                          "governance key recorded in this host's trust anchor (an authenticated restore); if "
                          "there is no anchor either, production (VIGIL_POSTURE=production) refuses fail-closed "
                          "and non-production falls back to integrity-only with a loud warning (which does NOT "
                          "authenticate the signer).")
    prs.add_argument("--force", action="store_true",
                     help="REPLACE existing state at the destination. The base-dir is a WHOLE-tree capture, so "
                          "--force whole-replaces it (only re-creatable transients are dropped). The "
                          "crucible-root and sigil-home are SUBSET captures: --force replaces ONLY the captured "
                          "units (crucible: .blackboard/store.sqlite + .console/runs; sigil: spine/floor/"
                          "security-manifest/warden) and never touches un-captured data OUTSIDE those units (the "
                          "CRUCIBLE code, sigil vector/config caches). A captured unit is replaced WHOLESALE, "
                          "so proof created after the backup that lives inside one (e.g. a new .console/runs "
                          "engagement) is dropped by a restore (the DR-snapshot semantic). Without --force, "
                          "restore refuses when a captured unit already exists rather than overwrite it. The "
                          "replacement is staged + verified first and swapped in atomically per unit (crash-safe).")
    grp2 = prs.add_mutually_exclusive_group()
    grp2.add_argument("--sovereign-only", dest="sovereign_only", action="store_true",
                      help="restore ONLY the sovereign plane")
    grp2.add_argument("--offense-only", dest="offense_only", action="store_true",
                      help="restore ONLY the offense plane")
    prs.add_argument("--passphrase-env", dest="passphrase_env", default="VIGIL_BACKUP_PASSPHRASE",
                     help="env var holding the backup passphrase (never passed on argv)")
    prs.add_argument("--allow-rollback", dest="allow_rollback", action="store_true",
                     help="deliberately restore a backup OLDER than the latest recorded in the host trust "
                          "anchor. Restore normally refuses this (a rollback/substitution to a genuine older "
                          "signed backup, which the signature and the pin do not catch); pass this to override "
                          "when you are intentionally rolling back (e.g. the latest backup is unusable). "
                          "Reintroduces pre-revocation/pre-patch state — used loudly, logged.")
    prs.set_defaults(func=_cmd_restore)

    ppos = sub.add_parser(
        "posture",
        help="Certificate of Non-Exploitability — mint (attest), verify offline, or serve a signed posture "
             "bundle. Sub-verbs: attest --out … | verify --bundle … | endpoint --bundle … "
             "(run `vigil posture attest -h` etc. for each).")
    ppos.add_argument("posture_args", nargs=argparse.REMAINDER,
                      help="the posture sub-verb and its flags (passed through to the posture sub-CLI verbatim)")
    ppos.set_defaults(func=_cmd_posture)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # `--version` (W4-2, #442) short-circuits BEFORE the passthrough intercept, argparse, and the
    # install-manifest gate: an operator must be able to ask a fresh or degraded install what it is. The
    # shared vigil_core.build_info is sovereign-safe (vigil_core only — no framework/sigil), so this stays
    # boundary-clean.
    if argv and argv[0] in ("--version", "-V"):
        from vigil_core.build_info import version_line
        print(version_line("vigil"))
        return 0
    # S1 control plane: a subsystem verb forwards to that subsystem's console-script, EXEC'd in its OWN
    # venv (sovereign or offense) — a separate process in the correct trust domain, never co-loaded here.
    # This intercept runs BEFORE argparse so all remaining args (incl. the sub-CLI's own flags) pass through
    # opaquely. `dispatch` is pure-stdlib and imports no subsystem, so this path stays boundary-clean.
    from .dispatch import PASSTHROUGH_VERBS, dispatch
    if argv and argv[0] in PASSTHROUGH_VERBS:
        return dispatch(argv[0], argv[1:])
    args = build_parser().parse_args(argv)
    # W5-4 (#448): fail-closed install-manifest gate for the offense `.vigil-live` data dir — write-if-absent
    # (fresh install, no operator action) + verify-if-present (refuse-newer / fail closed on corruption). Runs
    # only for native (argparse) verbs; a PASSTHROUGH verb is handled above and runs the target subsystem's
    # OWN gate. Never crosses FATAL-2: `install_gate` imports only vigil_core + stdlib.
    from .install_gate import ensure_operable_or_exit
    from .strix_runtime import resolve_base_dir
    _gate_rc = ensure_operable_or_exit(
        resolve_base_dir(getattr(args, "base_dir", None)), getattr(args, "command", "") or "")
    if _gate_rc is not None:
        return _gate_rc
    try:
        return int(args.func(args))
    except Exception as exc:  # noqa: BLE001 — the CLI surfaces a clean error, never a traceback dump
        print(f"vigil: error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
