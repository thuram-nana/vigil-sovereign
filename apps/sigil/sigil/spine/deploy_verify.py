"""The deploy-verify pipeline with rollback proof (W11-8, #489).

The defect this closes: there was no deployment/rollback VERIFICATION. W4-2 (#442) shipped the release
workflow, W5-5/W5-7 (#449/#451) shipped the crash-safe migrate/rollback orchestrator + the N-1 -> N
upgrade/rollback HARNESS, and ``make smoke`` shipped a boundary+CLI smoke check — but nothing tied them
into the property an operator actually needs at a deploy: **deploy a build, run a post-deploy smoke, and if
the smoke fails, AUTOMATICALLY roll back to the prior version and PROVE the prior version is restored with
its owner signature and every record intact.** ``make smoke`` was never invoked by any workflow, so a broken
smoke could ship unnoticed; there was no negative control proving a broken deployment is actually caught.

This module is that pipeline, modelled at the level where it is falsifiable on a PR runner. It REUSES
#451's machinery rather than re-implementing it:

  * a **deployment** is modelled as an upgrade of a live, owner-signed data plane — ``build_n_minus_1_
    signed_spine`` stands up the *prior* (currently-deployed) version, and the real ``upgrade()``
    orchestrator "deploys" the new build (it takes + verifies its own pre-deploy backup, which is the
    rollback target);
  * the **post-deploy smoke** is a real, falsifiable health probe of the deployed data plane
    (:func:`spine_health_smoke` re-verifies the deployed store's owner signature + hash chain), OR any
    external smoke COMMAND run through :func:`run_smoke`, whose exit code is HONOURED (``ok`` is derived
    from the process return code and nothing else — the default command is ``make smoke``);
  * the **rollback** restores the prior version with ``restore_from_backup`` and RE-VERIFIES it: the
    original owner signature still anchors the restored store, the layout is back to the prior (legacy)
    shape, and the record count + sequence set match the prior version exactly.

## The falsifiable properties (what the required test turns on)

  1. a HEALTHY deployment passes post-deploy smoke and STANDS (no rollback);
  2. a deliberately-BROKEN deployment (its post-deploy smoke fails) is CAUGHT and AUTO-ROLLED-BACK, and the
     rollback restores the prior version with the owner signature + every record intact — the negative
     control, proving the pipeline is a real gate and not a rubber stamp;
  3. the smoke runner HONOURS the smoke command's exit code: a non-zero exit is a smoke FAILURE that drives
     the rollback, a zero exit is a pass (proven deterministically with a stand-in command, so the required
     PR job needs neither the built venvs nor ``make``).

## Honest scope (the split, per the programme doctrine)

The FAST, DETERMINISTIC core above is what runs on every PR (the required ``SIGIL governor gates (P7 ...)``
job runs the whole ``apps/sigil/tests/`` directory). It cannot build the two isolated venvs and run the REAL
``make smoke`` against a real stood-up system on a PR runner — that is the heavier variant, wired to the
scheduled/dispatch ``.github/workflows/deploy-verify.yml`` (honestly labelled, NOT a required check), which
runs the real ``make smoke`` THROUGH this module's :func:`run_smoke` (so its exit code is honoured) and then
drives this same harness. A true multi-host cloud/canary deploy is deferred until real staging
infrastructure exists; it is documented as such in ``docs/decisions/W11-8-deploy-verify-pipeline.md``.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from ..reuse import KeyPair, SignedChainHead, TrustRoot, sign_head
from .manifest import read_manifest
from .store import SpineStore
from .upgrade import restore_from_backup, upgrade
from .upgrade_harness import build_n_minus_1_signed_spine, verify_signed_spine

_OWNER_KEY_ID = "owner"


def _sign_deployed_head(store: SpineStore, keypair: KeyPair, slug: str) -> SignedChainHead:
    """Re-anchor the deployed store: the new build signs the store it now serves with the SAME owner key,
    so the post-deploy smoke verifies the deployed head over the deployed entries. Uses the same owner key
    id as ``build_n_minus_1_signed_spine`` so one trust root verifies both the prior and deployed heads."""
    return sign_head(store.entries(), engagement_slug=slug,
                     signers=[(_OWNER_KEY_ID, keypair.private_key_b64)])

# ====================================================================================================
# smoke — the post-deploy health check whose verdict is HONOURED
# ====================================================================================================
@dataclass(frozen=True)
class SmokeResult:
    """The outcome of one post-deploy (or post-rollback) smoke check. ``ok`` is the ONLY thing the
    pipeline acts on. For a COMMAND smoke, ``ok`` is derived solely from ``returncode == 0`` — that is what
    "the smoke's exit code is honoured" means concretely. ``phase`` is ``post-deploy`` or ``post-rollback``."""

    ok: bool
    detail: str
    phase: str = ""
    returncode: Optional[int] = None
    cmd: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeployContext:
    """What a smoke check is handed: where the deployed data plane lives (for a health probe) and where the
    repo is (for a command smoke). A smoke opens its OWN fresh ``SpineStore`` so it always reads what is on
    disk right now, never a stale in-memory handle."""

    data_path: Path
    head: SignedChainHead
    trust_root: TrustRoot
    phase: str
    repo_root: Optional[Path] = None


# A smoke is any callable that, given the deploy context, returns a SmokeResult.
Smoke = Callable[[DeployContext], SmokeResult]


def run_smoke(
    cmd: Sequence[str], *, cwd: Optional[Path] = None, env: Optional[dict] = None,
    timeout: int = 300, phase: str = "",
) -> SmokeResult:
    """Run a smoke COMMAND as a subprocess and HONOUR its exit code: ``ok`` is ``True`` IFF the process
    exits 0. This is the primitive that makes ``make smoke`` load-bearing — the caller cannot pass a
    non-zero exit off as a success. A missing executable or a timeout is a smoke FAILURE (fail-closed),
    never a silent pass."""
    argv = [str(c) for c in cmd]
    try:
        proc = subprocess.run(
            argv, cwd=str(cwd) if cwd else None, env=env,
            capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return SmokeResult(ok=False, detail=f"smoke command not found: {exc}", phase=phase,
                           returncode=None, cmd=tuple(argv))
    except subprocess.TimeoutExpired:
        return SmokeResult(ok=False, detail=f"smoke command timed out after {timeout}s", phase=phase,
                           returncode=None, cmd=tuple(argv))
    tail = (proc.stdout or "").strip().splitlines()[-1:] or (proc.stderr or "").strip().splitlines()[-1:]
    return SmokeResult(
        ok=(proc.returncode == 0), phase=phase, returncode=proc.returncode, cmd=tuple(argv),
        detail=f"exit {proc.returncode}" + (f": {tail[0]}" if tail else ""))


def spine_health_smoke(ctx: DeployContext) -> SmokeResult:
    """The default post-deploy smoke: a real, falsifiable HEALTH PROBE of the deployed data plane. It opens
    a fresh store over the deployed bytes and re-verifies the owner signature + hash chain
    (``verify_signed_spine``). A deployment that came up with a corrupted/torn store fails this — which is
    exactly what the broken-deployment negative control exercises."""
    store = SpineStore(str(ctx.data_path))
    ok, why = verify_signed_spine(store, ctx.head, ctx.trust_root)
    return SmokeResult(ok=ok, detail=("healthy" if ok else why), phase=ctx.phase)


def command_smoke(cmd: Sequence[str], *, cwd: Optional[Path] = None, env: Optional[dict] = None) -> Smoke:
    """Build a smoke that runs an external COMMAND (default operational choice: ``make smoke``) and honours
    its exit code. ``cwd`` defaults to the deploy context's ``repo_root``. Used by the scheduled workflow to
    run the REAL ``make smoke`` as the post-deploy smoke, and by the exit-code tests with a stand-in."""
    def _smoke(ctx: DeployContext) -> SmokeResult:
        return run_smoke(cmd, cwd=cwd or ctx.repo_root, env=env, phase=ctx.phase)
    return _smoke


def make_smoke() -> Smoke:
    """The operational default post-deploy smoke: run ``make smoke`` and honour its exit code."""
    return command_smoke(("make", "smoke"))


# ====================================================================================================
# the deploy -> post-deploy-smoke -> (auto-rollback if broken) roundtrip
# ====================================================================================================
@dataclass(frozen=True)
class DeployVerifyResult:
    """The outcome of one deploy-verify run. ``ok`` is True IFF the pipeline did the RIGHT thing: either a
    healthy deployment passed smoke and stood, OR a broken deployment was caught by smoke and safely rolled
    back to a re-verified prior version. ``outcome`` is ``deployed`` or ``rolled_back``."""

    ok: bool
    outcome: str
    detail: str
    prior_count: int = 0
    prior_layout: str = ""
    deployed_layout: str = ""
    post_deploy_smoke_ok: bool = False
    rolled_back: bool = False
    restored_signature_ok: bool = False
    restored_chain_ok: bool = False
    restored_data_intact: bool = False
    restored_layout: str = ""
    post_rollback_smoke_ok: bool = False
    steps: tuple[dict, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in self.__dict__.items()}


_CORRUPT_TOKENS = (b"compressible", b"realistic", b"deployed", b"record", b"text")


def break_deployment(spine_dir: Path) -> bool:
    """Simulate a DELIBERATELY-BROKEN deployment: corrupt one record's payload bytes in the deployed store
    (same-length replacement -> still valid JSON, but it no longer hashes to its ``cert_digest``), so the
    deployed store's chain no longer verifies and the post-deploy health smoke fails. Returns True IFF a
    record was actually corrupted (the negative control asserts this precondition, so a no-op corruption
    cannot masquerade as a caught failure).

    Robust across the retain-all segment layout: it corrupts a record in an OPEN plaintext ``*.jsonl``
    segment if one holds content, otherwise inside a SEALED, gzipped ``*.jsonl.gz`` segment (decompress ->
    mutate a record's content -> recompress), so a broken deployment is detected whether the corrupt
    record sits in the open tail or a sealed segment."""
    for jsonl in sorted(Path(spine_dir).rglob("*.jsonl")):
        raw = jsonl.read_bytes()
        for token in _CORRUPT_TOKENS:
            if token in raw:
                jsonl.write_bytes(raw.replace(token, b"x" * len(token), 1))
                return True
    import gzip
    for gz in sorted(Path(spine_dir).rglob("*.jsonl.gz")):
        raw = gzip.decompress(gz.read_bytes())
        for token in _CORRUPT_TOKENS:
            if token in raw:
                gz.write_bytes(gzip.compress(raw.replace(token, b"x" * len(token), 1)))
                return True
    return False


def deploy_verify_roundtrip(
    work_dir: Path, *, smoke: Smoke = spine_health_smoke, records: int = 12, n_writer_records: int = 3,
    break_deploy: bool = False, seg_max_records: int = 50, repo_root: Optional[Path] = None,
) -> DeployVerifyResult:
    """One full deploy-verify roundtrip on realistic OWNER-SIGNED data, reusing #451's machinery:

      1. **prior version** — stand up the currently-deployed build-(N-1) signed spine and verify it;
      2. **deploy the new build** — the real ``upgrade()`` orchestrator migrates N-1 -> N and takes + verifies
         its own pre-deploy backup (the rollback target); the build-N writer then appends new records;
      3. (negative control) if ``break_deploy``, corrupt the deployed store so it is unhealthy;
      4. **post-deploy smoke** — run ``smoke`` over the deployed state and HONOUR its verdict;
      5. if smoke PASSED -> the deployment STANDS (``outcome='deployed'``);
         if smoke FAILED -> **auto-rollback**: ``restore_from_backup`` restores the prior version, then it is
         RE-VERIFIED (original owner signature anchors it, layout back to legacy, record count + sequence set
         identical to the prior version), and a post-rollback smoke confirms the restored version is healthy
         (``outcome='rolled_back'``).

    ``ok`` is True IFF the pipeline behaved correctly for whichever path it took."""
    work_dir = Path(work_dir)
    spine_dir = work_dir / "spine"
    backups = work_dir / "backups"
    data = spine_dir / "spine.jsonl"
    steps: list[dict] = []

    # 1. prior (currently-deployed) version.
    store, head, kp, tr = build_n_minus_1_signed_spine(
        spine_dir, records=records, seg_max_records=seg_max_records)
    prior_count = store.count()
    prior_seqs = [r.seq for r in store.iter_records()]
    prior_layout = "legacy" if read_manifest(store._layout) is None else "segment"
    ok_prior, why_prior = verify_signed_spine(store, head, tr)
    steps.append({"step": "prior_version", "count": prior_count, "layout": prior_layout,
                  "signed": ok_prior, "why": why_prior})
    if not ok_prior:
        return DeployVerifyResult(ok=False, outcome="error", detail=f"prior version does not verify: {why_prior}",
                                  prior_count=prior_count, prior_layout=prior_layout, steps=tuple(steps))

    # 2. deploy the new build (real upgrade orchestrator; takes + verifies its own pre-deploy backup).
    rep = upgrade(SpineStore(str(data), seg_max_bytes=0, seg_max_records=seg_max_records), backup_dir=backups)
    backup_path = Path(rep["backup"])
    deployed = SpineStore(str(data))
    deployed_layout = "segment" if read_manifest(deployed._layout) is not None else "legacy"
    for j in range(n_writer_records):                       # the new build writes data post-deploy
        deployed.append(kind="event", source="deploy", actor="n-writer",
                        payload={"n": 2000 + j, "text": f"build-N deployed record {j}"})
    # the deployed build re-anchors the store it now serves; one owner trust root verifies both heads.
    deployed_head = _sign_deployed_head(SpineStore(str(data)), kp, "deploy")
    steps.append({"step": "deploy", "migrated": rep.get("migrated"), "layout": deployed_layout,
                  "backup": str(backup_path)})

    # 3. deliberately break the deployment (negative control only).
    broken = False
    if break_deploy:
        broken = break_deployment(spine_dir)
        steps.append({"step": "break_deployment", "corrupted_a_record": broken})

    # 4. post-deploy smoke — its verdict is honoured. Verifies the DEPLOYED head over the deployed store.
    ctx = DeployContext(data_path=data, head=deployed_head, trust_root=tr, phase="post-deploy",
                        repo_root=repo_root)
    smoke_res = smoke(ctx)
    steps.append({"step": "post_deploy_smoke", "ok": smoke_res.ok, "detail": smoke_res.detail,
                  "returncode": smoke_res.returncode})

    # 5a. smoke PASSED -> the deployment stands.
    if smoke_res.ok:
        return DeployVerifyResult(
            ok=True, outcome="deployed",
            detail="deployment passed post-deploy smoke and stands",
            prior_count=prior_count, prior_layout=prior_layout, deployed_layout=deployed_layout,
            post_deploy_smoke_ok=True, rolled_back=False, steps=tuple(steps))

    # 5b. smoke FAILED -> AUTO-ROLLBACK to the prior version, then PROVE the restore.
    restore_from_backup(spine_dir, backup_path)
    restored = SpineStore(str(data))
    restored_layout = "legacy" if read_manifest(restored._layout) is None else "segment"
    restored_chain_ok, rcwhy = restored.verify()
    restored_signature_ok, rswhy = verify_signed_spine(restored, head, tr)
    restored_data_intact = (restored.count() == prior_count
                            and [r.seq for r in restored.iter_records()] == prior_seqs)
    post_rollback = spine_health_smoke(
        DeployContext(data_path=data, head=head, trust_root=tr, phase="post-rollback", repo_root=repo_root))
    steps.append({"step": "rollback", "layout": restored_layout, "chain_ok": restored_chain_ok,
                  "signed": restored_signature_ok, "data_intact": restored_data_intact,
                  "post_rollback_smoke_ok": post_rollback.ok, "chain_why": rcwhy, "signed_why": rswhy})

    ok = bool(restored_signature_ok and restored_chain_ok and restored_data_intact
              and restored_layout == prior_layout and post_rollback.ok)
    detail = ("broken deployment caught by post-deploy smoke and rolled back; prior version restored with "
              "owner signature and every record intact") if ok else (
              "rollback did NOT cleanly restore the prior version — see steps")
    return DeployVerifyResult(
        ok=ok, outcome="rolled_back", detail=detail,
        prior_count=prior_count, prior_layout=prior_layout, deployed_layout=deployed_layout,
        post_deploy_smoke_ok=False, rolled_back=True, restored_signature_ok=restored_signature_ok,
        restored_chain_ok=restored_chain_ok, restored_data_intact=restored_data_intact,
        restored_layout=restored_layout, post_rollback_smoke_ok=post_rollback.ok, steps=tuple(steps))


# ====================================================================================================
# CLI — runs BOTH paths and prints the verdict. Exit 0 IFF both behaved correctly.
# ====================================================================================================
def run_full_deploy_verify(
    work_dir: Path, *, records: int = 12, healthy_smoke: Optional[Smoke] = None,
) -> dict:
    """Run the healthy path AND the deliberately-broken path, returning a combined verdict. The healthy path
    uses ``healthy_smoke`` if given (the scheduled workflow passes the REAL ``make smoke``); the broken path
    always uses the health probe so the corruption is actually detected. ``ok`` is True IFF the healthy
    deployment stood AND the broken deployment was caught + rolled back with the prior version restored."""
    work_dir = Path(work_dir)
    healthy = deploy_verify_roundtrip(
        work_dir / "healthy", smoke=healthy_smoke or spine_health_smoke, records=records)
    broken = deploy_verify_roundtrip(work_dir / "broken", records=records, break_deploy=True)
    ok = (healthy.ok and healthy.outcome == "deployed"
          and broken.ok and broken.outcome == "rolled_back"
          and broken.restored_signature_ok and broken.restored_data_intact)
    return {"ok": ok, "healthy": healthy.to_dict(), "broken": broken.to_dict()}


def main(argv: Optional[list[str]] = None) -> int:  # pragma: no cover — CLI convenience / workflow driver
    """``python -m sigil.spine.deploy_verify [--records N] [--smoke-cmd CMD]`` — run the deploy-verify
    pipeline (healthy deploy stands; broken deploy is caught + auto-rolled-back) and print the JSON verdict.
    ``--smoke-cmd`` (e.g. ``--smoke-cmd 'make smoke'``) runs that REAL command as the healthy path's
    post-deploy smoke, honouring its exit code. Exit 0 IFF the whole pipeline behaved correctly."""
    import argparse
    import shlex
    import tempfile

    ap = argparse.ArgumentParser(description="VIGIL deploy-verify pipeline with rollback proof (W11-8)")
    ap.add_argument("--records", type=int, default=12)
    ap.add_argument("--smoke-cmd", default=None,
                    help="real post-deploy smoke command for the healthy path (e.g. 'make smoke'); its exit "
                         "code is honoured. Omitted -> the built-in signed-spine health probe.")
    args = ap.parse_args(argv)
    repo_root = Path.cwd()
    healthy_smoke = command_smoke(shlex.split(args.smoke_cmd), cwd=repo_root) if args.smoke_cmd else None
    with tempfile.TemporaryDirectory(prefix="vigil-deploy-verify-") as tmp:
        verdict = run_full_deploy_verify(Path(tmp), records=args.records, healthy_smoke=healthy_smoke)
    print(json.dumps(verdict, indent=2))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
