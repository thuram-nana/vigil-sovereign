"""redpen_fix — the Red-Pen "Fix this" + Retest engine (offense plane, VIGIL R5, design §7 / HANDOFF §12).

Two customer-driven, OFF-by-default (``VIGIL_REDPEN_ENABLED``) follow-ups to a reproduced Red-Pen finding:

  * **Fix this** (:func:`redpen_fix_this` + :func:`make_redpen_fix_worker`). On an explicit customer action for
    ONE reproduced finding: write the patch, RE-REVIEW it, and only then open a gated fix PR. The re-review
    (:func:`verify_before_pr`) is the load-bearing control — a fix PR opens ONLY when ALL THREE hold:
      1. the finding's reproduction now PASSES (its exploit/rule no longer fires on the patched clone),
      2. the repository's own tests PASS, and
      3. a **Quick Red-Pen** (:func:`redpen.run_redpen`) of the patch introduces NO NEW FACT
         (a reproduced O-1 FACT in the fix's changed files is a regression the fix is responsible for — refuse).
    The write is the already-built proof-carrying-remediation ladder (``codefix_runner.autopatch_live``) and the
    PR open is the already-gated ``github_fix_pr.authorized_fix_pr`` (``pr_enabled`` OFF ∧ an owner-signed
    repo-EXACT ``"pr"`` grant ∧ clone-origin == grant ∧ WARDEN A3 + m-of-n quorum ∧ a signed audit record).
    **VIGIL NEVER MERGES** — structurally: the only write that exists is ``open_pr`` from a FIX BRANCH, and the
    EXACT reviewed diff is pinned into the PR pass (``proposed_diff``) so the opened patch IS the re-reviewed one.

  * **Retest** (:func:`redpen_retest` + :func:`make_redpen_retest_worker`). Re-fire a finding's PROOF against the
    current repository and mark it **Verified-Fixed** or **Still-Vulnerable**. For a code finding the proof is the
    deterministic DAA re-scan (``codescan.verify_finding_cleared``) — offline, no model, no credits.

Sovereign → offense: the sovereign provisioner (``ui.redpen_provision``) gates the action (flag + the
``manage_code`` permission + the owner-signed connected-repo record; Fix also reserves/meters via
``reserve_redpen_review``) and PUBLISHES a small action marker to a DEDICATED ``redpen-actions`` seam (distinct
from the review-lease seam). :func:`redpen_action_jobs_from_seam` is the KEYLESS trigger that turns those markers
into ``SecurityJob``\\ s — it only PRODUCES jobs, never runs one (the queue + ``jobs.runner`` stay the sole
executor; a produced job grants NO bypass — the ``"pr"`` grant + the signed-spine fact are re-checked offense-side).

FATAL-2: every ``framework``-backed piece (autopatch ladder, fix-PR executor, Quick Red-Pen certify seam,
codescan oracle, trusted-finding rebuild) is imported LAZILY inside the function that needs it, so this module is
import-clean in either venv and is driven only on the offense plane. Module scope pulls only stdlib + the pure
``.model`` + the framework-free ``redpen.engine`` flag + ``vigil_core.seam_base``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from vigil_core.redpen_action import (
    REDPEN_ACTION_SEAM_SUBDIR, REDPEN_FIX_ACTION, REDPEN_RETEST_ACTION,
)

from ..redpen.engine import redpen_enabled
from .model import SecurityJob, _clip, work_delivery_id

Worker = Callable[[SecurityJob], dict]


# ---- result shapes (JSON-safe summaries the worker returns) -----------------------------------------


@dataclass(frozen=True)
class ReReview:
    """The verdict of the pre-PR re-review (:func:`verify_before_pr`). ``ok`` is True ONLY when the
    reproduction cleared, the repo tests passed, and the Quick Red-Pen found no new FACT."""

    ok: bool
    reproduction_cleared: bool = False
    tests_passed: bool = False
    new_facts: int = 0
    reason: str = ""

    def as_dict(self) -> dict:
        return {"ok": self.ok, "reproduction_cleared": self.reproduction_cleared,
                "tests_passed": self.tests_passed, "new_facts": self.new_facts, "reason": self.reason}


@dataclass(frozen=True)
class RedPenFixResult:
    """The outcome of a Fix-this action. ``opened_pr`` is True ONLY after the re-review passed AND the gated
    ``authorized_fix_pr`` chain opened a PR from a fix branch; ``enabled`` is False (everything empty) when the
    master flag is off."""

    enabled: bool
    opened_pr: bool = False
    status: str = ""
    pr_ref: str = ""
    remediated: bool = False
    review: Optional[ReReview] = None
    reason: str = ""

    def as_dict(self) -> dict:
        return {"enabled": self.enabled, "opened_pr": self.opened_pr, "status": self.status,
                "pr_ref": self.pr_ref, "remediated": self.remediated,
                "review": self.review.as_dict() if self.review is not None else None,
                "reason": self.reason}


@dataclass(frozen=True)
class RetestResult:
    """One finding's retest verdict. ``status`` is ``"Verified-Fixed"`` (the proof no longer fires) or
    ``"Still-Vulnerable"`` (it still fires, or the re-scan could not confirm clearance — fail-closed)."""

    ref: str
    status: str
    cleared: bool
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"ref": self.ref, "status": self.status, "cleared": self.cleared, "detail": self.detail}


VERIFIED_FIXED = "Verified-Fixed"
STILL_VULNERABLE = "Still-Vulnerable"

#: R3 interface — resolve a posted FACT's REPRODUCTION recipe: ``(slug, finding_ref) -> recipe | None``. The
#: recipe is the R1 ``redpen.LensCandidate`` whose twice-fired PoC produced the FACT (only ``poc_command`` /
#: ``fire_markers`` / ``fire_mode`` are read, duck-typed). ``None`` ⇒ the finding is a DAA static fact and its
#: proof is the deterministic re-scan (``codescan.verify_finding_cleared``). It must read an OFFENSE-side record the
#: review worker itself wrote — never a seam marker (a forged marker must not choose the command the sandbox runs).
ProofResolver = Callable[[str, str], Any]


# ---- re-fire a reproduced finding's PoC (the proof behind Fix's pre-PR verify and Retest) -----------


def refire_reproduction(
    proof: Any,
    *,
    workspace: str,
    sandbox: Optional[Callable[[str], Any]] = None,
    timeout: Optional[float] = None,
    runs: Optional[int] = None,
) -> dict:
    """Re-run a reproduced finding's PoC in the S5 sandbox against ``workspace`` (the current tree, or a patched
    clone) and report whether the defect still FIRES. The fire decision is R1's own (``redpen.reproduce._fired``
    over the recipe's declared markers), so a re-fire judges exactly as the original reproduction did.

    Returns ``{"fired": True|False|None, "fires", "clean_runs", "runs", "reason"}``:
      * ``True``  — the PoC fired on a run: the finding is STILL there (conservative — one fire suffices);
      * ``False`` — POSITIVE evidence of clearance: every required run COMPLETED (an exit code, not timed out) and
        none fired, AND the recipe declares at least one fire marker;
      * ``None``  — could not confirm either way: no command, no markers (a marker-less recipe can never 'not
        fire' meaningfully), the sandbox unavailable / erroring, or a run that timed out / failed to spawn.
    ``None`` is NEVER read as cleared — silence is not evidence (a hung or unrunnable PoC is not a fix)."""
    from ..live.sandbox_exec import SandboxUnavailable, run_sandboxed   # stdlib-only sibling (lazy for symmetry)
    from ..redpen.reproduce import DEFAULT_REPRO_TIMEOUT, DEFAULT_RUNS_REQUIRED, _fired

    command = str(getattr(proof, "poc_command", "") or "").strip()
    markers = tuple(m for m in (getattr(proof, "fire_markers", ()) or ()) if m)
    mode = str(getattr(proof, "fire_mode", "any") or "any")
    n = max(1, int(runs if runs is not None else DEFAULT_RUNS_REQUIRED))
    out: dict = {"fired": None, "fires": 0, "clean_runs": 0, "runs": n, "reason": ""}
    if not command:
        out["reason"] = "the finding's reproduction declares no PoC command — cannot re-run its proof"
        return out
    if not markers:
        out["reason"] = "the finding's reproduction declares no fire markers — a re-run cannot be judged"
        return out
    t = float(timeout if timeout is not None else DEFAULT_REPRO_TIMEOUT)
    runner = sandbox if sandbox is not None else (
        lambda cmd: run_sandboxed(cmd, workspace=workspace, timeout=t))
    for _ in range(n):
        try:
            outcome = runner(command)
        except SandboxUnavailable as exc:
            out["reason"] = f"the sandbox is unavailable — the proof could not be re-run: {exc}"
            return out
        except Exception as exc:  # noqa: BLE001 — an erroring run confirms nothing (never a 'fixed')
            out["reason"] = f"the proof re-run failed: {type(exc).__name__}: {exc}"
            return out
        if _fired(outcome, markers, mode):
            out.update(fired=True, fires=int(out["fires"]) + 1,
                       reason="the finding's PoC still fires on the re-run")
            return out
        if getattr(outcome, "timed_out", False) or getattr(outcome, "exit_code", None) is None:
            out["reason"] = "a re-run did not complete (timed out / failed to start) — cannot confirm clearance"
            return out
        out["clean_runs"] = int(out["clean_runs"]) + 1
    out.update(fired=False, reason=f"the PoC completed {n}/{n} re-runs without firing")
    return out


class ReproFixVerdict:
    """A fix-verification verdict over a REPRODUCTION re-fire, shaped for ``autopatch``'s readers: ``fired`` is
    ``True`` (still fires), ``False`` (positively cleared) or ``None`` (could not confirm — the pre-PR verify then
    lands on ``verify-unverified``, which the re-review refuses). Carries NO signed cert: a cleared re-fire earns the
    honest ``verified-no-pr``, never the signed ``remediated``."""

    __slots__ = ("fired", "detail")

    def __init__(self, fired: Optional[bool], detail: dict) -> None:
        self.fired = fired
        self.detail = detail


def build_reproduction_fix_oracle(proof: Any, *, sandbox: Optional[Callable[[str], Any]] = None,
                                  timeout: Optional[float] = None, runs: Optional[int] = None) -> Any:
    """The Fix pre-PR verify oracle for a SANDBOX-reproduced finding: ``oracle(request, patched_build)`` re-fires
    the finding's own PoC (:func:`refire_reproduction`) inside the PATCHED clone (``patched_build`` = the clone
    workdir / its ``build_ref``). The reproduction analogue of ``codescan.build_code_fix_oracle``."""
    def _oracle(_request: Any, patched_build: Any) -> ReproFixVerdict:
        root = str(getattr(patched_build, "build_ref", "") or patched_build or "")
        if not root:
            return ReproFixVerdict(None, {"reason": "no patched clone to re-run the proof in"})
        res = refire_reproduction(proof, workspace=root, sandbox=sandbox, timeout=timeout, runs=runs)
        return ReproFixVerdict(res.get("fired"), res)

    return _oracle


# ---- the pre-PR re-review (the load-bearing control) ------------------------------------------------


def verify_before_pr(
    patch_result: Any,
    *,
    patched_clone: str,
    changed_paths: Sequence[str],
    reviewer: Any,
    engagement_slug: str,
    signers: "Sequence[tuple[str, str]]",
    run_redpen: Optional[Callable[..., Any]] = None,
    require_tests: bool = True,
    lenses: "Optional[Sequence[str]]" = None,
    sandbox: Any = None,
    confirm: Any = None,
    verifier: Any = None,
) -> ReReview:
    """Re-review a written patch BEFORE its PR opens. Returns a passing :class:`ReReview` ONLY when every check
    holds; any failing check refuses (``ok=False``) so the caller never opens the PR. The three checks:

      1. **Reproduction cleared.** ``patch_result.status == "verified-no-pr"`` — the pre-PR verify leg of the
         PCR ladder re-fired the ORIGINAL finding's oracle over the patched clone and it went SILENT (and the
         adversarial breaker found no gate-gaming). Any other status (``verify-still-vulnerable``,
         ``verify-cheat-suspected``, ``build-failed``, …) means the fix did not actually clear the finding.
      2. **Tests pass.** ``patch_result.tests_passed is True`` — the repo's REAL suite ran in the sandbox clone
         and passed. A skipped (``None``) or failing (``False``) suite is refused when ``require_tests`` (default).
      3. **No new FACT.** A diff-scoped Quick Red-Pen (:func:`redpen.run_redpen` over the fix's ``changed_paths``)
         reproduces NO FACT. A FACT in the fix's own changed files is a regression the fix introduced — refuse
         the PR (decision O-1: the check is over REPRODUCED facts; ``run_redpen`` mints a FACT only for a twice-
         fired, O-1-eligible candidate). A flag-off Quick Red-Pen (``enabled=False``) fails CLOSED — a patch that
         could not be re-reviewed is never opened.

    ``run_redpen`` is the Quick Red-Pen seam (default: the real ``redpen.run_redpen``); ``reviewer`` is the
    gateway-backed lens reviewer (R3 wires the live one; tests inject a fake). ``sandbox`` / ``confirm`` /
    ``verifier`` are forwarded reproduction/certify seams (tests inject deterministic fakes; FATAL-2)."""
    status = str(getattr(patch_result, "status", "") or "")
    if status != "verified-no-pr":
        return ReReview(ok=False, reproduction_cleared=False,
                        reason=f"the fix did not clear the finding on the patched clone (status={status!r}) — "
                               "refusing the PR")
    tests_passed = getattr(patch_result, "tests_passed", None) is True
    if require_tests and not tests_passed:
        return ReReview(ok=False, reproduction_cleared=True, tests_passed=tests_passed,
                        reason="the repository's tests did not pass on the patched clone (suite skipped or "
                               "failed) — refusing the PR")

    rp = run_redpen
    if rp is None:
        from ..redpen import run_redpen as _real_run_redpen   # lazy (framework reached only via the certify seam)
        rp = _real_run_redpen
    report = rp(checkout_path=patched_clone, changed_paths=tuple(changed_paths or ()), reviewer=reviewer,
                engagement_slug=engagement_slug, signers=signers, workspace=patched_clone, lenses=lenses,
                sandbox=sandbox, confirm=confirm, verifier=verifier)
    if not getattr(report, "enabled", False):
        # The Quick Red-Pen could not run (the engine flag is off) — we cannot assert "no new FACT", so we
        # refuse rather than open an un-re-reviewed PR (fail-closed).
        return ReReview(ok=False, reproduction_cleared=True, tests_passed=tests_passed,
                        reason="the Quick Red-Pen is disabled (VIGIL_REDPEN_ENABLED off) — cannot re-review the "
                               "patch; refusing the PR (fail-closed)")
    facts = tuple(getattr(report, "facts", ()) or ())
    if facts:
        return ReReview(ok=False, reproduction_cleared=True, tests_passed=tests_passed, new_facts=len(facts),
                        reason=f"the Quick Red-Pen reproduced {len(facts)} new FACT(s) in the patched files — "
                               "refusing the PR (the fix introduced a vulnerability)")
    tests_note = "the tests pass" if tests_passed else "the test suite was not required (not run)"
    return ReReview(ok=True, reproduction_cleared=True, tests_passed=tests_passed, new_facts=0,
                    reason=f"re-review passed: the reproduction cleared, {tests_note}, and the Quick Red-Pen "
                           "found no new FACT")


# ---- Fix this: write → re-review → gated PR (never merge) --------------------------------------------


def _finding_ref(finding: Any) -> str:
    return str(getattr(finding, "ref", "") or getattr(finding, "id", "") or "")


def _locate_patched_clone(config: Any, remediation_id: str) -> Optional[str]:
    """The disposable clone ``autopatch_live`` left the written patch in — the SAME workdir the codefix session
    cloned into (``<base_dir>/codefix-<remediation_id>``), via the real ``_safe_workdir`` so the naming/escape
    guard stays in lockstep. Returns the path iff it resolves to an existing directory, else ``None`` (the
    re-review then fails closed — we never Quick-Red-Pen a clone that is not there)."""
    from ..live.codefix_runner import _safe_workdir   # lazy; framework-free but offense sibling
    wd = _safe_workdir(getattr(config, "base_dir", ""), remediation_id)
    if wd and os.path.isdir(wd):
        return wd
    return None


def redpen_fix_this(
    finding: Any,
    *,
    config: Any,                                  # live.codefix_runner.CodefixConfig (target_repo = the clone)
    trust_root: Any,
    repo: str,
    slug: str,
    audit: Callable[[dict], None],
    reviewer: Any,
    signers: "Sequence[tuple[str, str]]",
    quorum: Optional[Callable[[Any], Any]] = None,
    verify_oracle: Optional[Callable[[Any, Any], Any]] = None,
    client: Any = None,
    killswitch: Any = None,
    now: Any = None,
    grant_path: Any = None,
    epoch_path: Any = None,
    remote_of: Optional[Callable[..., str]] = None,
    require_tests: bool = True,
    lenses: "Optional[Sequence[str]]" = None,
    _autopatch: Any = None,
    _run_redpen: Optional[Callable[..., Any]] = None,
    _fix_pr: Any = None,
    _build_oracle: Any = None,
    _locate_clone: Optional[Callable[[Any, str], Optional[str]]] = None,
) -> RedPenFixResult:
    """Run one "Fix this" action for a reproduced ``finding``, fail-closed at every step. Inert (``enabled=False``)
    when ``VIGIL_REDPEN_ENABLED`` is off — the ladder, the re-review and the fix-PR executor are not touched.

    Order:
      * **pass 1 — WRITE + PRE-PR VERIFY.** ``autopatch_live`` with ``pr_enabled=False`` + ``verify_before_pr=True``
        proposes the patch (the metered coder — ``config.model`` is the grant model), applies it in the S5 sandbox
        clone, runs the build/test gate, and re-fires the finding's own fix-oracle; it returns ``verified-no-pr``
        iff the finding cleared, the breaker found no gate-gaming, and the build held. No PR is opened in pass 1.
      * **re-review.** :func:`verify_before_pr` over the patched clone: reproduction cleared ∧ tests pass ∧ Quick
        Red-Pen finds no new FACT. Any failure ⇒ NO PR (an honest refusal).
      * **pass 2 — GATED PR (never merge).** ``authorized_fix_pr`` opens the PR with the EXACT reviewed diff pinned
        in (``proposed_diff``), so the opened patch is the re-reviewed one. The open requires ``pr_enabled`` + an
        owner-signed repo-EXACT ``"pr"`` grant + clone-origin == grant + WARDEN A3 + the m-of-n ``quorum`` + a
        signed audit record. The only write is ``open_pr`` from a fix branch — VIGIL never merges.

    Returns a :class:`RedPenFixResult`. ``_autopatch`` / ``_run_redpen`` / ``_fix_pr`` / ``_build_oracle`` /
    ``_locate_clone`` are offline-test injection seams (default: the real ladder / Quick Red-Pen / fix-PR executor /
    code fix-oracle / clone locator)."""
    if not redpen_enabled():
        return RedPenFixResult(enabled=False, reason="Red-Pen is off (VIGIL_REDPEN_ENABLED) — inert")

    ref = _finding_ref(finding)

    autopatch_live = _autopatch
    if autopatch_live is None:
        from ..live.codefix_runner import autopatch_live as _al   # lazy (offense)
        autopatch_live = _al
    build_oracle = _build_oracle
    if build_oracle is None:
        from ..codescan import build_code_fix_oracle   # lazy (offense)
        build_oracle = build_code_fix_oracle

    # The fix-verification oracle re-fires the ORIGINAL finding's DAA rule over the patched clone (goes silent iff
    # the finding is cleared). Shared by pass 1 (the pre-PR verify) and pass 2 (the PR-pass verify).
    fix_oracle = verify_oracle if verify_oracle is not None else build_oracle(ref)

    # --- pass 1: write the patch + pre-PR verify (NO PR) ---------------------------------------------
    cfg_no_pr = dataclasses.replace(config, pr_enabled=False)
    pass1 = autopatch_live(finding, config=cfg_no_pr, client=client, killswitch=killswitch,
                           operator_present=True, verify_oracle=fix_oracle, verify_before_pr=True, now=now)

    # --- re-review ----------------------------------------------------------------------------------
    locate = _locate_clone or _locate_patched_clone
    patched_clone = locate(cfg_no_pr, str(getattr(pass1, "remediation_id", "") or ""))
    changed_paths = tuple(getattr(pass1, "patched_paths", ()) or ())
    if not patched_clone:
        review = ReReview(ok=False, reason="the written patch's sandbox clone is unavailable — cannot re-review "
                          "(fail-closed); no PR opened")
        return RedPenFixResult(enabled=True, opened_pr=False, status=str(getattr(pass1, "status", "") or ""),
                               review=review, reason=review.reason)

    review = verify_before_pr(
        pass1, patched_clone=patched_clone, changed_paths=changed_paths, reviewer=reviewer,
        engagement_slug=slug, signers=signers, run_redpen=_run_redpen, require_tests=require_tests, lenses=lenses)
    if not review.ok:
        return RedPenFixResult(enabled=True, opened_pr=False, status=str(getattr(pass1, "status", "") or ""),
                               review=review, reason="fix PR refused by the re-review: " + review.reason)

    # --- pass 2: open the gated fix PR with the EXACT reviewed diff pinned in (never merge) ----------
    reviewed_diff = str(getattr(pass1, "applied_diff", "") or "")

    def _pinned_autopatch(f: Any, *, config: Any, client: Any = None, killswitch: Any = None,
                          quorum: Any = None, verify_oracle: Any = None) -> Any:
        # authorized_fix_pr drives autopatch_live with THIS signature; we add the reviewed diff so pass 2 re-opens
        # the re-reviewed patch (never a freshly, differently-proposed one).
        inner = _autopatch
        if inner is None:
            from ..live.codefix_runner import autopatch_live as _al2   # lazy (offense)
            inner = _al2
        return inner(f, config=config, client=client, killswitch=killswitch, quorum=quorum,
                     verify_oracle=verify_oracle, proposed_diff=reviewed_diff, prefer_deterministic=False)

    fix_pr = _fix_pr
    if fix_pr is None:
        from ..live.github_fix_pr import authorized_fix_pr   # lazy (offense)
        fix_pr = authorized_fix_pr
    cfg_pr = dataclasses.replace(config, pr_enabled=True)
    _extra = {"remote_of": remote_of} if remote_of is not None else {}
    result = fix_pr(slug=slug, trust_root=trust_root, repo=repo, finding=finding, config=cfg_pr, audit=audit,
                    quorum=quorum, verify_oracle=fix_oracle, client=client, killswitch=killswitch, now=now,
                    grant_path=grant_path, epoch_path=epoch_path, _autopatch=_pinned_autopatch, **_extra)
    return RedPenFixResult(
        enabled=True, opened_pr=bool(getattr(result, "opened_pr", False)),
        status=str(getattr(result, "status", "") or ""), pr_ref=str(getattr(result, "pr_ref", "") or ""),
        remediated=bool(getattr(result, "remediated", False)), review=review,
        reason="fix PR opened from a fix branch (re-reviewed; VIGIL never merges)"
               if getattr(result, "opened_pr", False)
               else ("fix PR not opened: " + str(getattr(result, "reason", "") or "")))


def _grant_model(config_model: str, override: Optional[str]) -> str:
    """The model the codefix coder MUST use — the GRANT model (M1c-2b): the explicit ``override`` (the grant's model,
    which the worker assembly reads from the owner-signed model grant), else — inside the grant scope of a METERED
    run — the grant model ``codefix_runner._metered_model`` resolves (the ONE place that knows where the grant scope
    publishes it), else the config's own model (an unmetered run is byte-identical). Pinned on ``CodefixConfig.model``
    so the coder never asks the gateway for a model the grant does not admit."""
    if override:
        return str(override)
    from ..live.codefix_runner import _metered_model   # lazy (its metered-mode probe is framework-lazy + total)
    return _metered_model(config_model)


def make_redpen_fix_worker(
    *,
    spine_base_dir: str,
    checkout: Callable[[SecurityJob], str],
    codefix_config: Any,                          # live.codefix_runner.CodefixConfig (template; target_repo per job)
    trust_root: Any,
    reviewer: Any,
    signers: "Sequence[tuple[str, str]]",
    audit: Callable[[dict], None],
    model: Optional[str] = None,
    quorum: Optional[Callable[[Any], Any]] = None,
    quorum_factory: Optional[Callable[[SecurityJob], Any]] = None,
    now: Any = None,
    grant_path: Any = None,
    epoch_path: Any = None,
    remote_of: Optional[Callable[..., str]] = None,
    require_tests: bool = True,
    lenses: "Optional[Sequence[str]]" = None,
    proof_resolver: Optional[ProofResolver] = None,
    grant_scope: Optional[Callable[[SecurityJob], Any]] = None,
    _repro_sandbox: Optional[Callable[[str], Any]] = None,
    _fix_this: Optional[Callable[..., RedPenFixResult]] = None,
    _from_spine: Optional[Callable[..., Any]] = None,
) -> Worker:
    """Build the Fix-this worker :meth:`JobRunner.run_one` invokes for a ``redpen_action == "fix"`` job. For the
    job's ``extra["finding_ref"]`` it (a) rebuilds the CONFIRMED fact from the engagement's OWN signed offense
    spine (``finding_from_spine`` — prove-don't-guess; an absent/unknown ref fails CLOSED), (b) picks the finding's
    own proof for the pre-PR "reproduction now passes" check — the PoC re-fire (:func:`build_reproduction_fix_oracle`)
    when ``proof_resolver(slug, ref)`` returns the reproduction recipe, else the DAA re-scan
    (``build_code_fix_oracle``, inside :func:`redpen_fix_this`), and (c) INSIDE ``grant_scope(job)`` pins the codefix
    config to the PR-head clone and the GRANT MODEL (:func:`_grant_model`) and drives :func:`redpen_fix_this`. The
    worker runs ONLY on an explicit fix job — there is no automatic fix.

    Metering (M1c-2b): ``grant_scope(job)`` is the context the assembly supplies to route this job's model calls
    through the loopback model gateway on the job's owner-signed model grant — the same per-run scope
    ``engage_worker._model_grant_scope`` applies — so the coder spends the grant, never a provider key, and
    ``_grant_model`` resolves the grant's model inside it. Omitted ⇒ no scope (an unmetered run, byte-identical).

    The fix PR opens ONLY if ``redpen_fix_this``'s chain clears (the re-review passes AND ``authorized_fix_pr``'s
    ``pr_enabled`` + ``"pr"`` grant + m-of-n + signed audit all pass). Inert (``enabled=False``) when the master
    flag is off. ``quorum_factory(job)`` supplies the PER-JOB m-of-n quorum (a drain spans many slugs, each
    needing a quorum bound to its OWN slug); a plain ``quorum`` is the direct-caller path. ``_repro_sandbox`` /
    ``_fix_this`` / ``_from_spine`` are offline-test seams."""
    def _worker(job: SecurityJob) -> dict:
        if not redpen_enabled():
            return {"redpen_action": REDPEN_FIX_ACTION, "enabled": False, "opened_pr": False,
                    "reason": "Red-Pen is off (VIGIL_REDPEN_ENABLED) — inert"}
        if (job.extra or {}).get("redpen_action") != REDPEN_FIX_ACTION:
            raise ValueError(f"redpen fix worker got a non-fix job (redpen_action="
                             f"{(job.extra or {}).get('redpen_action')!r})")
        ref = str((job.extra or {}).get("finding_ref") or "")
        if not ref:
            # a fix must positively identify the confirmed fact it remediates — never a silent fall-back
            from ..live.github_write import GitHubWriteError   # lazy (framework-free)
            raise GitHubWriteError("fix refused: the job carries no finding_ref — cannot identify the confirmed "
                                   "fact to remediate (fail-closed)")
        from_spine = _from_spine
        if from_spine is None:
            from ..live.trusted_finding import finding_from_spine   # lazy (offense)
            from_spine = finding_from_spine

        root = checkout(job)
        fobj = from_spine(base_dir=spine_base_dir, slug=job.slug, target_repo=root, finding_ref=ref)
        q = quorum_factory(job) if quorum_factory is not None else quorum
        # The finding's OWN proof drives "the reproduction now passes": a sandbox-reproduced FACT re-fires its PoC
        # in the patched clone; a DAA static fact (resolver → None) keeps redpen_fix_this's DAA re-scan oracle.
        proof = proof_resolver(job.slug, ref) if proof_resolver is not None else None
        oracle = build_reproduction_fix_oracle(proof, sandbox=_repro_sandbox) if proof is not None else None
        fix_this = _fix_this or redpen_fix_this
        scope = grant_scope(job) if grant_scope is not None else contextlib.nullcontext()
        with scope:
            # resolved INSIDE the grant scope, so a metered run pins the grant's own model on the config
            cfg = dataclasses.replace(codefix_config, target_repo=root,
                                      model=_grant_model(getattr(codefix_config, "model", ""), model))
            result = fix_this(fobj, config=cfg, trust_root=trust_root, repo=job.repo, slug=job.slug, audit=audit,
                              reviewer=reviewer, signers=signers, quorum=q, verify_oracle=oracle, now=now,
                              grant_path=grant_path, epoch_path=epoch_path, remote_of=remote_of,
                              require_tests=require_tests, lenses=lenses)
        return {"redpen_action": REDPEN_FIX_ACTION, "finding_ref": ref,
                "proof": "reproduction" if proof is not None else "daa", **result.as_dict()}

    return _worker


# ---- Retest: re-fire each finding's proof -----------------------------------------------------------


def redpen_retest(
    refs: "Sequence[str]",
    *,
    root: str,
    slug: str = "",
    max_files: int = 5000,
    proof_resolver: Optional[ProofResolver] = None,
    sandbox: Optional[Callable[[str], Any]] = None,
    _verify: Optional[Callable[..., dict]] = None,
) -> "list[RetestResult]":
    """Re-fire each finding's PROOF against the current repository tree ``root`` and mark it Verified-Fixed or
    Still-Vulnerable. The proof is the finding's own:

      * a SANDBOX-reproduced FACT (``proof_resolver(slug, ref)`` returns its recipe) — re-run its PoC in the S5
        sandbox (:func:`refire_reproduction`): Verified-Fixed ONLY on positive evidence (every run completed, none
        fired); a fire, or a re-run that could not complete (sandbox unavailable / timeout / no markers), is
        Still-Vulnerable — silence is never read as fixed;
      * a DAA static fact (resolver → ``None``, or no resolver) — the deterministic re-scan
        (``codescan.verify_finding_cleared``): ``cleared`` ⇒ Verified-Fixed, else Still-Vulnerable (a moved/removed
        file stays Still-Vulnerable, never a false 'fixed').

    Offline and non-destructive; no model and no credits. ``detail["proof"]`` names which proof ran and
    ``detail["reason"]`` why. Inert (``[]``) when the master flag is off. ``sandbox`` / ``_verify`` are test seams."""
    if not redpen_enabled():
        return []
    verify = _verify
    if verify is None:
        from ..codescan import verify_finding_cleared   # lazy (offense)
        verify = verify_finding_cleared
    out: "list[RetestResult]" = []
    for ref in refs or ():
        r = str(ref or "")
        if not r:
            continue
        proof = proof_resolver(slug, r) if proof_resolver is not None else None
        if proof is not None:
            res = refire_reproduction(proof, workspace=str(root), sandbox=sandbox)
            cleared = res.get("fired") is False          # STRICT: only positive evidence of clearance
            detail = {"proof": "reproduction", **res}
        else:
            res = verify(root=str(root), ref=r, max_files=max_files)
            res = res if isinstance(res, dict) else {}
            cleared = res.get("cleared") is True         # STRICT: a non-bool truthy value is not 'cleared'
            detail = {"proof": "daa", **res}
        out.append(RetestResult(ref=r, status=VERIFIED_FIXED if cleared else STILL_VULNERABLE,
                                cleared=cleared, detail=detail))
    return out


def _job_refs(job: SecurityJob) -> "list[str]":
    """The finding refs a retest job carries — ``extra["finding_refs"]`` (a list) ∪ a single ``finding_ref``,
    bounded + de-duplicated in first-seen order. Total (a malformed ``extra`` yields no refs)."""
    extra = job.extra or {}
    raw: "list[Any]" = []
    many = extra.get("finding_refs")
    if isinstance(many, (list, tuple)):
        raw.extend(many)
    one = extra.get("finding_ref")
    if one:
        raw.append(one)
    seen: set[str] = set()
    refs: "list[str]" = []
    for v in raw:
        s = _clip(v, 256)
        if s and s not in seen:
            seen.add(s)
            refs.append(s)
    return refs


def make_redpen_retest_worker(
    *,
    checkout: Callable[[SecurityJob], str],
    max_files: int = 5000,
    proof_resolver: Optional[ProofResolver] = None,
    _sandbox: Optional[Callable[[str], Any]] = None,
    _verify: Optional[Callable[..., dict]] = None,
    _retest: Optional[Callable[..., "list[RetestResult]"]] = None,
) -> Worker:
    """Build the Retest worker :meth:`JobRunner.run_one` invokes for a ``redpen_action == "retest"`` job. It
    checks out the repository (``checkout(job)``) and re-fires each ``extra`` finding ref's own proof
    (:func:`redpen_retest` — the PoC re-fire for a sandbox-reproduced FACT via ``proof_resolver``, else the DAA
    re-scan). READ/scan only — it posts nothing and writes nothing external. Inert when the master flag is off.
    Exposed so the Code screen's "Retest" can call it (the sovereign side triggers it; this is the executor)."""
    def _worker(job: SecurityJob) -> dict:
        if not redpen_enabled():
            return {"redpen_action": REDPEN_RETEST_ACTION, "enabled": False, "results": []}
        if (job.extra or {}).get("redpen_action") != REDPEN_RETEST_ACTION:
            raise ValueError(f"redpen retest worker got a non-retest job (redpen_action="
                             f"{(job.extra or {}).get('redpen_action')!r})")
        refs = _job_refs(job)
        root = checkout(job)
        retest = _retest or redpen_retest
        results = retest(refs, root=root, slug=job.slug, max_files=max_files, proof_resolver=proof_resolver,
                         sandbox=_sandbox, _verify=_verify)
        return {"redpen_action": REDPEN_RETEST_ACTION, "enabled": True,
                "results": [r.as_dict() for r in results]}

    return _worker


# ---- the KEYLESS sovereign→offense trigger (the dedicated redpen-actions seam) -----------------------


def _action_seam_dir(base_dir: Any) -> Path:
    """The ``redpen-actions`` directory under the shared seam base — the ONE channel the sovereign provisioner
    publishes Fix/Retest markers to and this trigger reads (SEPARATE from the review credit-launch-lease seam)."""
    from vigil_core.seam_base import resolve_seam_base   # framework-free (shared)
    return Path(resolve_seam_base(base_dir)) / REDPEN_ACTION_SEAM_SUBDIR


def _job_from_marker(marker: dict, *, now: float) -> Optional[SecurityJob]:
    """Build one ``SecurityJob`` from a published Red-Pen action marker, fail-closed. A marker missing a known
    action / a slug / a repo, or malformed, yields ``None`` (no job). The marker is an UNTRUSTED trigger: the
    authority is re-checked offense-side (the ``"pr"`` grant + the signed-spine fact), so a forged marker can
    open nothing."""
    try:
        action = str(marker.get("redpen_action") or "")
        if action not in (REDPEN_FIX_ACTION, REDPEN_RETEST_ACTION):
            return None
        slug = _clip(marker.get("slug"), 80)
        repo = _clip(marker.get("repo"))
        nonce = _clip(marker.get("nonce"), 128)
        if not slug or not repo or not nonce:
            return None
        extra: dict = {"redpen_action": action, "nonce": nonce}
        ref = _clip(marker.get("finding_ref"), 256)
        if ref:
            extra["finding_ref"] = ref
        refs = marker.get("finding_refs")
        if isinstance(refs, (list, tuple)):
            extra["finding_refs"] = [_clip(x, 256) for x in refs if _clip(x, 256)]
        if action == REDPEN_FIX_ACTION and not ref:
            return None   # a fix MUST name exactly one finding — fail-closed
        # the delivery id is content-addressed over (slug, action, nonce) so a re-poll of the same marker
        # coalesces in the queue's permanent seen-set (exactly-once); a new action click (new nonce) re-enqueues.
        delivery = work_delivery_id(slug, action, nonce)
        return SecurityJob.normalize(source="api", repo=repo, engagement_slug=slug,
                                     commit=_clip(marker.get("commit"), 128), delivery_id=delivery, extra=extra)
    except Exception:  # noqa: BLE001 — a malformed marker is 'no job', never a crash
        return None


def redpen_action_jobs_from_seam(base_dir: Any, *, now: Optional[float] = None) -> "list[SecurityJob]":
    """Read every published Red-Pen action marker on the seam under ``base_dir`` and return one
    ``SecurityJob(source="api")`` per well-formed marker (``extra["redpen_action"]`` ∈ {fix, retest}). Inert
    (``[]``) when the master flag is off — every route is ABSENT when Red-Pen is off. TOTAL + fail-closed: a
    malformed marker is skipped, never raised; like every trigger it ONLY PRODUCES jobs, it never runs one."""
    if not redpen_enabled():
        return []
    _ = time.time() if now is None else float(now)
    seam = _action_seam_dir(base_dir)
    out: "list[SecurityJob]" = []
    try:
        names = sorted(p for p in os.listdir(seam)) if os.path.isdir(seam) else []
    except OSError:
        return []
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            text = (seam / name).read_text(encoding="utf-8")
            marker = json.loads(text)
        except (OSError, ValueError):
            continue
        if not isinstance(marker, dict):
            continue
        job = _job_from_marker(marker, now=_)
        if job is not None:
            out.append(job)
    return out


@dataclass
class RedPenActionTrigger:
    """A ``TriggerSource`` polling the ``redpen-actions`` seam: ``poll()`` returns one ``SecurityJob`` per
    well-formed published Fix/Retest marker, or ``[]`` (flag off / none / malformed). It PRODUCES, never
    executes (the queue + ``jobs.runner`` are the sole executor)."""

    base_dir: Any
    now: Optional[float] = None

    def poll(self) -> "list[SecurityJob]":
        try:
            return redpen_action_jobs_from_seam(self.base_dir, now=self.now)
        except Exception:  # noqa: BLE001 — a flaky seam read never sinks the drain
            return []


__all__ = [
    "REDPEN_FIX_ACTION", "REDPEN_RETEST_ACTION", "REDPEN_ACTION_SEAM_SUBDIR",
    "VERIFIED_FIXED", "STILL_VULNERABLE",
    "ReReview", "RedPenFixResult", "RetestResult", "ProofResolver", "ReproFixVerdict",
    "refire_reproduction", "build_reproduction_fix_oracle",
    "verify_before_pr", "redpen_fix_this", "make_redpen_fix_worker",
    "redpen_retest", "make_redpen_retest_worker",
    "redpen_action_jobs_from_seam", "RedPenActionTrigger",
]
