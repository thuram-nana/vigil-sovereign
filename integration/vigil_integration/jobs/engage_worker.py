"""
jobs.engage_worker — the customer-launch WORKER (slice K4-3), invoked ONLY by ``JobRunner.run_one``.

A worker runs an AUTHORIZED ``SecurityJob`` and returns its result; it is called ONLY after the hard
authorization gate (``authorize_job`` + ``build_customer_launch_gate``) allows the job, never by a trigger.
:func:`make_engage_worker` builds the worker that drives CRUCIBLE's EXISTING governed execution — it
lazy-imports ``framework.v2.engage.run_engagement`` (no duplicate engine) and runs it under the job's
owner-signed ``cust_<hash>`` engagement slug. The engine's own gate chain (``_run_gates``: authority +
kill-switch → scope → destructive-confirm → budget → rate-limit → egress floor) AND the single-use arm
(``_engage_launch_lease_precondition`` → ``verify_customer_launch_lease(consume=True)``, the ONE
authoritative consume) re-enforce everything at execution; the worker adds no bypass.

Defence-in-depth at the EXECUTION boundary (beyond the scheduling-time gate):
  * the engagement HOST is bound AUTHORITATIVELY from the VERIFIED customer ``EngagementAuthority``'s
    exact-host scope — NOT from the (advisory) ``job.extra`` seed — so a tampered carrier cannot steer the
    scan off the verified asset; and
  * the K4 production-disable flag is RE-CHECKED here: a ``LIVE`` customer target is refused while
    ``customer_prod_execution_enabled()`` is False (TWIN / STAGING / loopback proceed), so even a mis-wired
    gate cannot run a live customer engagement with the flag off.

Integration-layer code: ``.model`` (pure) at module scope; ``framework`` (engage + authority) and
``vigil_core`` (posture + TargetEnvironment) are imported LAZILY inside the worker — NO ``framework`` at
module scope, NO ``sigil`` import, NO execution at import (two-env boundary).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from vigil_core.seam_base import resolve_seam_base

from .model import SecurityJob

_ATTEMPTS_DIRNAME = ".engage-attempts"


#: M1c-2b — the worker outcome a METERED run reports when the model gateway STOPS it for want of prepaid credit.
#: Deliberately NOT a ``vigil_core.EngagementOutcome`` (``completed`` / ``canceled`` / ``failed``): those are the
#: SETTLE triggers, and a credit pause must NEVER settle — the launch is parked, not charged and not refunded.
PAUSED_CREDIT_OUTCOME = "paused_credit"


@dataclass(frozen=True)
class CreditPaused:
    """M1c-2b — the result a worker returns when a METERED run's prepaid credits are exhausted mid-run. The launch
    is PARKED, not failed and not completed: its owner-signed lease is HELD unsettled (neither charged nor
    refunded, never tombstoned), and the single-use floor is held re-armable (the resume-required marker), so W3's
    resume-after-top-up (§11.6) re-arms the SAME lease WITHOUT re-burning it. ``outcome`` is the distinct
    ``paused_credit`` tag the seam reports (``JobRunner.run_one`` → ``JobOutcome.result``); a RETURN (never a raise)
    keeps the one-shot delivery, so the launch does NOT re-drive into the still-exhausted gateway. The W3 interface
    this slice defines: the held, unsettled lease + the worker's resume-required marker + this outcome; W3 adds the
    SOVEREIGN-side credit-pause record, the resume trigger and the 7-day close. Carries ONLY public identity
    (slug + nonce) — no key, no amount (FATAL-2 / money-silent)."""

    engagement_slug: str
    nonce: str
    outcome: str = PAUSED_CREDIT_OUTCOME


#: M1c-2b — the env a METERED run must NEVER carry: the persisted provider key, its hot-reload flag, the Anthropic
#: SDK's key sibling (``ANTHROPIC_AUTH_TOKEN`` — a stale one would bypass the grant), and the api-base siblings a
#: Strix / LiteLLM child resolves BEFORE ``LLM_API_BASE`` (a stray one would repoint it off the loopback gateway).
#: ``_model_grant_scope`` unsets every one of these for the run and restores them exactly on exit.
_GRANT_SCOPE_UNSET = (
    "SIGIL_ANTHROPIC_API_KEY",
    "VIGIL_LIVE_KEY_RELOAD",
    "ANTHROPIC_AUTH_TOKEN",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
)


#: A customer launch re-drives (resume) on a transient worker failure up to this many arm attempts; the LAST
#: attempt is TERMINAL — only its failure emits a refunding FAILED completion. This bounds the FAILED emit to
#: a terminal abandonment so a transient-fail-then-succeed (re-drive) never spools a FAILED that would RACE
#: the eventual COMPLETED into a free run, AND a permanently-failing launch still terminates (the terminal
#: FAILED settles + tombstones the lease, so the launch poller stops re-enqueuing it).
_MAX_ARM_ATTEMPTS = 3


def _mark_attempt(base_dir: Any, slug: str, nonce: str) -> "tuple[int, bool]":
    """Record a durable per-``(slug, nonce)`` arm attempt and return ``(ATTEMPT COUNT, slot_created)``. Numbered
    ``O_EXCL`` markers under ``.engage-attempts``: the Nth distinct call creates ``<key>.<N>`` and returns N.
    Count 1 is a FRESH arm (``run_engagement`` consumes the single-use floor); count > 1 is a RE-DRIVE (resume —
    the arm re-validates WITHOUT re-burning the floor, so a crash-after-consume re-delivery is not stranded as a
    'replay'); count >= ``_MAX_ARM_ATTEMPTS`` is the TERMINAL attempt (its failure is a real abandonment, not a
    transient retry). FAIL-SAFE: an unusable marker store returns ``(1, False)`` (a FRESH, NON-terminal arm — it
    never silently resumes an un-attempted lease, and never reports TERMINAL off a broken store, so a transient
    failure is never mis-refunded). The key is ``sha256(slug\\x00nonce)``; a genuine re-lease (new nonce) gets a
    NEW key ⇒ a fresh count.

    ``slot_created`` is True ONLY when THIS call actually minted a new numbered slot. It is False on the two
    paths that mint NO slot — the FAIL-SAFE OSError (``(1, False)``) and SATURATED (``(MAX+1, False)``) returns —
    so a later in-flight-pause rollback (:func:`_release_attempt`) can be gated on it and never unlink a slot
    THIS attempt did not create (which would be a PRIOR attempt's, silently eroding crash budget)."""
    base = base_dir if base_dir is not None else resolve_seam_base()
    key = hashlib.sha256((str(slug) + "\x00" + str(nonce)).encode("utf-8")).hexdigest()
    try:
        d = Path(base) / _ATTEMPTS_DIRNAME
        d.mkdir(parents=True, exist_ok=True)
        for n in range(1, _MAX_ARM_ATTEMPTS + 2):      # 1..MAX+1; the first free slot is THIS attempt's number
            try:
                fd = os.open(d / f"{key}.{n}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                return n, True
            except FileExistsError:
                continue
        return _MAX_ARM_ATTEMPTS + 1, False            # all slots taken ⇒ beyond max (terminal); minted NO slot
    except OSError:
        return 1, False                                # fail-safe: fresh, NON-terminal arm; minted NO slot


#: pause/resume PR-3 — the suffix of the durable per-(slug,nonce) "the floor was burned; the next arm must
#: RESUME" marker, written when an in-flight PAUSE rolls back its attempt slot (so the rollback does not reset
#: the resume decision to a floor-RE-burning fresh arm). Lives beside the numbered attempt markers.
_RESUME_MARK_SUFFIX = "resume"


def _attempt_key(slug: str, nonce: str) -> str:
    """The shared ``.engage-attempts`` key for ``(slug, nonce)`` — the SAME hash :func:`_mark_attempt` uses, so
    the rollback and resume-required markers address the same slot family."""
    return hashlib.sha256((str(slug) + "\x00" + str(nonce)).encode("utf-8")).hexdigest()


def _release_attempt(base_dir: Any, slug: str, nonce: str, attempt: int) -> None:
    """pause/resume PR-3 — roll back THIS attempt's numbered marker so an in-flight PAUSE never consumes
    crash-attempt budget (``_MAX_ARM_ATTEMPTS``). ``_mark_attempt`` always hands out the LOWEST free slot, so the
    slot just taken is the current maximum; deleting exactly it keeps the slots contiguous and a genuine CRASH
    still advances toward the terminal attempt. Best-effort: a failed unlink leaves the slot (the pause then
    counts as one crash attempt — fail-SAFE toward eventual termination, NEVER toward a never-terminating launch
    or a lost refund). No nonce / bad attempt ⇒ no-op."""
    if not nonce or attempt < 1:
        return
    base = base_dir if base_dir is not None else resolve_seam_base()
    with contextlib.suppress(OSError):
        (Path(base) / _ATTEMPTS_DIRNAME / f"{_attempt_key(slug, nonce)}.{attempt}.json").unlink()


def _record_resume_required(base_dir: Any, slug: str, nonce: str) -> None:
    """pause/resume PR-3 — durably record that THIS (slug,nonce)'s single-use floor WAS burned and the next arm
    MUST resume (verify + re-bind, NOT re-consume), so an in-flight pause whose attempt slot was rolled back
    re-drives WITHOUT a replay refusal. Idempotent ``O_CREAT``; keyed per (slug,nonce) so a genuine re-lease
    (new nonce) is unaffected. Best-effort: a failed write degrades to a one-cycle replay refusal that self-heals
    on the next re-drive (``attempt > 1`` then holds) — money-safe (never a double-charge)."""
    if not nonce:
        return
    base = base_dir if base_dir is not None else resolve_seam_base()
    with contextlib.suppress(OSError):
        d = Path(base) / _ATTEMPTS_DIRNAME
        d.mkdir(parents=True, exist_ok=True)
        fd = os.open(d / f"{_attempt_key(slug, nonce)}.{_RESUME_MARK_SUFFIX}.json", os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)


def _resume_required(base_dir: Any, slug: str, nonce: str) -> bool:
    """pause/resume PR-3 — True iff a prior in-flight pause POSITIVELY recorded that THIS (slug,nonce)'s floor
    was burned (so the arm must RESUME, not re-consume). FAIL-CLOSED toward FRESH: any read error ⇒ False. This
    direction is the money-safe one — a false False causes at worst a one-cycle replay refusal that self-heals
    (``attempt > 1`` on the next re-drive), whereas a false True would make a FRESH arm SKIP the single-use
    consume and leave the floor un-burned (a replayable lease). No nonce ⇒ False."""
    if not nonce:
        return False
    base = base_dir if base_dir is not None else resolve_seam_base()
    try:
        return (Path(base) / _ATTEMPTS_DIRNAME / f"{_attempt_key(slug, nonce)}.{_RESUME_MARK_SUFFIX}.json").is_file()
    except OSError:
        return False


def _is_engagement_paused(exc: BaseException) -> bool:
    """pause/resume PR-3 — True iff ``exc`` is the engine's re-driveable in-flight pause halt
    (``framework.v2.engage.EngagementPaused``). Lazy + guarded (FATAL-2: no ``framework`` at module scope). By
    the time a run has raised, the runner has already imported ``framework.v2.engage``, so this is a cheap
    ``sys.modules`` lookup. SAFE DEFAULT = False: if the type cannot be resolved the exception is treated as a
    NORMAL failure (the transient/terminal FAILED path), never silently converted into a held, infinitely
    re-driven launch — the money-dangerous direction is a false POSITIVE, which ``isinstance`` cannot produce."""
    try:
        from framework.v2.engage import EngagementPaused
    except Exception:  # noqa: BLE001 — cannot classify ⇒ treat as a normal failure (safe default)
        return False
    return isinstance(exc, EngagementPaused)


def _lease_currently_paused(base_dir: Any, slug: str, nonce: str) -> bool:
    """pause/resume PR-4 (HARD #2) — True iff THIS (slug, nonce) lease is paused RIGHT NOW. Used to classify a
    NON-``EngagementPaused`` run failure as a gate→arm-window pause (the PRECONDITION raised ``EngagementRefused``
    because the lease was paused AFTER the pickup gate passed but BEFORE the arm) vs a genuine failure.
    ``is_lease_paused`` is total + fail-closed (a corrupt marker ⇒ True/held — correct, the pickup gate refuses
    it too). FAIL toward False (the genuine-failure/terminal path) ONLY when the seam import is unavailable, so a
    REAL failure with NO pause marker is never wrongly held — a false POSITIVE here would re-drive forever. No
    nonce ⇒ False."""
    if not nonce:
        return False
    try:
        from vigil_integration.live.credit_lease_pause import is_lease_paused
        return bool(is_lease_paused(base_dir, slug, nonce))
    except Exception:  # noqa: BLE001 — cannot read the pause store ⇒ treat as a genuine failure (terminates)
        return False


def _is_credits_exhausted(exc: BaseException) -> bool:
    """M1c-2b — True iff ``exc`` is the engine's terminal METERED credit stop
    (``framework.v2.common.errors.CreditsExhausted``). Lazy + guarded (FATAL-2: no ``framework`` at module scope).
    By the time a run has raised, the runner has imported ``framework``, so this is a cheap ``sys.modules`` lookup.
    SAFE DEFAULT = False: a type that cannot be resolved is treated as a NORMAL failure (the transient/terminal
    FAILED path), never silently converted into a held, unsettled launch — the money-dangerous direction is a
    false POSITIVE, which ``isinstance`` cannot produce."""
    try:
        from framework.v2.common.errors import CreditsExhausted
    except Exception:  # noqa: BLE001 — cannot classify ⇒ treat as a normal failure (safe default)
        return False
    return isinstance(exc, CreditsExhausted)


def _grant_model_effort(token: str, root: Any) -> "Optional[tuple[str, str]]":
    """M1c-2b — decode the owner-signed model-grant ``token`` for its ``(model, effort)``, verifying under the
    owner key the worker ALREADY loaded (``root``'s authorizer pubkeys — the SAME trust root the arm verifies the
    lease under). The gateway ADMITS only the grant's model (a wrong model → provider 400), so the model MUST be
    the grant's — never a derived ``VIGIL_RUN_MODEL`` that could have drifted since publish; the effort is the
    grant's (the one the gateway pins). Returns ``(model, effort)`` or ``None`` (no root / no authorizer pubkey, or
    the token does not verify / is malformed). Lazy (two-env): ``vigil_core`` only, no ``framework``. Total:
    never raises; never logs the token."""
    try:
        from vigil_core.model_grant import decode_token
    except Exception:  # noqa: BLE001 — verifier unavailable ⇒ cannot confirm the grant (fail-closed)
        return None
    try:
        pubkeys = [str(getattr(a, "public_key_b64", "") or "").strip()
                   for a in (getattr(root, "authorizers", None) or [])]
    except Exception:  # noqa: BLE001 — an odd trust root ⇒ no pubkeys (fail-closed)
        return None
    for pk in pubkeys:
        if not pk:
            continue
        grant, _reason = decode_token(token, pk)      # total: (grant, "") or (None, reason), never raises
        if grant is not None:
            model = str(getattr(grant, "model", "") or "").strip()
            effort = str(getattr(grant, "effort", "") or "").strip()
            if model and effort:
                return model, effort
    return None


def _read_run_model_grant(base_dir: Any, slug: str, nonce: str, root: Any
                          ) -> "tuple[Optional[Any], str, str]":
    """M1c-2b — resolve THIS launch's MODEL GRANT (a metered run) or confirm it is a FLAT run, BEFORE the arm.

    The sovereign plane writes a per-launch owner-signed grant to the seam at a METERED publish, BEFORE the lease
    it mints the job from, so a metered launch's job always has its grant when the worker runs (the keyless
    "this run is metered" signal — §15.5). Returns ``(bundle, model, effort)``:

      * ``(None, "", "")`` — a FLAT launch: no grant published for this slug ⇒ byte-identical (no gateway, no
        env scope). Also the no-nonce / defensive case (a grant is nonce-bound; a job with no launch nonce is not
        a metered launch).
      * ``(bundle, model, effort)`` — a METERED launch: the owner-verified grant bound to THIS nonce + its decoded
        model/effort.

    RAISES ``RuntimeError`` BEFORE the arm (so the single-use floor is never burned) when this is a METERED
    context with no USABLE grant: a grant published for this slug but absent for this nonce / malformed, or one
    whose token does not verify under the owner key. A metered launch must never arm without its model access —
    it would run with no gateway (or reach for an inherited provider key), the exact leak this slice closes.
    Keyless + lazy (``framework`` is never imported here)."""
    if not nonce:
        return None, "", ""
    base = base_dir if base_dir is not None else resolve_seam_base()   # the engine arm reads the same seam base
    from vigil_integration.live.model_grant_broker import grant_path, read_model_grant
    bundle = read_model_grant(base, slug, expect_nonce=nonce)
    if bundle is not None:
        me = _grant_model_effort(str(getattr(bundle, "token", "") or ""), root)
        if me is None:
            raise RuntimeError(
                f"engage worker: the model grant for {slug!r} does not verify under the owner key — refusing "
                f"the metered run BEFORE the arm (fail-closed; the single-use floor is not burned)")
        return bundle, me[0], me[1]
    # No usable grant bound to THIS launch. Is a grant FILE nonetheless present for the slug (a metered launch
    # whose grant is absent for this nonce / malformed)? Then this is a metered context with no model access —
    # refuse before the arm rather than run it unmetered. A broken presence probe reads as "no file" (flat).
    try:
        gp = grant_path(base, slug)
        present = gp is not None and os.path.lexists(gp)
    except Exception:  # noqa: BLE001 — a presence probe that breaks ⇒ treat as no file (flat)
        present = False
    if present:
        raise RuntimeError(
            f"engage worker: a model grant was published for {slug!r} but none is usable for this launch "
            f"(absent for its nonce / malformed) — refusing the metered run BEFORE the arm (fail-closed; the "
            f"single-use floor is not burned)")
    return None, "", ""


@contextlib.contextmanager
def _model_grant_scope(bundle: Any, model: str, effort: str) -> "Iterator[None]":
    """M1c-2b — scope a METERED run's model environment to its owner-signed grant + the loopback model gateway for
    the duration of ONE run, restoring EXACTLY on exit (each key back to its prior value, or UNSET when it had
    none). ``bundle is None`` ⇒ a NO-OP (a flat run: byte-identical). While it is active, every model call of the
    run — the kernel Anthropic backend, the live think step, a Strix child — spends the grant through the gateway
    and NEVER the provider key: the gateway (``ANTHROPIC_BASE_URL`` / ``LLM_API_BASE``) and the grant as the key
    (``ANTHROPIC_API_KEY`` / ``LLM_API_KEY`` / ``VIGIL_MODEL_GRANT``) are set, the Anthropic backend is pinned
    (``CRUCIBLE_LLM_BACKEND=anthropic``) with routing off (``CRUCIBLE_MODEL_ROUTING=0``) at the grant's model
    (``CRUCIBLE_ANTHROPIC_MODEL`` / ``STRIX_LLM``) and effort (``CRUCIBLE_EFFORT``), and the provider-key env is
    UNSET (:data:`_GRANT_SCOPE_UNSET`). Mutating ``os.environ`` for the whole run is safe ONLY because
    ``JobRunner.run_one`` serialises jobs — one job at a time under the per-slug run lease, so ``os.environ`` is
    stable for the run and every in-process sample reads the same values (the SAME assumption
    :func:`_model_routing_scope` relies on)."""
    if bundle is None:
        yield
        return
    token = str(getattr(bundle, "token", "") or "")
    gateway = str(getattr(bundle, "gateway_url", "") or "")
    set_env = {
        "ANTHROPIC_BASE_URL": gateway,
        "ANTHROPIC_API_KEY": token,
        "VIGIL_MODEL_GRANT": token,
        "CRUCIBLE_LLM_BACKEND": "anthropic",
        "CRUCIBLE_MODEL_ROUTING": "0",
        "CRUCIBLE_ANTHROPIC_MODEL": model,
        "CRUCIBLE_EFFORT": effort,
        "STRIX_LLM": f"anthropic/{model}",
        "LLM_API_BASE": gateway,
        "LLM_API_KEY": token,
    }
    touched = list(set_env.keys()) + list(_GRANT_SCOPE_UNSET)   # snapshot EVERY key we set OR unset
    prev = {k: os.environ.get(k) for k in touched}
    try:
        for k, v in set_env.items():
            os.environ[k] = v
        for k in _GRANT_SCOPE_UNSET:
            os.environ.pop(k, None)
        yield
    finally:
        for k in touched:
            if prev[k] is None:
                os.environ.pop(k, None)                 # restore EXACTLY: a key that was unset goes back to unset
            else:
                os.environ[k] = prev[k]


#: W4 — the model gateway's worker-time heartbeat path (mirrors ``sigil.model_gateway.WORKER_HEARTBEAT_PATH``;
#: hard-coded here because the keyless worker must not import the sovereign plane — FATAL-2).
_WORKER_HEARTBEAT_PATH = "/v1/vigil/worker/heartbeat"
#: W4 — how often (seconds) a metered run pings the gateway while it runs. The SOVEREIGN gateway measures the
#: interval and bills the worker time; the worker only pings (it never self-reports a number). Smaller than the
#: gateway's worker slot (default 60 s) so every interval stays well inside the slot it reserved.
_WORKER_HEARTBEAT_INTERVAL_ENV = "VIGIL_WORKER_HEARTBEAT_INTERVAL_S"
_DEFAULT_WORKER_HEARTBEAT_INTERVAL_S = 30.0
#: Terminal HTTP codes a heartbeat gets: a bad / expired / closed / credit-exhausted grant (401 / 403) or a gateway
#: that does not serve the endpoint (404 / 405). On any of these the worker stops pinging; a credit pause then flows
#: through the model path (W3). Everything else (200, a transient 0, a busy 429 / 529) keeps the heartbeat going.
_HEARTBEAT_STOP_CODES = frozenset({401, 403, 404, 405})


def _worker_heartbeat_interval_s() -> float:
    """``VIGIL_WORKER_HEARTBEAT_INTERVAL_S`` (seconds, >= 1), default 30. A bad / sub-second value falls back to the
    default (a heartbeat is best-effort; it never fails a run over a misconfigured interval)."""
    raw = (os.environ.get(_WORKER_HEARTBEAT_INTERVAL_ENV) or "").strip()
    if not raw:
        return _DEFAULT_WORKER_HEARTBEAT_INTERVAL_S
    try:
        v = float(raw)
    except ValueError:
        return _DEFAULT_WORKER_HEARTBEAT_INTERVAL_S
    return v if v >= 1.0 else _DEFAULT_WORKER_HEARTBEAT_INTERVAL_S


def _post_heartbeat(gateway_url: str, token: str, *, timeout: float = 10.0) -> int:
    """POST an EMPTY worker-time heartbeat to the loopback model gateway, authenticated by the run's grant token.
    Returns the HTTP status (200 on success; the gateway's own 4xx/5xx code; 0 on a transient connection error, which
    the caller treats as non-terminal). The worker sends no number — the sovereign gateway measures the time between
    pings. stdlib only (FATAL-2: the keyless worker never imports the sovereign plane); proxies are bypassed so the
    loopback gateway is reached directly, never through a relay that would see the bearer grant."""
    import urllib.error
    import urllib.request
    url = gateway_url.rstrip("/") + _WORKER_HEARTBEAT_PATH
    req = urllib.request.Request(url, data=b"", method="POST",
                                 headers={"x-api-key": token, "content-type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return int(getattr(resp, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:  # noqa: BLE001 — a transient failure is never fatal to the run; the next beat retries
        return 0


@contextlib.contextmanager
def _worker_heartbeat_scope(bundle: Any, *, post: "Optional[Callable[[str, str], int]]" = None,
                            interval_s: "Optional[float]" = None) -> "Iterator[None]":
    """W4 — while a METERED run executes, ping the model gateway's worker-time endpoint so the SOVEREIGN side meters
    the run's worker time. ``bundle is None`` (a FLAT run) ⇒ a NO-OP (byte-identical: no thread, no network). It
    sends one ping at START (opens the first slot; bills nothing), one every ``interval_s`` while the run executes,
    and one FINAL ping on exit (commits the last slot's elapsed). The keyless worker sends NO number — it only pings;
    the gateway measures the interval and bounds each to the slot it reserved, so the worker can neither inflate the
    time nor be charged for time it did not run. Best-effort: a transient error never breaks the run; a TERMINAL
    refusal (:data:`_HEARTBEAT_STOP_CODES` — a bad / closed / exhausted grant, or a gateway without the endpoint)
    stops the pings (a credit pause then flows through the model path, W3). The periodic ping runs on a daemon
    thread so it never delays the run, and ``JobRunner.run_one`` serialises jobs, so one run's heartbeat never
    overlaps another's. ``post`` / ``interval_s`` are injectable for tests."""
    if bundle is None:
        yield
        return
    token = str(getattr(bundle, "token", "") or "")
    gateway = str(getattr(bundle, "gateway_url", "") or "")
    if not token or not gateway:
        yield                                  # a malformed bundle: never block the run on a missing heartbeat target
        return
    send = post if post is not None else _post_heartbeat
    interval = _worker_heartbeat_interval_s() if interval_s is None else float(interval_s)
    stop = threading.Event()
    dead = threading.Event()                   # set once the gateway refused a ping terminally

    def _ping() -> bool:
        """One ping; True iff the gateway refused it TERMINALLY. Never raises (a transient error is not terminal)."""
        try:
            return int(send(gateway, token)) in _HEARTBEAT_STOP_CODES
        except Exception:  # noqa: BLE001 — a heartbeat is best-effort: it never breaks the run
            return False

    if _ping():                                # the first ping opens the slot (bills nothing)
        yield                                  # already terminal (e.g. the grant is exhausted): the model path pauses
        return

    def _loop() -> None:
        while not stop.wait(interval):
            if _ping():
                dead.set()                     # that refusing ping already committed the open slot: stop pinging
                return

    beater = threading.Thread(target=_loop, name="vigil-worker-heartbeat", daemon=True)
    beater.start()
    try:
        yield
    finally:
        stop.set()
        beater.join(timeout=2.0)               # no periodic ping may race the final one
        if not dead.is_set():
            _ping()                            # a final ping commits the last slot's elapsed time before the settle


#: The low-impact self-serve engage profile. Customer authorities are minted ``allow_destructive=False``
#: (``add_customer_target``), so the engine's destructive-confirm gate already refuses destructive tools; the
#: run therefore stays read-only/non-destructive without a special flag. Left empty = run_engagement's
#: defaults (its finite request/page budgets are a fail-safe OPSEC cap, and the owner-signed authority
#: ``max_actions`` caps it further); a deployment may inject a tighter profile via ``profile_kwargs``.
_LOW_IMPACT_PROFILE: "dict[str, Any]" = {}


def _default_run_engagement(*, slug: str, seed_url: str, **kw: Any) -> Any:
    """Invoke CRUCIBLE's existing governed engage path. Lazy (two-env): ``framework`` is imported only here,
    at run time, never at module scope."""
    from framework.v2.engage import run_engagement
    return run_engagement(slug, seed_url, **kw)


def _default_run_tier_enabled() -> bool:
    """The default EC-7 gate: the SHARED ``vigil_core`` reader of ``VIGIL_TIERED_PRODUCTS`` (NO ``sigil``
    import — FATAL-2; the sovereign ``config.tiered_products_enabled`` mirrors the same leaf). Lazy: vigil_core
    is imported at call time, never at module scope. OFF ⇒ the worker derives/applies no run tier."""
    from vigil_core import run_tier
    return run_tier.tiered_products_enabled()


def _default_read_depth(slug: str, host: str, tenant: Optional[str], *, base_dir: Any, now: Any) -> Optional[str]:
    """Read the launch's OWNER-SIGNED depth via the SAME verified+bound lease EC-3 reads for its ceiling
    (authoritative, verify-ONLY — never consumes the single-use floor, never trusts ``job.extra``): the depth the lease
    names (W2b-3, a metered launch), else the tier its signed ``units_reserved`` derive. Lazy (two-env): ``framework``
    is imported only here. Fail-closed: any missing / forged / wrong-host / wrong-tenant / expired / settled lease ⇒
    ``None`` (the caller then classifies the SMALLER 'quick' tier)."""
    from framework.v2.launch_lease import read_verified_launch_depth
    return read_verified_launch_depth(slug, host, tenant, base_dir=base_dir, now=now)


def _depth_from_units(read_units: "Callable[..., Optional[int]]") -> "Callable[..., Optional[str]]":
    """A depth reader over an injected units reader (tests): the tier those units derive (None/bad ⇒ "quick")."""
    def _read(*a: Any, **k: Any) -> Optional[str]:
        from vigil_core import run_tier
        return run_tier.run_tier_for_units(read_units(*a, **k))
    return _read


@contextlib.contextmanager
def _model_routing_scope(enabled: Optional[bool]) -> "Iterator[None]":
    """Scope the EC-2a model-routing lever (``CRUCIBLE_MODEL_ROUTING``) to the EC-7 run tier for the duration
    of ONE run, restoring the prior value EXACTLY on exit (including unset). ``enabled is None`` ⇒ a NO-OP
    (byte-identical: EC-7 off, so the deployment's own routing setting stands untouched). ``True`` turns the
    cheaper per-binding tiers ON for a 'quick' run; ``False`` forces every binding to its capable model for a
    'deep' run (fail-toward-capable). Scoping the WHOLE ``run_engagement`` call is correct even though the run
    spawns parallel self-consistency samples — the worker runs one job at a time (``JobRunner.run_one``), so
    ``os.environ`` is stable for the run and every in-process sample reads the same value."""
    if enabled is None:
        yield
        return
    key = "CRUCIBLE_MODEL_ROUTING"
    prev = os.environ.get(key)
    os.environ[key] = "1" if enabled else "0"
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = prev


def _launch_governance_signers(base_dir: Any) -> "list[tuple[str, str]]":
    """Load the STABLE offense-governance signer for this ``base_dir`` as ``[(key_id, priv_b64)]`` — the same
    key the sovereign launch step (``ui.launch_governance``) owner-DELEGATED at launch, so the crossing + the
    completion signal this worker emits verify under that delegation. vigil_core-only (no framework); the key
    is loaded-or-created under the engagement base (sealed under the vault when provisioned)."""
    from vigil_integration.live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
    )
    base = base_dir if base_dir is not None else resolve_seam_base()
    kp = load_or_create_governance_keypair(path=str(Path(base) / DEFAULT_GOVERNANCE_KEY_FILE))
    return [(GOVERNANCE_KEY_ID, kp.private_key_b64)]


def _completion_spool(base_dir: Any, completion_spool_dir: Any, slug: str) -> str:
    """The completion settle-spool this worker emits to. An explicit ``completion_spool_dir`` is used as-is
    (the caller controls it). The DEFAULT is PER-SLUG — ``base/completion-spool/<slug>/`` — so each tenant's
    completions land in their OWN spool (K4-5 red-pen MED): a per-slug-scoped settle-drain then reads only its
    own tenant's completions and can never atomically-claim + quarantine (destroy) another tenant's valid
    completion out of a shared incoming/ dir."""
    if completion_spool_dir is not None:
        return str(completion_spool_dir)
    base = base_dir if base_dir is not None else resolve_seam_base()
    return str(Path(base) / "completion-spool" / str(slug))


def _finding_spool(base_dir: Any, finding_spool_dir: Any, slug: str) -> str:
    """The FACT finding-spool this worker crosses to. Explicit path used as-is; the DEFAULT is PER-SLUG
    (``base/finding-spool/<slug>/``) for the same per-tenant isolation as the completion spool."""
    if finding_spool_dir is not None:
        return str(finding_spool_dir)
    base = base_dir if base_dir is not None else resolve_seam_base()
    return str(Path(base) / "finding-spool" / str(slug))


def make_engage_worker(
    *,
    base_dir: Any = None,
    trust_root: Any = None,
    run: "Optional[Callable[..., Any]]" = None,
    profile_kwargs: "Optional[dict[str, Any]]" = None,
    prod_execution_enabled: "Optional[Callable[[], bool]]" = None,
    run_tier_enabled: "Optional[Callable[[], bool]]" = None,
    read_units: "Optional[Callable[..., Optional[int]]]" = None,
    read_depth: "Optional[Callable[..., Optional[str]]]" = None,
    now: Any = None,
    finding_spool_dir: Any = None,
    completion_spool_dir: Any = None,
    signers: "Optional[list]" = None,
    emit_completion: bool = True,
    heartbeat_post: "Optional[Callable[[str, str], int]]" = None,
    heartbeat_interval_s: "Optional[float]" = None,
) -> "Callable[[SecurityJob], Any]":
    """Build the customer-launch worker: ``(SecurityJob) -> result``. Invoked ONLY by ``JobRunner.run_one``,
    i.e. only after ``build_customer_launch_gate`` allowed the job. It loads the VERIFIED customer authority
    for the job's slug, binds the seed host authoritatively from its exact-host scope, re-checks the K4
    production-disable flag (a ``LIVE`` target needs the explicit opt-in), then drives ``run_engagement`` —
    whose arm consumes the single-use lease and whose gate chain re-enforces scope + egress. Any precondition
    failure RAISES (``JobRunner`` turns a worker error into a ``failed`` outcome + ``release_delivery``, so
    the work is re-driveable, never a silent false-clean).

    EC-7 (tiered Quick/Deep products): when ``run_tier_enabled()`` is True the worker reads the run's depth
    from the launch's OWNER-SIGNED lease (``read_depth`` — the SAME verified+bound lease EC-3 reads,
    authoritative, never the tamperable ``job.extra``): the depth the lease names (W2b-3: a metered launch, whose
    units are only an allowance chunk), else the tier its ``units_reserved`` derive (an injected ``read_units``
    derives it the same way) — and overlays the depth's engagement roster
    (``engage.profile_kwargs`` — a 'deep' launch runs the full browser/SSO/GraphQL/access-control roster, a
    'quick' launch the lean default) + sets the EC-2a model-routing lever for the run (quick ⇒ cheaper tiers
    on; deep ⇒ capable models). OFF by default ⇒ byte-identical: no derivation, run_engagement's own default
    roster, ``CRUCIBLE_MODEL_ROUTING`` untouched. A bad/absent/unverifiable lease fails SAFE to the smaller
    'quick' tier (never silently escalates a run to the fuller, more expensive 'deep').

    ``run`` / ``prod_execution_enabled`` / ``run_tier_enabled`` / ``read_units`` / ``read_depth`` / ``trust_root`` are
    injectable for tests (a mock engine + mock flags + a stub units reader + an explicit owner root) so the
    full wiring is exercised deterministically without a live scan."""
    def _worker(job: SecurityJob) -> Any:
        from framework.v2.authority.store import load_authority_root, load_verified_authority
        from vigil_core.authority import TargetEnvironment
        from vigil_core.posture import customer_prod_execution_enabled

        root = trust_root if trust_root is not None else load_authority_root()
        if root is None:
            raise RuntimeError("engage worker: no authority trust root pinned (fail-closed)")
        authority = load_verified_authority(job.slug, root)        # raises on an unverifiable / absent authority
        if authority is None:
            raise RuntimeError(f"engage worker: no verified authority for {job.slug!r}")
        if not str(getattr(authority, "issued_by", "")).startswith("customer:"):
            raise RuntimeError("engage worker: not a customer engagement authority (issued_by != 'customer:')")
        scope = list(getattr(authority, "scope", None) or [])
        host = scope[0] if scope else ""
        if not host:
            raise RuntimeError("engage worker: customer authority has no scope host (fail-closed)")
        # K4 production-disable RE-CHECK at the execution boundary (defence-in-depth over the gate).
        enabled = prod_execution_enabled or customer_prod_execution_enabled
        if authority.environment == TargetEnvironment.LIVE and not enabled():
            raise RuntimeError(
                "engage worker: production-target customer execution is disabled (K4 flag off) — refusing a "
                "LIVE customer-target arm until VIGIL_CUSTOMER_PROD_EXECUTION is explicitly enabled")
        seed_url = f"https://{host}"                               # AUTHORITATIVE seed (authority scope, not extra)
        # K4-5a crash-after-arm fix: a FRESH arm consumes the single-use floor; a RE-DRIVE must RESUME (the
        # arm re-validates + re-binds the lease WITHOUT re-burning the floor), else a worker crash AFTER the
        # arm consumed but before completion strands the paid reservation as a 'replay' on re-delivery. The
        # durable per-(slug,nonce) attempt marker distinguishes the two: the FIRST attempt arms fresh, any
        # later attempt resumes. Single-use integrity is preserved — resume still re-validates owner-pin /
        # bind / settlement, and two concurrent arms of one slug are serialized by the per-slug run lease; the
        # marker only governs whether THIS (slug,nonce) re-burns its own floor. No nonce ⇒ fresh arm (safe).
        nonce = str((job.extra or {}).get("nonce") or "")
        attempt, _slot_created = _mark_attempt(base_dir, job.slug, nonce) if nonce else (1, False)
        # a re-drive resumes (K4-5a), never re-burns the floor. pause/resume PR-3: an in-flight PAUSE rolls its
        # attempt slot back (so pauses never consume crash-attempt budget), so ``attempt`` alone can read 1 on a
        # post-pause re-drive even though the floor WAS burned on the original arm — the resume-required marker
        # makes RESUME hold regardless, so the re-drive re-validates/re-binds WITHOUT re-burning the floor into a
        # replay refusal.
        resume = (attempt > 1) or _resume_required(base_dir, job.slug, nonce)
        terminal = attempt >= _MAX_ARM_ATTEMPTS                    # the LAST attempt: its failure is a real abandonment
        runner = run if run is not None else _default_run_engagement
        kwargs = dict(_LOW_IMPACT_PROFILE if profile_kwargs is None else profile_kwargs)
        kwargs.pop("resume", None)                                 # resume is a worker concern, never a profile key
        kwargs.pop("launch_nonce", None)                           # ...and so is the launch identity
        # Bind the run to THIS job's launch. The seam holds ONE lease per slug and a customer slug is reused by
        # every launch of the same (org, host), so the lease on the seam can be a LATER launch's: the engine then
        # refuses before its arm (so this job never burns that launch's single-use floor) and binds its pause
        # halt + resume state to this nonce, never to whichever lease is on the seam. No nonce ⇒ not passed
        # (the engine keeps its seam read, as before).
        if nonce:
            kwargs["launch_nonce"] = nonce
        # EC-7 — tiered Quick/Deep run profile (default-OFF ⇒ byte-identical). When the owner has enabled
        # tiered products, read the run's depth from the launch's OWNER-SIGNED lease (the SAME verified+bound lease
        # EC-3 reads for its token ceiling — authoritative, never the tamperable job.extra): the depth it names
        # (W2b-3), else the tier its units_reserved derive. Then OVERLAY the depth's engagement roster (additively —
        # the profile system only ever UNIONS flags on) and HOLD the EC-2a routing lever for the run. A bad / absent /
        # unverifiable lease ⇒ None ⇒ "quick" (fail-SAFE: the smaller-impact, cheaper depth — never a silent
        # escalation to a fuller, costlier one).
        tier_enabled = run_tier_enabled if run_tier_enabled is not None else _default_run_tier_enabled
        read_d = (read_depth if read_depth is not None
                  else _depth_from_units(read_units) if read_units is not None else _default_read_depth)
        routing_override: Optional[bool] = None
        if tier_enabled():
            from framework.v2.engage import profile_kwargs as _engage_profile_kwargs
            from vigil_core import run_tier
            tier = run_tier.depth_of(read_d(job.slug, host, (job.tenant_id or None), base_dir=base_dir, now=now)
                                     or "quick", None)             # None/bad ⇒ "quick" (fail-safe)
            kwargs["profile"] = run_tier.engage_profile_for(tier)  # surface|full — the roster NAME (manifest-recorded)
            kwargs.update(_engage_profile_kwargs(kwargs["profile"]))   # the enable_* passes that roster turns ON
            routing_override = run_tier.routing_enabled_for(tier)  # quick ⇒ cheaper tiers on; deep ⇒ capable models
            # L1 (live Max) — overlay the depth's per-ENGAGEMENT controls (pricing design §6). Only the "max"
            # depth carries them (engage_controls_for); quick/deep get the inert baseline, so NOTHING is added for
            # them (byte-identical — the kwargs are passed only when non-default). A Max run is held to ONE rate
            # limit + connection cap for the whole engagement (a single global throttle, not per-tool) and to
            # governed tools only — the engine enforces both inside run_engagement / the gated executor.
            controls = run_tier.engage_controls_for(tier)
            if controls.governed_tools_only:
                kwargs["governed_tools_only"] = True
            if controls.min_request_interval_s > 0.0:
                kwargs["per_engagement_rate_floor_s"] = controls.min_request_interval_s
            if controls.connection_cap > 0:
                kwargs["per_engagement_connection_cap"] = controls.connection_cap
        # M1c-2b — a METERED customer run reaches a model ONLY through the loopback model gateway, spending its
        # owner-signed grant. Read the grant published for THIS launch (written BEFORE the lease, so it is always
        # present for a metered launch's job — the keyless "this run is metered" signal): a usable grant ⇒ metered,
        # scope its env around the runner (below) and force model-routing OFF (the gateway admits only the grant's
        # model, so a quick-tier route would 400); a grant FILE present but unusable ⇒ a metered launch with no
        # model access ⇒ _read_run_model_grant REFUSES here, BEFORE the arm, so this job never burns the single-use
        # floor; no grant ⇒ a FLAT launch (byte-identical: grant_bundle is None ⇒ the scope below is a no-op).
        grant_bundle, grant_model, grant_effort = _read_run_model_grant(base_dir, job.slug, nonce, root)
        if grant_bundle is not None:
            routing_override = False       # a metered run never routes — belt to the engine's own routing_enabled()
        # K4-5d(B): the completion SEAM. Load the owner-delegated offense-governance signers BEFORE the arm
        # (fail-closed — a run that could never settle must not consume the lease), then:
        #   run succeeds → cross the confirmed FACTs (best-effort) + emit a COMPLETED settle signal (REQUIRED —
        #                  the billing trigger: the sovereign settle-drain reads it and settles to consumption);
        #   run raises   → emit a FAILED settle signal (consumed=0, full refund) then RE-RAISE, so JobRunner
        #                  still marks the job failed + release_delivery (re-driveable), and the paid reservation
        #                  is refunded rather than stranded as consumed.
        # Both signals are governance-SIGNED and verified sovereign-side against the launch's owner delegation
        # (ui.launch_governance). No nonce ⇒ no settle binding ⇒ no emit (defensive; launch jobs always carry one).
        do_settle = bool(emit_completion and nonce)
        sgnrs = (signers if signers is not None else _launch_governance_signers(base_dir)) if do_settle else None
        try:
            with _model_grant_scope(grant_bundle, grant_model, grant_effort):  # M1c-2b: metered env (no-op when flat)
                with _model_routing_scope(routing_override):      # EC-7: scope CRUCIBLE_MODEL_ROUTING to the tier (no-op when off)
                    # W4 — meter the run's worker time on the sovereign side while it executes (no-op when flat).
                    with _worker_heartbeat_scope(grant_bundle, post=heartbeat_post, interval_s=heartbeat_interval_s):
                        result = runner(slug=job.slug, seed_url=seed_url, resume=resume, **kwargs)
        except Exception as _run_exc:  # noqa: BLE001 — a run failure re-raises (JobRunner -> failed + release_delivery -> re-drive)
            # M1c-2b — a METERED run whose prepaid credits are exhausted (the model gateway's terminal credit stop)
            # is a reversible CREDIT PAUSE, not a failure: HOLD the lease for a W3 top-up + resume. Classify it
            # FIRST (by TYPE, not message) so it: emits NO settle signal — no COMPLETED charge, no FAILED refund,
            # the lease stays unsettled, neither tombstoned nor refunded (the sovereign credit-pause record is W3);
            # and mirrors the cooperative-pause bookkeeping (roll the attempt slot back + record resume-required),
            # so repeat credit pauses never exhaust _MAX_ARM_ATTEMPTS and the eventual resume re-validates / re-binds
            # WITHOUT re-burning the single-use floor into a replay refusal. Then RETURN the distinct
            # ``paused_credit`` outcome (never a raise): JobRunner keeps the one-shot delivery, so the launch is
            # PARKED — it does NOT re-drive into the still-exhausted gateway. W3's resume-after-top-up (§11.6)
            # re-triggers it from the held lease + the resume-required marker.
            if _is_credits_exhausted(_run_exc):
                if nonce:
                    if _slot_created:
                        _release_attempt(base_dir, job.slug, nonce, attempt)
                    _record_resume_required(base_dir, job.slug, nonce)
                return CreditPaused(engagement_slug=job.slug, nonce=nonce)
            # pause/resume PR-3 — a COOPERATIVE in-flight PAUSE halt is NOT a failure; it is a re-driveable
            # transient. Classify it by TYPE (not by message) BEFORE the FAILED-settle path so a paused launch:
            #   * NEVER emits the terminal refunding FAILED settle (the lease is HELD for resume, not refunded or
            #     tombstoned — no premature refund, and the launch poller keeps re-driving), and
            #   * rolls its attempt slot back + records resume-required, so repeat pause/resume can NEVER exhaust
            #     ``_MAX_ARM_ATTEMPTS`` into a spurious terminal abandonment, and the eventual resume re-drive
            #     re-validates/re-binds WITHOUT re-burning the single-use floor into a replay refusal.
            # Then re-raise unchanged, so JobRunner still marks the job failed + release_delivery → re-enqueue.
            if _is_engagement_paused(_run_exc):
                if nonce:
                    # Roll back ONLY a slot THIS attempt actually minted — on the _mark_attempt fail-safe /
                    # saturated paths no slot was created, and unlinking ``<key>.<attempt>`` there would delete a
                    # PRIOR attempt's slot and silently erode crash budget. resume-required is recorded
                    # regardless (the floor burn it reflects is independent of whether a slot was minted).
                    if _slot_created:
                        _release_attempt(base_dir, job.slug, nonce, attempt)
                    _record_resume_required(base_dir, job.slug, nonce)
                raise
            # pause/resume PR-4 (HARD #2) — a NON-EngagementPaused failure whose lease is NOW paused is the
            # gate→arm-window pause: the precondition raised EngagementRefused because the lease was paused AFTER
            # the pickup gate passed but BEFORE _advance_floor, so the single-use floor was NOT burned. Treat it
            # as a REVERSIBLE halt: emit NO FAILED settle (no premature refund/tombstone — the seam poller holds a
            # paused lease and re-produces on resume; PR-A's pickup gate catches any racing re-pickup), roll back
            # the do-nothing attempt slot, and record NO resume-required (the floor was NOT burned, so the re-arm
            # MUST consume — recording it would skip the burn = a replayable lease / free run). Re-raise ⇒
            # JobRunner release_delivery + the launch re-drives. FAIL-SAFE: a genuine failure with no pause marker
            # is NOT held (it terminates normally) — see _lease_currently_paused.
            if nonce and _lease_currently_paused(base_dir, job.slug, nonce):
                if _slot_created:
                    _release_attempt(base_dir, job.slug, nonce, attempt)
                raise
            # Emit a refunding FAILED completion ONLY on the TERMINAL attempt. A transient failure (attempt <
            # _MAX_ARM_ATTEMPTS) re-drives WITHOUT a premature refund, so it can never spool a FAILED that RACES
            # the eventual COMPLETED into a free run (the K4-5 red-pen HIGH). The terminal FAILED settles +
            # tombstones the lease, so a permanently-failing launch still terminates (the poller stops re-driving).
            if do_settle and terminal:
                try:
                    from .completion_signal import emit_completion_signal
                    emit_completion_signal(engagement_slug=job.slug, nonce=nonce, outcome="failed",
                                           signers=sgnrs, spool_dir=_completion_spool(base_dir, completion_spool_dir, job.slug))
                except Exception:  # noqa: BLE001 — a failed-settle emit is best-effort; never mask the run error
                    pass
            raise
        if do_settle:
            # FDX-2: a COMPLETED run's settle DEPENDS on its confirmed FACTs being durably crossed to the
            # sovereign finding spool FIRST — the COMPLETED signal's very existence must prove the FACTs
            # crossed, so a paid run can never settle with its FACTs lost. CAUTION: cross_confirmed_findings
            # is TOTAL — it COUNTS a per-finding durability/sign/serialize failure (e.g. an unwritable finding
            # spool) and RETURNS a CrossingResult WITHOUT raising (findings_crossing.py). So merely CALLING it
            # is not a gate; we must INSPECT the result and raise on `errors`, else a swallowed spool-write
            # failure falls through to the COMPLETED emit — the exact FACT-loss-while-charging hole this slice
            # closes. On a raise, JobRunner marks the job failed + release_delivery, so the launch RE-DRIVES
            # (resume re-reaches completion and the crossing retries; the finding spool's content-addressed
            # dedup + the receiver's two-anchor ingest make the retry idempotent, so an already-crossed FACT
            # lands exactly once). Money-safe: a crossing that keeps erroring HOLDS the reservation (never
            # charges) rather than recognising revenue on a run whose FACTs were lost; a FACT that does not
            # re-fire legitimately degrades to a LEAD (counted in `leads`, NOT crossed, NOT an error) and does
            # not block. The terminal FAILED path (above) still refunds a genuine run failure.
            from .findings_crossing import cross_confirmed_findings, findings_from_report
            found = findings_from_report(getattr(result, "report", None))
            if found:
                crossing = cross_confirmed_findings(
                    found, engagement_slug=job.slug, signers=sgnrs,
                    spool_dir=_finding_spool(base_dir, finding_spool_dir, job.slug))
                if crossing.errors:
                    raise RuntimeError(
                        f"findings crossing incomplete for {job.slug}: {crossing.errors} of {len(found)} "
                        f"confirmed FACT(s) failed to cross durably (crossed={crossing.crossed}, "
                        f"leads={crossing.leads}) — refusing to emit the COMPLETED settle signal so the launch "
                        f"re-drives rather than settle with its FACTs lost")
            from .completion_signal import emit_completion_signal
            emit_completion_signal(engagement_slug=job.slug, nonce=nonce, outcome="completed",
                                   signers=sgnrs, spool_dir=_completion_spool(base_dir, completion_spool_dir, job.slug))
        return result
    return _worker
