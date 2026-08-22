"""sx-s1 — THE single authoritative Strix runtime adapter.

WHY THIS MODULE EXISTS. Before this slice VIGIL started the vendored Strix agent from several places with
DIFFERENT amounts of pre-flight: the Ops Console (``launch_assessment`` codebase + ``retry_run``) ran the
full pre-flight — resolve the per-session model, gate model egress against the sovereignty tier, pin the
sandbox onto the gated network, hand the child its proof-run dir and the engagement base dir — but the
``vigil strix`` super-CLI verb dispatched the raw ``.venv-offense/bin/strix`` console-script with NONE of
it: no sandbox network pin (the container landed on Docker's default bridge, a route to the LAN / internet /
169.254.169.254), no proof-run dir, no model/sovereignty gate, and — the concrete bug — it never set
``VIGIL_BASE_DIR``, so the child's WARDEN gate re-rooted its approvals dir to the process CWD and, finding no
provisioned owner authority there, HARD-BLOCKED every ``exec_command`` the agent tried. A "bare"
``.venv-offense/bin/strix`` invocation had the same gap.

WHAT IT PROVIDES.

  * ``resolve_strix_bin()`` — the ONE place the Strix executable is located.
  * ``resolve_base_dir()`` — the engagement base dir the child's WARDEN reads for the provisioned owner
    authority + approvals root, returned as an ABSOLUTE path so a child that chdir's (or a ``vigil strix``
    run from any CWD) can no longer re-root the approvals dir and hard-block every ``exec_command``.
  * ``strix_child_env()`` — the single assembler of a gated Strix child's env overrides (proof-run dir,
    engagement slug, the absolute base dir, the sandbox-network pin, the per-session model pin, the
    loopback ``api_base`` pin).
  * ``prepare()`` — the FULL pre-flight for a launch: resolve model / gate sovereignty → pre-flight the
    sandbox network (gateway running + gated network present, pin the sandbox onto it) → resolve the
    absolute base dir → assemble the child env. Returns a gated ``LaunchDecision`` or a fail-closed refusal
    (any missing/ambiguous gate decision is DENY, never proceed ungated).
  * ``launch()`` / ``main()`` — the entry the ``vigil strix`` verb routes to: pre-flight, then exec the real
    agent with the gated environment. So the CLI paths finally run the SAME pre-flight the console does.

BOUNDARY (FATAL-2). This module lives in the integration plane and must import cleanly in BOTH the offense
and the sovereign leg (the production-invariants board imports every ``vigil_integration`` module in both).
So every ``framework``/``strix`` import here is FUNCTION-LOCAL — reached only on the offense-plane launch
path, never at module import — and it NEVER imports ``sigil``. The sovereignty gate is not re-implemented
here: it reuses the ONE tested console implementation (``framework.v2.console.actions``) so the CLI and the
console can never drift into two different egress policies.

HONEST BOUND. For the ``vigil strix`` CLI path this adapter drives the full pre-flight and the child
process lifecycle (spawn → wait → exit code); artifacts land under ``VIGIL_PROOF_RUN_DIR`` via the vendored
agent's own proof sink. Active container health-monitoring and per-run teardown beyond process lifecycle,
and folding the console's own background-supervision spawn into this same adapter, are not part of this
slice — see the slice's honest residual. The gated network itself is created/owned by ``vigil services up``
(the gateway lifecycle); this adapter verifies it and pins onto it, it does not create it.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

#: The base-dir convention shared with the ``vigil`` sub-CLI (``--base-dir`` defaults) and the console.
DEFAULT_BASE_DIR = ".vigil-live"


def resolve_strix_bin() -> str:
    """The ONE place the vendored Strix console-script is located.

    Prefer the ``strix`` that sits beside the running interpreter — the offense venv both the console and
    this adapter run in (``.venv-offense/bin/strix``) — so a child spawned with a scrubbed ``PATH`` still
    finds it; else fall back to ``PATH``; else the bare name (a caller that already has it on ``PATH``).
    Total: never raises.
    """
    try:
        cand = Path(sys.executable).resolve().parent / "strix"
        if cand.exists():
            return str(cand)
    except Exception:  # noqa: BLE001 — a weird sys.executable must never crash the locator
        pass
    return shutil.which("strix") or "strix"


def resolve_base_dir(explicit: Optional[str] = None) -> str:
    """THE engagement base dir the spawned Strix child's WARDEN reads for the provisioned owner authority +
    approvals root, as an ABSOLUTE path.

    Precedence: ``explicit`` argument > ``$VIGIL_BASE_DIR`` > the ``.vigil-live`` convention — absolutized
    ONCE, here. Absolutizing is the fix for the ``vigil strix`` hard-block: a relative ``.vigil-live`` (the
    default) is resolved against whatever CWD the child happens to have, so an agent that chdir's, or a CLI
    run from a different directory than where ``vigil approve provision-authority`` wrote the authority,
    finds an EMPTY base and every ``exec_command`` fails closed with "no approval authority provisioned".
    Pinning an absolute path resolved at launch time keeps the child bound to the operator's provisioned
    authority regardless of any later chdir. Total: never raises.
    """
    raw = explicit or os.environ.get("VIGIL_BASE_DIR") or DEFAULT_BASE_DIR
    try:
        return os.path.abspath(os.path.expanduser(str(raw)))
    except Exception:  # noqa: BLE001 — a pathological value must not sink the launch; return it unmodified
        return str(raw)


def strix_child_env(*, base_dir: Optional[str], run_dir: str, slug: str,
                    sandbox_env: Optional[dict] = None, llm_env: Optional[dict] = None,
                    alias_extra: Optional[dict] = None) -> dict[str, str]:
    """Assemble a gated Strix child's environment overrides in ONE place, in ONE precedence.

    Base layer — the VIGIL run context every gated Strix launch needs: the proof-run dir (the vendored
    agent's ``install_from_env`` proof sink writes proofs + evidence under it), the engagement slug, and the
    ABSOLUTE base dir (so the child's WARDEN finds the provisioned authority; see ``resolve_base_dir``).
    Then, merged LAST so they WIN: the sandbox-network pin, the per-session model pin, and the loopback
    ``api_base`` pin — mirroring how the console's ``_spawn_background`` merges ``env_extra`` over
    ``os.environ`` for the child.
    """
    out: dict[str, str] = {
        "VIGIL_PROOF_RUN_DIR": str(run_dir),
        "VIGIL_ENGAGEMENT": str(slug or ""),
        "VIGIL_BASE_DIR": resolve_base_dir(base_dir),
    }
    out.update(sandbox_env or {})
    out.update(llm_env or {})
    out.update(alias_extra or {})
    return out


@dataclass(frozen=True)
class LaunchDecision:
    """The verdict of :func:`prepare`. ``ok`` gates the spawn; a non-empty ``refusal`` must abort it.

    ``env`` is the child-env overrides (merged over ``os.environ`` for the child); ``remove`` names env
    keys to delete AFTER the merge (the sovereignty positive-control's stripped ``api_base`` siblings).
    ``banner`` is the loud line printed when an operator explicitly accepted ungated egress.
    """

    ok: bool
    refusal: str = ""
    banner: str = ""
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    remove: list[str] = field(default_factory=list)
    slug: str = ""
    run_dir: str = ""


# (refusal_message, alias_extra, alias_remove) — the model-egress gate's verdict for a resolved STRIX_LLM env.
SovereigntyGate = Callable[[dict], "tuple[str, dict, list]"]


def _default_sovereignty_gate(llm_env: dict) -> "tuple[str, dict, list]":
    """Gate model egress + compute the loopback ``api_base`` pin, reusing the ONE tested console
    implementation so the CLI and the console can never drift into two different sovereignty policies.

    Returns ``(refusal, alias_extra, alias_remove)``: a non-empty ``refusal`` aborts the launch (the active
    sovereignty tier forbids the backend the child would dial); ``alias_extra``/``alias_remove`` are the
    positive-control pin/strip that keeps a permitted LOCAL run on-host. Fail-closed: if the policy engine
    cannot even be loaded/evaluated, that is a refusal, never a silent proceed.

    Framework import is FUNCTION-LOCAL (offense-plane only; never ``sigil`` → FATAL-2 holds) and only ever
    runs on the real launch path — never at module import, so this module still loads in the sovereign leg.
    """
    try:
        from framework.v2.console import actions as _actions  # offense-plane vendored engine; never sigil
    except Exception as exc:  # noqa: BLE001 — no policy engine ⇒ cannot decide ⇒ refuse (fail-closed)
        return ((f"the Strix model-egress policy engine could not be loaded "
                 f"({type(exc).__name__}: {exc}); refusing rather than risk egressing off-host"), {}, [])
    try:
        refusal = _actions._strix_sovereignty_refusal(llm_env)
        if refusal:
            return refusal, {}, []
        alias_extra, alias_remove = _actions._strix_child_alias_guard(llm_env)
        return "", dict(alias_extra or {}), list(alias_remove or [])
    except Exception as exc:  # noqa: BLE001 — "cannot decide" is never "permitted"
        return ((f"the Strix model-egress policy could not be evaluated ({type(exc).__name__}); "
                 f"refusing the run rather than risk egressing off-host"), {}, [])


_SLUG_FLAGS = ("--target", "--mount")


def _sanitize_slug(raw: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]", "-", str(raw or "")).strip("-.")
    return (slug or "strix-cli")[:64]


def derive_slug(argv: Sequence[str]) -> str:
    """A best-effort engagement slug from the Strix argv (the ``--target``/``--mount`` basename, or an
    explicit ``--slug``), for the run dir + ``VIGIL_ENGAGEMENT``. Never raises; defaults to ``strix-cli``."""
    argv = list(argv)
    for i, a in enumerate(argv):
        a = str(a)
        if a == "--slug" and i + 1 < len(argv):
            return _sanitize_slug(argv[i + 1])
        if a.startswith("--slug="):
            return _sanitize_slug(a.split("=", 1)[1])
    for i, a in enumerate(argv):
        a = str(a)
        for flag in _SLUG_FLAGS:
            if a == flag and i + 1 < len(argv):
                return _sanitize_slug(Path(str(argv[i + 1])).name)
            if a.startswith(flag + "="):
                return _sanitize_slug(Path(a.split("=", 1)[1]).name)
    return "strix-cli"


def _make_run_dir(base_dir: str, slug: str) -> str:
    """A fresh proof-run dir under the engagement base dir. Best-effort mkdir; returns the path either way."""
    rd = Path(base_dir) / "runs" / f"{slug}-{int(time.time())}"
    try:
        rd.mkdir(parents=True, exist_ok=True)
    except Exception:  # noqa: BLE001 — a mkdir failure must not crash pre-flight; the sink degrades gracefully
        pass
    return str(rd)


def prepare(argv: Sequence[str], *, base_dir: Optional[str] = None, run_dir: Optional[str] = None,
            slug: Optional[str] = None, llm_env: Optional[dict] = None,
            allow_ungated: Optional[bool] = None, networking=None,
            sovereignty_gate: Optional[SovereigntyGate] = None) -> LaunchDecision:
    """Run the FULL Strix pre-flight and return a gated :class:`LaunchDecision` (or a fail-closed refusal).

    Order (every refusal precedes any spawn):
      1. resolve model → gate model egress against the sovereignty tier (reused console policy), and compute
         the loopback ``api_base`` positive-control pin/strip;
      2. pre-flight the sandbox network — REFUSE unless the gateway is running and the gated network exists,
         and pin the sandbox onto it (``strix_sandbox.preflight``);
      3. resolve the ABSOLUTE base dir + a proof-run dir;
      4. assemble the child env.

    ``networking``/``sovereignty_gate`` are injectable seams for tests (so the pre-flight is exercised with
    no Docker and no framework import). Total: never raises — any unexpected failure is a refusal.
    """
    argv = list(argv)
    slug = slug or derive_slug(argv)
    llm_env = dict(llm_env or {})
    gate = sovereignty_gate or _default_sovereignty_gate

    # (1) model egress gate — fail-closed
    try:
        sov_refusal, alias_extra, alias_remove = gate(llm_env)
    except Exception as exc:  # noqa: BLE001 — a gate that raises is a refusal, never a bypass
        return LaunchDecision(ok=False, slug=slug,
                              refusal=f"the Strix model-egress gate failed ({type(exc).__name__}: {exc}); "
                                      f"refusing rather than risk egressing off-host")
    if sov_refusal:
        return LaunchDecision(ok=False, slug=slug, refusal=str(sov_refusal))

    # (2) sandbox network pre-flight — fail-closed
    try:
        from .strix_sandbox import preflight, warning_banner
    except Exception as exc:  # noqa: BLE001 — cannot verify egress confinement ⇒ refuse
        return LaunchDecision(ok=False, slug=slug,
                              refusal=f"the Strix sandbox egress pre-flight could not be loaded "
                                      f"({type(exc).__name__}: {exc}); refusing to start an agent whose "
                                      f"traffic cannot be confined to the signed scope")
    sbx = preflight(allow_ungated=allow_ungated, networking=networking)
    if not sbx.ok:
        return LaunchDecision(ok=False, slug=slug,
                              refusal=str(sbx.refusal or "the Strix sandbox could not be pinned to the "
                                          "gated network"))
    banner = warning_banner(sbx)

    # (3) base dir + proof-run dir
    abs_base = resolve_base_dir(base_dir)
    run_dir = run_dir or _make_run_dir(abs_base, slug)

    # (4) child env
    env = strix_child_env(base_dir=abs_base, run_dir=run_dir, slug=slug,
                          sandbox_env=dict(sbx.env), llm_env=llm_env, alias_extra=alias_extra)
    return LaunchDecision(ok=True, banner=banner, argv=argv, env=env, remove=list(alias_remove),
                          slug=slug, run_dir=run_dir)


def launch(argv: Sequence[str], *, base_dir: Optional[str] = None, allow_ungated: Optional[bool] = None,
           networking=None, sovereignty_gate: Optional[SovereigntyGate] = None,
           runner: Optional[Callable[[list, dict], int]] = None) -> int:
    """THE ``vigil strix`` entry: pre-flight, then exec the real agent with the gated environment.

    Returns the agent's exit code, or a non-zero code on a fail-closed refusal (2) / an unexecutable agent
    (127). ``runner`` is an injectable spawn seam for tests; production runs the vendored ``strix`` binary
    with stdio inherited (so its interactive TUI works), mirroring the console's ``_spawn_background`` env
    merge: ``{**os.environ, **decision.env}`` then delete ``decision.remove`` (case-insensitive).
    """
    decision = prepare(argv, base_dir=base_dir, allow_ungated=allow_ungated, networking=networking,
                       sovereignty_gate=sovereignty_gate)
    if not decision.ok:
        print(f"vigil strix: refused — {decision.refusal}", file=sys.stderr)
        return 2
    if decision.banner:
        print(decision.banner, file=sys.stderr)

    child_env = {**os.environ, **decision.env}
    if decision.remove:
        _rm = {str(k).upper() for k in decision.remove}
        for _k in [k for k in child_env if str(k).upper() in _rm]:
            child_env.pop(_k, None)

    strix = resolve_strix_bin()
    cmd = [strix, *decision.argv]
    if runner is not None:
        return int(runner(cmd, child_env))
    try:
        return subprocess.run(cmd, env=child_env).returncode  # noqa: S603 — argv list, no shell
    except OSError as exc:
        print(f"vigil strix: cannot execute the Strix agent at {strix!r} ({exc}) — the offense environment "
              f"looks corrupt/half-built; rebuild with envs/build_envs.sh.", file=sys.stderr)
        return 127


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Module entry (``python -m vigil_integration.strix_runtime …``) the ``vigil strix`` verb routes to."""
    return launch(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
