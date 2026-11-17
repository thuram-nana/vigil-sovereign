"""
redpen.reproduce — refute a lens candidate by REPRODUCING it in the S5 sandbox, twice (design §7.2 §3).

A candidate survives to certification only if its proof-of-concept FIRES against the reviewed commit in
the network-isolated, workspace-confined bubblewrap sandbox (:func:`live.sandbox_exec.run_sandboxed`:
``--unshare-net``, no egress, writable only inside the workspace) and does so TWICE — a defect that fires
once and not again is a flake, not a finding. The second run is what buys "no flakes"; nothing is minted
below two independent fires.

This module is the EVIDENCE PRODUCER, not the judge: it runs the PoC, decides "fired" from the candidate's
declared markers over the captured stdout+stderr, and hands the captured bytes to :mod:`redpen.certify`,
where the deterministic oracle is the sole authority on whether a FACT exists. It sets
``provenance="reproduced"`` ONLY when both runs fired — the first of the two independent refusals that back
the twice-fire requirement (``confirm_and_certify``'s own G4 gate is the second).

Fail-closed honesty:
  * the sandbox being unavailable (no ``bwrap``) is an HONEST SKIP — ``status="unavailable"`` with
    ``fired_twice=False`` — NEVER a FACT and never a silent pass;
  * a candidate that declares no fire markers cannot be judged "fired" (no marker = fail-closed not-fired);
  * a timed-out / spawn-errored run does not count as a fire.

Import-clean: ``live.sandbox_exec`` is stdlib-only, so this module pulls no ``framework`` at import
(FATAL-2). The sandbox is an injectable seam (``sandbox=``) so tests drive it with a deterministic fake —
no ``bwrap``, no network.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..live.sandbox_exec import SandboxOutcome, SandboxUnavailable, run_sandboxed

DEFAULT_REPRO_TIMEOUT = 30.0
DEFAULT_RUNS_REQUIRED = 2   # the "twice" of design §7.2 §3 — do NOT lower without lowering the bar.

# The sandbox seam: a pre-bound runner taking the PoC command and returning a SandboxOutcome. The default
# binds run_sandboxed to the workspace; tests inject a fake (no bwrap, no network).
SandboxFn = Callable[[str], SandboxOutcome]


@dataclass(frozen=True)
class Reproduction:
    """The outcome of a twice-run sandbox reproduction.

      * ``status``       — ``"reproduced"`` (fired on every required run), ``"not_reproduced"`` (fired
        fewer times than required — a flake or no fire), ``"unavailable"`` (the sandbox could not run —
        an honest skip), or ``"error"`` (an unexpected failure driving the sandbox).
      * ``fired_twice``  — fired on ALL ``runs_required`` runs (True only for ``status=="reproduced"``).
      * ``provenance``   — ``"reproduced"`` iff ``fired_twice``, else ``""``; the value ``certify`` forwards
        to ``confirm_and_certify`` (a non-reproduced run can never back a signed FACT).
      * ``stdout`` / ``stderr`` / ``request_value`` — the captured evidence the oracle later judges.
    """

    status: str
    fired_twice: bool
    fires: int
    runs: int
    provenance: str
    stdout: str = ""
    stderr: str = ""
    request_value: str = ""
    reason: str = ""


def _fired(outcome: SandboxOutcome, markers: "tuple[str, ...]", mode: str) -> bool:
    """Did this run fire? True iff the candidate's declared markers are present in the captured
    stdout+stderr. Fail-closed: no markers, a timed-out run, or a spawn error (no exit code) is NOT a
    fire — a reproduction must positively demonstrate the defect's signature."""
    if not markers:
        return False
    if getattr(outcome, "timed_out", False):
        return False
    blob = (outcome.stdout or "") + "\n" + (outcome.stderr or "")
    present = [m for m in markers if m and m in blob]
    if mode == "all":
        return len(present) == len([m for m in markers if m])
    return bool(present)


def _bind_default_sandbox(workspace: Any, timeout: float) -> SandboxFn:
    """The real sandbox runner, bound to the workspace. Kept here (not at import) so a missing ``bwrap``
    surfaces only when a reproduction actually runs — as a :class:`SandboxUnavailable`, which
    :func:`reproduce_candidate` turns into an honest ``unavailable`` skip, never a FACT."""
    return functools.partial(run_sandboxed, workspace=workspace, timeout=timeout)


def reproduce_candidate(
    candidate: Any,
    *,
    workspace: Any,
    sandbox: "Optional[SandboxFn]" = None,
    timeout: float = DEFAULT_REPRO_TIMEOUT,
    runs_required: int = DEFAULT_RUNS_REQUIRED,
) -> Reproduction:
    """Run ``candidate``'s PoC in the sandbox ``runs_required`` times and require it to FIRE every time.

    ``candidate`` carries ``poc_command`` (the shell command run inside the box), ``fire_markers`` (the
    substrings whose presence in the captured output means "fired") and ``fire_mode`` (``"any"``/``"all"``,
    default ``"any"``); for the request-side channel it also carries ``request_value`` (the decoded payload
    the twice-fired run proves reaches the sink). ``sandbox`` is the injectable runner (default: the real
    ``run_sandboxed`` bound to ``workspace``).

    Returns a :class:`Reproduction`. ``provenance="reproduced"`` is set ONLY when the PoC fired on all
    required runs — the first independent refusal behind the twice-fire bar.
    """
    command = str(getattr(candidate, "poc_command", "") or "").strip()
    markers = tuple(getattr(candidate, "fire_markers", ()) or ())
    mode = str(getattr(candidate, "fire_mode", "any") or "any")
    request_value = str(getattr(candidate, "request_value", "") or "")
    runs_required = max(1, int(runs_required))

    if not command:
        return Reproduction(
            status="not_reproduced", fired_twice=False, fires=0, runs=0, provenance="",
            request_value=request_value, reason="candidate declared no poc_command")

    runner = sandbox if sandbox is not None else _bind_default_sandbox(workspace, timeout)

    # Run EVERY required run and COUNT the fires — do not short-circuit on the first non-fire, so the
    # twice-fire bar (``fires >= runs_required``) is the single load-bearing decision. A flake that fires
    # once and not again counts exactly one fire and is refused below.
    fires = 0
    first_fire: "SandboxOutcome | None" = None
    for _ in range(runs_required):
        try:
            outcome = runner(command)
        except SandboxUnavailable as exc:
            # Honest skip — the sandbox cannot run, so the defect was NOT reproduced. Never a FACT.
            return Reproduction(
                status="unavailable", fired_twice=False, fires=fires, runs=runs_required, provenance="",
                request_value=request_value, reason=f"sandbox unavailable: {exc}")
        except Exception as exc:  # noqa: BLE001 — a reproduction failure must not promote; it demotes.
            return Reproduction(
                status="error", fired_twice=False, fires=fires, runs=runs_required, provenance="",
                request_value=request_value, reason=f"sandbox run failed: {type(exc).__name__}: {exc}")
        if _fired(outcome, markers, mode):
            fires += 1
            if first_fire is None:
                first_fire = outcome

    fired_twice = fires >= runs_required
    return Reproduction(
        status="reproduced" if fired_twice else "not_reproduced",
        fired_twice=fired_twice, fires=fires, runs=runs_required,
        provenance="reproduced" if fired_twice else "",
        stdout=(first_fire.stdout if first_fire else ""),
        stderr=(first_fire.stderr if first_fire else ""),
        request_value=request_value,
        reason="" if fired_twice else f"fired {fires}/{runs_required} runs — not reproduced")
