"""
warden_gate — the WARDEN raise-only tool-NAME floor for offense tools (VIGIL P7 Slice 2).

Every offense tool call is gated by its CLASS/NAME here, not by its target — target authorization
is the P6 egress gateway's job (this gate asserts only "is a tool of THIS class permitted, and does
it need owner approval"). The SIGIL WARDEN kernel classifies a tool name to a tier A0..A3
(danger-first, whole-token, fail-closed to A3). Two facts from the seam map drive this module:

  * Read-shaped offense names auto-classify LOW: ``http.get`` / ``dns.query`` / ``port.list`` all
    contain an A0 verb token and classify to A0, which would AUTO-RUN. So a raise-only FLOOR
    (default A2) is imposed the same ``max()`` way the kernel's own registry raises a pin — the
    floor can only ever RAISE a tool's tier, never lower it.
  * The Governor auto-approves only tiers at/below the auto-bar (A1) AND at/below the agent's
    ceiling. Setting the offense ceiling to A1 with an A2 floor means every offense tool is QUEUED
    for owner approval — offense never auto-runs. (Posture knob: on a TWIN/STAGING target the
    operator may lower the floor to A1 so recon auto-runs while destructive/exec stays A3→queue.)

Classification is delegated to an INJECTABLE classifier (default: the ``sigil-kernel`` binary via
subprocess, which is env-agnostic and fail-closed), so this module imports neither the SIGIL
package nor any offense engine — it is import-clean and lives on the shared integration seam.

The SDK wiring: :func:`attach_from_env` composes ``WardenGateHooks`` onto the Strix ``Runner``'s hooks and is
**ON BY DEFAULT** for any VIGIL-governed run — Strix's arbitrary ``exec_command`` shell tool is classified +
gated as of the first tool call, no opt-in required. An EXPLICIT opt-*out* (``VIGIL_WARDEN_STRIX_GATE`` in
{``0``,``off``,``false``,``no``}) turns it off, reserved for the byte-identical-vendor test / a deliberately
ungoverned standalone run; and if the ``vigil_integration`` package is not importable (a bare vendored Strix
checkout) the runner's soft-import guard leaves the vendor byte-identical. A non-AUTO (QUEUE) decision no
longer hard-blocks: it is routed to the per-action, single-use, owner-signed approval BROKER
(:mod:`live.approval_broker`) — the hook publishes a pending request, waits (bounded by
``VIGIL_APPROVAL_WAIT_SECONDS``, default 0 ⇒ non-blocking) for a token the owner signs for THIS exact call
(``vigil approve sign`` / the Safety screen), verifies it against the deployment-pinned owner key, and spends
its nonce ONCE — then the call runs. No authority provisioned, or no valid token in the window ⇒ the call is
BLOCKED (fail-safe). A hard class ``deny`` (denylist / empty name) always raises immediately. The DECISION
CORE + the approval token/ledger are complete and fully tested.

FATAL-2: this module is import-clean (stdlib only at module scope) so it loads in BOTH environments, but it
is OFFENSE-side — only the offense-env Strix process ever calls :func:`attach_from_env`; the sovereign never
loads it. The SDK (``agents.lifecycle``) and the classifier (``live.wiring.default_classify``) are imported
LAZILY inside the wiring functions, so importing this module never drags the offense engine or the SDK into
the sovereign environment.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

# Tier is represented as the kernel's own string labels ("A0".."A3") + an ordinal, rather than a
# third copy of the Tier enum (the seam map warned the Rust and Python enums must stay in sync;
# a third would be worse). The kernel emits these exact strings.
TIERS: tuple[str, ...] = ("A0", "A1", "A2", "A3")
_ORD = {t: i for i, t in enumerate(TIERS)}

DEFAULT_FLOOR = "A2"    # offense tools floor here — never auto-A0/A1 on a LIVE target
DEFAULT_CEILING = "A1"  # offense agent ceiling — anything above A1 must QUEUE (never auto-approve)
AUTO_BAR = "A1"         # mirrors governor AUTO_BAR: only <=A1 can auto

Classifier = Callable[[str], str]


class WardenDenied(RuntimeError):
    """A tool call the WARDEN gate refuses outright (a class that must never run, or — in the
    fail-safe hook — anything not auto-approved). Raised; must not be silently caught."""


@dataclass(frozen=True)
class ToolDecision:
    tool: str
    tier: str        # the floored, effective tier ("A0".."A3")
    outcome: str     # "auto" | "queue" | "deny"
    reason: str

    @property
    def auto(self) -> bool:
        return self.outcome == "auto"


def _tier_max(a: str, b: str) -> str:
    return a if _ORD.get(a, 3) >= _ORD.get(b, 3) else b


def decide_tool(
    tool_name: str,
    *,
    classify: Classifier,
    floor: str = DEFAULT_FLOOR,
    ceiling: str = DEFAULT_CEILING,
    denylist: Iterable[str] = (),
) -> ToolDecision:
    """Decide a tool call by name. Pure — the classifier is injected. Fail-closed throughout.

    - empty / unknown name or unknown classifier output → DENY (fail-closed A3).
    - a name on ``denylist`` → DENY.
    - else tier = max(classify(name), floor) (raise-only) → AUTO iff tier<=A1 AND tier<=ceiling,
      else QUEUE.
    """
    name = (tool_name or "").strip()
    if not name:
        return ToolDecision("", "A3", "deny", "empty tool name (fail-closed)")
    if name in set(denylist):
        return ToolDecision(name, "A3", "deny", f"tool {name!r} is on the hard denylist")

    base = classify(name)
    if base not in _ORD:
        base = "A3"  # a classifier that returned garbage is treated as maximally dangerous
    fl = floor if floor in _ORD else "A3"
    tier = _tier_max(base, fl)

    if _ORD[tier] <= _ORD[AUTO_BAR] and _ORD[tier] <= _ORD.get(ceiling, 0):
        return ToolDecision(name, tier, "auto", f"{tier} is at/below the auto-bar and the ceiling")
    return ToolDecision(
        name, tier, "queue",
        f"{tier} requires owner approval (>= A2 or above the offense ceiling {ceiling})",
    )


def kernel_classifier(kernel_bin: str | None = None, *, timeout: float = 15.0) -> Classifier:
    """A classifier backed by the ``sigil-kernel classify`` CLI (env-agnostic subprocess).

    NOTE: this is the OPTIONAL real-kernel classifier. The LIVE offense gate wires the pure in-process
    ``live.wiring.default_classify`` (no subprocess), so this factory is exercised only when a caller
    explicitly opts into the Rust kernel. It stays import-clean (no sigil / offense import) by design.

    Returns a function name->tier-string. Fail-closed: ANY failure (missing binary, timeout,
    non-zero exit, unparseable output, unknown tier) yields "A3". Results are cached by name
    (classify is pure/deterministic) so a hook gating many tools does not re-shell per call.

    An UNRESOLVED binary (no explicit ``kernel_bin`` and none on PATH) fail-closes to A3 WITHOUT executing
    a bare ``sigil-kernel`` name — a bare-name exec would resolve via PATH at call time, letting an attacker
    who plants a ``sigil-kernel`` on PATH control tier decisions (the same verify≠exec footgun the sigil
    side's kernel pin closes). Verifying the binary's owner-signed pin here is out of scope until this
    path is wired live (it would need the owner pubkey + manifest plumbed cross-env)."""
    resolved = kernel_bin or shutil.which("sigil-kernel")   # None if unresolved — NO bare-name fallback
    cache: dict[str, str] = {}

    def classify(name: str) -> str:
        if name in cache:
            return cache[name]
        if not resolved:
            return "A3"   # unresolved → fail-closed; never bare-name-exec an attacker-planted PATH binary
        tier = "A3"
        try:
            proc = subprocess.run(
                [resolved, "classify", name, "--json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                import json
                last = proc.stdout.strip().splitlines()[-1]
                obj = json.loads(last)
                t = obj.get("tier") if isinstance(obj, dict) else None
                if t in _ORD:
                    tier = t
        except Exception:
            tier = "A3"  # fail-closed
        cache[name] = tier
        return tier

    return classify


class WardenGateHooks:
    """Duck-typed openai-agents ``RunHooks`` adapter for the tool-name gate.

    Not a subclass of the SDK ``RunHooks`` (the SDK isn't vendored on disk) — it exposes the same
    ``async on_tool_start(context, agent, tool)`` shape so it can be composed/attached once the SDK
    is available. Per the seam map, ``on_tool_start``'s return value is ignored and the ONLY way to
    block a call is to RAISE, so this adapter is deliberately fail-safe: it raises ``WardenDenied``
    for anything that is not an AUTO decision. A QUEUE decision therefore blocks (does not run)
    until the graceful approval-queue wrapper is wired — a future slice upgrades QUEUE from
    hard-block to approve-then-run. Every decision is recorded for audit/testing.
    """

    def __init__(
        self,
        *,
        classify: Classifier,
        floor: str = DEFAULT_FLOOR,
        ceiling: str = DEFAULT_CEILING,
        denylist: Iterable[str] = (),
        approver: Optional[Callable[[str, str, Any], bool]] = None,
    ):
        self._classify = classify
        self._floor = floor
        self._ceiling = ceiling
        self._denylist = tuple(denylist)
        # The per-action owner-approval callback for a QUEUE decision: (tool_name, target, args) -> approved?
        # It publishes a pending request + (bounded) waits for a single-use owner-signed token + spends it.
        # None ⇒ no authority provisioned ⇒ a QUEUE hard-blocks (fail-safe).
        self._approver = approver
        self.decisions: list[ToolDecision] = []

    def evaluate(self, tool_name: str) -> ToolDecision:
        d = decide_tool(
            tool_name, classify=self._classify, floor=self._floor,
            ceiling=self._ceiling, denylist=self._denylist,
        )
        self.decisions.append(d)
        return d

    async def on_tool_start(self, context, agent, tool) -> None:
        # The SDK passes the ACTUAL call arguments on ``context`` (a ToolContext: ``.tool_name`` /
        # ``.tool_arguments`` — the raw args string); ``tool`` is only the static definition. Read the
        # context so the approval binds + displays the REAL command, not a constant (red-pen BLOCK-1).
        name = getattr(context, "tool_name", None) or getattr(tool, "name", None) or str(tool)
        decision = self.evaluate(name)
        # A hard class deny (denylist / empty name) never runs — raise immediately.
        if decision.outcome == "deny":
            raise WardenDenied(
                f"WARDEN gate DENIED tool {name!r}: {decision.reason} (hard class deny — never runs)."
            )
        # AUTO (<= A1 and <= ceiling): allowed.
        if decision.auto:
            return
        # QUEUE (>= A2 / above the offense ceiling) — the WARDEN human leg. Route to the per-action,
        # single-use, owner-signed approval broker. No approver wired (no authority provisioned) ⇒ fail-safe
        # hard-block, exactly as before. A valid, action-bound, single-use owner token ⇒ this ONE call runs.
        if self._approver is None:
            raise WardenDenied(
                f"WARDEN gate blocked tool {name!r}: {decision.outcome} ({decision.reason}); no approval "
                f"authority provisioned (run `vigil approve provision-authority`)."
            )
        target = _strix_target(tool)
        args = _strix_args(getattr(context, "tool_arguments", None))
        try:
            approved = bool(self._approver(name, target, args))
        except Exception as exc:  # noqa: BLE001 — an approver error is fail-closed (block)
            raise WardenDenied(
                f"WARDEN gate blocked tool {name!r}: approval errored ({type(exc).__name__}) — fail-closed."
            )
        if not approved:
            raise WardenDenied(
                f"WARDEN gate blocked tool {name!r}: {decision.outcome} — no valid owner approval within the "
                f"window (sign it with `vigil approve sign` / the Safety screen, then it runs)."
            )
        # owner-approved (per-action, single-use token consumed) → allow this ONE call.


# ---------------------------------------------------------------------------------------------------
# T3 — the Strix runner soft-wire: compose this offense-side gate onto Strix's run hooks, opt-in.
# ---------------------------------------------------------------------------------------------------

# The Strix WARDEN gate is ON BY DEFAULT. This env is an explicit opt-OUT (values below) reserved for the
# byte-identical-vendor test / a deliberately ungoverned standalone run. It is a posture switch only — when on
# it can never LOWER a tier or auto-allow; when off the vendored Strix behaves byte-identically.
_STRIX_GATE_ENV = "VIGIL_WARDEN_STRIX_GATE"
_STRIX_GATE_OFF_VALUES = frozenset({"0", "off", "false", "no"})


def _strix_gate_on() -> bool:
    """The Strix WARDEN gate default: ON. Absent env (or any value not in the OFF set) ⇒ ON. An EXPLICIT
    ``VIGIL_WARDEN_STRIX_GATE`` in {0,off,false,no} ⇒ OFF (byte-identical vendor / ungoverned standalone)."""
    val = os.environ.get(_STRIX_GATE_ENV)
    if val is None:
        return True
    return val.strip().lower() not in _STRIX_GATE_OFF_VALUES


def _strix_base_dir() -> str:
    """The engagement base dir the approvals root + persisted authority live under (matches the console/CLI
    ``VIGIL_BASE_DIR`` convention; defaults to ``.vigil-live``)."""
    return os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"


def _strix_target(tool: Any) -> str:
    """Best-effort approval-binding target for a Strix tool call. Strix's shell/exec tools have NO network
    target (they run locally), so bind them to a constant local sentinel — the single-use nonce still makes
    each queued invocation independently owner-approved."""
    return "strix:exec"


def _strix_args(raw_arguments: Any) -> Any:
    """Normalize the SDK ``ToolContext.tool_arguments`` — the RAW arguments STRING of the ACTUAL tool call
    (NOT the static ``tool`` definition, which carries no call args) — into the value the approval binds and
    the owner sees. A JSON-object string is parsed to a dict (so secret values can be masked in the preview);
    a non-JSON string is bound verbatim (still command-specific); anything else is a stable non-empty
    sentinel. THIS is what makes the token per-command: the ``action_digest`` covers the command, and the
    owner sees the exact command before signing (red-pen BLOCK-1: reading ``tool`` bound a constant)."""
    import json as _json

    if isinstance(raw_arguments, dict):
        return raw_arguments
    if isinstance(raw_arguments, str) and raw_arguments.strip():
        try:
            parsed = _json.loads(raw_arguments)
        except Exception:  # noqa: BLE001 — a non-JSON args string still binds verbatim (command-specific)
            return raw_arguments
        return parsed if isinstance(parsed, (dict, list, str, int, float)) else raw_arguments
    return {"_": "no-args"}


# The Strix arbitrary-execution chokepoint. EVERY CLI invocation the agent makes — nmap, ffuf, python3,
# curl, agent-browser — flows through ``exec_command`` (``write_stdin`` streams input to a still-running
# exec_command process). So gating THESE two names gates all arbitrary execution, while Strix's benign,
# sandbox-contained tools (thinking / notes / todo / web_search / apply_patch / reporting / view_image /
# load_skill / finish) auto-run and the agent stays functional. This is precisely the audit's gap — the
# ungoverned agent shell — and nothing more.
_STRIX_EXEC_TOOLS = frozenset({"exec_command", "write_stdin"})


def _strix_shell_classifier(name: str) -> str:
    """A3 for the Strix arbitrary-exec chokepoint (``exec_command`` / ``write_stdin``) so it QUEUES for owner
    approval under the A1 ceiling; A0 (auto) for every other Strix tool. Deliberately NOT the offense
    ``default_classify`` — that rates every non-recon name A2, which under a default-on gate would block the
    whole agent. This targets the shell and only the shell."""
    return "A3" if str(name or "").strip() in _STRIX_EXEC_TOOLS else "A0"


def _build_strix_approver(base_dir: str) -> Optional[Callable[[str, str, Any], bool]]:
    """Offense-side per-action approver for the Strix shell gate: bind the tool call, publish a pending
    request, (bounded) wait for the owner-signed token, verify it against the deployment-pinned owner key, and
    spend its nonce ONCE. Returns None when no authority is provisioned ⇒ the hook hard-blocks (fail-safe).
    Verification uses the PUBLIC key only, all imports are offense-side + lazy (FATAL-2)."""
    try:
        import time
        from pathlib import Path

        from .live.approval_broker import ApprovalBroker, approvals_root, load_authority
        from .live.approval_token import ApprovalAction, action_digest, consume_token
        from .live.nonce_ledger import NonceLedger
    except Exception:  # noqa: BLE001 — integration/SDK not importable ⇒ no approver ⇒ hard-block (safe)
        return None
    authority = load_authority(base_dir)
    if authority is None:
        return None
    broker = ApprovalBroker(approvals_root(base_dir))
    ledger = NonceLedger(Path(base_dir) / "approval-nonces")

    def approve(tool_name: str, target: str, args: Any) -> bool:
        try:
            act = ApprovalAction(tool_name, target, action_digest(tool_name, target, args))
        except Exception:  # noqa: BLE001 — a non-serialisable action can't be bound ⇒ deny (fail-closed)
            return False
        broker.bind(act, args_preview=args)
        pend = broker.token_source()  # publishes the pending request + (bounded) polls for a signed token
        if not (isinstance(pend, tuple) and len(pend) == 2):
            return False
        token, action = pend
        return bool(
            consume_token(token, action, authority=authority, now=time.time(), ledger=ledger).authorized
        )

    return approve


def compose_run_hooks(*members: Any) -> Any:
    """Compose N openai-agents ``RunHooks``-shaped objects into ONE ``RunHooks`` that fans each lifecycle
    callback out to every member in order. Used to run Strix's existing ``ReportUsageHooks`` (SDK usage /
    budget accounting) AND this module's :class:`WardenGateHooks` (the ``on_tool_start`` tool-name gate) off
    a single hooks object, because the SDK ``Runner`` accepts only one. A member that does not implement a
    given callback is skipped; a ``WardenDenied`` raised by a member's ``on_tool_start`` PROPAGATES (that is
    exactly how a denied classification BLOCKS the tool call). Forwarding is signature-agnostic
    (``*args, **kwargs``) so it is robust to SDK callback-arity changes.

    The SDK base class (``agents.lifecycle.RunHooks``) is imported LAZILY here — offense-env only — so this
    module stays import-clean in the sovereign environment (FATAL-2)."""
    from agents.lifecycle import RunHooks   # lazy — offense/SDK env only; never at module scope (FATAL-2)

    active = [m for m in members if m is not None]

    class _CompositeRunHooks(RunHooks):   # type: ignore[misc,valid-type]
        async def _fan(self, method: str, *args: Any, **kwargs: Any) -> None:
            for m in active:
                fn = getattr(m, method, None)
                if fn is None:
                    continue
                await fn(*args, **kwargs)   # a WardenDenied propagates here → blocks the tool call

        async def on_agent_start(self, *a: Any, **k: Any) -> None:
            await self._fan("on_agent_start", *a, **k)

        async def on_agent_end(self, *a: Any, **k: Any) -> None:
            await self._fan("on_agent_end", *a, **k)

        async def on_handoff(self, *a: Any, **k: Any) -> None:
            await self._fan("on_handoff", *a, **k)

        async def on_tool_start(self, *a: Any, **k: Any) -> None:
            await self._fan("on_tool_start", *a, **k)

        async def on_tool_end(self, *a: Any, **k: Any) -> None:
            await self._fan("on_tool_end", *a, **k)

        async def on_llm_start(self, *a: Any, **k: Any) -> None:
            await self._fan("on_llm_start", *a, **k)

        async def on_llm_end(self, *a: Any, **k: Any) -> None:
            await self._fan("on_llm_end", *a, **k)

    return _CompositeRunHooks()


def attach_from_env(base_hooks: Any) -> Any:
    """Compose this offense-side WARDEN tool-name gate onto Strix's run ``base_hooks``. **ON BY DEFAULT** —
    returns a composite ``RunHooks`` (existing accounting + the WARDEN ``on_tool_start`` gate) unless the
    explicit opt-OUT ``VIGIL_WARDEN_STRIX_GATE`` in {0,off,false,no} is set, or the integration/SDK cannot be
    wired, or ANY failure — in which cases it returns ``base_hooks`` UNCHANGED so a bare vendored Strix stays
    byte-identical and a wiring error can never stop a scan.

    The classifier is :func:`_strix_shell_classifier` (floor A0, ceiling A1): it QUEUES exactly the
    arbitrary-exec chokepoint (``exec_command`` / ``write_stdin``) and auto-runs every other (sandbox-
    contained) Strix tool, so the agent stays functional while its shell is governed. A QUEUE is routed to the
    per-action, single-use, owner-signed approval broker via :func:`_build_strix_approver` — the call runs
    ONLY on a valid owner token for THIS exact call; no authority provisioned / no token in the window ⇒
    hard-block (fail-safe). The SDK + broker are imported LAZILY (offense-env only), keeping this module
    import-clean in the sovereign env (FATAL-2)."""
    if not _strix_gate_on():
        return base_hooks
    try:
        approver = _build_strix_approver(_strix_base_dir())
        warden = WardenGateHooks(classify=_strix_shell_classifier, floor="A0", approver=approver)
        return compose_run_hooks(base_hooks, warden)
    except Exception:  # noqa: BLE001 — never let WARDEN wiring stop a scan; fall back to the base hooks
        return base_hooks
