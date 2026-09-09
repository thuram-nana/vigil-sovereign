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
checkout) the runner's ``ImportError`` guard leaves the vendor byte-identical. Any OTHER wiring failure is
**FAIL-CLOSED**: :func:`attach_from_env` raises :class:`WardenGateUnavailable` rather than returning ungated
hooks, so a governed run stops instead of silently running an UNGUARDED arbitrary shell. A non-AUTO (QUEUE) decision no
longer hard-blocks: it is routed to the per-action, single-use, owner-signed approval BROKER
(:mod:`live.approval_broker`) — the hook publishes a pending request, waits (bounded by
``VIGIL_APPROVAL_WAIT_SECONDS``, default 300s ⇒ a 5-minute window; an explicit 0 opts back into instant
non-blocking deny) for a token the owner signs for THIS exact call (``vigil approve sign`` from a terminal
holding the owner key — the keyless console cannot sign it), verifies it against the deployment-pinned
owner key, and spends
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

import asyncio
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

from .progress import append_progress  # stdlib-only sibling — keeps this module framework/SDK/strix-clean

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


class WardenGateUnavailable(RuntimeError):
    """The WARDEN gate could not be WIRED onto a governed run, so the run must not proceed.

    Distinct from :class:`WardenDenied` (a specific call was refused *by* a working gate). This says the
    gate itself is missing on a run that asked for it, which is strictly worse: without it, Strix's
    arbitrary ``exec_command`` / ``write_stdin`` shell is unguarded. Raised by :func:`attach_from_env`
    instead of silently falling back to ungated hooks. Not raised for the deliberate opt-out, and not
    raised in a bare vendored Strix checkout (where ``vigil_integration`` is simply not importable and
    the runner's ``ImportError`` path leaves Strix byte-identical)."""


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
    block a call is to RAISE, so this adapter applies its verdict by raising ``WardenDenied`` to block
    and returning to allow.

    A QUEUE decision is APPROVE-THEN-RUN (wired, not deferred): it is routed to the per-action,
    single-use, owner-signed approval broker (``approver``) — the same broker/token/nonce-ledger the
    offense engine uses. The broker publishes a public-safe pending request and (bounded) waits for a
    matching owner-signed token; a valid, action-bound, single-use token authorizes THIS one call to
    run, otherwise it raises. Fail-safe: with NO ``approver`` (no authority provisioned) a QUEUE
    hard-blocks. The wait is offloaded off the asyncio event loop (``run_in_executor``) so a live
    interactive approval window does not stall the async runner. Every decision is recorded for
    audit/testing.
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

    def _note_block(self, name: str, decision: ToolDecision, reason: str) -> None:
        """Best-effort: surface this WARDEN block to the console's live process box via the offense child's
        progress feed, so the operator sees ``blocked by WARDEN, because X`` for a Strix codebase run (which
        otherwise streams nothing). ``fatal`` distinguishes a hard class DENY (never runs) from an approvable
        QUEUE block. ``append_progress`` is best-effort and never raises, so the block itself is unaffected —
        and it no-ops entirely unless the console handed this child a run dir (``$VIGIL_PROOF_RUN_DIR``).

        TOTAL by contract: it swallows everything. ``append_progress`` is already total, but this second
        guard is load-bearing — without it a broken/patched feed would replace the caller's ``WardenDenied``
        with an unrelated exception, losing the block reason and the type callers catch to render it. Making
        a refusal visible must never change what the refusal DOES."""
        try:
            # Bound the displayed name: `name` falls back to str(tool), which for an SDK tool object can be
            # a long repr (potentially its whole JSON schema). The UI displays this field.
            shown = str(decision.tool or name or "")[:120]
            append_progress({
                "event": "warden.block",
                "gate": "warden",
                "action_refused": shown,
                "tier": decision.tier,
                "outcome": decision.outcome,
                "fatal": decision.outcome == "deny",
                # bounded like action_refused: a reason can embed the tool name (decide_tool's denylist
                # message does), and the UI now renders it in the box row AND the Live timeline.
                "reason": str(reason or decision.reason or "")[:400],
            })
        except Exception:  # noqa: BLE001 — telemetry must NEVER alter the gate's control flow
            pass

    async def on_tool_start(self, context, agent, tool) -> None:
        # The SDK passes the ACTUAL call arguments on ``context`` (a ToolContext: ``.tool_name`` /
        # ``.tool_arguments`` — the raw args string); ``tool`` is only the static definition. Read the
        # context so the approval binds + displays the REAL command, not a constant (red-pen BLOCK-1).
        name = getattr(context, "tool_name", None) or getattr(tool, "name", None) or str(tool)
        decision = self.evaluate(name)
        # A hard class deny (denylist / empty name) never runs — raise immediately.
        if decision.outcome == "deny":
            self._note_block(name, decision, f"{decision.reason} (hard class deny — never runs)")
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
            self._note_block(name, decision, "no approval authority provisioned")
            raise WardenDenied(
                f"WARDEN gate blocked tool {name!r}: {decision.outcome} ({decision.reason}); no approval "
                f"authority provisioned (run `vigil approve provision-authority`)."
            )
        args = _strix_args(getattr(context, "tool_arguments", None))
        target = _strix_target(name, args)
        try:
            # The approver publishes the pending request then (bounded) waits for a matching owner-signed
            # token — a synchronous, blocking poll. Offload it to a worker thread so the bounded wait does NOT
            # stall the asyncio event loop the SDK runner drives (a live interactive approval window would
            # otherwise block every other task on the loop). The approver's file I/O + atomic O_EXCL nonce
            # burn are thread-safe.
            approved = bool(await asyncio.get_running_loop().run_in_executor(
                None, self._approver, name, target, args))
        except Exception as exc:  # noqa: BLE001 — an approver error is fail-closed (block)
            self._note_block(name, decision, f"approval errored ({type(exc).__name__}) — fail-closed")
            raise WardenDenied(
                f"WARDEN gate blocked tool {name!r}: approval errored ({type(exc).__name__}) — fail-closed."
            )
        if not approved:
            self._note_block(name, decision, "no valid owner approval within the window")
            raise WardenDenied(
                f"WARDEN gate blocked tool {name!r}: {decision.outcome} — no valid owner approval within the "
                f"window. Sign it from a terminal holding your owner key: `vigil approve sign --request-id "
                f"<id>` (see `vigil approve list`). The console is keyless and cannot sign this."
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


# The external egress endpoint the vendored ``web_search`` tool posts to — a FIXED host
# (``vendor/strix/strix/tools/web_search/tool.py``: ``url = "https://api.perplexity.ai/chat/completions"``).
# Naming it in the label tells the owner WHERE the query egresses, not merely that it does.
_WEB_SEARCH_DESTINATION = "strix:web_search:api.perplexity.ai:443"


def _has_control_chars(s: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7f for c in s)


def _canonical_destination(url: str) -> "Optional[str]":
    """The CANONICAL network destination ``scheme://host:port`` for a URL, or None if it has no usable host
    or is malformed. This is the address an owner is actually authorizing traffic to — deliberately NOT the
    raw attacker-controlled URL, which can (a) spoof the visible host
    (``https://trusted.example@evil.example/`` connects to ``evil.example``), and (b) smuggle secrets
    (``user:pass@``, session tokens / signed params in the query). So:

      * userinfo, path, query and fragment are DROPPED (host-spoofing + secret-leakage surface);
      * the host is lowercased, trailing-dot stripped, IDNA/punycode-normalized (a Unicode homograph shows
        as ``xn--…``), numeric IP encodings (decimal ``2130706433`` / hex ``0x7f000001``) collapsed to the
        canonical address, IPv6 bracketed;
      * control characters anywhere ⇒ refuse (return None);
      * a malformed port ⇒ refuse; a missing port ⇒ the scheme's default.

    urllib does the heavy lifting (``.hostname`` already strips userinfo + lowercases + de-brackets IPv6);
    this adds the normalizations urllib does not."""
    import ipaddress
    import re as _re
    from urllib.parse import urlsplit

    raw = (url or "").strip()
    if not raw or _has_control_chars(raw):
        return None
    try:
        u = urlsplit(raw)
        host = u.hostname          # lowercased, userinfo removed, IPv6 de-bracketed
        port = u.port              # raises ValueError on a malformed port
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".")
    if not host:
        return None
    if _re.fullmatch(r"0x[0-9a-fA-F]+|[0-9]+", host):   # numeric IP encoding → canonical
        try:
            host = str(ipaddress.ip_address(int(host, 0)))
        except ValueError:
            pass
    else:                                               # IDNA/punycode → ascii so homographs can't hide
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:  # noqa: BLE001 — not IDNA-encodable (IP, invalid) ⇒ keep the lowercased host
            pass
    try:
        is_v6 = isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        is_v6 = ":" in host
    disp = f"[{host}]" if is_v6 else host
    if len(disp) > 255:
        disp = disp[:255] + "…(truncated)"
    scheme = (u.scheme or "").lower()
    if port is None:
        port = {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(scheme)
    if scheme and port is not None:
        return f"{scheme}://{disp}:{port}"
    if scheme:
        return f"{scheme}://{disp}"
    return disp


def _sanitize_label_token(s: str, *, cap: int = 128) -> str:
    """A short, control-char-free, length-capped token safe to place in a human-facing approval label."""
    t = str(s).strip()
    if _has_control_chars(t):
        return "invalid"
    return t if len(t) <= cap else t[:cap] + "…(truncated)"


def _header_host_override(headers: Any) -> "Optional[str]":
    """A ``Host`` header the replay overrides (case-insensitive), sanitized — else None. A replay can keep the
    original CONNECTION destination while changing the virtual host, and those are different security
    properties, so the owner must see the override when it is present."""
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if isinstance(k, str) and k.strip().lower() == "host" and isinstance(v, str) and v.strip():
            return _sanitize_label_token(v)
    return None


def _strix_target(tool_name: str, args: Any = None) -> str:
    """The approval-binding target label an owner SEES before signing a queued Strix call.

    The single-use nonce already binds each queued invocation independently (the action_digest covers the
    full ``args``), so this label is not what makes a token unforgeable. What it fixes is a DIFFERENT gap:
    for the network tools the label used to be the constant ``"strix:exec"`` — so an owner asked to approve
    a ``repeat_request`` saw "exec", blind to which HOST the attacker-modified traffic would hit. W16-5 added
    ``repeat_request`` (attacker-modified traffic to a URL) to the gated set, which made the old "Strix's
    tools have NO network target" justification false. This resolves a CANONICAL destination into the label
    so the owner authorizes a specific host — not a sentinel, and not the raw spoofable/secret-bearing URL.

    * ``repeat_request`` — sends a modified copy of a captured request. The connection destination is the
      canonical ``scheme://host:port`` of ``modifications.url`` when the agent overrides it (secrets and
      host-spoofing stripped by :func:`_canonical_destination`); a ``Host`` header override is surfaced
      separately (``;host=…``) since it can differ from the connection destination. When there is no url
      override the true destination lives in the referenced captured request, which is NOT in the args —
      only ``request_id`` is — so the label carries ``req=<id>`` (inspectable via ``view_request``). Fully
      resolving that id to its captured host+port and binding the request snapshot (with a pre-replay
      recheck to close the check/replay gap) needs Caido access at gate time and is the S6/S7 follow-up;
      until then this is a partial, honestly-labelled measure, not full destination resolution.
    * ``web_search`` — external egress to the fixed ``api.perplexity.ai:443`` (named, so it is never
      confused with engagement traffic). The query stays bound in ``args``.
    * ``exec_command`` / ``write_stdin`` — the command string IS the payload and is bound via ``args``;
      they have no single network destination, so the local sentinel remains honest for them.

    NOTE this is defense-in-depth on the AUTHORISATION path — it is not, and cannot be, a substitute for
    forcing Strix's actual traffic through VIGIL's scope-enforcing egress (S2/S3). A human label never
    enforces scope; the gateway does.
    """
    name = str(tool_name or "").strip()
    if name == "repeat_request":
        return _repeat_request_target(args)
    if name == "web_search":
        return _WEB_SEARCH_DESTINATION
    return "strix:exec"


def _repeat_request_target(args: Any) -> str:
    if not isinstance(args, dict):
        return "strix:repeat_request"
    mods = args.get("modifications")
    mods = mods if isinstance(mods, dict) else {}
    url = mods.get("url")
    if isinstance(url, str) and url.strip():
        canon = _canonical_destination(url)
        label = f"strix:repeat_request:{canon}" if canon else "strix:repeat_request:unparseable-url"
    else:
        rid = args.get("request_id")
        if isinstance(rid, (str, int)) and str(rid).strip():
            label = f"strix:repeat_request:req={_sanitize_label_token(str(rid))}"
        else:
            return "strix:repeat_request"
    host_override = _header_host_override(mods.get("headers"))
    if host_override:
        label += f";host={host_override}"
    return label


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
# exec_command process). So gating THESE two names gates all arbitrary execution.
#
# ACCEPTED GAP (S4 item 4 — whole-shell approval, honestly labelled). An approved ``exec_command`` runs the
# WHOLE command string — pipes, subshells, arbitrary binaries — with NO argv allowlist and NO per-binary
# re-check. The CRUCIBLE path does the opposite: ``live/executor.py`` denies a tool with no typed argv
# ``_BUILDERS`` entry, and ``terminal.run`` is confined to the read-only ``_TERMINAL_ALLOWLIST``. That
# asymmetry is DELIBERATE and cannot be closed the CRUCIBLE way here: Strix is a general offensive agent
# whose tool surface is unbounded by design (it MUST run nmap/ffuf/curl/python3/msf/…), so a fixed argv
# allowlist would defeat its purpose, and a denylist of dangerous spellings is unsound (trivially evaded).
# Strix's exec is contained instead by three OTHER controls: (1) this per-action, single-use, owner-signed
# WARDEN approval — the owner reviews the EXACT command string (bound via ``_strix_args``) before it runs;
# (2) the S2/S3 scope-enforcing egress gateway, which governs where its traffic may go; and (3) the S5
# container hardening, which bounds what a compromised exec can reach. The exec approval target therefore
# stays the honest LOCAL sentinel ``strix:exec`` (there is no single network destination to bind) — see
# ``_strix_target`` — rather than a spoofable network-style label. Pinned by ``test_strix_exec_whole_shell_gap``.
_STRIX_EXEC_TOOLS = frozenset({"exec_command", "write_stdin"})

# The Strix tools that REACH THE NETWORK without going through ``exec_command`` — so a gate that only
# watches the shell chokepoint would let them auto-fire, yet each touches the target / egresses and must be
# owner-gated exactly like the shell (constitution: "a modified request to a REMOTE target must be gated"):
#   * ``repeat_request`` replays a captured request with attacker-chosen modifications (auth-bypass,
#     payload injection, parameter tampering) straight to the target via Caido's replay engine. It sends
#     attacker-MODIFIED traffic to the target over the network and does NOT transit ``exec_command``.
#     Caido's replay path also need not transit the L3/L4 egress gateway, so this per-action WARDEN
#     approval is the only layer that reliably governs it.
#   * ``web_search`` is network EGRESS (a Perplexity-backed lookup) — NOT the sandbox-contained, no-network
#     tool its previous classification treated it as.
_STRIX_NETWORK_TOOLS = frozenset({"repeat_request", "web_search"})

# The union the gate floors to A3 (⇒ QUEUE for a single-use owner-signed approval under the A1 ceiling).
_STRIX_GATED_TOOLS = _STRIX_EXEC_TOOLS | _STRIX_NETWORK_TOOLS

# The EXPLICIT allowlist of Strix tools that are genuinely sandbox-contained / read-only and may auto-run so
# the agent stays functional. This is the full current tool surface MINUS the gated set — every name here is
# a real, shipped Strix tool (see ``strix.agents.factory._BASE_TOOLS`` + the SDK Shell/Filesystem
# capabilities; the offline drift guard in ``test_strix_unknown_tool_fail_closed.py`` harvests the shipped
# names from the vendored render manifest and fails CI if any shipped tool is neither gated nor here).
#
# Why an allowlist and not a denylist: the previous classifier returned A0 (auto) for every name NOT in the
# gated set — so a NEW upstream tool added on a Strix upgrade (a fresh network/exec surface among them)
# would AUTO-RUN, ungated, until someone noticed. Invariant 4 ("no unknown tool executed through a generic
# shell") requires the opposite: an unrecognized tool must FAIL CLOSED (queue for owner approval) until it
# is explicitly classified here. The two dangerous defaults trade places — the safe one wins.
_STRIX_AUTO_TOOLS = frozenset({
    # thinking / skills / lifecycle
    "think", "load_skill", "finish_scan", "agent_finish",
    # todo
    "create_todo", "list_todos", "update_todo", "mark_todo_done", "mark_todo_pending", "delete_todo",
    # notes
    "create_note", "list_notes", "get_note", "update_note", "delete_note",
    # reporting (writes a report artifact; no target traffic)
    "create_vulnerability_report", "create_dependency_report",
    # proxy READ tools (inspect already-captured traffic; do NOT send — repeat_request is gated, above)
    "list_requests", "view_request", "list_sitemap", "view_sitemap_entry", "scope_rules",
    # agents-graph (spawns/controls CHILD agents, which run under this SAME gate — their exec/network still
    # queues, so orchestration itself is sandbox-contained)
    "view_agent_graph", "send_message_to_agent", "wait_for_message", "create_agent", "stop_agent",
    # filesystem / media (edits inside /workspace; renders a captured image) — no network, no host exec
    "apply_patch", "view_image",
})


def _strix_shell_classifier(name: str) -> str:
    """A3 for the Strix tools that must QUEUE for owner approval under the A1 ceiling — the arbitrary-exec
    chokepoint (``exec_command`` / ``write_stdin``) AND the tools that reach the network WITHOUT transiting
    the shell (``repeat_request`` sends attacker-modified traffic to the target; ``web_search`` egresses);
    A0 (auto) ONLY for the explicitly allowlisted, sandbox-contained / read-only tools in
    ``_STRIX_AUTO_TOOLS``; and A3 (fail-closed → queue) for EVERY OTHER name — an empty name, or a tool this
    build does not recognize (e.g. one a Strix upgrade added). Deliberately NOT the offense
    ``default_classify`` — that rates every non-recon name A2, which under a default-on gate would block the
    whole agent. This governs the target-touching / egress surface AND makes an unknown tool fail closed."""
    n = str(name or "").strip()
    if n in _STRIX_GATED_TOOLS:
        return "A3"
    if n in _STRIX_AUTO_TOOLS:
        return "A0"
    return "A3"  # unknown / unregistered / empty → fail closed (queue for owner approval)


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
    _approvals_root = approvals_root(base_dir)
    ledger = NonceLedger(Path(base_dir) / "approval-nonces")

    def approve(tool_name: str, target: str, args: Any) -> bool:
        try:
            act = ApprovalAction(tool_name, target, action_digest(tool_name, target, args))
        except Exception:  # noqa: BLE001 — a non-serialisable action can't be bound ⇒ deny (fail-closed)
            return False
        # PER-CALL broker: the SDK runs exec tools CONCURRENTLY (each bounded-wait on its own worker thread),
        # and ApprovalBroker holds a mutable ``self._current``. A single shared instance let concurrent binds
        # clobber one another — call A would then publish/poll for call B's action and be denied (an
        # intermittent, burst-only false denial). A fresh broker per call isolates each action's bind +
        # token wait. ``authority`` (read-only) and ``ledger`` (file-backed, single-use) stay shared.
        broker = ApprovalBroker(_approvals_root)
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
    """Compose this offense-side WARDEN tool-name gate onto Strix's run ``base_hooks``. **ON BY DEFAULT,
    FAIL-CLOSED** — returns a composite ``RunHooks`` (existing accounting + the WARDEN ``on_tool_start``
    gate).

    There is exactly ONE way to end up deliberately ungated: the explicit opt-OUT
    ``VIGIL_WARDEN_STRIX_GATE`` in {0,off,false,no}, which returns ``base_hooks`` UNCHANGED so a bare
    vendored Strix stays byte-identical.

    **A WIRING FAILURE IS NOT AN OPT-OUT.** This function previously swallowed ANY exception and returned
    the ungated ``base_hooks`` on the reasoning that "a wiring error can never stop a scan". That traded
    the system's own fail-closed invariant for availability, on the single most dangerous surface it has:
    Strix's arbitrary ``exec_command`` / ``write_stdin`` shell. The effect was that a broken wire produced
    an UNGATED shell with NO signal to the operator — an accident, not a decision, and indistinguishable
    from a healthy governed run. It now raises :class:`WardenGateUnavailable`, so a governed run STOPS
    rather than silently proceeding ungoverned. An operator who genuinely wants an ungated run must say so
    with the opt-out env var: a deliberate, visible, auditable act.

    The classifier is :func:`_strix_shell_classifier` (floor A0, ceiling A1): it QUEUES the arbitrary-exec
    chokepoint (``exec_command`` / ``write_stdin``) AND the tools that reach the network without transiting
    the shell (``repeat_request`` — attacker-modified traffic to the target; ``web_search`` — egress), and
    auto-runs ONLY the explicitly allowlisted sandbox-contained / read-only tools (``_STRIX_AUTO_TOOLS``), so
    the agent stays functional while its target-touching / egress surface is governed. An UNKNOWN tool — one
    this build does not recognize, e.g. a fresh surface a Strix upgrade added — FAILS CLOSED to A3 (queue),
    never auto-runs. A QUEUE is routed to the
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
    except Exception as exc:  # noqa: BLE001 — fail CLOSED: an ungated arbitrary shell is never the fallback
        raise WardenGateUnavailable(
            "the VIGIL WARDEN gate on Strix's arbitrary shell (exec_command / write_stdin) could not be "
            f"wired: {exc!r}. Refusing to run UNGATED. This is deliberate: a wiring failure is not an "
            "opt-out, and continuing would leave the most dangerous surface in the system unguarded with "
            f"no signal. To run without the gate on purpose, set {_STRIX_GATE_ENV}=0."
        ) from exc
