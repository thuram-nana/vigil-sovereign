"""
tools.governance — the sovereign tool-call boundary (VIGIL-FUSION F3, slice 1).

redamon runs a tool through a soft ``PhaseAwareToolExecutor`` (a Python ``is_tool_allowed_in_phase``
check) behind a fail-OPEN shared-bearer MCP auth. VIGIL subordinates every tool call to the sovereign
core instead: the manifest's declared phase maps onto the WARDEN authority tier (informational→A1,
exploitation→A2, post_exploitation→A3), a destructive tool floors at A3 and additionally needs the
m-of-n threshold-destruction authorization, and the whole thing routes through the SAME injected
conjunctive gate the F2 ReAct core uses (``gate(tool_name, target, destructive) -> verdict``). Every
decision is fail-closed:

  * a tool not declared by an enabled manifest, or declared but not for the current phase, is DENIED
    before the gate is even consulted (``is_tool_allowed_in_phase`` reads the registry's least-privilege
    phase-view; an unregistered tool has an empty phase list → denied everywhere);
  * no gate wired, or any gate exception → DENY (never caught-and-continued);
  * a destructive tool is flagged ``requires_quorum`` so the caller routes it through the m-of-n leg.

The classifier here is a conservative *floor* (a known-dangerous tool name can only RAISE the tier, never
lower it); the precise per-tool blast class comes from the tool catalog's explicit metadata in a later
slice. Pure/injected — the gate is a callable, so the boundary is testable without the live kernel.

Import-clean: reuses the F2 phase→tier machine (``agent.phases``) + the registry; stdlib/pydantic only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ..agent.phases import tool_tier
from ..agent.state import Phase
from .mcp_registry import _is_secret_key, _mask_secret, _redact_arg_list, _redact_str

# Known-dangerous tool NAMES → floor the tier at A3 + require the m-of-n threshold-destruction leg. This
# is a conservative floor (over-inclusion only RAISES the tier, the safe direction); the operator's
# manifest ``destructive`` declaration is the authoritative source and is honored on top of it. A false
# NEGATIVE here is the dangerous direction, so the list is deliberately broad across families.
_DESTRUCTIVE_TOOLS = frozenset({
    # metasploit / payload generation
    "metasploit", "metasploit_console", "msfconsole", "msfvenom", "msfcli", "msfdb", "msf_restart",
    # brute-force / cracking
    "hydra", "medusa", "sqlmap", "patator", "ncrack", "crowbar", "hashcat", "john", "johntheripper",
    # active scan / injection exploit
    "nuclei", "wpscan", "commix", "xsser", "proxy_fuzz",
    # denial of service (named tools — no shared substring)
    "slowloris", "hulk", "goldeneye", "torshammer", "slowhttptest", "xerxes", "loic", "hoic",
    # command-and-control / implants
    "empire", "cobaltstrike", "cobalt_strike", "sliver", "mythic", "havoc", "brute_ratel",
    "merlin", "covenant", "poshc2",
    # lateral movement / relay / credential theft
    "crackmapexec", "cme", "netexec", "nxc", "impacket", "responder", "psexec", "smbexec", "wmiexec",
    "secretsdump", "evil-winrm", "evilwinrm", "mimikatz",
    # shells / pivots / transfer
    "netcat", "nc", "ncat", "socat", "chisel", "ligolo", "webshell",
    # arbitrary execution
    "kali_shell", "execute_code",
})
_DESTRUCTIVE_PATTERNS = (
    "metasploit", "msf", "hydra", "medusa", "sqlmap",
    "_dos", "ddos", "slowloris",
    "reverse_shell", "revshell", "reverse_tcp", "bind_shell", "webshell", "reverse_https",
    "_brute", "bruteforce", "brute_force",
    "cobalt", "mimikatz",
)


def is_destructive_tool(tool_name: Any, *, declared: Optional[bool] = None) -> bool:
    """Whether ``tool_name`` is destructive/high-blast (floors at A3 + m-of-n). ``declared`` is the
    operator's authoritative manifest blast class: ``True`` forces destructive; ``False``/``None`` fall
    through to the known-dangerous-name floor (which can still raise it). Raise-only — the name floor
    never LOWERS an operator-declared destructive tool."""
    if declared:
        return True
    if not isinstance(tool_name, str) or not tool_name:
        return False
    n = tool_name.lower()
    if n in _DESTRUCTIVE_TOOLS:
        return True
    return any(p in n for p in _DESTRUCTIVE_PATTERNS)


def _coerce_phase(phase: Any) -> Optional[Phase]:
    if isinstance(phase, Phase):
        return phase
    if isinstance(phase, str):
        try:
            return Phase(phase)
        except ValueError:
            return None
    return None


def is_tool_allowed_in_phase(tool_name: Any, phase: Any, *, view: Any) -> bool:
    """Fail-closed phase gate: ``tool_name`` may run in ``phase`` only if ``phase`` is among the tool's
    manifest-declared effective phases. An unknown phase, an unregistered tool, or a tool with an empty
    phase list is DENIED (VIGIL inverts redamon's default-allow-everywhere)."""
    p = _coerce_phase(phase)
    if p is None or not isinstance(tool_name, str):   # non-str tool_name is unhashable/invalid → deny
        return False
    phases = view.get(tool_name) if isinstance(view, dict) else None
    if not phases or not isinstance(phases, (list, tuple, set)):
        return False
    return p.value in phases


def tool_call_tier(tool_name: Any, phase: Any, *, destructive: Optional[bool] = None,
                   declared_destructive: Optional[bool] = None) -> str:
    """The WARDEN tier a tool call must clear: the phase tier, floored at A3 for a destructive tool. An
    unknown phase resolves to the strictest tier (A3), never a lenient default. ``destructive`` forces
    the classification; otherwise it is ``declared_destructive`` (manifest) OR the name floor."""
    p = _coerce_phase(phase)
    d = bool(destructive) if destructive is not None else is_destructive_tool(
        tool_name, declared=declared_destructive)
    if p is None:
        return "A3"
    return tool_tier(p, destructive=d)


def _tool_target(tool_args: Any) -> str:
    """Best-effort target host/url for the gate/egress check (the LLM's proposal; the executor
    re-derives the authoritative target server-side in a later slice)."""
    if not isinstance(tool_args, dict):
        return ""
    for key in ("target", "url", "target_url", "host", "domain"):
        v = tool_args.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


_MAX_REDACT_DEPTH = 40   # a value nested deeper than this is masked wholesale rather than risking RecursionError


def _redact_value(v: Any, *, key_is_secret: bool, depth: int = 0) -> Any:
    """Redact one value: a value under a secret KEY is masked whole; otherwise nested dicts/lists are
    descended (bounded depth) and free strings have inline secrets (Bearer/api_key=/…) masked."""
    if key_is_secret:
        return _mask_secret(v) if isinstance(v, str) else "••••"
    if depth >= _MAX_REDACT_DEPTH:
        return "••••[nested]" if isinstance(v, (dict, list)) else (_redact_str(v) if isinstance(v, str) else v)
    if isinstance(v, dict):
        return {k: _redact_value(val, key_is_secret=_is_secret_key(k), depth=depth + 1)
                for k, val in v.items()}
    if isinstance(v, list):
        # an argv-style list of strings ("args"/"argv": ["--api-key", "SECRET"]) gets flag→value
        # redaction; a mixed/structured list is descended element-wise.
        if v and all(isinstance(e, str) for e in v):
            return _redact_arg_list(v)
        return [_redact_value(e, key_is_secret=False, depth=depth + 1) for e in v]
    if isinstance(v, str):
        return _redact_str(v)
    return v


def redact_tool_args(tool_args: Any) -> Dict[str, Any]:
    """Mask secrets before a tool call is written to the immutable spine. Descends nested dicts/lists
    (bounded to a safe depth), masks any value under a secret key (token/api_key/client_secret/
    refresh_token/x-api-key/private_key/ssh_key/…, matched by stem + word-boundary + camelCase token),
    and scrubs inline secrets in free string values via the SAME secret vocabulary — ``Bearer <tok>``,
    any ``secret-param=value``/``"secret-param":"value"`` (incl. URL query strings and ``Cookie:``
    headers), and ``--secret-flag <value>``. Non-secret args pass through structurally unchanged; a
    value nested past the depth bound is masked rather than crashing. Best-effort residual (documented,
    not silently claimed): a purely POSITIONAL secret with no key/flag/structure (a bare list element or
    a lone positional command arg) is indistinguishable from a benign value and is not detected —
    declare secrets via a named key/flag, ``auth``, or ``env`` rather than positionally."""
    if not isinstance(tool_args, dict):
        return {}
    return {k: _redact_value(v, key_is_secret=_is_secret_key(k)) for k, v in tool_args.items()}


@dataclass(frozen=True)
class ToolCallVerdict:
    allowed: bool          # may this tool call auto-proceed now?
    outcome: str           # "allow" | "queue" | "deny"
    tier: str              # the WARDEN tier the call was gated at
    destructive: bool
    requires_quorum: bool  # destructive → the m-of-n threshold-destruction leg
    reason: str


def authorize_tool_call(
    tool_name: Any,
    tool_args: Any,
    phase: Any,
    *,
    gate: Optional[Callable[..., Any]] = None,
    view: Any,
    destructive_view: Any = None,
    now: Any = None,
) -> ToolCallVerdict:
    """Authorize a single tool call through the sovereign core, fail-closed. Order: (1) the fail-closed
    phase gate (unregistered/out-of-phase → DENY before the gate is consulted); (2) tier + destructive
    classification — the operator's manifest ``destructive_view`` (tool→bool) is authoritative and the
    known-dangerous-name floor raises it further; (3) the injected conjunctive
    ``gate(tool_name, target, destructive)`` — its verdict decides, and any gate error or a missing gate
    is a DENY. A destructive call is flagged ``requires_quorum`` (and the gate is told ``destructive``)
    so the m-of-n leg is driven. Never raises."""
    p = _coerce_phase(phase)
    declared = destructive_view.get(tool_name) if isinstance(destructive_view, dict) \
        and isinstance(tool_name, str) else None
    d = is_destructive_tool(tool_name, declared=declared)
    if p is None:
        return ToolCallVerdict(False, "deny", "A3", d, d, f"unknown phase {phase!r} (fail-closed)")
    if not is_tool_allowed_in_phase(tool_name, p, view=view):
        return ToolCallVerdict(False, "deny", tool_call_tier(tool_name, p, destructive=d), d, d,
                               f"tool {tool_name!r} not permitted in phase {p.value} "
                               "(unregistered or out-of-phase)")
    tier = tool_tier(p, destructive=d)
    target = _tool_target(tool_args)
    if gate is None:
        return ToolCallVerdict(False, "deny", tier, d, d,
                               "no conjunctive gate wired — a tool call cannot proceed (fail-closed)")
    try:
        verdict = gate(tool_name, target, d)
    except Exception as exc:  # noqa: BLE001 — any gate error is a DENY, never caught-and-continued
        return ToolCallVerdict(False, "deny", tier, d, d, f"gate error (fail-closed): {exc}")
    raw_outcome = getattr(verdict, "outcome", "deny")
    allowed = getattr(verdict, "allowed", False) is True and raw_outcome == "allow"
    outcome = "allow" if allowed else ("queue" if raw_outcome == "queue" else "deny")
    return ToolCallVerdict(allowed, outcome, tier, d, d, getattr(verdict, "reason", "") or
                           ("tool call authorized" if allowed else "tool call not authorized"))


def authorized_tool_names(phase: Any, *, view: Any) -> List[str]:
    """The set of currently-registered tools permitted in ``phase`` (for rendering the LLM's tool menu).
    A pure view over the registry phase-map; being on this list is necessary but NOT sufficient — every
    call still clears the conjunctive gate at execution."""
    p = _coerce_phase(phase)
    if p is None or not isinstance(view, dict):
        return []
    return sorted(name for name, phases in view.items()
                  if isinstance(name, str) and isinstance(phases, (list, tuple, set))
                  and p.value in phases)
