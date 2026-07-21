"""
live.gauntlet_subproc — the LIVE AI-Gauntlet subprocess adapter (VIGIL-LIVE, §12 WS1c).

The drop-in that wires the F8 offensive-LLM sensor (``vigil_integration.gauntlet``) to a REAL garak /
PyRIT command-line invocation, without importing either framework. garak/PyRIT carry heavy, conflicting
ML dependencies, so they run out-of-process behind an INJECTED subprocess runner
(``run_tool(argv) -> envelope``); this adapter never imports them and never opens a socket itself. On
this validation box garak is NOT installed, so ``run_tool`` honestly reports ``{'available': False}`` and
the adapter returns ``[]`` — a fail-closed, HONEST no-signal, never a fabricated finding.

Going live changes NOTHING about the sovereign contract. This module is pure glue:

  * it does NOT re-implement routing — every candidate is parsed and routed by the already-hardened
    ``gauntlet`` core (``parse_adapter_output`` + ``route_candidate``), so the sovereign invariant is
    enforced in exactly one tested place;
  * a ``judge_llm`` (LLM-judge, non-deterministic) candidate is ALWAYS a LEAD — it is returned before
    any oracle call, so no maxed-out ASR and no adversarial oracle can launder it into a FACT;
  * ONLY a deterministic ``oracle_kind`` (contains/classifier/regex) that the INJECTED randomized-
    challenge oracle CONFIRMS (returns a non-empty signed evidence ref for) mints a signed FACT;
  * ASR is computed as a METRIC only — never a promotion signal;
  * the ``target`` is EGRESS-PINNED: for this validation the gauntlet may only fire against loopback
    (127.0.0.0/8, ``::1``, ``localhost``). A non-loopback / unparseable target → DENY → ``[]``. The
    egress check is an injected callable (``egress_check``) with the ``(allowed, reason)`` contract —
    egress is ALLOWED iff the verdict's first element is exactly ``True``; the loopback pin
    (:func:`loopback_only_egress`) is the shipped default. A non-pinned deployment wires the general SSRF
    gate through the shipped :func:`ssrf_egress_gate` ADAPTER — NEVER
    ``vigil_gateway.denylist.is_egress_denied`` directly: that function returns ``(denied, reason)`` (the
    INVERSE of this contract's polarity) and takes a resolved IP, not a target URL, so wiring it raw
    silently inverts the gate — every DENY (incl. cloud metadata ``169.254.169.254``) would read as an
    ALLOW. This module never asserts an egress policy of its own beyond the fail-closed loopback default.

Fail-closed / deny-by-default: no oracle wired, no ``run_tool``, a runner error/timeout, an unknown CLI,
a malformed envelope, a non-loopback target, or malformed tool output → ``[]`` / all-LEADs, never a FACT
and never a raise. Deterministic: the per-run challenge token derives from the injected ``probe.seed``
(no wallclock/RNG anywhere). Secret-free: any argv preview reuses the F3 redaction seam
(``redact_tool_args``); raw tool evidence is handed only to the injected oracle, never returned in a
finding.

Import-clean: pydantic/stdlib + the F8 gauntlet core + the F3 tools redaction seam. No garak/PyRIT
import, no network, no shell — argv lists only. (The general SSRF gate
``vigil_gateway.denylist.is_egress_denied`` is imported LAZILY, only as :func:`ssrf_egress_gate`'s
default denied-check, so this module loads and unit-tests without the gateway on the path.)
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence
from urllib.parse import urlsplit

from ..agent.state import Finding
from ..gauntlet import (
    KNOWN_TOOLS,
    GauntletResult,
    GauntletSpec,
)
from ..gauntlet import (
    run_gauntlet as _sensor_run_gauntlet,
)
from ..gauntlet.sensor import GauntletOracle
from ..tools import redact_tool_args

# ---------------------------------------------------------------------------------------------------
# injected boundaries
# ---------------------------------------------------------------------------------------------------

# The subprocess boundary. Given the CLI argv, the injected runner executes garak/PyRIT out-of-process
# and returns an ENVELOPE describing the run. Contract (all fields optional, read totally):
#
#     {"available": bool,                 # False (or absent) → the CLI is not installed / did not run
#      "report":   str | list | dict,     # the tool's native report (garak jsonl / PyRIT results / …)
#      "returncode": int, ...}            # advisory only; not trusted for veracity
#
# ``available`` MUST be exactly ``True`` for the report to be read; anything else is treated as "the
# tool is not available" → no signal. Report aliases (``report``/``stdout``/``output``/``jsonl``/``raw``)
# span the runners. Any exception the runner raises is caught and degraded to "unavailable".
RunTool = Callable[[Sequence[str]], object]

# The egress gate: ``(target) -> (allowed, reason)`` — egress is ALLOWED iff the verdict's first element
# is exactly ``True`` (see :func:`_egress_allowed`). The shipped default (:func:`loopback_only_egress`)
# pins egress to loopback for this validation. To wire the general SSRF gate in a non-pinned deployment,
# inject :func:`ssrf_egress_gate` — do NOT inject ``vigil_gateway.denylist.is_egress_denied`` directly:
# its ``(denied, reason)`` polarity is the INVERSE of this contract and it takes a resolved IP (not a
# target URL), so wiring it raw silently turns every DENY into an ALLOW.
EgressCheck = Callable[[object], "tuple[bool, str]"]

# Report field aliases across garak / PyRIT / Giskard / promptfoo runner envelopes.
_REPORT_KEYS = ("report", "stdout", "output", "jsonl", "raw", "results")


# ---------------------------------------------------------------------------------------------------
# the probe spec
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class GauntletProbe:
    """One live gauntlet probe. ``tool`` selects the CLI (must be a ``KNOWN_TOOLS`` member — garak /
    pyrit / giskard / promptfoo); ``probes`` are the probe/attack families to drive; ``seed`` is the
    INJECTED deterministic seed (no RNG/wallclock — it derives the per-run challenge token in the
    reused router). ``model_type``/``model_name``/``extra_argv`` shape the CLI argv the injected runner
    executes."""

    tool: str = "garak"
    probes: tuple[str, ...] = ()
    seed: str = ""
    model_type: str = "rest"
    model_name: str = ""
    extra_argv: tuple[str, ...] = field(default_factory=tuple)


def _coerce_probe(probe: object) -> Optional[GauntletProbe]:
    """Coerce whatever was passed as ``probe`` into a :class:`GauntletProbe`, TOTAL. Accepts a
    ``GauntletProbe`` (used as-is), a bare string (a single probe family on the default garak CLI), or a
    sequence of strings (several families). Anything else → ``None`` (no runnable probe → fail-closed)."""
    if isinstance(probe, GauntletProbe):
        return probe
    if isinstance(probe, str):
        s = probe.strip()
        return GauntletProbe(probes=(s,)) if s else GauntletProbe()
    if isinstance(probe, (list, tuple)):
        fams = tuple(str(p).strip() for p in probe if isinstance(p, str) and str(p).strip())
        return GauntletProbe(probes=fams)
    return None


# ---------------------------------------------------------------------------------------------------
# egress pin — loopback only (deterministic; no DNS)
# ---------------------------------------------------------------------------------------------------


def _target_host(target: object) -> Optional[str]:
    """Extract the host from a target URL / ``host:port`` / bare host, TOTAL and DNS-free. Folds ``\\``
    → ``/`` before parsing so a ``http://127.0.0.1\\@evil`` userinfo trick resolves to the host the real
    client (requests/urllib3, which treat ``\\`` as ``/``) would actually connect to. Returns the
    lowercased host, or ``None`` if unparseable."""
    if not isinstance(target, str):
        return None
    s = target.strip()
    if not s:
        return None
    # A bare IP literal (incl. unbracketed IPv6 like ``::1``, which ``urlsplit`` cannot netloc-parse):
    # accept it directly so a caller may pass a raw host, not only a URL.
    bare = s.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return bare.lower()
    except ValueError:
        pass
    s = s.replace("\\", "/")
    try:
        parts = urlsplit(s if "://" in s else "//" + s)
        host = (parts.hostname or "").strip("[]").lower()
    except (ValueError, TypeError):
        return None
    return host or None


def loopback_only_egress(target: object) -> tuple[bool, str]:
    """The shipped default egress gate: ALLOW iff ``target`` is loopback (127.0.0.0/8, ``::1``, or the
    ``localhost`` literal). Deterministic and DNS-free — a non-literal hostname (other than
    ``localhost``) is DENIED rather than resolved, so egress can never widen past the loopback pin via a
    hostname that resolves off-loopback. Fail-closed on any ambiguity."""
    host = _target_host(target)
    if not host:
        return False, "target has no parseable host (fail-closed)"
    if host == "localhost":
        return True, "loopback (localhost)"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False, (
            f"host {host!r} is not a loopback IP literal — egress is pinned to 127.0.0.0/8 for "
            "validation (fail-closed; no DNS resolution)"
        )
    if ip.is_loopback:
        return True, f"loopback {ip}"
    return False, f"{ip} is not loopback — egress pinned to 127.0.0.0/8 for validation"


def ssrf_egress_gate(
    target: object,
    *,
    denied_check: Optional[Callable[[str], tuple[bool, str]]] = None,
    resolve: Optional[Callable[[str], Sequence[str]]] = None,
) -> tuple[bool, str]:
    """The general SSRF/egress adapter — the ONLY correct way to wire the gateway's SSRF gate as an
    ``egress_check``. TOTAL and fail-closed; obeys the ``(allowed, reason)`` :data:`EgressCheck`
    contract.

    ``vigil_gateway.denylist.is_egress_denied`` must NEVER be injected as ``egress_check`` directly: it
    returns ``(denied, reason)`` (the INVERSE polarity of this contract) and it expects a resolved IP
    string, not a target URL — so wiring it raw silently turns every DENY into an ALLOW (cloud metadata
    ``169.254.169.254``, and any URL — being "unparseable" as an IP — would all read as allowed). This
    adapter closes that gap:

      * ``denied_check`` is the ``(denied, reason)`` gate; it defaults to
        ``vigil_gateway.denylist.is_egress_denied`` (imported LAZILY — a missing gateway → DENY), so this
        function may be wired straight in as ``egress_check`` and behaves correctly;
      * the host is extracted from the target URL / ``host:port`` / bare host with the same DNS-free
        parser the loopback pin uses (``\\`` is folded to ``/`` first, matching the real client);
      * an IP-literal host is checked directly; a non-literal hostname is resolved ONLY through the
        injected ``resolve`` callable — with no resolver wired a hostname is DENIED (fail-closed,
        DNS-free, deterministic), never silently allowed;
      * EVERY candidate IP is passed to ``denied_check``; if ANY is denied the target is DENIED;
      * the ``denied → allowed`` polarity is inverted exactly ONCE, here, so the ``(allowed, reason)``
        verdict this module consumes is correct."""
    check = denied_check
    if check is None:
        try:
            from vigil_gateway.denylist import is_egress_denied as check  # lazy: keep module import-clean
        except Exception:  # noqa: BLE001 — no SSRF gate available → deny, never allow
            return False, "SSRF egress gate unavailable (fail-closed)"
    if not callable(check):
        return False, "SSRF denied-check is not callable (fail-closed)"

    host = _target_host(target)
    if not host:
        return False, "target has no parseable host (fail-closed)"

    try:
        ipaddress.ip_address(host)
        candidates: list[str] = [host]
    except ValueError:
        if resolve is None:
            return False, (
                f"host {host!r} is not an IP literal and no resolver is wired — the SSRF adapter is "
                "DNS-free/fail-closed (resolve to an IP first, or inject a resolver)"
            )
        try:
            resolved = resolve(host)
        except Exception:  # noqa: BLE001 — a resolver error denies, never allows
            return False, f"resolver raised for host {host!r} (fail-closed)"
        if isinstance(resolved, str):
            candidates = [resolved.strip()] if resolved.strip() else []
        elif isinstance(resolved, (list, tuple)):
            candidates = [str(x).strip() for x in resolved if str(x).strip()]
        else:
            candidates = []
        if not candidates:
            return False, f"host {host!r} did not resolve to any IP (fail-closed)"

    denials: list[str] = []
    for ip in candidates:
        try:
            verdict = check(ip)
            denied, reason = verdict[0], verdict[1]  # gateway contract: (denied, reason)
        except Exception:  # noqa: BLE001 — a gate error denies, never allows
            return False, f"SSRF gate raised for {ip!r} (fail-closed)"
        if denied is not False:  # anything but an explicit False is DENIED (fail-closed)
            denials.append(reason if isinstance(reason, str) else f"{ip} denied")
    if denials:
        return False, "; ".join(denials)
    return True, f"SSRF gate allowed {','.join(candidates)}"


def _egress_allowed(check: object, target: object) -> tuple[bool, str]:
    """Run the injected egress check, TOTAL. A non-callable check falls back to the loopback pin; any
    exception in the check is a DENY (fail-closed). A verdict that is not an unambiguous
    ``(True, reason)`` is treated as DENY."""
    fn = check if callable(check) else loopback_only_egress
    try:
        verdict = fn(target)
    except Exception:  # noqa: BLE001 — an egress-check error denies, never allows
        return False, "egress check raised (fail-closed)"
    if isinstance(verdict, tuple) and len(verdict) == 2 and verdict[0] is True:
        reason = verdict[1] if isinstance(verdict[1], str) else "allowed"
        return True, reason
    reason = ""
    if isinstance(verdict, tuple) and len(verdict) == 2 and isinstance(verdict[1], str):
        reason = verdict[1]
    return False, reason or "egress denied (fail-closed)"


# ---------------------------------------------------------------------------------------------------
# argv construction (argv list only — never a shell string)
# ---------------------------------------------------------------------------------------------------


def build_argv(probe: GauntletProbe, *, target: object) -> list[str]:
    """Build the CLI argv the injected runner executes. An argv LIST (never a shell string) — no
    ``shell=True``, no interpolation. ``--target`` carries the (already loopback-pinned) endpoint the
    runner binds the generator to. Deterministic: identical ``probe`` + ``target`` → identical argv."""
    probes_csv = ",".join(probe.probes) if probe.probes else "all"
    argv: list[str] = [probe.tool, "--model_type", probe.model_type or "rest", "--probes", probes_csv]
    if probe.model_name:
        argv += ["--model_name", probe.model_name]
    argv += ["--target", "" if target is None else str(target)]
    argv += [str(a) for a in probe.extra_argv]
    return argv


def redacted_argv(argv: Sequence[str]) -> list[str]:
    """A secret-scrubbed copy of an argv, safe to log/observe. Reuses the ONE F3 redaction vocabulary
    (``redact_tool_args`` — ``--api-key``/``Bearer``/``token=``…) so a credential embedded in the argv
    (e.g. an auth flag or a URL userinfo) never reaches a log or span. Total: on any failure, returns
    the argv fully masked rather than leaking it."""
    try:
        out = redact_tool_args({"argv": list(argv)}).get("argv")
        if isinstance(out, list):
            return [x if isinstance(x, str) else str(x) for x in out]
    except Exception:  # noqa: BLE001 — a redaction failure must never leak the raw argv
        pass
    return ["••••" for _ in argv]


# ---------------------------------------------------------------------------------------------------
# envelope interpretation (total on any runner output)
# ---------------------------------------------------------------------------------------------------


def _safe_run_tool(run_tool: object, argv: Sequence[str]) -> object:
    """Call the injected runner exactly once, TOTAL. Any exception (missing binary, timeout, crash) is
    caught and degraded to ``None`` → interpreted as unavailable."""
    if not callable(run_tool):
        return None
    try:
        return run_tool(list(argv))
    except Exception:  # noqa: BLE001 — a subprocess failure is no signal, never a crash
        return None


def _interpret_envelope(result: object) -> tuple[bool, str]:
    """Interpret a runner envelope into ``(available, report_text)``, TOTAL.

    ``available`` is True ONLY when the envelope is a mapping with ``available is True`` — garak's
    ``{'available': False}`` (not installed) and any non-mapping / malformed result yield
    ``(False, "")`` → zero findings, never a fabricated one. When available, the first present report
    alias is returned as text (a list/dict report is JSON-serialized so the reused string parser can
    read it); an available-but-empty report yields ``(True, "")`` → still zero findings (honest)."""
    if not isinstance(result, Mapping) or result.get("available") is not True:
        return False, ""
    for key in _REPORT_KEYS:
        if key not in result:
            continue
        v = result.get(key)
        if isinstance(v, str):
            return True, v
        if isinstance(v, (list, dict)):
            try:
                return True, json.dumps(v)
            except (TypeError, ValueError):
                return True, ""
    return True, ""


# ---------------------------------------------------------------------------------------------------
# the live result view
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class LiveGauntletReport:
    """The full live-run view: whether the CLI actually ran, the routed findings, and the ASR metric
    surface. ``available`` is honest — ``False`` when garak is not installed or the target was
    egress-denied. ``overall_asr``/``fact_count``/``lead_count`` are descriptive; the FACT/LEAD split was
    decided entirely by ``oracle_kind`` + the injected oracle, never by ASR."""

    tool: str
    available: bool
    egress_allowed: bool
    egress_reason: str
    findings: tuple[Finding, ...] = ()
    overall_asr: float = 0.0
    fact_count: int = 0
    lead_count: int = 0


def _empty_report(tool: str, *, egress_allowed: bool = False, egress_reason: str = "") -> LiveGauntletReport:
    return LiveGauntletReport(
        tool=tool, available=False, egress_allowed=egress_allowed, egress_reason=egress_reason,
    )


def run_gauntlet_report(
    probe: object,
    *,
    target: object,
    oracle: Optional[GauntletOracle] = None,
    run_tool: Optional[RunTool] = None,
    egress_check: Optional[EgressCheck] = None,
) -> LiveGauntletReport:
    """Drive one live gauntlet run and return the full view (findings + ASR metric + honest
    availability). TOTAL and fail-closed on every path — see module docstring. Never raises."""
    try:
        spec_probe = _coerce_probe(probe)
        if spec_probe is None or spec_probe.tool not in KNOWN_TOOLS:
            tool = spec_probe.tool if spec_probe is not None else (probe if isinstance(probe, str) else "")
            return _empty_report(tool if isinstance(tool, str) else "")
        tool = spec_probe.tool

        # (1) egress pin — a non-loopback / unparseable / denied target never reaches the runner.
        allowed, reason = _egress_allowed(egress_check, target)
        if not allowed:
            return _empty_report(tool, egress_allowed=False, egress_reason=reason)

        # (2) subprocess boundary — no runner wired is no signal (fail-closed).
        if not callable(run_tool):
            return _empty_report(tool, egress_allowed=True, egress_reason=reason)

        # (3) run the CLI out-of-process (once) and interpret its envelope, totally.
        argv = build_argv(spec_probe, target=target)
        available, report_text = _interpret_envelope(_safe_run_tool(run_tool, argv))
        if not available:
            # garak not installed / crashed → honest empty result, never a fabricated finding.
            return _empty_report(tool, egress_allowed=True, egress_reason=reason)

        # (4) parse + route through the reused, hardened sensor core. The report is replayed to the
        #     sensor (the runner already fired once); routing — and thus the sovereign FACT/LEAD
        #     invariant — is enforced there, not re-implemented here.
        def _replay(_argv: Sequence[str]) -> str:
            return report_text

        spec = GauntletSpec(
            tool=tool, argv=tuple(argv), run_tool=_replay, seed=spec_probe.seed, target=str(target),
        )
        result: GauntletResult = _sensor_run_gauntlet(spec, oracle=oracle)
        return LiveGauntletReport(
            tool=tool, available=True, egress_allowed=True, egress_reason=reason,
            findings=tuple(result.findings), overall_asr=result.overall_asr,
            fact_count=result.fact_count, lead_count=result.lead_count,
        )
    except Exception:  # noqa: BLE001 — the whole adapter is total on any unexpected input
        return _empty_report(probe.tool if isinstance(probe, GauntletProbe) else "")


def run_gauntlet(
    probe: object,
    *,
    target: object,
    oracle: Optional[GauntletOracle] = None,
    run_tool: Optional[RunTool] = None,
    egress_check: Optional[EgressCheck] = None,
) -> list[Finding]:
    """The live AI-Gauntlet entrypoint: ``run_gauntlet(probe, *, target, oracle, run_tool) ->
    list[Finding]``. Drives a real garak/PyRIT CLI through the injected ``run_tool`` subprocess boundary,
    parses its report, and routes each candidate by ``oracle_kind`` — a deterministic kind the injected
    oracle CONFIRMS becomes a signed FACT; every ``judge_llm`` (and unmapped) candidate stays a LEAD.

    garak unavailable / runner error / non-loopback target / malformed output → ``[]``, never a
    fabricated finding. ASR is computed as a metric (see :func:`run_gauntlet_report`), never a promotion
    signal. Deterministic (``probe.seed``-derived challenge token). Never raises."""
    return list(run_gauntlet_report(
        probe, target=target, oracle=oracle, run_tool=run_tool, egress_check=egress_check,
    ).findings)
