"""
live.executor — the GOVERNED live Kali-tool executor (VIGIL-LIVE, §12 WS1a).

This is the binder that replaces the F3/F6 "run a tool" thunk with a real subprocess spawn of a Kali
tool (nmap/nuclei/httpx/ffuf/sqlmap/hydra/nikto/wapiti/zaproxy). Going live changes NOTHING about the
sovereign contract: the LLM only proposes a tool call, only the injected conjunctive gate authorizes it,
and — for this validation — traffic may only reach the loopback substrate. This module is the choke
point that enforces all three, fail-closed, before a single byte of a subprocess spawns.

``execute`` runs a strict, deny-by-default pipeline (every stage refuses BEFORE the subprocess):

  1. **Loopback pin.** The target host is derived from ``tool_args`` and resolved with
     ``socket.getaddrinfo``; the call is REFUSED unless EVERY resolved address is IPv4 loopback
     (``127.0.0.0/8``). A non-loopback / unresolvable / metadata / IPv6-loopback / smuggled-second-host
     target is denied here, before authorization, before any spawn. ``vigil_gateway.denylist``'s
     ``is_egress_denied`` is the shared conscience consulted for the precise deny reason on the
     non-loopback branch (metadata/link-local/private) — it is an INDEPENDENT second refusal, never the
     allow decision (it would "allow" a public IP; loopback is the only allowed set, enforced by
     ``is_loopback``).
  2. **Authorization.** ``tools.authorize_tool_call`` routes the call through the sovereign core: the
     manifest phase → WARDEN tier, a destructive tool floored at A3 + flagged for the m-of-n
     threshold-destruction leg, and the SAME injected conjunctive gate the ReAct core uses. Execution
     proceeds ONLY on ``verdict.allowed`` — a missing/erroring gate, an out-of-phase or unregistered
     tool, or a destructive tool that did not clear the gate's m-of-n leg all DENY.
  3. **Argv build + run.** A per-tool builder constructs an argv LIST (never a shell string) that PINS
     the loopback host:port derived in step 1 and reconstructs the target from the VALIDATED components
     only — so a target that smuggles a second host/URL (``127.0.0.1@evil.com``, ``127.0.0.1 evil.com``)
     can never reach a non-loopback host (client-independent). Any option that would smuggle a host/URL,
     or a required option that is missing/unsafe, makes the builder refuse. The argv runs through the
     INJECTED ``run`` (default: ``subprocess.run``, ``shell=False``, argv list, timeout + output cap).
  3b. **Report absorption (report-file tools only).** ``ffuf``/``nikto``/``wapiti``/``zaproxy`` have no
     usable machine-readable stdout — their JSON (exactly the shape ``framework.v2.imports.parsers``
     parses) goes to a FILE named by a flag — for ``zaproxy``, by the automation plan that flag points
     at. For those the builder ALLOCATES that path itself, inside a private VIGIL-owned directory, and
     this stage reads it back as the call's ``stdout`` (deleting the artifact), demoting the tool's
     console chatter to ``stderr``. See ``_report_path``/``_absorb_report``.

  4. **Signed, redacted record.** The full captured stdout/stderr is hashed and a REDACTED copy (the F3
     ``_redact_str`` vocabulary — Bearer/kv/flag/url-userinfo, plus tool-specific secret argv positions
     masked) is written into a signed, append-only ``ExecRecord``. The RAW output is returned to the
     caller unredacted so the deterministic ORACLE can re-fire over it — the record persists no secret.

Sovereign invariants (the red-pen attacks exactly these):

  * NO subprocess runs unless the target resolves to ``127.0.0.0/8`` AND the gate allows — both,
    fail-closed. Non-loopback → deny before the spawn; gate deny/None/exception → no spawn.
  * A smuggled second host/URL cannot reach a non-loopback host (argv pins the validated loopback host).
  * No ``shell=True``, no arg interpolated into a shell; argv is always a list.
  * Every execution is a signed, REDACTED spine record — no credential leaks into it.
  * Total on malformed input (tool/model/log/arg data is attacker-influenceable): every path degrades to
    a DENY / no-signal and never raises.
  * A destructive tool stays behind the m-of-n leg (via ``authorize_tool_call``'s ``requires_quorum`` +
    the gate's destruction authority — proceed only on allow).

Import-clean: pydantic + stdlib + the reuse seam (``vigil_gateway.denylist``, ``..tools`` governance +
its F3 redactors, ``..agent.state``). Injected callables (``gate``/``run``/``signer``) so the whole
binder is unit-testable without a live kernel, sidecar, or a real tool spawn.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
from dataclasses import dataclass, is_dataclass, replace
from ipaddress import ip_address
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from vigil_gateway.denylist import is_egress_denied

from ..agent.state import Phase
from ..agent.targets import extract_target
from ..tools import authorize_tool_call
from ..tools.mcp_registry import _redact_arg_list, _redact_str

__all__ = ["ExecResult", "ExecRecord", "RunOutcome", "execute", "execute_terminal", "subprocess_runner",
           "derive_gate_binding"]

# Defaults — generous but bounded. A live tool must never hang the loop or fill the spine.
DEFAULT_TIMEOUT: float = 120.0        # seconds; wall-time budget for the whole subprocess
DEFAULT_OUTPUT_CAP: int = 1_000_000   # chars of stdout/stderr retained (per stream) before truncation


# ---------------------------------------------------------------------------------------------------
# small, total coercion + crypto helpers (no wallclock / RNG — deterministic + spine-safe)
# ---------------------------------------------------------------------------------------------------


def _sha256_hex(s: str) -> str:
    return hashlib.sha256((s if isinstance(s, str) else "").encode("utf-8")).hexdigest()


def _as_int(value: Any) -> int:
    """Coerce an injected seq/now coordinate to int, total (bool excluded — ``True`` is not a coordinate)."""
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _sign(signer: Optional[Callable[[bytes], Any]], data: bytes) -> str:
    """Invoke the injected signer over canonical record bytes, fail-closed. A missing/erroring signer or a
    non-str/empty return yields ``""`` (an unsigned record) — never a fabricated signature, never a crash.
    The write path refuses to run at all with no signer wired (see :func:`execute`); this guards the rare
    case of a wired signer that raises AFTER the irreversible spawn, which must not crash the executor."""
    if not callable(signer):
        return ""
    try:
        ref = signer(data)
    except Exception:  # noqa: BLE001 — a signer outage yields an unsigned record, never a crash
        return ""
    return ref if isinstance(ref, str) and ref.strip() else ""


def _cap(s: str, cap: int) -> tuple[str, bool]:
    s = s if isinstance(s, str) else ""
    if cap >= 0 and len(s) > cap:
        return s[:cap], True
    return s, False


# ---------------------------------------------------------------------------------------------------
# the injected run contract + the default subprocess runner
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RunOutcome:
    """What the injected ``run`` returns: the captured streams + lifecycle flags. Deterministic w.r.t. the
    argv; carries no decision. ``exit_code`` is ``None`` on a timeout / spawn failure."""

    exit_code: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


def _decode(b: Any) -> str:
    if isinstance(b, bytes):
        return b.decode("utf-8", errors="replace")
    return b if isinstance(b, str) else ""


def subprocess_runner(argv: list, *, timeout: float = DEFAULT_TIMEOUT,
                      output_cap: int = DEFAULT_OUTPUT_CAP, cwd: Optional[str] = None,
                      env: Optional[dict] = None) -> RunOutcome:
    """The default live runner: spawn ``argv`` with ``subprocess.run``, NO shell, capture both streams
    under a wall-time ``timeout`` and truncate each to ``output_cap``. Total — a timeout or a spawn error
    (OSError/ValueError) degrades to a ``RunOutcome`` with ``exit_code=None``, never an exception. The
    argv is always a LIST; there is no shell and no string interpolation anywhere on this path.

    ``cwd`` runs the child in that directory (a build/git tree). ``env``, when given, is the child's FULL
    environment — pass secrets (e.g. a GH token) HERE, never in ``argv`` (argv shows up in ``ps``/logs);
    both default to inherit-parent, so existing callers are unchanged."""
    args = [str(a) for a in argv]
    try:
        # stdin=DEVNULL: a governed executor is NON-INTERACTIVE — never read the parent's stdin. Without this a
        # bare stdin-reading allowlisted command (e.g. `cat`/`grep <pat>` with no file operand) would block up
        # to the wall-time timeout on an inherited interactive/pipe stdin (red-pen T2 LOW). None of the network
        # tools read stdin either, so this is uniformly correct + fail-fast.
        proc = subprocess.run(args, capture_output=True, timeout=timeout, shell=False, check=False,  # noqa: S603
                              cwd=cwd, env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        out, t1 = _cap(_decode(exc.stdout), output_cap)
        err, t2 = _cap(_decode(exc.stderr), output_cap)
        return RunOutcome(exit_code=None, stdout=out, stderr=err, timed_out=True, truncated=t1 or t2)
    except (OSError, ValueError) as exc:
        return RunOutcome(exit_code=None, stdout="", stderr=f"spawn failed: {type(exc).__name__}: {exc}")
    out, t1 = _cap(_decode(proc.stdout), output_cap)
    err, t2 = _cap(_decode(proc.stderr), output_cap)
    return RunOutcome(exit_code=proc.returncode, stdout=out, stderr=err, truncated=t1 or t2)


def _coerce_outcome(o: Any, cap: int) -> RunOutcome:
    """Duck-type any injected ``run`` return into a capped ``RunOutcome``, total. A fake/echo runner that
    returns a ``RunOutcome`` (or any object exposing the same attributes) is normalised uniformly."""
    out, t1 = _cap(_as_str(getattr(o, "stdout", "")), cap)
    err, t2 = _cap(_as_str(getattr(o, "stderr", "")), cap)
    ec = getattr(o, "exit_code", None)
    ec = ec if (ec is None or (isinstance(ec, int) and not isinstance(ec, bool))) else None
    return RunOutcome(exit_code=ec, stdout=out, stderr=err,
                      timed_out=bool(getattr(o, "timed_out", False)),
                      truncated=bool(getattr(o, "truncated", False)) or t1 or t2)


# ---------------------------------------------------------------------------------------------------
# the signed, redacted spine record + the caller-facing result
# ---------------------------------------------------------------------------------------------------


class ExecRecord(BaseModel):
    """One append-only, signed record of a governed tool execution. Everything here is REDACTED or a
    content hash — no raw secret ever lands on the spine. ``stdout_sha256``/``stderr_sha256`` commit to
    the RAW captured streams the oracle re-examines, so the record is a provable link to that output
    without storing it in the clear. ``seq``/``now`` are the injected deterministic coordinates."""

    seq: int
    now: int = 0
    kind: str = "live.exec"
    tool: str = ""
    phase: str = ""
    tier: str = ""
    destructive: bool = False
    requires_quorum: bool = False
    target: str = ""                              # the canonical loopback target the argv was pinned to
    argv: list[str] = Field(default_factory=list)  # REDACTED argv (F3 vocabulary + secret positions masked)
    exit_code: Optional[int] = None
    timed_out: bool = False
    truncated: bool = False
    stdout_sha256: str = ""                        # sha256 over the RAW captured stdout
    stderr_sha256: str = ""                        # sha256 over the RAW captured stderr
    stdout: str = ""                               # REDACTED (capped) stdout
    stderr: str = ""                               # REDACTED (capped) stderr
    signature: str = ""                            # injected signer over ``signing_bytes()`` ("" ⇒ unsigned)

    def signing_bytes(self) -> bytes:
        """Canonical bytes the signer signs (signature excluded) — sorted keys + tight separators, so any
        two callers derive byte-identical signing material for the same record."""
        payload = self.model_dump(mode="json")
        payload.pop("signature", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @property
    def record_id(self) -> str:
        return _sha256_hex(self.signing_bytes().decode("utf-8"))


@dataclass(frozen=True)
class ExecResult:
    """The result of an :func:`execute` call. ``ran`` is True only when every gate passed and the runner
    was invoked. ``stdout``/``stderr`` are the RAW captured streams (for the deterministic oracle to
    re-fire over) — the caller must feed only ``record`` (redacted) to the spine, never these. ``argv`` is
    the REDACTED argv (secret-free), ``record`` is the signed spine record (``None`` only on a deny)."""

    tool: str
    ran: bool
    outcome: str                                   # "ran" | "deny"
    reason: str
    tier: str = "A0"
    destructive: bool = False
    requires_quorum: bool = False
    signed: bool = False
    target: str = ""
    argv: tuple[str, ...] = ()
    exit_code: Optional[int] = None
    timed_out: bool = False
    truncated: bool = False
    stdout: str = ""                               # RAW — for the oracle, NOT for the spine
    stderr: str = ""                               # RAW — for the oracle, NOT for the spine
    record: Optional[ExecRecord] = None

    @property
    def allowed(self) -> bool:
        return self.ran


def _deny(tool: Any, reason: str, *, tier: str = "A0", destructive: bool = False,
          requires_quorum: bool = False, target: str = "") -> ExecResult:
    return ExecResult(tool=tool if isinstance(tool, str) else "", ran=False, outcome="deny",
                      reason=reason, tier=tier, destructive=destructive,
                      requires_quorum=requires_quorum, target=target)


# ---------------------------------------------------------------------------------------------------
# loopback resolution + pinning — the sovereign egress gate
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pinned:
    """The VALIDATED target components. The argv builders reconstruct the target from THESE ONLY (never
    the caller's raw string), so a smuggled second host cannot survive into an argv."""

    host: str            # a resolved IPv4 loopback literal (127.0.0.0/8) — the pinned connect host
    port: Optional[int]  # validated int port, or None
    scheme: str          # original url scheme (lowercased), or ""
    path: str            # url path (host-free by urlsplit), may be ""
    query: str           # url query (host-free by urlsplit), may be ""
    raw_host: str        # the original hostname (host-free), for the record/reason only


def _resolve_scoped_target(target: str, *, scope: Any = None,
                           allowed_ips: Optional[frozenset] = None) -> tuple[Optional[_Pinned], str]:
    """Parse + resolve ``target`` and pin the EXACT resolved IP, refusing anything outside the AUTHORIZED
    egress. Total/fail-closed: any parse/resolve failure, malformed port, empty/unresolvable host → (None, r).

    Two modes:
      * ``scope is None`` (default — every direct caller / unit test): LEGACY loopback-only — refuse unless
        every resolved address is IPv4 loopback ``127.0.0.0/8`` (IPv6 ``::1`` refused; IPv4-only per the
        validation charter). The fail-closed default stays loopback, never wider.
      * ``scope`` provided (production, threaded from the SIGNED authority via wiring): the target host must
        be in the signed authority scope (the scope the gate enforces — signature-verified against the
        engagement's governance trust root; owner-tied only when the ``sigil delegate-offense`` ceremony has
        blessed that key) AND every resolved IP must clear the egress floor
        (``is_egress_denied(..., loopback_allowed_if_scoped=True)``); then pin the EXACT resolved IP
        (resolve-once-pin-exact-IP = TOCTOU/DNS-rebind defence). Loopback is reachable ONLY when the signed
        scope authorises it; the metadata/link-local/reserved floor is never liftable by any scope."""
    raw = (target or "").strip()
    if not raw:
        return None, "no target host/url in tool_args (fail-closed)"
    try:
        parts = urlsplit(raw if "://" in raw else "//" + raw)
        host = parts.hostname
        try:
            port = parts.port
        except ValueError:
            return None, "malformed port in target (fail-closed)"
        scheme = (parts.scheme or "").lower()
        path = parts.path or ""
        query = parts.query or ""
    except ValueError:
        return None, "unparseable target (fail-closed)"
    if not host:
        return None, "no host in target (fail-closed)"
    host = host.strip("[]")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError, ValueError):
        return None, f"target host {host!r} did not resolve (fail-closed)"
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4] if len(info) >= 5 else None
        if sockaddr and isinstance(sockaddr[0], str):
            ips.append(sockaddr[0].split("%")[0])   # drop any IPv6 zone id
    if not ips:
        return None, f"target host {host!r} resolved to no address (fail-closed)"

    if scope is None:
        # LEGACY loopback-only path — behaviour byte-identical to the pre-remote pin (fail-closed default).
        for ip in ips:
            try:
                addr = ip_address(ip)
            except ValueError:
                return None, f"resolved address {ip!r} is unparseable (fail-closed)"
            if addr.version == 4 and addr.is_loopback:
                continue
            if addr.is_loopback:   # IPv6 ::1 — loopback, but outside the IPv4 127.0.0.0/8 pin
                return None, (f"REFUSED: {host!r} resolved to IPv6 loopback {ip}; "
                              "egress pinned to IPv4 127.0.0.0/8 only")
            denied, why = is_egress_denied(ip)
            reason = why if denied else f"non-loopback {ip}"
            return None, f"REFUSED: {host!r} resolved to {reason}; egress pinned to 127.0.0.0/8 only"
        pin_host = sorted(ips, key=ip_address)[0]  # deterministic; every ip here is IPv4 loopback
        return _Pinned(host=pin_host, port=port, scheme=scheme, path=path, query=query, raw_host=host), "ok"

    # SCOPED path — signed authority scope + the never-liftable egress floor (remote/LAN/loopback-when-scoped).
    if not scope.matches(host):
        return None, f"REFUSED: {host!r} is not in the signed authority scope (fail-closed)"
    allowed = allowed_ips if allowed_ips is not None else scope.resolved_allowed_ips()
    for ip in ips:
        denied, why = is_egress_denied(ip, allowed, loopback_allowed_if_scoped=True)
        if denied:
            return None, f"REFUSED: {host!r} resolved to {ip} — {why}"
    # every ip cleared the floor and is in-scope; pin the exact resolved IP (TOCTOU/rebind defence). Sort by
    # string for a DETERMINISTIC record on multi-homed hosts (plain str sort avoids the v4/v6 ip_address
    # comparison error while still pinning one of the already-cleared, in-scope addresses).
    pin_host = sorted(ips)[0]
    return _Pinned(host=pin_host, port=port, scheme=scheme, path=path, query=query, raw_host=host), "ok"


def _fmt_host(host: str) -> str:
    """Bracket a bare IPv6 literal for use in a netloc/URL; IPv4 + hostnames pass through unchanged.
    (Loopback IPv4 output is byte-identical to before — the bracketing only affects remote IPv6 targets.)"""
    return f"[{host}]" if (":" in host and not host.startswith("[")) else host


def _display_target(p: _Pinned) -> str:
    h = _fmt_host(p.host)
    return f"{h}:{p.port}" if p.port is not None else h


def _scope_target(p: _Pinned) -> str:
    """The scope-facing target passed to the gate (AUDIT-G4): the VALIDATED hostname (the urlsplit host,
    userinfo-stripped) + port — NOT the resolved IP. For a loopback IP-literal target ``raw_host == host`` so
    this is byte-identical to ``_display_target``; for a hostname/remote target it is the hostname, which is
    what the authority scope (``host_matches_scope``) matches on (the resolved IP never would)."""
    h = _fmt_host(p.raw_host)
    return f"{h}:{p.port}" if p.port is not None else h


def _netloc(p: _Pinned) -> str:
    h = _fmt_host(p.host)
    return f"{h}:{p.port}" if p.port is not None else h


def _pinned_url(p: _Pinned, *, default_scheme: str = "http", ensure_path: str = "/") -> str:
    """Reconstruct a URL from the VALIDATED components only (pinned loopback host). The path/query come
    from urlsplit and are host-free by construction, so nothing here can redirect the connect host."""
    scheme = p.scheme or default_scheme
    path = p.path or ensure_path
    if not path.startswith("/"):
        path = "/" + path
    url = f"{scheme}://{_netloc(p)}{path}"
    if p.query:
        url += "?" + p.query
    return url


# ---------------------------------------------------------------------------------------------------
# argv builders — one per tool. Each PINS the loopback host and refuses smuggled hosts / unsafe options.
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Build:
    argv: list[str]           # the raw argv list to hand the runner
    redacted_argv: list[str]  # the secret-free argv for the spine record
    target: str               # the canonical loopback target the argv was pinned to
    report_path: Optional[str] = None  # report-file tools ONLY: the VIGIL-ALLOCATED artifact `_execute`
    #                                    reads back as the call's machine-readable stdout (never caller-set)


_PORT_SPEC_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")
_CSV_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:,[A-Za-z0-9][A-Za-z0-9._-]{0,63})*$")
_SVC_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$")


def _opt(tool_args: Any, *keys: str) -> Any:
    if not isinstance(tool_args, dict):
        return None
    for k in keys:
        v = tool_args.get(k)
        if v is not None and v != "":
            return v
    return None


def _valid_ports(v: Any) -> Optional[str]:
    if isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 65535:
        return str(v)
    if isinstance(v, str) and _PORT_SPEC_RE.match(v):
        for tok in re.split(r"[,-]", v):
            if not (1 <= int(tok) <= 65535):
                return None
        return v
    return None


def _safe_csv(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _CSV_TOKEN_RE.match(v) else None


def _safe_token(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _SVC_TOKEN_RE.match(v) else None


def _int_in(v: Any, lo: int, hi: int) -> Optional[int]:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if lo <= n <= hi else None


def _bounded_opt(tool_args: Any, keys: tuple, lo: int, hi: int, default: int) -> Optional[int]:
    """A caller-supplied INTEGER knob (a scan bound): ABSENT → the builder's default; PRESENT → it must
    validate inside ``[lo, hi]`` or this returns None and the builder REFUSES the whole call. Refuse
    rather than guess — an out-of-range/garbage bound is never silently replaced by a best-effort value,
    because the caller would then believe it had bounded a scan it had not. The value is only ever placed
    as the VALUE of a flag the builder itself chose, so no caller input can introduce an option."""
    raw = _opt(tool_args, *keys)
    if raw is None:
        return default
    if isinstance(raw, bool):     # True is not a bound
        return None
    return _int_in(raw, lo, hi)


def _local_file(v: Any) -> Optional[str]:
    """A path to an existing LOCAL file (a wordlist/passlist). Refuses a URL or a non-file — a smuggled
    ``http://evil/…`` never satisfies ``isfile`` and never reaches the tool as a fetchable target."""
    if not isinstance(v, str) or not v or "://" in v:
        return None
    try:
        return v if os.path.isfile(v) else None
    except (OSError, ValueError):
        return None


def _safe_login(v: Any) -> Optional[str]:
    """A single username argv token: no whitespace, no leading '-', no scheme. It is one argv element (no
    shell), so injection is impossible; the only risk is it being read as a flag, which the guard bars."""
    if not isinstance(v, str) or not v or v.startswith("-"):
        return None
    if any(c.isspace() for c in v) or "://" in v:
        return None
    return v


def _redact_argv(argv: list, secret_idx: Any = ()) -> list[str]:
    """Secret-free argv for the record: run the F3 arg-list scrubber (``--secret-flag value`` + inline
    secrets, ONE vocabulary) then overlay the tool-specific secret positions the generic scrubber cannot
    know (e.g. hydra's ``-p <password>``, whose flag name is not a recognised secret key)."""
    base = _redact_arg_list([str(a) for a in argv])
    idx = set(secret_idx or ())
    return ["••••" if i in idx else base[i] for i in range(len(base))]


# ---------------------------------------------------------------------------------------------------
# report-file artifacts — for the tools whose machine-readable output is a FILE, not stdout
# ---------------------------------------------------------------------------------------------------
#
# ffuf / nikto / wapiti / zaproxy print human chatter on stdout and write their JSON — exactly the
# shapes ``framework.v2.imports.parsers`` parses (``parse_ffuf_export`` / ``parse_nikto_export`` /
# ``parse_wapiti_export`` / ``parse_zap_export``) — to a file named by a flag. A builder that
# omitted that flag would produce
# output nothing in VIGIL can read, so the builder ALLOCATES the path itself and ``_execute`` reads it
# back (see ``_absorb_report``). The path is derived from the tool + the PINNED target only: the caller
# never supplies, influences, or names it — there is no caller-controlled file-write primitive here.
#
#   * Stale-report defence (a FABRICATION risk, not a hygiene one): the path is deterministic, so a
#     report left by an EARLIER run of the same tool+target would be read back as THIS run's output if
#     the tool crashed, timed out, or was killed before writing. ``_report_path`` therefore UNLINKS the
#     path before returning it and ``_absorb_report`` unlinks again after reading. A run that produced no
#     report yields EMPTY machine-readable output — never another run's bytes. (Two CONCURRENT runs of the
#     same tool against the same target would share the path; the engine loop is serial, and the worst
#     case there is still same-tool/same-target bytes — never a different target's.)
#   * Hijack defence: the root is created 0700 and RE-VALIDATED on every allocation (a real directory,
#     not a symlink, owned by this euid, no group/other bits), so no other local user can pre-create a
#     symlink at the report path and redirect the scanner's write. Any check failing ⇒ None ⇒ the builder
#     REFUSES: a report scanner never runs without a private place to put its report.
_REPORT_DIR_NAME = "vigil-live-reports"

#: The identity every tool this engine drives should present. The doctrine is correlatability, not
#: stealth: an authorised owner-test wants the operator to be able to grep their own logs and find
#: exactly which traffic was ours. Several tools default to a RANDOM browser User-Agent — httpx's
#: `-random-agent` is true unless overridden — which turns an auditable test into an actor a defender
#: cannot distinguish from a crowd of fake browsers. Where a builder can pin this, it does.
#: Matches the agent the rest of the engine already sends, so there is ONE identity, not several.
_CORRELATABLE_USER_AGENT = "OBSIDIAN/1.0 (authorized owner-test)"


def _report_root() -> Optional[str]:
    """The private VIGIL-owned directory every report artifact lives in, or None if it cannot be
    established SAFELY (see the hijack defence above). Total — never raises."""
    try:
        root = os.path.join(tempfile.gettempdir(), _REPORT_DIR_NAME)
        os.makedirs(root, mode=0o700, exist_ok=True)
        st = os.lstat(root)                       # lstat, not stat: a symlink at the root must NOT resolve
    except (OSError, ValueError):
        return None
    if not stat.S_ISDIR(st.st_mode):              # a symlink/file squatting the root path → refuse
        return None
    euid_of = getattr(os, "geteuid", None)
    if callable(euid_of) and st.st_uid != euid_of():
        return None
    if st.st_mode & 0o077:                        # group/other access ⇒ another user could plant a symlink
        try:
            os.chmod(root, 0o700)
            st = os.lstat(root)
        except OSError:
            return None
        if st.st_mode & 0o077:
            return None
    return root


def _report_subdir(name: str) -> Optional[str]:
    """A private per-tool STATE directory under the report root (wapiti's session/config store, ZAP's
    home). Pinning these keeps a scanner from writing into the operator's ``$HOME`` and keeps each run's
    state inside the same 0700 root. None (⇒ the builder refuses) if it cannot be established."""
    root = _report_root()
    if root is None or not re.match(r"^[a-z0-9][a-z0-9-]{0,31}$", name):
        return None
    path = os.path.join(root, name)
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        st = os.lstat(path)
    except (OSError, ValueError):
        return None
    return path if stat.S_ISDIR(st.st_mode) else None


def _report_path(tool: str, key: str) -> Optional[str]:
    """Allocate THIS call's report artifact path: ``<root>/<tool>-<sha256(tool|key)[:16]>.json``, with any
    previous artifact at that path (and at nikto's ``<path>.json`` variant) removed first. Deterministic
    — so the argv, and therefore the signed record, is reproducible — and never caller-named. The
    ``.json`` extension is load-bearing for ZAP, which picks the report FORMAT from it."""
    root = _report_root()
    if root is None:
        return None
    digest = hashlib.sha256(f"{tool}|{key}".encode("utf-8")).hexdigest()[:16]
    path = os.path.join(root, f"{tool}-{digest}.json")
    for candidate in (path, path + ".json"):
        try:
            os.unlink(candidate)
        except FileNotFoundError:
            pass
        except OSError:
            return None      # cannot guarantee a fresh artifact ⇒ refuse rather than risk stale bytes
    return path


def _read_report(path: str, cap: int) -> tuple[str, bool, str]:
    """Read AND REMOVE the report artifact. Returns ``(text, truncated, note)``; a missing/unreadable
    report is ``("", False, "<note>")`` — an empty machine-readable output, never stale bytes. Nikto
    appends the format extension inconsistently across versions, so ``<path>.json`` is accepted too
    (mirroring ``eval.adapters_ext.NiktoAdapter``). Total — never raises."""
    text, truncated, note = "", False, f"[vigil] no machine-readable report was written to {path}"
    for candidate in (path, path + ".json"):
        try:
            with open(candidate, "rb") as fh:
                raw = fh.read(cap + 1 if cap >= 0 else -1)
        except OSError:
            continue
        text, truncated = _cap(raw.decode("utf-8", errors="replace"), cap)
        truncated = truncated or (cap >= 0 and len(raw) > cap)   # byte-level overflow the char cap misses
        note = ""
        break
    for candidate in (path, path + ".json"):
        try:
            os.unlink(candidate)
        except OSError:
            pass
    return text, truncated, note


def _absorb_report(path: str, outcome: RunOutcome, cap: int) -> RunOutcome:
    """For a report-file tool the machine-readable output IS the artifact, so make it the outcome's
    ``stdout`` — the one stream the oracle intake and the import adapters consume — and demote the tool's
    console chatter into ``stderr`` (kept for diagnosis, but where nothing can mistake prose for a
    report). The record's ``stdout_sha256`` then commits to the REPORT, which is the byte string the
    findings actually came from."""
    text, truncated, note = _read_report(path, cap)
    console = outcome.stdout
    parts = [p for p in (outcome.stderr,
                         f"[vigil] tool console stdout:\n{console}" if console else "",
                         note) if p]
    stderr, capped = _cap("\n".join(parts), cap)
    return RunOutcome(exit_code=outcome.exit_code, stdout=text, stderr=stderr,
                      timed_out=outcome.timed_out,
                      truncated=outcome.truncated or truncated or capped)


def _build_nmap(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    # `-oX -` (XML on stdout) is what makes this builder's output READABLE by the engine. The only nmap
    # reader VIGIL has is ``framework.v2.sensors.nmap.parse_nmap_xml``, which consumes `nmap -oX` XML and
    # — being total by design — returns [] for anything else. This builder used to emit nmap's
    # human-readable text, so every scan it drove parsed to ZERO observations: the tool ran, found the
    # open service, and the engine saw nothing, with no error anywhere to say so. The engine's OWN
    # sensor already invokes nmap as `-oX -` (sensors/nmap.py); this makes the executor's argv agree
    # with the reader that exists rather than diverging from it. Caught by tools/livefire —
    # `nmap yes NO — the reader read nothing`.
    argv = ["nmap", "-Pn", "-n", "-oX", "-"]
    ports = _valid_ports(_opt(tool_args, "ports", "port"))
    if ports:
        argv += ["-p", ports]
    elif p.port is not None:
        argv += ["-p", str(p.port)]
    if _opt(tool_args, "service_detection", "sV") is True:
        argv.append("-sV")
    argv.append(p.host)   # a 127.0.0.0/8 literal — never starts with '-'
    return _Build(argv, _redact_argv(argv), _display_target(p))


# ---------------------------------------------------------------------------------------------------
# resolving a tool NAME to the binary the operator DECLARED it means
# ---------------------------------------------------------------------------------------------------
#
# THIS DEFECT HAPPENED TWICE, WHICH IS WHY THE MACHINERY BELOW IS PER-TOOL DATA AND NOT A PER-TOOL FIX.
# The httpx case is written out immediately below. ``_build_zaproxy`` then repeated it exactly: it
# emitted ``argv[0] = "zaproxy"`` while the registry's ZAP ``ToolSpec`` declares
# ``alt_binaries=("zap.sh", "zap-cli")`` AND RESOLVES THEM — so on a host carrying only ``zap.sh`` (the
# name ZAP's own upstream distribution installs; the ``zaproxy`` name comes from the Debian package)
# the operator's tools screen reported ZAP installed and controllable, and every run of it failed to
# spawn. The first fix was httpx-shaped and the drift guard that came with it was httpx-shaped, so
# neither could see the second occurrence one builder away.
#
# So the declaration is now a TABLE (``_DECLARED_TOOLS``) covering every tool whose registry entry
# declares alternate names, every builder for such a tool resolves through ``resolve_tool_binary``,
# and the drift guard is derived from the registry for ALL nine builders rather than for one of them
# (``integration/tests/test_builder_binary_resolution.py``). A tenth builder, or an alternate name
# added to any existing tool, fails that guard instead of shipping a tool the engine cannot spawn.
#
# THE ORIGINAL DEFECT. ``_build_httpx`` emitted ``argv[0] = "httpx"``. On Kali — this framework's
# own platform — ``/usr/bin/httpx`` is the PYTHON HTTP CLIENT's CLI, an unrelated program that happens
# to share the name, and ProjectDiscovery's httpx ships as ``/usr/bin/httpx-toolkit`` PRECISELY because
# of that collision. So on a stock box this builder could never reach the tool it was written for: it
# either spawned the impostor (which prints "The httpx command line client could not run…" and exits)
# or failed to spawn at all. Every other part of the argv was verified correct against the real binary.
#
# WHY THIS IS NOT AN IMPLICIT FALLBACK. Silently executing a DIFFERENTLY-NAMED program is a supply-chain
# decision, and an executor must never make it on the operator's behalf — a previous reviewer refused to
# add a fallback for exactly that reason, and that reasoning stands. Nothing is invented here. The
# decision was already MADE, explicitly and reviewably, in ``framework/v2/tools/registry.py``: its
# ``ToolSpec`` for ``httpx`` declares ``alt_binaries=("httpx-toolkit",)`` — the other name the SAME tool
# installs under — and ``wrong_markers``, the version-banner substrings that identify a DIFFERENT tool
# squatting the name. That declaration is the operator-visible artifact: it drives the tools screen's
# installed/shadowed/missing status, the installer, and the manual install hint. This resolver HONOURS
# the declaration; it never widens it.
#
# WHY THESE CONSTANTS ARE COPIED RATHER THAN IMPORTED. ``live.executor`` is sovereign-side and must never
# import ``framework`` (the P5 two-env boundary) — the same constraint that makes
# ``framework/v2/tools/profile.py`` MIRROR this module's ``_BUILDERS`` keys in ``_TYPED_BUILDER_TOOLS``
# instead of importing them. So the declaration is mirrored here in the same shape, and a DRIFT-GUARD
# test (``integration/tests/test_builder_binary_resolution.py``) parses the registry's SOURCE and asserts
# this mirror still equals it. A name added to (or removed from) the registry and forgotten here fails
# the build instead of silently rotting.
#
# The resolution ORDER and the empty-banner behaviour deliberately match ``registry._resolve_with_banner``
# exactly, so what the operator's tools screen reports as the resolved binary is the binary that actually
# runs. A divergence between "what the screen says" and "what ran" is the very class of defect this work
# exists to remove.

_BINARY_PROBE_TIMEOUT_S: float = 2.0            # mirrors registry._VERSION_TIMEOUT_S


@dataclass(frozen=True)
class _DeclaredTool:
    """One registry ``ToolSpec``'s BINARY DECLARATION, mirrored on the sovereign side.

    ``names``          ``(binary, *alt_binaries)`` in the registry's own resolution order.
    ``version_args``   the flag that produces the identifying banner (``()`` where the registry
                       declares ``version_args=None`` — a GUI/daemon wrapper that must not be launched
                       to read a version; with no banner there is nothing to disambiguate, which is
                       exactly why such a tool declares no ``wrong_markers`` either).
    ``wrong_markers``  banner substrings that identify a DIFFERENT tool squatting the name.
    ``apt``            the package that provides the real binary — the install hint in a refusal.
    """

    names: tuple[str, ...]
    version_args: tuple[str, ...] = ()
    wrong_markers: tuple[str, ...] = ()
    apt: str = ""


#: The mirror. One entry per tool whose registry ``ToolSpec`` declares ``alt_binaries`` — those are the
#: tools where a bare name is not enough to reach the binary, and the ONLY tools a builder may resolve
#: through, because resolution honours the operator's declaration and never widens it. Kept equal to
#: ``framework/v2/tools/registry.py`` by the drift guard, which derives the expected content from the
#: registry SOURCE for every builder in ``_BUILDERS`` — so a tool that GAINS an alternate name there and
#: is forgotten here fails the build rather than silently becoming unspawnable.
_DECLARED_TOOLS: dict[str, _DeclaredTool] = {
    # ProjectDiscovery's httpx, which Kali ships as `httpx-toolkit` because the plain name belongs to
    # the unrelated Python HTTP client whose banners are the `wrong_markers` below.
    "httpx": _DeclaredTool(
        names=("httpx", "httpx-toolkit"),
        version_args=("-version",),
        wrong_markers=("command line client could not run", "options] url", "no such option",
                       "pip install"),
        apt="httpx-toolkit"),
    # OWASP ZAP. `zaproxy` is the Debian package's launcher name; `zap.sh` is what ZAP's own upstream
    # distribution installs, and `zap-cli` is the third declared name. No version probe (the registry
    # declares `version_args=None`: this is a GUI/daemon wrapper and reading a version means launching
    # it), hence no banner and no impostor check — the first declared name on PATH is the answer, which
    # is precisely what the registry's own resolver does for a spec with no `wrong_markers`.
    "zaproxy": _DeclaredTool(names=("zaproxy", "zap.sh", "zap-cli"), apt="zaproxy"),
}


def _which(name: str) -> Optional[str]:
    """PATH lookup for ``name``. Kept as a module-level seam (rather than an inline ``shutil.which``)
    so a test can pin the box's PATH exactly — a unit test of an argv must not depend on which security
    tools happen to be installed on the machine running it. Total: never raises."""
    try:
        return shutil.which(name)
    except Exception:  # noqa: BLE001 — a broken PATH env is "not found", never a crash
        return None


def _version_banner(path: str, version_args: tuple[str, ...]) -> str:
    """Best-effort, read-only capture of a binary's version banner (stdout+stderr) — the evidence used to
    tell WHICH tool sits on a shared name. Mirrors ``registry._probe_raw``: no shell, stdin closed, a
    throwaway cwd (a "read-only" probe must not litter the operator's tree), a hard timeout, and a total
    contract — a spawn error or timeout yields ``""``.

    This runs AFTER the loopback/scope pin and AFTER the conjunctive gate has allowed the call (builders
    are only reached at step 3 of ``_execute``), and it spawns the very binary the call is authorised to
    run, with a version flag and no network target. It is not a new egress surface."""
    if not version_args:
        return ""            # nothing to ask ⇒ no banner ⇒ cannot disambiguate (see _resolve_declared_binary)
    try:
        with tempfile.TemporaryDirectory(prefix="vigil-verprobe-") as td:
            proc = subprocess.run(  # noqa: S603 — fixed argv (resolved path + our flag), shell=False
                [path, *version_args], capture_output=True, text=True,
                timeout=_BINARY_PROBE_TIMEOUT_S, stdin=subprocess.DEVNULL, check=False, cwd=td,
                shell=False)
    except Exception:  # noqa: BLE001 — timeout/spawn error/decode error ⇒ no banner, never a crash
        return ""
    return (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")


def _resolve_declared_binary(names: tuple[str, ...], *, version_args: tuple[str, ...] = (),
                             wrong_markers: tuple[str, ...] = (),
                             apt: str = "") -> tuple[Optional[str], str]:
    """Resolve a declared tool name to the ABSOLUTE path of the binary it means.

    Returns ``(path, "")`` when a usable binary was found, else ``(None, reason)`` where ``reason`` names
    EVERY name that was tried and what was found on each — so a refusal tells the operator what to install
    instead of leaving them to guess. Never raises.

    Rules (all three matter):

      * Names are tried in the DECLARED order (primary first, then the registry's ``alt_binaries``).
      * With ``wrong_markers`` set, each candidate's version banner is read and a candidate whose banner
        identifies a DIFFERENT tool is SKIPPED, never run — the impostor is never a fallback, and never
        the result even when it is the only thing on PATH.
      * A candidate whose banner is EMPTY cannot be disambiguated, and is accepted (trust-PATH). This is
        the registry's own documented default: no known impostor shadows one of these names with zero
        output, while the real tool prints a version. Accepting it here keeps the executor's resolution
        byte-identical to the status the operator's tools screen shows.
    """
    impostor: str = ""
    tried: list[str] = []
    for name in names:
        path = _which(name)
        if not path:
            tried.append(f"{name}: not on PATH")
            continue
        path = os.path.abspath(path)
        if not wrong_markers:
            return path, ""
        banner = _version_banner(path, version_args)
        low = banner.lower()
        if banner.strip() and any(m in low for m in wrong_markers):
            first = (banner.strip().splitlines() or [""])[0][:80]
            tried.append(f"{name}: {path} is a DIFFERENT tool of the same name ({first!r})")
            impostor = impostor or path
            continue
        return path, ""
    detail = "; ".join(tried) or "no candidate names were declared"
    hint = f" — install it: sudo apt-get install -y {apt}" if apt else ""
    lead = ("the only binaries of these names on PATH are a different tool"
            if impostor else "none of these binaries is on PATH")
    return None, (f"no usable {names[0] if names else '?'} binary: {lead} "
                  f"[{detail}]{hint}")


def resolve_tool_binary(tool: str) -> tuple[Optional[str], str]:
    """``(path, "")`` / ``(None, reason)`` for the binary the executor will actually spawn for ``tool``.

    THE ONE resolution entry point, for two reasons. Inside this module it is what makes the fix
    per-DECLARATION rather than per-builder: a builder asks for its tool by name and gets whatever the
    registry declared, so the next tool to gain an alternate name needs no new code here. Outside it, it
    is how any caller that reports tool readiness (the live-fire harness's ``resolved_binary``, a tools
    screen) can resolve a name EXACTLY the way the run will — a harness that resolved a name itself
    would be checking a different binary from the one about to run, which is the very divergence this
    machinery exists to remove.

    A tool with no ``_DECLARED_TOOLS`` entry has no declared alternates, so its bare name IS the
    declaration; that is stated as an explicit outcome rather than an error, so a caller asking about
    any of the nine builders gets an answer."""
    spec = _DECLARED_TOOLS.get(tool)
    if spec is None:
        path = _which(tool)
        return (os.path.abspath(path), "") if path else (None, f"no usable {tool} binary: "
                                                               f"[{tool}: not on PATH]")
    return _resolve_declared_binary(spec.names, version_args=spec.version_args,
                                    wrong_markers=spec.wrong_markers, apt=spec.apt)


def _resolve_httpx_binary() -> tuple[Optional[str], str]:
    """The declared-binary resolution for ``httpx``: ProjectDiscovery's httpx, under either name it is
    declared to install as, and never the same-named Python HTTP client. ``(path, "")`` or
    ``(None, reason)``. Kept as a named function because ``tools/livefire`` binds it by name."""
    return resolve_tool_binary("httpx")


def _build_httpx(tool_args: Any, p: _Pinned) -> "_Build | str | None":
    # argv[0] is the RESOLVED ABSOLUTE PATH, not the bare name: on this framework's own platform the bare
    # name reaches an unrelated program (see the section above). Recording the absolute path is the point
    # — the signed record then says exactly WHICH binary produced the bytes the oracle read, so a run
    # driven by `/usr/bin/httpx-toolkit` is distinguishable after the fact from one driven by whatever
    # else happened to own the name. If no declared binary is present, REFUSE with the reason (both names
    # + the install hint) rather than spawn something that is not this tool.
    binary, why = resolve_tool_binary("httpx")
    if binary is None:
        return why
    url = _pinned_url(p)
    # `-json`: ProjectDiscovery httpx writes JSONL — ONE JSON object per probed URL, one per line — on
    # stdout, which is the stream `_execute` hashes into the record and hands the oracle/reader. `-silent`
    # keeps its banner and progress chatter off that stream so the JSONL is not interleaved with prose.
    # Emitting the tool's default human-readable line here would repeat the nmap defect: a driver whose
    # output no engine reader can consume runs, finds the service, and reports nothing.
    #
    # `-probe`: a probe that DID NOT CONNECT is recorded rather than dropped. Without it httpx writes
    # ZERO BYTES for a host with nothing listening (measured on this box: `httpx-toolkit -u
    # http://127.0.0.1:<closed>/ -silent -json` → empty, exit 0), which is byte-identical to "httpx never
    # ran" — so a negative result carries no evidence that the tool reached its conclusion. With it the
    # same run emits `{"url":…,"error":"… connection refused","status_code":0,"failed":true}`: a
    # positive, recognisable no-endpoint-here artifact. This is the same argument `_build_ffuf` makes for
    # taking ffuf's report file over its `-json` stream, and it costs the POSITIVE case nothing —
    # `parse_httpx_export` drops every `failed: true` record, so a refused connection still mints no
    # observation and a host that refused the connection never enters the world-model as an asset.
    # `-H User-Agent: …` — httpx's own `-random-agent` DEFAULTS TRUE (verified against the installed
    # binary's help text), so without this every probe goes out under a randomly-chosen browser
    # identity. That is the exact inversion of this system's doctrine: an authorised owner-test is
    # meant to be CORRELATABLE, so the operator can grep their own logs and find this traffic — "you
    # are not evading them". A tool quietly behaving like an evasive one, inside a system whose whole
    # claim is that it is authorised and auditable, is a defect even though it trips no gate. It was
    # invisible precisely because it is a DEFAULT, not a flag anyone wrote down.
    #
    # An explicit header overrides the random agent and matches the identity the rest of the engine
    # already sends, so a defender sees one consistent actor rather than a crowd of fake browsers.
    argv = [binary, "-u", url, "-silent", "-no-color", "-disable-update-check",
            "-H", f"User-Agent: {_CORRELATABLE_USER_AGENT}", "-json", "-probe"]
    return _Build(argv, _redact_argv(argv), url)


def _build_nuclei(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    url = _pinned_url(p)
    argv = ["nuclei", "-target", url, "-jsonl", "-no-color", "-disable-update-check"]
    tags = _safe_csv(_opt(tool_args, "tags"))
    if tags:
        argv += ["-tags", tags]
    sev = _safe_csv(_opt(tool_args, "severity"))
    if sev:
        argv += ["-severity", sev]
    return _Build(argv, _redact_argv(argv), url)


_FFUF_MAX_TIME = 90       # seconds of in-tool scan budget (override: `max_time`, 1..3600) — see below


def _build_ffuf(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    # `-of json -o <report>` is what makes this builder's output READABLE by the engine. ffuf's default
    # output is the progress table it draws on the console, which nothing in VIGIL parses; the engine's
    # only ffuf reader (``framework.v2.imports.parsers.parse_ffuf_export``) consumes ffuf's own JSON
    # report — the `{commandline, time, results: [...], config: {...}}` object its `-of json` writer
    # emits. Leaving the default would repeat the nmap defect exactly: the tool runs, discovers the
    # path, and the engine sees nothing, with no error anywhere to say so.
    #
    # The REPORT FILE, not `-json` on stdout, and for soundness rather than taste:
    #   * ffuf ALWAYS writes the report, and a scan that matched nothing writes `"results": []`. That is
    #     a positive, recognisable clean-scan artifact. `-json` emits NOTHING AT ALL for a clean scan,
    #     which is byte-identical to "ffuf never ran" — and a negative control whose silence cannot be
    #     told apart from a dead tool is not evidence. (Same argument as the stale-report defence
    #     above, and as `_build_zaproxy`'s "a silent no-op scan is worse than a refusal".)
    #   * `-json` base64-encodes every result's `input` values (measured on ffuf 2.1.0: `"FUZZ":
    #     "YWJvdXQ="`); the report file writes them plainly.
    # `_absorb_report` then makes the report the call's stdout, and ffuf's console table becomes stderr.
    #
    # `-maxtime` IS PART OF MAKING THE OUTPUT READABLE — it is not hygiene, and it is why this builder
    # carries an in-tool budget like the three report scanners below. ffuf writes its report ONCE, when
    # the job ends. The executor kills an over-running subprocess at its wall clock, and `subprocess.run`
    # kills with SIGKILL, which ffuf cannot catch: measured on ffuf 2.1.0 against a loopback target with a
    # 400k-entry wordlist, `timeout -s KILL 6` left NO report file at all (exit 137), so the call returned
    # empty machine-readable output with nothing anywhere to say the scan had been cut off. The same run
    # given `-maxtime 5` instead exited 0 at 5.2s and DID write its report, holding everything found so
    # far. A wordlist big enough to outlast `DEFAULT_TIMEOUT` is the normal case for content discovery
    # (`directory-list-2.3-medium` is ~220k entries), so without this the common ffuf run reports nothing
    # — the same silent no-op `_build_zaproxy` refuses to ship. The default fits inside `DEFAULT_TIMEOUT`
    # for the reason the nikto block states: a caller who wants a longer scan must raise BOTH this knob
    # and `execute(timeout=…)`, and the bound is never silently assumed for them.
    wordlist = _local_file(_opt(tool_args, "wordlist", "wordlist_path", "wordlist_file"))
    if not wordlist:
        return None
    maxtime = _bounded_opt(tool_args, ("max_time", "maxtime"), 1, 3600, _FFUF_MAX_TIME)
    if maxtime is None:
        return None                      # an out-of-range/garbage bound: refuse rather than guess
    path = p.path or "/"
    if "FUZZ" not in path and "FUZZ" not in (p.query or ""):
        path = (path.rstrip("/") or "") + "/FUZZ"
    url = _pinned_url(replace(p, path=path))
    report = _report_path("ffuf", url)
    if report is None:
        return None
    argv = ["ffuf", "-u", url, "-w", wordlist, "-noninteractive",
            "-maxtime", str(maxtime), "-of", "json", "-o", report]
    return _Build(argv, _redact_argv(argv), url, report_path=report)


def _build_sqlmap(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    url = _pinned_url(p)
    argv = ["sqlmap", "-u", url, "--batch", "--disable-coloring"]
    level = _int_in(_opt(tool_args, "level"), 1, 5)
    if level is not None:
        argv += ["--level", str(level)]
    risk = _int_in(_opt(tool_args, "risk"), 1, 3)
    if risk is not None:
        argv += ["--risk", str(risk)]
    data = _opt(tool_args, "data")
    if isinstance(data, str) and data:
        # a POST body sent to the PINNED host; it cannot change the connect host. Inline secrets in it are
        # scrubbed by _redact_str in the record (one vocabulary).
        argv += ["--data", data]
    # `--flush-session` — a FRESH scan, never a resumed one. This is a SOUNDNESS fix, not hygiene.
    # sqlmap keys its session store by HOSTNAME ONLY (output/<host>/session.sqlite), so a confirmed
    # injection point found at one host:PORT is silently resumed and re-reported for every other port on
    # that same host. On loopback — where the whole range, and every VIGIL twin/control, is 127.0.0.1 —
    # that means a target with NO injectable parameter inherits the previous target's verdict, and the
    # engine's own sqlmap reader mints it as a real observation against a host that has none. Measured
    # by tools/livefire: one run wrote BOTH the vulnerable app and the parameterized hardened control
    # into sqlmap's results CSV with an identical `BTU` technique set, the control's coming entirely
    # from "sqlmap resumed the following injection point(s) from stored session". A per-run
    # XDG_DATA_HOME does not fix it: both legs share one hostname WITHIN a run.
    # Placement is load-bearing and goes LAST for the same reason _build_wapiti documents: the shared F3
    # arg scrubber treats any flag whose name contains "session" as secret-bearing and masks the arg
    # AFTER it, so anywhere else this would blank a neighbouring FLAG (`--batch` → ••••) and make the
    # signed record misdescribe the run.
    argv.append("--flush-session")
    return _Build(argv, _redact_argv(argv), url)


# --- hydra's http-*-form module option -------------------------------------------------------------
#
# A form login is the commonest credential surface there is, and until this existed the hydra builder
# could not attack one: `service` is validated as a bare token, and hydra's form modules are useless
# without their module option (`[ERROR] the variables argument needs at least the strings ^USER^,
# ^PASS^, ^USER64^ or ^PASS64^: (null)` — hydra 9.7, measured). Every form login on the range was
# therefore undrivable.
#
# The option is a COLON-SEPARATED triple, `path:body:condition`, and it is BUILT HERE from three
# separately-validated components — never passed through as caller text. That is what makes the two
# properties provable rather than hoped for:
#
#   * IT CANNOT INTRODUCE A SECOND TARGET. hydra takes its target host from the positional `server`
#     argument alone; the module option carries a request PATH. A colon is the option's own field
#     separator AND the only way to reach hydra's other module options (`H=` extra header, `C=` cookie
#     path) — so a colon is rejected outright in all three components, which also makes `://`
#     unconstructible. A leading `//` is rejected as well: `//evil/x` is a network-path reference to a
#     reader that resolves it, and there is no reason to allow the ambiguity.
#   * IT CANNOT INTRODUCE A FLAG. The spec is the VALUE of `-m`, a flag chosen here, and it must begin
#     with `/`, so it can never be read as an option however hydra's getopt is fed.
#
# The CONDITION is prose matched against the response, so it may contain single spaces. It may not
# contain a RUN of spaces: hydra echoes the module option back into the `misc:` field of the very
# `[port][service] host: … login: … password: …` line the engine's hydra reader parses, and that
# line's fields are separated by exactly three spaces. A condition able to contain `   login: ` could
# forge a field boundary in the tool output the reader trusts. Single spaces cannot.
_HYDRA_FORM_SERVICES = frozenset({"http-get-form", "http-post-form",
                                  "https-get-form", "https-post-form"})
# An absolute, host-free request path (+ optional query). No colon, no whitespace, no backslash
# (hydra's `\:` escape), no `^` (its placeholder marker).
_FORM_PATH_RE = re.compile(r"^/[A-Za-z0-9._~%?&=+,@!$'()*;/-]{0,255}$")
# The form body template. The path alphabet plus `^` for the ^USER^/^PASS^ placeholders.
_FORM_BODY_RE = re.compile(r"^[A-Za-z0-9._~%?&=+,@!$'()*;/^-]{1,512}$")
# The success/failure condition: prose, so SPACE is in the alphabet (but see the run-of-spaces rule).
_FORM_COND_RE = re.compile(r"^[A-Za-z0-9._~%?&=+,@!$'()*;/ -]{1,256}$")


def _valid_form_component(value: Any, pattern: "re.Pattern[str]") -> bool:
    """A form-spec component: a str matching its strict alphabet, with no run of two or more spaces
    (which could forge a field boundary in the tool output the engine's hydra reader parses)."""
    return isinstance(value, str) and bool(pattern.fullmatch(value)) and "  " not in value


def _hydra_form_option(tool_args: Any, service: str) -> tuple[bool, str]:
    """``(ok, module_option)`` for hydra's ``-m``. ``ok`` False ⇒ the builder REFUSES the whole call.

    A form module REQUIRES the spec (hydra errors out without it); a NON-form module refuses one
    outright rather than dropping it silently — a caller that supplied a login form and got an
    unauthenticated root-path attack instead would believe it had tested something it had not.
    Exactly one of the failure / success condition must be given, and it is emitted with hydra's own
    explicit `F=` / `S=` marker so the third field can never be read as anything else."""
    path = _opt(tool_args, "form_path", "path")
    body = _opt(tool_args, "form_body", "form_params", "body")
    fail = _opt(tool_args, "form_fail", "failure", "fail_string")
    success = _opt(tool_args, "form_success", "success", "success_string")
    supplied = any(v is not None for v in (path, body, fail, success))

    if service not in _HYDRA_FORM_SERVICES:
        return (not supplied, "")        # form keys on a non-form module → refuse, never silently drop
    if not supplied:
        return (False, "")               # a form module without its spec cannot attack anything
    if (fail is None) == (success is None):
        return (False, "")               # exactly one condition, never both and never neither
    if not _valid_form_component(path, _FORM_PATH_RE) or path.startswith("//"):
        return (False, "")
    if not _valid_form_component(body, _FORM_BODY_RE):
        return (False, "")
    if "^USER^" not in body or "^PASS^" not in body:
        # Without both, hydra substitutes nothing and the run tests one fixed pair. Its base64
        # placeholders (`^USER64^`/`^PASS64^`) are deliberately NOT on offer: the narrower form is
        # the one the range needs, and a capability nobody has asked for is a surface for free.
        return (False, "")
    marker, condition = ("F=", fail) if fail is not None else ("S=", success)
    if not _valid_form_component(condition, _FORM_COND_RE):
        return (False, "")
    return (True, f"{path}:{body}:{marker}{condition}")


def _build_hydra(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    service = _safe_token(_opt(tool_args, "service", "module"))
    if not service:
        return None
    ok, module_option = _hydra_form_option(tool_args, service)
    if not ok:
        return None
    argv = ["hydra"]
    if p.port is not None:
        argv += ["-s", str(p.port)]
    user = _safe_login(_opt(tool_args, "username", "user", "login"))
    userfile = _local_file(_opt(tool_args, "userlist", "user_file", "username_file"))
    if user:
        argv += ["-l", user]
    elif userfile:
        argv += ["-L", userfile]
    else:
        return None
    secret_idx: set[int] = set()
    passwd = _opt(tool_args, "password", "pass")
    passfile = _local_file(_opt(tool_args, "passlist", "password_file", "password_list"))
    if isinstance(passwd, str) and passwd and not passwd.startswith("-"):
        argv += ["-p", passwd]
        secret_idx.add(len(argv) - 1)   # the inline password is the secret position the record must mask
    elif passfile:
        argv += ["-P", passfile]
    else:
        return None
    if module_option:
        # After the password block so `secret_idx`, computed above, still indexes the right argv slot.
        #
        # WHAT THE RECORD SHOWS, stated exactly, because it is not simply "the password is masked". The
        # shared F3 arg scrubber sees the `password=` assignment inside this one argv element and masks
        # from there to the next WHITESPACE — and the only whitespace in the spec is inside the failure
        # condition, so the mask runs across the field separator and swallows the `F=` marker too. A run
        # built from `/login`, `username=^USER^&password=^PASS^`, `F=Invalid credentials` is recorded as
        # `-m /login:username=^USER^&password=•••• credentials` (measured, live). So the record shows
        # WHICH form path and which fields were attacked but NOT the condition that decided success.
        #
        # That loss is accepted rather than fixed, because the alternative is worse. The spec is not
        # secret-free by construction: its body is a caller-supplied template, and a form that needs a
        # literal alongside the placeholders (`&api_key=…`) puts that literal in this exact string. An
        # exemption that kept the element verbatim would therefore write real caller secrets into the
        # signed spine record. Masking a value we cannot prove is secret-free is the safe direction; a
        # verbatim exemption is not, and neither is a `preserve` overlay that a future builder could
        # point at genuinely secret text. What must NOT happen — a masked FLAG, which would make the
        # record misdescribe the option set itself — does not happen here: `-m` is untouched, and so is
        # every flag around it (`_is_secret_key("m")` is False). The argv handed to the runner is the
        # true spec; only the record's copy is masked.
        argv += ["-m", module_option]
    argv += [p.host, service]
    # NO `-o <file> -b json`, deliberately, even though hydra's JSON report is the tidier shape to
    # read. That report embeds hydra's OWN `commandline`, and the shared record scrubber does not
    # recognise `-p` as secret-bearing (`_is_secret_key("p")` is False — its vocabulary knows
    # `pw`/`pwd`/`pass`, not the single letter), so an inline-password call would write a plaintext
    # credential into the signed spine record via `_absorb_report`. hydra's STDOUT never echoes its
    # argv, and the scrubber does mask its `password: <value>` result form — both measured on this
    # host. So the engine's hydra reader consumes stdout, and the record keeps its no-credential
    # invariant. See `framework.v2.imports.parsers.parse_hydra_export`.
    return _Build(argv, _redact_argv(argv, secret_idx), f"{_display_target(p)} {service}")


# --- report-file scanners -------------------------------------------------------------------------
# One well-understood invocation each, producing the machine-readable report the matching import adapter
# already parses. Three properties hold for all three (the reason a typed builder beats a skill playbook):
# the target is rebuilt from the VALIDATED pin (`_pinned_url`) and never concatenated from caller text;
# EVERY flag is chosen here (the caller supplies only values that survive a strict validator, so a
# caller string can never become an option); and the run is BOUNDED — the executor's wall-clock
# `timeout` plus each tool's own in-tool caps.

# nikto: a bounded signature sweep. `-Format json -output <file>` is the report `parse_nikto_export`
# reads (an ARRAY of per-host blocks, each with a `vulnerabilities` LIST of `{msg, url}` — nikto's
# report plugin always encodes an array, even for one host). `-nocheck` (no startup update
# fetch), `-nolookup` (no DNS) and `-ask no` remove every request nikto would otherwise make to a host
# OTHER than the pinned target — traffic the egress pin does not cover because nikto, not we, addresses
# it. `-nointeractive` keeps it from blocking on a prompt.
#
# NB every DEFAULT in-tool budget below fits inside ``DEFAULT_TIMEOUT`` on purpose: the executor kills the
# subprocess at its wall clock, and a tool killed before it writes its report produces NOTHING. A caller
# who wants a longer scan must raise BOTH the knob and ``execute(timeout=…)`` — the upper bounds allow
# that, the defaults never assume it.
#
# Nikto's `-Tuning` selects SCAN CATEGORIES, and category `6` is DENIAL OF SERVICE (`nikto -H` on
# 2.6.0; 51 of the 7232 entries in `db_tests` carry it). VIGIL does not classify nikto destructive
# (`wiring.DEFAULT_DESTRUCTIVE_VIEW` = sqlmap/hydra/metasploit), so a DoS category reachable through
# this builder would be a destructive capability delivered by a non-destructive path. A signature
# sweep looking for misconfiguration has no need of it, so it is not on offer: the builder EXCLUDES
# the category by default and REFUSES any tuning that would re-enable it. Refusing is the smaller,
# clearer capability than promoting nikto to the destructive path.
#
# `x` is nikto's per-character negation ("all except the char that follows"), so the DoS category is
# reachable two ways and the naive "reject any '6'" rule gets BOTH backwards: it would refuse `x6`
# (the string that DISABLES DoS) and accept `x1` (which excludes category 1 and therefore leaves DoS
# ON). `_nikto_tuning_runs` reproduces nikto's own include/exclude computation instead — see
# `set_scan_items` in `/usr/share/nikto/plugins/nikto_core.plugin`.
#
# That computation is only well-behaved on tuning strings with DISTINCT characters. Nikto matches
# each category with a /g regex against the SAME scalar, so `pos()` carries between iterations and a
# repeated character silently flips its own classification (`x66` and `x11` do not mean what they
# read as). A repeated category means nothing to a category selector, so the validator rejects
# repeats and the model stays provable: differentially tested against a verbatim transcription of
# that Perl over 40,657 (tuning, category-tag) pairs across 5,115 distinct-character tuning
# strings, with zero divergences.
#
# AND THAT MODEL IS PER-CATEGORY, WHICH IS NOT THE QUESTION THE GATE HAS TO ANSWER. A check's tuning
# tag is a SET (`36`, `1234576890ab`, `b6`, …), so "does category 6 run?" is a different question from
# "can a DoS check run?". `_valid_nikto_tuning` therefore no longer asks the first one: it requires
# the DoS category to be EXCLUDED, which is the only condition that holds independently of what the
# tags contain. Its docstring carries the measurement.
_NIKTO_TUNING_RE = re.compile(r"[0-9abcdex]{1,14}\Z")   # the -Tuning alphabet, nothing else
_NIKTO_DOS_CATEGORY = "6"      # nikto -H: "6  Denial of Service"
_NIKTO_DEFAULT_TUNING = "x6"   # every category EXCEPT denial of service
_NIKTO_MAX_TIME = 90           # seconds of in-tool scan budget (override: `max_time`, 1..3600)
_NIKTO_REQ_TIMEOUT = 10        # seconds per request (override: `request_timeout`, 1..120)


def _nikto_tuning_sets(tuning: str) -> tuple[frozenset, frozenset]:
    """``(included, excluded)`` categories for a DISTINCT-character nikto tuning string, as nikto's
    own ``set_scan_items`` computes them: a category is EXCLUDED when the `x` immediately precedes
    it, INCLUDED otherwise. `x` itself selects nothing."""
    included, excluded = set(), set()
    for i, ch in enumerate(tuning):
        if ch == "x":
            continue
        (excluded if i and tuning[i - 1] == "x" else included).add(ch)
    return frozenset(included), frozenset(excluded)


def _nikto_tuning_runs(tuning: str, category: str) -> bool:
    """Would a check tagged ``category`` RUN under ``-Tuning tuning``? Nikto's rule: an exclude list
    decides alone when it is non-empty (everything but the excluded categories runs); otherwise the
    include list decides; a tuning that selects neither runs nothing at all. An EMPTY tuning is
    nikto's "no -Tuning given" case, which runs every check — including denial of service."""
    if tuning == "":
        return True
    included, excluded = _nikto_tuning_sets(tuning)
    if excluded:
        return category not in excluded
    return category in included


def _valid_nikto_tuning(tuning: object) -> bool:
    """A caller tuning is accepted only when it is the tuning alphabet, names no category twice, and
    puts the DENIAL OF SERVICE category in the EXCLUDE set — which is the only thing that actually
    keeps nikto's DoS checks from running.

    WHY "EXCLUDED", AND NOT "NOT INCLUDED". A check's tuning tag is a SET of categories, not one
    category: nikto matches each tuning character against the whole tag with ``$item[2] =~ /$tune/i``.
    So a check can be DoS *and* something else, and 25 of nikto 2.6.0's 51 DoS checks are — the tags
    in ``db_tests`` are ``6`` (26), ``1234576890ab`` (20), ``36`` (2), ``76``, ``6d`` and ``b6``.
    Judging a tuning by asking "does category 6 run?" therefore answered a question about a single
    character while nikto was answering one about a set, and an include-only tuning walked straight
    through it: ``-Tuning 1`` matches the ``1`` in ``1234576890ab`` and runs 20 DoS checks; ``3`` runs
    22, ``7`` 21, ``b`` 21, ``2`` 20, ``d`` 1. Measured by running nikto's own ``set_scan_items``
    selection loop, transcribed verbatim out of ``/usr/share/nikto/plugins/nikto_core.plugin``, over
    its real ``db_tests``: of the 3,616 distinct-character tunings up to length 3, the previous rule
    accepted 2,568 that still run at least one DoS check.

    The EXCLUDE side does not have that problem, and it is sound WITHOUT knowing the tag set. When the
    exclude list is non-empty it decides alone (nikto's own comment: "if includes is null and excludes
    is not null, add all but excludes" — and the loop sets ``$add = 0`` and breaks on the first exclude
    character that matches). So ``6`` in the excludes means every check whose tag CONTAINS a ``6`` is
    dropped, whatever else that tag says. Under the same measurement the rule below accepts 29 tunings
    and not one of them runs a DoS check — including the builder's default ``x6``.

    The cost is honest and named: an include-only tuning (``-Tuning 1``) is now REFUSED rather than
    silently carrying DoS checks with it. Nikto cannot express "category 1 but not category 6" at all —
    an include list cannot subtract — so there is no narrower rule to write, and the alternative is
    parsing ``db_tests`` at build time and re-deriving the answer from data that changes when the
    operator updates nikto. Refusing is the smaller, checkable capability."""
    if not isinstance(tuning, str) or not _NIKTO_TUNING_RE.fullmatch(tuning):
        return False
    if len(set(tuning)) != len(tuning):
        return False                     # a repeated category: nikto's /g `pos()` makes it unreadable
    _included, excluded = _nikto_tuning_sets(tuning)
    if _NIKTO_DOS_CATEGORY not in excluded:
        return False                     # would leave denial of service reachable → not on offer
    # An exclude-bearing tuning always selects something (everything but the excluded categories), so
    # the "a tuning that runs zero checks is a silent no-op" case cannot arise from here.
    return not _nikto_tuning_runs(tuning, _NIKTO_DOS_CATEGORY)


def _build_nikto(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    url = _pinned_url(p)
    maxtime = _bounded_opt(tool_args, ("max_time", "maxtime"), 1, 3600, _NIKTO_MAX_TIME)
    req_timeout = _bounded_opt(tool_args, ("request_timeout", "timeout"), 1, 120, _NIKTO_REQ_TIMEOUT)
    if maxtime is None or req_timeout is None:
        return None
    tuning = _opt(tool_args, "tuning")   # `_opt` already folds an empty string to None
    if tuning is None:
        tuning = _NIKTO_DEFAULT_TUNING   # NEVER omit -Tuning: nikto's default is EVERY category
    elif not _valid_nikto_tuning(tuning):
        return None                      # off-alphabet, repeated, no-op, or DoS-enabling → refuse
    report = _report_path("nikto", url)
    if report is None:
        return None
    argv = ["nikto", "-h", url, "-Format", "json", "-output", report,
            "-nointeractive", "-ask", "no", "-nocheck", "-nolookup",
            "-maxtime", f"{maxtime}s", "-timeout", str(req_timeout),
            "-Tuning", tuning]
    return _Build(argv, _redact_argv(argv), url, report_path=report)


# wapiti: a bounded crawl+attack whose `-f json -o <file>` report is what `parse_wapiti_export` reads
# (`{"vulnerabilities": {"<category>": [{path, parameter, level}]}}`). The scope enum is deliberately
# NARROWED: `domain`/`subdomain`/`punk` would let the crawler leave the pinned host, which the egress pin
# cannot stop (wapiti resolves those hosts itself), so only the three same-host scopes are offered.
# `--no-bugreport` suppresses wapiti's crash-report upload — egress to a third party, never acceptable
# from a governed run. Session/config stores are pinned inside the report root instead of `$HOME`.
_WAPITI_SCOPES = frozenset({"url", "page", "folder"})
_WAPITI_MAX_SCAN_TIME = 90     # seconds of whole-scan budget (override: `max_scan_time`, 1..3600)
_WAPITI_MAX_ATTACK_TIME = 60   # seconds cap per attack module (so no one module eats the whole budget)
_WAPITI_DEPTH = 2              # crawl depth (override: `depth`, 0..5)
_WAPITI_LINKS_PER_PAGE = 50
_WAPITI_FILES_PER_DIR = 50

# THE DEFAULT MODULE SET EGRESSES TO A THIRD PARTY. Observed in a live-fire run: with no module list
# supplied, wapiti runs its defaults, which include `ssrf` — and that module asks an EXTERNAL endpoint
# of the tool author's choosing for out-of-band results:
#
#   [*] Launching module ssrf
#   [*] Asking endpoint URL https://wapiti3.ovh/get_ssrf.php?session_id=... for results, please wait...
#
# That host was reachable on 443 from this machine. It breaks the charter's hard limit — "no external
# egress; no tool, no DNS, no callback may leave the host" — and the scope pin does NOT protect
# against it: the pin constrains the TARGET, while this is the tool contacting a host of its own. Nor
# does `--no-bugreport`, which is a different path entirely.
#
# So the module set is now DECLARED rather than defaulted. Every module below attacks the pinned
# target directly and needs no third-party collaborator. Out-of-band classes (ssrf, and anything else
# that needs a callback) are deliberately absent: this engine has its own gated out-of-band facility,
# and borrowing a stranger's is neither authorised nor auditable.
#
# A caller may still pass an explicit `modules` list — that path is validated as a plain token CSV —
# but the DEFAULT can no longer reach off-host.
_WAPITI_SAFE_MODULES = (
    "backup,brute_login_form,cookieflags,csp,csrf,exec,file,htaccess,http_headers,"
    "methods,permanentxss,redirect,sql,ssl,xss"
)
#: Modules that reach a THIRD-PARTY HOST — either for an out-of-band callback or for a signature
#: database they fetch themselves. Refused even when a caller names them explicitly: the charter's
#: no-egress limit is not the caller's to waive.
#:
#:   ssrf, log4shell — need an out-of-band collaborator, and wapiti's is the tool author's own host
#:     (`attack.py`: ``external_endpoint`` → ``http://wapiti3.ovh/``, ``dns_endpoint`` →
#:     ``dns.wapiti3.ovh``). Measured live: "Asking endpoint URL https://wapiti3.ovh/get_ssrf.php…".
#:   wapp — NOT an out-of-band module, and it was on the declared-safe list until this run proved it
#:     egresses too. ``mod_wapp.attack`` runs against the root URL of every scan and calls
#:     ``_verify_wapp_database``, which on a missing/unreadable local database falls through to
#:     ``update_wappalyzer()`` — an HTTPS fetch from
#:     ``https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/`` (``attack.py``'s
#:     ``wapp_url`` default). The database lives in wapiti's CONFIG dir, which this builder PINS to a
#:     VIGIL-owned directory that VIGIL never populates (and `wapiti --update` has never been run on
#:     this host: no ``categories.json`` / ``technologies.json`` / ``groups.json`` exists anywhere on
#:     it). So under THIS builder `wapp` can only ever take the download path. A module set is not
#:     "safe by declaration" — every member has to be checked for a host of its own.
_WAPITI_EGRESSING_MODULES = frozenset({"ssrf", "log4shell", "wapp"})

#: THE GUARD IS AN ALLOWLIST, and it has to be.
#:
#: The set above was used as a BLOCKLIST over the caller's module names, and that was unsound —
#: because `-m` is not a list of module names. It is a small language that also accepts PRESET GROUP
#: names, which wapiti expands itself. Measured against the installed wapiti 3.2.10:
#:
#:     modules='ssrf'    -> refused      (the blocklist saw the name)
#:     modules='all'     -> ACCEPTED     -> 36 modules, including ssrf, log4shell AND wapp
#:     modules='common'  -> ACCEPTED     -> 16 modules, including ssrf
#:
#: `all` and `common` are ordinary tokens, so they passed the CSV check and intersected with nothing.
#: A caller could re-open the charter's no-egress limit with three letters, and the test meant to
#: prevent exactly that only ever tried literal module names.
#:
#: Enumerating the presets instead would repeat the mistake one level up: the next release adds a
#: group and the guard silently widens. So a caller may name ONLY a module that appears below — each
#: verified to attack the pinned target directly, with no third party involved. Everything else is
#: refused: a preset, an unknown module, or a module added by a future wapiti. A tool's own vocabulary
#: is not something this engine can safely inherit.
#:
#: AND AN ALLOWLIST THAT OMITS A SAFE MODULE IS A DEFECT, not a conservative default — because the
#: refusal is TOTAL. `_build_wapiti` returns None for the WHOLE call when any one named token is not
#: below, so a single missing name does not narrow a scan, it cancels it. That is exactly what
#: happened to `upload`: it is in wapiti's OWN default set (`wapiti --list-modules`: "exec file
#: permanentxss redirect sql ssl ssrf upload xss") and in its `common` preset, it was omitted here,
#: and the live-fire wapiti row — which drives wapiti's default set minus the egressing `ssrf` —
#: was refused outright on BOTH legs. Measured: `wapiti  NO  NO — the reader read nothing  FAIL`,
#: with the reason "argv builder for 'wapiti' refused the arguments". A driver that had been proven
#: end to end became unprovable, and the failure named the arguments rather than this list.
#: `mod_upload` was then read: it imports only `RequestError` from httpx and attacks the crawled
#: forms of the pinned target — no out-of-band collaborator, no signature database, no host of its
#: own — so it belongs here on the same evidence as every other name in the set.
_WAPITI_ALLOWED_MODULES = frozenset({
    "backup", "brute_login_form", "cookieflags", "crlf", "csp", "csrf", "exec", "file",
    "htaccess", "http_headers", "methods", "permanentxss", "redirect", "sql", "ssl",
    "timesql", "upload", "xss", "xxe",
})


def _build_wapiti(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    url = _pinned_url(p)
    max_scan = _bounded_opt(tool_args, ("max_scan_time", "max_time"), 1, 3600, _WAPITI_MAX_SCAN_TIME)
    depth = _bounded_opt(tool_args, ("depth",), 0, 5, _WAPITI_DEPTH)
    if max_scan is None or depth is None:
        return None
    modules = _opt(tool_args, "modules", "module")
    if modules is not None and _safe_csv(modules) is None:
        return None                      # a module list that is not a plain token CSV → refuse. A leading
        #                                  '-' (wapiti's "deselect" form) fails the token rule by design.
    if modules:
        # ALLOWLIST, not blocklist. Every named token must be a module verified to stay on the pinned
        # target. This refuses an off-host module named directly (`ssrf`), and — the reason a
        # blocklist was unsound — it also refuses a PRESET GROUP name like `all` or `common`, which
        # wapiti would expand into a set containing those very modules. The charter's no-egress limit
        # is not the caller's to waive, so this is a refusal rather than a warning.
        named = {m.strip().lower() for m in str(modules).split(",") if m.strip()}
        if not named or not named <= _WAPITI_ALLOWED_MODULES:
            return None
    else:
        # No list supplied: use the DECLARED safe set rather than wapiti's defaults, which egress.
        modules = _WAPITI_SAFE_MODULES
    scope = _opt(tool_args, "scope")
    if scope is None:
        scope = "folder"
    elif isinstance(scope, str) and scope.strip().lower() in _WAPITI_SCOPES:
        scope = scope.strip().lower()
    else:
        return None                      # an off-host scope (or garbage) → refuse, never widen the pin
    report = _report_path("wapiti", url)
    state = _report_subdir("wapiti-state")
    if report is None or state is None:
        return None
    argv = ["wapiti", "-u", url, "-f", "json", "-o", report,
            "--scope", scope, "-d", str(depth),
            "--max-scan-time", str(max_scan),
            "--max-attack-time", str(min(max_scan, _WAPITI_MAX_ATTACK_TIME)),
            "--max-links-per-page", str(_WAPITI_LINKS_PER_PAGE),
            "--max-files-per-dir", str(_WAPITI_FILES_PER_DIR),
            "--store-session", state, "--store-config", state, "--no-bugreport"]
    if modules:
        argv += ["-m", modules]
    # `--flush-session` (a fresh scan, never a resumed one) goes LAST deliberately: the shared F3 arg
    # scrubber reads any flag whose name contains "session" as secret-bearing and masks the arg AFTER it,
    # so anywhere else it would blank a neighbouring FLAG and make the signed record misdescribe the run.
    argv.append("--flush-session")
    return _Build(argv, _redact_argv(argv), url, report_path=report)


# zaproxy: ZAP driven by its AUTOMATION FRAMEWORK (`-cmd -autorun <plan>`) — crawl the site, wait for
# the passive scanner, ACTIVELY SCAN EVERY URL THE CRAWL FOUND, then write the traditional
# `{"site": [{"alerts": […]}]}` report `parse_zap_export` reads. `-silent` ("ensures ZAP does not make
# any unsolicited requests, including check for updates") and `-notel` hold the same no-third-party-egress
# line as above; `-dir` pins ZAP's home inside the report root so a run cannot mutate the operator's
# `~/.ZAP`. The AUTHORITATIVE bound remains the executor's wall-clock `timeout`, which does not depend on
# ZAP honouring anything.
#
# THIS BUILDER USED TO DRIVE ZAP'S QUICK SCAN (`-quickurl … -quickout <file>`), AND SEEDED WITH A BARE
# HOST THAT SCAN COULD NOT FIND AN INJECTION — not "did not", could not. Measured against the loopback
# range (`infra/loopback/vulnapp.py`, whose `/search?q=` is reflected AND injectable), seeded with the
# host root, ZAP's own log says it in one line:
#
#     HostProcess - Scanning 1 node(s) from http://127.0.0.1:19106
#     completed host/plugin … | CrossSiteScriptingScanRule … 0 message(s) sent and 0 alert(s) raised
#     completed host/plugin … | SqlInjectionScanRule … 0 message(s) sent and 0 alert(s) raised
#
# 99 requests in total, 2 of them to /search and both the benign `q=test` the SPIDER fetched: the crawl
# found the parameter and the active scanner never touched it. The report came back with 4 alerts, all
# passive header hygiene, BYTE-IDENTICAL to the hardened control's — a clean report that meant "I did not
# look". Raising the budget fivefold changed nothing (byte-identical report), because the limit was never
# time. It is structural, and it is in ZAP's own quickstart add-on: `AttackThread.run` builds
# `new Target(accessNode(url))`, spiders with it, and hands the SAME target to the active scanner —
# moving the start node up to its parent ONLY when the node is a leaf whose grandparent is not the tree
# root, which is never true one level under a site node. `setRecurse(true)` is therefore inert: the seed
# leaf has no children, so the active scanner scans exactly the node it was handed and nothing the spider
# discovered. (Read out of `quickstart-release-53.zap`'s bytecode, then confirmed by the log line above.)
# That is the nmap defect's class — a scanner that runs, is not read, and reports nothing — with the
# break one stage earlier: the bytes were readable, there was simply nothing in them.
#
# THE AUTOMATION FRAMEWORK HAS NO SUCH NARROWING. `activeScan`'s `context` parameter means "all URLs of
# the context", so everything the spider added to the sites tree is attacked. Same target, same builder
# budgets, same measurement: `Scanning 5 node(s)` instead of 1, most of the traffic aimed at /search,
# and a report carrying reflected XSS and SQL injection on `q` — 15 findings through
# `parse_zap_export`, where the quick scan produced 0 of either. (ZAP's DOM-XSS rule fires on this
# target too and is deliberately NOT counted here: `_ZAP_NO_BROWSER` below denies it a browser because
# a browser is egress. It raised a third alert before that pin and none after it — a charter decision,
# not this fix's to claim.) The seed is not lost to the crawl either: seeded with `/search?zzz=apple`,
# a parameter name that appears nowhere on the site and is linked from nowhere, the run still reaches 6
# nodes and `search(zzz)` is one of them.
#
# AND A SCAN THAT COULD NOT RUN NOW SAYS SO, WHICH IS THE OTHER HALF. `failOnError: true` with
# `continueOnFailure: false` aborts the plan on a job that cannot reach the target: measured against a
# closed port, exit 1, NO report written at all, and `Job spider failed to access URL … Connection
# refused` on the console this executor keeps as the record's stderr. That is what makes the empty
# report readable as evidence — "nothing was there to attack" is a different, distinguishable artifact
# from "I never got there", which is the distinction a silent negative control destroys.
#
# WHAT IS STILL TRUE AND MUST NOT BE OVERCLAIMED: ZAP attacks the parameters it has SEEN. This makes the
# active scan cover the crawl instead of one node; it does not make the crawl complete. A parameter
# behind a login, behind a budget that expired, or on a URL nothing links to and no caller named is
# still not attacked, and the report will not know it. The bound is stated, not papered over: the plan
# is written with `progressToStdout`, so `Job spider found N URLs` and the per-job timings land in the
# stderr of the signed record next to the report, and a clean report can be read against the coverage
# that produced it.
#
# THE BUDGET IS A CEILING ON THREE STAGES NOW, NOT ONE. Worst case is JVM boot + `max_minutes` of
# crawling + the passive drain + `max_minutes` of active scanning, so a run that spends its whole budget
# outlasts `DEFAULT_TIMEOUT` — and the executor's timeout kills with SIGKILL, before the report job runs,
# leaving NOTHING. ZAP is the one tool here whose realistic run does not fit the default wall clock; its
# floor is one minute because that is the granularity ZAP's own caps use. A caller who wants a ZAP scan
# to COMPLETE must raise `execute(timeout=…)` to match the `max_minutes` they asked for. The builder
# cannot do that for them, and it will not pretend a one-minute default is a full scan.
_ZAP_MAX_MINUTES = 1           # spider AND active-scan budget in minutes (override: `max_minutes`, 1..60)

# The passive scanner has to drain before the report job runs, or alerts that were queued when the
# active scan ended are simply missing from the report. This is a CEILING on that wait, not a sleep:
# measured on the range it finishes in under a second. It is bounded for the reason every other budget
# here is — an unbounded wait is an unbounded run, and the executor's SIGKILL leaves no report at all.
_ZAP_PASSIVE_WAIT_MINUTES = 1

# ZAP starts its MAIN PROXY LISTENER even for a one-shot headless scan, and defaults to 8080 — a port
# very often already in use on an operator's own machine. When it is, ZAP exits 1 after ~10 seconds with
# "Failed to start the main proxy: Address already in use" and writes NO report, while the executor sees a
# process that ran to completion and returns an empty result. A silent no-op scan is worse than a refusal:
# nothing fires and nothing explains why. Pin the listener high and out of the way so a scan does not
# depend on what else the operator happens to be running. Measured on this host: without the pin, exit=1
# and zero bytes; with it, exit=0, a ~12KB report, and the import adapter parses 14 findings from it.
_ZAP_PROXY_PORT = 18099

# The plan is a FILE, which is a new surface, so it is written under the same rules as every argv here:
# every value in it is VIGIL-DERIVED (the pinned URL rebuilt from the validated components, the report
# path this module allocated, an integer bound already range-checked), and anything that cannot be
# written as a plain single-quoted YAML scalar with NO escaping at all makes the builder REFUSE. There
# is no shape of caller input that adds a job, a URL or an option to the plan: the caller contributes
# exactly one integer, and it contributes it three times as a number.
#
# `'` ends a single-quoted scalar; `"` and `\` are what a DOUBLE-quoted scalar would reinterpret, and
# they are refused too so the same plan text means the same thing under either quoting. Non-printable
# and non-ASCII are refused because a YAML reader's handling of them is not worth depending on. The
# report components are held to a stricter alphabet still: ZAP's report job treats `reportFile` as a
# PATTERN and substitutes `{{…}}` / `[[…]]` inside it, so a brace or a bracket there would rename the
# artifact out from under `_read_report` and produce an empty result with nothing to say why.
_ZAP_PLAN_FORBIDDEN = "'\"\\"
_ZAP_PLAN_REPORT_FORBIDDEN = _ZAP_PLAN_FORBIDDEN + "[]{}"


def _zap_plan_safe(value: Any, *, forbidden: str = _ZAP_PLAN_FORBIDDEN) -> bool:
    """True when ``value`` can be written into the plan verbatim inside single quotes."""
    return (isinstance(value, str) and bool(value)
            and all(0x20 <= ord(c) <= 0x7e for c in value)
            and not any(c in value for c in forbidden))


def _zap_plan_text(site: str, seed: str, report_dir: str, report_file: str,
                   minutes: int) -> Optional[str]:
    """The ZAP automation plan for ONE bounded scan of ONE pinned site, or None (⇒ refuse).

    ``site`` is the pinned origin — the context, and therefore the whole of what may be crawled and
    attacked. ``seed`` is the caller's pinned URL — where the crawl starts, so a URL nothing links to
    is still reached and still scanned. The active-scan job names the CONTEXT rather than a URL, which
    is the entire fix: it attacks every URL the crawl put in the sites tree, not just the seed node.

    The scope is the pin and only the pin. ``urls`` bounds the context to the pinned origin and
    ``includePaths`` re-states that as an anchored literal (``\\Q…\\E``, Java's quote-the-literal form,
    so nothing in a URL can be read as a regex metacharacter). Both are built from ``_pinned_url`` of
    the VALIDATED components, so a target that smuggled a second host contributes neither."""
    if not (_zap_plan_safe(site) and _zap_plan_safe(seed)
            and _zap_plan_safe(report_dir, forbidden=_ZAP_PLAN_REPORT_FORBIDDEN)
            and _zap_plan_safe(report_file, forbidden=_ZAP_PLAN_REPORT_FORBIDDEN)):
        return None
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= 60:
        return None
    return (
        "# VIGIL-generated ZAP automation plan. Do not edit: the file is named for the sha256 of its\n"
        "# own bytes, so the argv in the signed execution record commits to exactly this plan.\n"
        "env:\n"
        "  contexts:\n"
        "    - name: 'vigil-target'\n"
        "      urls:\n"
        f"        - '{site}'\n"
        "      includePaths:\n"
        f"        - '\\Q{site}\\E.*'\n"
        "  parameters:\n"
        "    failOnError: true\n"          # a job that cannot reach the target ABORTS, loudly, with no report
        "    failOnWarning: false\n"
        "    continueOnFailure: false\n"
        "    progressToStdout: true\n"     # the coverage a clean report has to be read against
        "jobs:\n"
        "  - type: spider\n"
        "    parameters:\n"
        "      context: 'vigil-target'\n"
        f"      url: '{seed}'\n"
        f"      maxDuration: {minutes}\n"
        "  - type: passiveScan-wait\n"
        "    parameters:\n"
        f"      maxDuration: {_ZAP_PASSIVE_WAIT_MINUTES}\n"
        "  - type: activeScan\n"
        "    parameters:\n"
        "      context: 'vigil-target'\n"  # NOT `url` — the context is every URL the crawl found
        f"      maxScanDurationInMins: {minutes}\n"
        f"      maxRuleDurationInMins: {max(1, minutes // 2)}\n"
        "  - type: report\n"
        "    parameters:\n"
        "      template: 'traditional-json'\n"
        f"      reportDir: '{report_dir}'\n"
        f"      reportFile: '{report_file}'\n"
    )


def _zap_plan_path(text: str) -> Optional[str]:
    """Write ``text`` into the private report root under a CONTENT-ADDRESSED name, and return the path.

    Content-addressed because the plan is now what decides the shape of the scan, and the argv is what
    the signed record commits to: naming the file for `sha256(plan)[:16]` puts the plan's bytes inside
    the recorded argv, so a record can still be read after the fact as "this exact scan ran". A name
    derived from the target instead would let two different scans share a record. Re-running the same
    scan rewrites the same file rather than accumulating one per run.

    ``O_NOFOLLOW`` + 0600 inside the already-0700 root: the plan names the report artifact, so a
    symlink swapped in ahead of the write is a way to aim ZAP's output elsewhere. Total — any OSError
    returns None and the builder refuses rather than running ZAP against a plan that is not this one."""
    root = _report_root()
    if root is None:
        return None
    path = os.path.join(root, f"zaproxy-plan-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}.yaml")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
    except (OSError, ValueError):
        return None
    return path


# ZAP INSTALLS UNDER THREE NAMES AND THIS BUILDER USED TO KNOW ONE. `zaproxy` is the Debian/Kali
# package's launcher; ZAP's own upstream distribution installs `zap.sh`, and `zap-cli` is the third
# name — all three are DECLARED as this tool's `alt_binaries` in the registry, and the registry RESOLVES
# them, so the operator's tools screen reported ZAP installed and controllable on a host carrying only
# `zap.sh` while every run of it failed to spawn. That is the httpx defect exactly, one builder down
# (see the resolution section above), so it is fixed the same way and by the same shared code:
# resolution through the DECLARED names only, the RESOLVED ABSOLUTE PATH in the argv — so the signed
# record says which of the three actually ran — and a refusal naming every name tried when none is
# present. A differently-named binary that is NOT declared is still never executed.
#
# Resolution goes FIRST, ahead of the bound check and the report allocation. A call that cannot spawn
# anything should not leave a 0700 report directory and a ZAP home behind, and "no usable zaproxy
# binary: [zaproxy: not on PATH; zap.sh: not on PATH; zap-cli: not on PATH] — install it: …" is a more
# actionable refusal than the generic bad-arguments sentence when both are wrong at once.

#: ZAP MUST NOT DRIVE A BROWSER, because ZAP's browser has a host of its own.
#:
#: This is `_build_wapiti`'s `wapp` finding again, in a different tool: a component that needs no
#: out-of-band collaborator and is nobody's idea of an "egressing module", yet reaches a third party
#: on its own initiative every run. ZAP ships `domxss-release-23.zap`, whose DOM XSS ACTIVE SCAN RULE
#: drives a real Firefox through the selenium add-on — and Firefox, on startup, resolves
#: `firefox.settings.services.mozilla.com` for its Remote Settings sync. That is DNS leaving the host
#: for a name that is not the target, which the charter's hard limit forbids in as many words ("No
#: external egress. No tool, no DNS, no callback may leave the host"), and neither `-silent` (which
#: covers the callhome add-on) nor `-notel` (telemetry) nor the egress pin (which constrains the
#: TARGET, not a host the tool addresses itself) touches it.
#:
#: MEASURED, not reasoned. The engine's own zaproxy argv was run against a loopback target inside a
#: network namespace whose only off-loopback route is a blackhole, with every packet captured: 16 DNS
#: queries for `firefox.settings.services.mozilla.com` in one 41-second scan, and nothing else off
#: loopback. The same argv with the two lines below: ZERO packets, `Automation plan succeeded!`, a
#: 20,645-byte report that still carries the Cross Site Scripting alert. The scan loses the DOM XSS
#: rule — a rule that cannot run under this charter at all — and loses nothing else.
#:
#: A path that CANNOT exist is the mechanism, deliberately, rather than an attempt to name and
#: disable each browser-driven rule: rules are a moving set (a future add-on adds another), a browser
#: binary is the one thing all of them need, and `selenium.*Binary` is the option ZAP itself resolves
#: them through. Chrome is pinned as well as Firefox so the answer does not depend on which browsers
#: happen to be installed on the operator's box.
_ZAP_NO_BROWSER: tuple[str, ...] = (
    "-config", "selenium.firefoxBinary=/nonexistent/vigil-no-browser",
    "-config", "selenium.chromeBinary=/nonexistent/vigil-no-browser",
)


def _build_zaproxy(tool_args: Any, p: _Pinned) -> "_Build | str | None":
    binary, why = resolve_tool_binary("zaproxy")
    if binary is None:
        return why
    url = _pinned_url(p)
    minutes = _bounded_opt(tool_args, ("max_minutes", "max_scan_minutes"), 1, 60, _ZAP_MAX_MINUTES)
    if minutes is None:
        return None
    report = _report_path("zaproxy", url)
    home = _report_subdir("zaproxy-home")
    if report is None or home is None:
        return None
    # The report job takes the artifact as (directory, name); `_report_path` owns both, and the name is
    # passed WITH its extension. Measured on zap-2.17.0: a `reportFile` that already ends in `.json` is
    # written as-is, and one that does not has `.json` appended — and `_read_report` looks for `<path>`
    # AND `<path>.json`, so the artifact is found under either behaviour rather than being silently
    # written one character away from where this call reads.
    plan = _zap_plan_text(_pinned_url(replace(p, path="", query="")), url,
                          os.path.dirname(report), os.path.basename(report), minutes)
    if plan is None:
        return ("zaproxy: this target cannot be written into a ZAP automation plan (its path or query "
                "carries a quote, a backslash, or a non-printable character). Refusing rather than "
                "emitting a plan whose meaning depends on how a YAML reader unescapes it.")
    plan_path = _zap_plan_path(plan)
    if plan_path is None:
        return None
    # The `-config` bounds are kept ALONGSIDE the plan's job parameters, and not as belt-and-braces
    # decoration: a job that does not set a parameter inherits the running configuration, so these are
    # the floor under any future plan edit that drops one. They are also what keeps the bound visible in
    # the argv itself, where a reader of the signed record looks first.
    argv = [binary, "-cmd", "-silent", "-notel", "-dir", home,
            "-config", f"network.localServers.mainProxy.port={_ZAP_PROXY_PORT}",
            "-autorun", plan_path,
            "-config", f"spider.maxDuration={minutes}",
            "-config", f"scanner.maxScanDurationInMins={minutes}",
            "-config", f"scanner.maxRuleDurationInMins={max(1, minutes // 2)}",
            *_ZAP_NO_BROWSER]
    return _Build(argv, _redact_argv(argv), url, report_path=report)


# A builder returns a ``_Build`` (run this argv), ``None`` (refuse — the caller states the generic
# reason), or a ``str`` (refuse, and this is the reason the operator is shown verbatim). Anything that is
# not a ``_Build`` is a REFUSAL: there is no shape of return value that runs something unvalidated.
_BUILDERS: dict[str, Callable[[Any, _Pinned], "_Build | str | None"]] = {
    "nmap": _build_nmap,
    "nuclei": _build_nuclei,
    "httpx": _build_httpx,
    "ffuf": _build_ffuf,
    "sqlmap": _build_sqlmap,
    "hydra": _build_hydra,
    "nikto": _build_nikto,
    "wapiti": _build_wapiti,
    "zaproxy": _build_zaproxy,
}


# ---------------------------------------------------------------------------------------------------
# the governed executor
# ---------------------------------------------------------------------------------------------------


def derive_gate_binding(tool_name: Any, tool_args: Any, *, scope: Any = None,
                        allowed_ips: Optional[frozenset] = None) -> Optional[tuple[str, str]]:
    """The EXACT ``(tool_name, target)`` the conjunctive gate will be called with for THIS tool call — the
    single reused derivation so an approval action bound to this matches the gate-seen pair BYTE-FOR-BYTE
    (the per-action approval binding, VIGIL A2 §4). It reproduces what :func:`execute` /
    :func:`execute_terminal` / :func:`execute_sandbox` pass to :func:`tools.governance.authorize_tool_call`
    (which forwards it verbatim to ``gate(tool_name, target, ...)``):

      * ``terminal.run`` / ``sandbox.exec`` authorize under the CONSTANT tool name + the fixed local host
        ``"127.0.0.1"`` (they skip network target-pinning).
      * a network tool authorizes under the caller's ORIGINAL ``tool_name`` (unchanged) + ``_scope_target``
        of the resolve-and-pinned target (the validated hostname[:port] — resolution-independent, so a second
        resolution here yields the same string as ``execute``'s).

    Returns None if the target cannot be derived (an unparseable/unresolvable/out-of-scope target, or a
    non-string tool name) — the caller then binds nothing, so the action stays QUEUED (fail-closed: a
    mismatch or an underivable target is NEVER upgraded to allow). ``scope``/``allowed_ips`` MUST be the same
    the executor is called with, else a legitimate remote target could fail to bind (still fail-closed)."""
    name = tool_name.strip().lower() if isinstance(tool_name, str) else ""
    if name == _TERMINAL_TOOL:
        return _TERMINAL_TOOL, "127.0.0.1"     # execute_terminal: authorize_tool_call(_TERMINAL_TOOL, …, "127.0.0.1")
    if name == _SANDBOX_TOOL:
        return _SANDBOX_TOOL, "127.0.0.1"       # execute_sandbox: authorize_tool_call(_SANDBOX_TOOL, …, "127.0.0.1")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    pinned, _why = _resolve_scoped_target(extract_target(tool_args), scope=scope, allowed_ips=allowed_ips)
    if pinned is None:
        return None
    return tool_name, _scope_target(pinned)     # execute: authorize_tool_call(tool_name, …, _scope_target(pinned))


def _phase_str(phase: Any) -> str:
    if isinstance(phase, Phase):
        return phase.value
    return phase if isinstance(phase, str) else ""


def _build_record(*, seq: Any, now: Any, tool: str, phase: Any, verdict: Any, target: str,
                  redacted_argv: list, outcome: RunOutcome,
                  signer: Optional[Callable[[bytes], Any]]) -> tuple[ExecRecord, bool]:
    rec = ExecRecord(
        seq=_as_int(seq), now=_as_int(now), tool=tool, phase=_phase_str(phase),
        tier=getattr(verdict, "tier", ""), destructive=bool(getattr(verdict, "destructive", False)),
        requires_quorum=bool(getattr(verdict, "requires_quorum", False)), target=target,
        argv=[str(a) for a in redacted_argv], exit_code=outcome.exit_code,
        timed_out=bool(outcome.timed_out), truncated=bool(outcome.truncated),
        stdout_sha256=_sha256_hex(outcome.stdout), stderr_sha256=_sha256_hex(outcome.stderr),
        stdout=_redact_str(outcome.stdout), stderr=_redact_str(outcome.stderr),
    )
    sig = _sign(signer, rec.signing_bytes())
    return rec.model_copy(update={"signature": sig}), bool(sig)


def execute(
    tool_name: Any,
    tool_args: Any,
    phase: Any,
    *,
    gate: Optional[Callable[..., Any]] = None,
    view: Any = None,
    destructive_view: Any = None,
    run: Callable[..., Any] = subprocess_runner,
    signer: Optional[Callable[[bytes], Any]] = None,
    seq: Any = 0,
    now: Any = 0,
    timeout: float = DEFAULT_TIMEOUT,
    output_cap: int = DEFAULT_OUTPUT_CAP,
    scope: Any = None,
    allowed_ips: Optional[frozenset] = None,
) -> ExecResult:
    """Run a governed live Kali tool, fail-closed at every stage. Order (no subprocess until BOTH the egress
    guard AND the gate pass): (1) resolve+pin the target — to the SIGNED authority ``scope`` when provided (the
    metadata/link-local floor is never liftable), else loopback-only (fail-closed default); (2) authorize via
    ``authorize_tool_call`` (phase→tier ∧ conjunctive gate ∧ m-of-n leg for destructive), scoped on the
    validated hostname; (3) build a host-pinned argv LIST + run it via the injected ``run`` (no shell);
    (4) write a signed, redacted ``ExecRecord`` and return the RAW output for the oracle. Never raises — any
    unexpected condition is a DENY. With no ``signer`` wired the call is refused BEFORE any spawn."""
    try:
        return _execute(tool_name, tool_args, phase, gate=gate, view=view,
                        destructive_view=destructive_view, run=run, signer=signer, seq=seq, now=now,
                        timeout=timeout, output_cap=output_cap, scope=scope, allowed_ips=allowed_ips)
    except Exception:  # noqa: BLE001 — total on untrusted input; an internal error is a DENY, never a raise
        name = tool_name if isinstance(tool_name, str) else ""
        return _deny(name, "internal error while executing the tool call (fail-closed)")


def _execute(tool_name: Any, tool_args: Any, phase: Any, *, gate, view, destructive_view, run, signer,
             seq, now, timeout, output_cap, scope=None, allowed_ips=None) -> ExecResult:
    name = tool_name.strip().lower() if isinstance(tool_name, str) else ""
    if not name:
        return _deny("", "empty/invalid tool name (fail-closed)")

    # (0) An execution MUST be recordable: no signer wired ⇒ we cannot produce the signed spine record,
    #     so we refuse to run an unrecordable (hence unprovable) tool call — before any subprocess.
    if not callable(signer):
        return _deny(name, "no signer wired — refusing to run an unrecordable tool call (fail-closed)")

    builder = _BUILDERS.get(name)
    if builder is None:
        return _deny(name, f"no argv builder for tool {name!r} — unknown/unsupported tool denied (fail-closed)")

    # (1) Egress guard — resolve+pin the target, BEFORE authorization and BEFORE any subprocess. With a
    #     signed `scope` the target must be in-scope AND clear the never-liftable floor; else loopback-only
    #     (fail-closed default). A smuggled second host resolves out-of-scope / to a denied IP and dies here.
    pinned, why = _resolve_scoped_target(extract_target(tool_args), scope=scope, allowed_ips=allowed_ips)
    if pinned is None:
        return _deny(name, why)
    disp = _display_target(pinned)          # the exact resolved host:port dialed (record/deny ground truth)

    # (2) Authorization — phase→WARDEN tier ∧ the injected conjunctive gate ∧ destructive→m-of-n leg.
    #     Proceed ONLY on allow (a missing/erroring gate, out-of-phase, or an unmet m-of-n all DENY here).
    #     AUDIT G4: the gate scopes on the executor-VALIDATED hostname (`_scope_target`), NOT on the LLM's
    #     proposed tool_args string — so the sovereign scope/destruction decision is made against the host
    #     the authority actually authorises (for a loopback IP-literal this equals `disp`).
    verdict = authorize_tool_call(tool_name, tool_args, phase, gate=gate,
                                  view=view if isinstance(view, dict) else {},
                                  destructive_view=destructive_view, resolved_target=_scope_target(pinned),
                                  now=now)
    if not getattr(verdict, "allowed", False):
        return _deny(name, f"authorization denied: {getattr(verdict, 'reason', '')}",
                     tier=getattr(verdict, "tier", "A0"),
                     destructive=bool(getattr(verdict, "destructive", False)),
                     requires_quorum=bool(getattr(verdict, "requires_quorum", False)), target=disp)

    # (3) Build a host-pinned argv (refuses smuggled hosts / unsafe or missing options) and run it.
    if pinned.host.startswith("-"):
        return _deny(name, "refusing a pinned host that parses as a flag (fail-closed)",
                     tier=verdict.tier, destructive=verdict.destructive,
                     requires_quorum=verdict.requires_quorum, target=disp)
    build = builder(tool_args, pinned)
    if isinstance(build, str):
        # A builder may refuse WITH its own reason (a str) when the generic sentence below would be
        # actively misleading — e.g. httpx refusing because no binary of any DECLARED name is installed,
        # which is neither a smuggled host nor a bad argument, and which the operator can only fix if
        # they are told which names were tried. Still a refusal: nothing is spawned on this path.
        return _deny(name, f"argv builder for {name!r} refused: {build.strip() or 'no reason given'} "
                     "— fail-closed", tier=verdict.tier, destructive=verdict.destructive,
                     requires_quorum=verdict.requires_quorum, target=disp)
    if not isinstance(build, _Build):
        return _deny(name, f"argv builder for {name!r} refused the arguments (unsafe/smuggled host or a "
                     "missing required option) — fail-closed", tier=verdict.tier,
                     destructive=verdict.destructive, requires_quorum=verdict.requires_quorum, target=disp)

    argv = [str(a) for a in build.argv]
    try:
        raw_outcome = run(argv, timeout=timeout, output_cap=output_cap)
    except Exception as exc:  # noqa: BLE001 — a runner outage never crashes the executor
        raw_outcome = RunOutcome(exit_code=None, stdout="", stderr=f"runner error: {type(exc).__name__}: {exc}")
    outcome = _coerce_outcome(raw_outcome, output_cap)

    # (3b) A report-file tool's machine-readable output is the VIGIL-allocated artifact, not stdout: read
    #      it back (and delete it) so the oracle/import path sees the JSON, never the console prose. Runs
    #      on EVERY exit path — a timeout or crash yields an EMPTY report, never a previous run's bytes.
    if build.report_path:
        try:
            outcome = _absorb_report(build.report_path, outcome, output_cap)
        except Exception as exc:  # noqa: BLE001 — the subprocess ALREADY ran, so a read failure must
            # degrade to an honest "ran, no report" record; it may never become a DENY, which would
            # claim a spawn that did happen did not.
            outcome = RunOutcome(exit_code=outcome.exit_code, stdout="",
                                 stderr=f"{outcome.stderr}\n[vigil] report absorption failed: "
                                        f"{type(exc).__name__}",
                                 timed_out=outcome.timed_out, truncated=outcome.truncated)

    # (4) Signed, redacted spine record; RAW streams returned for the oracle (never persisted here).
    record, signed = _build_record(seq=seq, now=now, tool=name, phase=phase, verdict=verdict,
                                    target=build.target, redacted_argv=build.redacted_argv,
                                    outcome=outcome, signer=signer)
    return ExecResult(
        tool=name, ran=True, outcome="ran", reason="tool executed under the sovereign gates",
        tier=verdict.tier, destructive=verdict.destructive, requires_quorum=verdict.requires_quorum,
        signed=signed, target=build.target, argv=tuple(record.argv), exit_code=outcome.exit_code,
        timed_out=outcome.timed_out, truncated=outcome.truncated,
        stdout=outcome.stdout, stderr=outcome.stderr, record=record,
    )


# ===================================================================================================
# T1 — a governed LOCAL terminal, safe by CONSTRUCTION (no network target, so no IP-pin to lift)
# ===================================================================================================
#
# ``execute`` above is a TARGET-PINNED network-tool runner: it resolves + pins a loopback/scope IP and the
# per-tool builder pins the argv to that IP — the never-liftable egress floor. A generic terminal has NO
# network target, so it cannot ride that path. Instead the floor is preserved BY CONSTRUCTION: the
# allowlist admits ONLY local, non-network, non-interpreter, non-writer read/inspect utilities. None of
# them opens a socket, spawns an interpreter, or mutates the host, so a terminal command CANNOT make
# network egress or persist a change — there is nothing to pin because there is nothing that egresses.
#
# The safety argument, stated so the red-pen can attack exactly it:
#   * NO shell is ever invoked (``subprocess`` runs an argv LIST with ``shell=False``); the command is
#     split on ASCII whitespace ONLY, and the WHOLE command is refused if it holds any shell metacharacter,
#     so no token can be interpreted specially (no pipe/redirect/substitution/glob/var-expansion).
#   * ``argv[0]`` MUST be one of the curated local read/inspect binaries below. Every NETWORK binary
#     (curl/wget/nc/ssh/scp/…), every INTERPRETER (bash/sh/python/perl/ruby/node/awk/…), and every WRITER
#     (tee/cp/mv/rm/dd/sed -i/…) is absent from the allowlist and therefore DENIED.
#   * The few binaries that COULD exec/write are handled by ALLOWLIST, not a spelling denylist — a red-pen
#     proved a denylist cannot be complete (GNU getopt_long accepts unambiguous prefix ABBREVIATIONS like
#     `sort --compress=`/`--out=`, and coreutils have positional aliases like `date MMDDhhmm`). So:
#       - ``sort``/``uniq``/``file``/``env`` — genuinely exec/write-capable; simply NOT on the allowlist.
#       - ``find``  — every ``-``-leading token must be on the read-only predicate allowlist
#                     (``_FIND_SAFE_PREDICATES``); the exec/write predicates (-exec/-execdir/-delete/-fprint*/
#                     -fls/-ok*/…) are refused by OMISSION (no missed spelling can slip through). Non-``-``
#                     tokens are paths/patterns/values — reads, never a program to run.
#       - ``date``/``hostname`` — admitted ONLY bare (they print); a flag/operand could set the clock/host.
#     So no allowlisted binary — under any accepted argv — can open a socket, spawn an interpreter, or
#     mutate a file/the host: egress and host-write are both impossible by construction.
#   * ``terminal.run`` classifies A2 under the ONE shared WARDEN classifier (no A3 danger token, not in the
#     recon auto-set), so under the A1 offense ceiling the conjunctive gate QUEUES it — it can NEVER
#     auto-run; owner approval is always required (the gate's job; we assert the classification here too).
#   * No signer ⇒ REFUSE before running (unrecordable = unprovable). Every run is a signed, redacted
#     ``ExecRecord`` — reusing the exact machinery ``execute`` uses. Total: any failure is a DENY, never a
#     raise.

# The curated LOCAL read/inspect allowlist. Only binaries that can NEITHER exec, write a file, NOR egress
# under ANY argv are admitted, so "no egress / no host-write by construction" is TRUE, not merely guarded.
# A red-pen refuted an earlier spelling-DENYLIST guard: GNU getopt_long accepts any unambiguous prefix
# ABBREVIATION (`sort --compress=` ≡ `--compress-program`, `sort --out=` ≡ `--output`) and coreutils have
# positional aliases (`date MMDDhhmm` sets the clock, a 2nd `uniq` operand is an output file) — a denylist of
# spellings can never be complete. So the exec/write-capable binaries (sort/uniq/file/env) are DROPPED; the
# only capable binary kept is `find`, admitted via a read-only PREDICATE ALLOWLIST (below) that rejects the
# exec/write predicates by OMISSION (immune to any missed spelling); and the two host-state PRINTERS
# (date/hostname) are admitted BARE only (a flag/operand could set the clock/hostname).
_TERMINAL_ALLOWLIST: frozenset = frozenset({
    # pure read/print — safe under ANY argv (no exec/write/egress option or operand exists). Read files,
    # dirs, and system state; transform stdin→stdout; hash/inspect/compare — the full LOCAL read toolkit:
    "ls", "cat", "head", "tail", "wc", "stat", "pwd", "whoami", "id", "uname", "echo",
    "df", "du", "ps", "uptime", "grep", "cut", "tr",
    "nl", "tac", "rev", "fold", "expand", "column", "paste", "comm", "cmp", "diff",
    "readlink", "realpath", "basename", "dirname",
    "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
    "base64", "base32", "od", "hexdump", "strings",   # NB `xxd` EXCLUDED: `xxd -r - OUT` WRITES a file (its
    #   2nd positional is an output path) — od/hexdump are the read-only hex-dump substitutes (red-pen BLOCK).
    "arch", "nproc", "lscpu", "lsblk", "free", "cal", "groups", "locale",
    # NB deliberately EXCLUDED: `getent` — `getent hosts <name>` does a DNS lookup (network egress), which
    #   breaks the never-liftable egress floor; `env`/`printenv` — dump secrets / `env PROG` execs; and every
    #   network / interpreter / writer binary. Egress + host-write stay impossible by construction.
    # capable-but-GUARDED: admitted via a read-only FLAG allowlist that rejects their write/exec forms by
    # OMISSION (immune to getopt_long prefix-abbreviation — the red-pen bypass), so composition (pipelines)
    # gets the classic `sort`/`uniq` without their `-o`/output-operand writes or `--compress-program` exec:
    "find",                                  # read-only predicate allowlist (_FIND_SAFE_PREDICATES)
    "sort", "uniq",                          # read-only flag allowlist (_SORT_SAFE_FLAGS / _UNIQ_SAFE_FLAGS)
    "file",                                  # read-only; -C/--compile (magic-db WRITE) rejected
    "date", "hostname",                      # print-only, admitted BARE (see _TERMINAL_BARE_ONLY)
})

# date / hostname: admitted ONLY bare — a flag/operand can SET the system clock/hostname (a host write).
_TERMINAL_BARE_ONLY: frozenset = frozenset({"date", "hostname"})

# ``sort``: read-only FLAG allowlist — any ``-``-leading token NOT here is refused, so `-o`/`--output` (WRITE)
# and `--compress-program` (EXEC) are rejected by OMISSION, immune to any abbreviation (`--out=`/`--compress=`).
# Non-``-`` tokens are input FILES (reads) or flag values. Value-taking flags (-k/-t/-S/…) pass their value as
# the next non-``-`` token.
_SORT_SAFE_FLAGS: frozenset = frozenset({
    "-b", "-c", "-C", "-d", "-f", "-g", "-h", "-i", "-k", "-M", "-m", "-n", "-r", "-R", "-s", "-t", "-u", "-V", "-z",
    "--check", "--dictionary-order", "--ignore-case", "--general-numeric-sort", "--ignore-leading-blanks",
    "--human-numeric-sort", "--ignore-nonprinting", "--merge", "--month-sort", "--numeric-sort", "--reverse",
    "--random-sort", "--sort", "--stable", "--field-separator", "--key", "--unique", "--version-sort",
    "--zero-terminated", "--buffer-size", "--parallel",
})
# ``uniq``: read-only FLAG allowlist. uniq has no write FLAG — its write is a SECOND positional (the output
# file), so we also refuse ≥2 file operands (skipping the value of a separate numeric flag `-f N`).
_UNIQ_SAFE_FLAGS: frozenset = frozenset({
    "-c", "-d", "-D", "-f", "-i", "-s", "-u", "-w", "-z",
    "--count", "--repeated", "--all-repeated", "--ignore-case", "--skip-fields", "--skip-chars",
    "--check-chars", "--unique", "--zero-terminated", "--group",
})
_UNIQ_VALUE_FLAGS: frozenset = frozenset({"-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"})

# ``find``: an ALLOWLIST of read-only predicates/operators. Any ``-``-leading token NOT in this set is
# refused — so every exec/write predicate (-exec/-execdir/-ok/-okdir/-delete/-fprint/-fprint0/-fprintf/-fls)
# is rejected by OMISSION (a denylist once missed -fprint0; an allowlist cannot miss one). -print/-printf/-ls
# write to STDOUT only (safe); the file-writing -f* variants are simply absent. A non-``-`` token is a
# path/pattern/numeric value (a read), never a program to run.
_FIND_SAFE_PREDICATES: frozenset = frozenset({
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-lname", "-ilname", "-regex", "-iregex",
    "-type", "-xtype", "-maxdepth", "-mindepth", "-depth", "-size", "-empty", "-perm", "-links", "-inum",
    "-newer", "-newermt", "-anewer", "-cnewer", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin",
    "-user", "-group", "-uid", "-gid", "-nouser", "-nogroup", "-readable", "-writable", "-executable",
    "-print", "-print0", "-printf", "-ls", "-true", "-false", "-prune", "-quit",
    "-o", "-a", "-and", "-or", "-not", "-regextype", "-follow", "-mount", "-xdev", "-noleaf",
    "-ignore_readdir_race", "-noignore_readdir_race", "(", ")", "!",
})

# Shell metacharacters (+ NUL + backslash): the WHOLE command is refused if any appears. No shell is ever
# invoked, but this makes "argv is a literal whitespace-split of a benign command" an auditable property —
# a pipe/redirect/substitution/subshell/brace/quote-escape can never survive to a token.
_TERMINAL_METACHARS: frozenset = frozenset(
    [";", "&", "|", ">", "<", "`", "$", "(", ")", "{", "}", "\n", "\r", "\x00", "\\"]
)

_TERMINAL_TOOL = "terminal.run"
_SANDBOX_TOOL = "sandbox.exec"


def _terminal_warden_tier() -> str:
    """The WARDEN tier ``terminal.run`` classifies to under the ONE shared classifier of record
    (``vigil_core.warden_tiers``), mirroring ``wiring.default_classify`` for a NON-recon name: A3 if the
    name carries an A3 danger token, else A2. ``terminal.run`` is not in the offense recon auto-set, so it
    is A2 — NEVER auto (A0/A1). Checked as a construction invariant (defense in depth): a classifier drift
    that made a ``terminal.run`` auto-eligible trips the caller's refusal. Total — any import failure
    yields A3 (the most-gated tier), never an exception."""
    try:
        from vigil_core.warden_tiers import has_danger_token
        return "A3" if has_danger_token(_TERMINAL_TOOL) else "A2"
    except Exception:  # noqa: BLE001 — cannot import the classifier ⇒ fail-closed to the most-gated tier
        return "A3"


def _sandbox_warden_tier() -> str:
    """The WARDEN tier ``sandbox.exec`` classifies to under the ONE shared classifier — A3 (it carries an A3
    danger token; arbitrary exec is the most-gated capability). NEVER auto (A0/A1). Checked as a construction
    invariant in the executor. Total — any import failure yields A3 (fail-closed to the most-gated tier)."""
    try:
        from vigil_core.warden_tiers import has_danger_token
        return "A3" if has_danger_token(_SANDBOX_TOOL) else "A2"
    except Exception:  # noqa: BLE001 — cannot import the classifier ⇒ fail-closed to the most-gated tier
        return "A3"


def _parse_terminal_command(command: Any) -> tuple[Optional[list], str]:
    """Parse + allowlist-validate a LOCAL terminal command into an argv LIST, fail-closed. NO shell is ever
    consulted: the command is refused whole if it holds any shell metacharacter, then split on ASCII
    whitespace only. Returns ``(argv, "ok")`` or ``(None, reason)`` on any refusal (metachar / off-allowlist
    binary / unsafe ``find`` predicate / bare ``..`` token / NUL)."""
    if not isinstance(command, str):
        return None, "terminal command must be a string (fail-closed)"
    cmd = command.strip()
    if not cmd:
        return None, "empty terminal command (fail-closed)"
    bad = sorted(_TERMINAL_METACHARS & set(cmd))
    if bad:
        return None, f"terminal command contains disallowed metacharacter(s) {bad!r} — refused (fail-closed)"
    argv = cmd.split()   # split on ASCII whitespace runs ONLY — no shell, no glob, no variable expansion
    if not argv:
        return None, "terminal command produced no argv tokens (fail-closed)"
    binary = argv[0]
    if binary not in _TERMINAL_ALLOWLIST:
        return None, (f"terminal binary {binary!r} is not on the local read/inspect allowlist "
                      "(network/interpreter/writer binaries are denied) — fail-closed")
    for tok in argv:
        if "\x00" in tok:
            return None, "terminal argv token contains a NUL byte (fail-closed)"
        if tok == "..":
            return None, "terminal argv token is a bare '..' traversal — refused (fail-closed)"
    guard = _terminal_binary_guard(binary, argv)
    if guard is not None:
        return None, guard
    return argv, "ok"


def _terminal_binary_guard(binary: str, argv: list) -> Optional[str]:
    """Second-stage refusal for the two capable classes still on the allowlist. Returns a refusal reason or
    None. This is ALLOWLIST-based (not a spelling denylist), so it is immune to the getopt_long
    prefix-abbreviation / positional-alias bypasses a red-pen used against the old guard:
      * ``date``/``hostname`` — admitted ONLY bare (any flag/operand could set the clock/hostname);
      * ``find`` — every ``-``-leading token must be on the READ-ONLY predicate allowlist, so the exec/write
        predicates are refused by OMISSION (no missed spelling can slip through).
    The pure-read tools (ls/cat/grep/…) can neither exec nor write under any argv and fall through to None."""
    rest = argv[1:]
    if binary in _TERMINAL_BARE_ONLY and rest:
        what = "clock" if binary == "date" else "hostname"
        return (f"{binary!r} is admitted only with NO arguments — a bare `{binary}` prints, but a flag/operand "
                f"could set the system {what} (a host write). Refused (fail-closed).")
    if binary == "find":
        for tok in rest:
            if tok.startswith("-") and tok not in _FIND_SAFE_PREDICATES:
                return (f"find predicate {tok!r} is not on the read-only predicate allowlist — the exec/write "
                        "predicates (-exec/-execdir/-delete/-fprint*/-fls/-ok*/…) are refused by omission "
                        "(fail-closed)")
        return None
    if binary == "sort":
        # EXACT flag membership: `-o`/`--output` (WRITE) and `--compress-program` (EXEC) are refused by
        # omission, immune to any abbreviation (`--out=`/`--compress=`) or bundling (`-ro`). Use separate
        # flags (`-r -n -k 2`), not bundled/attached forms.
        for tok in rest:
            if tok.startswith("-") and tok != "-" and tok not in _SORT_SAFE_FLAGS:
                return (f"sort option {tok!r} is not on the read-only flag allowlist — its write/exec flags "
                        "(-o/--output, --compress-program) are refused by omission; use separate flags "
                        "like `-r -n -k 2` (fail-closed)")
        return None
    if binary == "uniq":
        # EXACT flag membership + refuse a SECOND file operand (uniq's write is `uniq IN OUT`), skipping the
        # value of a separate numeric flag (`-f 2`) so it is not miscounted as the output operand.
        operands, skip_next = 0, False
        for tok in rest:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-") and tok != "-":
                if tok not in _UNIQ_SAFE_FLAGS:
                    return f"uniq option {tok!r} is not on the read-only flag allowlist — refused (fail-closed)"
                if tok in _UNIQ_VALUE_FLAGS:
                    skip_next = True
                continue
            operands += 1
        if operands >= 2:
            return "uniq with two file operands WRITES the second (the output file) — refused (fail-closed)"
        return None
    if binary == "file":
        # file's only write is -C/--compile (compile a magic database). Refuse it + every `--compile` prefix.
        for tok in rest:
            if tok == "-C" or (tok.startswith("--") and len(tok) > 2 and "compile".startswith(tok[2:])):
                return f"file option {tok!r} compiles + WRITES a magic database — refused (fail-closed)"
        return None
    return None


_MAX_PIPELINE_STAGES: int = 8              # bound a pipeline's length (defense in depth)
_PIPELINE_INTERMEDIATE_CAP: int = 8_000_000   # bytes; cap the data flowing BETWEEN stages (memory bound)


def _parse_terminal_pipeline(command: Any) -> tuple[Optional[list], str]:
    """Parse a LOCAL terminal command that MAY be a pipeline of allowlisted read tools (``A | B | C``) into a
    LIST of stage-argvs, fail-closed. NO shell is ever consulted: the ``|`` is split HERE and each stage is
    validated by the SAME single-command allowlist parser (:func:`_parse_terminal_command`), which still
    refuses every OTHER metacharacter (`;&><$()\\{}` backtick, NUL, backslash, newline), every off-allowlist
    binary, every unsafe ``find`` predicate, and ``..``/NUL tokens. Because every stage is an allowlisted
    read/print tool, a pipeline can neither egress, write, nor exec — composition is safe BY CONSTRUCTION,
    exactly like a single command. Returns ``(stages, "ok")`` (a plain command → a single stage) or
    ``(None, reason)`` on any refusal."""
    if not isinstance(command, str):
        return None, "terminal command must be a string (fail-closed)"
    cmd = command.strip()
    if not cmd:
        return None, "empty terminal command (fail-closed)"
    # refuse every dangerous metachar EXCEPT the pipe (which we handle ourselves, never via a shell) up front,
    # so a redirect/subshell/substitution/etc. ANYWHERE in the whole command is rejected before we split.
    bad = sorted((_TERMINAL_METACHARS - {"|"}) & set(cmd))
    if bad:
        return None, f"terminal command contains disallowed metacharacter(s) {bad!r} — refused (fail-closed)"
    raw_stages = cmd.split("|")
    if len(raw_stages) > _MAX_PIPELINE_STAGES:
        return None, f"pipeline has too many stages (>{_MAX_PIPELINE_STAGES}) — refused (fail-closed)"
    stages: list = []
    for raw in raw_stages:
        s = raw.strip()
        if not s:
            return None, "empty pipeline stage (a leading/trailing/double '|') — refused (fail-closed)"
        argv, why = _parse_terminal_command(s)   # allowlist + no-metachar (a stage has no '|') + find/bare guards
        if argv is None:
            return None, why
        stages.append(argv)
    return stages, "ok"


def _run_pipeline(stages: list, *, timeout: float = DEFAULT_TIMEOUT, output_cap: int = DEFAULT_OUTPUT_CAP,
                  cwd: Optional[str] = None) -> RunOutcome:
    """Run an allowlisted pipeline (2+ stages) SEQUENTIALLY, feeding each stage's captured stdout as the next
    stage's stdin — NO shell, argv LISTs, ``stdin`` closed (DEVNULL) for the head. Sequential (not concurrent
    Popen) so there are no fd/deadlock hazards; the data flowing between stages is capped (memory bound) and
    each stage is time-boxed to an equal slice of ``timeout``. Total: a stage timeout / spawn error degrades
    to a ``RunOutcome`` (never raises)."""
    per_stage = max(1.0, float(timeout) / max(1, len(stages)))
    data: Optional[bytes] = None              # None → the head stage reads NO stdin (DEVNULL)
    exit_code: Optional[int] = 0
    stderr, truncated = "", False
    for i, argv in enumerate(stages):
        args = [str(a) for a in argv]
        try:
            proc = subprocess.run(  # noqa: S603 — argv LIST, shell=False; every stage is allowlist-validated
                args, input=data, capture_output=True, timeout=per_stage, shell=False, cwd=cwd,
                stdin=(subprocess.DEVNULL if data is None else None))
        except subprocess.TimeoutExpired:
            return RunOutcome(exit_code=None, stdout="", stderr=f"pipeline stage {i} ({args[0]}) timed out",
                              timed_out=True, truncated=True)
        except (OSError, ValueError) as exc:
            return RunOutcome(exit_code=None, stdout="",
                              stderr=f"pipeline stage {i} ({args[0]}) spawn failed: {type(exc).__name__}: {exc}")
        exit_code = proc.returncode
        stderr = _decode(proc.stderr)
        out_bytes = proc.stdout or b""
        if i < len(stages) - 1:
            if len(out_bytes) > _PIPELINE_INTERMEDIATE_CAP:   # bound the data handed to the next stage
                out_bytes, truncated = out_bytes[:_PIPELINE_INTERMEDIATE_CAP], True
            data = out_bytes
        else:
            final_out, t = _cap(_decode(out_bytes), output_cap)
            return RunOutcome(exit_code=exit_code, stdout=final_out, stderr=stderr, truncated=truncated or t)
    return RunOutcome(exit_code=exit_code, stdout="", stderr=stderr, truncated=truncated)


def _safe_terminal_cwd(cwd: Any) -> tuple[Optional[str], str]:
    """Confine the terminal ``cwd``: ``None`` inherits the process cwd (subprocess default); a string is
    accepted only if it holds no ``..`` and no NUL and names an existing directory. Any other value → refuse
    (``(None, reason)``)."""
    if cwd is None:
        return None, "ok"
    if not isinstance(cwd, str) or not cwd:
        return None, "terminal cwd must be a non-empty string or None (fail-closed)"
    if ".." in cwd or "\x00" in cwd:
        return None, "terminal cwd contains a '..' traversal or NUL — refused (fail-closed)"
    if not os.path.isdir(cwd):
        return None, "terminal cwd is not an existing directory (fail-closed)"
    return cwd, "ok"


def execute_terminal(
    command: Any,
    phase: Any,
    *,
    gate: Optional[Callable[..., Any]] = None,
    view: Any = None,
    destructive_view: Any = None,
    run: Callable[..., Any] = subprocess_runner,
    run_pipeline: Callable[..., Any] = _run_pipeline,
    signer: Optional[Callable[[bytes], Any]] = None,
    seq: Any = 0,
    now: Any = 0,
    timeout: float = DEFAULT_TIMEOUT,
    output_cap: int = DEFAULT_OUTPUT_CAP,
    cwd: Optional[str] = None,
) -> ExecResult:
    """Run a governed LOCAL terminal command, fail-closed at every stage. REUSES the gate + signed-record
    machinery of :func:`execute` but SKIPS network target-pinning — because the allowlist admits only local,
    non-network, non-interpreter, non-writer utilities, a terminal command cannot make network egress, so the
    egress floor is preserved BY CONSTRUCTION rather than by an IP-pin. Order (all fail-closed): (0) no
    ``signer`` ⇒ refuse an unrecordable command BEFORE anything; (1) parse + allowlist-validate the command
    (no shell, argv list, metachar/off-allowlist/unsafe-find refusals deny); (2) confine ``cwd``;
    (3) authorize via ``authorize_tool_call`` scoped on the LOCAL host ``127.0.0.1`` (CRUCIBLE loopback scope
    check + kill-switch apply) — ``terminal.run`` is A2 so under the A1 ceiling it QUEUES, never auto;
    (4) run the argv via the injected ``run`` (``shell=False``); (5) write a signed, redacted ``ExecRecord``
    and return the RAW output. Never raises — any unexpected condition is a DENY."""
    try:
        return _execute_terminal(command, phase, gate=gate, view=view, destructive_view=destructive_view,
                                 run=run, run_pipeline=run_pipeline, signer=signer, seq=seq, now=now,
                                 timeout=timeout, output_cap=output_cap, cwd=cwd)
    except Exception:  # noqa: BLE001 — total on untrusted input; an internal error is a DENY, never a raise
        return _deny(_TERMINAL_TOOL, "internal error while executing the terminal command (fail-closed)")


def _execute_terminal(command, phase, *, gate, view, destructive_view, run, run_pipeline, signer, seq, now,
                      timeout, output_cap, cwd) -> ExecResult:
    # (0) An execution MUST be recordable: no signer wired ⇒ we cannot produce the signed spine record, so
    #     we refuse to run an unrecordable (hence unprovable) command — BEFORE we even parse it.
    if not callable(signer):
        return _deny(_TERMINAL_TOOL, "no signer wired — refusing to run an unrecordable command (fail-closed)")

    # (1) Parse + allowlist-validate the command with NO shell. Supports an allowlisted PIPELINE (`A | B | C`):
    #     the '|' is split here and EACH stage is validated by the same single-command parser, so a stage that
    #     is off-allowlist / holds any other metachar / is an unsafe find predicate DENIES the whole command.
    #     Every stage is a read/print tool → the pipeline can neither egress, write, nor exec (safe by
    #     construction). A plain command is just a one-stage pipeline.
    stages, why = _parse_terminal_pipeline(command)
    if stages is None:
        return _deny(_TERMINAL_TOOL, why)
    # a flat, '|'-separated token list for the signed record (redacted); the display of what actually ran.
    flat_argv: list = []
    for i, st in enumerate(stages):
        flat_argv += list(st)
        if i < len(stages) - 1:
            flat_argv.append("|")

    # (2) Confine the working directory (default: inherit the process cwd; a '..'/NUL/non-dir cwd denies).
    safe_cwd, cwd_why = _safe_terminal_cwd(cwd)
    if safe_cwd is None and cwd is not None:
        return _deny(_TERMINAL_TOOL, cwd_why)

    # (3) Construction invariant (defense in depth): terminal.run must classify A2/A3 under the ONE shared
    #     WARDEN classifier — NEVER auto (A0/A1). The conjunctive gate is what actually queues it; this is a
    #     belt-and-suspenders refusal should a future classifier drift make a terminal.run auto-eligible.
    warden_tier = _terminal_warden_tier()
    if warden_tier not in ("A2", "A3"):
        return _deny(_TERMINAL_TOOL,
                     f"terminal.run classified {warden_tier!r} (auto-eligible) — refused (fail-closed)",
                     tier=warden_tier)

    # (4) Authorize through the sovereign core, scoped on the LOCAL host 127.0.0.1 (so the CRUCIBLE loopback
    #     scope check + kill-switch apply). The phase gate (terminal.run must be registered for the phase),
    #     the destructive classification, and the injected conjunctive gate all decide here. Proceed ONLY on
    #     allow; a queue / deny / missing-gate / gate-error is a DENY.
    verdict = authorize_tool_call(_TERMINAL_TOOL, {"command": command}, phase, gate=gate,
                                  view=view if isinstance(view, dict) else {},
                                  destructive_view=destructive_view, resolved_target="127.0.0.1", now=now)
    if not getattr(verdict, "allowed", False):
        return _deny(_TERMINAL_TOOL, f"authorization denied: {getattr(verdict, 'reason', '')}",
                     tier=getattr(verdict, "tier", warden_tier),
                     destructive=bool(getattr(verdict, "destructive", False)),
                     requires_quorum=bool(getattr(verdict, "requires_quorum", False)), target="local")

    # Record the call at the WARDEN classification tier (A2/A3 — the tier the OFFENSE gate actually gates a
    # terminal command at), overriding the network phase-tier label, so the "never auto" property is visible
    # on the signed spine record; destructive/quorum flags carry over from the real verdict.
    rec_verdict = replace(verdict, tier=warden_tier) if is_dataclass(verdict) else verdict

    # (5) Run: a single stage goes through the INJECTED runner (shell=False, argv LIST); a 2+-stage pipeline
    #     runs via _run_pipeline (sequential stdout→stdin, no shell). Both time-boxed + output-capped + confined.
    try:
        if len(stages) == 1:
            raw_outcome = run(stages[0], timeout=timeout, output_cap=output_cap, cwd=safe_cwd)
        else:
            raw_outcome = run_pipeline(stages, timeout=timeout, output_cap=output_cap, cwd=safe_cwd)
    except Exception as exc:  # noqa: BLE001 — a runner outage (incl. a runner that rejects cwd=) never crashes
        raw_outcome = RunOutcome(exit_code=None, stdout="", stderr=f"runner error: {type(exc).__name__}: {exc}")
    outcome = _coerce_outcome(raw_outcome, output_cap)

    # (6) Signed, redacted spine record; RAW streams returned for the caller/oracle (never persisted here).
    record, signed = _build_record(seq=seq, now=now, tool=_TERMINAL_TOOL, phase=phase, verdict=rec_verdict,
                                   target="local", redacted_argv=_redact_argv(flat_argv), outcome=outcome,
                                   signer=signer)
    return ExecResult(
        tool=_TERMINAL_TOOL, ran=True, outcome="ran",
        reason="terminal command executed under the sovereign gates",
        tier=warden_tier, destructive=bool(getattr(verdict, "destructive", False)),
        requires_quorum=bool(getattr(verdict, "requires_quorum", False)),
        signed=signed, target="local", argv=tuple(record.argv), exit_code=outcome.exit_code,
        timed_out=outcome.timed_out, truncated=outcome.truncated,
        stdout=outcome.stdout, stderr=outcome.stderr, record=record,
    )


# ===================================================================================================
# sandbox.exec — the GATED entry over the network-isolated bwrap sandbox (live.sandbox_exec)
# ===================================================================================================
#
# Where ``execute_terminal`` runs an ALLOWLISTED read-only command on the host, ``execute_sandbox`` runs an
# ARBITRARY command inside the bwrap sandbox (safe by KERNEL isolation — no egress, workspace-confined write).
# It reuses the SAME gate + signed-record machinery: (0) no signer ⇒ refuse; (1) validate command + workspace;
# (2) construction invariant — sandbox.exec must classify A2/A3 (never auto); (3) authorize through the
# conjunctive gate scoped on 127.0.0.1 (CRUCIBLE loopback scope + kill-switch + the owner-approval / M2
# per-action-token leg — sandbox.exec is A3 so under the A1 ceiling it QUEUES, never auto); (4) run inside the
# isolated box (a missing bwrap / unsafe workspace is a DENY — NEVER an un-sandboxed run); (5) signed, redacted
# ExecRecord. Never raises — any unexpected condition is a DENY.


def execute_sandbox(
    command: Any,
    phase: Any,
    *,
    workspace: Any = None,
    gate: Optional[Callable[..., Any]] = None,
    view: Any = None,
    destructive_view: Any = None,
    run_sandbox: Optional[Callable[..., Any]] = None,
    signer: Optional[Callable[[bytes], Any]] = None,
    seq: Any = 0,
    now: Any = 0,
    timeout: float = DEFAULT_TIMEOUT,
    output_cap: int = DEFAULT_OUTPUT_CAP,
) -> ExecResult:
    """Run an ARBITRARY ``command`` inside the network-isolated, workspace-confined bwrap sandbox, gated +
    signed exactly like every other governed tool. Fail-closed at every stage; never raises."""
    try:
        return _execute_sandbox(command, phase, workspace=workspace, gate=gate, view=view,
                                destructive_view=destructive_view, run_sandbox=run_sandbox, signer=signer,
                                seq=seq, now=now, timeout=timeout, output_cap=output_cap)
    except Exception:  # noqa: BLE001 — total on untrusted input; an internal error is a DENY, never a raise
        return _deny(_SANDBOX_TOOL, "internal error while executing the sandbox command (fail-closed)")


def _execute_sandbox(command, phase, *, workspace, gate, view, destructive_view, run_sandbox, signer, seq,
                     now, timeout, output_cap) -> ExecResult:
    from .sandbox_exec import SandboxUnavailable
    from .sandbox_exec import run_sandboxed as _run_sandboxed
    run_sandbox = run_sandbox or _run_sandboxed

    # (0) recordable — no signer ⇒ refuse an unrecordable (hence unprovable) command before anything.
    if not callable(signer):
        return _deny(_SANDBOX_TOOL, "no signer wired — refusing to run an unrecordable command (fail-closed)")
    cmd = command if isinstance(command, str) else str(command or "")
    if not cmd.strip():
        return _deny(_SANDBOX_TOOL, "empty sandbox command (fail-closed)")
    if not workspace:                                    # None / empty — the runner's _safe_workspace does the rest
        return _deny(_SANDBOX_TOOL, "no sandbox workspace wired (fail-closed)")

    # (1) construction invariant (defense in depth): sandbox.exec must classify A2/A3 — NEVER auto (A0/A1).
    warden_tier = _sandbox_warden_tier()
    if warden_tier not in ("A2", "A3"):
        return _deny(_SANDBOX_TOOL,
                     f"sandbox.exec classified {warden_tier!r} (auto-eligible) — refused (fail-closed)",
                     tier=warden_tier)

    # (2) authorize — scoped on the LOCAL host 127.0.0.1 (CRUCIBLE loopback scope check + kill-switch), the
    #     phase gate (sandbox.exec must be registered for the phase), the destructive classification, and the
    #     injected conjunctive gate (owner-approval / M2 per-action token). Proceed ONLY on allow.
    verdict = authorize_tool_call(_SANDBOX_TOOL, {"command": cmd}, phase, gate=gate,
                                  view=view if isinstance(view, dict) else {},
                                  destructive_view=destructive_view, resolved_target="127.0.0.1", now=now)
    if not getattr(verdict, "allowed", False):
        return _deny(_SANDBOX_TOOL, f"authorization denied: {getattr(verdict, 'reason', '')}",
                     tier=getattr(verdict, "tier", warden_tier),
                     destructive=bool(getattr(verdict, "destructive", False)),
                     requires_quorum=bool(getattr(verdict, "requires_quorum", False)), target="local")
    rec_verdict = replace(verdict, tier=warden_tier) if is_dataclass(verdict) else verdict

    # (3) run inside the network-isolated, workspace-confined bwrap sandbox. A missing bwrap or an unsafe
    #     workspace is a DENY (fail-closed — there is NEVER an un-sandboxed fallback). The command is ARBITRARY:
    #     it is safe by KERNEL isolation (no egress, no write outside the workspace), not by an allowlist.
    try:
        sout = run_sandbox(cmd, workspace=workspace, timeout=timeout, output_cap=output_cap)
        outcome = _coerce_outcome(sout, output_cap)      # SandboxOutcome duck-types (stdout/stderr/exit_code/…)
    except SandboxUnavailable as e:
        return _deny(_SANDBOX_TOOL, f"sandbox unavailable — refused (fail-closed): {e}", tier=warden_tier,
                     destructive=bool(getattr(verdict, "destructive", False)),
                     requires_quorum=bool(getattr(verdict, "requires_quorum", False)), target="local")
    except ValueError as e:
        return _deny(_SANDBOX_TOOL, f"unsafe sandbox workspace — refused (fail-closed): {e}", tier=warden_tier,
                     destructive=bool(getattr(verdict, "destructive", False)),
                     requires_quorum=bool(getattr(verdict, "requires_quorum", False)), target="local")
    except Exception as exc:  # noqa: BLE001 — a runner outage is a captured failure, never a crash
        outcome = _coerce_outcome(
            RunOutcome(exit_code=None, stdout="", stderr=f"sandbox runner error: {type(exc).__name__}: {exc}"),
            output_cap)

    # (4) signed, redacted spine record; RAW streams returned for the caller (never persisted here). The
    #     command is recorded (redacted) as a single argv element — the exact string the sandbox shell ran.
    record, signed = _build_record(seq=seq, now=now, tool=_SANDBOX_TOOL, phase=phase, verdict=rec_verdict,
                                   target="local", redacted_argv=_redact_argv([cmd]), outcome=outcome,
                                   signer=signer)
    return ExecResult(
        tool=_SANDBOX_TOOL, ran=True, outcome="ran",
        reason="sandbox command executed under the sovereign gates + kernel isolation",
        tier=warden_tier, destructive=bool(getattr(verdict, "destructive", False)),
        requires_quorum=bool(getattr(verdict, "requires_quorum", False)),
        signed=signed, target="local", argv=tuple(record.argv), exit_code=outcome.exit_code,
        timed_out=outcome.timed_out, truncated=outcome.truncated,
        stdout=outcome.stdout, stderr=outcome.stderr, record=record,
    )
