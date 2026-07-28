"""
live.executor — the GOVERNED live Kali-tool executor (VIGIL-LIVE, §12 WS1a).

This is the binder that replaces the F3/F6 "run a tool" thunk with a real subprocess spawn of a Kali
tool (nmap/nuclei/httpx/ffuf/sqlmap/hydra). Going live changes NOTHING about the sovereign contract: the
LLM only proposes a tool call, only the injected conjunctive gate authorizes it, and — for this
validation — traffic may only reach the loopback substrate. This module is the choke point that enforces
all three, fail-closed, before a single byte of a subprocess spawns.

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
import socket
import subprocess
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

__all__ = ["ExecResult", "ExecRecord", "RunOutcome", "execute", "execute_terminal", "subprocess_runner"]

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


def _build_nmap(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    argv = ["nmap", "-Pn", "-n"]
    ports = _valid_ports(_opt(tool_args, "ports", "port"))
    if ports:
        argv += ["-p", ports]
    elif p.port is not None:
        argv += ["-p", str(p.port)]
    if _opt(tool_args, "service_detection", "sV") is True:
        argv.append("-sV")
    argv.append(p.host)   # a 127.0.0.0/8 literal — never starts with '-'
    return _Build(argv, _redact_argv(argv), _display_target(p))


def _build_httpx(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    url = _pinned_url(p)
    argv = ["httpx", "-u", url, "-silent", "-no-color", "-disable-update-check", "-json"]
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


def _build_ffuf(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    wordlist = _local_file(_opt(tool_args, "wordlist", "wordlist_path", "wordlist_file"))
    if not wordlist:
        return None
    path = p.path or "/"
    if "FUZZ" not in path and "FUZZ" not in (p.query or ""):
        path = (path.rstrip("/") or "") + "/FUZZ"
    url = _pinned_url(replace(p, path=path))
    argv = ["ffuf", "-u", url, "-w", wordlist, "-noninteractive"]
    return _Build(argv, _redact_argv(argv), url)


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
    return _Build(argv, _redact_argv(argv), url)


def _build_hydra(tool_args: Any, p: _Pinned) -> Optional[_Build]:
    service = _safe_token(_opt(tool_args, "service", "module"))
    if not service:
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
    argv += [p.host, service]
    return _Build(argv, _redact_argv(argv, secret_idx), f"{_display_target(p)} {service}")


_BUILDERS: dict[str, Callable[[Any, _Pinned], Optional[_Build]]] = {
    "nmap": _build_nmap,
    "nuclei": _build_nuclei,
    "httpx": _build_httpx,
    "ffuf": _build_ffuf,
    "sqlmap": _build_sqlmap,
    "hydra": _build_hydra,
}


# ---------------------------------------------------------------------------------------------------
# the governed executor
# ---------------------------------------------------------------------------------------------------


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
    if build is None:
        return _deny(name, f"argv builder for {name!r} refused the arguments (unsafe/smuggled host or a "
                     "missing required option) — fail-closed", tier=verdict.tier,
                     destructive=verdict.destructive, requires_quorum=verdict.requires_quorum, target=disp)

    argv = [str(a) for a in build.argv]
    try:
        raw_outcome = run(argv, timeout=timeout, output_cap=output_cap)
    except Exception as exc:  # noqa: BLE001 — a runner outage never crashes the executor
        raw_outcome = RunOutcome(exit_code=None, stdout="", stderr=f"runner error: {type(exc).__name__}: {exc}")
    outcome = _coerce_outcome(raw_outcome, output_cap)

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
    # pure read/print — safe under ANY argv (no exec/write/egress option or operand exists):
    "ls", "cat", "head", "tail", "wc", "stat", "pwd", "whoami", "id", "uname", "echo",
    "df", "du", "ps", "uptime", "grep", "cut", "tr",
    "find",                                  # walk — SAFE-PREDICATE allowlist (_FIND_SAFE_PREDICATES)
    "date", "hostname",                      # print-only, admitted BARE (see _TERMINAL_BARE_ONLY)
})

# date / hostname: admitted ONLY bare — a flag/operand can SET the system clock/hostname (a host write).
_TERMINAL_BARE_ONLY: frozenset = frozenset({"date", "hostname"})

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
    return None


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
                                 run=run, signer=signer, seq=seq, now=now, timeout=timeout,
                                 output_cap=output_cap, cwd=cwd)
    except Exception:  # noqa: BLE001 — total on untrusted input; an internal error is a DENY, never a raise
        return _deny(_TERMINAL_TOOL, "internal error while executing the terminal command (fail-closed)")


def _execute_terminal(command, phase, *, gate, view, destructive_view, run, signer, seq, now, timeout,
                      output_cap, cwd) -> ExecResult:
    # (0) An execution MUST be recordable: no signer wired ⇒ we cannot produce the signed spine record, so
    #     we refuse to run an unrecordable (hence unprovable) command — BEFORE we even parse it.
    if not callable(signer):
        return _deny(_TERMINAL_TOOL, "no signer wired — refusing to run an unrecordable command (fail-closed)")

    # (1) Parse + allowlist-validate the command with NO shell (metachar refusal → off-allowlist binary →
    #     unsafe find predicate → bare '..' / NUL token all DENY here, before any authorization or spawn).
    argv, why = _parse_terminal_command(command)
    if argv is None:
        return _deny(_TERMINAL_TOOL, why)

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

    # (5) Run the argv via the injected runner — shell=False, argv LIST, timeout + output cap + confined cwd.
    try:
        raw_outcome = run(argv, timeout=timeout, output_cap=output_cap, cwd=safe_cwd)
    except Exception as exc:  # noqa: BLE001 — a runner outage (incl. a runner that rejects cwd=) never crashes
        raw_outcome = RunOutcome(exit_code=None, stdout="", stderr=f"runner error: {type(exc).__name__}: {exc}")
    outcome = _coerce_outcome(raw_outcome, output_cap)

    # (6) Signed, redacted spine record; RAW streams returned for the caller/oracle (never persisted here).
    record, signed = _build_record(seq=seq, now=now, tool=_TERMINAL_TOOL, phase=phase, verdict=rec_verdict,
                                   target="local", redacted_argv=_redact_argv(argv), outcome=outcome,
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
