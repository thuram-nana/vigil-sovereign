"""AS-2j — fail-closed hardening lint for the AEGIS-SaaS tenant gateway systemd unit (R15).

The shipped unit ``infra/systemd/aegis-saas-gateway@.service`` is the isolation boundary for a tenant's
plaintext (spec §5.7). This lint pins every hardening directive the boundary rests on, so a future edit
that weakens it toward the pre-AS-2j state (the N-A negative control — a TCP bind, a secret in the
environment, ``PrivateNetwork=no``, no ``ProtectProc``, a shared read-write trust root, no ``MemoryMax``)
is caught BEFORE it ships. It is the enforceable half of the N-A fix: the unit closes the hole, the lint
keeps it closed.

FAIL-CLOSED. Every rule defaults to a violation: a missing/weakened directive reds, an unreadable or
unparseable file reds (it is not silently "clean"), and an absent required directive reds rather than being
assumed present. A GREEN result (``lint_gateway_unit`` -> ``[]``) means every invariant was positively
observed.

stdlib ONLY — no sigil, no framework, no vigil_core import (FATAL-2). Pure text analysis; never raises on
bad input (bad input becomes a Violation). Runnable as a CLI (``python -m vigil_integration.aegis_unit_lint
<unit>...``; exit 1 on any violation, 0 when clean), so it can back a ``make gate`` / aegis-infra job as
well as the deterministic offline tests.

Live cross-checks that need a booted systemd (``systemd-analyze verify|security`` and the IMDS/DNS/route
probe) are owner/infra-gated (AS-26/AS-6a) and intentionally NOT invoked here — this lint is deterministic
and host-independent.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------- MemoryMax formula (spec §5.7)
# MemoryMax >= pool * (max_req + 2*max_resp) + base ; inverse admission ceiling P = floor((0.8*MM - base)/R).
# The two gateway caps are the ground truth (framework/v2/aegis/gateway.py): _MAX_REQUEST_BODY (10 MiB) and
# _MAX_RESPONSE_BYTES (25 MiB). base is the interpreter+framework+httpx baseline RSS (AS-5a removes the join
# copy that makes the response term 2x).
_MiB = 1024 * 1024
MAX_REQ_BYTES = 10 * _MiB
MAX_RESP_BYTES = 25 * _MiB
BASE_RSS_BYTES = 192 * _MiB
DOCUMENTED_POOL = 12          # the pool the shipped unit's MemoryMax is sized for (see the unit comment)
SHIPPED_MEMORY_MAX = "1024M"  # what the shipped unit sets (>= the formula minimum for DOCUMENTED_POOL)


def per_slot_bytes(max_req: int = MAX_REQ_BYTES, max_resp: int = MAX_RESP_BYTES) -> int:
    """R = max_req + 2*max_resp — the worst-case resident bytes one in-flight request+response slot holds."""
    return max_req + 2 * max_resp


def required_memory_max_bytes(pool: int, max_req: int = MAX_REQ_BYTES,
                              max_resp: int = MAX_RESP_BYTES, base: int = BASE_RSS_BYTES) -> int:
    """The formula minimum MemoryMax (bytes) to admit ``pool`` concurrent slots above the baseline RSS."""
    return pool * per_slot_bytes(max_req, max_resp) + base


def pool_ceiling(memory_max_bytes: int, max_req: int = MAX_REQ_BYTES,
                 max_resp: int = MAX_RESP_BYTES, base: int = BASE_RSS_BYTES) -> int:
    """Admission ceiling P = floor((0.8*MemoryMax - base)/R) (spec §8.1). The 0.8 factor leaves headroom so
    MemoryHigh reclaim engages before the hard MemoryMax OOM cap. Never negative."""
    usable = 0.8 * memory_max_bytes - base
    if usable <= 0:
        return 0
    return int(usable // per_slot_bytes(max_req, max_resp))


_SUFFIX = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4,
           "P": 1024 ** 5, "E": 1024 ** 6}


def parse_memory_value(raw: str) -> "int | None":
    """systemd memory value -> bytes. ``None`` for ``infinity``, a percentage (host-dependent — not allowed
    on a hardened unit), or anything unparseable. Suffixes K/M/G/T... are base-1024 (``man systemd.resource-
    control``). Fail-closed: a value we cannot pin to an absolute byte count is treated as absent."""
    if raw is None:
        return None
    s = raw.strip()
    if not s or s.lower() == "infinity" or s.endswith("%"):
        return None
    unit = ""
    if s[-1].upper() in _SUFFIX and not s[-1].isdigit():
        unit = s[-1].upper()
        s = s[:-1].strip()
    try:
        n = float(s)
    except ValueError:
        return None
    if n < 0:
        return None
    return int(n * _SUFFIX[unit])


# --------------------------------------------------------------------------- unit parsing (stdlib, strict)
@dataclass(frozen=True)
class Violation:
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


def _logical_lines(text: str) -> "list[str]":
    """Fold backslash line-continuations into one logical line each (systemd joins with a space), so a stray
    trailing backslash on an ExecStart cannot make a following ``Restart=...`` parse as its own directive."""
    out: "list[str]" = []
    buf = ""
    for raw in text.splitlines():
        buf += raw
        if raw.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1] + " "
            continue
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


class Unit:
    """A parsed systemd unit: section -> ordered list of (key, value). Multiplicity is PRESERVED (systemd
    accumulates ``LoadCredential=``/``BindReadOnlyPaths=``/``RestrictAddressFamilies=``/...), and last-wins is
    computed on demand for single-valued keys. Section names are matched case-insensitively."""

    def __init__(self, text: str) -> None:
        self.sections: "dict[str, list[tuple[str, str]]]" = {}
        section = ""
        for line in _logical_lines(text):
            s = line.strip()
            if not s or s.startswith("#") or s.startswith(";"):
                continue
            if s.startswith("[") and s.endswith("]"):
                section = s[1:-1].strip().lower()
                self.sections.setdefault(section, [])
                continue
            if section and "=" in s:
                k, v = s.split("=", 1)
                self.sections.setdefault(section, []).append((k.strip(), v.strip()))

    def has_section(self, section: str) -> bool:
        return section.lower() in self.sections

    def all(self, section: str, key: str) -> "list[str]":
        return [v for k, v in self.sections.get(section.lower(), []) if k == key]

    def last(self, section: str, key: str) -> "int | str | None":
        vals = self.all(section, key)
        return vals[-1] if vals else None


def _exec_tokens(unit: Unit) -> "list[str]":
    """Whitespace tokens of the effective (last) ExecStart, with any leading ``@``/``-``/``:`` exec-prefix on
    the binary stripped. Returns [] if there is no ExecStart."""
    raw = unit.last("service", "ExecStart")
    if not isinstance(raw, str) or not raw.strip():
        return []
    toks = raw.split()
    if toks and toks[0] and toks[0][0] in "@-:+!":
        toks[0] = toks[0].lstrip("@-:+!")
    return toks


def _has_flag(tokens: "list[str]", flag: str) -> bool:
    """True iff ``flag`` appears as a whole argv token (``--flag`` or ``--flag=value``) — NOT as a substring,
    so ``--saas-host`` never counts as ``--host``."""
    return any(t == flag or t.startswith(flag + "=") for t in tokens)


# --------------------------------------------------------------------------- the rules
def lint_gateway_unit(text: str) -> "list[Violation]":
    """Return every hardening violation in the gateway unit ``text`` (empty list == fully hardened). Each rule
    defaults to a violation; a rule contributes nothing ONLY when its invariant is positively observed."""
    v: "list[Violation]" = []

    if not text or not text.strip():
        return [Violation("EMPTY", "unit file is empty/unreadable (fail-closed: not treated as clean)")]
    unit = Unit(text)
    if not unit.has_section("service"):
        return [Violation("NO_SERVICE", "no [Service] section — not a runnable unit (fail-closed)")]

    svc_keys = {k for k, _ in unit.sections.get("service", [])}

    def req(key: str, predicate, code: str, msg: str) -> None:
        """Require a [Service] directive whose EFFECTIVE (last) value satisfies ``predicate``."""
        val = unit.last("service", key)
        if val is None or not predicate(str(val)):
            v.append(Violation(code, f"{msg} (got {key}={val!r})"))

    # --- B. ingress: unix socket + peer-cred, never TCP (R15) -------------------------------------------
    toks = _exec_tokens(unit)
    if not toks:
        v.append(Violation("NO_EXECSTART", "no ExecStart — nothing to isolate (fail-closed)"))
    else:
        if not _has_flag(toks, "--listen-unix"):
            v.append(Violation("NO_UNIX_SOCKET",
                               "ExecStart must serve over --listen-unix (SO_PEERCRED), not a TCP port"))
        for tcp in ("--host", "--port"):
            if _has_flag(toks, tcp):
                v.append(Violation("TCP_BIND",
                                   f"ExecStart binds TCP via {tcp} — the gateway must have no IP listener"))

    # --- C. no route / DNS / IMDS (R15) -----------------------------------------------------------------
    req("PrivateNetwork", lambda x: x.lower() in ("yes", "true", "1"),
        "NO_PRIVATE_NETWORK", "PrivateNetwork=yes required (no route/DNS/IMDS namespace)")
    _raf = unit.all("service", "RestrictAddressFamilies")
    if not _raf:
        v.append(Violation("NO_ADDR_FAMILY_RESTRICTION",
                           "RestrictAddressFamilies required and must be AF_UNIX-only (blocks IP sockets)"))
    else:
        joined = " ".join(_raf).upper()
        if "AF_INET" in joined:   # covers AF_INET and AF_INET6
            v.append(Violation("IP_ADDR_FAMILY_ALLOWED",
                               "RestrictAddressFamilies permits AF_INET/AF_INET6 — the gateway could reach "
                               "IMDS/DNS; restrict to AF_UNIX"))
        if "~" in joined:
            v.append(Violation("ADDR_FAMILY_DENYLIST",
                               "RestrictAddressFamilies uses a deny-list (~) — use an AF_UNIX allow-list so "
                               "unlisted families are denied by default (fail-closed)"))
    if "any" not in [x.lower() for x in unit.all("service", "IPAddressDeny")]:
        v.append(Violation("NO_IP_ADDRESS_DENY",
                           "IPAddressDeny=any required (defense-in-depth block of all IP egress/ingress)"))

    # --- D. /proc leak of the deployment secret (N-A) ---------------------------------------------------
    req("ProtectProc", lambda x: x.lower() == "invisible",
        "NO_PROTECT_PROC", "ProtectProc=invisible required (no /proc/<pid>/environ secret leak)")
    req("ProcSubset", lambda x: x.lower() == "pid",
        "NO_PROC_SUBSET", "ProcSubset=pid required (hide non-pid /proc)")

    # --- E. secrets via credentials, never the environment (N-A core) -----------------------------------
    for key, val in unit.sections.get("service", []):
        if key == "Environment":
            name = val.split("=", 1)[0].strip().upper()
            if name == "AEGIS_GW_SECRET" or name.endswith(("_SECRET", "_TOKEN", "_PASSWORD")) or "SECRET" in name:
                v.append(Violation("SECRET_IN_ENV",
                                   f"Environment= carries a secret ({name}) — it leaks via /proc/<pid>/environ; "
                                   "deliver it through LoadCredential= instead"))
    _creds = " ".join(unit.all("service", "LoadCredential")
                      + unit.all("service", "LoadCredentialEncrypted"))
    for cred in ("gw-secret", "report-secret"):
        if cred not in _creds:
            v.append(Violation("NO_CREDENTIAL",
                               f"LoadCredential= for {cred!r} required (secret must come from the credential "
                               "store, not the environment)"))

    # --- F. read-only mounts; no shared read-write trust root (N-A shared-RW) ----------------------------
    req("ProtectSystem", lambda x: x.lower() == "strict",
        "NO_PROTECT_SYSTEM_STRICT", "ProtectSystem=strict required (rootfs + /var read-only)")
    _shared_roots = ("/", "/var", "/var/lib", "/var/lib/aegis-saas", "/etc", "/etc/aegis-saas")
    for rwp in unit.all("service", "ReadWritePaths"):
        for path in rwp.split():
            clean = path.lstrip("-+!").rstrip("/") or "/"
            if clean in _shared_roots:
                v.append(Violation("SHARED_RW_ROOT",
                                   f"ReadWritePaths={path} exposes a SHARED writable root (spools/publish/trust "
                                   "root) — the N-A defect; make only the per-instance StateDirectory writable"))
    if "StateDirectory" not in svc_keys:
        v.append(Violation("NO_STATE_DIRECTORY",
                           "StateDirectory= required (the only per-instance writable surface; no shared RW)"))
    if not unit.all("service", "BindReadOnlyPaths"):
        v.append(Violation("NO_READONLY_MOUNTS",
                           "BindReadOnlyPaths= required for the publish dir + authority (trust) root "
                           "(read-only verify inputs)"))

    # --- G. memory bound (defect #6 — fail-open under exhaustion) ---------------------------------------
    mm_raw = unit.last("service", "MemoryMax")
    mm = parse_memory_value(str(mm_raw)) if mm_raw is not None else None
    if mm is None:
        v.append(Violation("NO_MEMORY_MAX",
                           f"MemoryMax must be a finite absolute value (got {mm_raw!r}); it is the hard ceiling "
                           "that bounds the exhaustion blast radius"))
    elif pool_ceiling(mm) < 1:
        v.append(Violation("MEMORY_MAX_TOO_SMALL",
                           f"MemoryMax={mm_raw!r} leaves no admission headroom above base RSS "
                           f"(pool_ceiling={pool_ceiling(mm)})"))
    if "TasksMax" not in svc_keys or parse_memory_value(str(unit.last("service", "TasksMax") or "")) is None:
        # TasksMax bounds the (today unbounded) per-connection threads; must be a finite count.
        tm = unit.last("service", "TasksMax")
        try:
            ok = tm is not None and str(tm).strip().lower() != "infinity" and int(str(tm).strip()) > 0
        except ValueError:
            ok = False
        if not ok:
            v.append(Violation("NO_TASKS_MAX",
                               f"TasksMax must be a finite positive count (got {tm!r}) to bound worker threads"))

    # --- H. no root / no new privileges / no capabilities -----------------------------------------------
    _dyn = str(unit.last("service", "DynamicUser") or "").lower() in ("yes", "true", "1")
    _user = str(unit.last("service", "User") or "").strip()
    if not _dyn and (_user == "" or _user in ("root", "0")):
        v.append(Violation("ROOT_OR_NO_USER",
                           "runs as root / no dedicated uid — set DynamicUser=yes or a non-root User= "
                           "(per-instance uid; TT-B's uid cannot reach TT-A)"))
    req("NoNewPrivileges", lambda x: x.lower() in ("yes", "true", "1"),
        "NO_NNP", "NoNewPrivileges=yes required")
    _caps = unit.all("service", "CapabilityBoundingSet")
    _has_empty_reset = any(c.strip() == "" for c in _caps)
    _grants_cap = any(tok.upper().startswith("CAP_") for c in _caps for tok in c.split()
                      if not tok.startswith("~"))
    if not _has_empty_reset or _grants_cap:
        v.append(Violation("CAPS_NOT_DROPPED",
                           "CapabilityBoundingSet= must reset to empty and grant no CAP_* (drop all caps)"))

    # --- I. bounded crash-loop (T-FO) -------------------------------------------------------------------
    if unit.last("unit", "StartLimitIntervalSec") is None or unit.last("unit", "StartLimitBurst") is None:
        v.append(Violation("NO_START_LIMIT",
                           "[Unit] StartLimitIntervalSec= and StartLimitBurst= required (bound the crash-loop; "
                           "systemd reads StartLimit* only in [Unit])"))
    _restart = str(unit.last("service", "Restart") or "").lower()
    if _restart not in ("always", "on-failure", "on-abnormal", "on-abort", "on-watchdog"):
        v.append(Violation("NO_SUPERVISING_RESTART",
                           f"Restart={_restart or '<unset>'} does not pick a crashed edge back up"))

    return v


# --------------------------------------------------------------------------- CLI
def lint_file(path: "str | Path") -> "list[Violation]":
    """Lint a unit file by path. Fail-closed: an unreadable file is a violation, not a pass."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [Violation("UNREADABLE", f"cannot read {path}: {e}")]
    return lint_gateway_unit(text)


def main(argv: "list[str] | None" = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        sys.stderr.write("usage: python -m vigil_integration.aegis_unit_lint <gateway-unit>...\n")
        return 2
    worst = 0
    for path in args:
        violations = lint_file(path)
        if violations:
            worst = 1
            sys.stderr.write(f"RED  {path}\n")
            for viol in violations:
                sys.stderr.write(f"       {viol}\n")
        else:
            sys.stdout.write(f"GREEN {path}\n")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
