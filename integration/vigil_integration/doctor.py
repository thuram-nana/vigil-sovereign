"""doctor — a read-only preflight/health report for the WHOLE system.

Answers, in one place: is every prerequisite present, are the two venvs built, are the runtime dirs
writable, are the UI ports free (or already held by a running `vigil up`), and is every docker service the
system needs UP (create the missing ones with `vigil services up`)? Read-only + pure-stdlib (no
framework/strix/sigil), so it runs on the boundary-safe path and never mutates anything.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path

_UI_PORTS = (("proxy", 8770), ("cockpit", 8733), ("console", 8787), ("api", 8799))


def find_repo_root() -> Path:
    """Best-effort repo root — the dir holding `.venv-offense` / `.vigil-live` / `docker-compose.yml`.
    Anchors on the offense venv (a console/CLI runs IN `repo/.venv-offense`, so `sys.prefix`'s parent is
    the repo), then the cwd. Never raises; falls back to the venv parent. Shared by the readiness report
    and the services bring-up so both agree on which tree to inspect/act on."""
    import sys
    for start in (Path(sys.prefix).parent, Path.cwd()):
        try:
            start = start.resolve()
        except OSError:
            continue
        for cand in [start, *start.parents]:
            if (cand / ".venv-offense").exists():
                return cand
    return Path(sys.prefix).parent


def _port_free(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # mirror the real proxy bind
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _writable(p: Path) -> bool:
    """True if p exists and is writable, OR p is absent but its nearest existing parent is writable (so it
    can be created). Never raises."""
    try:
        probe = p
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        return os.access(str(probe), os.W_OK)
    except OSError:
        return False


# ── LLM backend probe ───────────────────────────────────────────────────────────────────────────────
# The LOCAL, network-served backends the engine routes through the loopback-enforced provider layer (never
# a cloud SDK). SELF-CONTAINED stdlib mirror of live.think_claude._LOCAL_BACKEND_NAMES (minus `dryrun`, the
# in-process stub handled separately) — kept here so doctor never imports framework on the boundary-safe
# path. KEEP IN SYNC with integration/vigil_integration/live/think_claude.py.
_LOCAL_NET_BACKENDS = ("ollama", "vllm", "llama-cpp", "tgi", "self-hosted")
# Ollama's endpoint when CRUCIBLE_OLLAMA_HOST is unset — mirror of think_claude._configured_local_endpoint.
_OLLAMA_DEFAULT_HOST = "http://localhost:11434"
_SOVEREIGN_TRUTHY = ("1", "true", "yes", "on")     # mirror of kernel.sovereignty._TRUTHY


def _resolve_tier() -> str:
    """The sovereignty TIER from env — stdlib mirror of kernel.sovereignty._resolve_tier_from_env: an
    explicit CRUCIBLE_SOVEREIGNTY_TIER wins (an UNKNOWN name → AIR_GAPPED, fail-closed); the legacy
    CRUCIBLE_SOVEREIGN_MODE flag → AIR_GAPPED; else PERMISSIVE (the development default)."""
    raw = os.environ.get("CRUCIBLE_SOVEREIGNTY_TIER", "").strip().upper()
    if raw:
        return raw if raw in ("AIR_GAPPED", "SOVEREIGN_CLOUD", "TRUSTED_CLOUD", "PERMISSIVE") else "AIR_GAPPED"
    if os.environ.get("CRUCIBLE_SOVEREIGN_MODE", "").strip().lower() in _SOVEREIGN_TRUTHY:
        return "AIR_GAPPED"
    return "PERMISSIVE"


def _local_endpoint(backend: str) -> str:
    """The endpoint a LOCAL backend WILL dial, resolved from env WITHOUT constructing it — stdlib mirror of
    think_claude._configured_local_endpoint. Ollama → CRUCIBLE_OLLAMA_HOST (default localhost:11434); the
    self-hosted family → CRUCIBLE_SELFHOSTED_ENDPOINT / LLM_API_BASE."""
    name = (backend or "").strip().lower()
    if name == "ollama":
        return os.environ.get("CRUCIBLE_OLLAMA_HOST", _OLLAMA_DEFAULT_HOST).strip()
    return (os.environ.get("CRUCIBLE_SELFHOSTED_ENDPOINT") or os.environ.get("LLM_API_BASE") or "").strip()


def _endpoint_host_port(url: str) -> "tuple[str, int]":
    """(host, port) from a URL — port defaults by scheme (https→443, else 80). ('', 0) when unparseable.
    Never raises."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return "", 0
    host = (parts.hostname or "").strip().strip("[]")
    if not host:
        return "", 0
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:                                  # an out-of-range port literal
        return host, 0
    return host, int(port)


def _host_is_loopback(host: str) -> bool:
    """True IFF host is loopback (`localhost` or a loopback IP LITERAL). A hostname (DNS can move) or a
    non-loopback IP is NOT — mirror of think_claude._url_host_is_local's host rule. Never raises."""
    import ipaddress
    h = (host or "").strip().strip("[]").lower()
    if not h:
        return False
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _tcp_reachable(host: str, port: int, timeout: float = 1.5) -> bool:
    """True IFF a bare TCP connect to (host, port) succeeds in `timeout`s. Read-only (no request body),
    used ONLY against a loopback endpoint, so nothing leaves the host. Never raises."""
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_llm_backend() -> dict:
    """Resolve the LLM backend `vigil engage`'s think step will use, plus its endpoint, and — for a LOCAL
    network backend — whether its loopback daemon actually answers.

    Read-only + pure-stdlib: it makes at most ONE bare TCP connect, and ONLY to a loopback endpoint (a
    non-loopback local endpoint, which the engine itself REFUSES, is reported but never probed), so nothing
    leaves the host. Reachability is a tri-state: True/False for a probed loopback backend, None when not
    applicable (a cloud pick, the in-process DryRun stub, or a non-loopback/absent endpoint). Never raises."""
    override = os.environ.get("CRUCIBLE_LLM_BACKEND", "").strip().lower()
    tier = _resolve_tier()
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    out: dict = {"tier": tier, "override": override or None, "anthropic_api_key": has_key}

    def _describe_local(backend: str) -> None:
        from vigil_core.doctor import strip_url_credentials
        ep = _local_endpoint(backend)
        # This report is surfaced to operator+ over the offense /api/doctor. A credentialed endpoint
        # (LLM_API_BASE=https://user:key@proxy) must never leak its userinfo into a field or detail — the
        # real `ep` is used for probing (host/port carry no userinfo), the redacted copy is what surfaces.
        safe_ep = strip_url_credentials(ep) if ep else ep
        out.update(backend=backend, local=True, endpoint=(safe_ep or None))
        if not ep:
            out["reachable"] = None
            out["detail"] = (f"local backend {backend!r}: no endpoint configured "
                             f"(set CRUCIBLE_SELFHOSTED_ENDPOINT / LLM_API_BASE) — reachability not probed.")
            return
        host, port = _endpoint_host_port(ep)
        if not _host_is_loopback(host):
            out["reachable"] = None                     # the engine refuses this; do NOT egress-probe it
            out["detail"] = (f"local backend {backend!r} points at a NON-loopback endpoint ({safe_ep}); the engine "
                             f"REFUSES it (it would send the prompt off-host). Point it at localhost / 127.0.0.1.")
            return
        reachable = _tcp_reachable(host, port)
        out["reachable"] = reachable
        out["detail"] = (f"local backend {backend!r} at {safe_ep} is "
                         f"{'reachable' if reachable else 'NOT answering'} on loopback.")

    if override:
        out["source"] = "CRUCIBLE_LLM_BACKEND"
        if override in _LOCAL_NET_BACKENDS:
            _describe_local(override)
        elif override == "dryrun":
            out.update(backend="dryrun", local=True, endpoint=None, reachable=None,
                       detail="the deterministic in-process DryRun stub — always available, egresses nothing.")
        else:                                           # a cloud backend (or unknown name): no local probe
            out.update(backend=override, local=False, endpoint=None, reachable=None,
                       detail=(f"cloud backend {override!r} (tier {tier}); reachability is not probed offline. "
                               f"ANTHROPIC_API_KEY is {'set' if has_key else 'NOT set'}."))
        return out

    # auto (CRUCIBLE_LLM_BACKEND unset): an HONEST best-effort of the engine's documented order — cloud
    # first WHEN the tier admits an Anthropic key and one is set, else the local Ollama daemon, else DryRun.
    out["source"] = "auto"
    cloud_ok = tier in ("PERMISSIVE", "TRUSTED_CLOUD")   # tiers that admit a direct / ZDR Anthropic key
    if cloud_ok and has_key:
        name = ("anthropic-zdr"
                if os.environ.get("CRUCIBLE_ANTHROPIC_ZDR", "").strip().lower() in _SOVEREIGN_TRUTHY
                else "anthropic")
        out.update(backend=name, local=False, endpoint=None, reachable=None,
                   detail=(f"auto ⇒ cloud {name!r} (tier {tier}, ANTHROPIC_API_KEY set); reachability not "
                           f"probed offline. Set CRUCIBLE_LLM_BACKEND to pin a backend."))
        return out
    _describe_local("ollama")                            # no usable cloud key (or a local-only tier)
    if not out.get("reachable"):                         # Ollama absent → the always-available DryRun stub
        prior = out.get("detail", "")
        out.update(backend="dryrun", local=True, endpoint=None, reachable=None,
                   detail=(f"{prior} Falling back to the in-process DryRun stub (always available; egresses "
                           f"nothing). Start Ollama (CRUCIBLE_OLLAMA_HOST) or set CRUCIBLE_LLM_BACKEND.").strip())
    return out


# ── Security-posture probes (W9-4a) ───────────────────────────────────────────────────────────────────
# One honest line PER security control showing its CURRENT state, so an operator (and a reviewer) sees at a
# glance which controls are ON vs OFF-by-default. These probes are INFORMATIONAL: none of them calls
# `_issue()`, so the posture BLOCK itself never changes `vigil doctor`'s exit code. The opt-in refuse-to-
# start PRODUCTION gate (W9-4b) is a SEPARATE block below (`evaluate_production_gate`) that reuses these
# same probes and DOES flip the exit code — but only when VIGIL_POSTURE=production. Every probe reads REAL
# on-disk / env state — never an optimistic default — and fails SOFT to "UNKNOWN": a missing/unreadable
# control is reported, never a crash.
#
# FATAL-2 (the two-env boundary): `doctor` is the OFFENSE/integration plane. It NEVER imports `sigil` or the
# `framework`. The one SOVEREIGN-plane control (vault / secrets-at-rest) is read WITHOUT importing sigil — by
# reading the on-disk state under SIGIL_HOME (the TPM-sealed KEK blobs vs the plaintext `sigil.env`). The
# entitlement control is read WITHOUT importing the framework — by reading the trust-root file on disk. Every
# path below is pure pathlib / os / subprocess(systemctl); no offense or sovereign package is imported.

# mirror of entitlement.policy._ENFORCE_ENV — enforcement is ACTIVE iff this is truthy OR a trust root exists
_ENTITLEMENT_ENFORCE_ENV = "CRUCIBLE_ENTITLEMENT_ENFORCED"
# mirror of gateway.vigil_gateway.docker.STRIX_NETWORK_ENV — set ⇒ the Strix sandbox is pinned onto the gate
_STRIX_SANDBOX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"
# the sealed-KEK blob filenames the sovereign vault provisions (mirror of vigil_core.kek._SEAL_PUB/_SEAL_PRIV)
_VAULT_SEAL_PUB = "kek.tpm.pub"
_VAULT_SEAL_PRIV = "kek.tpm.priv"
# the AEAD seal magic + version a sealed file starts with (mirror of vigil_core.sealing._MAGIC/_VERSION) —
# lets doctor tell a SEALED key file (ciphertext at rest) from a PLAINTEXT one WITHOUT importing vigil_core,
# by reading the first bytes on disk (FATAL-2: pure disk read). A shape check, never a decrypt.
_SEAL_MAGIC = b"VSL1"
_SEAL_VERSION = 1
# the trust-root key files W9-2 rotates + seals, relative to SIGIL_HOME (mirror of sigil.config paths +
# warden_key.warden_home). Reported per-key so `vigil doctor` shows the sealing state of EACH.
_W9_KEY_FILES = (
    ("owner.priv", ("spine", "keys", "owner.priv")),
    ("spine.dek", ("spine", "keys", "spine.dek")),
    ("warden.key", ("warden", "warden.key")),
)


def _sigil_home() -> Path:
    """SIGIL_HOME — the sovereign plane's home dir (env override, else ~/.sigil). Stdlib mirror of
    sigil.config._resolve_home, read WITHOUT importing sigil (FATAL-2)."""
    return Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))


def _display_path(p: "Path | str") -> str:
    """A tidy, portable rendering of a path for the human report: collapse a leading $HOME to `~` so the
    posture lines don't embed an absolute per-user path. Never raises."""
    s = str(p)
    try:
        home = os.path.expanduser("~")
        if home and home != "~" and (s == home or s.startswith(home + os.sep)):
            return "~" + s[len(home):]
    except OSError:
        pass
    return s


def _crucible_root(repo: Path) -> "Path | None":
    """The CRUCIBLE tree (holds CLAUDE.md + framework/v2 + targets) — a boundary-safe, no-import mirror of
    framework.v2.common.paths.crucible_root's discovery: an explicit CRUCIBLE_ROOT (validated to contain
    CLAUDE.md) wins, else `<repo>/engine/crucible`, else `<repo>` itself, else a walk up from repo. None when
    no CLAUDE.md is found (⇒ the framework-scoped controls report UNKNOWN rather than guessing)."""
    env = os.environ.get("CRUCIBLE_ROOT", "").strip()
    if env:
        p = Path(env).expanduser()
        try:
            if (p / "CLAUDE.md").is_file():
                return p
        except OSError:
            pass
    try:
        for cand in (repo / "engine" / "crucible", repo, *repo.parents):
            if (cand / "CLAUDE.md").is_file():
                return cand
    except OSError:
        return None
    return None


def _entitlement_dir(repo: Path) -> "Path | None":
    """Where the entitlement trust root lives — CRUCIBLE_ENTITLEMENT_DIR override, else
    `<crucible_root>/framework/v2/.entitlement`. Stdlib mirror of framework...paths.entitlement_dir; no
    import. None when the crucible root can't be located and no override is set."""
    override = os.environ.get("CRUCIBLE_ENTITLEMENT_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    root = _crucible_root(repo)
    return (root / "framework" / "v2" / ".entitlement") if root is not None else None


def _authority_root_dir(repo: Path) -> "Path | None":
    """Where the remote-engage LAUNCH-GATE authority trust root lives — VIGIL_AUTHORITY_ROOT_DIR override,
    else `<crucible_root>/framework/v2/.authority-root`. Stdlib mirror of framework...paths.authority_root_dir;
    no import. DELIBERATELY DISTINCT from the entitlement dir: the launch gate (authority.store.
    load_authority_root) reads THIS root, while entitlement CAPABILITY enforcement keys on `.entitlement/`.
    None when the crucible root can't be located and no override is set."""
    override = os.environ.get("VIGIL_AUTHORITY_ROOT_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    root = _crucible_root(repo)
    return (root / "framework" / "v2" / ".authority-root") if root is not None else None


def _posture_sovereignty() -> "tuple[str, str]":
    """The sovereignty TIER — PERMISSIVE (dev default) admits cloud LLM egress; a raised rung gates it."""
    tier = _resolve_tier()
    if tier == "PERMISSIVE":
        return "PERMISSIVE", ("dev default — the sovereignty ladder binds but admits cloud LLM egress; set "
                              "CRUCIBLE_SOVEREIGNTY_TIER (AIR_GAPPED / SOVEREIGN_CLOUD / TRUSTED_CLOUD) to raise it")
    return tier, f"CRUCIBLE_SOVEREIGNTY_TIER={tier} — LLM egress is gated by this tier"


def _posture_egress(services: dict) -> "tuple[str, str]":
    """The egress gate. ON only if the gated topology is ACTUALLY wired: the vigil-gateway container is
    running AND the Strix sandbox is pinned onto the locked-down net (STRIX_DOCKER_SANDBOX_NETWORK set). Off
    by default — a gateway that isn't running, or a sandbox not pinned onto it, does NOT gate egress."""
    pinned = bool(os.environ.get(_STRIX_SANDBOX_NETWORK_ENV, "").strip())
    gw = services.get("vigil-gateway") if isinstance(services, dict) else None
    if isinstance(gw, dict) and "error" in gw:
        return "UNKNOWN", f"gateway probe failed: {gw['error']}"
    running = isinstance(gw, dict) and gw.get("state") == "running"
    if running and pinned:
        return "ON", "vigil-gateway container running and the sandbox is pinned onto the gated net"
    if running and not pinned:
        return "OFF", (f"vigil-gateway is running but {_STRIX_SANDBOX_NETWORK_ENV} is unset — the sandbox is "
                       f"NOT pinned onto the gated net, so egress is not routed through it")
    if isinstance(gw, dict):
        return "OFF", (f"no vigil-gateway container running (state: {gw.get('state', 'absent')!r}); "
                       f"{_STRIX_SANDBOX_NETWORK_ENV} {'set' if pinned else 'unset'}")
    return "OFF", (f"the gated egress topology is not up (docker/gateway absent); "
                   f"{_STRIX_SANDBOX_NETWORK_ENV} {'set' if pinned else 'unset'}")


def _posture_entitlement(repo: Path) -> "tuple[str, str]":
    """The capability-entitlement gate. ACTIVE iff a trust root is provisioned OR
    CRUCIBLE_ENTITLEMENT_ENFORCED is truthy; else UNGOVERNED (gated capabilities permitted but not enforced).
    Read from the on-disk trust-root file — the framework is NEVER imported (FATAL-2)."""
    if os.environ.get(_ENTITLEMENT_ENFORCE_ENV, "").strip().lower() in _SOVEREIGN_TRUTHY:
        return "ACTIVE", f"{_ENTITLEMENT_ENFORCE_ENV} is set — gated capabilities fail closed"
    d = _entitlement_dir(repo)
    if d is None:
        return "UNKNOWN", "could not locate the entitlement dir (no CRUCIBLE_ROOT / CLAUDE.md found)"
    tr = d / "trust-root.json"
    try:
        present = tr.is_file()
    except OSError:
        return "UNKNOWN", f"could not read {tr}"
    if present:
        return "ACTIVE", f"trust root provisioned ({_display_path(tr)}) — gated capabilities fail closed"
    return "UNGOVERNED", (f"no trust root at {_display_path(tr)} — gated capabilities are permitted (logged at "
                          f"WARNING) but NOT enforced")


def _posture_entitlement_anchor(repo: Path) -> "tuple[str, str]":
    """WHERE the ENTITLEMENT trust root is anchored — the CAPABILITY-ENFORCEMENT root, NOT the launch gate.
    `.entitlement/trust-root.json` holds the authoriser keys + threshold that `entitlement.policy.
    _enforcement_active()` keys gated-capability enforcement on (deep_static_analysis / active_recon /
    exploit_execution); if it sits at the DEFAULT in-tree location (offense-writable), a full owner-uid
    filesystem-write actor could swap it. A hardened deployment anchors it OUT-OF-BAND via
    CRUCIBLE_ENTITLEMENT_DIR on a read-only / HSM-backed mount. (The remote-engage LAUNCH gate verifies its
    authority against a SEPARATE root — see the `authority-root-anchor` posture / VIGIL_AUTHORITY_ROOT_DIR.)
    Advisory only (never a gate failure) — it reports the anchor posture so an operator SEES it. Read from
    disk only; the framework is never imported (FATAL-2)."""
    override = (os.environ.get("CRUCIBLE_ENTITLEMENT_DIR") or "").strip()
    d = _entitlement_dir(repo)
    if d is None:
        return "UNKNOWN", "could not locate the entitlement dir (no CRUCIBLE_ROOT / CLAUDE.md found)"
    tr = d / "trust-root.json"
    try:
        present = tr.is_file()
    except OSError:
        present = False
    # The "hardened but never provisioned" caveat (red-pen): the refuse-to-replace guard only bites once a
    # real trust root exists, so a hardened deployment must CLI-provision it before relying on the anchor.
    caveat = "" if present else (" NOTE: no trust root is provisioned yet — CLI-provision it before relying "
                                 "on the anchor (the refuse-to-replace guard only bites once one exists).")
    if override:
        return "OUT-OF-BAND", (f"CRUCIBLE_ENTITLEMENT_DIR is set ({_display_path(tr)}) — the entitlement "
                               f"capability-enforcement root is anchored away from the default in-tree "
                               f"location; use a read-only / HSM-backed mount so an in-tree filesystem-write "
                               f"actor cannot swap it.{caveat}")
    return "DEFAULT-IN-TREE", (f"the entitlement trust root uses the default in-tree location "
                               f"({_display_path(tr)}), which is offense-writable. For a governed / "
                               f"national-agency deployment, anchor it out-of-band via CRUCIBLE_ENTITLEMENT_DIR "
                               f"on a read-only/HSM mount — see docs/runbooks/anchor-trust-root-out-of-band.md."
                               f"{caveat}")


def _posture_authority_root_anchor(repo: Path) -> "tuple[str, str]":
    """WHERE the remote-engage LAUNCH-GATE authority root is anchored — the trust root the launch gate
    verifies an owner-signed EngagementAuthority against (`authority.store.load_authority_root` →
    `.authority-root/trust-root.json`), NOT the entitlement capability-enforcement root. If it sits at the
    DEFAULT in-tree location (offense-writable), a full owner-uid filesystem-write actor could swap both it
    and a self-signed authority. A hardened deployment anchors it OUT-OF-BAND via VIGIL_AUTHORITY_ROOT_DIR on
    a read-only / HSM-backed mount. Advisory only (never a gate failure) — it reports the anchor posture so an
    operator SEES it. Read from disk only; the framework is never imported (FATAL-2)."""
    override = (os.environ.get("VIGIL_AUTHORITY_ROOT_DIR") or "").strip()
    d = _authority_root_dir(repo)
    if d is None:
        return "UNKNOWN", "could not locate the authority-root dir (no CRUCIBLE_ROOT / CLAUDE.md found)"
    tr = d / "trust-root.json"
    try:
        present = tr.is_file()
    except OSError:
        present = False
    # The "hardened but never provisioned" caveat (mirrors entitlement-anchor): the install-time
    # refuse-to-replace guard only bites once a real authority root exists, so provision it before relying
    # on the anchor / making the mount read-only.
    caveat = "" if present else (" NOTE: no authority root is provisioned yet — CLI-provision it before "
                                 "relying on the anchor (the refuse-to-replace guard only bites once one exists).")
    if override:
        return "OUT-OF-BAND", (f"VIGIL_AUTHORITY_ROOT_DIR is set ({_display_path(tr)}) — the launch-gate "
                               f"authority root is anchored away from the default in-tree location; use a "
                               f"read-only / HSM-backed mount so an in-tree filesystem-write actor cannot swap "
                               f"it.{caveat}")
    return "DEFAULT-IN-TREE", (f"the launch-gate authority root uses the default in-tree location "
                               f"({_display_path(tr)}), which is offense-writable. For a governed / "
                               f"national-agency deployment, anchor it out-of-band via VIGIL_AUTHORITY_ROOT_DIR "
                               f"on a read-only/HSM mount — see docs/runbooks/anchor-trust-root-out-of-band.md."
                               f"{caveat}")


def _posture_vault() -> "tuple[str, str]":
    """The sovereign-plane secrets-at-rest control, read WITHOUT importing sigil (FATAL-2): the TPM-sealed
    KEK blobs under SIGIL_HOME/vault (⇒ SEALED, secrets rest as ciphertext) vs the legacy plaintext
    `sigil.env` (⇒ UNPROVISIONED, keys plaintext). A live OS-keyring backend is NOT observable from disk
    (see the honest-limits note); this probe reports the on-disk at-rest state."""
    home = _sigil_home()
    vault = home / "vault"
    try:
        sealed = (vault / _VAULT_SEAL_PUB).is_file() and (vault / _VAULT_SEAL_PRIV).is_file()
        env_plain = (home / "sigil.env").is_file()
    except OSError:
        return "UNKNOWN", f"could not read {home}"
    if sealed:
        return "SEALED", f"TPM-sealed KEK provisioned at {_display_path(vault)} — secrets rest as ciphertext"
    if env_plain:
        return "UNPROVISIONED", (f"keys plaintext ({_display_path(home / 'sigil.env')}) — run `sigil vault "
                                 f"provision` to seal secrets at rest")
    return "UNPROVISIONED", (f"no owner vault at {_display_path(vault)} and no secret store yet — a secret would "
                             f"seal to the plaintext {_display_path(home / 'sigil.env')}")


def _file_seal_state(p: Path) -> str:
    """The at-rest sealing state of ONE key file, from its first bytes on disk (FATAL-2: no import, no
    decrypt): ``SEALED`` (starts with the AEAD magic+version), ``PLAINTEXT`` (present but not sealed),
    ``ABSENT`` (no file), or ``UNREADABLE``. A ``$SIGIL_WARDEN_HOME`` override is honoured for warden.key."""
    try:
        with p.open("rb") as f:
            head = f.read(len(_SEAL_MAGIC) + 1)
    except FileNotFoundError:
        return "ABSENT"
    except OSError:
        return "UNREADABLE"
    if not head:
        return "ABSENT"
    if head[: len(_SEAL_MAGIC)] == _SEAL_MAGIC and len(head) > len(_SEAL_MAGIC) and head[len(_SEAL_MAGIC)] == _SEAL_VERSION:
        return "SEALED"
    return "PLAINTEXT"


def _posture_key_sealing() -> "tuple[str, str]":
    """The per-key at-rest sealing state (audit W9-2), read WITHOUT importing sigil (FATAL-2): the owner
    private key, the spine DEK, and the WARDEN kernel key. Reports one state PER key so an operator sees
    exactly which trust-root keys rest sealed vs plaintext. Roll-up: an INCOMPLETE key rotation (a crash
    anchor / journal left on disk) dominates — it must be reconciled before the old key is retired (red-pen
    HIGH); else SEALED iff every PRESENT key is sealed; PLAINTEXT if any present key is plaintext (the defect
    W9-2 closes); ABSENT if none exist yet."""
    home = _sigil_home()
    warden_home = Path(os.environ["SIGIL_WARDEN_HOME"]) if os.environ.get("SIGIL_WARDEN_HOME") else home / "warden"
    per = []
    for label, rel in _W9_KEY_FILES:
        p = (warden_home / "warden.key") if label == "warden.key" else home.joinpath(*rel)
        per.append((label, _file_seal_state(p)))
    present = [(lbl, st) for (lbl, st) in per if st not in ("ABSENT", "UNREADABLE")]
    detail = ", ".join(f"{lbl}={st}" for lbl, st in per)
    # INCOMPLETE-rotation anchors (pure disk read, no import): a `.prev` KEK/DEK anchor or a WARDEN rotation
    # journal means a crash left a rotation half-finished — until reconciled the OLD key still decrypts.
    incomplete = []
    if (home / "vault" / (_VAULT_SEAL_PUB + ".prev")).exists() or (home / "vault" / (_VAULT_SEAL_PRIV + ".prev")).exists():
        incomplete.append("KEK(.prev)")
    if (home / "spine" / "keys" / "spine.dek.prev").exists():
        incomplete.append("DEK(.prev)")
    if (warden_home / "warden.rotation.pending").exists():
        incomplete.append("WARDEN(pending)")
    if incomplete:
        return "INCOMPLETE", (f"a key rotation is INCOMPLETE ({', '.join(incomplete)}) — the old key is not "
                              f"yet retired; run `sigil key reconcile` to finish it (fail-closed) [{detail}]")
    if not present:
        return "ABSENT", f"no trust-root key files present yet ({detail})"
    if any(st == "PLAINTEXT" for _lbl, st in present):
        return "PLAINTEXT", (f"a trust-root key rests PLAINTEXT ({detail}) — provision the vault and run "
                             f"`sigil key rotate-kek` / `sigil key seal-warden` to seal keys at rest")
    if all(st == "SEALED" for _lbl, st in present):
        return "SEALED", f"every present trust-root key rests sealed ({detail})"
    return "UNKNOWN", detail


# ── backup / cadence timers (W7-8) ────────────────────────────────────────────────────────────────────
# The backup-DURABILITY timers the PRODUCTION posture REQUIRES to be ENABLED *and* to have a SUCCESSFUL
# last run. `vigil-backup` and `vigil-backup-push` are ALTERNATIVES (their own unit docs say enable ONE:
# the push unit already takes a full local backup before it replicates), so AT LEAST ONE of the pair must
# be engaged; the recovery drill proves the backup→restore round-trip and is required on its own. The
# reprove / integrity / posture / ha-mirror timers are engagement- or topology-specific (ha-mirror runs
# ONLY on a passive standby), so they are REPORTED per-timer but NOT forced by the production gate.
_BACKUP_TIMER_ALTERNATIVES = ("vigil-backup.timer", "vigil-backup-push.timer")
_BACKUP_TIMER_REQUIRED = ("vigil-backup-drill.timer",)


def _one_timer_status(systemctl: str, timer_name: str) -> dict:
    """Read ONE timer's enablement (`systemctl is-enabled <timer>`) and its LAST SUCCESSFUL RUN (from the
    SERVICE the timer triggers: `systemctl show <service> -p ExecMainExitTimestamp -p ExecMainStatus -p
    Result`). A oneshot service that has never completed a run reports an EMPTY ExecMainExitTimestamp — that
    is the authoritative "never fired" signal (ExecMainStatus/Result carry success DEFAULTS for a unit that
    never ran, so they cannot stand alone). Fail-soft: any probe error leaves that field False/None, never
    a crash. Returns {name, enabled: bool, last_run: str|None, last_ok: bool}."""
    enabled = False
    try:
        r = subprocess.run([systemctl, "--user", "is-enabled", timer_name],
                           capture_output=True, text=True, timeout=10)
        enabled = r.stdout.strip() == "enabled"
    except (OSError, subprocess.SubprocessError):
        enabled = False
    service = timer_name[: -len(".timer")] + ".service"
    ts = status = result = ""
    try:
        r = subprocess.run([systemctl, "--user", "show", service,
                            "-p", "ExecMainExitTimestamp", "-p", "ExecMainStatus", "-p", "Result"],
                           capture_output=True, text=True, timeout=10)
        props: dict = {}
        for line in r.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                props[k.strip()] = v.strip()
        ts = props.get("ExecMainExitTimestamp", "")
        status = props.get("ExecMainStatus", "")
        result = props.get("Result", "")
    except (OSError, subprocess.SubprocessError):
        pass
    last_run = ts or None
    # SUCCESSFUL last run: the service actually completed (non-empty timestamp) with a zero exit + success
    # result. A fired-but-FAILED run is NOT counted as engaged — a failing backup is worse than a missing one.
    last_ok = bool(ts) and status == "0" and result in ("", "success")
    return {"name": timer_name, "enabled": enabled, "last_run": last_run, "last_ok": last_ok}


def _scan_backup_timers(repo: Path) -> "tuple[list, str]":
    """Scan `<repo>/infra/systemd/*.timer` and read each one's enablement + last-successful-run via
    systemctl. Returns (timers, status) where `timers` is a JSON-safe list of `_one_timer_status` dicts and
    `status` is 'ok' / 'no-units' (dir empty) / 'no-systemctl' (systemctl not on PATH). Never raises."""
    timers_dir = repo / "infra" / "systemd"
    try:
        names = sorted(p.name for p in timers_dir.glob("*.timer")) if timers_dir.is_dir() else []
    except OSError:
        names = []
    if not names:
        return [], "no-units"
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return ([{"name": n, "enabled": None, "last_run": None, "last_ok": None} for n in names],
                "no-systemctl")
    return [_one_timer_status(systemctl, n) for n in names], "ok"


def _fmt_timer(t: dict) -> str:
    """One human phrase for a timer's state, used in the posture detail line."""
    name = t["name"]
    if not t.get("enabled"):
        return f"{name}: disabled"
    if t.get("last_ok"):
        return f"{name}: enabled, last ran {t.get('last_run')}"
    return f"{name}: enabled, never fired"


def _posture_backups(repo: Path) -> "tuple[str, str]":
    """Is BACKUP DURABILITY actually running? Reads infra/systemd/*.timer enablement AND each paired
    service's last successful run via systemctl. The state is decided over the DURABILITY set — at least one
    of {vigil-backup, vigil-backup-push} PLUS vigil-backup-drill:

      ON      — a backup timer AND the drill are enabled and have a SUCCESSFUL last run (durability proven);
      PENDING — the required timers are enabled but at least one has NEVER FIRED (enabled != running yet);
      OFF     — a required timer is disabled (backups are not scheduled);
      UNKNOWN — no timer units found, systemctl unavailable, or a canonical backup unit is missing from the
                tree (fail-closed: an unreadable/absent control is never reported as engaged).

    The PRODUCTION gate requires ON, so BOTH a disabled (OFF) and a never-fired (PENDING) timer refuse the
    start — exactly the W7-8 acceptance requirement."""
    timers, status = _scan_backup_timers(repo)
    if status == "no-units":
        return "UNKNOWN", f"no timer units found under {_display_path(repo / 'infra' / 'systemd')}"
    if status == "no-systemctl":
        return "UNKNOWN", (f"systemctl not available — cannot read enablement of {len(timers)} timer unit(s)")
    by = {t["name"]: t for t in timers}
    total = len(timers)
    enabled_all = [t["name"] for t in timers if t.get("enabled")]

    # fail-closed on a partial tree: the canonical backup + drill units MUST be present to judge durability.
    alt_present = [n for n in _BACKUP_TIMER_ALTERNATIVES if n in by]
    missing_solo = [n for n in _BACKUP_TIMER_REQUIRED if n not in by]
    if not alt_present:
        return "UNKNOWN", (f"expected a backup timer ({' or '.join(_BACKUP_TIMER_ALTERNATIVES)}) under "
                           f"{_display_path(repo / 'infra' / 'systemd')} — none present")
    if missing_solo:
        return "UNKNOWN", (f"expected backup timer unit(s) missing from "
                           f"{_display_path(repo / 'infra' / 'systemd')}: {', '.join(missing_solo)}")

    required = [*alt_present, *_BACKUP_TIMER_REQUIRED]
    # the backup leg is satisfied by ANY alternative that is enabled + fired; the drill leg by ITS unit.
    alt_engaged = [n for n in alt_present if by[n]["enabled"] and by[n]["last_ok"]]
    alt_enabled = [n for n in alt_present if by[n]["enabled"]]
    solo_engaged = all(by[n]["enabled"] and by[n]["last_ok"] for n in _BACKUP_TIMER_REQUIRED)
    solo_enabled = all(by[n]["enabled"] for n in _BACKUP_TIMER_REQUIRED)

    if alt_engaged and solo_engaged:
        engaged = [*alt_engaged[:1], *_BACKUP_TIMER_REQUIRED]
        return "ON", (f"{len(enabled_all)}/{total} systemd timers enabled; backup durability engaged — "
                      + "; ".join(_fmt_timer(by[n]) for n in engaged))
    if alt_enabled and solo_enabled:
        never = [n for n in required if by[n]["enabled"] and not by[n]["last_ok"]]
        return "PENDING", ("backup timers enabled but not yet proven by a successful run: "
                           + ", ".join(never) + " — durability engages after the first successful fire "
                           "(`systemctl --user start vigil-backup.service` to seed it now)")
    disabled = [n for n in required if not by[n]["enabled"]]
    return "OFF", (f"{len(enabled_all)}/{total} systemd timers enabled — backup durability NOT running; "
                   f"need one of {'/'.join(a[:-6] for a in _BACKUP_TIMER_ALTERNATIVES)} + "
                   f"{', '.join(s[:-6] for s in _BACKUP_TIMER_REQUIRED)} enabled and fired "
                   f"(disabled: {', '.join(disabled) or 'none'})")


def _backup_timers_report(repo: Path) -> list:
    """The per-timer breakdown surfaced in `vigil doctor` (AC: report EACH timer's enabled state + last
    successful run). A plain list of `_one_timer_status` dicts; empty when nothing could be read."""
    timers, _status = _scan_backup_timers(repo)
    return timers


def _posture_charter(repo: Path) -> "tuple[str, str]":
    """Is a signed charter + EngagementAuthority present for the active engagement? The active slug is
    VIGIL_ENGAGEMENT (as the console exports to Strix); absent one, scan for ANY non-template target that has
    both a charter and a signed authority. Read from disk; the framework is NEVER imported (FATAL-2)."""
    root = _crucible_root(repo)
    if root is None:
        return "UNKNOWN", "could not locate the crucible root (no CRUCIBLE_ROOT / CLAUDE.md found)"
    targets = root / "targets"
    authority_dir = root / "framework" / "v2" / ".authority"

    def _has_charter(slug: str) -> bool:
        try:
            return (targets / slug / "charter.md").is_file()
        except OSError:
            return False

    def _has_authority(slug: str) -> bool:
        try:
            return (authority_dir / f"{slug}.authority.json").is_file()
        except OSError:
            return False

    slug = os.environ.get("VIGIL_ENGAGEMENT", "").strip()
    if slug:
        ch, au = _has_charter(slug), _has_authority(slug)
        if ch and au:
            return "PRESENT", f"engagement {slug!r}: signed charter + EngagementAuthority present"
        if ch:
            return "CHARTER-ONLY", f"engagement {slug!r}: charter present but NO signed EngagementAuthority"
        return "ABSENT", f"engagement {slug!r}: no charter under {_display_path(targets / slug)}"

    try:
        slugs = ([p.name for p in targets.iterdir() if p.is_dir() and not p.name.startswith("_")]
                 if targets.is_dir() else [])
    except OSError:
        slugs = []
    provisioned = sorted(s for s in slugs if _has_charter(s) and _has_authority(s))
    chartered = sorted(s for s in slugs if _has_charter(s))
    if provisioned:
        return "PRESENT", (f"no active VIGIL_ENGAGEMENT; {len(provisioned)} engagement(s) with "
                           f"charter+authority: {', '.join(provisioned)}")
    if chartered:
        return "CHARTER-ONLY", (f"no active VIGIL_ENGAGEMENT; charter(s) but no signed authority: "
                                f"{', '.join(chartered)}")
    return "ABSENT", "no active VIGIL_ENGAGEMENT and no chartered engagement under targets/"


def _posture_legacy_owner_token() -> "tuple[str, str]":
    """The sovereign-plane legacy embedded shared owner token (W10-7). The sigil cockpit maps its printed
    shared session token to the OWNER principal — a deliberate fail-open so the operator physically at the
    host is never locked out. DISABLED iff the operator has explicitly turned it off
    (SIGIL_LEGACY_OWNER_TOKEN falsy); ENABLED (the default) otherwise. Read from env only — no import of
    sigil (FATAL-2). Under the PRODUCTION gate it must be DISABLED; the sigil server ALSO refuses the token
    at runtime under VIGIL_POSTURE=production (defense in depth), so the two enforce the same rule."""
    # Report DISABLED on the EXPLICIT operator opt-outs — a falsy SIGIL_LEGACY_OWNER_TOKEN OR the GOVERNED
    # posture — NOT merely because production refuses the token at runtime. The production START gate keys on
    # this and deliberately requires the explicit opt-out (defense in depth: it will not accept "production
    # refuses it at runtime" as sufficient, so the config is unambiguous). GOVERNED is an explicit posture the
    # operator arms, so it satisfies the same requirement while (unlike production) still permitting egress.
    from vigil_core.posture import (GOVERNED_ENV, LEGACY_OWNER_TOKEN_ENV,
                                     is_governed_posture, legacy_owner_token_disabled)
    if legacy_owner_token_disabled():
        return "DISABLED", (f"{LEGACY_OWNER_TOKEN_ENV} is set falsy — the legacy shared owner token is "
                            f"refused; per-user proof-of-possession auth is required")
    if is_governed_posture():
        return "DISABLED", (f"{GOVERNED_ENV} is set — a governed deployment refuses the legacy shared owner "
                            f"token (per-user PoP auth required; external egress still permitted, unlike "
                            f"production)")
    return "ENABLED", (f"{LEGACY_OWNER_TOKEN_ENV} is unset — the legacy embedded shared owner token maps to "
                       f"the owner principal (a fail-open dev convenience); set {LEGACY_OWNER_TOKEN_ENV}=0 "
                       f"or {GOVERNED_ENV}=1 to require per-user PoP auth")


def _posture_egress_supervisor() -> "tuple[str, str]":
    """The seccomp connect/sendto/sendmsg egress supervisor (W10-8), read WITHOUT sending any traffic:
    ARMED iff it is ENABLED (opt-in via VIGIL_EGRESS_GUARD, or FORCED on by the production posture) AND its
    binary is present. Under the production gate it must be ARMED — production forces `require` mode, so a
    missing binary is MISSING_BINARY (the guard would refuse every spawn) and OFF cannot occur. This is a
    control against a tool's OWN non-loopback egress and a mis-built argv, NOT a containment boundary for
    hostile code; it does not cover 32-bit binaries / sendmmsg / io_uring (its stated bound, in the docs).
    Reads env + a filesystem existence check only — no traffic, no sigil/framework import (FATAL-2)."""
    from vigil_integration.live import egress_guard as _eg
    if not _eg.enabled():
        return "OFF", ("the seccomp egress supervisor is not enabled — set VIGIL_EGRESS_GUARD=require, or "
                       "run under VIGIL_POSTURE=production which forces it on")
    binary = _eg.guard_binary()
    if binary is None:
        return "MISSING_BINARY", ("the supervisor is enabled but its binary is not built — run "
                                  "`make -C tools/egress-guard` or set VIGIL_EGRESS_GUARD_BIN; under "
                                  "`require`/production mode every guarded spawn is REFUSED (fail-closed) "
                                  "until it exists")
    mode = "require (fail-closed)" if _eg.required() else "enabled"
    return "ARMED", (f"seccomp connect/sendto/sendmsg supervisor {mode} ({binary}); bound: refuses a "
                     f"tool's own non-loopback egress, NOT a containment boundary for hostile code")


def _posture_witness(repo: Path) -> "tuple[str, str]":
    """The transparency-log WITNESS-SET control (W8-3): is the production witness roster a strict majority
    of DISTINCT witnesses, or a solo / non-distinct set? DELEGATES the distinctness decision to
    ``vigil_integration.witness_provision.roster_posture`` (which REUSES ``transparency.is_split_view_resistant``
    — the strict-majority-of-distinct-canonical-keys rule already merged in the transparency log). Reports
    DISTINCT-QUORUM (production-fit), SOLO (absent roster / one witness — the shipped default is detection,
    not prevention), NOT-DISTINCT (witnesses share a canonical key, a sub-majority threshold, or a
    non-canonical key — fail-closed), or UNKNOWN (present-but-unreadable roster). Read from a plain JSON
    roster on disk — NEVER imports sigil/framework (FATAL-2); ``witness_provision`` pulls only vigil_core +
    the offense-free transparency layer. The roster path is $VIGIL_WITNESS_ROSTER, else <repo>/.vigil-live/."""
    from vigil_integration import witness_provision as _wp
    return _wp.roster_posture(_wp.roster_path(repo))


def _posture_owner_key_backend() -> "tuple[str, str]":
    """Which backend holds the OWNER key (W9-6, #439): a FILE-based Ed25519 key loaded into the process
    (the default), or a PKCS#11 HARDWARE token that signs so the private key never enters the process. When
    the hardware backend is selected but its module/token is absent this reports the FAIL-CLOSED state —
    owner signing REFUSES rather than silently using a file key. Reads env only (no token open, no PIN, no
    side-effects); imports only vigil_core (FATAL-2)."""
    from vigil_core.key_backend import describe_owner_backend
    return describe_owner_backend()


def _collect_posture(repo: Path, services: dict) -> list:
    """The security-posture block: one honest line PER control, its CURRENT state read from real on-disk /
    env state (never an optimistic default). INFORMATIONAL — never flips `ok`. Every probe fails soft to
    UNKNOWN. FATAL-2: the sovereign-plane vault and the framework entitlement are read from DISK, importing
    neither sigil nor framework. The order is the plan's: egress-gate, vault, sovereignty, entitlement,
    backups, charter, egress-supervisor, witness, owner-key-backend."""
    def _entry(control: str, fn) -> dict:
        try:
            state, detail = fn()
        except Exception as exc:  # noqa: BLE001 — a posture probe must never crash the report
            state, detail = "UNKNOWN", f"probe error: {type(exc).__name__}: {exc}"
        return {"control": control, "state": state, "detail": detail}

    return [
        _entry("egress-gate", lambda: _posture_egress(services)),
        _entry("vault", _posture_vault),
        _entry("key-sealing", _posture_key_sealing),
        _entry("sovereignty", _posture_sovereignty),
        _entry("entitlement", lambda: _posture_entitlement(repo)),
        _entry("entitlement-anchor", lambda: _posture_entitlement_anchor(repo)),
        _entry("authority-root-anchor", lambda: _posture_authority_root_anchor(repo)),
        _entry("backups", lambda: _posture_backups(repo)),
        _entry("charter", lambda: _posture_charter(repo)),
        _entry("egress-supervisor", _posture_egress_supervisor),
        _entry("witness", lambda: _posture_witness(repo)),
        _entry("owner-key-backend", _posture_owner_key_backend),
    ]


# ── PRODUCTION posture gate (W9-4b) ───────────────────────────────────────────────────────────────────
# The opt-in REFUSE-TO-START gate. When VIGIL_POSTURE=production (or `prod`; case-insensitive), a start path
# (`vigil up` / `vigil engage`) refuses to run unless ALL EIGHT production preconditions hold: the vault is
# SEALED, the sovereignty tier is non-PERMISSIVE, entitlement enforcement is ACTIVE, the backup/reprove
# timers are ON, a signed charter + EngagementAuthority is PRESENT, the legacy embedded shared owner
# token is DISABLED (per-user PoP auth required — W10-7), the seccomp egress supervisor is ARMED (its
# binary built, so production's forced `require` mode is fail-closed not spawn-refusing — W10-8), and the
# transparency-log witness set is a strict majority of DISTINCT witnesses (W8-3 — a solo/non-distinct set
# is refused; distinctness reuses `transparency.is_split_view_resistant`). The first five read the exact
# SAME on-disk/env posture probes `vigil doctor` renders; the sixth reads SIGIL_LEGACY_OWNER_TOKEN, the
# seventh reads VIGIL_EGRESS_GUARD + the guard-binary path, and the eighth reads the on-disk witness roster
# (no import of sigil/framework — the FATAL-2 boundary holds).
#
# ADDITIVE + OPT-IN: with VIGIL_POSTURE unset (or any non-production value) the gate is INERT — it never
# blocks, so behaviour is byte-identical to before. FAIL-CLOSED: any control NOT in its required good-state
# — UNKNOWN included — is UNMET; a control we cannot read is never treated as satisfied. The egress-gate
# control (the docker-gateway topology) is DELIBERATELY excluded from the gate: a loopback engagement
# legitimately needs no docker gateway, so requiring it would refuse the documented loopback quickstart.
# (This is distinct from egress-supervisor, the seccomp syscall guard, which IS a gate precondition.)

# control -> (required good-states, one-line requirement text used in the operator refusal). The order is
# the plan's five conditions plus W10-7's legacy-token and W10-8's egress-supervisor; each `required` set is the state(s) `doctor` reports
# when the control is actually ENGAGED (see the _posture_* probes above). SHARED REGISTRY (W6-6): the spec
# lives in `vigil_core.doctor` — the namespace-pure package BOTH trust planes import — so `vigil doctor`
# and `sigil doctor` gate on the exact SAME controls and good-states. Imported here (keeping the historical
# `_PRODUCTION_GATE` name) is a boundary-safe `vigil_core` import; FATAL-2 holds.
from vigil_core.doctor import REQUIRED_CONTROLS as _PRODUCTION_GATE
from vigil_core.doctor import render_gate_block as _render_gate_block


def production_posture() -> "str | None":
    """The raw VIGIL_POSTURE value IFF it selects the production gate (case-insensitive `production` / `prod`),
    else None. The SINGLE source of truth for 'is the refuse-to-start gate armed?' — every caller keys on
    this so the arming rule can never drift between the CLI start paths and the doctor report. Delegates to
    `vigil_core.posture` (the namespace-pure package BOTH trust planes import) so the sovereign sigil server
    parses `VIGIL_POSTURE` identically — the offense gate and the running server can never disagree on what
    'production' means (FATAL-2 safe: vigil_core imports nothing from framework/strix/sigil)."""
    from vigil_core.posture import production_posture as _pp
    return _pp()


def evaluate_production_gate(repo_root, posture: "list | None" = None) -> dict:
    """Evaluate the PRODUCTION preconditions from the same posture probes `vigil doctor` renders.

    Returns a JSON-safe dict:
      {armed, posture, controls:[{control,state,detail,required,requirement,met}], unmet:[...same...], ok}
    `armed` is True IFF VIGIL_POSTURE selects production. When NOT armed the gate is inert: `ok` is True and
    `unmet` is empty regardless of state, so a start path can gate unconditionally on `not result['ok']`
    and be byte-identical to before when the posture is unset. FAIL-CLOSED: a probe that errors, or reports
    any state outside its required good-set (UNKNOWN included), is UNMET. Never raises.

    `posture` (optional) is a precomputed `_collect_posture(...)` list — passed by `collect()` so the shared
    doctor report does not re-run the five informational probes (notably the systemctl calls). The sixth
    control (legacy-owner-token) is not in that informational block, so it is always probed here — a cheap
    env read. When `posture` is None, every control is probed here (the CLI start-path helper's case)."""
    repo = Path(repo_root)
    by_control: dict = {}
    if posture is not None:
        by_control = {str(p.get("control")): (str(p.get("state", "UNKNOWN")), str(p.get("detail", "")))
                      for p in posture if isinstance(p, dict)}
    probes = {
        "vault": _posture_vault,
        "sovereignty": _posture_sovereignty,
        "entitlement": lambda: _posture_entitlement(repo),
        "backups": lambda: _posture_backups(repo),
        "charter": lambda: _posture_charter(repo),
        "legacy-owner-token": _posture_legacy_owner_token,
        "egress-supervisor": _posture_egress_supervisor,
        "witness": lambda: _posture_witness(repo),
    }
    # Gather the current state of every registry control (reuse the precomputed posture where present, else
    # probe here — FAIL CLOSED: an unreadable control becomes UNKNOWN, never a crash), then hand the SHARED
    # registry decision to `vigil_core.doctor.evaluate` so the offense start-path gate and `sigil doctor`
    # reach the identical verdict from the identical spec (W6-6). No new import crosses the boundary.
    from vigil_core.doctor import evaluate as _evaluate
    control_states: dict = {}
    for control, _required, _requirement in _PRODUCTION_GATE:
        if control in by_control:
            control_states[control] = by_control[control]
        else:
            try:
                control_states[control] = probes[control]()
            except Exception as exc:  # noqa: BLE001 — FAIL CLOSED: an unreadable control is UNMET, not a crash
                control_states[control] = ("UNKNOWN", f"probe error: {type(exc).__name__}: {exc}")
    return _evaluate(control_states)


def production_gate_message(result: dict, action: str = "start") -> str:
    """The operator-facing refusal: ONE line per UNMET precondition naming the failing control, its current
    state, and how to satisfy it. Called only when `result['ok']` is False (armed + at least one unmet)."""
    unmet = result.get("unmet", [])
    lines = [
        (f"vigil {action}: REFUSED (fail-closed) — VIGIL_POSTURE={result.get('posture')} selects the "
         f"PRODUCTION security posture, and {len(unmet)} precondition(s) are not met:"),
    ]
    for e in unmet:
        lines.append(f"  ✗ {e['control']}: {e['state']} — {e['requirement']}")
        lines.append(f"      now: {e['detail']}")
    lines.append("  Satisfy every precondition above, or unset VIGIL_POSTURE for a non-production run. "
                 "`vigil doctor` shows the current state of each control.")
    return "\n".join(lines)


def _gateway_services(repo: Path) -> dict:
    """The docker gateway state the egress-gate posture control reads — a best-effort, function-local,
    read-only probe (the same one `collect()` makes at step 5, minus the RootServices display). Empty when
    docker is absent (⇒ egress-gate reports OFF, honestly). Never raises."""
    services: dict = {}
    if not shutil.which("docker"):
        return services
    try:
        from vigil_gateway.docker import SandboxNetworking
        gw = SandboxNetworking().status()
        services["vigil-gateway"] = {"state": gw.get("gateway", "absent"),
                                     "networks": gw.get("networks", {}), "image": gw.get("image")}
    except Exception as exc:  # noqa: BLE001 — a probe must never crash the report
        services["vigil-gateway"] = {"error": str(exc)}
    return services


def security_report(repo_root, services: "dict | None" = None) -> dict:
    """The SHARED security block both doctors render: the per-control posture lines, the per-timer backup
    breakdown, and the opt-in PRODUCTION posture gate. Returns
    ``{posture:[...], backup_timers:[...], production_gate:{...}}``.

    This is the ONE implementation of 'what is the security posture, and does it pass the production gate?'
    — `collect()` (the `vigil doctor` entry point) and `sigil doctor` (the sovereign entry point) both call
    it, so the two entry points can never drift on the posture block or the gate verdict (W6-6). FATAL-2:
    pure on-disk / env / systemctl / docker reads; imports only `vigil_core` and the offense-free
    `vigil_gateway` — never `sigil` or `framework`. Never raises."""
    repo = Path(repo_root)
    svc = _gateway_services(repo) if services is None else services
    posture = _collect_posture(repo, svc)
    return {"posture": posture,
            "backup_timers": _backup_timers_report(repo),
            "production_gate": evaluate_production_gate(repo, posture=posture)}


# NOTE on offense host tools (nmap/nuclei/httpx/…): doctor deliberately does NOT probe them. The engine's
# tool registry (framework.v2.tools.registry) already resolves them SHADOW-AWARE (an alt-name + version
# banner check that steps over a same-named impostor, e.g. the Python `httpx` shadowing ProjectDiscovery
# `httpx`), and that status is surfaced live on the Tools screen / `/api/tools`. A second, shadow-BLIND
# `shutil.which(name)` here would contradict the engine it previews (false-green on an impostor, false-red
# on a correctly alt-named install) — so offense-tool status is handed off to the registry, and doctor
# covers the SYSTEM prerequisites the registry does not (docker + daemon, compose, venvs, toolchain, images).

# The docker images the offence/defence engines need at RUN time. Each is BUILT (not pulled) and the
# build context is non-obvious, so the hint names the make target that encodes it.
_ENGINE_IMAGES = {
    "vigil/strix-sandbox:local": ("the Strix offence sandbox", "make strix"),
    "vigil/aegis-gateway:local": ("the AEGIS defensive gateway", "make aegis-image"),
}

# Concrete install commands for the core prerequisites (Kali/Debian).
_INSTALL = {
    # docker.io + docker-compose-v2 are BOTH distro packages (Debian bookworm+/Kali), so this apt line
    # never half-fails the way `docker.io && docker-compose-plugin` did (the -plugin package ships only
    # from download.docker.com's repo, so the && chain aborted on a stock box before enabling the daemon).
    "docker": "sudo apt install -y docker.io docker-compose-v2 && sudo systemctl enable --now docker "
              "&& sudo usermod -aG docker \"$USER\"   # then log out/in for the group to take effect",
    "docker-daemon": "sudo systemctl start docker   # enable at boot: sudo systemctl enable --now docker; "
                     "if 'permission denied': sudo usermod -aG docker \"$USER\" then re-login",
    "git": "sudo apt install -y git",
    "nft": "sudo apt install -y nftables",
    "bwrap": "sudo apt install -y bubblewrap",
    "cargo": "sudo apt install -y cargo   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
    "egress-guard": "make -C tools/egress-guard   # seccomp egress guard (needed under VIGIL_POSTURE=production)",
    "venv": "./bootstrap.sh   # or: envs/build_envs.sh",
}


def _docker_daemon_running(timeout: float = 5.0):
    """True/False iff the docker daemon answers ``docker info``; None if the docker binary is absent.
    doctor previously checked only that the docker BINARY existed — a STOPPED daemon was invisible, so a
    bring-up would fail later with an opaque error instead of a clear 'start dockerd' remedy here. The
    timeout is kept short because this runs synchronously in the console `/api/services` read path."""
    if not shutil.which("docker"):
        return None
    try:
        return subprocess.run(["docker", "info"], capture_output=True, text=True,
                              timeout=timeout).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _image_present(image: str, timeout: float = 5.0) -> bool:
    try:
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True,
                              timeout=timeout).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _dependencies_report(repo: Path, has_docker: bool, daemon_up, compose_ok: bool) -> list:
    """A per-item, ACTIONABLE SYSTEM-prerequisite preflight: for each prerequisite,
    ``{name, kind, present, required, detail, how_to_install}``. INFORMATIONAL — it never flips the
    doctor ``ok`` gate (the existing _issue/_note logic owns the exit code); it exists so the operator
    (via ``vigil doctor``) sees exactly what is missing and the exact command to install it. Offense host
    tools are intentionally NOT here — they are the registry's shadow-aware job (see the module note).
    Fails soft."""
    deps: list = []

    def _add(name, kind, present, required, detail, how_to_install=""):
        deps.append({"name": name, "kind": kind, "present": bool(present), "required": bool(required),
                     "detail": detail, "how_to_install": ("" if present else how_to_install)})

    # core binaries / toolchain
    _add("python3", "binary", bool(shutil.which("python3")), True, "the interpreter", "sudo apt install -y python3")
    _add("git", "binary", bool(shutil.which("git")), False, "clone/update + signed commits", _INSTALL["git"])
    _add("cargo", "toolchain", bool(shutil.which("cargo") or shutil.which("rustc")), True,
         "builds the WARDEN kernel in the sovereign venv", _INSTALL["cargo"])
    _add("nft", "binary", bool(shutil.which("nft")), False, "nftables egress backstop for the sandbox", _INSTALL["nft"])
    _add("bwrap", "binary", bool(shutil.which("bwrap")), False, "bubblewrap sandbox for local tool runs", _INSTALL["bwrap"])

    # docker: the binary AND — the check doctor lacked — the running DAEMON
    _add("docker", "binary", has_docker, False,
         "runs the gateway + qdrant/neo4j/otel services and the engine sandboxes (optional: SIGIL falls "
         "back to embedded vectors)", _INSTALL["docker"])
    if has_docker:
        _add("docker daemon", "daemon", bool(daemon_up), False,
             "must be RUNNING to build images / start containers", _INSTALL["docker-daemon"])
        _add("docker compose", "binary", compose_ok, False, "compose v2 plugin", _INSTALL["docker"])

    # the two venvs (hard prerequisites for the full system)
    _add("offense venv (.venv-offense/bin/vigil)", "venv",
         (repo / ".venv-offense" / "bin" / "vigil").exists(), True, "the offence engine + CLI", _INSTALL["venv"])
    _add("sovereign venv (.venv-sovereign/bin/sigil)", "venv",
         (repo / ".venv-sovereign" / "bin" / "sigil").exists(), True, "the sovereign cockpit", _INSTALL["venv"])

    # egress guard (needed only under production posture). Resolve it the SAME way the runtime does
    # (live.egress_guard.guard_binary — $VIGIL_EGRESS_GUARD_BIN, else the in-repo build, else PATH), NOT a
    # hard-coded literal: the built binary is `egress_guard` with an UNDERSCORE (tools/egress-guard/Makefile),
    # so the old `egress-guard` (hyphen) literal reported a BUILT guard as absent (audit F-03). The posture
    # block at _posture_egress_supervisor already uses this resolver — this makes the dependency row agree.
    try:
        from vigil_integration.live import egress_guard as _eg  # noqa: PLC0415 — lazy, boundary-safe (stdlib)
        _guard_present = _eg.guard_binary() is not None
    except Exception:  # noqa: BLE001 — a probe must never crash the report
        _guard_present = False
    _add("egress-guard", "binary", _guard_present, False,
         "seccomp egress guard (required under VIGIL_POSTURE=production)", _INSTALL["egress-guard"])

    # engine images (built on demand; the daemon must be up to probe or build them)
    for image, (what, how) in _ENGINE_IMAGES.items():
        can_probe = bool(has_docker and daemon_up)
        present = _image_present(image) if can_probe else False
        detail = what + ("" if can_probe else " — cannot probe (docker daemon down)")
        _add(image, "image", present, False, detail, how)

    return deps


def collect(repo_root) -> dict:
    """Assemble the health report as a plain dict (JSON-safe). Never raises — every probe fails soft."""
    repo = Path(repo_root)
    report: dict = {"ok": True, "issues": [], "notes": []}

    def _issue(msg: str) -> None:      # a HARD prerequisite (flips ok False → `vigil doctor` exits 1)
        report["ok"] = False
        report["issues"].append(msg)

    def _note(msg: str) -> None:       # advisory (optional dependency) — does NOT flip ok
        report["notes"].append(msg)

    # 1) binaries
    bins = {b: bool(shutil.which(b)) for b in ("docker", "git", "python3", "nft", "bwrap")}
    report["binaries"] = bins
    has_docker = bins["docker"]
    compose_ok = False
    if has_docker:
        try:
            compose_ok = subprocess.run(["docker", "compose", "version"],
                                        capture_output=True, text=True, timeout=15).returncode == 0
        except (OSError, subprocess.SubprocessError):
            compose_ok = False
    report["docker_compose"] = compose_ok
    if not has_docker:
        _note("docker is not installed — the gateway + qdrant/neo4j/otel services can't be brought up "
              "(optional: the engine still runs; SIGIL falls back to embedded vectors).")

    # 1b) Actionable dependency preflight (WS1a) — the missing SYSTEM-prerequisite report WITH install
    #     commands. INFORMATIONAL: it does NOT flip `ok` (the _issue/_note logic owns the exit code); it
    #     adds the per-item {present, how_to_install} `vigil doctor` surfaces. Includes the docker DAEMON
    #     check doctor lacked (a stopped daemon was invisible) and the engine images (offense host tools
    #     are the registry's shadow-aware job). The keys are pre-seeded and the block is wrapped like every
    #     other probe, so a future addition can never break collect()'s never-raises contract OR the stable
    #     top-level shape the console read relies on.
    report["docker_daemon"] = None
    report["dependencies"] = []
    try:
        daemon_up = _docker_daemon_running() if has_docker else None
        report["docker_daemon"] = daemon_up
        report["dependencies"] = _dependencies_report(repo, has_docker, daemon_up, compose_ok)
        if has_docker and daemon_up is False:
            _note("docker is installed but the daemon is not answering `docker info` — start it with "
                  "`sudo systemctl start docker` (add yourself to the 'docker' group if 'permission "
                  "denied'). The gateway + services + engine sandboxes cannot come up until it is running.")
    except Exception as _exc:  # noqa: BLE001 — a probe must never crash the report
        report["notes"].append(f"dependency preflight partially failed: {_exc}")

    # 2) the two venvs (hard prerequisites for `vigil up`)
    venvs = {
        "offense (vigil)": (repo / ".venv-offense" / "bin" / "vigil").exists(),
        "sovereign (sigil)": (repo / ".venv-sovereign" / "bin" / "sigil").exists(),
    }
    report["venvs"] = venvs
    for label, present in venvs.items():
        if not present:
            _issue(f"the {label} venv is not built — run ./bootstrap.sh (or envs/build_envs.sh).")

    # 3) runtime dirs
    home = Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))
    live = repo / ".vigil-live"
    report["dirs"] = {
        "SIGIL_HOME": {"path": str(home), "exists": home.exists(), "writable": _writable(home)},
        ".vigil-live": {"path": str(live), "exists": live.exists(), "writable": _writable(live)},
    }
    for key in ("SIGIL_HOME", ".vigil-live"):
        if not report["dirs"][key]["writable"]:
            _issue(f"{key} ({report['dirs'][key]['path']}) is not writable — `vigil up` needs to write there.")

    # 4) UI ports (free, or in-use — likely a `vigil up` already running)
    report["ui_ports"] = {name: ("free" if _port_free(p) else "in-use") for name, p in _UI_PORTS}

    # 5) docker services (create the absent ones with `vigil services up`)
    services: dict = {}
    if has_docker:
        try:
            from vigil_gateway.docker import SandboxNetworking
            gw = SandboxNetworking().status()
            services["vigil-gateway"] = {"state": gw.get("gateway", "absent"),
                                         "networks": gw.get("networks", {}), "image": gw.get("image")}
        except Exception as exc:  # noqa: BLE001 — a probe must never crash the report
            services["vigil-gateway"] = {"error": str(exc)}
        try:
            from .services import RootServices
            for name, meta in RootServices(repo).status().items():
                services[name] = {"state": meta["state"], "purpose": meta["purpose"],
                                  "reachable": meta.get("reachable")}   # endpoint-aware: True even if a
        except Exception as exc:  # noqa: BLE001
            services["_root_error"] = str(exc)
    report["docker_services"] = services

    # 6) the `vigil` entrypoint — the console SUBPROCESSES it (never imports it across the two-env boundary).
    #    Resolve it EXACTLY as the console does (console.actions._vigil_bin: a VIGIL_BIN override, else on
    #    $PATH) so doctor agrees with the console. ABSENT ⇒ two visible features degrade SILENTLY, so this is
    #    a HARD issue that names them.
    vigil_env = os.environ.get("VIGIL_BIN", "").strip()
    vigil_bin = vigil_env or shutil.which("vigil")
    report["vigil_entrypoint"] = {
        "resolved": bool(vigil_bin), "path": vigil_bin or None,
        "source": ("VIGIL_BIN" if vigil_env else ("PATH" if vigil_bin else None)),
    }
    if not vigil_bin:
        _issue("`vigil` is not on $PATH (and VIGIL_BIN is unset) — TWO features degrade silently: the console "
               "Terminal Run button errors ('the vigil entrypoint is not resolvable'), and the "
               "agentic/fireteam engage bridge falls back to the non-agentic offense engine. Fix: add "
               "~/.local/bin to $PATH (bootstrap.sh installs the launcher there) or export "
               "VIGIL_BIN=<repo>/.venv-offense/bin/vigil.")

    # 7) LLM backend — the backend + endpoint `vigil engage`'s think step will use, and (for a LOCAL network
    #    backend) whether its loopback daemon actually answers. A local backend that is not answering is a
    #    NOTE (advisory: a cloud pick needs no local daemon; a LOCAL pick never falls back to cloud — it
    #    REFUSES — so a dead local daemon is worth surfacing, but it does not block the rest of bring-up).
    llm = _probe_llm_backend()
    report["llm_backend"] = llm
    if llm.get("local") and llm.get("reachable") is False:
        _note(f"the LLM backend {str(llm.get('backend'))!r} at {llm.get('endpoint')} is not answering on "
              f"loopback — a LOCAL model pick will REFUSE (it never falls back to cloud). Start it, or pick a "
              f"cloud model / set CRUCIBLE_LLM_BACKEND.")

    # 8) Security posture (W9-4a) — one honest line PER security control showing its CURRENT state (ON vs
    #    OFF-by-default). INFORMATIONAL: `_collect_posture` calls NEITHER `_issue()` nor `_note()`, so this
    #    block changes neither the exit code nor any existing report field (the refuse-to-start production
    #    gate is step 9 below, and fires only under VIGIL_POSTURE=production). FATAL-2: the sovereign vault +
    #    framework entitlement are read from DISK — neither sigil nor framework is imported. `services` is
    #    passed so egress-gate reuses the already-collected gateway state.
    report["posture"] = _collect_posture(repo, services)

    # 8b) Backup / cadence timers (W7-8) — the per-timer breakdown behind the `backups` posture line: EACH
    #    infra/systemd/*.timer's enabled state AND last successful run, so an operator can see exactly which
    #    cadence is (or is not) running. INFORMATIONAL — it never flips `ok` on its own; the refuse-to-start
    #    decision rides the `backups` posture control in the production gate (step 9). Same systemctl reads,
    #    no new import — FATAL-2 intact.
    report["backup_timers"] = _backup_timers_report(repo)

    # 9) PRODUCTION posture gate (W9-4b) — the opt-in refuse-to-start gate, surfaced here so `vigil doctor`
    #    doubles as the production preflight. INERT unless VIGIL_POSTURE=production: when NOT armed the whole
    #    block is skipped, so the report is byte-identical to before (the additive, default-safe contract).
    #    When armed, each UNMET precondition is a HARD `_issue()` — it blocks a `vigil up` / `vigil engage`
    #    start, exactly what `_issue` means — so `ok` flips and the failing control is named. Reuses the
    #    already-collected posture (no re-probe). No new import: same on-disk/env reads, FATAL-2 intact.
    gate = evaluate_production_gate(repo, posture=report["posture"])
    if gate["armed"]:
        report["production_gate"] = gate
        for e in gate["unmet"]:
            _issue(f"PRODUCTION posture (VIGIL_POSTURE={gate['posture']}): {e['control']} is {e['state']} — "
                   f"{e['requirement']} (refuses `vigil up` / `vigil engage` until satisfied)")
    # 10) Integrity (W6-7) — continuously verify the property the product EXISTS to guarantee: the spine
    #    hash-chain / attestation. Runs the boundary-safe integrity verifier over the sovereign spine home
    #    (SIGIL_HOME): chain integrity, signed-head freshness, the anti-rollback floor, clock skew, plus the
    #    DEAD-MAN check that the scheduled verifier is actually running. A genuine integrity VIOLATION is a
    #    HARD issue (it flips `ok`); ABSENT/idle states are not. FATAL-2: the verifier reads inert on-disk
    #    bytes and imports only `vigil_core` — never `sigil`. Function-local import keeps doctor's load path
    #    light (mirrors the services import above).
    try:
        from . import integrity_verifier as _iv
        ir = _iv.verify_integrity(home)
        report["integrity"] = {
            "ok": ir.ok,
            "checks": [{"check": c.check, "status": c.status, "detail": c.detail} for c in ir.checks],
        }
        for c in ir.checks:
            if c.failed:
                _issue(f"spine integrity check '{c.check}' FAILED: {c.detail}")
        stale, hb_detail = _iv.heartbeat_is_stale(_iv._default_heartbeat_path(home))
        report["integrity"]["heartbeat_stale"] = stale
        report["integrity"]["heartbeat_detail"] = hb_detail
        # Dead-man: the periodic verifier not running is a NOTE by default (the timer is opt-in — an
        # operator who never enabled it should not see a hard failure), but if a spine exists it is a real
        # gap worth surfacing.
        if stale:
            _note(f"the scheduled integrity verifier is not running: {hb_detail} — enable it with "
                  f"`vigil verify-integrity --watch` (systemd: vigil-integrity.timer).")
    except Exception as exc:  # noqa: BLE001 — the integrity probe must never crash the report
        report["integrity"] = {"ok": None, "error": f"{type(exc).__name__}: {exc}", "checks": []}
        _note(f"the integrity verifier could not run: {exc}")

    # 10b) BUILD integrity (W9-7 #440 / W4-3 #443) — "are my own files the ones that shipped?" Reads the
    #     signed build manifest at the install/repo root and reports ONE of six explicit states, never an
    #     optimistic default. A tampered SIGNED RELEASE install (MODIFIED / MISSING) is a HARD issue (it
    #     flips `ok`) — an operator must know their files were changed. The other four states are NOTES: a
    #     source checkout carries no manifest (UNKNOWN_BUILD) and a dev/unsigned build is not a shipped
    #     release — none of those should brick doctor. FATAL-2: `vigil_core.signed_build_manifest` imports
    #     only stdlib + vigil_core crypto (never sigil/framework); function-local import keeps the load path
    #     light (mirrors the integrity block above). HONEST SCOPE: user-space self-verification detects an
    #     accidental/naive tamper; it does NOT defend against a hostile admin who re-signs under their own
    #     key (see docs/decisions/W9-7-signed-build-manifest.md).
    try:
        from vigil_core.signed_build_manifest import BuildIntegrityState as _BIS, evaluate_build_integrity
        bi = evaluate_build_integrity(repo)
        report["build_integrity"] = bi.to_dict()
        if bi.state in (_BIS.MODIFIED, _BIS.MISSING):
            _issue(f"BUILD integrity {bi.state}: {bi.detail} — this install's shipped files do not match "
                   f"the signed build manifest (`python3 tools/build_manifest.py verify` for detail).")
        elif bi.state != _BIS.VALID:
            _note(f"build integrity: {bi.state} — {bi.detail}. A signed build manifest is produced by the "
                  f"release build (`tools/build_manifest.py generate`); a source checkout carries none.")
    except Exception as exc:  # noqa: BLE001 — the build-integrity probe must never crash the report
        report["build_integrity"] = {"state": "UNKNOWN_BUILD", "ok": False,
                                     "error": f"{type(exc).__name__}: {exc}"}
        _note(f"the build-integrity verifier could not run: {exc}")

    # 11) HA/timer unit alerts (W8-1) — the DEAD-MAN for every scheduled unit. Reads each unit's heartbeat
    #     (written by its ExecStopPost hook) and surfaces any that are STALE/ABSENT (the timer stopped) or
    #     whose last run FAILED, plus the alert-delivery dead-man. ADVISORY by default (the alert timer is
    #     opt-in, like the integrity one — an operator who never enabled it should not see a hard failure),
    #     so this block calls only _note() and never flips `ok`. FATAL-2: reads inert on-disk JSON, imports
    #     only vigil_core. Function-local import keeps doctor's load path light.
    try:
        from . import unit_alerts as _ua
        statuses = _ua.collect_statuses(_ua.default_state_dir())
        report["unit_alerts"] = {
            "state_dir": str(_ua.default_state_dir()),
            "statuses": [st.to_dict() for st in statuses],
        }
        bad = [st for st in statuses if st.is_alarm]
        # If NO unit has ever written a heartbeat, the alerting path is simply not enabled — one calm NOTE,
        # not one per unit (mirrors the integrity dead-man's opt-in posture).
        if bad and all(st.state == _ua.ABSENT for st in statuses):
            _note("no scheduled-unit heartbeats found — the HA/timer staleness alerting is not enabled. "
                  "Enable it: install the ExecStopPost hooks + `systemctl --user enable --now "
                  "vigil-alerts.timer` (see infra/systemd/vigil-alerts.*).")
        else:
            for st in bad:
                _note(f"scheduled unit {st.unit} is {st.state}: {st.detail}")
        d_stale, d_detail = _ua.delivery_is_stale(_ua.default_state_dir())
        report["unit_alerts"]["delivery_stale"] = d_stale
        report["unit_alerts"]["delivery_detail"] = d_detail
        if d_stale and any(st.is_alarm and st.state != _ua.ABSENT for st in statuses):
            _note(f"alert delivery dead-man: {d_detail} — alarms may not be reaching anyone.")
    except Exception as exc:  # noqa: BLE001 — the unit-alerts probe must never crash the report
        report["unit_alerts"] = {"error": f"{type(exc).__name__}: {exc}", "statuses": []}
        _note(f"the unit-alerts monitor could not run: {exc}")
    return report


def render(report: dict) -> str:
    """A compact human-readable rendering of collect()'s dict."""
    def _mark(ok: bool) -> str:
        return "OK " if ok else "!! "
    lines = ["VIGIL doctor — system readiness", "=" * 34]
    lines.append("\nBinaries:")
    for b, present in report.get("binaries", {}).items():
        lines.append(f"  {_mark(present)}{b}")
    lines.append(f"  {_mark(report.get('docker_compose'))}docker compose (v2)")
    dd = report.get("docker_daemon")
    if dd is not None:
        lines.append(f"  {'OK ' if dd else '!! '}docker daemon"
                     + ("" if dd else " (NOT running — `sudo systemctl start docker`)"))
    lines.append("\nEnvironments:")
    for label, present in report.get("venvs", {}).items():
        lines.append(f"  {_mark(present)}{label} venv")
    lines.append("\nRuntime dirs:")
    for key, d in report.get("dirs", {}).items():
        lines.append(f"  {_mark(d['writable'])}{key}  ({d['path']}, writable={d['writable']})")
    lines.append("\nUI ports (127.0.0.1):")
    for name, st in report.get("ui_ports", {}).items():
        lines.append(f"  {'OK ' if st == 'free' else '.. '}{name}: {st}")
    lines.append("\nDocker services (create absent ones: `vigil services up [--all]`):")
    for name, d in report.get("docker_services", {}).items():
        if isinstance(d, dict) and "error" in d:
            lines.append(f"  !! {name}: {d['error']}")
        elif isinstance(d, dict):
            st = d.get("state", "?")
            purpose = f"  ({d['purpose']})" if d.get("purpose") else ""
            if st != "running" and d.get("reachable"):
                # endpoint-aware: a bare TCP connect succeeded on the port — so SOMETHING is answering
                # (e.g. an externally-named sigil-qdrant). Identity is NOT proven (not a protocol/banner
                # check) and it is not this compose project's container — but the port is not free, so
                # this is NOT the misleading "absent" the compose-scoped view showed. Honest wording, no
                # green mark, no "container" claim.
                lines.append(f"  ?? {name}: a process is answering on the port "
                             f"(outside this compose project — verify it is {name}){purpose}")
            else:
                lines.append(f"  {'OK ' if st == 'running' else '.. '}{name}: {st}{purpose}")
        else:
            lines.append(f"  .. {name}: {d}")
    deps = report.get("dependencies")
    if deps:
        missing = [x for x in deps if not x.get("present")]
        lines.append("\nDependencies (install what's missing — informational, does NOT affect the exit code):")
        if not missing:
            lines.append("  OK  every probed dependency is present")
        else:
            width = max((len(str(x.get("name", ""))) for x in missing), default=0)
            for x in missing:
                req = "required" if x.get("required") else "optional"
                lines.append(f"  !! {str(x.get('name')):<{width}}  [{x.get('kind')}, {req}]"
                             + (f"  — {x['detail']}" if x.get("detail") else ""))
                if x.get("how_to_install"):
                    lines.append(f"       → {x['how_to_install']}")
    ve = report.get("vigil_entrypoint")
    if ve is not None:
        lines.append("\n`vigil` entrypoint (Terminal Run + agentic/fireteam bridge subprocess it):")
        if ve.get("resolved"):
            lines.append(f"  OK vigil: {ve.get('path')}  (via {ve.get('source')})")
        else:
            lines.append("  !! vigil: NOT on $PATH (VIGIL_BIN unset) — Terminal Run errors, and agentic/"
                         "fireteam engage falls back to the non-agentic engine")
    llm = report.get("llm_backend")
    if llm is not None:
        lines.append("\nLLM backend (`vigil engage` think step):")
        reach = llm.get("reachable")
        mark = "!! " if reach is False else "OK "
        seg = f"  {mark}{llm.get('backend', '?')}  (source: {llm.get('source', '?')}, tier: {llm.get('tier')}"
        if llm.get("endpoint"):
            seg += f", endpoint: {llm['endpoint']}"
        seg += (", reachable" if reach is True else (", NOT answering" if reach is False else "")) + ")"
        lines.append(seg)
        if llm.get("detail"):
            lines.append(f"     {llm['detail']}")
    posture = report.get("posture")
    if posture:
        # INFORMATIONAL: one line PER control, its CURRENT state. An OFF/UNPROVISIONED/UNGOVERNED/ABSENT
        # line is NOT a failure (these are off-by-default) — the marker distinguishes an engaged control
        # (OK) from an off one (..) from an unreadable one (??). None of this affects the exit code.
        _on = {"ON", "SEALED", "ACTIVE", "PRESENT"}
        _unknown = {"UNKNOWN"}
        lines.append("\nSecurity posture (informational — off-by-default controls; does NOT affect the "
                     "exit code):")
        width = max((len(str(p.get("control", ""))) for p in posture), default=0)
        for p in posture:
            control, state = str(p.get("control", "?")), str(p.get("state", "?"))
            detail = str(p.get("detail", ""))
            mark = "OK " if state in _on else ("?? " if state in _unknown else ".. ")
            seg = f"  {mark}{(control + ':'):<{width + 1}} {state}"
            if detail:
                seg += f"  — {detail}"
            lines.append(seg)
    backup_timers = report.get("backup_timers")
    if backup_timers:
        # W7-8: EACH backup / cadence timer's enabled state + last successful run. Marker: OK = enabled and
        # a successful last run; .. = enabled but never fired (or disabled); ?? = enablement unreadable.
        lines.append("\nBackup / cadence timers (enabled + last successful run — `backups` posture rides "
                     "these):")
        twidth = max((len(str(t.get("name", ""))) for t in backup_timers), default=0)
        for t in backup_timers:
            name, enabled = str(t.get("name", "?")), t.get("enabled")
            if enabled is None:
                mark, state = "?? ", "unreadable (systemctl absent)"
            elif not enabled:
                mark, state = ".. ", "disabled"
            elif t.get("last_ok"):
                mark, state = "OK ", f"enabled, last ran {t.get('last_run')}"
            else:
                mark, state = ".. ", "enabled, never fired"
            lines.append(f"  {mark}{(name + ':'):<{twidth + 1}} {state}")
    gate = report.get("production_gate")
    if gate:
        # W9-4b: shown ONLY when VIGIL_POSTURE=production (else the field is absent). Unlike the
        # informational block above, an unmet precondition here IS a hard failure — it also appears in
        # "Action needed" and flips the exit code, because it refuses `vigil up` / `vigil engage`.
        # THE shared formatter (W6-6 / AC3): the exact block the README-regeneration generator renders,
        # so `vigil doctor`'s output and the README block can never drift. The blank separator is ours.
        lines.append("")
        lines.extend(_render_gate_block(gate))
    integ = report.get("integrity")
    if integ is not None:
        lines.append("\nSpine integrity (the property the product exists to guarantee):")
        if integ.get("error"):
            lines.append(f"  ?? verifier error: {integ['error']}")
        for c in integ.get("checks", []):
            st = str(c.get("status", "?"))
            mark = {"ok": "OK ", "fail": "!! ", "warn": ".. ", "absent": "-- ",
                    "unknown": "?? "}.get(st, "?? ")
            lines.append(f"  {mark}{c.get('check', '?')}: {st}  — {c.get('detail', '')}")
        if integ.get("heartbeat_stale") is not None:
            hb = "!! " if integ.get("heartbeat_stale") else "OK "
            lines.append(f"  {hb}scheduled-verifier heartbeat: {integ.get('heartbeat_detail', '')}")
    bi = report.get("build_integrity")
    if bi is not None:
        # W9-7/W4-3: one honest headline state + the per-artifact breakdown. VALID = OK; MODIFIED/MISSING =
        # a tampered signed release (hard, also in "Action needed"); the other four are informational.
        state = str(bi.get("state", "?"))
        mark = {"VALID": "OK ", "MODIFIED": "!! ", "MISSING": "!! "}.get(state, ".. ")
        lines.append("\nBuild integrity (are my files the ones that shipped? — one of six explicit states):")
        lines.append(f"  {mark}{state}  — {bi.get('detail', bi.get('error', ''))}")
        if bi.get("build_id"):
            lines.append(f"     build_id={bi.get('build_id')} channel={bi.get('channel')} "
                         f"version={bi.get('product_version')}")
        for a in bi.get("artifacts", []):
            st = str(a.get("status", "?"))
            amark = {"VALID": "OK ", "MODIFIED": "!! ", "MISSING": "!! ",
                     "ATTESTED_ONLY": "-- "}.get(st, "?? ")
            lines.append(f"  {amark}{a.get('name', '?')} ({a.get('kind', '?')}): {st}")

    issues = report.get("issues", [])
    if issues:
        lines.append("\nAction needed (blocks bring-up):")
        lines += [f"  - {m}" for m in issues]
    else:
        lines.append("\nAll hard prerequisites present. Bring up services with `vigil services up`, then "
                     "`vigil up`.")
    notes = report.get("notes", [])
    if notes:
        lines.append("\nNotes (optional):")
        lines += [f"  - {m}" for m in notes]
    return "\n".join(lines)
