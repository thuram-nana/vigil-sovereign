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
        ep = _local_endpoint(backend)
        out.update(backend=backend, local=True, endpoint=(ep or None))
        if not ep:
            out["reachable"] = None
            out["detail"] = (f"local backend {backend!r}: no endpoint configured "
                             f"(set CRUCIBLE_SELFHOSTED_ENDPOINT / LLM_API_BASE) — reachability not probed.")
            return
        host, port = _endpoint_host_port(ep)
        if not _host_is_loopback(host):
            out["reachable"] = None                     # the engine refuses this; do NOT egress-probe it
            out["detail"] = (f"local backend {backend!r} points at a NON-loopback endpoint ({ep}); the engine "
                             f"REFUSES it (it would send the prompt off-host). Point it at localhost / 127.0.0.1.")
            return
        reachable = _tcp_reachable(host, port)
        out["reachable"] = reachable
        out["detail"] = (f"local backend {backend!r} at {ep} is "
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
# `_issue()`, so the posture block NEVER changes `vigil doctor`'s exit code or existing behaviour (the
# refuse-to-start PRODUCTION gate is a separate later slice, W9-4b). Every probe reads REAL on-disk / env
# state — never an optimistic default — and fails SOFT to "UNKNOWN": a missing/unreadable control is
# reported, never a crash.
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


def _posture_backups(repo: Path) -> "tuple[str, str]":
    """Are the systemd backup/reprove/HA timers enabled? Enumerated from infra/systemd/*.timer and probed
    with `systemctl is-enabled`. ON iff at least one is enabled; OFF when none are (the default — the units
    ship in the repo but are not installed/enabled)."""
    timers_dir = repo / "infra" / "systemd"
    try:
        timer_files = sorted(p.name for p in timers_dir.glob("*.timer")) if timers_dir.is_dir() else []
    except OSError:
        timer_files = []
    if not timer_files:
        return "UNKNOWN", f"no timer units found under {_display_path(timers_dir)}"
    total = len(timer_files)
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return "UNKNOWN", f"systemctl not available — cannot read enablement of {total} timer unit(s)"
    enabled: list = []
    for name in timer_files:
        try:
            r = subprocess.run([systemctl, "is-enabled", name], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.stdout.strip() == "enabled":
            enabled.append(name)
    if enabled:
        return "ON", f"{len(enabled)}/{total} systemd timers enabled: {', '.join(enabled)}"
    return "OFF", (f"0/{total} systemd timers enabled ({', '.join(t[:-6] for t in timer_files)}) — "
                   f"backups/reprove/HA are not running")


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


def _collect_posture(repo: Path, services: dict) -> list:
    """The security-posture block: one honest line PER control, its CURRENT state read from real on-disk /
    env state (never an optimistic default). INFORMATIONAL — never flips `ok`. Every probe fails soft to
    UNKNOWN. FATAL-2: the sovereign-plane vault and the framework entitlement are read from DISK, importing
    neither sigil nor framework. The order is the plan's: egress-gate, vault, sovereignty, entitlement,
    backups, charter."""
    def _entry(control: str, fn) -> dict:
        try:
            state, detail = fn()
        except Exception as exc:  # noqa: BLE001 — a posture probe must never crash the report
            state, detail = "UNKNOWN", f"probe error: {type(exc).__name__}: {exc}"
        return {"control": control, "state": state, "detail": detail}

    return [
        _entry("egress-gate", lambda: _posture_egress(services)),
        _entry("vault", _posture_vault),
        _entry("sovereignty", _posture_sovereignty),
        _entry("entitlement", lambda: _posture_entitlement(repo)),
        _entry("backups", lambda: _posture_backups(repo)),
        _entry("charter", lambda: _posture_charter(repo)),
    ]


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
                services[name] = {"state": meta["state"], "purpose": meta["purpose"]}
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
    #    OFF-by-default). INFORMATIONAL: `_collect_posture` calls NEITHER `_issue()` nor `_note()`, so it
    #    changes neither the exit code nor any existing report field (the refuse-to-start production gate is
    #    W9-4b). FATAL-2: the sovereign vault + framework entitlement are read from DISK — neither sigil nor
    #    framework is imported. `services` is passed so egress-gate reuses the already-collected gateway state.
    report["posture"] = _collect_posture(repo, services)
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
            lines.append(f"  {'OK ' if st == 'running' else '.. '}{name}: {st}"
                         + (f"  ({d['purpose']})" if d.get("purpose") else ""))
        else:
            lines.append(f"  .. {name}: {d}")
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
