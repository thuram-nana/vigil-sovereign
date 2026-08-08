"""external_tool — run a REAL external security tool through the gated offense topology and let the
deterministic oracle turn its output into a signed FACT (TRUTHENOVATION R4).

This is the tool-agnostic bridge between "an external tool ran" and "a machine-verified FACT". It does
NOT reinvent adjudication, scope, or the egress floor — it composes the three parts that already exist:

  1. SCOPE GATE (before any traffic) — :class:`ScopeGate` composes the gateway's L3/L4 conscience
     (``vigil_gateway.denylist`` — the single source of truth for what egress is permitted) with the
     charter scope (``vigil_gateway.scope_source`` → CRUCIBLE ``host_matches_scope``). An out-of-scope
     target, a metadata/link-local address (169.254.169.254), or a private IP that is not charter-
     authorised is REFUSED here, BEFORE the tool is ever launched — no traffic leaves.

  2. GATED EXEC (the topology seam) — :class:`ExecBackend` is where the tool actually runs. The REAL
     offense-topology backend (:class:`DockerTopologyBackend`) launches the tool INSIDE a container
     pinned to the internal ``vigil_sandbox`` network (docker.py), whose ONLY exit is the filtering
     gateway behind the nftables egress gate. The tool physically cannot reach anything the gateway
     denylist forbids. :class:`LocalSubprocessBackend` runs the tool directly on the host — used for the
     loopback-service proof, because the docker/bwrap isolation backends UNSHARE the network namespace
     and so cannot reach a HOST loopback service (the container backend is for EXTERNAL scoped hosts).

  3. ORACLE ADJUDICATION (the FACT gate) — the tool's parsed output is a PROPOSAL, never a fact. For a
     service/port the tool reports "open", the runner reproduces the claim INDEPENDENTLY with a bounded,
     gated handshake (``framework.v2.verify.capture_handshake``) and judges the RETAINED connect
     evidence with the pure ``service_reachability_oracle`` — exactly CRUCIBLE's prove-don't-guess rule
     that "a scanner's say-so alone never confirms". Only on a fired oracle is a proof-carrying
     certificate minted + signed (``oracle_adapter.confirm_and_certify``, ``provenance="live_redrive"``
     — the handshake IS a live re-drive of the scope-gated target). Everything else stays a labelled
     lead.

Honesty / residual (see docs/DEFERRED-INFRA.md R4): the MECHANISM is tool-agnostic — any external tool
plus an output parser and an oracle mapping plugs in. Only the PRESENT-tool path (nmap against a
loopback service) is exercised live here. The LLM-red-team tools (garak / PyRIT / promptfoo) are ABSENT
from this environment (no network to install them), so their live-fire is DEFERRED; this module does NOT
mint a garak/PyRIT FACT. The DockerTopologyBackend builds the real pinned-network argv, but its live
container run is gated on docker + the sandbox network + a tool image being present.

FATAL-2: ``framework`` (offense) imports are function-local, so importing this module never co-loads the
offense engine into the sovereign env. ``vigil_gateway`` is pure/offense-neutral (its scope predicate is
lazy) and is imported at module load via a small path bootstrap mirroring ``scope_source``.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Protocol, Sequence, runtime_checkable


# ---------------------------------------------------------------------------
# vigil_gateway bootstrap — the gateway package is path-based (PYTHONPATH=gateway in CI); locate it
# relative to the repo root if a plain import fails, exactly as scope_source does. Pure (no framework).
# ---------------------------------------------------------------------------
def _gateway_modules():
    try:
        from vigil_gateway import denylist, scope_source  # type: ignore
        return denylist, scope_source
    except ImportError:
        repo_root = Path(__file__).resolve().parents[3]
        gw = repo_root / "gateway"
        if gw.is_dir() and str(gw) not in sys.path:
            sys.path.insert(0, str(gw))
        from vigil_gateway import denylist, scope_source  # type: ignore
        return denylist, scope_source


_DEFAULT_TIMEOUT = 120.0
_OUTPUT_CAP = 2_000_000  # 2 MB per stream — a scanner can be chatty
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def _is_loopback_host(target: str) -> bool:
    """True iff ``target`` (a host or URL) resolves to the loopback name/IP literally — a conservative,
    offline check (no DNS) used only to keep the unisolated LocalSubprocessBackend off external targets."""
    from urllib.parse import urlsplit
    t = (target or "").strip()
    host = (urlsplit(t).hostname if "//" in t else t) or t
    return host.strip("[]").lower() in _LOOPBACK_HOSTS


# ---------------------------------------------------------------------------
# The outcome of one tool run (JSON-safe, no live handles).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ToolOutcome:
    argv: list[str]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    backend: str
    timed_out: bool = False
    truncated: bool = False


class BackendUnavailable(RuntimeError):
    """The requested exec backend cannot run here (docker/image/network missing). Fail-closed — the
    runner never silently falls back to an un-gated exec that would drop the topology."""


# ---------------------------------------------------------------------------
# Exec backends — WHERE the tool runs (the topology seam).
# ---------------------------------------------------------------------------
@runtime_checkable
class ExecBackend(Protocol):
    name: str

    def available(self) -> tuple[bool, str]:
        """(runnable, reason). A backend that cannot run returns ``(False, why)`` — the runner raises
        :class:`BackendUnavailable` rather than run un-gated."""
        ...

    def run(self, tool_argv: Sequence[str], *, timeout: float) -> ToolOutcome:
        ...


def _cap(s: str) -> tuple[str, bool]:
    if len(s) > _OUTPUT_CAP:
        return s[:_OUTPUT_CAP], True
    return s, False


def _run_argv(argv: list[str], *, timeout: float, backend: str) -> ToolOutcome:
    """One bounded, captured subprocess run with stdin closed. Total — a spawn error / timeout is a
    captured negative ToolOutcome, never a raise (so adjudication sees "the tool produced nothing")."""
    try:
        proc = subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as te:
        so = te.stdout if isinstance(te.stdout, str) else (te.stdout.decode("utf-8", "replace") if te.stdout else "")
        se = te.stderr if isinstance(te.stderr, str) else (te.stderr.decode("utf-8", "replace") if te.stderr else "")
        so, t1 = _cap(so)
        se, t2 = _cap(se)
        return ToolOutcome(argv, None, so, se, backend, timed_out=True, truncated=t1 or t2)
    except OSError as e:
        return ToolOutcome(argv, None, "", f"spawn error: {type(e).__name__}: {e}", backend)
    so, t1 = _cap(proc.stdout or "")
    se, t2 = _cap(proc.stderr or "")
    return ToolOutcome(argv, proc.returncode, so, se, backend, truncated=t1 or t2)


@dataclass(frozen=True)
class LocalSubprocessBackend:
    """Run the tool DIRECTLY on the host. The runner's :class:`ScopeGate` is the only thing that keeps
    it in scope (the tool receives ONLY the already-authorised target). Used for the loopback-service
    proof: the docker/bwrap isolation backends unshare the net namespace and cannot reach a HOST
    loopback listener, so this is the backend that exercises the scope-gate → oracle → FACT path
    against a loopback target the owner's charter authorises.

    ``loopback_only`` (default True): this backend runs the tool UNISOLATED on the host, so the runner
    refuses it against a NON-loopback target (crit 1) — an external scan must go through the network-
    namespaced, resource-capped DockerTopologyBackend. Set False only for a deliberate host-run against a
    non-loopback target the operator has isolated by other means."""

    name: str = "local"
    loopback_only: bool = True

    def available(self) -> tuple[bool, str]:
        return True, "host subprocess"

    def run(self, tool_argv: Sequence[str], *, timeout: float) -> ToolOutcome:
        argv = list(tool_argv)
        if not argv:
            return ToolOutcome(argv, None, "", "empty tool argv", self.name)
        binary = shutil.which(argv[0])
        if not binary:
            return ToolOutcome(argv, None, "", f"tool not found on PATH: {argv[0]!r}", self.name)
        return _run_argv([binary, *argv[1:]], timeout=timeout, backend=self.name)


@dataclass(frozen=True)
class DockerTopologyBackend:
    """Run the tool INSIDE a container pinned to the internal ``vigil_sandbox`` network — the REAL gated
    offense topology (docker.py). The sandbox network is ``internal: true`` (Docker installs no default
    route), so the tool's ONLY exit is the filtering gateway behind the nftables egress gate: it can
    reach only what the gateway denylist permits. The container drops ALL caps and gets
    ``no-new-privileges``.

    ``available()`` is honest about what is missing (docker daemon / the sandbox network / the tool
    image). ``build_argv`` is a pure function of its inputs so the pinned-network wrapper is unit-
    testable with no docker present; the live container run is gated on ``available()``."""

    image: str
    network: str = "vigil_sandbox"
    docker_bin: Optional[str] = None
    name: str = "docker"
    # Least-privilege resource limits (crit 1/11) — a hostile/runaway tool cannot exhaust the host or spawn
    # a fork bomb, and writes nowhere but an ephemeral tmpfs. All overridable for a tool that needs more.
    memory: str = "1g"                 # hard memory cap (== --memory-swap ⇒ no swap)
    cpus: str = "1.0"                  # CPU quota
    pids_limit: int = 256             # fork-bomb guard
    read_only_rootfs: bool = True     # read-only container FS + a size-capped /tmp tmpfs
    tmpfs_size: str = "64m"
    run_user: str = "65534:65534"     # nobody:nogroup — never root inside the container
    require_digest_pin: bool = True   # fail-closed: refuse an image that is not pinned by @sha256 digest

    def _docker(self) -> Optional[str]:
        return self.docker_bin or shutil.which("docker")

    def build_argv(self, tool_argv: Sequence[str]) -> list[str]:
        docker = self._docker() or "docker"
        argv = [
            docker, "run", "--rm", "--network", self.network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--memory", self.memory, "--memory-swap", self.memory,
            "--cpus", str(self.cpus), "--pids-limit", str(self.pids_limit),
            "--user", self.run_user,
        ]
        if self.read_only_rootfs:
            argv += ["--read-only", "--tmpfs", f"/tmp:rw,size={self.tmpfs_size}"]
        argv += [self.image, *list(tool_argv)]
        return argv

    @staticmethod
    def _is_digest_pinned(image: str) -> bool:
        # a digest-pinned image is <name>@sha256:<64 hex> — a tag (":latest") is mutable and NOT pinned.
        _, _, digest = image.partition("@")
        return digest.startswith("sha256:") and len(digest) == len("sha256:") + 64

    def _network_exists(self, docker: str) -> bool:
        try:
            p = subprocess.run([docker, "network", "inspect", self.network],
                               capture_output=True, text=True, timeout=15)
            return p.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _image_present(self, docker: str) -> bool:
        try:
            p = subprocess.run([docker, "image", "inspect", self.image],
                               capture_output=True, text=True, timeout=15)
            return p.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def available(self) -> tuple[bool, str]:
        # crit-1 fail-closed: a mutable tag can be repointed at arbitrary bytes between provisioning and
        # run — refuse to run an image that is not pinned by @sha256 digest (unless explicitly opted out).
        if self.require_digest_pin and not self._is_digest_pinned(self.image):
            return False, (f"image {self.image!r} is not digest-pinned (@sha256:...) — refusing "
                           f"(set require_digest_pin=False only for a trusted local dev image)")
        docker = self._docker()
        if not docker:
            return False, "docker binary not found"
        try:
            info = subprocess.run([docker, "info"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"docker daemon unreachable: {type(e).__name__}"
        if info.returncode != 0:
            return False, "docker daemon unreachable (docker info failed)"
        if not self._network_exists(docker):
            return False, (f"the {self.network!r} internal network is not up — run "
                           f"SandboxNetworking().ensure_networks() to create the gated topology")
        if not self._image_present(docker):
            return False, f"tool image {self.image!r} not present locally (offline: cannot pull)"
        return True, "docker topology ready"

    def run(self, tool_argv: Sequence[str], *, timeout: float) -> ToolOutcome:
        argv = self.build_argv(tool_argv)
        return _run_argv(argv, timeout=timeout, backend=self.name)


# ---------------------------------------------------------------------------
# Tool spec — the tool-agnostic contract: build the argv, and parse the output into proposed services.
# A PROPOSAL is never a fact; the oracle re-execution below is what confirms it.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProposedService:
    host: str
    port: int
    protocol: str = "tcp"


@dataclass(frozen=True)
class Redrive:
    """One RUNNER-OWNED oracle re-drive for a proposed (host, port): an independent, gated ``capture`` the
    runner performs itself + a ``context`` builder that turns the captured evidence into an oracle_context
    for ``bug_class``. The runner judges what IT captured, never the tool's row — so a tool proposing a
    finding it cannot reproduce yields no FACT. ``context`` returning ``None`` skips this re-drive (the
    captured evidence did not support it, e.g. no cert presented). Every framework import inside ``capture``
    / ``context`` is FUNCTION-LOCAL (FATAL-2)."""
    bug_class: str
    capture: Callable[..., dict]              # (host, port, *, slug, protocol) -> captured evidence
    context: Callable[[dict], "dict | None"]  # captured evidence -> oracle_context (None -> skip)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    build_argv: Callable[[str], list[str]]
    propose: Callable[[ToolOutcome, str], list[ProposedService]]
    # The runner-owned re-drives to run for EACH proposed service. Empty ⇒ the runner uses the legacy
    # reachability re-drive (the injectable ``capture`` param + reachable_context + service_reachable), so
    # nmap and every existing caller are byte-for-byte unchanged. A spec that mints a non-reachability FACT
    # (e.g. TLS) carries its re-drives HERE — never body-supplied provenance (the HIGH-3 guard).
    redrives: "tuple[Redrive, ...]" = ()
    # OPTIONAL argv that prints the tool's VERSION (e.g. ["nmap","--version"]). The runner runs it once
    # through the SAME gated backend (no target traffic) and stamps the parsed version into every FACT this
    # run mints (criterion 9 tool_version). None ⇒ no version stamped (byte-identical certificate).
    version_argv: "Callable[[], list[str]] | None" = None


_NMAP_GREPABLE_OPEN = re.compile(r"\b(\d{1,5})/open/(tcp|udp)\b")


# --- TLS posture re-drives (weak protocol/cipher + broken-hash cert) -------------------------------
# The runner negotiates its OWN bounded, gated TLS handshake (capture_tls_handshake, the same audited gate
# as reachability) and judges THAT with the pure tls/weak-crypto oracles — never sslscan's output rows.

def _tls_capture(host: str, port: int, *, slug: str, protocol: str = "tcp") -> dict:
    from framework.v2.verify import capture_tls_handshake  # offense-side only (FATAL-2: function-local)
    return capture_tls_handshake(host, int(port), slug=slug)


def _weak_tls_context(handshake: dict) -> "dict | None":
    from framework.v2.verify import weak_tls_context  # offense-side only
    if not handshake.get("connected"):
        return None
    return weak_tls_context(handshake)


def _weak_crypto_context(handshake: dict) -> "dict | None":
    import base64
    from framework.v2.verify import weak_crypto_context  # offense-side only
    b64 = handshake.get("cert_der_b64")
    if not b64:
        return None
    try:
        der = base64.b64decode(b64)
    except Exception:
        return None
    fc = weak_crypto_context(der)
    return fc.to_verifier_context() if fc is not None else None


# Both re-drives SHARE the one _tls_capture function object, so the runner negotiates ONE handshake and
# judges it for both a weak protocol/cipher and a broken-hash cert.
_TLS_REDRIVES: "tuple[Redrive, ...]" = (
    Redrive("weak_tls", _tls_capture, _weak_tls_context),
    Redrive("weak_crypto_artifact", _tls_capture, _weak_crypto_context),
)


def tls_scan(*, port: int = 443, extra_args: Sequence[str] = ()) -> ToolSpec:
    """A :class:`ToolSpec` for ``sslscan`` as a PROPOSER of a TLS endpoint. ``build_argv`` emits
    ``sslscan --no-colour <target>:<port>``; ``propose`` yields the (host, port) only when the tool
    actually reached a TLS service. The tool's per-cipher rows are never trusted — the runner re-drives its
    OWN gated handshake and the deterministic oracle judges the NEGOTIATED (protocol, cipher) and the
    PRESENTED cert. HONEST SCOPE: capture_tls_handshake uses a standard client, so ``weak_tls`` fires only
    on a weakness a modern client still negotiates; ``weak_crypto_artifact`` fires unconditionally on an
    MD5/SHA1-signed cert (offline-re-verifiable) — the two together are the runner-owned TLS FACTs."""
    def build(target: str) -> list[str]:
        return ["sslscan", "--no-colour", *list(extra_args), f"{target}:{port}"]

    def propose(outcome: ToolOutcome, target: str) -> list[ProposedService]:
        text = (outcome.stdout or "") + "\n" + (outcome.stderr or "")
        reached = any(m in text for m in ("Connected to", "Testing SSL server", "Accepted", "Preferred"))
        return [ProposedService(host=target, port=port, protocol="tcp")] if reached else []

    return ToolSpec("tls_scan", build, propose, redrives=_TLS_REDRIVES,
                    version_argv=lambda: ["sslscan", "--version"])


def nmap_service_scan(*, ports: str = "1-1024", extra_args: Sequence[str] = ()) -> ToolSpec:
    """A :class:`ToolSpec` for nmap in grepable mode. ``build_argv`` emits ``nmap -Pn -n -oG - -p
    <ports> <target>`` (host-discovery off, no DNS, grepable to stdout); ``propose`` parses each
    ``<port>/open/<proto>`` row into a :class:`ProposedService`. The parsed "open" is a PROPOSAL — the
    runner re-proves each with a gated handshake before any FACT is minted."""
    def build(target: str) -> list[str]:
        return ["nmap", "-Pn", "-n", *list(extra_args), "-oG", "-", "-p", ports, target]

    def propose(outcome: ToolOutcome, target: str) -> list[ProposedService]:
        seen: set[tuple[int, str]] = set()
        out: list[ProposedService] = []
        for m in _NMAP_GREPABLE_OPEN.finditer(outcome.stdout or ""):
            port, proto = int(m.group(1)), m.group(2)
            if 0 < port < 65536 and (port, proto) not in seen:
                seen.add((port, proto))
                out.append(ProposedService(host=target, port=port, protocol=proto))
        return out

    return ToolSpec("nmap", build, propose, version_argv=lambda: ["nmap", "--version"])


# ---------------------------------------------------------------------------
# Scope gate — refuse an out-of-scope / egress-denied target BEFORE any traffic.
# ---------------------------------------------------------------------------
@dataclass
class ScopeGate:
    """Compose the charter scope with the gateway's L3/L4 egress conscience. ``authorize(host)`` returns
    ``(allowed, reason)`` and is consulted BEFORE the tool is launched.

    The gateway denylist (``vigil_gateway.denylist``) is the single source of truth for egress: a
    metadata/link-local/reserved address is refused unconditionally; a private IP is refused unless it
    is exactly charter-authorised; loopback is refused unless ``loopback_allowed_if_scoped`` (the owner
    engaging a loopback target their signed charter names). The charter scope
    (``vigil_gateway.scope_source``) additionally requires the hostname itself to be in scope."""

    scope: Any  # a vigil_gateway.scope_source.ScopeSource
    loopback_allowed_if_scoped: bool = False
    resolver: Callable[..., Any] = socket.getaddrinfo

    def _resolve(self, host: str) -> list[str]:
        """Concrete IPs the target resolves to (the literal itself if it is already an IP). Total."""
        h = (host or "").strip().strip("[]")
        try:
            socket.inet_aton(h)
            return [h]
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, h)
            return [h]
        except OSError:
            pass
        try:
            infos = self.resolver(h, None)
        except (socket.gaierror, OSError, UnicodeError):
            return []
        return [info[4][0] for info in infos if info[4] and info[4][0]]

    def authorize(self, host: str) -> tuple[bool, str]:
        denylist, _ = _gateway_modules()
        h = (host or "").strip()
        if not h:
            return False, "empty target (fail-closed)"
        # 1. charter scope — the hostname must be in the signed scope.
        if not self.scope.matches(h):
            return False, f"{h!r} is not in the charter scope"
        # 2. gateway L3/L4 egress conscience over every resolved IP (single source of truth).
        #    The allow-set is ONLY the charter-authorized IPs (non-wildcard scope entries
        #    resolved to concrete IPs) — we do NOT self-authorize the target's own resolved
        #    IP. Self-adding it would lift the denylist's Tier-2 private-IP / DNS-rebinding
        #    gate for a broad wildcard scope (``*.example.com`` resolving to 10.x via split-
        #    horizon or attacker-controlled DNS), diverging from the gateway proxy this claims
        #    to compose. A legitimate IP-literal or exact-hostname scope is already present in
        #    resolved_allowed_ips, so dropping the self-add removes ONLY the wildcard→private
        #    bypass and leaves every authorized path (including scoped loopback) unchanged.
        ips = self._resolve(h)
        if not ips:
            return False, f"{h!r} does not resolve to any IP (fail-closed)"
        allowed_ips = frozenset(self.scope.resolved_allowed_ips(resolver=self.resolver))
        for ip in ips:
            denied, reason = denylist.is_egress_denied(
                ip, allowed_ips, loopback_allowed_if_scoped=self.loopback_allowed_if_scoped)
            if denied:
                return False, f"egress denied for {ip}: {reason}"
        return True, f"{h} in scope and egress-permitted ({', '.join(ips)})"


# ---------------------------------------------------------------------------
# The runner — scope-gate → gated exec → capture → oracle → signed FACT.
# ---------------------------------------------------------------------------
@dataclass
class RunnerResult:
    status: str                      # "refused" (pre-traffic) | "ran"
    reason: str
    tool: str
    target: str
    outcome: Optional[ToolOutcome] = None
    facts: list = field(default_factory=list)          # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)          # AdapterResult (status=="lead")
    proposed: list = field(default_factory=list)        # ProposedService parsed from the tool output
    contexts: dict = field(default_factory=dict)        # finding_ref -> oracle_context (for offline re-verify)
    outcomes: list = field(default_factory=list)        # per-item {check_id, bug_class, outcome} — the typed
                                                        # positive/clean/inconclusive/unsupported/error/skipped
                                                        # taxonomy (criterion 7), so no state is conflated.
    tool_errored: bool = False                          # the tool run itself errored (timeout / spawn failure)
    observation: Any = None                             # the canonical normalized Observation (crit 4):
                                                        # tool identity+version, target, raw-output digest,
                                                        # proposals, outcome_class — one shape per run.

    @property
    def refused(self) -> bool:
        return self.status == "refused"


def _default_capture(host: str, port: int, *, slug: str, protocol: str) -> dict:
    """Reproduce a bounded, gated handshake with CRUCIBLE's active-recon capture (function-local
    framework import — FATAL-2). The oracle judges THIS retained connect evidence, not the tool's row."""
    from framework.v2.verify import capture_handshake  # offense-side only
    return capture_handshake(host, port, slug=slug, protocol=protocol)


def _preflight_gate_refusal(engagement_slug: str) -> "str | None":
    """Fail-closed pre-flight for the TOOL EXEC itself — returns a refusal reason, or None to proceed.

    Mirrors the oracle re-drive's gate order (``verify.reachability._authorize``: kill-switch → entitlement)
    so the tool SUBPROCESS — not merely the later oracle re-drive — is halted by a tripped kill-switch, a
    missing charter context, or an un-entitled run, BEFORE any traffic leaves. Charter SCOPE + egress are
    additionally enforced by ``ScopeGate.authorize`` right after this. Framework imports are function-local
    (FATAL-2): importing this module co-loads no offense engine. A failing check REFUSES (never proceeds)."""
    if not engagement_slug:
        return "an external tool run requires an engagement slug (no charter context = no authorization)"
    try:
        from framework.v2.authority import KillSwitch  # offense-side only
        if KillSwitch(engagement_slug).is_tripped():
            return "kill-switch tripped"
    except Exception as e:  # noqa: BLE001 — a failing kill-switch check REFUSES (fail-closed)
        return f"kill-switch check failed (fail-closed): {e}"
    try:
        from framework.v2.entitlement import require_capability  # offense-side only
        from framework.v2.entitlement.models import Capability
        require_capability(Capability.ACTIVE_RECON)
    except Exception as e:  # noqa: BLE001 — no entitlement ⇒ refuse
        return f"active_recon not entitled (fail-closed): {e}"
    return None


def _capture_tool_version(spec: "ToolSpec", backend: "ExecBackend", timeout: float) -> str:
    """Best-effort tool version via ``spec.version_argv`` through the SAME gated backend (no target). The
    parsed value is the producer's ASSERTED version (stamped + signed into the cert; NOT a proof of which
    binary ran — see EvidenceCertificate.tool_version). Never fatal: any failure yields "" (dropped from the
    cert → byte-identical). Returns the first non-empty stdout/stderr line, capped, single-line."""
    va = getattr(spec, "version_argv", None)
    if va is None:
        return ""
    try:
        argv = list(va())
        if not argv:
            return ""
        out = backend.run(argv, timeout=min(timeout, 20.0))
        text = (out.stdout or "") + "\n" + (out.stderr or "")
        for line in text.splitlines():
            line = line.strip()
            if line:
                return line[:120]
    except Exception:  # noqa: BLE001 — version capture is advisory; never break a run over it
        return ""
    return ""


def _reachable_context(handshake: dict) -> dict:
    from framework.v2.verify import reachable_context  # offense-side only
    return reachable_context(handshake)


def run_external_tool(
    spec: ToolSpec,
    target: str,
    *,
    scope_gate: ScopeGate,
    backend: ExecBackend,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    capture: Callable[..., dict] = _default_capture,
    timeout: float = _DEFAULT_TIMEOUT,
    freshness_ttl_seconds: int = 0,
) -> RunnerResult:
    """Run ``spec`` against ``target`` through ``backend`` and mint a signed FACT for every proposed
    service the deterministic oracle CONFIRMS.

    Order (each step fail-closed):

      1. ``scope_gate.authorize(target)`` — if refused, return ``status="refused"`` with the reason and
         run NOTHING. No traffic leaves for an out-of-scope / egress-denied target.
      2. ``backend.available()`` — if the gated backend cannot run, raise :class:`BackendUnavailable`
         (never a silent un-gated fallback).
      3. ``backend.run(...)`` launches the tool through the topology and captures its output.
      4. For each ``ProposedService`` parsed from the output, reproduce a gated handshake
         (``capture``) and drive ``oracle_adapter.confirm_and_certify`` (``provenance="live_redrive"``)
         — a fired oracle mints a signed proof-carrying FACT; anything else is a labelled lead.

    ``signers`` = the governance authorisers ``[(key_id, priv_b64)]`` — required (a zero-signature
    certificate is never labelled a fact; confirm_and_certify enforces this)."""
    # 0. PRE-FLIGHT GATE on the tool exec (crit 3/11): kill-switch + charter-context + entitlement, BEFORE
    #    scope/egress or any traffic — so a tripped kill-switch halts the tool SUBPROCESS, not just the later
    #    oracle re-drive. (WARDEN A2 + the m-of-n conjunctive approval are enforced upstream at the body/
    #    orchestrator layer — HexstrikeAgentBody._warden_gate — which is sovereign-side; the offense runner
    #    cannot import that gate under FATAL-2, so it self-enforces the offense-side floor here.)
    refusal = _preflight_gate_refusal(engagement_slug)
    if refusal is not None:
        from .observation import refused_observation  # noqa: PLC0415
        return RunnerResult("refused", f"pre-flight gate: {refusal}", spec.name, target,
                            observation=refused_observation(spec, target))

    allowed, reason = scope_gate.authorize(target)
    if not allowed:
        from .observation import refused_observation  # noqa: PLC0415
        return RunnerResult("refused", reason, spec.name, target,
                            observation=refused_observation(spec, target))

    # crit-1 isolation floor: a loopback-only backend (LocalSubprocessBackend runs UNISOLATED on the host)
    # must NOT be used against a NON-loopback target — an external scan goes through the network-namespaced,
    # resource-capped DockerTopologyBackend. Refuse before any traffic.
    if getattr(backend, "loopback_only", False) and not _is_loopback_host(target):
        from .observation import refused_observation  # noqa: PLC0415
        return RunnerResult(
            "refused",
            f"{backend.name} backend is loopback-only (unisolated host run); target {target!r} is not "
            f"loopback — use the network-namespaced DockerTopologyBackend for an external target",
            spec.name, target, observation=refused_observation(spec, target))

    ok, why = backend.available()
    if not ok:
        raise BackendUnavailable(f"{backend.name} backend unavailable: {why}")

    outcome = backend.run(spec.build_argv(target), timeout=timeout)

    # function-local (FATAL-2): drive the existing anti-hallucination adapter — do NOT reimplement it.
    from ..oracle_adapter import Outcome, confirm_and_certify

    # Tool-level ERROR: the run timed out or the process could not spawn (exit_code is None). Its output is
    # untrustworthy — a chatty scanner that timed out mid-write must not have a truncated row treated as a
    # clean/positive signal. We still parse proposals (propose is total), but the ERROR is recorded so a
    # caller never conflates "the tool errored" with "the tool ran and found nothing".
    tool_errored = bool(outcome.timed_out) or (outcome.exit_code is None)

    proposed = spec.propose(outcome, target)
    # The re-drives to run per proposed service. Empty spec.redrives ⇒ the legacy reachability re-drive
    # (built from the injectable `capture` param), so nmap + every existing caller are byte-for-byte
    # unchanged. A TLS/etc. spec carries its OWN runner-owned re-drives on the spec.
    redrives = spec.redrives or (Redrive("service_reachable", capture, _reachable_context),)
    # Best-effort tool VERSION (criterion 9): run the spec's version_argv ONCE through the SAME gated backend
    # (no target traffic) and stamp the parsed version into every FACT this run mints. Never fatal — an
    # absent/failing version_argv just leaves the version "" (dropped from the cert → byte-identical).
    tool_version = _capture_tool_version(spec, backend, timeout)
    facts: list = []
    leads: list = []
    contexts: dict = {}
    outcomes: list = []
    if tool_errored:
        outcomes.append({"check_id": spec.name, "bug_class": "", "outcome": Outcome.ERROR.value})
    for svc in proposed:
        # One capture per distinct capture callable per service (so two re-drives sharing a handshake —
        # weak_tls + weak_crypto — negotiate it ONCE), then judge it for each re-drive's bug_class.
        captured: dict = {}
        for rd in redrives:
            cap_key = id(rd.capture)
            if cap_key not in captured:
                captured[cap_key] = rd.capture(svc.host, svc.port, slug=engagement_slug, protocol=svc.protocol)
            item = f"{spec.name}:{svc.host}:{svc.port}/{svc.protocol}#{rd.bug_class}"
            oracle_context = rd.context(captured[cap_key])
            if oracle_context is None:
                # SKIPPED: the runner's own capture yielded no evidence this re-drive can judge (e.g. no
                # cert presented for weak_crypto) — NOT a clean negative, and never a fabricated FACT.
                outcomes.append({"check_id": item, "bug_class": rd.bug_class, "outcome": Outcome.SKIPPED.value})
                continue
            finding = {
                "check_id": item,
                "bug_class": rd.bug_class,
                "insertion_point": f"{svc.host}:{svc.port}",
                "oracle_context": oracle_context,
            }
            res = confirm_and_certify(
                finding, engagement_slug=engagement_slug, signers=signers, provenance="live_redrive",
                tool_version=tool_version, freshness_ttl_seconds=freshness_ttl_seconds)
            # retain the exact context keyed by the result's finding_ref so a caller can re-verify the
            # signed certificate OFFLINE (verify_certificate needs the context; the cert stores its digest).
            contexts[res.finding_ref] = oracle_context
            outcomes.append({"check_id": item, "bug_class": rd.bug_class,
                             "outcome": res.outcome or (Outcome.POSITIVE.value if res.is_fact else "")})
            (facts if res.is_fact else leads).append(res)

    detail = (f"{spec.name} ran via {outcome.backend}; proposed {len(proposed)} service(s), "
              f"oracle-confirmed {len(facts)} FACT(s), {len(leads)} lead(s)"
              + ("; TOOL ERRORED (timeout/spawn)" if tool_errored else ""))
    from .observation import observe  # noqa: PLC0415
    observation = observe(spec, target, outcome, proposed, tool_version=tool_version,
                          outcome_class="errored" if tool_errored else "ran")
    return RunnerResult("ran", detail, spec.name, target, outcome, facts, leads, proposed, contexts,
                        outcomes=outcomes, tool_errored=tool_errored, observation=observation)
