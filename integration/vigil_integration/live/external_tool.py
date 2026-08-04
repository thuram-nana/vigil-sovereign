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
    against a loopback target the owner's charter authorises."""

    name: str = "local"

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

    def _docker(self) -> Optional[str]:
        return self.docker_bin or shutil.which("docker")

    def build_argv(self, tool_argv: Sequence[str]) -> list[str]:
        docker = self._docker() or "docker"
        return [
            docker, "run", "--rm", "--network", self.network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            self.image, *list(tool_argv),
        ]

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
class ToolSpec:
    name: str
    build_argv: Callable[[str], list[str]]
    propose: Callable[[ToolOutcome, str], list[ProposedService]]


_NMAP_GREPABLE_OPEN = re.compile(r"\b(\d{1,5})/open/(tcp|udp)\b")


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

    return ToolSpec("nmap", build, propose)


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

    @property
    def refused(self) -> bool:
        return self.status == "refused"


def _default_capture(host: str, port: int, *, slug: str, protocol: str) -> dict:
    """Reproduce a bounded, gated handshake with CRUCIBLE's active-recon capture (function-local
    framework import — FATAL-2). The oracle judges THIS retained connect evidence, not the tool's row."""
    from framework.v2.verify import capture_handshake  # offense-side only
    return capture_handshake(host, port, slug=slug, protocol=protocol)


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
    allowed, reason = scope_gate.authorize(target)
    if not allowed:
        return RunnerResult("refused", reason, spec.name, target)

    ok, why = backend.available()
    if not ok:
        raise BackendUnavailable(f"{backend.name} backend unavailable: {why}")

    outcome = backend.run(spec.build_argv(target), timeout=timeout)

    # function-local (FATAL-2): drive the existing anti-hallucination adapter — do NOT reimplement it.
    from ..oracle_adapter import confirm_and_certify

    proposed = spec.propose(outcome, target)
    facts: list = []
    leads: list = []
    contexts: dict = {}
    for svc in proposed:
        handshake = capture(svc.host, svc.port, slug=engagement_slug, protocol=svc.protocol)
        oracle_context = _reachable_context(handshake)
        finding = {
            "check_id": f"{spec.name}:{svc.host}:{svc.port}/{svc.protocol}",
            "bug_class": "service_reachable",
            "insertion_point": f"{svc.host}:{svc.port}",
            "oracle_context": oracle_context,
        }
        res = confirm_and_certify(
            finding, engagement_slug=engagement_slug, signers=signers, provenance="live_redrive")
        # retain the exact context keyed by the result's finding_ref so a caller can re-verify the
        # signed certificate OFFLINE (verify_certificate needs the context, the cert stores only its digest).
        contexts[res.finding_ref] = oracle_context
        (facts if res.is_fact else leads).append(res)

    detail = (f"{spec.name} ran via {outcome.backend}; proposed {len(proposed)} service(s), "
              f"oracle-confirmed {len(facts)} FACT(s), {len(leads)} lead(s)")
    return RunnerResult("ran", detail, spec.name, target, outcome, facts, leads, proposed, contexts)
