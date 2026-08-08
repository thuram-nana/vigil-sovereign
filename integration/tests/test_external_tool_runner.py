"""TRUTHENOVATION R4 — a REAL external tool, run through the gated offense topology, adjudicated by the
deterministic oracle into a signed FACT (never a raw tool dump).

The headline proof (``test_loopback_nmap_...``) is genuinely live: it stands up a real loopback TCP
listener, runs the REAL host ``nmap`` against it through the runner (scope-gated to the owner's loopback
target), and the tool's parsed "open" is re-proven by an INDEPENDENT gated handshake whose retained
evidence the ``service_reachability_oracle`` fires on — minting a proof-carrying certificate that
survives CRUCIBLE's own ``verify_certificate`` end-to-end. The scope gate refuses an out-of-scope /
metadata target BEFORE any traffic (a spy backend proves the tool never launched).

MUST run in its OWN offense process (it loads ``framework.*``): sigil.governor.assert_no_offense refuses
to co-load framework with a SIGIL module. CI runs it in the offense-process group (see ci.yml).

Residual (honest, docs/DEFERRED-INFRA.md R4): the LLM-red-team tools (garak / PyRIT / promptfoo) are
ABSENT here, so their live-fire is DEFERRED — this file mints NO garak/PyRIT FACT. The
DockerTopologyBackend's argv construction + availability reporting are unit-tested; its live container
run is gated on docker + the sandbox network + a tool image, and skipped when absent.
"""

from __future__ import annotations

import shutil
import socket
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")

from vigil_core import (  # noqa: E402
    AuthorizerKey,
    TrustRoot,
    generate_keypair,
)
from vigil_gateway.scope_source import StaticScopeSource  # noqa: E402
from vigil_integration.live.external_tool import (  # noqa: E402
    BackendUnavailable,
    DockerTopologyBackend,
    LocalSubprocessBackend,
    ProposedService,
    RunnerResult,
    ScopeGate,
    ToolOutcome,
    ToolSpec,
    nmap_service_scan,
    run_external_tool,
)

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=SIGNER.public_key_b64)])


# --- shared fixtures: isolate charter/killswitch paths and grant the active-recon entitlement --------
@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-08-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


# ===================================================================================================
# 1. THE HEADLINE LIVE PROOF — loopback nmap through the runner → a signed oracle-confirmed FACT.
# ===================================================================================================
@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed (present-tool path)")
def test_loopback_nmap_through_the_gate_mints_an_oracle_confirmed_fact(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2.evidence.certify import verify_certificate

    _charter(tmp_path, "127.0.0.1")  # the owner scopes their own loopback target
    # a real listening socket on an ephemeral loopback port — a genuine 3-way handshake, no mocks.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    # -p <the one open port>: keeps the scan a fast, single-port connect (still a REAL nmap run).
    spec = nmap_service_scan(ports=str(port))
    try:
        res = run_external_tool(
            spec, "127.0.0.1",
            scope_gate=gate, backend=LocalSubprocessBackend(),
            engagement_slug="alpha", signers=SIGNERS, timeout=60.0)
    finally:
        srv.close()

    assert res.status == "ran"
    # nmap actually proposed the open port from its OWN output (not a mock):
    assert any(p.port == port for p in res.proposed), f"nmap did not report {port} open: {res.outcome}"
    # the oracle CONFIRMED it via an independent gated handshake → exactly one signed FACT:
    assert len(res.facts) == 1, f"expected 1 oracle-confirmed FACT, got facts={res.facts} leads={res.leads}"
    fact = res.facts[0]
    assert fact.is_fact and fact.confirmed_by == "service_reachability"
    # THE contract: the minted cert survives CRUCIBLE's own layered verifier — authentic + bound +
    # REPRODUCED. The retained handshake (res.contexts) re-verifies offline with no network.
    oracle_context = res.contexts[fact.finding_ref]
    ver = verify_certificate(fact.signed, oracle_context=oracle_context, trust_root=TRUST)
    assert ver.ok is True, f"cert must verify end-to-end, got: {ver}"


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed (present-tool path)")
def test_a_closed_loopback_port_yields_no_fact(tmp_path: Path) -> None:
    """A port nmap reports CLOSED (or that nmap never proposes) must not mint a FACT — the oracle only
    fires on a reproduced connect. We scan a port with NOTHING listening: no proposal, no fact."""
    _charter(tmp_path, "127.0.0.1")
    # find a definitely-closed ephemeral port: bind, read the number, close it.
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()

    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    res = run_external_tool(
        nmap_service_scan(ports=str(closed_port)), "127.0.0.1",
        scope_gate=gate, backend=LocalSubprocessBackend(),
        engagement_slug="alpha", signers=SIGNERS, timeout=60.0)
    assert res.status == "ran"
    assert res.facts == []  # nothing was reproduced → no FACT (honest negative)


# ===================================================================================================
# 2. THE SCOPE GATE — an out-of-scope / metadata target is refused BEFORE any traffic.
# ===================================================================================================
class _SpyBackend:
    """Records whether run() was ever called — proves the scope gate blocks BEFORE traffic."""
    name = "spy"

    def __init__(self) -> None:
        self.runs: list = []

    def available(self) -> tuple[bool, str]:
        return True, "spy"

    def run(self, tool_argv, *, timeout):  # pragma: no cover - must never be reached in refusal tests
        self.runs.append(list(tool_argv))
        return ToolOutcome(list(tool_argv), 0, "", "", self.name)


def test_out_of_scope_target_is_refused_before_any_traffic(tmp_path: Path) -> None:
    _charter(tmp_path, "127.0.0.1")
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    spy = _SpyBackend()
    res = run_external_tool(
        nmap_service_scan(ports="80"), "scanme.example.org",
        scope_gate=gate, backend=spy, engagement_slug="alpha", signers=SIGNERS)
    assert res.refused and "not in the charter scope" in res.reason
    assert spy.runs == []          # NO traffic — the tool was never launched
    assert res.facts == [] and res.outcome is None


def test_metadata_address_is_refused_even_if_a_charter_lists_it(tmp_path: Path) -> None:
    # 169.254.169.254 (cloud IMDS) is hard-denied by the gateway floor — NOT liftable by scope/opt-in.
    _charter(tmp_path, "169.254.169.254")
    gate = ScopeGate(scope=StaticScopeSource(["169.254.169.254"]), loopback_allowed_if_scoped=True)
    spy = _SpyBackend()
    res = run_external_tool(
        nmap_service_scan(ports="80"), "169.254.169.254",
        scope_gate=gate, backend=spy, engagement_slug="alpha", signers=SIGNERS)
    assert res.refused and "always-denied" in res.reason
    assert spy.runs == []


def test_loopback_without_owner_opt_in_is_refused(tmp_path: Path) -> None:
    # loopback is hard-denied by default; only the owner's explicit opt-in lifts it.
    _charter(tmp_path, "127.0.0.1")
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=False)
    spy = _SpyBackend()
    res = run_external_tool(
        nmap_service_scan(ports="80"), "127.0.0.1",
        scope_gate=gate, backend=spy, engagement_slug="alpha", signers=SIGNERS)
    assert res.refused and "loopback" in res.reason
    assert spy.runs == []


def _fake_resolver(mapping: dict) -> "Callable":
    """A getaddrinfo-shaped resolver over a fixed host→IP map; unknown hosts fail (authorise nothing)."""
    def _r(host, *_a, **_k):
        ip = mapping.get(host)
        if ip is None:
            raise socket.gaierror(f"no fake record for {host!r}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]
    return _r


def test_wildcard_scope_does_not_self_authorize_a_private_ip() -> None:
    # REGRESSION (red-pen R4-MEDIUM): a broad *.example.com scope must NOT implicitly authorise
    # reaching internal RFC1918 infra. The gate's allow-set is ONLY the charter-authorized IPs —
    # it does not self-add the target's own resolved IP — so a wildcard subdomain that resolves
    # (via split-horizon / attacker-controlled DNS) to 10.x is refused, matching the gateway proxy.
    gate = ScopeGate(
        scope=StaticScopeSource(["*.example.com"]), loopback_allowed_if_scoped=False,
        resolver=_fake_resolver({"internal.example.com": "10.0.0.5"}))
    allowed, reason = gate.authorize("internal.example.com")
    assert allowed is False
    assert "10.0.0.5" in reason and "egress denied" in reason


def test_exact_hostname_scope_still_authorizes_its_resolved_public_ip() -> None:
    # POSITIVE CONTROL: dropping the self-add must not break the legitimate exact-hostname path —
    # the scope entry resolves into the charter-authorized allow-set, so its public IP is permitted.
    gate = ScopeGate(
        scope=StaticScopeSource(["host.example.com"]), loopback_allowed_if_scoped=False,
        resolver=_fake_resolver({"host.example.com": "93.184.216.34"}))
    allowed, reason = gate.authorize("host.example.com")
    assert allowed is True
    assert "93.184.216.34" in reason


# ===================================================================================================
# 3. THE TOOL-AGNOSTIC PARSE + ADJUDICATION over a MOCK backend (no nmap needed — shape-only CI).
# ===================================================================================================
def _grepable(host: str, port: int) -> str:
    return (f"# Nmap scan\nHost: {host} ()\tStatus: Up\n"
            f"Host: {host} ()\tPorts: {port}/open/tcp/////\n# Nmap done\n")


class _CannedNmapBackend:
    """A backend that returns a fixed grepable nmap output — exercises parse → oracle → FACT with no
    real nmap, so the SHAPE is verified in CI even where the present tool is unavailable."""
    name = "canned"

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def available(self) -> tuple[bool, str]:
        return True, "canned"

    def run(self, tool_argv, *, timeout) -> ToolOutcome:
        return ToolOutcome(list(tool_argv), 0, self._stdout, "", self.name)


def test_canned_tool_output_is_adjudicated_by_the_oracle_via_a_real_handshake(tmp_path: Path) -> None:
    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    backend = _CannedNmapBackend(_grepable("127.0.0.1", port))
    try:
        res = run_external_tool(
            nmap_service_scan(ports=str(port)), "127.0.0.1",
            scope_gate=gate, backend=backend, engagement_slug="alpha", signers=SIGNERS)
    finally:
        srv.close()
    assert res.status == "ran" and len(res.facts) == 1 and res.facts[0].is_fact


def test_a_proposed_port_that_does_not_reproduce_stays_a_lead_not_a_fact(tmp_path: Path) -> None:
    # the tool PROPOSES an open port, but NOTHING is listening → the gated handshake refuses → the
    # oracle does not fire → it is a labelled lead, never a signed fact (the anti-hallucination core).
    _charter(tmp_path, "127.0.0.1")
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    backend = _CannedNmapBackend(_grepable("127.0.0.1", closed_port))  # lies that it is open
    res = run_external_tool(
        nmap_service_scan(ports=str(closed_port)), "127.0.0.1",
        scope_gate=gate, backend=backend, engagement_slug="alpha", signers=SIGNERS)
    assert res.status == "ran" and res.facts == [] and len(res.leads) == 1
    assert not res.leads[0].is_fact


def test_nmap_spec_parses_grepable_open_ports() -> None:
    spec = nmap_service_scan()
    outcome = ToolOutcome(["nmap"], 0,
                          "Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 443/open/tcp//https///\n"
                          "Host: 10.0.0.5 ()\tPorts: 80/closed/tcp/////\n", "", "x")
    props = spec.propose(outcome, "10.0.0.5")
    got = {(p.port, p.protocol) for p in props}
    assert got == {(22, "tcp"), (443, "tcp")}  # only OPEN rows; 80/closed excluded


def test_nmap_argv_carries_only_the_authorized_target() -> None:
    argv = nmap_service_scan(ports="1-100").build_argv("127.0.0.1")
    assert argv[0] == "nmap" and argv[-1] == "127.0.0.1" and "-Pn" in argv and "-oG" in argv


# ===================================================================================================
# 4. THE DOCKER TOPOLOGY BACKEND — argv construction + honest availability (unit; live run gated).
# ===================================================================================================
def test_docker_backend_builds_a_pinned_internal_network_argv() -> None:
    b = DockerTopologyBackend(image="vigil-nmap:latest", docker_bin="/usr/bin/docker")
    argv = b.build_argv(["nmap", "-Pn", "10.0.0.5"])
    assert argv[:3] == ["/usr/bin/docker", "run", "--rm"]
    assert "--network" in argv and argv[argv.index("--network") + 1] == "vigil_sandbox"
    assert "--cap-drop" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges:true" in argv
    # the image precedes the tool argv; the tool argv is preserved verbatim after it.
    i = argv.index("vigil-nmap:latest")
    assert argv[i + 1:] == ["nmap", "-Pn", "10.0.0.5"]


def test_docker_backend_reports_unavailable_when_docker_is_absent() -> None:
    b = DockerTopologyBackend(image="vigil-nmap:latest", docker_bin="/nonexistent/docker")
    ok, why = b.available()
    assert ok is False and "unreachable" in why.lower()


def test_runner_raises_when_the_gated_backend_is_unavailable(tmp_path: Path) -> None:
    # an IN-SCOPE target but a backend that cannot run → BackendUnavailable, never a silent un-gated run.
    _charter(tmp_path, "127.0.0.1")
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    b = DockerTopologyBackend(image="vigil-nmap:latest", docker_bin="/nonexistent/docker")
    with pytest.raises(BackendUnavailable):
        run_external_tool(nmap_service_scan(ports="80"), "127.0.0.1",
                          scope_gate=gate, backend=b, engagement_slug="alpha", signers=SIGNERS)


# --- the DEFERRED live-fire frontier, marked explicitly (never a fabricated pass) -------------------
def test_docker_container_topology_live_run_is_deferred_when_absent() -> None:
    """The docker-container topology + LLM-red-team tools (garak/PyRIT/promptfoo) live-fire is the R4
    residual. This asserts the honest DEFERRAL: without the built sandbox network + a tool image, the
    backend is unavailable and the runner refuses to run un-gated — it does NOT fabricate a FACT."""
    b = DockerTopologyBackend(image="vigil-garak:latest")  # an image that does not exist here
    ok, why = b.available()
    if ok:  # pragma: no cover - only if an operator has actually stood the topology up
        pytest.skip("docker topology + image present — live container path is exercised out-of-band")
    assert ok is False and why  # a precise reason (no daemon / no network / no image), never a fake pass


# ===================================================================================================
# 4. BRAIN-SLOT SLICE 4 — a SECOND runner-owned oracle re-drive: TLS posture (weak protocol/cipher +
#    a broken-hash cert). Proves the runner generalizes past nmap/reachability while keeping the
#    HIGH-3 discipline: the tool only PROPOSES the endpoint; the runner negotiates its OWN gated
#    handshake and the deterministic oracle judges THAT.
# ===================================================================================================
import ssl
import threading


class _FakeTLSBackend:
    """A backend that returns a canned sslscan-shaped 'reached a TLS service' output (so the ToolSpec
    proposes the endpoint) WITHOUT requiring sslscan installed — the FACT then comes entirely from the
    runner's OWN gated TLS handshake against the real loopback server."""
    name = "fake-tls"

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        return ToolOutcome(argv=list(argv), exit_code=0, stdout="Connected to 127.0.0.1\nAccepted  TLSv1.2\n",
                           stderr="", timed_out=False, truncated=False, backend=self.name)


def _weakcrypto_selfsigned_cert():
    """A self-signed X.509 cert with a 2048-bit RSA key signed with the BROKEN SHA-1 hash + its key (PEM).
    weak_crypto_artifact fires on the broken sig hash. We use SHA-1 (not a short key) so a DEFAULT TLS
    client can complete the handshake: on modern OpenSSL (CI security level 2) a <2048-bit key is rejected
    at handshake (EE_KEY_TOO_SMALL) before the cert can be retrieved, whereas a 2048-bit key handshakes and
    — under the capture's CERT_NONE — its SHA-1 signature is not verified but IS retrieved for the oracle to
    judge. Generated via the ``openssl`` CLI because modern ``cryptography`` refuses to SIGN with SHA-1;
    skips (never fakes) if openssl is absent or refuses SHA-1."""
    import subprocess
    import tempfile

    d = tempfile.mkdtemp()
    cert_p, key_p = Path(d) / "c.pem", Path(d) / "k.pem"
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-sha1", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key_p), "-out", str(cert_p), "-days", "3650",
         "-subj", "/CN=vigil-weakhash-test.local"],
        capture_output=True, text=True)
    if proc.returncode != 0 or not cert_p.is_file():
        pytest.skip(f"openssl could not mint a SHA-1 cert here (rc={proc.returncode}): {proc.stderr[:200]}")
    return cert_p.read_bytes(), key_p.read_bytes()


class _TLSServer:
    """A minimal threaded loopback TLS server that completes handshakes presenting the given cert."""
    def __init__(self, cert_pem: bytes, key_pem: bytes):
        import tempfile
        self._d = tempfile.mkdtemp()
        self._cf = Path(self._d) / "c.pem"
        self._kf = Path(self._d) / "k.pem"
        self._cf.write_bytes(cert_pem)
        self._kf.write_bytes(key_pem)
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(self._cf), str(self._kf))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                raw, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(16)
            except (ssl.SSLError, OSError):
                pass

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


def test_tls_scan_toolspec_argv_and_propose():
    from vigil_integration.live.external_tool import tls_scan

    spec = tls_scan(port=8443)
    assert spec.name == "tls_scan"
    assert spec.build_argv("example.test") == ["sslscan", "--no-colour", "example.test:8443"]
    assert len(spec.redrives) == 2 and {r.bug_class for r in spec.redrives} == {"weak_tls", "weak_crypto_artifact"}
    # proposes ONLY when the tool actually reached a TLS service
    reached = ToolOutcome(argv=[], exit_code=0, stdout="Connected to 1.2.3.4\n", stderr="",
                          timed_out=False, truncated=False, backend="x")
    missed = ToolOutcome(argv=[], exit_code=1, stdout="Connection refused\n", stderr="",
                         timed_out=False, truncated=False, backend="x")
    assert [p.port for p in spec.propose(reached, "1.2.3.4")] == [8443]
    assert spec.propose(missed, "1.2.3.4") == []


def test_nmap_spec_uses_the_legacy_reachability_redrive():
    """Backward-compat: nmap carries NO redrives on the spec, so the runner uses the legacy reachability
    re-drive (service_reachable) exactly as before — the change is additive."""
    assert nmap_service_scan(ports="80").redrives == ()


def test_loopback_tls_broken_hash_cert_mints_a_weak_crypto_fact(tmp_path: Path, monkeypatch):
    """THE slice-4 live proof: a real loopback TLS server presenting a SHA-1-signed cert. The runner
    negotiates its OWN gated handshake, retains the presented cert, and the weak_crypto_artifact oracle
    fires → a signed FACT that survives CRUCIBLE's verifier end-to-end. No sslscan binary needed — the
    tool is only the proposer; the FACT is the runner's independent re-drive."""
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.external_tool import tls_scan

    _charter(tmp_path, "127.0.0.1")
    cert_pem, key_pem = _weakcrypto_selfsigned_cert()
    srv = _TLSServer(cert_pem, key_pem)
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    try:
        res = run_external_tool(
            tls_scan(port=srv.port), "127.0.0.1",
            scope_gate=gate, backend=_FakeTLSBackend(),
            engagement_slug="alpha", signers=SIGNERS, timeout=30.0)
    finally:
        srv.close()

    assert res.status == "ran"
    assert any(p.port == srv.port for p in res.proposed)
    # the weak_crypto_artifact oracle CONFIRMED the SHA-1 cert the runner itself retrieved → a signed FACT
    crypto_facts = [f for f in res.facts if f.confirmed_by == "tls_weakness"]
    assert crypto_facts, f"expected a TLS_WEAKNESS FACT over the SHA-1 cert; facts={res.facts} leads={res.leads}"
    fact = crypto_facts[0]
    oracle_context = res.contexts[fact.finding_ref]
    ver = verify_certificate(fact.signed, oracle_context=oracle_context, trust_root=TRUST)
    assert ver.ok is True, f"the TLS FACT must verify end-to-end offline, got: {ver}"


def test_tls_no_cert_yields_no_crypto_fact():
    """If the runner's handshake retains no cert (a re-drive returning None), no weak_crypto FACT is
    minted — the runner never fabricates one from the tool's row (the None-skip path)."""
    from vigil_integration.live.external_tool import _weak_crypto_context, _weak_tls_context

    assert _weak_crypto_context({"connected": True}) is None      # no cert_der_b64 -> skip
    assert _weak_tls_context({"connected": False}) is None        # failed handshake -> skip
