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
    masscan_service_scan,
    naabu_service_scan,
    nmap_service_scan,
    run_external_tool,
    rustscan_service_scan,
)
from vigil_integration.oracle_adapter import Outcome  # noqa: E402

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
    # a DIGEST-PINNED image so the pin check passes and we reach the docker-absent path (the test's intent)
    b = DockerTopologyBackend(image="vigil-nmap@sha256:" + "c" * 64, docker_bin="/nonexistent/docker")
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
    # a DIGEST-PINNED garak image (absent locally) so available() reaches the no-daemon/no-network/no-image
    # path this test is about — not the pin gate.
    b = DockerTopologyBackend(image="vigil-garak@sha256:" + "d" * 64)
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


def _stronghash_selfsigned_cert():
    """A self-signed X.509 cert with a 2048-bit RSA key signed with the STRONG SHA-256 hash + its key (PEM).
    The weak_crypto_artifact oracle conclusively does NOT fire on it — the runner presents this cert so the
    re-drive reaches the CONCLUSIVE-non-fire branch (not the None-skip / not the FACT branch). Generated via
    the openssl CLI to mirror the SHA-1 helper; skips if openssl is absent."""
    import subprocess
    import tempfile

    d = tempfile.mkdtemp()
    cert_p, key_p = Path(d) / "c.pem", Path(d) / "k.pem"
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-sha256", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key_p), "-out", str(cert_p), "-days", "3650",
         "-subj", "/CN=vigil-stronghash-test.local"],
        capture_output=True, text=True)
    if proc.returncode != 0 or not cert_p.is_file():
        pytest.skip(f"openssl could not mint a SHA-256 cert here (rc={proc.returncode}): {proc.stderr[:200]}")
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


def test_loopback_tls_strong_hash_cert_is_inconclusive_not_clean(tmp_path: Path):
    """SLICE W16-13 end-to-end coverage of the MIGRATED runner over a real loopback TLS server presenting a
    STRONG (SHA-256) leaf cert. The runner negotiates its own gated handshake, retains the cert, and the
    weak_crypto_artifact oracle does NOT fire. The outcome now flows through the ADMISSION choke
    (``_oracle_signal`` -> ``verdict.admit`` -> ``certify_admitted``) under the registered
    ``weak_crypto.cert_signature_algorithm`` branch (clean_capable:false — the re-drive captures only the
    LEAF cert, so a non-firing cannot certify the whole chain free of weak crypto): the result is
    INCONCLUSIVE, never a CLEAN and never a fabricated FACT. This exercises the new mint path live; the
    ROUTING itself (no direct ``confirm_and_certify``) is discriminated by the claim-discipline frontier
    test. Because the weak_crypto oracle is non-conclusive on a strong leaf, the clean_capable:false
    declaration is the STANDING guard that keeps this INCONCLUSIVE rather than a false CLEAN the moment any
    conclusive-clean channel is added to this branch."""
    from vigil_integration.live.external_tool import tls_scan

    _charter(tmp_path, "127.0.0.1")
    cert_pem, key_pem = _stronghash_selfsigned_cert()
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
    wc = [o for o in res.outcomes if o["bug_class"] == "weak_crypto_artifact"]
    assert wc, f"expected a weak_crypto_artifact outcome over the presented cert; outcomes={res.outcomes}"
    # the whole point: a clean_incapable (leaf-only) branch must NOT leak a CLEAN on a conclusive non-fire
    assert all(o["outcome"] != Outcome.CLEAN.value for o in wc), (
        f"a clean_incapable branch (leaf-cert only) leaked a false CLEAN through the runner: {wc}")
    assert any(o["outcome"] == Outcome.INCONCLUSIVE.value for o in wc), (
        f"the conclusive non-fire must be INCONCLUSIVE, not CLEAN/other: {wc}")
    # and a strong-hash cert mints no weak_crypto FACT
    assert not any(getattr(f, "confirmed_by", "") == "tls_weakness" for f in res.facts), (
        "a strong-hash cert must not mint a weak-crypto FACT")


def test_weak_crypto_branch_keeps_a_conclusive_nonfire_inconclusive_not_clean():
    """LOW (W16-13): the STANDING guard the live TLS test relies on, asserted directly at the admission
    seam so it discriminates independently of the oracle's conclusiveness on a strong leaf. Even a
    CONCLUSIVE non-fire (fired=False, conclusive=True) over the registered
    ``weak_crypto.cert_signature_algorithm`` branch must NOT admit a CLEAN — the branch is
    ``clean_capable:false`` (leaf-cert only), so it may not assert absence and stays INCONCLUSIVE. This is
    the assertion that would flip the moment anyone flags that branch clean-capable without capturing the
    full chain; the end-to-end runner test cannot catch that because its oracle is non-conclusive."""
    from vigil_integration.live.verdict import admit, Verdict

    v = admit("weak_crypto.cert_signature_algorithm", fired=False, conclusive=True,
              observed={"gate_authorized": True})
    assert v.verdict is Verdict.INCONCLUSIVE, (
        f"a clean_incapable branch must not admit a CLEAN on a conclusive non-fire; got {v.verdict} "
        f"({v.reason})")
    # positive control: the SAME conclusive non-fire over a clean_capable branch DOES admit CLEAN, so the
    # INCONCLUSIVE above is the branch's declared incapability, not a blanket non-fire rule.
    clean = admit("open_redirect.location_header", fired=False, conclusive=True,
                  observed={"channel_established": True})
    assert clean.verdict is Verdict.CLEAN, (
        f"a clean_capable branch must admit CLEAN on a conclusive non-fire (control); got {clean.verdict} "
        f"({clean.reason})")


# ===================================================================================================
# 5. PHASE 0.5 — the tool-exec PRE-FLIGHT GATE (kill-switch + charter-context + entitlement), so the
#    TOOL SUBPROCESS itself is gated (not only the later oracle re-drive). Fail-closed BEFORE any traffic.
# ===================================================================================================
def test_tripped_killswitch_refuses_the_tool_exec_before_traffic(tmp_path: Path) -> None:
    from framework.v2.authority import KillSwitch
    _charter(tmp_path, "127.0.0.1")
    KillSwitch("alpha").trip("red-pen: halt")   # writes the monkeypatched tmp halt file
    spy = _SpyBackend()
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    res = run_external_tool(nmap_service_scan(ports="80"), "127.0.0.1",
                            scope_gate=gate, backend=spy, engagement_slug="alpha", signers=SIGNERS)
    assert res.refused and "kill-switch tripped" in res.reason
    assert spy.runs == []          # the tool NEVER launched
    assert res.facts == []


def test_empty_engagement_slug_refuses_the_tool_exec(tmp_path: Path) -> None:
    _charter(tmp_path, "127.0.0.1")
    spy = _SpyBackend()
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    res = run_external_tool(nmap_service_scan(ports="80"), "127.0.0.1",
                            scope_gate=gate, backend=spy, engagement_slug="", signers=SIGNERS)
    assert res.refused and "engagement slug" in res.reason and spy.runs == []


def test_unentitled_run_refuses_the_tool_exec(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _charter(tmp_path, "127.0.0.1")
    from framework.v2 import entitlement
    def _deny(cap):
        raise PermissionError("ACTIVE_RECON not granted")
    monkeypatch.setattr(entitlement, "require_capability", _deny)   # overrides the autouse no-op
    spy = _SpyBackend()
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    res = run_external_tool(nmap_service_scan(ports="80"), "127.0.0.1",
                            scope_gate=gate, backend=spy, engagement_slug="alpha", signers=SIGNERS)
    assert res.refused and "not entitled" in res.reason and spy.runs == []


def test_killswitch_check_ERROR_fails_closed_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A kill-switch CHECK that raises (not a clean trip) must REFUSE fail-closed — the tool never launches.
    Pins the except branch the red-pen flagged as correct-but-untested."""
    import framework.v2.authority as _authority
    _charter(tmp_path, "127.0.0.1")

    class _Boom:
        def __init__(self, slug): ...
        def is_tripped(self):
            raise OSError("stat blew up")
    monkeypatch.setattr(_authority, "KillSwitch", _Boom)
    spy = _SpyBackend()
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    res = run_external_tool(nmap_service_scan(ports="80"), "127.0.0.1",
                            scope_gate=gate, backend=spy, engagement_slug="alpha", signers=SIGNERS)
    assert res.refused and "fail-closed" in res.reason and spy.runs == []


def test_run_attaches_a_canonical_observation(tmp_path: Path) -> None:
    """PHASE 0.3 / crit-4: EVERY execution path — refused, ran, errored — attaches the ONE canonical
    Observation carrying the full field set (tool identity + trusted binary digest, version, target, args
    digest, backend, outcome class, raw-output digest, artifact refs, proposals, truncation, error/refusal
    reason). No path may attach a bare list or omit the record."""
    _charter(tmp_path, "127.0.0.1")
    gate_in = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    gate_out = ScopeGate(scope=StaticScopeSource(["10.99.99.99"]), loopback_allowed_if_scoped=True)

    # refused (out of scope) → a 'refused' Observation, tool never ran, WITH the refusal reason recorded
    ref = run_external_tool(nmap_service_scan(ports="80"), "127.0.0.1", scope_gate=gate_out,
                            backend=_SpyBackend(), engagement_slug="alpha", signers=SIGNERS)
    assert ref.refused and ref.observation is not None and ref.observation.outcome_class == "refused"
    assert ref.observation.raw_output_sha256 == "" and ref.observation.proposals == ()
    assert ref.observation.binary_sha256 == "" and ref.observation.args_sha256 == ""
    assert ref.observation.error_reason and ref.observation.error_reason == ref.reason  # WHY it was refused

    # ran → a 'ran' Observation binding the raw output, the exact argv, and the backend-attested binary bytes
    _BINDIGEST = "sha256:" + "b" * 64
    class _Reached:
        name = "b"
        def available(self):  # noqa: E704
            return True, ""
        def run(self, argv, *, timeout=0):
            return ToolOutcome(list(argv), 0, "Host: 127.0.0.1 ()\tPorts: 80/open/tcp//x///\n", "",
                               self.name, binary_sha256=_BINDIGEST)
    ran = run_external_tool(nmap_service_scan(ports="80"), "127.0.0.1", scope_gate=gate_in,
                            backend=_Reached(), engagement_slug="alpha", signers=SIGNERS)
    assert ran.observation is not None and ran.observation.outcome_class == "ran"
    assert ran.observation.tool == "nmap" and ran.observation.raw_output_sha256.startswith("sha256:")
    assert ("127.0.0.1", 80, "tcp") in ran.observation.proposals
    assert ran.observation.binary_sha256 == _BINDIGEST          # backend-attested, threaded to the record
    assert ran.observation.args_sha256.startswith("sha256:")    # the exact argv is bound
    assert ran.observation.backend == "b" and ran.observation.error_reason == ""  # a clean run has no error

    # errored (tool timed out) → an 'errored' Observation with the error recorded; still what-ran is bound
    class _TimedOut:
        name = "t"
        def available(self):  # noqa: E704
            return True, ""
        def run(self, argv, *, timeout=0):
            return ToolOutcome(list(argv), None, "", "", self.name, timed_out=True)
    err = run_external_tool(nmap_service_scan(ports="80"), "127.0.0.1", scope_gate=gate_in,
                            backend=_TimedOut(), engagement_slug="alpha", signers=SIGNERS)
    assert err.observation is not None and err.observation.outcome_class == "errored"
    assert err.observation.error_reason and err.tool_errored
    assert err.observation.args_sha256.startswith("sha256:")   # what ran is still bound on the error path


def test_local_backend_attests_a_real_host_binary_digest(tmp_path: Path) -> None:
    """crit-4 trusted binary digest: the LocalSubprocessBackend hashes the RESOLVED host executable that
    runs, and that digest reaches the Observation (proof the binary provenance is real, not a placeholder).
    Uses ``true`` (POSIX) via a bespoke recon ToolSpec so no target traffic is required."""
    import hashlib as _hashlib

    true_bin = shutil.which("true")
    if not true_bin:
        pytest.skip("no 'true' binary on PATH")
    with open(true_bin, "rb") as fh:
        want = "sha256:" + _hashlib.sha256(fh.read()).hexdigest()

    _charter(tmp_path, "127.0.0.1")
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    spec = ToolSpec("true", build_argv=lambda _t: ["true"], propose=lambda _o, _t: [], danger="recon")
    res = run_external_tool(spec, "127.0.0.1", scope_gate=gate,
                            backend=LocalSubprocessBackend(), engagement_slug="alpha", signers=SIGNERS)
    assert res.status == "ran" and res.observation is not None
    assert res.observation.binary_sha256 == want   # the digest of the exact host bytes that ran


# ===================================================================================================
# 6. PHASE 0.4 — runner isolation + resource limits (crit 1/11): least-privilege docker argv, a
#    fail-closed digest pin, and the loopback-only guard on the unisolated host backend.
# ===================================================================================================
def test_docker_argv_has_resource_limits_and_least_privilege() -> None:
    argv = DockerTopologyBackend(image="x@sha256:" + "a" * 64, docker_bin="/usr/bin/docker").build_argv(["nmap"])
    for flag, val in (("--memory", "1g"), ("--memory-swap", "1g"), ("--cpus", "1.0"),
                      ("--pids-limit", "256"), ("--user", "65534:65534")):
        assert flag in argv and argv[argv.index(flag) + 1] == val, f"{flag} missing/wrong"
    assert "--read-only" in argv
    assert "--tmpfs" in argv and argv[argv.index("--tmpfs") + 1].startswith("/tmp:rw,size=")
    assert "--cap-drop" in argv and "no-new-privileges:true" in argv


def test_docker_refuses_an_unpinned_image_by_default() -> None:
    # fail-closed: a mutable :latest tag is refused BEFORE any docker call
    ok, why = DockerTopologyBackend(image="vigil-nmap:latest", docker_bin="/nonexistent/docker").available()
    assert ok is False and "not digest-pinned" in why
    # a digest-pinned image passes the pin check (then fails only because docker is absent — a DIFFERENT,
    # non-pin reason: the pin gate no longer applies)
    ok2, why2 = DockerTopologyBackend(image="x@sha256:" + "b" * 64, docker_bin="/nonexistent/docker").available()
    assert ok2 is False and "not digest-pinned" not in why2
    # explicit opt-out lets an unpinned image past the pin check (still fails on absent docker)
    ok3, why3 = DockerTopologyBackend(image="dev:latest", docker_bin="/nonexistent/docker",
                                      require_digest_pin=False).available()
    assert ok3 is False and "not digest-pinned" not in why3
    # a MALFORMED "digest" is NOT pinned (non-hex / uppercase / wrong length / leading-junk@) — fail-closed
    for bad in ("x@sha256:" + "g" * 64, "x@sha256:" + "A" * 64, "x@sha256:" + "a" * 63,
                "x@sha256:" + "a" * 65, "x@sha256:" + "a" * 63 + " ", "x:latest",
                "a@sha256:" + "a" * 64 + "@sha256:zz"):
        assert DockerTopologyBackend._is_digest_pinned(bad) is False, f"wrongly pinned: {bad!r}"
    # a genuine lowercase-hex digest IS pinned (incl. a leading junk@ segment, via rpartition on last @)
    assert DockerTopologyBackend._is_digest_pinned("x@sha256:" + "0a" * 32) is True
    assert DockerTopologyBackend._is_digest_pinned("junk@x@sha256:" + "0a" * 32) is True


def test_local_backend_refused_against_a_non_loopback_target(tmp_path: Path) -> None:
    """The unisolated host backend must NOT run against a non-loopback target — refused before any run."""
    _charter(tmp_path, "10.1.2.3")
    gate = ScopeGate(scope=StaticScopeSource(["10.1.2.3"]), loopback_allowed_if_scoped=True)
    res = run_external_tool(nmap_service_scan(ports="80"), "10.1.2.3", scope_gate=gate,
                            backend=LocalSubprocessBackend(), engagement_slug="alpha", signers=SIGNERS)
    assert res.refused and "loopback-only" in res.reason
    # opting out (loopback_only=False) removes THAT refusal (it then proceeds past the guard)
    res2 = run_external_tool(nmap_service_scan(ports="80"), "10.1.2.3", scope_gate=gate,
                             backend=LocalSubprocessBackend(loopback_only=False), engagement_slug="alpha",
                             signers=SIGNERS)
    assert "loopback-only" not in res2.reason


# ===================================================================================================
# 7. H5 — the SERVICE_REACHABILITY reuse ToolSpecs (masscan / rustscan / naabu). Each REUSES the exact
#    reachability re-drive nmap uses (redrives=() → the runner's own gated capture_handshake judged by the
#    service_reachability.tcp_handshake branch): the tool is only a PROPOSER, the FACT is VIGIL's handshake.
# ===================================================================================================
def _h5_canned_stdout(tool: str, port: int, host: str = "127.0.0.1") -> str:
    """The real-format stdout each tool emits for one open port — the parser input the runner sees."""
    if tool == "masscan":
        return f"Discovered open port {port}/tcp on {host}\n"
    if tool == "rustscan":
        return f"{host} -> [{port}]\n"
    if tool == "naabu":
        return f"{host}:{port}\n"
    raise AssertionError(tool)


_H5_SPECS = {
    "masscan": masscan_service_scan,
    "rustscan": rustscan_service_scan,
    "naabu": naabu_service_scan,
}


def test_h5_specs_build_server_side_argv_carrying_only_the_authorized_target() -> None:
    # every flag is server-side; the target appears exactly once and never as a bare positional flag.
    m = masscan_service_scan(ports="1-100", rate=500).build_argv("10.0.0.5")
    assert m == ["masscan", "-p", "1-100", "--rate", "500", "--wait", "0", "10.0.0.5"]
    # a RANGE goes to rustscan's -r; a comma LIST goes to -p (never a mix); target is a flag VALUE (-a)
    assert rustscan_service_scan(ports="1-1024").build_argv("10.0.0.5") == \
        ["rustscan", "--no-config", "-g", "-a", "10.0.0.5", "-r", "1-1024"]
    assert rustscan_service_scan(ports="80,443").build_argv("h")[-2:] == ["-p", "80,443"]
    # naabu takes the target as the -host VALUE and -silent so only results print
    assert naabu_service_scan(ports="80,443").build_argv("10.0.0.5") == \
        ["naabu", "-silent", "-host", "10.0.0.5", "-p", "80,443"]


def test_h5_specs_parse_open_ports_and_pin_the_host_to_the_authorized_target() -> None:
    # SCOPE SAFETY: the parser pins host to the AUTHORIZED target, never a host the tool printed. Feed each
    # parser output that names a DIFFERENT host — the proposal host must still be the authorized target.
    # SOUNDNESS (UDP): the ``53/udp`` row is DROPPED — the runner re-proves each proposed port with a TCP
    # ``capture_handshake``, so proposing a udp port would drive a TCP connect the oracle would mislabel as
    # udp reachability. A udp-open row must never mint a TCP-handshake FACT (see verify.reachability).
    mo = ToolOutcome(["masscan"], 0,
                     "Discovered open port 22/tcp on 9.9.9.9\nDiscovered open port 443/tcp on 9.9.9.9\n"
                     "Discovered open port 53/udp on 9.9.9.9\nDiscovered open port 22/tcp on 9.9.9.9\n", "", "x")
    got = {(p.host, p.port, p.protocol) for p in masscan_service_scan().propose(mo, "target-host")}
    assert got == {("target-host", 22, "tcp"), ("target-host", 443, "tcp")}  # 53/udp dropped (soundness)
    ro = ToolOutcome(["rustscan"], 0, "9.9.9.9 -> [22,80, 443]\n", "", "x")
    assert {(p.host, p.port) for p in rustscan_service_scan().propose(ro, "target-host")} == \
        {("target-host", 22), ("target-host", 80), ("target-host", 443)}
    no = ToolOutcome(["naabu"], 0, "9.9.9.9:80\n9.9.9.9:443\n[2001:db8::1]:8080\n", "", "x")
    assert {(p.host, p.port) for p in naabu_service_scan().propose(no, "target-host")} == \
        {("target-host", 80), ("target-host", 443), ("target-host", 8080)}
    # a closed/other row proposes nothing
    assert masscan_service_scan().propose(ToolOutcome(["masscan"], 0, "no ports found\n", "", "x"), "t") == []


def test_udp_open_rows_are_dropped_by_the_masscan_and_nmap_parsers() -> None:
    """SOUNDNESS (Fix 0.2): a ``udp``-open row is never turned into a proposal — the runner's reachability
    re-drive is a TCP ``capture_handshake``, so proposing a udp port would drive a TCP connect the oracle
    would mislabel as udp reachability. Only the TCP rows survive; a UDP-ONLY output proposes nothing."""
    m_udp_only = ToolOutcome(["masscan"], 0,
                             "Discovered open port 53/udp on 9.9.9.9\nDiscovered open port 161/udp on 9.9.9.9\n",
                             "", "x")
    assert masscan_service_scan().propose(m_udp_only, "target-host") == [], "no TCP row ⇒ no proposal"
    m_mixed = ToolOutcome(["masscan"], 0,
                          "Discovered open port 80/tcp on 9.9.9.9\nDiscovered open port 53/udp on 9.9.9.9\n",
                          "", "x")
    assert {(p.port, p.protocol) for p in masscan_service_scan().propose(m_mixed, "t")} == {(80, "tcp")}
    # nmap grepable: the same drop, in nmap's own ``<port>/open/<proto>`` shape.
    n_mixed = ToolOutcome(["nmap"], 0,
                          "Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 53/open/udp//domain///\n", "", "x")
    assert {(p.port, p.protocol) for p in nmap_service_scan().propose(n_mixed, "t")} == {(22, "tcp")}


def test_a_udp_open_row_through_the_runner_yields_zero_facts(tmp_path: Path) -> None:
    """END-TO-END (Fix 0.2): masscan reports a REALLY-OPEN loopback port as ``udp`` open, and the listener
    SENDS A BANNER on accept. The counterfactual is therefore fully armed: had the udp row survived to a
    re-drive AND had capture_handshake not been TCP-gated, the runner's TCP connect would have read that
    banner and the oracle — whose ``protocol == "udp" and not banner`` guard is satisfied only WITHOUT a
    banner — would have fired at 0.97 and minted a (false) 'udp' reachability FACT. Both defences hold: the
    parser drops the udp row (zero proposals) so the connect is never even attempted ⇒ ZERO facts."""
    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    stop = threading.Event()

    def _serve_banner() -> None:
        # Accept any connections and immediately send an application banner, so a mislabelled TCP connect
        # WOULD read judgeable evidence (the faithful counterfactual). Never asserted on — purely the trap.
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.6 banner\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    server = threading.Thread(target=_serve_banner, daemon=True)
    server.start()
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    backend = _CannedNmapBackend(f"Discovered open port {port}/udp on 127.0.0.1\n")  # udp-labelled open row
    try:
        res = run_external_tool(
            masscan_service_scan(ports=str(port)), "127.0.0.1",
            scope_gate=gate, backend=backend, engagement_slug="alpha", signers=SIGNERS)
    finally:
        stop.set()
        server.join(timeout=2.0)
        srv.close()
    assert res.status == "ran"
    assert res.proposed == [], "the udp-open row must not become a proposal"
    assert res.facts == [] and res.leads == [], "a udp-open row must mint ZERO facts (and no lead)"


def test_h5_specs_carry_no_redrives_so_they_reuse_the_legacy_reachability_redrive() -> None:
    # The reuse property: no spec-carried re-drive ⇒ run_external_tool builds the service_reachable re-drive
    # from its own capture_handshake (SERVICE_REACHABILITY — exactly nmap's path). danger is "recon".
    for build in _H5_SPECS.values():
        spec = build(ports="80")
        assert spec.redrives == (), f"{spec.name} must reuse the legacy reachability re-drive, not carry its own"
        assert spec.danger == "recon"


def test_h5_specs_reject_an_invalid_ports_schema_fail_closed() -> None:
    for build in _H5_SPECS.values():
        for bad in ("1-2-3", "80;rm -rf", "$(id)", "-oX", "1-70000", "0", "", "80 443", "abc"):
            with pytest.raises(ValueError):
                build(ports=bad)
    # rustscan additionally refuses a range+list MIX in one flag (it cannot express it)
    with pytest.raises(ValueError):
        rustscan_service_scan(ports="1-100,443")
    # masscan additionally validates the rate (strict typed schema, no free-form string)
    with pytest.raises(ValueError):
        masscan_service_scan(rate=0)


@pytest.mark.parametrize("tool", ["masscan", "rustscan", "naabu"])
def test_h5_canned_output_mints_an_oracle_confirmed_reachability_fact(tool: str, tmp_path: Path) -> None:
    """Each reuse tool, driven through the REAL gated runner with a canned real-format proposal of a REALLY
    OPEN loopback port, mints exactly one signed FACT — because the runner re-proves the port with its OWN
    gated handshake (capture_handshake, SERVICE_REACHABILITY). The FACT re-verifies offline."""
    from framework.v2.evidence.certify import verify_certificate

    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    backend = _CannedNmapBackend(_h5_canned_stdout(tool, port))
    try:
        res = run_external_tool(
            _H5_SPECS[tool](ports=str(port)), "127.0.0.1",
            scope_gate=gate, backend=backend, engagement_slug="alpha", signers=SIGNERS)
    finally:
        srv.close()
    assert res.status == "ran", res.reason
    assert any(p.port == port for p in res.proposed), f"{tool} did not propose {port}: {res.proposed}"
    assert len(res.facts) == 1 and res.facts[0].is_fact, f"{tool}: expected 1 reachability FACT: {res.reason}"
    fact = res.facts[0]
    ver = verify_certificate(fact.signed, oracle_context=res.contexts[fact.finding_ref], trust_root=TRUST)
    assert ver.ok is True, f"{tool} reachability FACT must verify offline: {ver}"


@pytest.mark.parametrize("tool", ["masscan", "rustscan", "naabu"])
def test_h5_proposed_but_closed_port_stays_a_lead_never_a_fact(tool: str, tmp_path: Path) -> None:
    """NEGATIVE CONTROL: the tool PROPOSES an open port but NOTHING is listening → the runner's own gated
    handshake refuses → the oracle does not fire → a labelled LEAD, never a fabricated FACT (crit-6)."""
    _charter(tmp_path, "127.0.0.1")
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()  # now definitely closed
    gate = ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)
    backend = _CannedNmapBackend(_h5_canned_stdout(tool, closed_port))  # lies that it is open
    res = run_external_tool(
        _H5_SPECS[tool](ports=str(closed_port)), "127.0.0.1",
        scope_gate=gate, backend=backend, engagement_slug="alpha", signers=SIGNERS)
    assert res.status == "ran"
    assert any(p.port == closed_port for p in res.proposed), f"{tool} must have PROPOSED the closed port"
    assert res.facts == [] and len(res.leads) == 1 and not res.leads[0].is_fact, \
        f"{tool}: a non-reproducing proposal must stay a LEAD, got facts={res.facts}"


def test_h5_out_of_scope_target_is_refused_before_any_traffic(tmp_path: Path) -> None:
    # the H5 tools inherit the runner's scope gate: an out-of-scope target refuses before the tool launches.
    _charter(tmp_path, "127.0.0.1")
    gate_out = ScopeGate(scope=StaticScopeSource(["10.99.99.99"]), loopback_allowed_if_scoped=True)
    spy = _SpyBackend()
    res = run_external_tool(masscan_service_scan(ports="80"), "127.0.0.1", scope_gate=gate_out,
                            backend=spy, engagement_slug="alpha", signers=SIGNERS)
    assert res.refused and spy.runs == [] and res.facts == []
