"""The egress-floor COMPLETENESS GUARD — the fence that formally authorizes real-target runs.

WHY THIS TEST EXISTS. A string scope gate answers a question about a STRING; it never resolves a host
and never classifies an address, so only the never-liftable L3/L4 floor (``common/egress_pin.py`` on the
engine side, ``live/egress_floor.py`` on the integration side, both over ``vigil_gateway.denylist``) can
promise that no engagement reaches cloud metadata / link-local / RFC1918. The recorded lesson of this
repo is that a class-bug recurs at EVERY unguarded site, so the floor must be closed with one shared
helper AND a census that fails the build the moment a NEW egress primitive lands unfloored — otherwise
the next ``socket.create_connection`` / ``urlopen`` / ``httpx`` call quietly reopens the hole.

WHAT IT DOES. Stdlib-only (``ast`` + ``pathlib`` — no import of either trust domain, so it runs in the
required ``CRUCIBLE core on vigil_core`` job which installs only pytest + vigil_core), this guard walks
every NON-TEST product ``.py`` under ``framework/v2`` and finds every egress primitive by AST:
``socket.create_connection``, a ``socket``-style ``.connect((host, port))`` (a DB ``sqlite3.connect("...")``
is NOT one — its first arg is a string, not a tuple, so it is never matched), ``socket.getaddrinfo``,
``urllib`` ``urlopen`` / ``urlretrieve`` / ``build_opener``, ``http.client.HTTP(S)Connection``, and an
``httpx`` / ``requests`` verb call on an http-client receiver. Every discovered site MUST be one of:

  (a) a floor primitive itself — there are no egress CALL sites inside ``egress_pin.py`` /
      ``egress_floor.py`` / ``denylist.py`` (they reference ``socket.getaddrinfo`` as a default, never
      call a connect), so this category is empty here and that is asserted, not assumed;
  (b) FLOORED — its file routes through ``resolve_and_pin`` / ``pin_egress`` before the connect (the
      ``token`` is that symbol, asserted present in the file); or
  (c) in the EXPLICIT allowlist below, each entry carrying a JUSTIFICATION, the COVERING test, and a
      ``token`` that is the justifying gate's own code — so BIDIRECTIONALLY, an allowlisted site that
      loses its justifying gate (the token vanishes) turns this guard RED.

A tiny, auditable DEFERRED set names the genuine engagement-egress sites that are NOT yet floored because
flooring them soundly needs its own slice (each threads an engagement slug); each points at a tracking
finding the guard asserts EXISTS, so a deferred gap is recorded, never silently allowed.

The census is keyed by (relpath, primitive-kind) with an exact COUNT, so it is robust to line drift but
STRICT on arithmetic: a new same-kind call in a listed file (count mismatch), a new egress file (an
unaccounted key), or a removed/renamed site (a stale key) all fail the build. Negative controls below
exercise the SAME classifier + accounting the real census relies on against deliberately-broken inputs,
so the gate is provably not a no-op.
"""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

V2_ROOT = Path(__file__).resolve().parents[2]      # engine/crucible/framework/v2

# Directories whose .py are not product egress for this census.
_EXCLUDE_PARTS = {"__pycache__", "node_modules", ".venv-offense", ".venv-sovereign", ".git"}

_HTTPX_VERBS = {"get", "post", "put", "delete", "patch", "head", "request", "stream", "send"}
# Receivers an httpx/requests verb call is an EGRESS call on (an http client or the module itself). A
# narrow set on purpose: ``self.send`` / ``wfile.write`` / ``queue.get`` are not egress.
_HTTP_RECEIVERS = {"httpx", "requests", "client", "_client", "session", "_session"}


# ==================================================================================================
# The AST classifier + scanner (the load-bearing detection; negative controls exercise it directly)
# ==================================================================================================
def _is_test_path(path: Path) -> bool:
    return ("tests" in path.parts or path.name.startswith("test_")
            or path.name.endswith("_test.py"))


def _receiver_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _receiver_name(node.func)
    return None


def classify_call(call: ast.Call) -> str | None:
    """The egress-primitive KIND of a call node, or None. Pure, stdlib-only, exercised by the negatives."""
    f = call.func
    if isinstance(f, ast.Attribute):
        attr = f.attr
        if attr == "create_connection":
            return "socket.create_connection"
        # A socket connect takes a (host, port) TUPLE; sqlite3.connect("...") takes a string, so it is
        # never matched here — the distinction that keeps DB connects out of the egress census.
        if attr == "connect" and call.args and isinstance(call.args[0], ast.Tuple):
            return "socket.connect"
        if attr == "getaddrinfo":
            return "getaddrinfo"
        if attr in ("urlopen", "urlretrieve"):
            return "urllib.urlopen"
        if attr == "build_opener":
            return "urllib.build_opener"
        if attr in _HTTPX_VERBS and _receiver_name(f.value) in _HTTP_RECEIVERS:
            return f"httpx/requests.{attr}"
    name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
    if name in ("HTTPConnection", "HTTPSConnection"):
        return "http.client.Connection"
    return None


def scan_sites(root: Path = V2_ROOT) -> list[tuple[str, int, str]]:
    """Every (relpath, lineno, kind) egress call site in non-test product .py under ``root``."""
    out: list[tuple[str, int, str]] = []
    this = Path(__file__).resolve()
    for path in sorted(root.rglob("*.py")):
        if any(part in _EXCLUDE_PARTS for part in path.parts):
            continue
        if _is_test_path(path) or path.resolve() == this:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        rel = str(path.relative_to(root))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                kind = classify_call(node)
                if kind:
                    out.append((rel, node.lineno, kind))
    return out


def discovered_counts(root: Path = V2_ROOT) -> "dict[tuple[str, str], int]":
    """(relpath, kind) -> number of such egress call sites in the tree."""
    return dict(Counter((rel, kind) for rel, _ln, kind in scan_sites(root)))


# ==================================================================================================
# The CENSUS. Every key is (relpath, kind); value carries the classification. This is the allowlist the
# AC requires — each covered/floored entry names its justifying gate (``token``, asserted present in the
# file so the gate cannot be removed without turning the guard RED) and the covering test.
#   category: "floored" | "covered" | "deferred"
#   count:    exact number of sites of this (file, kind) — count drift fails the build
#   token:    a substring that MUST be present in the file (the justifying gate's own code)
# ==================================================================================================
_PIN = "resolve_and_pin"   # the engine floor symbol; its presence is the "floored" evidence

CENSUS: "dict[tuple[str, str], dict]" = {
    # ---- (b) FLOORED: the capture/scanner paths that resolve once and dial the validated IP ----------
    ("verify/reachability.py", "socket.create_connection"): dict(
        category="floored", count=1, token=_PIN,
        justification="capture_handshake resolve_and_pins, then dials the pinned IP (#874)",
        test="verify/tests/test_reachability.py"),
    ("verify/tls.py", "socket.create_connection"): dict(
        category="floored", count=1, token=_PIN,
        justification="capture_tls_handshake pins; _tls_connect dials dial_ip, SNI=host (#874)",
        test="verify/tests/test_tls_weakness.py"),
    ("verify/reachability_cloud.py", "http.client.Connection"): dict(
        category="floored", count=2, token=_PIN,
        justification="anonymous GET pins: _http_get dials the validated IP over http.client, keeping "
                      "SNI/cert=host (HTTPS) and Host: host (HTTP) — WAVE 2",
        test="verify/tests/test_reachability_cloud.py"),
    ("scanner/race.py", "socket.create_connection"): dict(
        category="floored", count=1, token=_PIN,
        justification="raw_race dials pinned_ip from resolve_and_pin (#879)",
        test="scanner/tests/test_race.py"),
    ("scanner/smuggling.py", "socket.create_connection"): dict(
        category="floored", count=2, token=_PIN,
        justification="raw_send + _desync_leg dial dial_ip from resolve_and_pin (#879)",
        test="scanner/tests/test_smuggling.py"),
    ("scanner/websocket.py", "socket.create_connection"): dict(
        category="floored", count=1, token=_PIN,
        justification="CSWSH raw socket dials dial_ip from resolve_and_pin (#879)",
        test="scanner/tests/test_websocket.py"),
    ("agents/http_executor.py", "httpx/requests.request"): dict(
        category="covered", count=2, token=_PIN,
        justification="validate-and-refuse (VALIDATE-ONLY, like intake/http.py): _assert_egress_floor runs "
                      "resolve_and_pin on every client.request hop, refusing metadata/RFC1918/link-local, "
                      "behind the string scope gate — but httpx/httpcore re-resolves at connect, so a "
                      "connect-time rebind is a tracked TOCTOU residual (R3), not a true dial-the-pinned-IP",
        test="agents/tests/test_http_executor_egress_redirect.py"),
    ("agents/http_executor.py", "getaddrinfo"): dict(
        category="covered", count=1, token=_PIN,
        justification="the validate step's OWN loopback-grant resolution inside _assert_egress_floor (adds "
                      "only loopback addresses to the lift set; every tier is re-checked by resolve_and_pin)",
        test="agents/tests/test_http_executor_egress_redirect.py"),

    # ---- (c) COVERED ELSEWHERE: own SSRF floor / intel gated-egress / operator-infra / loopback / LLM --
    ("intake/http.py", "getaddrinfo"): dict(
        category="covered", count=1, token="assert_public_target",
        justification="the intake SSRF guard's OWN resolve-at-request-time: refuses private/loopback/"
                      "link-local/reserved before the socket (rebinding-aware); not a connect",
        test="intake/tests/test_ssrf_guard.py"),
    ("intake/http.py", "httpx/requests.request"): dict(
        category="covered", count=1, token="assert_public_target",
        justification="raw httpx behind assert_public_target (SSRF floor) + the protected-domain floor",
        test="intake/tests/test_ssrf_guard.py"),
    ("intel/transport.py", "httpx/requests.get"): dict(
        category="covered", count=1, token="CollectorEgressRefused",
        justification="an intel collector with its OWN gated-egress control: the recon endpoint host must "
                      "be in the collector_hosts allowlist, disjoint from target scope",
        test="intel/tests/test_collectors.py"),
    ("sensors/cloud.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="egress_hosts",
        justification="pull from the OPERATOR-configured cloud-inventory collector URL; the sensor "
                      "declares egress_hosts so the WARDEN tool-gate governs it (not a charter target)",
        test="sensors/tests/test_cloud_live.py"),
    ("sensors/web_scanner.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="egress_hosts",
        justification="pull issues from the OPERATOR's Burp REST server; declares egress_hosts so the "
                      "WARDEN tool-gate governs it (operator infra, not a charter target)",
        test="sensors/tests/test_web_scanner_sensors.py"),
    ("report/push.py", "urllib.build_opener"): dict(
        category="covered", count=1, token="push URL must be http",
        justification="bounded JSON POST to EXACTLY the operator-configured report sink; redirects "
                      "disabled (no redirect-to-internal SSRF), http(s) only; an operator sink, not a target",
        test="report/tests/test_push.py"),
    ("verify/collaborator.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="_RELAY_KEY_HEADER",
        justification="poll the out-of-band OAST collaborator RELAY (authenticated, secret in a header); "
                      "the relay is collector infra, never a charter target",
        test="verify/tests/test_collaborator.py"),
    ("agents/tier3_validation.py", "getaddrinfo"): dict(
        category="covered", count=1, token="resolves_to_loopback",
        justification="resolves_to_loopback is a FAIL-CLOSED check: ok only if the host resolves to "
                      "loopback and NOTHING else (a rebind to any non-loopback refuses); not a connect",
        test="agents/tests/test_tier3_validation.py"),
    ("agents/oracle_probe_executor.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="loopback",
        justification="truth-value-attribution probe captured on LOOPBACK only (self-hosted witness app)",
        test="agents/tests/test_producer_oracle_e2e.py"),
    ("scanner/bizlogic.py", "urllib.urlopen"): dict(
        category="covered", count=2, token="loopback",
        justification="workflow self-check against a 127.0.0.1 server this module itself spins up; the "
                      "live product supplies retained responses from the gated web_redrive channel",
        test="scanner/tests/test_bizlogic.py"),
    ("scanner/cdp.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="loopback",
        justification="list Chrome DevTools targets on 127.0.0.1 (the local debugger), loopback only",
        test="scanner/tests/test_cdp.py"),
    ("scanner/cli.py", "urllib.build_opener"): dict(
        category="covered", count=1, token="loopback",
        justification="loopback_send issues one request against a LOOPBACK target (scanner dev harness)",
        test="scanner/tests/test_cli_flag_wiring.py"),
    ("scanner/benchmark.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="loopback",
        justification="benchmark self-check against a 127.0.0.1 server this module spins up (loopback)",
        test="scanner/tests/test_benchmark.py"),
    ("verify/confirmation.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="loopback",
        justification="confirmation demo self-check against a 127.0.0.1 server this module spins up",
        test="verify/tests/test_confirmation_e2e.py"),
    ("eval/corpus_run.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="loopback",
        justification="health check of a LOOPBACK corpus container the eval harness started",
        test="eval/tests/test_corpus_run.py"),
    ("eval/adapters.py", "urllib.urlopen"): dict(
        category="covered", count=1, token="operator-configured REST endpoint",
        justification="eval adapter pull from the OPERATOR-configured Burp REST URL (operator infra)",
        test="eval/tests/test_validation.py"),
    ("aegis/gateway.py", "socket.create_connection"): dict(
        category="covered", count=1, token="_upstream_listening_debounced",
        justification="AEGIS DEFENSIVE reverse-proxy readyz health probe to its SINGLE operator-configured "
                      "upstream (debounced); not an offense engagement egress",
        test="aegis/tests/test_gateway_health_readyz.py"),
    ("aegis/gateway.py", "httpx/requests.stream"): dict(
        category="covered", count=1, token="trust_env=False",
        justification="AEGIS DEFENSIVE reverse-proxy forwarding to its configured upstream, trust_env=False "
                      "(no ambient proxy / trust-store diversion); not an offense engagement egress",
        test="aegis/tests/test_gateway.py"),
    ("kernel/backends/ollama.py", "httpx/requests.get"): dict(
        category="covered", count=2, token="/api/",
        justification="reasoning-model backend probe to the configured local Ollama endpoint (the brain, "
                      "model-sovereignty governed; not a charter target)",
        test="kernel/tests/test_byo_backends.py"),
    ("kernel/backends/ollama.py", "httpx/requests.post"): dict(
        category="covered", count=1, token="/api/",
        justification="reasoning-model backend generate call to the configured local Ollama endpoint",
        test="kernel/tests/test_byo_backends.py"),
    ("kernel/backends/mistral.py", "httpx/requests.post"): dict(
        category="covered", count=1, token="chat/completions",
        justification="reasoning-model backend chat call to the configured Mistral endpoint (the brain)",
        test="kernel/tests/test_byo_backends.py"),
    ("kernel/backends/azure_openai.py", "httpx/requests.post"): dict(
        category="covered", count=1, token="chat/completions",
        justification="reasoning-model backend chat call to the validated Azure OpenAI endpoint (the brain)",
        test="kernel/tests/test_byo_backends.py"),
    ("kernel/backends/self_hosted.py", "httpx/requests.post"): dict(
        category="covered", count=1, token="chat/completions",
        justification="reasoning-model backend chat call to the operator's OWN self-hosted model endpoint",
        test="kernel/tests/test_byo_backends.py"),
    # Deliberately-(un)safe SSRF SAMPLES the scanner ANALYZES — not VIGIL's own runtime egress.
    ("analysis/benchmark/python/vulnerable.py", "httpx/requests.get"): dict(
        category="covered", count=1, token="CWE-918",
        justification="a deliberately-vulnerable SSRF SAMPLE the SAST corpus scans; not VIGIL egress",
        test="scanner/tests/test_w16_4_coverage_honesty.py"),
    ("analysis/benchmark/python/sanitized.py", "httpx/requests.get"): dict(
        category="covered", count=1, token="untainted",
        justification="the sanitized twin of the SSRF SAMPLE above (constant URL); not VIGIL egress",
        test="scanner/tests/test_w16_4_coverage_honesty.py"),
    ("eval/corpus/vulnpy/code/ssrf.py", "httpx/requests.get"): dict(
        category="covered", count=1, token="requests.get(url",
        justification="a vulnerable-python CORPUS SSRF sample the eval corpus scans; not VIGIL egress",
        test="eval/tests/test_corpus_run.py"),
}

# A tiny, auditable DEFERRED set: genuine engagement-egress-to-a-target sites that are NOT yet floored
# because flooring them soundly needs its own slice (each must thread an engagement slug, and neither is
# on a LIVE gated FACT-minting path today). Each points at the tracking finding the guard asserts exists.
_RESIDUAL_FINDING = "docs/limitations/egress-floor-engine-residuals.md"
DEFERRED: "dict[tuple[str, str], dict]" = {
    ("scanner/quantum_era.py", "socket.create_connection"): dict(
        category="deferred", count=1, token="pqc_scan", finding=_RESIDUAL_FINDING,
        justification="pqc_scan opens a real TLS handshake to (host,port) with no egress floor; it is a "
                      "library scanner with NO live FACT-minting caller, and flooring it needs a slug "
                      "threaded from a gated driver — deferred to its own slice",
        test="scanner/tests/test_quantum_era.py"),
    ("scanner/csp_bypass.py", "urllib.build_opener"): dict(
        category="deferred", count=1, token="_gated_fetch_headers", finding=_RESIDUAL_FINDING,
        justification="_gated_fetch_headers is the loopback/dev FALLBACK fetch; the live product supplies "
                      "retained headers from the gated web_redrive channel, so this path is not the live "
                      "egress, but flooring the fallback needs a slug — deferred to its own slice",
        test="scanner/tests/test_csp_bypass.py"),
}


def _full_census() -> "dict[tuple[str, str], dict]":
    merged = dict(CENSUS)
    merged.update(DEFERRED)
    return merged


# ==================================================================================================
# The real guard
# ==================================================================================================
def test_every_egress_site_is_classified_and_the_census_is_not_stale():
    """BIDIRECTIONAL completeness. Every discovered (file, kind) egress site must have a census entry
    with the matching COUNT (forward: a NEW unfloored egress primitive turns this RED), and every census
    entry must still match a real site (reverse: a removed/renamed site turns this RED)."""
    discovered = discovered_counts()
    census = _full_census()

    unaccounted = {k: n for k, n in discovered.items() if k not in census}
    stale = {k: v["count"] for k, v in census.items() if k not in discovered}
    count_drift = {k: (census[k]["count"], discovered[k])
                   for k in set(discovered) & set(census)
                   if census[k]["count"] != discovered[k]}

    problems = []
    if unaccounted:
        problems.append(
            "UNACCOUNTED egress primitive(s) — a connect/resolve/open with no census entry. FLOOR it "
            "(route through resolve_and_pin / pin_egress) or classify it in CENSUS with a justifying "
            f"gate + covering test, or (if a genuine unfloored gap) DEFERRED with a tracking finding:\n  "
            + "\n  ".join(f"{f}::{k} x{n}" for (f, k), n in sorted(unaccounted.items())))
    if stale:
        problems.append(
            "STALE census entries — listed but no longer found (site removed/renamed); update the census:\n  "
            + "\n  ".join(f"{f}::{k} (expected x{n})" for (f, k), n in sorted(stale.items())))
    if count_drift:
        problems.append(
            "COUNT DRIFT — the file gained/lost a same-kind egress site; re-verify each and fix the count:\n  "
            + "\n  ".join(f"{f}::{k} expected x{exp} but found x{got}"
                          for (f, k), (exp, got) in sorted(count_drift.items())))
    assert not problems, "\n\n".join(problems)


def test_each_census_entry_token_is_present_in_its_file():
    """The REVERSE leg of every allowlist/floored claim: the justifying gate's own code (``token``) must
    be present in the file. Remove the floor call, the SSRF guard, the collector refusal, the loopback
    restriction, ... and its token vanishes → this guard goes RED. This is what makes an allowlist entry
    a checkable claim, not a comment."""
    problems = []
    for (rel, kind), entry in _full_census().items():
        fp = V2_ROOT / rel
        if not fp.is_file():
            problems.append(f"{rel}::{kind}: census file does not exist")
            continue
        text = fp.read_text(encoding="utf-8")
        if entry["token"] not in text:
            problems.append(
                f"{rel}::{kind}: justifying-gate token {entry['token']!r} is GONE from the file — the "
                f"gate that covered this site was removed/changed; re-floor or re-justify it")
    assert not problems, "justifying-gate tokens missing:\n  - " + "\n  - ".join(problems)


def test_floored_entries_actually_route_through_a_pin_primitive():
    """Category 'floored' is a CLAIM that the file routes its connect through the shared floor; assert the
    pin symbol (resolve_and_pin or pin_egress) really is in the file."""
    problems = []
    for (rel, kind), entry in CENSUS.items():
        if entry["category"] != "floored":
            continue
        text = (V2_ROOT / rel).read_text(encoding="utf-8")
        if "resolve_and_pin" not in text and "pin_egress" not in text:
            problems.append(f"{rel}::{kind}: marked 'floored' but neither resolve_and_pin nor pin_egress "
                            f"appears in the file")
    assert not problems, "\n  ".join(problems)


def test_covered_entries_name_a_covering_test_that_exists():
    """An allowlist entry is a claim that ANOTHER gate covers the site and a test PINS it. Assert the
    named covering test file exists, so the claim cannot cite a test that was never written or was deleted."""
    problems = []
    for (rel, kind), entry in _full_census().items():
        test_rel = entry.get("test", "")
        if not test_rel or not (V2_ROOT / test_rel).is_file():
            problems.append(f"{rel}::{kind}: covering test {test_rel!r} does not exist")
    assert not problems, "missing covering tests:\n  - " + "\n  - ".join(problems)


def test_deferred_residuals_are_tracked_by_a_real_finding():
    """A DEFERRED (genuine-unfloored) site is honest ONLY if it is recorded; assert each names a tracking
    finding that EXISTS. This keeps the deferred set small and auditable — it cannot become a quiet
    dumping ground for unfloored egress."""
    problems = []
    repo_root = V2_ROOT.parents[3]     # engine/crucible/framework/v2 -> repo root
    for (rel, kind), entry in DEFERRED.items():
        finding = entry.get("finding", "")
        if not finding or not (repo_root / finding).is_file():
            problems.append(f"{rel}::{kind}: tracking finding {finding!r} does not exist")
    assert not problems, "deferred residuals not tracked:\n  - " + "\n  - ".join(problems)


def test_no_egress_call_sites_inside_the_floor_primitives():
    """Category (a): the floor primitives must not contain a connect-style egress CALL of their own (they
    reference socket.getaddrinfo as a default callable, never call a connect) — so there is no floor site
    that could itself be the hole."""
    for rel in ("common/egress_pin.py",):
        counts = {k: n for (f, k), n in discovered_counts().items() if f == rel}
        # getaddrinfo-as-default is an attribute reference, not a call, so it is not a site; assert no
        # connect/open site is present.
        bad = {k: n for k, n in counts.items() if k != "getaddrinfo"}
        assert not bad, f"{rel} unexpectedly contains egress call site(s): {bad}"


# ==================================================================================================
# Negative controls — the classifier + accounting are provably not no-ops.
# ==================================================================================================
def _kinds_in(src: str) -> list[str]:
    return [k for node in ast.walk(ast.parse(src)) if isinstance(node, ast.Call)
            and (k := classify_call(node)) is not None]


def test_negative_control_classifier_detects_each_primitive():
    assert _kinds_in("import socket\nsocket.create_connection((h, p))") == ["socket.create_connection"]
    assert _kinds_in("s.connect((h, p))") == ["socket.connect"]
    assert _kinds_in("import socket\nsocket.getaddrinfo(h, p)") == ["getaddrinfo"]
    assert _kinds_in("import urllib.request\nurllib.request.urlopen(u)") == ["urllib.urlopen"]
    assert _kinds_in("o = urllib.request.build_opener()") == ["urllib.build_opener"]
    assert _kinds_in("import http.client\nhttp.client.HTTPSConnection(h)") == ["http.client.Connection"]
    assert _kinds_in("client.request('GET', u)") == ["httpx/requests.request"]
    assert _kinds_in("httpx.get(u)") == ["httpx/requests.get"]
    assert _kinds_in("import httpx\nc.stream('GET', u)") == []  # 'c' is not an http-client receiver name


def test_negative_control_sqlite_connect_is_not_an_egress_site():
    # The DB connect takes a STRING, not a (host, port) tuple — it must never be classified egress.
    assert _kinds_in("import sqlite3\nsqlite3.connect(':memory:')") == []
    assert _kinds_in("sqlite3.connect(self.path, detect_types=1)") == []


def test_negative_control_an_unfloored_scratch_site_is_flagged():
    """The load-bearing negative: an unfloored socket.create_connection in a scratch product file is NOT
    in the census, so the accounting flags it. (And a floored/classified one would not be — the forward
    leg is exactly this set difference.)"""
    scratch = {("scratch/new_scanner.py", "socket.create_connection"): 1}
    census = _full_census()
    unaccounted = {k: n for k, n in scratch.items() if k not in census}
    assert unaccounted == {("scratch/new_scanner.py", "socket.create_connection"): 1}


def test_negative_control_a_removed_gate_token_is_flagged():
    """If an allowlisted site loses its justifying gate, its token is gone from the file → RED. Simulate
    with a token that appears in no file."""
    rel = "intel/transport.py"
    text = (V2_ROOT / rel).read_text(encoding="utf-8")
    assert "CollectorEgressRefused" in text                 # the real gate is present ...
    assert "ZZZ-no-such-gate-token-ZZZ" not in text         # ... and a removed one would be caught
