"""WAVE #4 — three more re-drive arms on the Strix proof-sink rail, over the last of the
``live.runtime_redrive`` RUNTIME_FACT_CLASSES: a Strix LEAD → an oracle-confirmed FACT VIGIL mints by
re-firing its OWN gated probe.

  * path_traversal (CWE-22) + lfi (CWE-98) — ``runtime_redrive(claimed_class="path_traversal")`` /
    ``side_effect`` oracle over branch ``path_traversal.file_signature``: the ``root:x:0:0:`` file-content
    signature appears under VIGIL's traversal payload and is ABSENT from a benign same-parameter control.
  * exposure (CWE-200/538)               — ``runtime_redrive(claimed_class="exposure")`` / ``predicate``
    oracle over branch ``exposure.secret_signature``: a VALUE-shaped secret signature (``DB_PASSWORD=``) at a
    fixed path, absent from a random control path.
  * ssi (CWE-97)                         — ``runtime_redrive(claimed_class="ssi")`` / ``ssi_evaluation``
    oracle over branch ``ssi.evaluation``: the server COMPUTED the product of a runner-crafted
    ``<!--#set-->``/``<!--#echo-->`` pair, the raw directive absent, the benign control lacking it.

Per arm: a REAL positive mints a signed FACT that re-verifies OFFLINE (``verify_certificate`` + the
``python3 -m framework.v2 verify`` CLI over the persisted ``proofs/reverifiable.json``) and whose TAMPER is
rejected; and each NAMED false-positive yields a LEAD (no mint).

SOUNDNESS FOCUS — the ``lfi``/``ContentSignatureCheck`` control flag. The raw ``ContentSignatureCheck`` path
fires on a NON-UNIQUE well-known signature with no benign control, so a docs/error page that always prints
``root:x:0:0:`` would mint a false FACT. This rail NEVER reaches that raw path: every arm here goes through
``proof.run._runtime_class_arm`` → ``runtime_redrive``, whose path_traversal branch sends the benign CONTROL
FIRST and refuses the candidate when the control already carries the signature.
``test_signature_printing_docs_page_without_a_read_is_refused`` proves it live (for an ``lfi``-labelled report
too), and ``test_every_w4_arm_drives_the_control_bearing_runner`` pins it structurally.

The RUNNER crafts every probe; the Strix report supplies ONLY the location. The transport is VIGIL's OWN
charter-gated, DNS-pinned, proxy-free send (``web_redrive._gated_web_send``).
"""
from __future__ import annotations

import http.server
import json
import re
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---- gate isolation + charter (mirrors test_strix_http_redrive) ----------------------------------------
@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def _mint(tmp_path: Path, signers, slug: str = "alpha"):
    """The proof-sink mint callback. Every W4 arm crafts its OWN gated controls, so NO control_fetch seam is
    needed (unlike the errsig arm)."""
    from vigil_integration.proof.run import build_report_mint
    return build_report_mint(run_dir=tmp_path, signers=signers, engagement_slug=slug)


# ---- a loopback app: one MODE per scenario (exposure probes FIXED paths, so its decoys are per-ORIGIN) ---

# The real first line of a Linux /etc/passwd — the KNOWN-CONTENT signature the side_effect oracle adjudicates.
_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")

# The SAME set+echo directive shape a naive include processor evaluates (mirrors test_ssi_redrive).
_SSI_SET_ECHO = re.compile(
    r'<!--#\s*set\s+var="(?P<name>[A-Za-z_][A-Za-z0-9_]*)"\s+'
    r'value="(?P<a>\d+)\s*\*\s*(?P<b>\d+)"\s*-->'
    r'\s*<!--#\s*echo\s+var="(?P=name)"\s*-->')


def _eval_ssi(raw: str) -> "str | None":
    m = _SSI_SET_ECHO.fullmatch((raw or "").strip())
    return str(int(m.group("a")) * int(m.group("b"))) if m else None


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


class _App(http.server.BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200, ctype: str = "text/html; charset=utf-8") -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)          # charset DECLARED → the body is adjudicable
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802, C901 — one flat dispatch per scenario mode
        mode = self.server.vigil_mode                     # type: ignore[attr-defined]
        parts = urlsplit(self.path)
        path = parts.path
        values = [v for vs in parse_qs(parts.query, keep_blank_values=True).values() for v in vs]
        joined = " ".join(values)

        # ---------- path traversal / LFI ----------
        if mode == "traversal_vuln":
            # VULNERABLE: a naive read — any value naming the traversal target returns the FILE'S CONTENT.
            if "etc/passwd" in joined:
                return self._send(_PASSWD, ctype="text/plain; charset=utf-8")
            return self._send("<html><body>no such document</body></html>")
        if mode == "traversal_docs":
            # FP: a docs/error page that ALWAYS prints the signature regardless of input. The runner's benign
            # CONTROL request sees it first and refuses the candidate — no payload is ever adjudicated.
            return self._send("<html><body><h1>Hardening guide</h1><pre>root:x:0:0:root:/root:/bin/bash"
                              "</pre><p>never expose this file</p></body></html>")
        if mode == "traversal_echo":
            # FP: the payload is REFLECTED verbatim but no file is read — the signature never appears.
            return self._send(f"<html><body>no such document: {joined}</body></html>")

        # ---------- secret / config exposure ----------
        if mode == "exposure_vuln":
            if path == "/.env":                           # VULNERABLE: a real, value-shaped secret leak
                return self._send("APP_ENV=production\nDB_PASSWORD=hunter2\n",
                                  ctype="text/plain; charset=utf-8")
            return self._send("<html><body>not found</body></html>", code=404)
        if mode == "exposure_soft404":
            # FP: a 200 catch-all that serves the signature at EVERY path (including the random control one),
            # so nothing is path-specific. The runner's random-path control refuses it.
            return self._send("APP_ENV=production\nDB_PASSWORD=hunter2\n",
                              ctype="text/plain; charset=utf-8")
        if mode == "exposure_keyonly":
            if path == "/.env":
                # FP: a bundle that merely NAMES the key — no `KEY=value` shape, so no secret is disclosed.
                return self._send("// deploy note: the worker reads DB_PASSWORD from the vault at boot\n",
                                  ctype="text/plain; charset=utf-8")
            return self._send("<html><body>not found</body></html>", code=404)

        # ---------- server-side includes ----------
        if mode == "ssi_vuln":                            # VULNERABLE: EVALUATES set+echo, emits the product
            rendered = next((p for p in (_eval_ssi(v) for v in values) if p), None)
            return self._send(f"<html><body><h1>Included</h1><p>{rendered or 'index'}</p></body></html>")
        if mode == "ssi_inert":
            # FP: SSI disabled — the directive is echoed back VERBATIM as an inert comment. The raw directive
            # survives and no product is computed → reflected, not evaluated.
            shown = next((v for v in values if _SSI_SET_ECHO.fullmatch(v.strip())), None)
            return self._send(f"<html><body><h1>Included</h1><p>{shown or 'index'}</p></body></html>")
        if mode == "ssi_static":                          # FP: input ignored — the product never appears
            return self._send(f"<html><body><h1>Included</h1><p>{_esc('index')}</p></body></html>")

        return self._send("<html><body>not found</body></html>", code=404)

    def log_message(self, *a):  # silence
        return


def _serve(mode: str):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _App)
    srv.vigil_mode = mode                                  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_mint(tmp_path, signers, check_id, mode, bug_class, *, path="/read", param="file", cwe=None):
    """Start the loopback app in ``mode`` and drive ONE Strix-shaped report through the proof-sink mint."""
    srv = _serve(mode)
    port = srv.server_address[1]
    try:
        report = {"id": check_id, "endpoint": f"http://127.0.0.1:{port}{path}"}
        if bug_class is not None:
            report["bug_class"] = bug_class
        if cwe is not None:
            report["cwe"] = cwe
        if param:
            report["param"] = param
            report["endpoint"] += f"?{param}=seed"
        return _mint(tmp_path, signers)(report)
    finally:
        srv.shutdown()


def _corrupt_context(oc: dict) -> None:
    """Strip the evidence of the fire from a retained oracle_context, so the deterministic oracle can no
    longer re-fire over it (the tamper-rejection half of every positive)."""
    if "observed_sink" in oc:                      # path_traversal: remove the read file's content
        oc["observed_sink"] = "<html><body>no such document</body></html>"
    if isinstance(oc.get("observed_evidence"), dict):   # exposure: blank the leaking body
        oc["observed_evidence"] = dict(oc["observed_evidence"], body="<html><body>not found</body></html>")
    if "ssi_observed" in oc:                       # ssi: remove the server-computed product
        oc["ssi_observed"] = "<html><body><h1>Included</h1><p>index</p></body></html>"


def _assert_fact_reverifies(mr, tr, tmp_path):
    """A minted FACT: the signed cert re-verifies OFFLINE over its retained context, a GROSS TAMPER is
    rejected, and the persisted proofs/reverifiable.json re-fires (and fails closed on tamper) through the
    `python3 -m framework.v2 verify` CLI."""
    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.verify import reverify

    assert mr is not None and mr.is_fact, f"expected a signed FACT; got {mr}"
    res = mr.result
    assert res.n_facts >= 1
    fact = res.facts[0]
    ctx = res.contexts[fact.finding_ref]

    # (1) the signed cert re-verifies OFFLINE from the retained JSON-safe context — no network, no runner.
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=tr).ok is True

    # (2) a TAMPER of the retained context is rejected (the oracle no longer re-fires over the altered bytes).
    tampered = json.loads(json.dumps(ctx))
    _corrupt_context(tampered)
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=tr).ok is False

    # (3) the offline CLI re-fires the persisted reverifiable.json.
    report_path = tmp_path / "proofs" / "reverifiable.json"
    assert report_path.is_file(), "a FACT must persist a re-verifiable report for offline CLI verify"
    assert reverify.main([str(report_path)]) == 0, "the persisted FACT must re-verify offline"

    doc = json.loads(report_path.read_text(encoding="utf-8"))
    for f in doc["active_findings"]:
        _corrupt_context(f.get("oracle_context") or {})
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(doc), encoding="utf-8")
    assert reverify.main([str(tampered_path)]) != 0, "a tampered context must not re-verify"


# =======================================================================================================
# path traversal (CWE-22) — and the lfi (CWE-98) alias that rides the SAME control-bearing arm
# =======================================================================================================

def test_path_traversal_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "pt-1", "traversal_vuln", "path_traversal")
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "path_traversal"
    assert all("path_traversal.file_signature" in str(a[0]) for a in mr.result.admissions)


def test_lfi_labelled_report_mints_under_the_path_traversal_branch(monkeypatch, tmp_path):
    """LFI DECISION pin. An ``lfi``/CWE-98 Strix LEAD is re-driven by the SAME control-bearing arm and, on
    confirmation, certified as ``path_traversal`` — the class the side_effect oracle actually proved. The
    evidence (a file-content signature under a traversal payload) does not distinguish an include/require
    sink from a plain read, so upgrading the class on the claimant's LABEL is refused by construction."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "lfi-1", "traversal_vuln", "lfi")
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "path_traversal", "an lfi LEAD must be certified as path_traversal"
    assert all(getattr(f, "bug_class", "path_traversal") != "lfi" for f in mr.result.facts), (
        "no certificate on this rail may claim the class `lfi`")


def test_cwe98_only_report_is_claimed_by_the_traversal_arm(monkeypatch, tmp_path):
    """A report carrying no bug_class at all, only ``CWE-98``, still routes to the traversal arm."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "cwe98-1", "traversal_vuln", None, cwe="CWE-98")
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "path_traversal"


@pytest.mark.parametrize("bug_class", ["path_traversal", "lfi"])
def test_signature_printing_docs_page_without_a_read_is_refused(monkeypatch, tmp_path, bug_class):
    """THE soundness flag, live and on BOTH labels: a page that already prints ``root:x:0:0:`` (a hardening
    doc, an error page, a paste) with NO file read. The raw ContentSignatureCheck path would fire on it; this
    rail's benign same-parameter CONTROL sees the signature FIRST and refuses the candidate → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, f"pt-docs-{bug_class}", "traversal_docs", bug_class)
    assert mr is None or not mr.is_fact, "a signature-printing page with no read must NOT mint a FACT"
    assert not (tmp_path / "proofs" / "reverifiable.json").exists(), "no FACT ⇒ nothing re-verifiable persisted"
    # and the refusal is the CONTROL's, recorded honestly rather than silently dropped.
    assert any("not attributable to a traversal" in n for n in (mr.result.notes if mr else [])), (
        "the benign control must be what refuses this page")


def test_path_traversal_payload_reflection_without_a_read_is_refused(monkeypatch, tmp_path):
    """FP: the traversal payload is REFLECTED verbatim but no file is read — the content signature never
    appears, so the side_effect oracle does not fire → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "pt-echo", "traversal_echo", "path_traversal")
    assert mr is None or not mr.is_fact, "a reflected-but-unread payload must NOT mint a traversal FACT"


# =======================================================================================================
# secret / config exposure (CWE-200 / CWE-538)
# =======================================================================================================

def test_exposure_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "exp-1", "exposure_vuln", "exposure", path="/", param=None)
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "exposure"
    assert all("exposure.secret_signature" in str(a[0]) for a in mr.result.admissions)


def test_exposure_soft_404_catch_all_is_refused(monkeypatch, tmp_path):
    """FP: a 200 soft-404 catch-all that serves ``DB_PASSWORD=`` at EVERY path — including the runner's random
    control path — so nothing is attributable to ``/.env``. The control refuses it → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "exp-soft", "exposure_soft404", "exposure", path="/", param=None)
    assert mr is None or not mr.is_fact, "a soft-404 catch-all must NOT mint an exposure FACT"
    assert any("soft-404" in n for n in (mr.result.notes if mr else [])), (
        "the random-path control must be what refuses this origin")


def test_exposure_bundle_naming_the_key_without_a_value_is_refused(monkeypatch, tmp_path):
    """FP: the served file merely NAMES ``DB_PASSWORD`` (a deploy note / JS bundle) with no ``KEY=value``
    shape — no secret is disclosed, so the VALUE-shaped signature does not match → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "exp-key", "exposure_keyonly", "exposure", path="/", param=None)
    assert mr is None or not mr.is_fact, "naming a secret's KEY must NOT mint an exposure FACT"


# =======================================================================================================
# server-side includes (CWE-97)
# =======================================================================================================

def test_ssi_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "ssi-1", "ssi_vuln", "ssi", path="/inc", param="doc")
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "ssi", "the ssi arm must drive claimed_class='ssi', never 'ssti'"
    assert all("ssi.evaluation" in str(a[0]) for a in mr.result.admissions)


def test_ssi_directive_reflected_as_an_inert_comment_is_refused(monkeypatch, tmp_path):
    """FP: SSI is disabled and the directive is echoed back VERBATIM as an inert HTML comment — the RAW
    directive survives and no product is computed → reflected, not evaluated → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "ssi-inert", "ssi_inert", "ssi", path="/inc", param="doc")
    assert mr is None or not mr.is_fact, "a verbatim-reflected directive must NOT mint an SSI FACT"


def test_ssi_static_page_is_refused(monkeypatch, tmp_path):
    """FP: the product never appears (no evaluation, no coincidence) → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr = _run_mint(tmp_path, signers, "ssi-static", "ssi_static", "ssi", path="/inc", param="doc")
    assert mr is None or not mr.is_fact, "a page that never evaluates the directive must NOT mint an SSI FACT"


# =======================================================================================================
# shared soundness: scope, the capture path, and the CONTROL guarantee the whole slice rests on
# =======================================================================================================

@pytest.mark.parametrize("bug_class,mode,path,param", [
    ("path_traversal", "traversal_vuln", "/read", "file"),
    ("lfi", "traversal_vuln", "/read", "file"),
    ("exposure", "exposure_vuln", "/", None),
    ("ssi", "ssi_vuln", "/inc", "doc"),
])
def test_out_of_scope_endpoint_is_refused_before_a_fact(monkeypatch, tmp_path, bug_class, mode, path, param):
    """A gate refusal (target host not in the charter scope) yields NO channel → LEAD, for every W4 arm."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")            # charter authorizes 127.0.0.1 only
    signers, _ = _signers_and_trust()
    endpoint = f"http://127.0.0.2:1{path}" + (f"?{param}=seed" if param else "")
    mr = _mint(tmp_path, signers)({"id": f"oos-{bug_class}", "bug_class": bug_class, "endpoint": endpoint})
    assert mr is None or not mr.is_fact, "an out-of-scope target must never mint a FACT"


@pytest.mark.parametrize("bug_class", ["path_traversal", "lfi", "exposure", "ssi"])
def test_a_capture_bearing_report_is_not_hijacked_by_a_w4_arm(tmp_path, bug_class):
    """A capture-bearing report is left for the executor-capture mint (every W4 arm is requires_no_capture),
    so a Strix-supplied capture can never be laundered through a W4 oracle."""
    from vigil_integration.proof.sink import CAPTURE_KEY
    signers, _ = _signers_and_trust()
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500, "bug_class": "error_based_sqli"},
                         {"channel": "error_signature", "role": "control", "response_bytes_ref": "ctrl"}],
           "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended",
                     "ctrl": b"HTTP/1.1 200 OK\r\n\r\n{\"items\": []}",
                     "req": b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    res = _mint(tmp_path, signers)({"id": f"cap-{bug_class}", "bug_class": bug_class, CAPTURE_KEY: cap})
    assert not hasattr(res, "result") or getattr(res, "result", None) is None or hasattr(res, "reproduced"), (
        "a capture-bearing report must not be hijacked by a W4 runtime arm")


def test_every_w4_arm_drives_the_control_bearing_runner():
    """STRUCTURAL half of the control guarantee (the live half is the docs-page test above).

    Every W4 driver must reach ``live.runtime_redrive.runtime_redrive`` — the ONE implementation that sends a
    benign CONTROL before adjudicating anything — with a RUNNER-supplied literal class, never the report's
    free text. If a future edit routed one of these arms at the raw ``ContentSignatureCheck``/``PathProbeCheck``
    (no control), or let the report choose the class, this fails."""
    from vigil_integration.proof import run
    from vigil_integration.live.runtime_redrive import RUNTIME_FACT_CLASSES

    seen: "list[tuple[str, str]]" = []

    def _spy(url, *, slug, engagement_slug, signers, claimed_class, timeout=8.0):
        seen.append((url, claimed_class))
        return None                              # _finish_runtime_arm(None) ⇒ no mint, no FACT

    import vigil_integration.live.runtime_redrive as rr
    original = rr.runtime_redrive
    rr.runtime_redrive = _spy
    try:
        for cls, drive in (("path_traversal", run._traversal_redrive), ("exposure", run._exposure_redrive),
                           ("ssi", run._ssi_redrive)):
            seen.clear()
            out = drive({"endpoint": "http://127.0.0.1:1/x", "bug_class": "attacker-chosen-nonsense"},
                        cls, run_dir="/nonexistent-run-dir", signers=[], engagement_slug="alpha")
            assert out is None, "a runner that returned nothing must not mint"
            assert seen == [("http://127.0.0.1:1/x", cls)], (
                f"{cls} arm must drive runtime_redrive with the RUNNER's literal class; saw {seen}")
            assert cls in RUNTIME_FACT_CLASSES, f"{cls} must be a control-bearing runtime_redrive class"
    finally:
        rr.runtime_redrive = original

    # the lfi alias resolves to the same control-bearing class before any driver runs.
    assert run._traversal_redrive_class({"bug_class": "lfi"}) == "path_traversal"


@pytest.mark.parametrize("bug_class,expected", [
    ("path_traversal", True), ("lfi", True), ("local_file_inclusion", True),
    ("exposure", True), ("information_disclosure", True), ("ssi", True), ("server_side_includes", True),
    ("ssti", False), ("boolean_sqli", False), ("open_redirect", False),
])
def test_sink_gate_matches_the_dispatch_rail(bug_class, expected):
    """The sink's ``or _<x>_redrivable(...)`` clauses and the dispatch rail's classifiers can never disagree
    about which reports reach the mint WITHOUT a capture — both delegate to the same classifier."""
    from vigil_integration.proof import run, sink
    report = {"id": "g", "bug_class": bug_class, "endpoint": "http://127.0.0.1:1/x"}
    w4 = (sink._traversal_redrivable(report) or sink._exposure_redrivable(report)
          or sink._ssi_redrivable(report))
    assert w4 is expected, f"{bug_class}: sink W4 gate={w4}, expected {expected}"
    handled = any(classify(report) is not None for classify, _d, _r in run._REDRIVE_ARMS)
    assert handled, f"{bug_class} must be claimed by SOME arm on the rail"
