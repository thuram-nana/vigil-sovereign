"""Release gate #2 / #10 — the FALSE-FACT battery, as an honest scoreboard.

WHAT THIS FILE IS. The release gate requires that *"Strix cannot mint a FACT from response resemblance
alone"* (#2) and that an independent red team attack BOTH claim directions (#10). This is the false-FACT
direction: it presents evidence that merely RESEMBLES a vulnerability — a static datastore-error page, a
benign reflection — and asserts VIGIL declines to certify it, while proving the SAME paths mint when the
finding is real. The sharp shape the plan names: an app that returns a Postgres/LDAP stack trace on any
malformed input, with the most-recent matching request cited as "the exploit" — a signed FACT resting on a
response with no record of what was sent.

TWO real seams are driven:
  * the captured-bytes / error-signature mint (``proof.run.build_report_mint``): a datastore-error RESPONSE
    with no bound exploit REQUEST must stay a LEAD (inv 6/8);
  * the web re-drive sink (``proof.sink.ProofSink`` → ``live.web_redrive``): a benign endpoint that only
    resembles a redirect/CORS finding must mint NOTHING; VIGIL's own gated probe refutes the would-be claim.

HOW IT STAYS HONEST (model: ``test_production_invariants.py``). Each attack row asserts the true bar; a bar
the system does not meet is ``@pytest.mark.xfail(strict=True, reason="<slice>")`` so a later fix flips the
board red until the marker is deleted. Every row has a negative control proving the path DOES mint when the
finding is genuine — otherwise "no FACT" is vacuously true.

  * ``test_a_class_is_never_laundered_into_a_different_class`` is xfail(strict) pending **S6** ("Delete the
    CWE-90/CWE-91 → error_based_sqli relabel … A certificate must never rename the vulnerability class it
    describes"). Today a CWE-90 (LDAP) finding mints a signed FACT certified as ``error_based_sqli``.

FRAMEWORK-DEPENDENT (mint context + oracle + web re-drive). ``importorskip`` framework → MUST be in the
ci.yml offense-leg run-list (enforced by ``test_ci_framework_tests_run_in_offense_leg``); skips cleanly in
the sovereign leg.
"""
from __future__ import annotations

import http.server
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE (framework) not importable in this leg")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_integration.proof.run import _oracle_bug_class, build_report_mint, read_proofs  # noqa: E402
from vigil_integration.proof.sink import CAPTURE_KEY, ProofSink  # noqa: E402

_SIGNER = generate_keypair()
SIGNERS = [("gov0", _SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=_SIGNER.public_key_b64)])


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant(monkeypatch):
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path, host, slug="alpha"):
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `t`  Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n",
        encoding="utf-8")


# =========================================================================================================
# COLUMN 1 — the error-signature / captured-bytes mint: resemblance alone (a static error page) is a LEAD.
# =========================================================================================================
# A benign CONTROL response (S6) — a fetch of the same endpoint carrying NO datastore/parser error. The
# error-signature oracle's control-comparison guard confirms the exploit error is attributable only when it
# is ABSENT here; an always-erroring page (this body carrying the SAME error) is refused to a LEAD.
_BENIGN_CONTROL = b"HTTP/1.1 200 OK\r\n\r\n{\"items\": []}"


def _errsig_capture(*, with_request: bool, control: "bytes | None" = _BENIGN_CONTROL):
    """A capture whose RESPONSE carries a datastore error the oracle fires on. ``with_request`` also binds the
    exploit REQUEST bytes — the difference between a resemblance and an attributable finding (inv 6/8). By
    default it carries a benign CONTROL exchange (S6); pass ``control=None`` to omit it, or ``control=<error
    bytes>`` for an always-erroring page."""
    ex = {"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
          "status": 500, "bug_class": "error_based_sqli", "observed_scheme": "http"}
    exchanges = [ex]
    blobs = {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"}
    if with_request:
        ex["request_bytes_ref"] = "req"
        blobs["req"] = b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"
    if control is not None:
        exchanges.append({"channel": "error_signature", "role": "control", "response_bytes_ref": "ctrl"})
        blobs["ctrl"] = control
    return {"exchanges": exchanges, "blobs": blobs}


def test_a_static_error_page_with_no_bound_request_is_a_lead_not_a_fact(tmp_path):
    """The sharp false-FACT shape: an app that returns a datastore stack trace, with the RESPONSE captured but
    NO record of the request that produced it. VIGIL cannot attribute the response to an exploit it sent, so
    the finding must stay a LEAD — a certificate must never rest on a response with no bound request."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    res = mint({"id": "e1", "bug_class": "error_based_sqli", CAPTURE_KEY: _errsig_capture(with_request=False)})
    assert res is None, (
        "a datastore-error RESPONSE with no bound request minted a FACT — resemblance alone became a claim"
    )


def test_negative_control_a_request_bound_error_signature_CAN_mint(tmp_path):
    """Non-vacuity: bind the exploit REQUEST and the SAME error-signature capture mints — so the LEAD above is
    'resemblance is not enough', not 'this path never mints'."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    res = mint({"id": "e2", "bug_class": "error_based_sqli", CAPTURE_KEY: _errsig_capture(with_request=True)})
    assert res is not None and getattr(res, "is_fact", False), (
        "a request-bound datastore-error capture did not mint — the false-FACT controls would be vacuous"
    )


def test_a_role_relabelled_error_signature_still_cannot_mint_without_a_request(tmp_path):
    """RED-PEN-class bypass: the oracle adjudicates the observed exchange regardless of its ``role`` string,
    so a role="" (or any non-'mutated') response-only capture must ALSO stay a LEAD — the gate selects the
    same observed exchange the oracle does, not a literal role filter."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    for role in ("", "q", "observed"):
        cap = {"exchanges": [{"channel": "error_signature", "role": role, "response_bytes_ref": "resp",
                              "status": 500, "bug_class": "error_based_sqli"}],
               "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"}}
        res = mint({"id": f"e-{role or 'empty'}", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
        assert res is None, f"role={role!r} response-only capture minted instead of staying a LEAD"


def test_a_dangling_or_whitespace_request_ref_does_not_satisfy_the_binding(tmp_path):
    """The binding must RESOLVE to non-empty request bytes, not merely be a non-empty ref STRING — a dangling
    ref (no blob) or whitespace materializes nothing and must stay a LEAD."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    resp = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    for name, blobs, ref in [("dangling", {"resp": resp}, "req"),
                             ("ws-bytes", {"resp": resp, "req": b"   "}, "req"),
                             ("ws-ref", {"resp": resp}, "   ")]:
        cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                              "request_bytes_ref": ref, "status": 500, "bug_class": "error_based_sqli"}],
               "blobs": blobs}
        res = mint({"id": f"e-{name}", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
        assert res is None, f"{name}: an unresolvable request ref minted instead of staying a LEAD"


def test_a_report_with_no_capture_at_all_mints_nothing(tmp_path):
    """The model's free text alone is never a proof — a finding with no attached capture mints nothing."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    assert mint({"id": "x", "bug_class": "error_based_sqli", "poc_script_code": "print('x')"}) is None


# =========================================================================================================
# COLUMN 1b — the CONTROL exchange (S6): the oracle's control-comparison guard is now LIVE, not dead code.
# An error-signature FACT is attributable ONLY when the SAME datastore error is ABSENT from a benign control
# of the same endpoint. A page that ALWAYS errors — the error present in BOTH observed and control — can no
# longer mint; a missing control refuses to a LEAD; a genuine payload-only error still mints.
# =========================================================================================================
def test_an_always_erroring_page_same_signature_in_control_mints_no_fact(monkeypatch, tmp_path):
    """THE key false-FACT negative control this slice closes: the error is present in the exploit response AND
    in a benign CONTROL of the same endpoint (an always-erroring page), so it is NOT attributable to the
    payload. The oracle's control-comparison guard suppresses the fire ⇒ the finding stays a LEAD, never a
    signed FACT.

    Strengthened (BLOCK-1) with the case where the always-erroring page is LARGE and its datastore error sits
    PAST the benign-fetch read cap: a live control fetch captures only a truncated (error-free) PREFIX, so the
    control cannot be adjudicated over — ``benign_control_fetch`` refuses it (None) and the finding stays a
    LEAD. Returning the prefix would fire the oracle on a benign always-erroring page and mint a FALSE FACT."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    # the control carries the SAME datastore error as the exploit response
    always_erroring = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    cap = _errsig_capture(with_request=True, control=always_erroring)
    res = mint({"id": "always-err", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
    assert res is None or not getattr(res, "is_fact", False), (
        "an always-erroring page (same error in observed AND control) minted a FACT — the control guard is "
        "still dead: this is exactly the false-FACT this slice must close"
    )

    # BLOCK-1: the SAME always-erroring page, but LARGE — the datastore error sits PAST the benign-fetch read
    # cap, so a live control fetch captures only a truncated (error-free) prefix. It must be refused (None),
    # keeping the finding a LEAD; returning the prefix fires the oracle on a benign always-erroring page.
    from vigil_integration.live.body_decode import MAX_RAW_BYTES
    from vigil_integration.proof.bootstrap import _live_control_fetch
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    huge_err = b"A" * (MAX_RAW_BYTES + 4096) + b"ORA-00933: SQL command not properly ended"
    port = _serve_map({"/err": (200, "text/plain; charset=utf-8", huge_err)}).server_address[1]
    cap2 = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                           "request_bytes_ref": "req", "status": 500}],
            "blobs": {"resp": always_erroring,
                      "req": f"GET /err?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()}}
    mint2 = build_report_mint(run_dir=tmp_path / "huge", signers=SIGNERS, engagement_slug="alpha",
                              control_fetch=_live_control_fetch("alpha"))
    res2 = mint2({"id": "always-err-huge", "bug_class": "error_based_sqli",
                  "endpoint": f"http://127.0.0.1:{port}/err", CAPTURE_KEY: cap2})
    assert res2 is None or not getattr(res2, "is_fact", False), (
        "a LARGE always-erroring page (error past the read cap) minted a FACT — a truncated control prefix "
        "must be refused, not adjudicated over (BLOCK-1)"
    )


def test_a_missing_control_stays_a_lead_not_a_fact(tmp_path):
    """A request-bound datastore error with NO control captured and no control fetcher wired is UNattributable
    — VIGIL cannot show the error is payload-provoked rather than a permanent property of the page. The mint
    refuses to a LEAD (never silently skipping the control)."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")   # no control_fetch
    cap = _errsig_capture(with_request=True, control=None)                                  # no control exchange
    res = mint({"id": "no-ctrl", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
    assert res is None or not getattr(res, "is_fact", False), (
        "an error-signature capture with NO control minted a FACT — a missing control must stay a LEAD"
    )


def test_a_missing_control_is_rescued_by_a_wired_benign_control_fetch(tmp_path):
    """Non-vacuity for the control seam: when NO executor control is captured but a benign control FETCHER is
    wired (production ``bootstrap`` supplies one), the mint performs the second benign fetch, feeds it to the
    oracle, and — the benign control carrying no error — mints. A same-error fetcher would instead LEAD."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha",
                             control_fetch=lambda _r: _BENIGN_CONTROL)
    cap = _errsig_capture(with_request=True, control=None)
    res = mint({"id": "fetched-ctrl", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
    assert res is not None and getattr(res, "is_fact", False), (
        "a wired benign control fetch did not rescue the mint — the control seam is vacuous"
    )
    # a fetcher that returns the SAME error (always-erroring page, discovered live) must NOT mint
    mint_bad = build_report_mint(run_dir=tmp_path / "b", signers=SIGNERS, engagement_slug="alpha",
                                 control_fetch=lambda _r: b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended")
    res_bad = mint_bad({"id": "fetched-err", "bug_class": "error_based_sqli",
                        CAPTURE_KEY: _errsig_capture(with_request=True, control=None)})
    assert res_bad is None or not getattr(res_bad, "is_fact", False), (
        "a live control fetch that found the SAME error minted a FACT — the guard must suppress it"
    )


def test_the_control_gated_mint_is_deterministic(tmp_path):
    """Determinism: minting the SAME control-bound capture twice yields the SAME disposition, class and
    content-addressed proof id (no wallclock / rng enters the control path)."""
    def _mint_once(where):
        m = build_report_mint(run_dir=where, signers=SIGNERS, engagement_slug="alpha")
        return m({"id": "det-1", "bug_class": "error_based_sqli",
                  CAPTURE_KEY: _errsig_capture(with_request=True)})
    a = _mint_once(tmp_path / "a")
    b = _mint_once(tmp_path / "b")
    assert a is not None and b is not None
    assert (a.is_fact, a.bug_class, a.status) == (b.is_fact, b.bug_class, b.status)
    recs_a = {r["proof_id"] for r in read_proofs(tmp_path / "a")}
    recs_b = {r["proof_id"] for r in read_proofs(tmp_path / "b")}
    assert recs_a == recs_b and recs_a, "the control-gated mint is not deterministic across runs"


def _serve_map(routes):
    """A loopback server for the CONTROL-fetch tests. ``routes`` maps a path -> ``(status, content_type, body)``;
    any other path is a 404. A short write when the client caps its read (the truncation tests) is expected and
    swallowed."""
    class _App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hit = routes.get(urlsplit(self.path).path)
            if hit is None:
                self.send_response(404)
                self.end_headers()
                return
            status, ctype, body = hit
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:  # noqa: BLE001 — the client caps its read at MAX_RAW_BYTES; a short write is expected
                pass

        def log_message(self, *a):
            return

    srv = http.server.HTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_a_truncated_benign_control_refuses_and_stays_a_lead(monkeypatch, tmp_path):
    """BLOCK-1 (oracle soundness): the benign control is fetched under a ``MAX_RAW_BYTES`` read cap while the
    observed side is the UNCAPPED retained blob — an asymmetric capture. An always-erroring page whose datastore
    error sits PAST the cap yields a truncated-but-decodable control PREFIX with the error absent; returning it
    let the oracle fire (error in observed, not in the truncated control) and mint a FALSE FACT.
    ``benign_control_fetch`` must REFUSE a truncated body (None) so the mint degrades to a LEAD. This FAILS on
    the pre-fix tree (the prefix is returned and a FACT is minted)."""
    from vigil_integration.live.body_decode import MAX_RAW_BYTES
    from vigil_integration.live.web_redrive import benign_control_fetch
    from vigil_integration.proof.bootstrap import _live_control_fetch
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    huge_err = b"A" * (MAX_RAW_BYTES + 4096) + b"ORA-00933: SQL command not properly ended"  # error past the cap
    port = _serve_map({"/err": (200, "text/plain; charset=utf-8", huge_err),
                       "/small": (200, "application/json", b'{"items": []}')}).server_address[1]
    base = f"http://127.0.0.1:{port}"

    # unit: the guard REFUSES a truncated body, but STILL returns a fully-read benign body (non-vacuity — the
    # guard is not simply "always None").
    assert benign_control_fetch(f"{base}/err", slug="alpha") is None, (
        "benign_control_fetch returned a truncated control PREFIX instead of refusing (None) — BLOCK-1")
    assert benign_control_fetch(f"{base}/small", slug="alpha") is not None, (
        "benign_control_fetch refused a fully-read benign body — the truncation guard is over-broad/vacuous")

    # end-to-end: observed datastore error present + a wired LIVE control fetcher whose control is truncated.
    ora = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500}],
           "blobs": {"resp": ora,
                     "req": f"GET /err?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()}}
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha",
                             control_fetch=_live_control_fetch("alpha"))
    res = mint({"id": "trunc-ctrl", "bug_class": "error_based_sqli",
                "endpoint": f"{base}/err", CAPTURE_KEY: cap})
    assert res is None or not getattr(res, "is_fact", False), (
        "a truncated benign control (error past the read cap) minted a FALSE FACT — observed and control were "
        "captured asymmetrically and the oracle fired on a benign always-erroring page (BLOCK-1)")


def test_the_control_is_paired_to_the_observed_exchange_not_a_free_text_endpoint(tmp_path):
    """BLOCK-2 (control-selection correctness): the benign control MUST be the twin of the OBSERVED exchange's
    own captured request, not a separate free-text ``report['endpoint']``. Here the observed exchange is an
    always-erroring ``/api/search?q='`` but ``endpoint`` names a DIFFERENT, clean page ``/``. A control keyed to
    the free-text endpoint fetches the clean page (error absent) and mints a FALSE FACT; the mint must instead
    fetch the observed twin (``/api/search``, always-erroring) and stay a LEAD. FAILS on the pre-fix tree (the
    fetcher is asked for ``/`` and a FACT is minted)."""
    ora = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    asked: "list[str]" = []

    def _spy(report):
        url = str(report.get("endpoint") or "")
        asked.append(url)
        # the observed twin (/api/search) always errors; the free-text endpoint (/) is a clean, different page
        return ora if "/api/search" in url else _BENIGN_CONTROL

    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500, "observed_scheme": "http"}],
           "blobs": {"resp": ora, "req": b"GET /api/search?q=%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha", control_fetch=_spy)
    res = mint({"id": "paired", "bug_class": "error_based_sqli", "endpoint": "http://t/", CAPTURE_KEY: cap})
    assert res is None or not getattr(res, "is_fact", False), (
        "the control was fetched from the free-text endpoint (a different, clean page) instead of the observed "
        f"twin — an always-erroring path minted a FALSE FACT (BLOCK-2). the fetcher was asked for: {asked!r}")
    assert asked and all("/api/search" in u for u in asked), (
        f"the control fetch was not paired to the observed exchange /api/search; the fetcher was asked for {asked!r}")


def test_the_control_twin_scheme_is_paired_to_the_observed_not_defaulted_http(tmp_path):
    """MEDIUM residual (S6 scheme soundness): the benign control twin must be fetched over the SAME transport
    SCHEME as the OBSERVED exchange, never a silent http default. An origin-form request line carries no
    scheme; the free-text ``report['endpoint']`` scheme is NOT trusted unless it exact-matches the observed
    host+path. For an https observed always-erroring page whose endpoint does not name the same host+path, a
    defaulted-http control could be fetched from a DIVERGENT clean http twin (error absent) and mint a FALSE
    FACT. Two arms, both FAIL on the pre-fix tree (which derives an http twin and mints):

      * scheme UNCONFIRMABLE => the twin is REFUSED (LEAD); the control is never fetched over a guessed http;
      * a CARRIED observed https scheme => the twin is fetched over https, paired to the observed exchange."""
    ora = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"

    # ARM 1 - scheme UNCONFIRMABLE: an origin-form request whose ``endpoint`` names a DIFFERENT host, with no
    # carried scheme. A clean control returned for ANY fetch would fire the oracle and mint; the mint must
    # instead refuse the twin (LEAD) and NEVER fetch over a silently-defaulted http.
    asked1: "list[str]" = []

    def _clean1(report):
        asked1.append(str(report.get("endpoint") or ""))
        return _BENIGN_CONTROL                                # clean => if fetched at all, the oracle fires & mints

    cap1 = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                           "request_bytes_ref": "req", "status": 500}],
            "blobs": {"resp": ora, "req": b"GET /api/search?q=%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    mint1 = build_report_mint(run_dir=tmp_path / "u", signers=SIGNERS, engagement_slug="alpha", control_fetch=_clean1)
    res1 = mint1({"id": "unconfirmable", "bug_class": "error_based_sqli",
                  "endpoint": "http://other-host/", CAPTURE_KEY: cap1})
    assert res1 is None or not getattr(res1, "is_fact", False), (
        "an unconfirmable twin scheme silently defaulted to http, fetched a clean http control, and minted a "
        "FALSE FACT - the twin scheme must be paired to the observed exchange or refused to a LEAD")
    assert not any(u.startswith("http://") for u in asked1), (
        f"a control was fetched over a silently-defaulted http scheme - {asked1!r}")

    # ARM 2 - the observed scheme IS carried (https, e.g. from the proxy's TLS flag on the capture). The twin
    # must be fetched over https, PAIRED to the observed exchange, even though the free-text endpoint says http.
    asked2: "list[str]" = []

    def _clean2(report):
        asked2.append(str(report.get("endpoint") or ""))
        return _BENIGN_CONTROL

    cap2 = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                           "request_bytes_ref": "req", "status": 500, "observed_scheme": "https"}],
            "blobs": {"resp": ora, "req": b"GET /api/search?q=%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    mint2 = build_report_mint(run_dir=tmp_path / "s", signers=SIGNERS, engagement_slug="alpha", control_fetch=_clean2)
    mint2({"id": "confirmed-https", "bug_class": "error_based_sqli",
           "endpoint": "http://t/", CAPTURE_KEY: cap2})
    assert asked2 and all(u.startswith("https://") for u in asked2), (
        f"a carried observed https scheme was not used for the twin - the control was fetched over {asked2!r}, "
        "not the observed https (the twin scheme must be paired to the observed exchange, never the endpoint's)")


def test_no_endpoint_scheme_borrow_even_on_an_exact_host_path_match(tmp_path):
    """OBJECTION-2 (doctrine): when the observed capture carries NO transport scheme (``observed_scheme``
    absent), the twin scheme must NOT be borrowed from the free-text ``report['endpoint']`` — NOT EVEN when
    that endpoint EXACT-matches the observed host+path. A host+path match does not witness the TRANSPORT the
    response actually came back over (BLOCK-2 already distrusts the free-text endpoint); borrowing its http
    here would fetch a (possibly divergent) clean http control of an always-erroring https page and mint a
    FALSE FACT. The mint must fail closed to a LEAD and NEVER fetch over the guessed http.

    FAILS on the pre-fix tree — its priority-3 borrow takes the exact-match endpoint's http scheme, fetches a
    clean control, and mints a FACT."""
    ora = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    asked: "list[str]" = []

    def _clean(report):
        asked.append(str(report.get("endpoint") or ""))
        return _BENIGN_CONTROL                            # clean => if fetched at all, the oracle fires & mints

    # origin-form request (no in-band scheme), NO observed_scheme; the endpoint EXACT-matches host+path.
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500}],
           "blobs": {"resp": ora, "req": b"GET /api/search?q=%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha", control_fetch=_clean)
    res = mint({"id": "exact-match-no-borrow", "bug_class": "error_based_sqli",
                "endpoint": "http://t/api/search", CAPTURE_KEY: cap})           # EXACT host+path match, http scheme
    assert res is None or not getattr(res, "is_fact", False), (
        "an absent observed_scheme borrowed the exact-match endpoint's http scheme, fetched a clean control, "
        "and minted a FALSE FACT — the endpoint scheme must never CONFIRM the twin transport (objection-2)")
    assert not asked, (
        f"a control was fetched despite an unconfirmable transport scheme (endpoint-scheme borrow) - {asked!r}")

    # OBJECTION-4 (honest telemetry): host+path WAS derivable here (only the transport scheme was
    # unconfirmed), so the degradation cause must name the SCHEME reason, never the blanket "no host+path".
    from vigil_integration.proof import degradation as _deg
    _causes = {(c["kind"], c["where"]): c for c in _deg.read_degradations(tmp_path)}
    _scheme_cause = _causes.get((_deg.REDRIVE_FAILED, "proof.run.mint.control_scheme_unconfirmed"))
    assert _scheme_cause is not None, (
        f"the unconfirmed-scheme degradation was not recorded under its own cause — got {list(_causes)!r} "
        "(objection-4: the two None causes must be distinguished)")
    assert "scheme" in _scheme_cause["detail"].lower() and "host+path" not in _scheme_cause["detail"], (
        f"the degradation detail misreports the cause: {_scheme_cause['detail']!r} (objection-4)")
    assert (_deg.REDRIVE_FAILED, "proof.run.mint.control_unpairable") not in _causes, (
        "a scheme-unconfirmed twin was mislabelled as 'no derivable host+path' (objection-4)")


def test_observed_scheme_overrides_a_conflicting_in_band_request_target_scheme(tmp_path):
    """OBJECTION-3 (authority order): the transport TLS flag (``observed_scheme``) is the ground truth of HOW
    the observed response was obtained and is AUTHORITATIVE over the in-band absolute-form request-target
    scheme. A proxied ``GET http://t/api/search`` observed over TLS (``observed_scheme='https'``) is an HTTPS
    exchange; its benign twin must be fetched over https, NEVER the in-band http. Fetching http could hit a
    DIVERGENT clean http twin of an always-erroring https page and mint a FALSE FACT.

    FAILS on the pre-fix tree — its ``scheme = sp.scheme or _obs`` lets the in-band http win and fetches the
    control over http."""
    ora = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    asked: "list[str]" = []

    def _clean(report):
        asked.append(str(report.get("endpoint") or ""))
        return _BENIGN_CONTROL

    # absolute-form request target carrying an in-band http scheme, but the transport flag says https.
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500, "observed_scheme": "https"}],
           "blobs": {"resp": ora, "req": b"GET http://t/api/search?q=%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha", control_fetch=_clean)
    mint({"id": "obs-overrides-inband", "bug_class": "error_based_sqli",
          "endpoint": "http://t/", CAPTURE_KEY: cap})
    assert asked, "the twin was never fetched — the authoritative observed https scheme should produce a twin"
    assert all(u.startswith("https://") for u in asked), (
        "the in-band http request-target scheme overrode the authoritative observed https transport flag - the "
        f"control was fetched over {asked!r}, not https (objection-3: observed_scheme must be authoritative)")
    assert not any(u.startswith("http://") for u in asked), (
        f"a control was fetched over http despite an observed https transport - {asked!r}")


# =========================================================================================================
# COLUMN 2 — CLASS LAUNDERING: a certificate must never rename the vulnerability class it describes (S6).
# =========================================================================================================
def test_a_class_is_never_laundered_into_a_different_class(tmp_path):
    """A Strix LDAP-injection finding (CWE-90), with a request-bound response carrying an LDAP error the
    generic error-signature oracle fires on, must NOT be certified as ``error_based_sqli``. Either the true
    class is preserved, or the mint refuses — never a certificate that renames LDAP injection as SQL
    injection."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500},
                         {"channel": "error_signature", "role": "control", "response_bytes_ref": "ctrl"}],
           "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nInvalid DN syntax: LDAP: error code 34 - invalid DN",
                     "ctrl": _BENIGN_CONTROL,
                     "req": b"GET /dir?u=*)(uid=*) HTTP/1.1\r\nHost: t\r\n\r\n"}}
    res = mint({"id": "ldap-1", "cwe": "CWE-90", "finding_class": "ldap injection", CAPTURE_KEY: cap})
    assert res is not None and getattr(res, "status", "") == "fact", "a genuine LDAP error must still certify"
    assert getattr(res, "bug_class", "") == "ldap_injection", (
        "a CWE-90 LDAP-injection finding (LDAP error in the response) must certify as its TRUE class "
        f"ldap_injection, never renamed to SQLi. got {getattr(res, 'bug_class', None)!r}"
    )


def test_negative_control_an_explicit_true_class_is_preserved():
    """Non-vacuity for the laundering row: when the finding declares its class explicitly, the mapper keeps it
    — so the xfail above is about the CWE/title INFERENCE relabel, and this probe genuinely reads the class
    field the fix must respect."""
    assert _oracle_bug_class({"bug_class": "ldap_injection", "cwe": "CWE-90"}) == "ldap_injection"
    assert _oracle_bug_class({"bug_class": "xpath_injection", "cwe": "CWE-91"}) == "xpath_injection"


def _errsig_cap(err_body: bytes, *, control: bytes = _BENIGN_CONTROL):
    """An error-signature capture: a request-bound 500 whose response carries `err_body`, plus a benign
    CONTROL exchange (S6) so the mint's mandatory control-comparison is satisfied for a genuine finding."""
    return {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                           "request_bytes_ref": "req", "status": 500},
                          {"channel": "error_signature", "role": "control", "response_bytes_ref": "ctrl"}],
            "blobs": {"resp": b"HTTP/1.1 500\r\n\r\n" + err_body,
                      "ctrl": control,
                      "req": b"GET /x?u=1 HTTP/1.1\r\nHost: t\r\n\r\n"}}


def test_the_certificate_class_follows_the_oracle_engine_not_the_claim(tmp_path):
    """The load-bearing S6 property, in every direction: the signed class is the datastore/parser ENGINE the
    deterministic oracle MATCHED, never the finding's self-report. A mis-CWE'd, mis-titled, or even
    explicitly mis-declared finding cannot rename the class the evidence proves."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")

    # reverse mis-label: CWE-90 (LDAP) CLAIM but the response is a POSTGRES error -> the SQL evidence wins.
    r = mint({"id": "rev", "cwe": "CWE-90", "finding_class": "ldap injection",
              CAPTURE_KEY: _errsig_cap(b"PostgreSQL ERROR: syntax error at or near")})
    assert r is not None and r.status == "fact" and r.bug_class == "error_based_sqli", (
        f"a Postgres error must certify as error_based_sqli regardless of a CWE-90 claim; got {getattr(r,'bug_class',None)!r}")

    # precedence laundering: CWE-90 whose TITLE mentions SQL, but the response is an LDAP error -> LDAP wins.
    r = mint({"id": "prec", "cwe": "CWE-90", "finding_class": "ldap injection",
              "title": "blind sql injection style extraction",
              CAPTURE_KEY: _errsig_cap(b"Invalid DN syntax: LDAP: error code 34 - invalid DN")})
    assert r is not None and r.status == "fact" and r.bug_class == "ldap_injection", (
        f"an LDAP error must certify as ldap_injection even when the title says 'sql'; got {getattr(r,'bug_class',None)!r}")

    # explicit mis-declared class: an explicit bug_class=error_based_sqli on an LDAP-error finding -> LDAP wins.
    r = mint({"id": "expl", "cwe": "CWE-90", "bug_class": "error_based_sqli",
              CAPTURE_KEY: _errsig_cap(b"javax.naming.directory LDAPException: bad filter")})
    assert r is not None and r.status == "fact" and r.bug_class == "ldap_injection", (
        f"the oracle's LDAP engine must override an explicit error_based_sqli claim; got {getattr(r,'bug_class',None)!r}")

    # XPath, and the genuine SQL control (no regression).
    r = mint({"id": "xp", "cwe": "CWE-91", "finding_class": "xpath injection",
              CAPTURE_KEY: _errsig_cap(b"XPathException: Expression must evaluate to a node-set")})
    assert r is not None and r.status == "fact" and r.bug_class == "xpath_injection", getattr(r, "bug_class", None)
    r = mint({"id": "sql", "cwe": "CWE-89", "finding_class": "sql injection",
              CAPTURE_KEY: _errsig_cap(b"You have an error in your SQL syntax")})
    assert r is not None and r.status == "fact" and r.bug_class == "error_based_sqli", getattr(r, "bug_class", None)


def test_engine_map_covers_every_oracle_engine_and_all_targets_known():
    """Drift guard: every datastore/parser ENGINE the error-signature oracle can emit is mapped to a KNOWN
    bug_class — so a newly-added error signature can never silently fall through to the producer's
    (launderable) self-report, and no mapped class is one the verifier would demote as unknown."""
    from vigil_integration.proof.run import _ERRSIG_ENGINE_TO_CLASS
    from framework.v2.verify.oracles import _ERROR_SIGNATURES
    from framework.v2.verify.verifier import is_known_bug_class, normalize_bug_class

    engines = {engine for _pat, engine, _conf in _ERROR_SIGNATURES}
    missing = engines - set(_ERRSIG_ENGINE_TO_CLASS)
    assert not missing, f"error-signature engines with no bug_class mapping (would fall back to the claim): {missing}"
    for engine, cls in _ERRSIG_ENGINE_TO_CLASS.items():
        assert is_known_bug_class(normalize_bug_class(cls)), f"{engine} -> {cls!r} is not a known bug class"


def test_an_unmapped_oracle_engine_fails_closed_to_a_lead(tmp_path, monkeypatch):
    """Runtime backstop for the drift guard: if the error-signature oracle fires on an engine with NO entry
    in _ERRSIG_ENGINE_TO_CLASS, the mint REFUSES (LEAD) and records a degradation — it never falls back to
    the producer's claim-derived class. So a future signature added without a map entry cannot re-open
    laundering even if the CI drift test is bypassed."""
    import vigil_integration.proof.run as run_mod
    from vigil_integration.proof.degradation import DEGRADED_NAME, PROOFS_SUBDIR
    monkeypatch.setattr(run_mod, "_ERRSIG_ENGINE_TO_CLASS",
                        {k: v for k, v in run_mod._ERRSIG_ENGINE_TO_CLASS.items() if k != "ldap"})
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    res = mint({"id": "unmapped", "cwe": "CWE-90", "bug_class": "error_based_sqli",
                CAPTURE_KEY: _errsig_cap(b"Invalid DN syntax: LDAP: error code 34 - invalid DN")})
    assert res is None, f"a fired-but-unmapped engine must fail closed to a LEAD, not mint; got {res!r}"
    deg = tmp_path / PROOFS_SUBDIR / DEGRADED_NAME
    assert deg.is_file() and "unmapped_engine" in deg.read_text(encoding="utf-8"), (
        "the fail-closed refusal must be recorded as a degradation so it cannot read as CLEAN")


# =========================================================================================================
# COLUMN 3 — the web re-drive sink: a benign endpoint that only RESEMBLES a finding mints nothing.
# =========================================================================================================
class _WebApp(http.server.BaseHTTPRequestHandler):
    """A REAL open-redirect + a SAFE reflection endpoint on the same loopback server."""

    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        if parts.path == "/redirect":                        # VULNERABLE: reflects `next` into Location
            self.send_response(302)
            self.send_header("Location", (q.get("next") or [""])[0])
            self.end_headers()
        elif parts.path == "/safe":                          # SAFE: reflects into the body as plain text
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"you asked for: {(q.get('next') or [''])[0]}".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        return


def _serve():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _WebApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _sink(tmp_path):
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="alpha")
    return ProofSink(quarantine_dir=str(tmp_path / "q"), mint=mint)


def test_a_benign_endpoint_that_resembles_a_redirect_mints_nothing(monkeypatch, tmp_path):
    """THE load-bearing web false-FACT control: a finding claims an open redirect at ``/safe``, but VIGIL's
    own gated probe shows the reflection never reaches the Location header. The would-be claim is refuted; no
    FACT is minted."""
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    port = _serve().server_address[1]
    out = _sink(tmp_path)({"id": "w1", "bug_class": "open_redirect",
                           "endpoint": f"http://127.0.0.1:{port}/safe?next=http://canary.evil.example/"})
    assert out.gate == "allow" and out.minted is False, (
        "a benign endpoint minted a FACT — VIGIL's re-drive did not refute the resemblance"
    )


def test_negative_control_a_truly_vulnerable_endpoint_DOES_mint(monkeypatch, tmp_path):
    """Non-vacuity: the SAME sink against a genuinely vulnerable ``/redirect`` mints a FACT off VIGIL's own
    fresh capture — so 'benign mints nothing' is a refutation, not a sink that never mints."""
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    port = _serve().server_address[1]
    out = _sink(tmp_path)({"id": "w2", "bug_class": "open_redirect",
                           "endpoint": f"http://127.0.0.1:{port}/redirect?next=http://canary.evil.example/"})
    assert out.gate == "allow" and out.minted is True, (
        "a live open redirect did not mint via VIGIL's re-drive — the web false-FACT control would be vacuous"
    )


def test_an_out_of_scope_endpoint_is_refused_and_mints_nothing(monkeypatch, tmp_path):
    """A finding pointing at a host the charter does not authorise is refused BEFORE any traffic — resemblance
    outside scope is not even probed, let alone certified."""
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")           # authorises 127.0.0.1 only
    out = _sink(tmp_path)({"id": "w3", "bug_class": "open_redirect",
                           "endpoint": "http://198.51.100.7/redirect?next=http://evil.example/"})
    assert out.minted is False, "an out-of-charter endpoint minted — the pre-flight gate did not refuse"


def test_a_no_channel_probe_is_inconclusive_not_a_fact(monkeypatch, tmp_path):
    """A closed port on an in-scope host establishes no channel → INCONCLUSIVE, never a FACT. 'Found nothing'
    (could not connect) must not become a claim in EITHER direction."""
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    out = _sink(tmp_path)({"id": "w4", "bug_class": "open_redirect",
                           "endpoint": "http://127.0.0.1:1/redirect?next=http://evil.example/"})
    assert out.minted is False, "a no-channel probe minted a FACT"


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_no_row_is_a_non_strict_xfail():
    """A non-strict xfail would swallow an XPASS and the board would stop self-updating when S6 lands."""
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a fix"
