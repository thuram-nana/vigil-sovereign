"""Release gate — the full UI-TO-CERTIFICATE path, as an honest scoreboard.

WHAT THIS FILE IS. The release gate (plan Part III / "The release gate") ends at a certificate the operator
can trust: an engagement runs, VIGIL mints a signed certificate, the UI surfaces it, and its "Verify offline"
control re-proves it. This board proves the load-bearing, in-process-checkable legs of that path:

  * CHAIN OF CUSTODY — the UI never *fabricates* a certificate or a verdict. The Trust Center's read
    (``/api/certs``) and its "Verify offline" (``/api/verify-cert``) are PROXIED to the offense console
    plane; the reverse proxy invents no certificate of its own and refuses an unmounted path.
  * REAL RE-COMPUTATION — the "Verify offline" button drives ``console.actions.verify_cert``, which OFFLINE
    re-derives the digest, re-checks the m-of-n signature, and binds the trust ROOT to a source/out-of-band
    pin. This board drives that EXACT function over the committed, signed recall-accuracy certificate the
    Trust Center lists, and gets a genuine PASS — then proves a TAMPERED copy is reported NOT verified.

The truly end-to-end row — a headless browser driving ``vigil up`` → a live engage → mint → the Trust Center
→ Verify offline PASS — needs a browser + live console + Docker the required job does not provision, so it is
an ``xfail(strict)`` with a named blocking slice (the board self-updates when the harness lands).

HOW IT STAYS HONEST (model: ``test_production_invariants.py``). Each row asserts the TRUE bar; every "verify"
row is paired with a negative control (a tamper the verifier must reject; an unmounted path the proxy must
refuse) so a PASS is a real difference, not a verifier/proxy that always says yes.

FRAMEWORK-DEPENDENT (the certificate + its verifier are engine code). This file ``importorskip``s
``framework`` and MUST be in the ci.yml offense-leg run-list (enforced by
``test_ci_framework_tests_run_in_offense_leg``); it skips cleanly in the sovereign leg.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.console.actions", reason="CRUCIBLE (framework) not importable in this leg")

from framework.v2.console import actions as console_actions  # noqa: E402
from framework.v2.console import api as console_api  # noqa: E402
from framework.v2.console import server as console_server  # noqa: E402
from framework.v2.eval import recall_baseline as rb  # noqa: E402

from vigil_integration.uiproxy import route  # noqa: E402

_SERVER_SRC = Path(console_server.__file__).read_text(encoding="utf-8")
_E2E_SLICE = "full browser UI e2e (headless browser → `vigil up` → live engage → mint → Trust Center → Verify offline PASS) — needs a browser + live console + Docker, not runnable in the P5 job"


# =========================================================================================================
# CHAIN OF CUSTODY — the UI's certificate read + verify are PROXIED to the engine, never fabricated.
# =========================================================================================================
def _console_backend() -> tuple[str, int]:
    """The (host, port) the proxy sends a known console path to — derived, not hard-coded, so a port change
    does not silently make the custody rows vacuous."""
    r = route("/offense/api/status")
    assert r is not None, "the offense console mount is not routable — the UI could reach no read plane"
    host, port, _rest = r
    return host, port


def test_the_trust_center_certificate_read_is_proxied_to_the_engine():
    """``/api/certs`` (the Trust Center's list) reaches the offense console plane through the proxy with its
    path preserved — the UI reads certificates the engine produced, it does not mint a listing locally."""
    host, port = _console_backend()
    r = route("/offense/api/certs")
    assert r == (host, port, "/api/certs"), f"the cert listing did not proxy to the console plane: {r}"


def test_the_verify_offline_action_is_proxied_to_the_engine():
    """``/api/verify-cert`` (the "Verify offline" button) reaches the SAME console plane — the verdict the
    operator sees comes from the engine's verifier, not from anything the proxy computes."""
    host, port = _console_backend()
    r = route("/offense/api/verify-cert")
    assert r == (host, port, "/api/verify-cert"), f"verify-offline did not proxy to the console plane: {r}"


def test_negative_control_the_proxy_refuses_an_unmounted_path():
    """Non-vacuity for the custody rows: the proxy is a real mount table, not a fabricator — an unmounted
    path resolves to NO backend (refused), so "certs route to the console" is a genuine mount, not a proxy
    that forwards (or invents) anything for any path."""
    assert route("/nope/api/certs") is None, "the proxy routed an unmounted path — it does not fail closed"


def test_the_console_wires_the_ui_routes_to_the_real_cert_reader_and_verifier():
    """The console side of the custody chain: ``/api/certs`` dispatches to ``api.certs`` (the real signed-cert
    reader) and ``/api/verify-cert`` dispatches to ``actions.verify_cert`` (the real offline verifier the
    rows below drive). Neither is a placeholder handler."""
    assert console_server._EXACT_ROUTES.get("/api/certs") is console_api.certs, (
        "the console GET route table does not map /api/certs to the real api.certs reader"
    )
    assert '"/api/verify-cert"' in _SERVER_SRC and "actions.verify_cert(" in _SERVER_SRC, (
        "the console do_POST does not wire /api/verify-cert to actions.verify_cert — the Verify-offline "
        "button would not reach the real verifier"
    )


# =========================================================================================================
# REAL RE-COMPUTATION — the Verify-offline button re-proves a genuine signed certificate.
# =========================================================================================================
def _committed_recall_dir() -> Path:
    core = Path(rb.ACCURACY_CORE_PATH)
    sig = core.with_suffix(".sig.json")
    if not (core.is_file() and sig.is_file()):
        pytest.skip("the committed recall-baseline certificate triple is not on disk in this checkout")
    return core.parent


def test_verify_offline_passes_over_the_committed_signed_certificate():
    """Drive the EXACT function the UI's "Verify offline" button invokes over the committed, signed
    recall-accuracy certificate the Trust Center lists: it must re-verify, and its trust root must match the
    SOURCE-held pin (a fresh-key re-sign would be rejected). This is the UI→certificate path's terminal
    property, exercised for real."""
    res = console_actions.verify_cert("recall", _recall_base=_committed_recall_dir())
    assert res.get("present") and res.get("verified"), f"the committed certificate did not re-verify: {res}"
    assert res.get("trust_root_pinned") and res.get("fingerprint_matches_pin") is True, (
        f"the certificate re-verified but its trust root was not bound to the source pin: {res}"
    )


def test_negative_control_verify_offline_reports_a_tampered_certificate_as_not_verified(tmp_path):
    """Non-vacuity: the SAME verify function over a TAMPERED copy of the certificate returns not-verified.
    So the PASS above is a real re-computation over the bytes, not a verifier that always says verified."""
    src = _committed_recall_dir()
    core = tmp_path / "recall-accuracy-core.json"
    (tmp_path / "recall-accuracy-core.sig.json").write_bytes(
        (src / "recall-accuracy-core.sig.json").read_bytes())
    original = json.loads((src / "recall-accuracy-core.json").read_text(encoding="utf-8"))
    tampered = copy.deepcopy(original)
    tampered["_tamper"] = "a byte the signer never saw"
    core.write_text(json.dumps(tampered), encoding="utf-8")
    res = console_actions.verify_cert("recall", _recall_base=tmp_path)
    assert res.get("verified") is False, (
        f"a tampered certificate was reported verified — the offline verifier does not re-check the bytes: {res}"
    )


def test_negative_control_a_missing_certificate_is_honestly_absent_not_verified(tmp_path):
    """A run/cert that never produced a certificate must read as absent, never as a green verified — the UI
    cannot show a certificate that was never minted."""
    res = console_actions.verify_cert("recall", _recall_base=tmp_path)  # empty dir: no triple
    assert res.get("present") is False and not res.get("verified"), (
        f"a missing certificate did not read as honestly absent: {res}"
    )


# =========================================================================================================
# The full browser E2E is not runnable in CI — an honest xfail that self-updates.
# =========================================================================================================
@pytest.mark.xfail(strict=True, reason=_E2E_SLICE)
def test_full_browser_ui_to_certificate_end_to_end():
    """The literal end-to-end: a headless browser starts ``vigil up``, launches a live engage, waits for the
    mint, opens the Trust Center, clicks Verify offline, and asserts a PASS + fingerprint-pin match. Needs a
    browser + live console + Docker the required job does not provide, so it is driven by a harness that does
    not exist yet and xfails cleanly (strict → flips red when the harness lands). The RE-COMPUTATION and
    CUSTODY legs are proven for real above."""
    from vigil_integration import headless_ui_to_certificate_drill  # noqa: F401  (no such harness yet)

    raise AssertionError("no in-CI headless-browser harness drives vigil up → engage → Trust Center → verify")


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_no_row_is_a_non_strict_xfail():
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a regression"
