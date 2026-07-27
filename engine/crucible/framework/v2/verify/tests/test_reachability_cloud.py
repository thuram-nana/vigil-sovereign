"""
Tests for Slice C3 — the active-exposure oracle (anonymous reachability of a public cloud resource).

A cloud POSTURE fact ("this bucket is public") is a statement about CONFIGURATION; it becomes a
reachability FACT only when a bounded, GATED, UNAUTHENTICATED HTTP GET actually reaches it. These cover
the pure oracle (judge a retained capture), the per-provider URL builders, the FindingContext carrier +
offline re-verification (the retained JSON-safe capture re-confirms with no network), and the gated,
bounded, credential-free active capture — with an injected connector, a real loopback HTTP server (a
genuine anonymous request), and every fail-closed refusal.
"""

from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path

import pytest

from framework.v2.verify import (
    OracleVerifier,
    anonymous_reachable_oracle,
    azure_blob_url,
    capture_anonymous_get,
    confirm_anonymous_reachable,
    gcs_public_url,
    s3_public_url,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.reachability_cloud import anonymous_capture_context
from framework.v2.verify.reverify import reverify_context


# ---- the pure oracle -------------------------------------------------------


def test_oracle_fires_on_an_unauthenticated_2xx_with_a_body() -> None:
    sig = anonymous_reachable_oracle(
        {"url": "https://b.s3.amazonaws.com/", "status": 200, "body_len": 128,
         "content_type": "application/xml", "authenticated": False})
    assert sig.fired and sig.confidence >= 0.7 and "s3.amazonaws.com" in sig.evidence


@pytest.mark.parametrize("status", [200, 201, 206, 299])
def test_oracle_fires_across_the_2xx_band_with_a_present_body(status: int) -> None:
    assert anonymous_reachable_oracle({"status": status, "body_len": 1}).fired


@pytest.mark.parametrize("cap", [
    {"status": 401, "body_len": 50},                       # present-but-protected — the OPPOSITE claim
    {"status": 403, "body_len": 50},                       # AccessDenied
    {"status": 404, "body_len": 50},                       # absent
    {"status": 301, "body_len": 50},                       # redirect (not a fetched success)
    {"status": 302, "body_len": 50},
    {"status": 500, "body_len": 50},                       # server error
    {"status": 200, "body_len": 0},                        # empty body (no content actually served)
    {"status": None, "body_len": 0, "error": "refused"},   # gate refusal / connect failure
    {"status": 200, "body_len": 10, "authenticated": True},  # authed -> cannot prove ANONYMOUS
    "not a mapping",
    {},
])
def test_oracle_does_not_fire_without_an_anonymous_2xx_with_a_body(cap) -> None:
    assert anonymous_reachable_oracle(cap).fired is False


def test_oracle_refuses_an_authenticated_capture_even_on_2xx() -> None:
    # a 2xx WITH a body but flagged authenticated must NOT confirm anonymous reachability
    sig = anonymous_reachable_oracle({"status": 200, "body_len": 999, "authenticated": True})
    assert not sig.fired and "ANONYMOUS" in sig.evidence


# ---- verifier routing + FindingContext carrier -----------------------------


def test_anonymous_reachable_routes_to_the_active_exposure_oracle() -> None:
    res = OracleVerifier().confirm(
        {"bug_class": "anonymous_reachable",
         "anon_get": {"status": 200, "body_len": 64, "authenticated": False}})
    assert res.confirmed and res.bug_class == "anonymous_reachable"


def test_finding_context_carries_the_capture_through_to_the_verifier() -> None:
    ctx = FindingContext.from_anonymous_capture({"status": 200, "body_len": 8})
    vctx = ctx.to_verifier_context()
    assert vctx["bug_class"] == "anonymous_reachable" and vctx["anon_get"]["body_len"] == 8
    assert OracleVerifier().confirm(vctx).confirmed


def test_a_403_capture_does_not_confirm() -> None:
    assert not confirm_anonymous_reachable({"status": 403, "body_len": 20}).confirmed


# ---- offline re-verification (prove-don't-guess: re-execute over retained evidence) ----


def test_confirmed_exposure_reverifies_offline_from_its_retained_context() -> None:
    cap = {"url": "https://acme-public.s3.amazonaws.com/", "status": 200, "body_len": 256,
           "snippet": "<ListBucketResult>...", "content_type": "application/xml", "authenticated": False}
    oracle_context = anonymous_capture_context(cap)
    # no network, no trust in the capturer — re-run the pure oracle over the retained evidence
    r = reverify_context(oracle_context, bug_class="anonymous_reachable")
    assert r.reproduced and r.ok
    # and the context is JSON-serialisable (the property that makes offline re-verify possible)
    json.dumps(oracle_context)


# ---- the per-provider URL builders (pure + total) --------------------------


def test_url_builders_construct_the_public_read_endpoints() -> None:
    assert s3_public_url("acme-assets") == "https://acme-assets.s3.amazonaws.com/"
    assert gcs_public_url("acme-assets") == "https://storage.googleapis.com/acme-assets"
    assert (azure_blob_url("acmestore", "public")
            == "https://acmestore.blob.core.windows.net/public?restype=container&comp=list")


@pytest.mark.parametrize("bad", ["", "  ", "evil/../x", "a@b", "bucket/key", "UP PER", "-lead", ".dot",
                                 "a:b", "x?y", "http://evil"])
def test_url_builders_reject_labels_that_could_smuggle_a_host_or_path(bad: str) -> None:
    # a malformed label yields "" (no probe, no fact) — the URL can never point off the provider host
    assert s3_public_url(bad) == ""
    assert gcs_public_url(bad) == ""
    assert azure_blob_url(bad, "ok") == "" and azure_blob_url("ok", bad) == ""


# ---- the gated, bounded, UNAUTHENTICATED active capture --------------------


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


def test_capture_with_an_injected_connector_confirms(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "acme-public.s3.amazonaws.com")
    cap = capture_anonymous_get(
        "https://acme-public.s3.amazonaws.com/", slug="alpha",
        connect=lambda url, timeout: (200, {"Content-Type": "application/xml"}, b"<ListBucketResult/>"))
    assert cap["status"] == 200 and cap["body_len"] > 0 and cap["authenticated"] is False
    assert cap["content_type"] == "application/xml"
    assert confirm_anonymous_reachable(cap).confirmed


def test_capture_turns_a_connect_failure_into_a_clean_negative(monkeypatch, tmp_path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "acme-public.s3.amazonaws.com")

    def _boom(url, timeout):
        raise ConnectionResetError("reset")

    cap = capture_anonymous_get("https://acme-public.s3.amazonaws.com/", slug="alpha", connect=_boom)
    assert cap["status"] is None and "Reset" in cap["error"]
    assert not confirm_anonymous_reachable(cap).confirmed


def test_capture_records_a_non_2xx_status_and_does_not_confirm(monkeypatch, tmp_path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "acme-public.s3.amazonaws.com")
    cap = capture_anonymous_get(
        "https://acme-public.s3.amazonaws.com/", slug="alpha",
        connect=lambda url, timeout: (403, {"Content-Type": "application/xml"}, b"<Error>AccessDenied</Error>"))
    assert cap["status"] == 403 and not confirm_anonymous_reachable(cap).confirmed


def test_capture_with_no_slug_is_refused_never_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    _grant_active_recon(monkeypatch)
    called = {"n": 0}
    cap = capture_anonymous_get(
        "https://acme-public.s3.amazonaws.com/",
        connect=lambda url, timeout: (called.update(n=1) or (200, {}, b"x")))
    assert cap["status"] is None and "slug" in cap["error"] and called["n"] == 0


def test_capture_kill_switch_refuses_and_never_connects(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "acme-public.s3.amazonaws.com")
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("halt")
    called = {"n": 0}

    def _spy(url, timeout):
        called["n"] += 1
        return (200, {}, b"x")

    cap = capture_anonymous_get("https://acme-public.s3.amazonaws.com/", slug="alpha", connect=_spy)
    assert cap["status"] is None and "kill-switch" in cap["error"] and called["n"] == 0


def test_capture_requires_the_active_recon_entitlement(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _charter(tmp_path, "acme-public.s3.amazonaws.com")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability",
                        lambda cap: (_ for _ in ()).throw(RuntimeError("not entitled")))
    called = {"n": 0}
    cap = capture_anonymous_get(
        "https://acme-public.s3.amazonaws.com/", slug="alpha",
        connect=lambda url, timeout: (called.update(n=1) or (200, {}, b"x")))
    assert cap["status"] is None and "not entitled" in cap["error"] and called["n"] == 0


def test_capture_out_of_scope_host_refused_never_connects(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "acme-public.s3.amazonaws.com")   # a DIFFERENT bucket host is in scope
    called = {"n": 0}
    cap = capture_anonymous_get(
        "https://attacker-bucket.s3.amazonaws.com/", slug="alpha",
        connect=lambda url, timeout: (called.update(n=1) or (200, {}, b"x")))
    assert cap["status"] is None and "scope" in cap["error"] and called["n"] == 0


@pytest.mark.parametrize("bad_url", [
    "ftp://acme-public.s3.amazonaws.com/",           # non-http(s) scheme
    "file:///etc/passwd",                            # file scheme
    "https://user:pass@acme-public.s3.amazonaws.com/",  # embedded credentials
    "https://acme-public.s3.amazonaws.com,evil/",    # not a single host
])
def test_capture_rejects_unsafe_urls_never_connects(monkeypatch, tmp_path, bad_url) -> None:
    _grant_active_recon(monkeypatch)
    # scope the base host so ONLY the URL-shape check can be what refuses these
    _charter(tmp_path, "acme-public.s3.amazonaws.com")
    called = {"n": 0}
    cap = capture_anonymous_get(
        bad_url, slug="alpha", connect=lambda url, timeout: (called.update(n=1) or (200, {}, b"x")))
    assert cap["status"] is None and "error" in cap and called["n"] == 0


# ---- a REAL loopback GET: genuinely anonymous, redirects not followed ------


def _serve_once(handler_cls) -> "http.server.HTTPServer":
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    return srv


def test_real_loopback_get_is_unauthenticated_and_confirms(monkeypatch, tmp_path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    seen: dict = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen["headers"] = {k.lower(): v for k, v in self.headers.items()}
            body = b"<ListBucketResult><Contents/></ListBucketResult>"
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # silence
            return

    srv = _serve_once(H)
    port = srv.server_address[1]
    try:
        cap = capture_anonymous_get(f"http://127.0.0.1:{port}/", slug="alpha")
    finally:
        srv.server_close()
    # a genuine anonymous request — the server saw NO credential headers
    assert cap["status"] == 200 and cap["body_len"] > 0
    assert "authorization" not in seen["headers"] and "cookie" not in seen["headers"]
    assert cap["authenticated"] is False
    assert confirm_anonymous_reachable(cap).confirmed


def test_real_loopback_redirect_is_not_followed_and_does_not_confirm(monkeypatch, tmp_path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "https://example.com/elsewhere")
            self.end_headers()

        def log_message(self, *a):
            return

    srv = _serve_once(H)
    port = srv.server_address[1]
    try:
        cap = capture_anonymous_get(f"http://127.0.0.1:{port}/", slug="alpha")
    finally:
        srv.server_close()
    # the 3xx is captured verbatim (NOT chased into a 200 elsewhere) and does not confirm
    assert cap["status"] == 302 and not confirm_anonymous_reachable(cap).confirmed


def test_snippet_is_bounded_and_redacts_credential_shaped_tokens(monkeypatch, tmp_path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "acme-public.s3.amazonaws.com")
    leaky = b"key=AKIAIOSFODNN7EXAMPLE and secret=" + b"a" * 60
    cap = capture_anonymous_get(
        "https://acme-public.s3.amazonaws.com/", slug="alpha",
        connect=lambda url, timeout: (200, {"Content-Type": "text/plain"}, leaky))
    assert len(cap["snippet"]) <= 256
    assert "AKIAIOSFODNN7EXAMPLE" not in cap["snippet"] and "aaaaaaaa" not in cap["snippet"]
    assert "<redacted>" in cap["snippet"]
