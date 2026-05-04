"""
Tests for UTI.

Strategy:

  - Detector tests use synthetic HTTPExchange fixtures so they do not
    need a network.  The fixtures are realistic enough to fire each
    detector's signature classes.
  - Classifier tests build Fingerprints by hand and verify the right
    archetype wins.
  - Drafter / scaffolder tests run against a temp dir.
  - End-to-end intake tests use a Fetcher in fixture-replay mode.
  - The live integration test is opt-in via CRUCIBLE_LIVE_INTAKE_URL
    pointing at any operator-authorised target, and respects the
    intake request budget.

Per the operator's directive (replacing FORGE PROTOCOL § 4.9), the
intake correctness bar is "unit tests against captured fixtures plus
one optional live test against any operator-authorised URL".
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from framework.v2.common import ethics, paths
from framework.v2.common.errors import AuthorizationMissing
from framework.v2.intake import (
    archetypes, intake as intake_mod, scaffolder, stack_classifier,
)
from framework.v2.intake.fingerprint import (
    api_detection, auth_detection, cdn_waf_detection, cms_detection,
    framework_detection, payment_detection, server_detection,
)
from framework.v2.intake.http import Fetcher
from framework.v2.intake.models import Fingerprint, HTTPExchange


# ---------------------------------------------------------------------------
# Synthetic HTTPExchange builders
# ---------------------------------------------------------------------------


def _ex(
    *,
    url: str = "https://example.com/",
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: str = "",
    cookies: dict[str, str] | None = None,
) -> HTTPExchange:
    return HTTPExchange(
        method="GET", url=url, status=status,
        headers=headers or {}, body_excerpt=body,
        cookies=cookies or {},
    )


# ---------------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------------


def test_server_detection_nginx() -> None:
    exs = [_ex(headers={"Server": "nginx/1.21.6"})]
    r = server_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "nginx" in labels


def test_framework_detection_laravel() -> None:
    exs = [_ex(
        url="https://x.example/login",
        headers={"X-Powered-By": "PHP/8.1"},
        cookies={"laravel_session": "abc", "XSRF-TOKEN": "def"},
        body='<meta name="csrf-token" content="abc">',
    )]
    r = framework_detection.detect(exs)
    labels = [d.label for d in r.detections]
    assert "laravel" in labels
    laravel = next(d for d in r.detections if d.label == "laravel")
    assert laravel.confidence > 0.9


def test_framework_detection_nextjs() -> None:
    exs = [_ex(
        headers={"X-Powered-By": "Next.js"},
        body='<script id="__NEXT_DATA__" type="application/json">{}</script>',
    )]
    r = framework_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "nextjs" in labels


def test_framework_detection_wordpress_via_meta() -> None:
    exs = [_ex(
        body='<meta name="generator" content="WordPress 6.4.2">',
    )]
    r = framework_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "wordpress" in labels


def test_cms_detection_wordpress_path() -> None:
    exs = [_ex(url="https://x.example/wp-content/themes/twentytwentythree/style.css")]
    r = cms_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "wordpress" in labels


def test_cms_detection_perfect_panel() -> None:
    exs = [_ex(
        body='<script src="https://cdn.glycon.net/panel/main.js"></script>',
    )]
    r = cms_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "perfect-panel" in labels


def test_auth_detection_oidc_well_known() -> None:
    exs = [_ex(
        url="https://x.example/.well-known/openid-configuration",
        body='{"issuer":"https://x.example","authorization_endpoint":"https://x.example/oauth/authorize"}',
    )]
    r = auth_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "oidc" in labels


def test_auth_detection_form_login() -> None:
    exs = [_ex(
        url="https://x.example/login",
        body='<form action="/login" method="post"><input type="password" name="pw"></form>',
    )]
    r = auth_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "form-login" in labels


def test_api_detection_graphql() -> None:
    exs = [_ex(url="https://x.example/graphql", body="GraphQL Playground")]
    r = api_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "graphql" in labels


def test_api_detection_openapi() -> None:
    exs = [_ex(url="https://x.example/openapi.json", body='{"openapi":"3.0.0"}')]
    r = api_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "openapi" in labels


def test_payment_detection_cryptomus() -> None:
    exs = [_ex(body='Pay with crypto via <a href="https://api.cryptomus.com/v1">Cryptomus</a>')]
    r = payment_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "cryptomus" in labels


def test_cdn_waf_detection_cloudflare() -> None:
    exs = [_ex(headers={"Server": "cloudflare", "CF-Ray": "abc-DFW"})]
    r = cdn_waf_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert "cloudflare" in labels


def test_cdn_waf_detection_security_headers() -> None:
    exs = [_ex(headers={
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
    })]
    r = cdn_waf_detection.detect(exs)
    labels = {d.label for d in r.detections}
    assert {"hsts", "csp", "xfo"} <= labels


# ---------------------------------------------------------------------------
# Stack classifier
# ---------------------------------------------------------------------------


def _fingerprint_from_exchanges(exs: list[HTTPExchange]) -> Fingerprint:
    """Build a Fingerprint by running every detector — same as intake."""
    from framework.v2.intake import fingerprint as fp_pkg
    detectors = {name: fn(exs) for name, fn in fp_pkg.ALL_DETECTORS}
    return Fingerprint(
        target_url=exs[0].url if exs else "https://example.com",
        detectors=detectors,
    )


def test_classify_picks_perfect_panel() -> None:
    exs = [_ex(
        body=(
            '<script src="https://cdn.glycon.net/panel/main.js"></script>'
            '<a href="https://api.cryptomus.com/v1">Cryptomus</a>'
        ),
        headers={"Server": "nginx", "X-Powered-By": "PHP/7.4"},
    )]
    fp = _fingerprint_from_exchanges(exs)
    cl = stack_classifier.classify(fp)
    assert cl.primary.archetype.slug == "php-smarty-smm-panel-fork"
    assert cl.primary.score > 0


def test_classify_picks_laravel_marketplace() -> None:
    exs = [_ex(
        url="https://shop.example/login",
        headers={"X-Powered-By": "PHP/8.1"},
        cookies={"laravel_session": "abc", "XSRF-TOKEN": "def"},
        body=(
            '<meta name="csrf-token" content="x">'
            '<script src="https://js.stripe.com/v3/"></script>'
        ),
    )]
    fp = _fingerprint_from_exchanges(exs)
    cl = stack_classifier.classify(fp)
    assert cl.primary.archetype.slug == "laravel-marketplace"


def test_classify_picks_nextjs_saas() -> None:
    exs = [_ex(
        headers={"X-Powered-By": "Next.js", "Server": "Vercel"},
        body='<script id="__NEXT_DATA__"></script>',
    )]
    fp = _fingerprint_from_exchanges(exs)
    cl = stack_classifier.classify(fp)
    assert cl.primary.archetype.slug == "nextjs-saas"


def test_classify_falls_back_to_generic() -> None:
    exs = [_ex(headers={"Server": "Caddy"}, body="<html><body>hi</body></html>")]
    fp = _fingerprint_from_exchanges(exs)
    cl = stack_classifier.classify(fp)
    assert cl.primary.archetype.slug == "generic-web"


# ---------------------------------------------------------------------------
# Drafters
# ---------------------------------------------------------------------------


def test_drafters_charter_contains_unsigned_marker() -> None:
    fp = Fingerprint(target_url="https://x.example")
    cl = stack_classifier.classify(fp)
    from framework.v2.intake import drafters
    body = drafters.draft_charter(
        slug="x-example", target_host="x.example",
        target_url="https://x.example", classification=cl, fingerprint=fp,
        operator_name="<name>",
    )
    assert "<name>" in body
    assert "Status:" in body and "UNSIGNED" in body
    # charter is still recognized as unsigned by the ethics gate when read back
    # (we don't write it; just check the format)


def test_drafters_threat_model_renders() -> None:
    fp = Fingerprint(target_url="https://x.example")
    cl = stack_classifier.classify(fp)
    from framework.v2.intake import drafters
    body = drafters.draft_threat_model(
        slug="x-example", target_host="x.example",
        classification=cl, fingerprint=fp,
        business_context="testing",
    )
    assert "Threat model" in body
    assert "Archetype" in body or "archetype" in body


def test_drafters_attack_tree_renders() -> None:
    fp = Fingerprint(target_url="https://x.example")
    cl = stack_classifier.classify(fp)
    from framework.v2.intake import drafters
    body = drafters.draft_attack_tree(
        slug="x-example", target_host="x.example", classification=cl,
    )
    assert "Attack tree" in body
    assert "[?]" in body  # leaves marked "not yet tested"


# ---------------------------------------------------------------------------
# Scaffolder + ethics
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect per-target paths to tmp dir but keep target_template_dir()
    pointing at the real v1 _template (we want the scaffolder to copy
    real scaffolding, just into a temp location)."""
    tdir = tmp_path / "targets"
    real_template = paths.target_template_dir()
    monkeypatch.setattr(paths, "targets_root", lambda: tdir)
    monkeypatch.setattr(paths, "target_template_dir", lambda: real_template)
    monkeypatch.setattr(paths, "target_dir", lambda slug: tdir / slug)
    monkeypatch.setattr(paths, "charter_path",  lambda slug: tdir / slug / "charter.md")
    monkeypatch.setattr(paths, "charter_draft_path", lambda slug: tdir / slug / "charter.draft.md")
    monkeypatch.setattr(paths, "threat_model_path", lambda slug: tdir / slug / "threat-model.md")
    monkeypatch.setattr(paths, "attack_tree_path",  lambda slug: tdir / slug / "attack-tree.md")
    monkeypatch.setattr(paths, "endpoints_path",    lambda slug: tdir / slug / "notes" / "endpoints.md")
    monkeypatch.setattr(paths, "fingerprint_path",  lambda slug: tdir / slug / "recon" / "fingerprint.json")
    return tdir


def test_scaffolder_writes_drafts(isolated_targets: Path) -> None:
    fp = Fingerprint(target_url="https://x.example",
                     detectors={}, security_headers={}, cookies_seen=[])
    cl = stack_classifier.classify(fp)

    written = scaffolder.scaffold(
        slug="x-example", target_url="https://x.example",
        target_host="x.example",
        fingerprint=fp, classification=cl,
        operator_name="<name>",
    )
    for key in ("scaffold_dir", "charter_draft", "threat_model",
                "attack_tree", "fingerprint_json"):
        assert Path(written[key]).exists(), f"{key} missing at {written[key]}"


def test_scaffolder_does_not_overwrite_signed_charter(isolated_targets: Path) -> None:
    fp = Fingerprint(target_url="https://x.example", detectors={})
    cl = stack_classifier.classify(fp)
    # Pre-create a signed charter
    target = isolated_targets / "x-example"
    target.mkdir(parents=True, exist_ok=True)
    (target / "charter.md").write_text("# Engagement charter\n\nSigned: `Real Operator`\n")

    scaffolder.scaffold(
        slug="x-example", target_url="https://x.example",
        target_host="x.example", fingerprint=fp, classification=cl,
    )
    # The signed charter must remain untouched
    assert (target / "charter.md").read_text().endswith("Signed: `Real Operator`\n")
    # but charter.draft.md is (re)written
    assert (target / "charter.draft.md").is_file()


# ---------------------------------------------------------------------------
# Ethics gate
# ---------------------------------------------------------------------------


def test_intake_refuses_unauthorized(isolated_targets: Path) -> None:
    with pytest.raises(AuthorizationMissing):
        intake_mod.run("https://never-authorized.example", record_to_memory=False)


# ---------------------------------------------------------------------------
# End-to-end with fixture-mode Fetcher
# ---------------------------------------------------------------------------


def test_intake_end_to_end_with_fixture_fetcher(
    tmp_path: Path,
    isolated_targets: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run the full pipeline against a synthetic Fetcher, no network."""
    # Authorize the fake host
    monkeypatch.setattr(ethics, "authorization_ledger", lambda: tmp_path / "auth.txt")
    (tmp_path / "auth.txt").write_text(
        f"{ethics.now_iso()} | testbot | fake-target.example\n"
    )

    # Build a Fetcher pre-filled with synthetic exchanges that look like
    # an SMM panel.
    fetcher = Fetcher(base_url="https://fake-target.example")
    fetcher._exchanges = [
        HTTPExchange(
            method="GET", url="https://fake-target.example/",
            status=200,
            headers={"Server": "nginx", "X-Powered-By": "PHP/7.4"},
            body_excerpt=(
                '<script src="https://cdn.glycon.net/panel/main.js"></script>'
                '<a href="https://api.cryptomus.com/v1">Cryptomus</a>'
                '<a href="https://commerce.coinbase.com">Coinbase</a>'
            ),
            cookies={"PHPSESSID": "a"},
        ),
        HTTPExchange(
            method="GET", url="https://fake-target.example/login",
            status=200,
            headers={},
            body_excerpt='<form action="/login"><input type="password" name="pw"></form>',
        ),
    ]
    fetcher._used = 2

    out = intake_mod.run(
        "https://fake-target.example",
        slug="fake-target",
        operator_name="testbot",
        business_context="synthetic test target",
        fetcher=fetcher,
        record_to_memory=False,
    )

    assert out.classification.primary.archetype.slug == "php-smarty-smm-panel-fork"
    assert out.request_count == 2
    assert Path(out.charter_draft_path).is_file()
    # Charter is unsigned
    text = Path(out.charter_draft_path).read_text(encoding="utf-8")
    assert "<name>" in text
    # Threat model + attack tree exist
    assert Path(out.threat_model_path).is_file()
    assert Path(out.attack_tree_path).is_file()
    # Fingerprint JSON parses
    fpj = json.loads(Path(out.fingerprint_json_path).read_text(encoding="utf-8"))
    assert fpj["fingerprint"]["target_url"] == "https://fake-target.example"


# ---------------------------------------------------------------------------
# Live integration — opt-in
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("CRUCIBLE_LIVE_INTAKE_URL"),
    reason="set CRUCIBLE_LIVE_INTAKE_URL=<https://your-authorised-target> to run the live intake",
)
def test_live_intake_against_authorised_target(isolated_targets: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    """Live HTTP fingerprint against any operator-authorised URL.

    The operator must have authorised the target host (set via
    CRUCIBLE_LIVE_INTAKE_URL). Budget capped at 12 to stay polite.
    """
    from urllib.parse import urlparse
    target_url = os.environ["CRUCIBLE_LIVE_INTAKE_URL"]
    host = urlparse(target_url).netloc.lower()

    # Use a temp ledger pre-authorising the chosen host.
    ledger = isolated_targets.parent / "intake-auth.txt"
    monkeypatch.setattr(ethics, "authorization_ledger", lambda: ledger)
    ledger.write_text(f"{ethics.now_iso()} | testbot | {host}\n")

    out = intake_mod.run(
        target_url,
        slug="live-intake-target",
        operator_name="testbot",
        business_context="live integration test",
        budget=12,
        record_to_memory=False,
    )
    assert out.request_count <= 12
    # We don't assert a specific archetype because the live site may
    # have changed; we only assert intake produced a scaffold.
    assert Path(out.charter_draft_path).is_file()
    assert Path(out.threat_model_path).is_file()
