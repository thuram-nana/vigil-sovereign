"""The range is unmistakably a lab: a machine-readable manifest + a persistent in-page banner."""

from __future__ import annotations

import json
import os

from conftest import REPO_ROOT

from vigil_range.meridian import theme


def test_lab_manifest_file_declares_intentionally_vulnerable():
    with open(os.path.join(REPO_ROOT, "range", "LAB-MANIFEST.json"), encoding="utf-8") as fh:
        m = json.load(fh)
    assert m["lab"] is True
    assert m["intentionally_vulnerable"] is True
    assert m["no_real_data"] is True
    assert m["loopback_only"] is True
    assert m["ports"] == {"target": 19010, "control": 19011}


def test_every_page_carries_the_lab_banner():
    html = theme.page("Any", "<main></main>", mode="vuln")
    assert "INTENTIONALLY VULNERABLE" in html
    assert "LAB ONLY" in html


def test_theme_reuses_vigil_tokens():
    # a couple of VIGIL's exact token values must be present (proves the estate theme was ported, not faked)
    assert "--bg-0: #0a0c10" in theme.TOKENS_CSS
    assert "--owner: #e8b64c" in theme.TOKENS_CSS
    assert "--st-confirmed: #4bbf8a" in theme.TOKENS_CSS
