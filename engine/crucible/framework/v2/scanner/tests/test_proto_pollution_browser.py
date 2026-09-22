"""
Client-side prototype pollution — END-TO-END deep-profile assertion against a REAL
browser and the REAL benchmark app (Wave 2.2).

Skip-gated on a working headless Chromium (``scanner.cdp.cdp_available``), exactly like
the other live CDP tests, so a browserless CI leg SKIPS this rather than failing (a
browserless run yields no prototype-pollution FACT — only a LEAD, never a false CLEAN —
which is covered deterministically by ``test_proto_pollution.py``).

It drives the full path the plan specifies: a ``__proto__[uniqKey]=uniqVal`` gadget across
the client sources into the VULNERABLE benchmark page (``/proto``), rendered in a real
DOM, read back through the planted ``__crucible_pp`` binding, and confirms the
``prototype_pollution`` oracle fires on the ACHIEVED Object.prototype state — AND that the
benign twin (``/proto/safe``, which reflects the payload but GUARDS the dangerous keys)
does NOT fire. The pages are unlinked from the index, so ``make gate`` stays byte-identical.
"""

from __future__ import annotations

import pytest

from framework.v2.eval.benchmark_app import serve
from framework.v2.scanner.cdp import CdpBrowser, cdp_available
from framework.v2.scanner.proto_pollution import confirm_proto_pollution
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no usable headless Chromium for the CDP driver")


def test_planted_prototype_pollution_facts_against_a_real_browser() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            results = confirm_proto_pollution(f"{base}/proto", browser=browser, settle=0.8)
            polluted = [r for r in results if r.polluted]
            assert polluted, "no client source polluted Object.prototype — prototype pollution not confirmed"
            r = polluted[0]
            assert r.bug_class == "prototype_pollution"
            outcome = OracleVerifier().confirm(r.context.to_verifier_context())
            assert outcome.confirmed
            assert any(s.kind is OracleKind.PROTOTYPE_POLLUTION and s.fired for s in outcome.signals)
        finally:
            browser.stop()


def test_benign_twin_reflects_without_polluting_never_facts_against_a_real_browser() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            results = confirm_proto_pollution(f"{base}/proto/safe", browser=browser, settle=0.8)
            assert results, "the benign twin should still be driven (it reflects the payload)"
            assert not any(r.polluted for r in results), "the guarded parser must NEVER pollute Object.prototype"
            assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed
        finally:
            browser.stop()
