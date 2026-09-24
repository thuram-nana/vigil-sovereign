"""Wave 4.1 — the planted SSI benchmark fixture (``/ssi``) evaluates an injected include directive, and the
benign twin (``/ssi/safe``) never does.

These routes are DELIBERATELY NOT linked from the index, so the default GET crawl (`make gate`) never reaches
them and the signed baseline stays byte-identical (proven by the unchanged gate tally). This file exercises
them directly — the same way the CSP / proto-pollution twins are exercised — to prove:

  * the planted ``/ssi`` route EVALUATES an ``<!--#set var=X value="N1*N2" --><!--#echo var=X -->`` directive
    pair server-side (product present, raw directive absent) so ssi_evaluation_oracle FIRES; and
  * the benign twin ``/ssi/safe`` REFLECTS the directive verbatim (SSI disabled) so the oracle NEVER fires —
    the honest boundary (reflected, not evaluated); and a non-directive payload is not reflected at all.
"""
from __future__ import annotations

from urllib.parse import urlencode
from urllib.request import urlopen

from framework.v2.eval.benchmark_app import serve
from framework.v2.verify.oracles import ssi_evaluation_oracle


def _get(base: str, path: str, doc: str) -> str:
    with urlopen(f"{base}{path}?{urlencode({'doc': doc})}", timeout=5) as r:  # noqa: S310 (loopback test)
        return r.read().decode("utf-8")


def test_planted_ssi_route_evaluates_and_fires() -> None:
    directive = '<!--#set var="vc" value="6131*7919" --><!--#echo var="vc" -->'
    product = str(6131 * 7919)
    with serve() as base:
        body = _get(base, "/ssi", directive)
        control = _get(base, "/ssi", "index")            # benign, no directive
    assert product in body and directive not in body, "the SSI route must EVALUATE (product present, raw absent)"
    sig = ssi_evaluation_oracle(directive, product, body, control_body=control)
    assert sig.fired, "ssi_evaluation_oracle must fire on the evaluated benchmark route"


def test_benign_ssi_twin_reflects_and_never_fires() -> None:
    directive = '<!--#set var="vc" value="6131*7919" --><!--#echo var="vc" -->'
    product = str(6131 * 7919)
    with serve() as base:
        body = _get(base, "/ssi/safe", directive)
        control = _get(base, "/ssi/safe", "index")
    # SSI disabled: the directive is echoed verbatim as an inert comment, the product never appears.
    assert directive in body and product not in body, "the twin must REFLECT the directive, never evaluate it"
    sig = ssi_evaluation_oracle(directive, product, body, control_body=control)
    assert not sig.fired, "the benign twin must NEVER fire the SSI oracle (reflected, not evaluated)"


def test_benign_twin_does_not_reflect_a_non_directive_payload() -> None:
    # A non-directive payload is not reflected at all (constant render), so the twin is never a generic sink.
    with serve() as base:
        body = _get(base, "/ssi/safe", "<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in body, "the twin must not reflect a non-directive payload"
