"""
report.howto — the per-finding "how to verify / test / patch" block.

A FACT yields a block naming its firing oracle + exact surface + the REAL verifier
command (with the certificate digest in prose, since no per-cert flag exists). A LEAD
yields a "confirm this lead" block that never implies proof. Remediation is woven with
the finding's own parameter/surface. Everything is a pure function of the finding, so the
same finding renders identically twice — and an opaque surface adds nothing (byte-identity).
"""

from __future__ import annotations

import json

from framework.v2.agents.models import FindingPayload
from framework.v2.report import ReportMeta
from framework.v2.report.export import to_json, to_sarif
from framework.v2.report.generate import render_technical
from framework.v2.report.grounding import grade_finding, grade_findings
from framework.v2.report.howto import (
    VERIFY_COMMAND,
    build_howto,
    finding_specific_remediation,
    has_howto,
    howto_export,
    howto_markdown,
    parse_surface,
)

from .conftest import firing_ctx, make_demoted, make_fact, make_lead


# ---------------------------------------------------------------------------
# surface parsing
# ---------------------------------------------------------------------------


def test_parse_surface_method_path_query() -> None:
    assert parse_surface("GET /search?q=") == ("GET", "/search", "q")
    assert parse_surface("POST /login") == ("POST", "/login", None)
    assert parse_surface("GET /order/{id}") == ("GET", "/order/{id}", "id")
    assert parse_surface("DELETE /users/:uid") == ("DELETE", "/users/:uid", "uid")
    assert parse_surface("/x?a=1&b=2") == (None, "/x", "a")  # no method -> None, param still read


def test_parse_surface_opaque_is_all_none_for_method_and_param() -> None:
    m, loc, p = parse_surface("misc")
    assert m is None and p is None            # nothing concrete to add


# ---------------------------------------------------------------------------
# FACT: real oracle + real command + certificate in prose
# ---------------------------------------------------------------------------


def test_fact_block_names_oracle_surface_and_real_verify_command() -> None:
    g = grade_finding(make_fact())
    assert g.is_fact
    md = "\n".join(howto_markdown(g))
    assert "How to verify, test & patch this finding" in md
    # exact surface: method + path + parameter
    assert "`GET /search`" in md
    assert "parameter `q`" in md
    # the oracle that fired + its rationale
    assert "differential_response" in md
    assert "differential fired across" in md
    # the REAL verifier interface (no invented flag), with the cert digest in prose
    assert VERIFY_COMMAND in md
    assert "python3 -m framework.v2 verify" in md
    assert f"sha256:{g.certificate_digest}" in md
    # honest re-check verb for a proven fact
    assert "Re-check the proof" in md
    # never promises a per-cert scoping flag that does not exist
    assert "--cert" not in md and "--certificate" not in md and "--digest" not in md


def test_fact_verify_note_is_honest_about_artifact_and_calibration() -> None:
    # red-pen BLOCK fix: `verify` reports OK over the RAW reverifiable.json, NOT over a rendered
    # report (where a calibration delta reads as CLAIM-MISMATCH). The note must say so and must not
    # falsely claim the verifier locates a row by slug or prints the certificate digest.
    g = grade_finding(make_fact())
    md = "\n".join(howto_markdown(g))
    assert "reverifiable.json" in md                       # the artifact that actually re-verifies
    assert "calibration" in md and "tampering" in md.lower()
    assert "locate this finding's row by its" not in md    # the dropped false locator
    assert "<reverifiable.json>" in VERIFY_COMMAND


def test_safe_span_strips_backticks_and_controls() -> None:
    # LOW-1 fix: a backtick/newline in an LLM-authored surface must not break the Markdown code span.
    from framework.v2.report.howto import _safe_span
    assert _safe_span("q`echo pwned`") == "qecho pwned"
    assert _safe_span("a\nb\tc") == "abc"
    assert _safe_span(None) == ""


def test_fact_export_carries_oracle_and_certificate() -> None:
    h = howto_export(grade_finding(make_fact()))
    assert h["grounding"] == "fact" and h["is_fact"] is True
    assert h["surface"] == {"method": "GET", "location": "/search", "parameter": "q"}
    assert h["oracle"]["kind"] == "differential_response"
    assert h["certificate"].startswith("sha256:")
    assert h["verify_command"] == VERIFY_COMMAND
    assert h["poc_replay"] is None  # a plain differential context is not a raw PoC capture


# ---------------------------------------------------------------------------
# LEAD: "confirm this lead", never "verify a fact"
# ---------------------------------------------------------------------------


def test_lead_block_says_confirm_not_verify_and_never_implies_proof() -> None:
    g = grade_finding(make_lead())
    assert not g.is_fact
    md = "\n".join(howto_markdown(g))
    assert "How to confirm this lead" in md
    assert "is a LEAD, not a proven fact" in md
    assert "To CONFIRM it" in md
    # honesty: never claims the lead is proven, never says the verifier confirms IT.
    assert "PROVEN" not in md
    assert "Re-check the proof" not in md
    assert "verify a fact" not in md
    # the verifier is named honestly: it re-checks proven certs; this lead carries none.
    assert "this lead carries none" in md
    # a lead has no certificate and no firing oracle in its export block.
    h = howto_export(g)
    assert h["grounding"] == "lead"
    assert h["oracle"] is None
    assert h["certificate"] is None


def test_demoted_lead_is_confirm_block_with_its_own_reason() -> None:
    g = grade_finding(make_demoted())
    assert g.grade == "demoted" and not g.is_fact
    md = "\n".join(howto_markdown(g))
    assert "How to confirm this lead" in md
    assert "did NOT re-verify" in md          # the demoted nuance, honestly stated
    assert howto_export(g)["grounding"] == "demoted"


# ---------------------------------------------------------------------------
# remediation is finding-specific
# ---------------------------------------------------------------------------


def test_remediation_weaves_the_findings_own_parameter() -> None:
    fact = make_fact()  # bug_class boolean_sqli, surface GET /search?q=
    rem = finding_specific_remediation(fact)
    # the class rule is present AND scoped to this finding's own parameter/surface.
    assert "parameterised queries" in rem            # class rule text
    assert "`q`" in rem and "GET /search" in rem     # finding-specific weave


def test_remediation_falls_back_to_class_text_without_a_parameter() -> None:
    # a surface with no query/template/param -> the class text verbatim, no fabricated surface.
    f = FindingPayload(
        finding_slug="010-x", title="t", severity="Low", bug_class="boolean_sqli",
        surface="the search feature", summary="s",
    )
    rem = finding_specific_remediation(f)
    assert rem.startswith("Use parameterised queries")   # verbatim class rule
    assert "For `" not in rem                            # nothing woven in


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_howto_is_deterministic_called_twice() -> None:
    for make in (make_fact, make_demoted, make_lead):
        g = grade_finding(make())
        assert howto_markdown(g) == howto_markdown(g)
        assert howto_export(g) == howto_export(g)
        assert build_howto(g) == build_howto(g)


# ---------------------------------------------------------------------------
# byte-identity gate: an opaque surface appends nothing
# ---------------------------------------------------------------------------


def test_opaque_surface_appends_no_howto() -> None:
    f = make_fact()
    f.surface = "misc"                       # no method, no parameter, no template
    g = grade_finding(f)
    assert has_howto(g) is False
    assert howto_markdown(g) == []
    md = render_technical([g], ReportMeta(target="acme"))
    # the finding still renders (as a proven fact) but the howto sub-block is absent.
    assert "PROVEN FACT" in md
    assert "How to verify, test & patch" not in md


# ---------------------------------------------------------------------------
# PoC replay pointer only when a reproduce-from-raw capture is present
# ---------------------------------------------------------------------------


def test_poc_pointer_appears_only_for_a_raw_capture() -> None:
    ctx = firing_ctx()
    ctx["baseline"]["request_bytes_ref"] = "poc/001/req_baseline.bin"
    f = make_fact()
    f.oracle_context = ctx
    g = grade_finding(f)
    assert g.is_fact                          # the extra byte-ref does not break grading
    h = build_howto(g)
    assert h.poc_replay is not None
    assert "evidence/poc.py" in h.poc_replay
    assert "replay_harness" in h.poc_replay
    md = "\n".join(howto_markdown(g))
    assert "Reproduce from raw" in md


# ---------------------------------------------------------------------------
# wiring: the block reaches the human report and both machine exports
# ---------------------------------------------------------------------------


def test_technical_report_carries_the_howto_block() -> None:
    graded = grade_findings([make_fact(), make_lead()])
    md = render_technical(graded, ReportMeta(target="acme"))
    assert "How to verify, test & patch this finding" in md   # the fact
    assert "How to confirm this lead" in md                   # the lead


def test_json_and_sarif_carry_how_to_verify_and_lead_stays_note() -> None:
    graded = grade_findings([make_fact(), make_lead()])
    # JSON: every finding carries how_to_verify; a lead's is honest (no oracle/cert).
    doc = json.loads(to_json(graded, ReportMeta(target="acme")))
    by_slug = {f["slug"]: f for f in doc["findings"]}
    assert by_slug["001-sqli"]["how_to_verify"]["oracle"]["kind"] == "differential_response"
    assert by_slug["001-sqli"]["how_to_verify"]["certificate"].startswith("sha256:")
    assert by_slug["003-idor"]["how_to_verify"]["oracle"] is None
    assert by_slug["003-idor"]["how_to_verify"]["certificate"] is None
    # SARIF: the property is attached; a LEAD is STILL capped at note (howto never lifts level).
    results = json.loads(to_sarif(graded, ReportMeta(target="acme")))["runs"][0]["results"]
    by = {r["properties"]["slug"]: r for r in results}
    assert by["001-sqli"]["properties"]["howToVerify"]["grounding"] == "fact"
    assert by["003-idor"]["properties"]["howToVerify"]["grounding"] == "lead"
    assert by["003-idor"]["level"] == "note"
