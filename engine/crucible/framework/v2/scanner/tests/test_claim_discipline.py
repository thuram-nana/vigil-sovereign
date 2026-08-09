"""Mechanical enforcement of docs/CLAIM-DISCIPLINE.md.

A doctrine document that is only prose is itself an overclaim: it asserts a property of the codebase that
nothing checks. These tests are the enforcement half. They are deliberately strict — a claim VIGIL cannot
back is a defect of the same kind as a wrong verdict, because the whole product is the trustworthiness of
its output.

What is enforced here:
  * every evidence branch that can produce a verdict is DECLARED, with fact_capable and clean_capable as
    SEPARATE claims (the distinction this codebase got wrong: a branch sound for confirming a property was
    used to assert its absence);
  * a branch whose evidence can be unavailable declares that precondition, so a non-firing over unreadable
    evidence cannot be reported as CLEAN;
  * capability-describing documents do not make absolute claims without an adjacent limitation;
  * the shipped capability matrix does not claim more than the branch registry supports.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[6]   # .../engine/crucible/framework/v2/scanner/tests -> repo root
_BRANCHES = _ROOT / "docs" / "capability-matrix" / "evidence-branches.json"
_MATRIX = _ROOT / "docs" / "capability-matrix" / "hexstrike.json"
_DOCTRINE = _ROOT / "docs" / "CLAIM-DISCIPLINE.md"

# Absolutes that assert more than any bounded verification can establish. Allowed only when the same
# paragraph states a limitation — the point is not to ban words, it is to ban unbounded claims.
# Kept in step with the phrases rule 3 says are banned — the prose and the checker must not drift apart.
_ABSOLUTES = (
    "guaranteed", "cannot be", "impossible", "never fails", "zero false positives", "100%",
    "fully verified", "proven secure", "complete coverage", "all vulnerabilities", "no false positives",
    "always correct", "always safe", "never misses",
)
_QUALIFIERS = (
    "limitation", "however", "not clean-capable", "lead-only", "inconclusive", "residual", "boundary",
    "does not", "cannot see", "scoped to", "only when", "except", "caveat", "bounded",
)


def _load(path: Path) -> dict:
    assert path.is_file(), f"{path} is missing — the discipline is not enforceable without it"
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_doctrine_document_exists_and_marks_every_rule_enforced_or_review() -> None:
    """Each rule must say whether a machine checks it. An unmarked rule is a claim about this document."""
    text = _DOCTRINE.read_text(encoding="utf-8")
    headings = [line for line in text.splitlines() if re.match(r"^## \d+\.", line)]
    assert headings, "the doctrine has no numbered rules"
    unmarked = [h for h in headings if "[ENFORCED" not in h and "[REVIEW]" not in h]
    assert not unmarked, f"rules must be marked [ENFORCED] or [REVIEW]: {unmarked}"


def test_every_declared_branch_separates_fact_and_clean_capability() -> None:
    """fact_capable and clean_capable are different claims and must both be explicit booleans."""
    for branch in _load(_BRANCHES)["branches"]:
        bid = branch.get("id")
        assert bid, f"branch without an id: {branch}"
        for field in ("fact_capable", "clean_capable"):
            assert isinstance(branch.get(field), bool), f"{bid}: {field} must be an explicit boolean"
        assert branch.get("evidence"), f"{bid}: must say what evidence it rests on"
        assert branch.get("limitation"), f"{bid}: must state honestly what it cannot see"


def test_body_dependent_branches_are_not_clean_capable_without_a_readable_body() -> None:
    """The defect this rule exists for: a body-derived branch that finds nothing over a body VIGIL could not
    decode (gzip/Brotli, an undeclared non-UTF-8 charset, a truncated response) must be INCONCLUSIVE, never
    CLEAN. Any branch whose evidence comes from the response body must therefore either declare the
    `body_semantically_available` precondition or renounce clean_capable."""
    for branch in _load(_BRANCHES)["branches"]:
        # Keyed off the DECLARED surface, never the branch name: a future body-derived branch called
        # `dom_redirect` or `html_meta_refresh` would slip past a substring match on "body".
        if branch.get("evidence_surface") != "response_body":
            continue
        # DECLARING the precondition is not the same as ENFORCING it — mutation-testing this guard showed
        # that flipping a body branch to clean_capable slipped through while the precondition was merely
        # listed. Body-derived branches are therefore clean_capable=false outright. Lifting this requires
        # (a) the runner to map an unavailable body to INCONCLUSIVE, and (b) a test proving it does — at
        # which point this assertion should be replaced by one that checks that behaviour, not this flag.
        assert branch["clean_capable"] is False, (
            f"{branch['id']}: body-derived branches may not be clean_capable — a non-firing cannot "
            f"distinguish 'the document says nothing' from 'we could not read the document'")
        assert "body_semantically_available" in branch.get("preconditions", []), (
            f"{branch['id']}: body-derived branches must declare the body_semantically_available precondition")


def test_every_capability_gap_carries_the_work_that_closes_it() -> None:
    """THE LADDER RULE. This registry exists to raise the system, not to license a weaker product.

    Wherever what is true today falls short of the target, the branch must name the concrete engineering
    that closes the gap. Without this, "do not overclaim" degenerates into a ratchet: every inconvenient
    capability gets quietly redefined as out of scope and the tool becomes honest about doing less. A gap is
    a BUILD ITEM, not an excuse — the claim stays and the system comes up to meet it."""
    for branch in _load(_BRANCHES)["branches"]:
        for now, target, kind in (("fact_capable", "target_fact_capable", "FACT"),
                                  ("clean_capable", "target_clean_capable", "CLEAN")):
            assert isinstance(branch.get(target), bool), f"{branch['id']}: {target} must be declared"
            if branch[now] or not branch[target]:
                continue
            work = (branch.get("blocking_work") or "").strip()
            assert len(work) > 40, (
                f"{branch['id']}: declared not-{kind}-capable while targeting {kind}-capable, but names no "
                f"blocking_work. Either state the engineering that closes the gap, or downgrade the TARGET "
                f"with an explicit target_downgrade_rationale — never leave a capability silently abandoned")


def test_downgrading_a_target_requires_an_explicit_rationale() -> None:
    """A target may be lowered only by arguing the capability is not achievable — never by convenience."""
    for branch in _load(_BRANCHES)["branches"]:
        for target, kind in (("target_fact_capable", "FACT"), ("target_clean_capable", "CLEAN")):
            if branch.get(target) is False:
                rationale = (branch.get("target_downgrade_rationale") or "").strip()
                assert len(rationale) > 40, (
                    f"{branch['id']}: target {kind}-capability is False without a stated rationale")


def test_every_branch_declares_a_known_evidence_surface() -> None:
    """The surface is a closed type so the rules above can key off it rather than off naming."""
    verdict = _admit()
    for branch in _load(_BRANCHES)["branches"]:
        surface = branch.get("evidence_surface")
        assert surface in verdict.known_surfaces(), (
            f"{branch['id']}: evidence_surface {surface!r} is not one of {sorted(verdict.known_surfaces())}")


def test_declared_limitations_point_at_real_code() -> None:
    """Rule 8's traceability half: a limitation must be findable where the behaviour lives, so the registry
    cannot drift away from the implementation it describes. This checks the reference RESOLVES — it cannot
    check that the limitation is complete or meaningful, which is why rule 8 is labelled part-review."""
    for branch in _load(_BRANCHES)["branches"]:
        refs = branch.get("implementation_refs") or []
        assert refs, f"{branch['id']}: no implementation_refs"
        for ref in refs:
            rel, _, symbol = ref.partition(":")
            path = _ROOT / rel
            assert path.is_file(), f"{branch['id']}: implementation_ref {rel} does not exist"
            assert symbol and symbol in path.read_text(encoding="utf-8"), (
                f"{branch['id']}: symbol {symbol!r} not found in {rel}")


def test_lead_only_branches_cannot_mint_or_clear() -> None:
    """A branch we cannot parse soundly (today: the JS sink, matched by regex over script text so it also
    matches comments and string literals) may neither confirm nor exonerate."""
    for branch in _load(_BRANCHES)["branches"]:
        if "lead-only" in branch["limitation"].lower():
            assert not branch["fact_capable"], f"{branch['id']}: LEAD-only but fact_capable"
            assert not branch["clean_capable"], f"{branch['id']}: LEAD-only but clean_capable"


def test_the_js_sink_may_only_mint_from_executable_code() -> None:
    """The JS sink was LEAD-only because a regex matched sinks inside comments and strings. It was promoted
    to FACT-capable only when that became structurally impossible, so this guard asserts the BEHAVIOUR that
    justifies the promotion rather than the flag — if the lexical filter regresses, the branch loses the
    property its capability rests on and this fails."""
    import sys
    engine = str(_ROOT / "engine" / "crucible")
    if engine not in sys.path:
        sys.path.insert(0, engine)
    from framework.v2.scanner.checks import _markup_redirect_hosts as hosts

    canary = "canary.evil"
    # never executed -> must not be extractable at all
    assert hosts(f'<script>// location.href="//{canary}/"</script>') == []
    assert hosts(f'<script>/* location.href="//{canary}/" */</script>') == []
    assert hosts(f"""<script>var s = "location.href='//{canary}/'";</script>""") == []
    assert hosts(f'<script>var re = /location.href="\\/\\/{canary}\\//;</script>') == []
    # genuinely executed -> must still be found, or the promotion bought nothing
    assert canary in hosts(f'<script>location.href="//{canary}/"</script>')
    assert canary in hosts(f'<script>top.location.href="//{canary}/"</script>')

    js = [b for b in _load(_BRANCHES)["branches"] if b["id"] == "open_redirect.js_sink"]
    assert js and js[0]["clean_capable"] is False, (
        "lexing shows a sink EXISTS; it cannot show none exists (a runtime-assembled redirect is invisible), "
        "so this branch must not claim CLEAN")


def _admit():
    """Import the admission module, or FAIL.

    Never skip. A skip here would remove the runtime enforcement this whole contract rests on while leaving
    CI green — a packaging error or a broken import would silently disable admission and nothing would say
    so. If a profile genuinely does not ship admission, exclude this file explicitly at the runner level;
    do not let it opt out dynamically."""
    import sys
    integration = str(_ROOT / "integration")
    if integration not in sys.path:
        sys.path.insert(0, integration)
    try:
        from vigil_integration.live import verdict
    except Exception as exc:                       # noqa: BLE001
        pytest.fail(f"admission enforcement unavailable — the contract is unenforced here: {exc}")
    return verdict


def test_the_verdict_vocabulary_is_closed_by_type() -> None:
    """Rule 1. 'Only these four verdicts reach output' must be a property of the type, not a convention."""
    verdict = _admit()
    assert {v.value for v in verdict.Verdict} == {"FACT", "LEAD", "CLEAN", "INCONCLUSIVE"}
    with pytest.raises(ValueError):
        verdict.Verdict("probably safe")
    admitted = verdict.admit("open_redirect.location_header", fired=True, conclusive=True,
                             observed={"channel_established": True})
    assert isinstance(admitted.verdict, verdict.Verdict), "a verdict escaped the closed enum"


def test_a_verdict_cannot_be_constructed_outside_admission() -> None:
    """Rule 2's architectural half: FACT/CLEAN carry authority, so building one without admission must fail
    loudly rather than quietly produce output."""
    verdict = _admit()
    with pytest.raises(verdict.DirectVerdictConstruction):
        verdict.AdmittedVerdict(verdict.Verdict.FACT, "open_redirect.location_header")


def test_admission_refuses_an_unregistered_branch() -> None:
    """Rule 2's runtime claim. A new evidence path must not inherit FACT/CLEAN authority by default."""
    verdict = _admit()
    with pytest.raises(verdict.UnregisteredBranch):
        verdict.admit("some.branch.nobody.declared", fired=True, conclusive=True,
                      observed={"channel_established": True})


def test_admission_cannot_mint_from_a_branch_that_is_not_fact_capable(monkeypatch) -> None:
    """Tested against a SYNTHETIC branch rather than whichever real branch happens to be quarantined today —
    otherwise the guard silently stops testing anything the moment every branch becomes FACT-capable."""
    verdict = _admit()
    synthetic = dict(verdict._branches())
    synthetic["synthetic.not_fact_capable"] = {
        "id": "synthetic.not_fact_capable", "fact_capable": False, "clean_capable": False,
        "evidence_surface": "response_body", "preconditions": ["channel_established"],
        "limitation": "synthetic branch used to prove admission refuses to mint",
    }
    monkeypatch.setattr(verdict, "_branches", lambda *a, **k: synthetic)
    got = verdict.admit("synthetic.not_fact_capable", fired=True, conclusive=True,
                        observed={"channel_established": True})
    assert got.verdict == verdict.LEAD, f"a non-FACT-capable branch minted {got.verdict}"


def test_admission_returns_inconclusive_not_clean_when_a_precondition_fails() -> None:
    """The defect this whole contract exists for: a body-derived non-firing over a body VIGIL could not
    decode must be INCONCLUSIVE. Header-derived evidence in the SAME capture is unaffected — availability is
    evaluated per branch, not once per response."""
    verdict = _admit()
    unreadable = {"channel_established": True, "body_semantically_available": False,
                  "not_followed_redirect": True}
    body = verdict.admit("open_redirect.body_markup", fired=False, conclusive=True, observed=unreadable)
    header = verdict.admit("open_redirect.location_header", fired=False, conclusive=True, observed=unreadable)
    assert body.verdict == verdict.INCONCLUSIVE, "a body branch scored a verdict over an unreadable body"
    assert header.verdict == verdict.CLEAN, "a header branch must not be blocked by an unreadable body"

    # A branch that IS clean_capable must still be blocked when ITS precondition fails — otherwise the
    # precondition check is unobservable behind the clean_capable flag. (Mutation testing caught exactly
    # that: disabling preconditions entirely left the previous assertions green.)
    no_channel = verdict.admit("open_redirect.location_header", fired=False, conclusive=True,
                               observed={"channel_established": False})
    assert no_channel.verdict == verdict.INCONCLUSIVE, (
        "a CLEAN-capable branch reported CLEAN with no channel — preconditions are not being evaluated")

    # An ABSENT precondition must count as not-held. A caller that simply forgets to report a fact must not
    # thereby unlock a CLEAN — an unknown is not a yes. (Mutation testing found this default untested.)
    silent = verdict.admit("open_redirect.location_header", fired=False, conclusive=True, observed={})
    assert silent.verdict == verdict.INCONCLUSIVE, (
        "an unreported precondition was treated as satisfied — absence of evidence became evidence")


def test_admission_never_reports_clean_from_a_branch_that_is_not_clean_capable() -> None:
    verdict = _admit()
    readable = {"channel_established": True, "body_semantically_available": True,
                "not_followed_redirect": True}
    for branch in _load(_BRANCHES)["branches"]:
        if branch["clean_capable"]:
            continue
        observed = dict(readable)
        observed.update({p: True for p in branch.get("preconditions", [])})
        got = verdict.admit(branch["id"], fired=False, conclusive=True, observed=observed)
        assert got.verdict != verdict.CLEAN, f"{branch['id']}: not clean_capable but admitted CLEAN"


@pytest.mark.parametrize("doc", ["docs/CLAIM-DISCIPLINE.md", "docs/capability-matrix/hexstrike.json",
                                 "docs/capability-matrix/evidence-branches.json"])
def test_capability_documents_make_no_unqualified_absolute_claims(doc: str) -> None:
    """An absolute claim is allowed only next to its boundary. Scope inflation — naming a family when only
    part of it qualifies — is how honest sentences become a dishonest document."""
    path = _ROOT / doc
    text = path.read_text(encoding="utf-8")
    offenders: list[str] = []
    for para in re.split(r"\n\s*\n", text):
        low = para.lower()
        for absolute in _ABSOLUTES:
            if absolute in low and not any(q in low for q in _QUALIFIERS):
                offenders.append(f"{doc}: {absolute!r} unqualified in: {para.strip()[:120]}")
    assert not offenders, "unqualified absolute claim(s):\n" + "\n".join(offenders)


def test_the_capability_matrix_does_not_outrun_the_branch_registry() -> None:
    """A tool may not be marked fact_capable unless some registered branch is fact_capable, and the web
    entry must carry the honest boundary rather than claiming the whole family."""
    matrix = _load(_MATRIX)
    branches = _load(_BRANCHES)["branches"]
    assert any(b["fact_capable"] for b in branches), "registry claims no FACT-capable branch at all"

    fact_tools = {t["name"] for t in matrix["tools"] if t.get("fact_capable")}
    assert fact_tools == {"nmap", "sslscan"}, f"unexpected fact_capable tool set: {fact_tools}"

    httpx = [t for t in matrix["tools"] if t["name"] == "httpx"]
    assert httpx, "the web proposer row must exist"
    notes = httpx[0]["notes"].lower()
    assert "header" in notes and ("not clean-capable" in notes or "lead-only" in notes), (
        "the web capability note must state its boundary: header-derived evidence is FACT-capable, "
        "body-derived branches are not CLEAN-capable until decoding is complete, JS is LEAD-only")
