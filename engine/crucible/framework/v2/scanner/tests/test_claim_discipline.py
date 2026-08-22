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

import ast
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

# The documents rule 3 ("Any document that claims a capability must state the boundary") is ENFORCED over.
# It used to be the three machine-readable capability files, while the rule said "any document" — so the
# enforcement claim outran the enforcement, and the documents an evaluator actually opens first (the README
# and the status map) were outside it. Widened to the reader-facing set rather than narrowing the rule,
# per docs/CLAIM-DISCIPLINE.md itself: when a claim outruns the code you build the code up.
# It is still not literally "any document" — design notes, ADRs and the plain-English chapters are not in
# it — so rule 3's prose names this list as the enforced scope and marks the rest [REVIEW].
_LINTED_DOCS = (
    "docs/CLAIM-DISCIPLINE.md",
    "docs/capability-matrix/hexstrike.json",
    "docs/capability-matrix/evidence-branches.json",
    "README.md",
    "docs/AS-BUILT.md",
    "docs/FEATURES.md",
    "docs/SUPPLY-CHAIN.md",
)

# Phrases in the shipped capability matrix that DENY a branch's ability to mint a FACT. Each is legal only
# while the registry agrees, so the pair is what makes the assertion load-bearing: flip the registry and the
# assertion flips with it (see ``test_the_capability_matrix_does_not_lag_the_branch_registry``).
#
# A PINNED TABLE rather than a natural-language rule, deliberately: deciding "does this sentence deny that
# capability?" from arbitrary prose is exactly the hand-approximation rule 4 forbids. A pin is small, exact,
# and fails loudly when the branch it names disappears.
_MATRIX_CAPABILITY_DENIALS = {
    "open_redirect.js_sink": (
        "js-redirect branch is lead-only",
        "js sink is lead-only",
        "needs a real js tokenizer",
    ),
    "open_redirect.body_markup": (
        "does not process content-encoding",
        "body-derived branches are lead-only",
        "body-derived branches are not fact-capable",
    ),
}


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


def test_admitted_verdict_cannot_be_escalated_via_dataclasses_replace() -> None:
    """Re-attack re-auth bypass: authorization is a construction-scope flag, NOT a copyable field. A token
    field survived dataclasses.replace(), so replace(inconclusive, verdict=FACT) forged a FACT carrying a
    valid token. The flag is set only inside admit()'s own construction, so a replace() (which re-runs
    __post_init__ outside that scope) must fail loudly."""
    import dataclasses

    verdict = _admit()
    admitted = verdict.admit("open_redirect.location_header", fired=False, conclusive=False,
                             observed={"channel_established": True})
    assert admitted.verdict is not verdict.Verdict.FACT
    with pytest.raises(verdict.DirectVerdictConstruction):
        dataclasses.replace(admitted, verdict=verdict.Verdict.FACT)


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


def test_family_composition_is_conservative() -> None:
    """A PRESENTATION invariant, and the last place a false CLEAN can appear.

    Per-branch admission is only half the guarantee: the moment several branch verdicts are summarised, the
    summary can assert something no branch did. A CLEAN header branch beside a FACT body branch must compose
    to FACT — reporting that family as "clean" would claim safety nothing established. An EMPTY set composes
    to INCONCLUSIVE, because nothing examined is not the same as nothing found."""
    verdict = _admit()
    V, compose = verdict.Verdict, verdict.compose
    assert compose([V.CLEAN, V.FACT]) is V.FACT
    assert compose([V.CLEAN, V.LEAD]) is V.LEAD
    assert compose([V.CLEAN, V.INCONCLUSIVE]) is V.INCONCLUSIVE
    assert compose([V.CLEAN, V.CLEAN]) is V.CLEAN
    assert compose([V.LEAD, V.FACT, V.INCONCLUSIVE, V.CLEAN]) is V.FACT
    assert compose([]) is V.INCONCLUSIVE, "an unexamined family must never compose to CLEAN"
    # accepts raw values too, so a reporting layer cannot bypass the lattice by passing strings
    assert compose(["CLEAN", "FACT"]) is V.FACT


def test_certificate_minting_requires_an_admitted_verdict() -> None:
    """Rule 2's architectural half, at the OUTPUT end.

    A verdict type that only admission can construct is worth little if minting still accepts a raw string
    or a raw oracle result — the registry would describe policy that nothing applies at the point where
    authority is actually conferred. Minting must refuse anything that has not passed admission."""
    import sys
    integration = str(_ROOT / "integration")
    if integration not in sys.path:
        sys.path.insert(0, integration)
    try:
        from vigil_integration.oracle_adapter import certify_admitted
    except Exception as exc:                       # noqa: BLE001
        pytest.fail(f"admission-gated minting unavailable — the contract is unenforced here: {exc}")
    verdict = _admit()

    finding = {"check_id": "t", "bug_class": "open_redirect", "oracle_context": {}}
    for raw in ("FACT", {"verdict": "FACT"}, None, 1, object()):
        with pytest.raises(TypeError):
            certify_admitted(finding, raw, engagement_slug="a", signers=[])

    # An admission that did NOT return FACT must not mint, and must say why.
    demoted = verdict.admit("open_redirect.body_markup", fired=False, conclusive=True,
                            observed={"channel_established": True, "body_semantically_available": True,
                                      "not_followed_redirect": True})
    result = certify_admitted(finding, demoted, engagement_slug="a", signers=[])
    assert not result.is_fact, "minting produced a FACT from a non-FACT admission"
    assert demoted.branch in result.reason, "the demotion is not auditable — no branch in the reason"


def test_no_sovereign_live_module_mints_by_calling_confirm_and_certify_directly() -> None:
    """SLICE D1 static guarantee. A certificate must be reached ONLY through admission
    (``oracle_adapter.certify_admitted``, which alone may call ``confirm_and_certify`` and which lives in
    ``oracle_adapter.py`` — NOT under ``live/``). A sovereign ``live/*`` module that calls
    ``confirm_and_certify`` DIRECTLY bypasses every branch-capability check, so a verdict can reach a signed
    certificate with no capability ever applied — exactly the ``Outcome.CLEAN`` escape ``sbom_verify`` used
    to have (the version_range branch is clean_capable:false, yet a direct mint let a conclusive non-fire
    return CLEAN).

    This scans the SOURCE of every ``integration/vigil_integration/live/*.py`` and fails on a direct call.
    ``sbom.py`` (an earlier slice's migration) MUST be clean. The residual ``_PENDING_MIGRATION`` frontier
    is now EMPTY (SLICE W16-13): ``wiring.py`` (its LLM-provenanced LEAD path + the ``error_based_sqli`` live
    re-drive) and ``external_tool.py`` (the tool-runner's per-service re-drives) both route through
    ``verdict.admit`` + ``oracle_adapter.certify_admitted`` — the ``error_based_sqli`` live re-drive admits to
    the registered ``error_signature.datastore_error`` branch and the tool-runner's weak-crypto re-drive to
    ``weak_crypto.cert_signature_algorithm`` (both clean_capable:false, so a conclusive non-fire is
    INCONCLUSIVE, not the false CLEAN a direct mint emitted); an arbitrary LLM class with no registered branch
    is REFUSED by ``admit`` (UnregisteredBranch) rather than minted. The frontier may only SHRINK — a NEW
    direct caller, or a regression in any migrated module (including sbom.py), fails here against an empty
    frontier."""
    import ast  # noqa: PLC0415

    live = _ROOT / "integration" / "vigil_integration" / "live"
    assert live.is_dir(), f"{live} is missing — the sovereign live surface must exist to be governed"
    # The mint primitives a sovereign live/* module may NOT call directly — reaching any of them skips the
    # admission/branch-capability layer. ``certify_admitted`` is the ONLY sanctioned path (it lives in
    # oracle_adapter.py, not under live/, so it is not scanned). AST-based (not a text grep) so an aliased
    # import (`from ..oracle_adapter import confirm_and_certify as cc; cc(...)`), an attribute call
    # (`oracle_adapter.confirm_and_certify(...)` / `certify.build_certificate(...)`), a `getattr(...)`
    # dispatch, or a direct `build_certificate`/`sign_certificate` mint are all caught (red-pen D1-LOW).
    _FORBIDDEN = {"confirm_and_certify", "build_certificate", "sign_certificate"}

    def _mints_directly(src: str) -> bool:
        tree = ast.parse(src)
        aliases = set()          # local names bound to a forbidden symbol via `import ... as`
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name in _FORBIDDEN:
                        aliases.add(a.asname or a.name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in (aliases | _FORBIDDEN):
                return True                                  # cc(...) or confirm_and_certify(...)
            if isinstance(fn, ast.Attribute) and fn.attr in _FORBIDDEN:
                return True                                  # oracle_adapter.confirm_and_certify(...)
            if (isinstance(fn, ast.Name) and fn.id == "getattr" and node.args        # getattr(x,"...")(...)
                    and isinstance(node.args[-1], ast.Constant) and node.args[-1].value in _FORBIDDEN):
                return True
        return False

    # The migration FRONTIER, not a permanent exemption. It is now EMPTY: every sovereign live/* module
    # mints through the admission choke (verdict.admit + oracle_adapter.certify_admitted). sbom.py,
    # web_redrive.py, wiring.py and external_tool.py are all migrated — NONE may call confirm_and_certify
    # directly. A new module that does, or a regression in a migrated one, fails here with an empty frontier.
    _PENDING_MIGRATION: "set[str]" = set()

    offenders = {py.name for py in sorted(live.glob("*.py"))
                 if _mints_directly(py.read_text(encoding="utf-8"))}

    assert "sbom.py" not in offenders, (
        "sbom.py calls confirm_and_certify() DIRECTLY — SLICE D1 requires it route through verdict.admit() "
        "+ oracle_adapter.certify_admitted() so the clean_capable:false version_range branch cannot leak "
        "Outcome.CLEAN")
    unexpected = offenders - _PENDING_MIGRATION
    assert not unexpected, (
        f"sovereign live module(s) call confirm_and_certify() directly, bypassing admission: "
        f"{sorted(unexpected)}. Route them through oracle_adapter.certify_admitted (admission decides, "
        f"minting executes); only a genuinely pending-migration module belongs on the documented "
        f"_PENDING_MIGRATION frontier, with the branch-registry work that unblocks it.")
    # Anti-rot: an allowlisted module that no longer offends means its migration LANDED — it must be removed
    # from the frontier so the allowlist keeps shrinking and cannot silently shelter a future direct caller.
    stale = _PENDING_MIGRATION - offenders
    assert not stale, (
        f"{sorted(stale)} no longer call confirm_and_certify() directly (migration landed) — remove them "
        f"from _PENDING_MIGRATION so the frontier reflects reality")


def test_admission_over_a_clean_incapable_branch_never_mints_or_clears() -> None:
    """SLICE D1 runtime guarantee, on the exact ``version_range`` branch ``sbom_verify`` uses. A CONCLUSIVE
    non-fire over a branch declared clean_capable:false is INCONCLUSIVE (never CLEAN), and minting that
    admission yields NO signed FACT and NO CLEAN outcome — the certificate path cannot manufacture a verdict
    admission refused. This is the runtime half of the BLOCKER-1 fix: even the strongest negative an oracle
    can give (conclusive, decisive) cannot clear a branch that is not entitled to assert absence."""
    verdict = _admit()
    branch = "version_range.manifest_membership"
    decl = next(b for b in _load(_BRANCHES)["branches"] if b["id"] == branch)
    assert decl["clean_capable"] is False, "precondition of this test: the branch is not clean_capable"

    admitted = verdict.admit(branch, fired=False, conclusive=True, observed={"manifest_parsed": True})
    assert admitted.verdict is verdict.Verdict.INCONCLUSIVE, (
        f"a clean_capable:false branch cleared to {admitted.verdict} on a conclusive non-fire")

    import sys
    integration = str(_ROOT / "integration")
    if integration not in sys.path:
        sys.path.insert(0, integration)
    try:
        from vigil_integration.oracle_adapter import certify_admitted
    except Exception as exc:                       # noqa: BLE001
        pytest.fail(f"admission-gated minting unavailable — the contract is unenforced here: {exc}")

    finding = {"check_id": "sbom:test", "bug_class": "vulnerable_dependency", "oracle_context": {}}
    result = certify_admitted(finding, admitted, engagement_slug="a", signers=[])
    assert not result.is_fact, "an INCONCLUSIVE admission produced a signed FACT"
    assert result.signed is None, "no certificate may be signed for a non-FACT admission"
    assert result.outcome != "clean", "an INCONCLUSIVE admission leaked a CLEAN outcome"
    assert result.outcome == "inconclusive"


def test_body_branches_are_attributable_to_one_evidence_source() -> None:
    """A verdict must be attributable to ONE registered branch. Meta-refresh and JS sinks are different
    branches with different capabilities (declarative refresh is statically decidable; a JS sink is only
    lexically decidable), so merging them would make a verdict unattributable — and an unattributable
    verdict cannot be checked against any branch's declared capability."""
    from framework.v2.scanner.checks import js_sink_hosts, meta_refresh_hosts

    canary = "canary.example.test"
    meta = f'<meta http-equiv=refresh content="0;url=https://{canary}/a">'
    js = f'<script>location.href="//{canary}/b"</script>'
    assert canary in meta_refresh_hosts(meta) and js_sink_hosts(meta) == []
    assert canary in js_sink_hosts(js) and meta_refresh_hosts(js) == []


def _unqualified_absolutes(doc: str, text: str) -> "list[str]":
    """Paragraphs asserting an absolute with no limitation beside it. Factored out so the widened doc set
    and the mutation control exercise the SAME checker rather than two that could drift."""
    offenders: list[str] = []
    for para in re.split(r"\n\s*\n", text):
        low = para.lower()
        for absolute in _ABSOLUTES:
            if absolute in low and not any(q in low for q in _QUALIFIERS):
                offenders.append(f"{doc}: {absolute!r} unqualified in: {para.strip()[:120]}")
    return offenders


@pytest.mark.parametrize("doc", _LINTED_DOCS)
def test_capability_documents_make_no_unqualified_absolute_claims(doc: str) -> None:
    """An absolute claim is allowed only next to its boundary. Scope inflation — naming a family when only
    part of it qualifies — is how honest sentences become a dishonest document."""
    path = _ROOT / doc
    assert path.is_file(), f"{doc} is listed as a capability-describing document but does not exist"
    assert not (offenders := _unqualified_absolutes(doc, path.read_text(encoding="utf-8"))), (
        "unqualified absolute claim(s):\n" + "\n".join(offenders))


def test_the_absolute_claim_lint_is_load_bearing() -> None:
    """MUTATION CONTROL for the lint above. A checker nobody has ever seen fail is indistinguishable from
    one that cannot fail — and this one now guards the documents an evaluator actually reads, so proving it
    fires matters more than before. A paragraph carrying its boundary must pass; the same claim stripped of
    that boundary must be caught."""
    bounded = "VIGIL's oracles have zero false positives within the bounded surface each branch declares."
    assert _unqualified_absolutes("synthetic", bounded) == [], "a bounded absolute must be allowed"
    assert _unqualified_absolutes("synthetic", "VIGIL's oracles have zero false positives."), (
        "the lint did not catch an unqualified absolute — it is not load-bearing")


def test_the_capability_matrix_does_not_outrun_the_branch_registry() -> None:
    """A tool may not be marked fact_capable unless some registered branch is fact_capable, and the web
    entry must carry the honest boundary rather than claiming the whole family."""
    matrix = _load(_MATRIX)
    branches = _load(_BRANCHES)["branches"]
    assert any(b["fact_capable"] for b in branches), "registry claims no FACT-capable branch at all"

    fact_tools = {t["name"] for t in matrix["tools"] if t.get("fact_capable")}
    # THE invariant: every fact_capable tool must map to a registered fact_capable branch family — the matrix
    # may not claim a FACT the registry cannot mint. H5 added masscan/rustscan/naabu as PROPOSERS that emit
    # open-port proposals with NO redrives, so the runner re-proves each port with its OWN gated
    # capture_handshake judged by the fact_capable service_reachability.tcp_handshake branch — nmap's exact
    # re-drive+oracle path — and each PASSES the full conformance battery (test_conformance.py). So the fact
    # set grows to the SERVICE_REACHABILITY reuse tools WITHOUT outrunning the registry.
    fact_families = {b["id"].split(".")[0] for b in branches if b["fact_capable"]}
    for t in matrix["tools"]:
        if t.get("fact_capable"):
            fam = (t.get("oracle_family") or "").lower()
            assert fam in fact_families, (
                f"{t['name']} is marked fact_capable but its oracle_family {fam!r} has no fact_capable branch "
                f"in the registry — the matrix outruns the registry")
    assert fact_tools == {"nmap", "sslscan", "masscan", "rustscan", "naabu"}, (
        f"unexpected fact_capable tool set: {fact_tools}")

    httpx = [t for t in matrix["tools"] if t["name"] == "httpx"]
    assert httpx, "the web proposer row must exist"
    notes = httpx[0]["notes"].lower()
    assert "header" in notes and ("not clean-capable" in notes or "lead-only" in notes), (
        "the web capability note must state its boundary: header-derived evidence is FACT-capable, "
        "body-derived branches are not CLEAN-capable, JS is FACT-capable only from executable code")


def _matrix_capability_prose(matrix: dict) -> str:
    """The matrix's capability-describing prose: its own note plus every tool note. Lower-cased, because a
    denial is a claim regardless of its casing."""
    return " ".join([matrix.get("note", "")] + [t.get("notes", "") for t in matrix["tools"]]).lower()


def _lag_offenders(prose: str, branches: "dict[str, dict]") -> "list[str]":
    """Where the shipped matrix and the registry disagree about what a branch can do.

    Factored out so the mutation control below drives the SAME function the assertion does."""
    offenders: list[str] = []
    for bid, denials in _MATRIX_CAPABILITY_DENIALS.items():
        if bid not in branches:
            offenders.append(f"{bid}: pinned in the lag table but absent from the registry — re-point the pin")
            continue
        present = [d for d in denials if d in prose]
        if branches[bid]["fact_capable"] and present:
            offenders.append(
                f"{bid}: the registry declares it FACT-capable, but the shipped matrix still denies it: "
                f"{present!r} — the document LAGS the code (an underclaim)")
        if not branches[bid]["fact_capable"] and not present:
            offenders.append(
                f"{bid}: the registry declares it NOT FACT-capable, but the shipped matrix states no such "
                f"boundary — the document OUTRUNS the code (an overclaim)")
    return offenders


def test_the_capability_matrix_does_not_lag_the_branch_registry() -> None:
    """The mirror of ``…_does_not_outrun_…``. That test catches the matrix claiming MORE than the registry
    declares; this one catches it still DENYING a capability the registry declares — which is how a
    capability that was actually built quietly goes unsold, and how a reader concludes the JS sink is a
    regex when ``js_lex.sink_is_executable`` is a tokenizer. ``docs/CLAIM-DISCIPLINE.md`` treats an
    underclaim as the same defect as an overclaim: the ratchet only moves toward accuracy."""
    branches = {b["id"]: b for b in _load(_BRANCHES)["branches"]}
    assert not (offenders := _lag_offenders(_matrix_capability_prose(_load(_MATRIX)), branches)), (
        "the shipped capability matrix disagrees with the branch registry:\n" + "\n".join(offenders))


def test_the_lag_check_is_load_bearing() -> None:
    """MUTATION CONTROL. Re-insert the exact stale sentence the readiness audit found ("the JS-redirect
    branch is LEAD-only … needs a real JS tokenizer") into the prose and assert the check fires; then flip
    the registry's own claim and assert the check demands that boundary back. Both directions, because a
    one-directional pin would let the table rot into a no-op."""
    branches = {b["id"]: b for b in _load(_BRANCHES)["branches"]}
    assert branches["open_redirect.js_sink"]["fact_capable"], (
        "this control assumes js_sink is FACT-capable today; if that changed, re-derive the control")

    stale = "the js-redirect branch is lead-only (its regex still matches sinks inside js comments)."
    assert _lag_offenders(stale, branches), "the lag check missed a re-inserted stale denial"

    demoted = {**branches, "open_redirect.js_sink": {**branches["open_redirect.js_sink"],
                                                     "fact_capable": False}}
    assert _lag_offenders(_matrix_capability_prose(_load(_MATRIX)), demoted), (
        "a demoted branch with no boundary in the matrix went unreported — the pin is one-directional")
    assert not _lag_offenders(stale, demoted), (
        "the denial that matches a demoted branch must be ACCEPTED, not flagged")


# --- rule 1, applied to the code's own prose: a docstring may not lag its callers ----------------------
#
# The readiness audit found the flagship anti-hallucination module describing itself as "the caller-less
# PRIMITIVE … exercised only by its tests; that is by design, not a gap" — two programs after production
# wired it. A phasing note that outlives its phase is an UNDERCLAIM, and the reader who opens the module
# named for the product's core guarantee is the worst possible person to mislead.
_FIREWALL = Path("engine/crucible/framework/v2/veracity/firewall.py")
_FIREWALL_CALLERS = (
    "report/grounding.py",
    "evidence/certify.py",
    "aegis/pipeline.py",
    "agents/critics.py",
    "agents/cognitive_refusal.py",
)
# Phrases that assert the module has no production callers. Legal only while that is true.
_FIREWALL_NO_CALLER_PHRASES = (
    "caller-less",
    "exercised only by its tests",
    "runtime enforcement is\nwired in the subsequent phases",
)
_V2 = Path("engine/crucible/framework/v2")


def _module_calls_admit(rel: str) -> bool:
    """Whether this module really routes a claim through the veracity firewall. Both halves are required —
    a bare ``admit(`` could be an unrelated helper (``verdict.admit`` in the sovereign live path is a
    different function entirely), and a bare mention of veracity could be a comment."""
    src = (_ROOT / _V2 / rel).read_text(encoding="utf-8")
    return "admit(" in src and ("veracity" in src or "firewall" in src)


def _firewall_doc_offenders(doc: str, callers: "tuple[str, ...]") -> "list[str]":
    """Where the firewall docstring and its real call graph disagree. Factored out so the mutation control
    drives the SAME function the assertion does."""
    offenders: list[str] = []
    low = doc.lower()
    for phrase in _FIREWALL_NO_CALLER_PHRASES:
        if phrase in low and callers:
            offenders.append(
                f"the firewall docstring still claims it has no production callers ({phrase!r}), but "
                f"{len(callers)} module(s) route through admit(): {callers!r} — an UNDERCLAIM")
    for rel in callers:
        # The FULL dotted path, not the bare stem: "pipeline" alone would be satisfied by any sentence
        # mentioning a pipeline, so dropping ``aegis.pipeline`` would go unnoticed.
        dotted = rel.removesuffix(".py").replace("/", ".")
        if dotted not in low and rel not in low:
            offenders.append(
                f"{rel} calls admit() but the firewall docstring does not name it ({dotted!r}) — the "
                f"WHERE THIS IS WIRED list has rotted")
    return offenders


def test_the_veracity_firewall_docstring_does_not_lag_its_callers() -> None:
    """Rule 1 turned on the codebase's own prose. Both directions are pinned: every module that really
    routes through ``admit()`` must be named in the docstring, and the retired "not yet wired" phrasing may
    not come back while those callers exist."""
    for rel in _FIREWALL_CALLERS:
        assert _module_calls_admit(rel), (
            f"{rel} no longer calls admit() — this pin is stale; re-derive the caller list AND the "
            f"firewall docstring rather than deleting the assertion")
    doc = (_ROOT / _FIREWALL).read_text(encoding="utf-8").split('"""')[1]
    assert not (offenders := _firewall_doc_offenders(doc, _FIREWALL_CALLERS)), "\n".join(offenders)


def test_the_firewall_docstring_check_is_load_bearing() -> None:
    """MUTATION CONTROL. The exact stale sentence the audit found must be caught, and so must a docstring
    that silently drops a caller."""
    stale = ("this is the caller-less PRIMITIVE (veracity P0) … Until then admit() is exercised only by "
             "its tests; that is by design, not a gap.")
    assert _firewall_doc_offenders(stale, _FIREWALL_CALLERS), (
        "the check missed the exact underclaim the readiness audit found")
    assert _firewall_doc_offenders("admit() re-executes each cited ground.", ("aegis/pipeline.py",)), (
        "a docstring naming none of its callers went unreported")
    assert _firewall_doc_offenders("wired by the defensive pipeline", ("aegis/pipeline.py",)), (
        "a bare stem satisfied the pin — dropping a named caller for a vague noun must still be caught")
    assert not _firewall_doc_offenders("wired by aegis.pipeline", ("aegis/pipeline.py",)), (
        "a docstring that DOES name its caller must pass")


def test_the_firewall_is_not_a_universal_graph_gate() -> None:
    """The docstring's HONEST BOUND, machine-checked in the other direction: it states that
    ``worldmodel.graph`` has no admission gate and that admission happens at the WRITERS. If someone wires
    the gate into ``graph`` itself, that bound becomes a stale underclaim — so this test fails and forces
    the docstring to be upgraded rather than left describing a weaker system than the one that ships."""
    graph_src = (_ROOT / _V2 / "worldmodel" / "graph.py").read_text(encoding="utf-8")
    # WIRED, not MENTIONED. This used to assert the substring "veracity" was absent from the file, which
    # also fired on a COMMENT — graph.py legitimately explains why it must let the firewall's ``demoted:``
    # marker through the confidence tiebreak, and naming the layer that owns that marker is the clearest
    # way to say it. The temptation at that point is to rename the comment to dodge the check, which is
    # precisely the evasion this file exists to catch, so the check reads the CODE instead: an import of
    # the veracity package, or a call to admit(). A prose reference is not a gate; either of those is.
    tree = ast.parse(graph_src)
    wired: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and "veracity" in (node.module or ""):
            wired.append(f"imports from {node.module}")
        elif isinstance(node, ast.Import):
            wired += [f"imports {a.name}" for a in node.names if "veracity" in a.name]
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name == "admit":
                wired.append("calls admit()")
    assert not wired, (
        "worldmodel/graph.py now WIRES the veracity firewall (" + "; ".join(wired) + ") — the firewall "
        "docstring's 'graph has NO admission gate' bound is no longer true and must be rewritten UP, not "
        "left stale")
    doc = (_ROOT / _FIREWALL).read_text(encoding="utf-8").split('"""')[1].lower()
    assert "no admission gate" in doc, (
        "the firewall docstring must keep stating the bound it actually has — that admission is on the "
        "wired paths, not on graph.add_node")


# --- S8: the evidence-family LEAD-only declaration + its two new schema columns -----------------------
#
# S8 adds ``control_requirements`` and ``oracle_version`` to every branch and registers the Strix candidate
# families LEAD-only (operator decision 2: a producer's report is a LEAD until VIGIL independently re-drives
# it into an already-FACT-capable branch). The manifest validator
# (integration/vigil_integration/live/tool_manifest.py) owns the STRUCTURAL invariants over the new columns;
# these ladder tests drive it and add the offense-leg check that a declared oracle_version is a REAL,
# versionable OracleKind — the check tool_manifest cannot make without importing framework.

# The Strix candidate families this slice declares LEAD-only. Pinned so a future edit that quietly promotes
# one to FACT-capable (before the re-drive it requires exists) fails here.
_STRIX_LEAD_ONLY = {
    "strix.dom_execution",
    "strix.auth_outcome",
    "strix.source_to_sink",
    "strix.service_reachability",
    "strix.tls_negotiation",
    "strix.cloud_credential_confirmation",
    "strix.misconfiguration_artifact",
}


def _tool_manifest():
    """Import the sovereign-safe branch-registry validator, or FAIL (never skip — the S8 columns are
    unenforced without it)."""
    import sys
    integration = str(_ROOT / "integration")
    if integration not in sys.path:
        sys.path.insert(0, integration)
    try:
        from vigil_integration.live import tool_manifest
    except Exception as exc:                       # noqa: BLE001
        pytest.fail(f"branch-registry validator unavailable — the S8 columns are unenforced here: {exc}")
    return tool_manifest


def test_every_branch_declares_the_s8_columns_and_passes_the_manifest_validator() -> None:
    """Rule: every evidence branch declares ``control_requirements`` (a non-empty list of non-empty strings)
    and ``oracle_version`` (a string), and satisfies fact_capable ⇒ oracle_version / LEAD-only ⇒ no
    oracle_version. Enforced by the SAME validator the manifest module ships, over the SAME registry."""
    tm = _tool_manifest()
    rows = tm.load_branch_registry(_BRANCHES)
    assert rows, "the branch registry is empty"
    errs = tm.validate_branch_registry(rows)
    assert not errs, "evidence-branch S8-column violations:\n  " + "\n  ".join(errs)


def test_every_fact_capable_branch_names_a_real_versionable_oracle() -> None:
    """The offense-leg strengthening of the structural rule: a declared ``oracle_version`` is not just a
    non-empty string, it is a REAL OracleKind whose deterministic source resolves to a version — so the FACT
    a branch mints truly binds a decision procedure a verifier can re-run. LEAD-only branches name none."""
    import sys
    engine = str(_ROOT / "engine" / "crucible")
    if engine not in sys.path:
        sys.path.insert(0, engine)
    from framework.v2.verify.models import OracleKind
    from framework.v2.verify.oracle_version import oracle_version

    kinds = {k.value for k in OracleKind}
    for branch in _load(_BRANCHES)["branches"]:
        bid, ov = branch["id"], branch.get("oracle_version", "")
        if branch["fact_capable"]:
            assert ov in kinds, f"{bid}: oracle_version {ov!r} is not a real OracleKind value"
            assert oracle_version(ov).startswith("sha256:"), (
                f"{bid}: OracleKind {ov!r} has no resolvable versioned source — a FACT cannot bind it")
        else:
            assert ov == "", f"{bid}: LEAD-only branch names oracle_version {ov!r} — it adjudicates no FACT"


def test_the_strix_candidate_families_are_registered_lead_only() -> None:
    """Operator decision 2, made structural: each Strix candidate family is present, LEAD-only (neither
    FACT- nor CLEAN-capable), still TARGETS FACT-capability, and names the missing oracle/control in
    blocking_work — so a Strix report can never mint a FACT until VIGIL wires its own re-drive."""
    by = {b["id"]: b for b in _load(_BRANCHES)["branches"]}
    missing = _STRIX_LEAD_ONLY - set(by)
    assert not missing, f"Strix candidate families absent from the ladder: {sorted(missing)}"
    for bid in sorted(_STRIX_LEAD_ONLY):
        b = by[bid]
        assert b["fact_capable"] is False, f"{bid}: a Strix producer report must be LEAD-only, not FACT-capable"
        assert b["clean_capable"] is False, f"{bid}: LEAD-only branch cannot be CLEAN-capable"
        assert b["target_fact_capable"] is True, f"{bid}: must still TARGET FACT-capability (the ladder rule)"
        assert "lead-only" in b["limitation"].lower(), f"{bid}: limitation must state it is LEAD-only"
        work = (b.get("blocking_work") or "").strip()
        assert len(work) > 40 and ("oracle" in work.lower() or "control" in work.lower() or "capture" in work.lower()), (
            f"{bid}: blocking_work must name the missing oracle/control that closes the FACT gap")
        assert b.get("control_requirements"), f"{bid}: must name the controls it depends on / is missing"


def test_the_s8_column_validator_is_load_bearing() -> None:
    """MUTATION CONTROL for the branch-registry validator. A checker nobody has seen fail is one that cannot
    fail — so a valid row must pass and each broken row must be caught: a fact_capable row with no
    oracle_version, a LEAD-only row that names one, and an empty / mistyped control_requirements list."""
    tm = _tool_manifest()

    ok_fact = {"id": "x.fact", "fact_capable": True, "oracle_version": "service_reachability",
               "control_requirements": ["warden_scope_gate"]}
    ok_lead = {"id": "x.lead", "fact_capable": False, "oracle_version": "",
               "control_requirements": ["missing_redrive"]}
    assert tm.validate_branch_row(ok_fact) == [], "a valid fact_capable row must pass"
    assert tm.validate_branch_row(ok_lead) == [], "a valid LEAD-only row must pass"

    assert any("oracle_version" in e for e in tm.validate_branch_row(
        {**ok_fact, "oracle_version": ""})), "fact_capable with empty oracle_version must be caught"
    assert any("oracle_version" in e for e in tm.validate_branch_row(
        {**ok_lead, "oracle_version": "service_reachability"})), "LEAD-only naming an oracle must be caught"
    assert any("control_requirements" in e for e in tm.validate_branch_row(
        {**ok_fact, "control_requirements": []})), "empty control_requirements must be caught"
    assert any("control_requirements" in e for e in tm.validate_branch_row(
        {**ok_fact, "control_requirements": ["", "  "]})), "blank control_requirements entries must be caught"
    # cross-row: a duplicate id is caught by the registry-level check.
    assert any("duplicate" in e for e in tm.validate_branch_registry([ok_fact, dict(ok_fact)])), (
        "a duplicate evidence branch id must be caught")
