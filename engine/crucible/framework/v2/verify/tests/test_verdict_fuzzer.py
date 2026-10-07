"""DETERMINISTIC verdict fuzzer for the Lane S / Lane P structural FACT-eligibility grammar.

This is the automated regression guard the Lane S saga earned: a hand-maintained battery of ~20 cases
(``test_posture_reexecutable._PREDICATE_CASES``) cannot prove that a FUTURE edit to the grammar did not
re-open a hole. This module ENUMERATES the grammar's whole leaf × op × wrapper × combinator space and
asserts two properties over every generated triple:

  (a1) SOUNDNESS — ``predicate_oracle`` fires (and ``_fact_eligible`` is True) EXACTLY on the shapes the
       grammar intends. Each case carries an INDEPENDENT, hand-derived ``eligible`` / ``fired`` verdict
       (encoding the documented spec in :mod:`framework.v2.verify.oracles` — PD2/PD3/PD-NUM/PD-VALUE/PD4,
       the liveness-flag demotion, the ``any`` whole-disjunction rule, the ``not`` never-a-driver rule),
       NOT a re-walk of the implementation. So if the grammar REGRESSES — e.g. the bare-liveness-flag
       exclusion (step 1) is deleted and ``gt[probe_count,0]`` mints again, or the ``any`` rule weakens to
       "ANY disjunct" and a mixed ``any`` with one unsound disjunct mints — the real oracle disagrees with
       this file's independent verdict and a test turns RED.

  (a2) KERNEL-PARITY — the REAL oracle's ``(fired, conclusive)`` equals BOTH zero-VIGIL stdlib kernels
       (``posture.certificate._reexec_fired_conclusive`` and ``docs/.../verify_vf._reexec_fired_conclusive``)
       over the ENTIRE generated space, extending the hand battery from ~20 cases to the whole grammar. A
       regression mirrored into only one engine (the external-repro moat diverging — the Lane S CI lesson)
       turns this RED.

DETERMINISM DOCTRINE. The verification layer forbids rng / wallclock, and ``hypothesis`` is not installed,
so this fuzzer is a DETERMINISTIC structured ENUMERATOR: pure Python, no ``random`` / ``time`` / external
corpus, reproducible byte-for-byte across runs, and BOUNDED (a few hundred cases, well under a minute). The
generated-case COUNT is asserted against a floor and logged (``test_case_count_is_logged_and_covers_axes``)
so a silent shrink of the generator is visible as a failing count rather than quiet coverage loss.

SELF-CONTAINED across CI legs. The two kernels are loaded via ``spec_from_file_location`` from repo-root
absolute paths (both are ``vigil_core`` + stdlib / cryptography only), so this file runs its parity leg in
the crucible-core job (``working-directory: engine/crucible``, no ``integration`` on the path) AND in the
offense leg AND in the local validate env — parity is never silently skipped.
"""
from __future__ import annotations

import importlib.util
from collections import namedtuple
from pathlib import Path

import pytest

from framework.v2.verify import oracles
from framework.v2.verify.oracles import _LIVENESS_AVAILABILITY_KEYS, predicate_oracle

# --------------------------------------------------------------------------------------------------
# The grammar's building blocks, as a deterministic enumerator.
# --------------------------------------------------------------------------------------------------
# A Leaf is a terminal predicate plus the observed/provenance bindings that resolve its operands, and the
# INDEPENDENT verdict about whether it is a self-sufficient positive discriminator (``eligible``) and about
# the observed values that make its *raw* evaluation True / False. ``obs_unsat`` is the observed variant that
# makes an ELIGIBLE leaf evaluate False (an eligible-but-non-firing / channel-confirmed-clean case); it is
# ``None`` for an ineligible leaf (we only need the raw-True variant there, to prove the gate SUPPRESSES a
# would-be fire). ``raises`` marks an eligible leaf whose evaluation raises (an ill-typed comparison) — the
# oracle reaches the eligibility gate first, then the eval error makes it a non-conclusive non-fire.
Leaf = namedtuple("Leaf", "pred prefs obs_sat obs_unsat eligible raises")

# A Case is a fully-assembled (predicate, observed, provenance_refs) triple with the independent verdict
# (``eligible`` — whether ``_fact_eligible`` must return True; ``fired`` — whether ``predicate_oracle.fired``
# must be True on this exact observed binding).
Case = namedtuple("Case", "cid pred obs prefs eligible fired")


def _leaf(pred, *, prefs=None, obs_sat, obs_unsat=None, eligible, raises=False):
    return Leaf(pred, dict(prefs or {}), dict(obs_sat), (dict(obs_unsat) if obs_unsat is not None else None),
                eligible, raises)


# ---- INELIGIBLE leaves (no positive discriminator): obs_sat makes the RAW eval True, so each case proves
#      the grammar SUPPRESSES a would-be fire. ------------------------------------------------------------

def leaf_bare_match_lit(ns, op):
    """A bare positive match of a captured var against a producer-authorable string LITERAL — the text-echo
    class the red-pen refuses. Ineligible for every match op."""
    k = f"{ns}_body"
    needle = "distinctive-token"
    if op in ("contains", "icontains"):
        obs = {k: f"xx {needle} yy"}
    elif op == "in":
        obs = {k: needle}
        return _leaf({op: [{"var": k}, [needle, "other"]]}, obs_sat=obs, eligible=False)
    else:  # eq / ieq
        obs = {k: needle}
    return _leaf({op: [{"var": k}, needle]}, obs_sat=obs, eligible=False)


def leaf_cv_vs_status(ns):
    """``eq[CV, 200]`` — a protocol-status constant is a gate-B corroborator, never a PD-VALUE."""
    k = f"{ns}_st"
    return _leaf({"eq": [{"var": k}, 200]}, obs_sat={k: 200}, eligible=False)


def leaf_min_len_floor(ns):
    """``min_len[CV, 1]`` — a length floor, never a value comparison."""
    k = f"{ns}_tok"
    return _leaf({"min_len": [{"var": k}, 1]}, obs_sat={k: "abcdef"}, eligible=False)


def leaf_ge_vs_num_lit(ns):
    """``ge[CV, 5]`` — a ``ge`` of a captured var against a scalar literal is NOT a PD-VALUE (only strict
    ``gt`` is; ``ge`` at a domain floor is vacuous)."""
    k = f"{ns}_n"
    return _leaf({"ge": [{"var": k}, 5]}, obs_sat={k: 9}, eligible=False)


def leaf_ge_vs_str_lit(ns):
    """``ge[CV, '!']`` — a string-literal floor (the red-pen's ge-at-domain-min string variant)."""
    k = f"{ns}_s"
    return _leaf({"ge": [{"var": k}, "!"]}, obs_sat={k: "zzzzzz"}, eligible=False)


def leaf_liveness_eq_bool(key):
    """``eq[<liveness flag>, True]`` — true for any reachable target, a corroborator, never a PD-VALUE.
    ``key`` is a member of ``_LIVENESS_AVAILABILITY_KEYS`` (NOT namespaced — the exclusion matches the exact
    name, case-insensitively)."""
    return _leaf({"eq": [{"var": key}, True]}, obs_sat={key: True}, eligible=False)


def leaf_liveness_gt_count(key):
    """``gt[<liveness count>, 0]`` — shares the EXACT shape of the genuine achieved ``gt[qty,0]``; only the
    NAMED key separates them, so this is ineligible while ``gt[qty,0]`` is eligible."""
    return _leaf({"gt": [{"var": key}, 0]}, obs_sat={key: 3}, eligible=False)


# ---- ELIGIBLE leaves (a positive discriminator): obs_sat fires, obs_unsat is eligible-but-non-firing. ----

def leaf_pd2(ns, op, swapped=False):
    """PD2 — a positive-match op with one VIGIL-injected provenance-ref (canary) operand and one captured
    var, ORDER-INSENSITIVE. The producer cannot author the canary."""
    cv, pr = f"{ns}_cv", f"{ns}_pr"
    prefs = {pr: "canary"}
    if op in ("contains", "icontains"):
        body, needle = (pr, cv) if swapped else (cv, pr)  # body contains needle
        obs_sat = {cv: ("xx canaryvalue yy" if body == cv else "canaryvalue"),
                   pr: ("xx canaryvalue yy" if body == pr else "canaryvalue")}
        obs_unsat = {cv: ("nomatchhere" if body == cv else "canaryvalue"),
                     pr: ("nomatchhere" if body == pr else "canaryvalue")}
        return _leaf({op: [{"var": body}, {"var": needle}]}, prefs=prefs,
                     obs_sat=obs_sat, obs_unsat=obs_unsat, eligible=True)
    if op == "in":
        elem, cont = (pr, cv) if swapped else (cv, pr)  # elem in cont
        obs_sat = {elem: "item", cont: ["item", "b"]} if elem != cont else {elem: "item"}
        obs_unsat = {elem: "zzz", cont: ["item", "b"]}
        return _leaf({op: [{"var": elem}, {"var": cont}]}, prefs=prefs,
                     obs_sat=obs_sat, obs_unsat=obs_unsat, eligible=True)
    # eq / ieq
    a, b = (pr, cv) if swapped else (cv, pr)
    return _leaf({op: [{"var": a}, {"var": b}]}, prefs=prefs,
                 obs_sat={cv: "canaryvalue", pr: "canaryvalue"},
                 obs_unsat={cv: "different", pr: "canaryvalue"}, eligible=True)


def leaf_pd3(ns):
    """PD3 — ``gt[PR, int>=0]``: a VIGIL-injected reduction strictly inside its domain."""
    pr = f"{ns}_red"
    return _leaf({"gt": [{"var": pr}, 0]}, prefs={pr: "reduction"},
                 obs_sat={pr: 5}, obs_unsat={pr: 0}, eligible=True)


def leaf_pdnum(ns, op):
    """PD-NUM — ``gt``/``ge`` over two DISTINCT captured quantities (e.g. successes > max_allowed)."""
    a, b = f"{ns}_a", f"{ns}_b"
    if op == "gt":
        return _leaf({op: [{"var": a}, {"var": b}]}, obs_sat={a: 7, b: 3}, obs_unsat={a: 3, b: 7}, eligible=True)
    return _leaf({op: [{"var": a}, {"var": b}]}, obs_sat={a: 7, b: 3}, obs_unsat={a: 2, b: 7}, eligible=True)


def leaf_pdvalue_bool(ns):
    """PD-VALUE — ``eq[CV, True]`` over a NON-liveness captured flag (a genuine achieved-state flag like
    ``checked_out``)."""
    k = f"{ns}_flag"
    return _leaf({"eq": [{"var": k}, True]}, obs_sat={k: True}, obs_unsat={k: False}, eligible=True)


def leaf_pdvalue_num_eq(ns):
    """PD-VALUE — ``eq[CV, -5]`` over a captured quantity (bizlogic ``eq[qty,-5]``)."""
    k = f"{ns}_q"
    return _leaf({"eq": [{"var": k}, -5]}, obs_sat={k: -5}, obs_unsat={k: 1}, eligible=True)


def leaf_pdvalue_num_gt(ns):
    """PD-VALUE — ``gt[CV, 0]`` over a NON-liveness captured quantity (bizlogic ``gt[qty,0]``). SAME shape
    as the refused ``gt[probe_count,0]``: only the key differs."""
    k = f"{ns}_qty"
    return _leaf({"gt": [{"var": k}, 0]}, obs_sat={k: 1}, obs_unsat={k: 0}, eligible=True)


def leaf_pdnum_typeerr(ns):
    """PD-NUM by SHAPE (two distinct captured vars) but an ill-typed comparison (str > int) — eligible, yet
    the eval raises, so the oracle returns a non-conclusive non-fire. Pins the ill-typed-child parity."""
    a, b = f"{ns}_s", f"{ns}_n"
    return _leaf({"gt": [{"var": a}, {"var": b}]}, obs_sat={a: "abcdef", b: 7}, eligible=True, raises=True)


def leaf_gate(ns):
    """An INELIGIBLE leaf that EVALUATES True — a corroborator conjunct used inside an ``all`` so firing of
    the ``all`` tracks the eligible sibling, not the gate."""
    return leaf_min_len_floor(ns)  # min_len[CV,1] over a 6-char body — ineligible, raw-True.


# --------------------------------------------------------------------------------------------------
# Case generation — product of leaf families × wrappers × combinators.
# --------------------------------------------------------------------------------------------------

MATCH_OPS = ("eq", "ieq", "contains", "icontains", "in")

# Every leaf family, with a stable id prefix. ``maker(ns)`` returns a Leaf.
_INELIGIBLE_LEAF_MAKERS = (
    *[(f"bare_{op}", (lambda ns, op=op: leaf_bare_match_lit(ns, op))) for op in MATCH_OPS],
    ("cv_vs_status", leaf_cv_vs_status),
    ("min_len", leaf_min_len_floor),
    ("ge_num_lit", leaf_ge_vs_num_lit),
    ("ge_str_lit", leaf_ge_vs_str_lit),
)
_ELIGIBLE_LEAF_MAKERS = (
    *[(f"pd2_{op}", (lambda ns, op=op: leaf_pd2(ns, op))) for op in MATCH_OPS],
    *[(f"pd2swap_{op}", (lambda ns, op=op: leaf_pd2(ns, op, swapped=True))) for op in MATCH_OPS],
    ("pd3", leaf_pd3),
    ("pdnum_gt", lambda ns: leaf_pdnum(ns, "gt")),
    ("pdnum_ge", lambda ns: leaf_pdnum(ns, "ge")),
    ("pdvalue_bool", leaf_pdvalue_bool),
    ("pdvalue_num_eq", leaf_pdvalue_num_eq),
    ("pdvalue_num_gt", leaf_pdvalue_num_gt),
    ("pdnum_typeerr", leaf_pdnum_typeerr),
)


def _merge(*dicts):
    out = {}
    for d in dicts:
        if d:
            out.update(d)
    return out


def _bare_cases(label, maker):
    """BARE wrapper — the leaf alone. Eligible leaves get a firing (sat) and an eligible-but-non-firing
    (unsat) case; ineligible leaves get the raw-True case (gate must suppress it)."""
    leaf = maker("b")
    if leaf.eligible:
        yield Case(f"bare[{label}]:sat", leaf.pred, leaf.obs_sat, leaf.prefs, True, not leaf.raises)
        if leaf.obs_unsat is not None:
            yield Case(f"bare[{label}]:unsat", leaf.pred, leaf.obs_unsat, leaf.prefs, True, False)
    else:
        yield Case(f"bare[{label}]:rawtrue", leaf.pred, leaf.obs_sat, leaf.prefs, False, False)


def _not_cases(label, maker):
    """NOT wrapper — ``not(X)`` is NEVER a positive fire-driver, so the whole predicate is ineligible and
    must NOT fire, even when X is a real PD that evaluates True."""
    leaf = maker("n")
    yield Case(f"not[{label}]", {"not": leaf.pred}, leaf.obs_sat, leaf.prefs, False, False)


def _all_gate_cases(label, maker):
    """ALL-with-gate — ``all([gate, leaf])``: eligible iff the leaf is (one eligible conjunct makes the whole
    conjunction eligible); the gate evaluates True so the ``all`` fires exactly when the leaf does."""
    leaf = maker("ag")
    gate = leaf_gate("gate_ag")
    pred = {"all": [gate.pred, leaf.pred]}
    base = _merge(gate.obs_sat, leaf.prefs)
    if leaf.eligible:
        yield Case(f"all_gate[{label}]:sat", pred, _merge(base, leaf.obs_sat), leaf.prefs, True,
                   not leaf.raises)
        if leaf.obs_unsat is not None:
            yield Case(f"all_gate[{label}]:unsat", pred, _merge(base, leaf.obs_unsat), leaf.prefs, True, False)
    else:
        yield Case(f"all_gate[{label}]:rawtrue", pred, _merge(base, leaf.obs_sat), leaf.prefs, False, False)


def _any_singleton_cases(label, maker):
    """ANY singleton — ``any([leaf])``: eligible iff the single disjunct is."""
    leaf = maker("as")
    pred = {"any": [leaf.pred]}
    if leaf.eligible:
        yield Case(f"any1[{label}]:sat", pred, leaf.obs_sat, leaf.prefs, True, not leaf.raises)
        if leaf.obs_unsat is not None:
            yield Case(f"any1[{label}]:unsat", pred, leaf.obs_unsat, leaf.prefs, True, False)
    else:
        yield Case(f"any1[{label}]:rawtrue", pred, leaf.obs_sat, leaf.prefs, False, False)


def _nested_cases(label, maker):
    """Nested combinators — ``all([all([leaf])])`` and ``any([any([leaf])])``: recursion must see through
    the nesting."""
    for tag, wrap in (("all_all", lambda p: {"all": [{"all": [p]}]}),
                      ("any_any", lambda p: {"any": [{"any": [p]}]})):
        leaf = maker(f"ns_{tag}")
        pred = wrap(leaf.pred)
        if leaf.eligible:
            yield Case(f"{tag}[{label}]:sat", pred, leaf.obs_sat, leaf.prefs, True, not leaf.raises)
        else:
            yield Case(f"{tag}[{label}]:rawtrue", pred, leaf.obs_sat, leaf.prefs, False, False)


def _generate():
    cases: list[Case] = []

    # --- single-leaf families through every structure-preserving wrapper ---
    for label, maker in (*_INELIGIBLE_LEAF_MAKERS, *_ELIGIBLE_LEAF_MAKERS):
        cases += _bare_cases(label, maker)
        cases += _not_cases(label, maker)
        cases += _all_gate_cases(label, maker)
        cases += _any_singleton_cases(label, maker)
        cases += _nested_cases(label, maker)

    # --- the ``any`` whole-disjunction rule: ANY disjunct ineligible => the whole ``any`` is ineligible and
    #     must NOT mint, even though another disjunct is a real PD that evaluates True. This is the soundness
    #     property a "fires if ANY disjunct fires" regression would break. ---
    pd = leaf_pd2("mix_e", "eq")                 # eligible, evaluates True on obs_sat
    bad = leaf_bare_match_lit("mix_i", "contains")  # ineligible, evaluates True on obs_sat
    cases.append(Case("any_mixed[pd2+bare]:both_raw_true",
                      {"any": [pd.pred, bad.pred]}, _merge(pd.obs_sat, bad.obs_sat),
                      pd.prefs, False, False))
    # and the dual: ``all([bad, pd])`` IS eligible (one eligible conjunct) and fires when both eval True.
    cases.append(Case("all_mixed[bare+pd2]:sat",
                      {"all": [bad.pred, pd.pred]}, _merge(pd.obs_sat, bad.obs_sat), pd.prefs, True, True))

    # --- ANY over two eligible disjuncts: eligible; fires iff either evaluates True. ---
    e1, e2 = leaf_pd2("aa1", "eq"), leaf_pdvalue_num_gt("aa2")
    cases.append(Case("any2[pd2+pdvalue]:first_true",
                      {"any": [e1.pred, e2.pred]}, _merge(e1.obs_sat, e2.obs_unsat), _merge(e1.prefs, e2.prefs),
                      True, True))
    cases.append(Case("any2[pd2+pdvalue]:none_true",
                      {"any": [e1.pred, e2.pred]}, _merge(e1.obs_unsat, e2.obs_unsat),
                      _merge(e1.prefs, e2.prefs), True, False))

    # --- PD4 present/absent differential at an ``all`` ---
    def _pd4(ns, needle, same_body):
        a = f"{ns}_a"
        b = a if same_body else f"{ns}_b"
        pred = {"all": [{"contains": [{"var": a}, needle]},
                        {"not": {"contains": [{"var": b}, needle]}}]}
        return a, b, pred

    a, b, pred = _pd4("pd4ok", "distinctive-canary", same_body=False)
    cases.append(Case("pd4[distinct,distinctive]:sat", pred,
                      {a: "xx distinctive-canary yy", b: "clean body text"}, {}, True, True))
    cases.append(Case("pd4[distinct,distinctive]:unsat", pred,
                      {a: "xx distinctive-canary yy", b: "also distinctive-canary here"}, {}, True, False))
    # needle too short (< _DISTINCTIVENESS_MIN_LEN) => NOT a PD4 => ineligible, though raw eval is True.
    a2, b2, pred2 = _pd4("pd4short", "ab", same_body=False)
    cases.append(Case("pd4[short_needle]:rawtrue", pred2, {a2: "xxabyy", b2: "clean"}, {}, False, False))
    # same captured body on both sides => not a differential => ineligible.
    a3, _b3, pred3 = _pd4("pd4same", "distinctive-canary", same_body=True)
    cases.append(Case("pd4[same_body]:rawtrue", pred3, {a3: "distinctive-canary"}, {}, False, False))

    # --- liveness-flag demotion (step 1): every key in the exclusion set, as a SOLE discriminator and as a
    #     lone ``any`` disjunct, is ineligible — though raw eval is True. ---
    for key in sorted(_LIVENESS_AVAILABILITY_KEYS):
        lv = leaf_liveness_eq_bool(key)
        cases.append(Case(f"liveness_sole_eq[{key}]:rawtrue", lv.pred, lv.obs_sat, {}, False, False))
        cases.append(Case(f"liveness_any_eq[{key}]:rawtrue", {"any": [lv.pred]}, lv.obs_sat, {}, False, False))
    # the gt[count,0] shape for the count-like keys (same shape as the eligible gt[qty,0]).
    for key in ("probe_count", "probes", "response_count", "reply_count"):
        lv = leaf_liveness_gt_count(key)
        cases.append(Case(f"liveness_sole_gt[{key}]:rawtrue", lv.pred, lv.obs_sat, {}, False, False))

    # liveness CORROBORATING inside an ``all`` that ALSO carries a real PD => the demotion costs nothing;
    # the ``all`` is eligible and fires when every conjunct evaluates True (the real graphql/host-header shape).
    lvb = leaf_liveness_eq_bool("body_available")
    red = leaf_pd3("liv_red")
    cases.append(Case("liveness_in_all_with_pd3:sat",
                      {"all": [lvb.pred, red.pred]}, _merge(lvb.obs_sat, red.obs_sat), red.prefs, True, True))
    # but as an ``any`` disjunct ALONGSIDE an eligible PD, the liveness disjunct is still ineligible => the
    # whole ``any`` is ineligible (every disjunct must carry a PD).
    cases.append(Case("liveness_any_with_pd3:ineligible",
                      {"any": [lvb.pred, red.pred]}, _merge(lvb.obs_sat, red.obs_sat), red.prefs, False, False))

    # the direct CONTRAST: gt[qty,0] (non-liveness key, SAME shape) IS eligible and fires — proving only the
    # NAMED key, not the floor value, is the discriminator.
    qty = leaf_pdvalue_num_gt("contrast")
    cases.append(Case("contrast_gt_qty_0:fires", qty.pred, qty.obs_sat, {}, True, True))

    # --- value-independent / tautology / degenerate shapes: all ineligible (no captured-value dependence /
    #     no PD), all => (fired False, conclusive False). ---
    cases.append(Case("taut_all_literal_eq", {"eq": ["x", "x"]}, {}, {}, False, False))
    cases.append(Case("taut_self_eq", {"eq": [{"var": "k"}, {"var": "k"}]}, {"k": "v"}, {}, False, False))
    cases.append(Case("taut_self_in", {"in": [{"var": "k"}, {"var": "k"}]}, {"k": ["v"]}, {}, False, False))
    cases.append(Case("taut_self_ge", {"ge": [{"var": "k"}, {"var": "k"}]}, {"k": 5}, {}, False, False))
    cases.append(Case("not_self_eq_distinct",
                      {"not": {"eq": [{"var": "a"}, {"var": "b"}]}}, {"a": "x", "b": "y"}, {}, False, False))

    # --- malformed predicates: the eligibility/binds walk raises => malformed branch, (False, False). ---
    cases.append(Case("malformed_empty_dict", {}, {}, {}, False, False))
    cases.append(Case("malformed_two_ops", {"eq": [1, 1], "gt": [2, 1]}, {}, {}, False, False))
    cases.append(Case("malformed_eq_no_args", {"eq": []}, {}, {}, False, False))
    cases.append(Case("malformed_all_empty", {"all": []}, {}, {}, False, False))

    # Guard against accidental duplicate ids (which would hide a shrink behind pytest de-dup).
    ids = [c.cid for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case id(s): " + ", ".join(
        sorted({i for i in ids if ids.count(i) > 1}))
    return cases


CASES: list[Case] = _generate()
CASE_COUNT = len(CASES)


# --------------------------------------------------------------------------------------------------
# The two zero-VIGIL stdlib kernels — loaded standalone (vigil_core + stdlib only), so parity runs in every
# CI leg including crucible-core (no ``integration`` on the path).
# --------------------------------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parents[6]
_CERT = _REPO / "integration" / "vigil_integration" / "posture" / "certificate.py"
_VERIFY_VF = _REPO / "docs" / "proof-carrying-finding" / "verify_vf.py"


def _load(name, path):
    if not path.exists():
        pytest.skip(f"kernel not present on this ref: {path}")
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:  # noqa: BLE001 — a kernel that cannot load standalone here is a clean skip
        pytest.skip(f"kernel {path.name} not importable standalone here: {e}")
    return mod


# --------------------------------------------------------------------------------------------------
# (a1) SOUNDNESS — the real oracle fires EXACTLY on the intended shapes.
# --------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("case", CASES, ids=[c.cid for c in CASES])
def test_soundness_fact_eligibility_and_fire(case):
    """``_fact_eligible`` equals the INDEPENDENT per-case verdict, and ``predicate_oracle.fired`` matches the
    hand-derived expectation. Because the verdicts are derived from the documented grammar (not a re-walk of
    the code), a regression — e.g. deleting the liveness-flag demotion so ``gt[probe_count,0]`` mints again,
    or weakening ``any`` to "ANY disjunct" so ``any_mixed`` mints — flips the real oracle away from these and
    fails HERE."""
    try:
        got_elig = oracles._fact_eligible(case.pred, dict(case.obs), dict(case.prefs))
    except Exception:  # noqa: BLE001 — a malformed node is not fact-eligible by contract
        got_elig = False
    assert got_elig is case.eligible, (
        f"{case.cid}: _fact_eligible={got_elig}, expected {case.eligible}")

    sig = predicate_oracle(case.obs, case.pred, provenance_refs=case.prefs)
    assert sig.fired is case.fired, f"{case.cid}: fired={sig.fired}, expected {case.fired}"
    # An ineligible/degenerate/malformed shape is never fired; a fired signal is always conclusive.
    if not case.eligible:
        assert sig.fired is False, f"{case.cid}: an ineligible shape must never fire"
    if sig.fired:
        assert sig.conclusive is True, f"{case.cid}: a fired signal must be conclusive"


# --------------------------------------------------------------------------------------------------
# (a2) KERNEL-PARITY — the real oracle and BOTH stdlib kernels agree on (fired, conclusive) over the WHOLE
# generated space.
# --------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("case", CASES, ids=[c.cid for c in CASES])
def test_kernel_parity_over_whole_grammar(case):
    """The REAL oracle's ``(fired, conclusive)`` equals both zero-VIGIL stdlib kernels over every generated
    triple — extending ``test_posture_reexecutable``'s ~20 hand cases to the entire grammar. A grammar edge
    mirrored into only one engine (the external-repro moat diverging) fails HERE."""
    cert = _load("fuzzer_cert_kernel", _CERT)
    vf = _load("fuzzer_verify_vf", _VERIFY_VF)
    sig = predicate_oracle(case.obs, case.pred, provenance_refs=case.prefs)
    real = (sig.fired, sig.conclusive)
    assert cert._reexec_fired_conclusive(case.pred, dict(case.obs), dict(case.prefs)) == real, (
        f"{case.cid}: posture kernel diverged from the real oracle: "
        f"{cert._reexec_fired_conclusive(case.pred, dict(case.obs), dict(case.prefs))} != {real}")
    assert vf._reexec_fired_conclusive(case.pred, dict(case.obs), dict(case.prefs)) == real, (
        f"{case.cid}: verify_vf kernel diverged from the real oracle: "
        f"{vf._reexec_fired_conclusive(case.pred, dict(case.obs), dict(case.prefs))} != {real}")


# --------------------------------------------------------------------------------------------------
# COUNT + axis coverage — a silent shrink of the generator is visible as a failing count, not quiet loss.
# --------------------------------------------------------------------------------------------------
def test_case_count_is_logged_and_covers_axes():
    """Log the generated-case COUNT and assert a floor + that every op, every wrapper, and every liveness key
    is exercised. If a future edit shrinks the generator, this floor fails rather than silently covering less."""
    print(f"\n[verdict-fuzzer] generated {CASE_COUNT} deterministic cases over the FACT-eligibility grammar")
    assert CASE_COUNT >= 180, f"generator shrank to {CASE_COUNT} cases (expected >= 180)"

    ids = " ".join(c.cid for c in CASES)
    for op in ("eq", "ieq", "contains", "icontains", "in", "min_len", "gt", "ge"):
        assert op in ids or any(op in str(c.pred) for c in CASES), f"op {op!r} not exercised"
    for wrapper in ("bare[", "not[", "all_gate[", "any1[", "all_all[", "any_any[", "any_mixed[",
                    "any2[", "pd4[", "liveness_", "taut_", "malformed_"):
        assert any(c.cid.startswith(wrapper) or wrapper in c.cid for c in CASES), (
            f"wrapper {wrapper!r} not exercised")
    for key in _LIVENESS_AVAILABILITY_KEYS:
        assert any(key in c.cid for c in CASES), f"liveness key {key!r} not exercised"

    # the regression canaries must be present and correctly classified by construction.
    by_id = {c.cid: c for c in CASES}
    assert by_id["liveness_sole_gt[probe_count]:rawtrue"].eligible is False
    assert by_id["contrast_gt_qty_0:fires"].eligible is True
    assert by_id["any_mixed[pd2+bare]:both_raw_true"].eligible is False
