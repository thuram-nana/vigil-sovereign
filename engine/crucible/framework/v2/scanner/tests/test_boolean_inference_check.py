"""
Wave 5 — BooleanInferenceCheck confirms boolean SQLi end to end via an SPRT whose per-round
signal is a TRUTH-VALUE ATTRIBUTION test.

Against a loopback target that really EVALUATES the injected comparison (a tautology returns the
table, a contradiction returns nothing) the check's varied always-true / always-false clauses
split cleanly by truth value and the oracle confirms. Against a target that ignores the clause it
refutes. Against pages whose body varies INDEPENDENTLY of the input — per-request random, coarse
uniform 1-of-K, and the SKEWED 1-of-K that defeated a determinism pre-gate — it must never mint.
"""

from __future__ import annotations

import contextlib
import random
import re
import secrets
import sqlite3
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE users(id INTEGER, name TEXT)")
_DB.executemany("INSERT INTO users VALUES(?, ?)", [(i, f"user{i:02d}") for i in range(20)])
_DB_LOCK = threading.Lock()

from framework.v2.scanner.checks import BooleanInferenceCheck

try:  # pragma: no cover - see the _check() note: this module must stay RUNNABLE against the pre-fix
    from framework.v2.scanner.checks import (                       # commits it is the regression for
        BOOLEAN_DISCRIMINATOR, boolean_clause_families)
except ImportError:  # pragma: no cover
    BOOLEAN_DISCRIMINATOR = {"dimensions": ["status", "length", "lexical"]}

    def boolean_clause_families():
        return ((("x' OR '1'='1", "x' OR 'b'>'a", "x' OR 9>4 AND 'k'<'m", "x' OR 'ab' LIKE 'a%",
                  "x' OR 'zz'<>'yy", "x' OR 'c' BETWEEN 'a' AND 'z", "x' OR 1 IN (SELECT 1) AND 'a'='a"),
                 ("x' OR '1'='2", "x' OR 'a'>'b", "x' OR 4>9 AND 'k'<'m", "x' OR 'ab' LIKE 'z%",
                  "x' OR 'zz'<>'zz", "x' OR 'u' BETWEEN 'a' AND 'z", "x' OR 1 IN (SELECT 2) AND 'a'='a")),)
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

# THE SHIPPED single-quote-breakout family, from the one definition the scanner arm actually uses.
# It is a STABLE PUBLIC CONSTANT (the literals used to be randomised per run; that is retracted —
# measured worthless, and it pointed at a defender's control), so this is the live set, not a draw.
_TRUE_CLAUSES, _FALSE_CLAUSES = boolean_clause_families()[0]
# NOTE, because a previous revision built a whole regression on the opposite belief: the seventh
# shape (`IN (SELECT ...)`) is not a different KIND of clause. `LIT IN (SELECT LIT)` over a one-row
# constant select is literal equality, and `_fold_atom` below folds it in three lines. The folder
# regressions are therefore run against the SHIPPED set, not against a K=6 subset of it.
# The LITERAL-ONLY clause set this all replaced: every TRUE is `X = X`, every FALSE is `X = Y`.
_LITERAL_ONLY_TRUE = ("x' OR '1'='1", "x' OR '7'='7", "x' OR 'ab'='ab", "x' OR 'q9'='q9")
_LITERAL_ONLY_FALSE = ("x' OR '1'='2", "x' OR '7'='8", "x' OR 'ab'='ac", "x' OR 'q9'='q8")


class _VulnApp(BaseHTTPRequestHandler):
    """A REAL string-concatenated SQL injection over sqlite3 — the origin EVALUATES the injected
    clause, so it answers the clause's TRUTH VALUE and not a hard-coded payload substring. (The
    previous fixture matched the payload string, which would have made any shape-varied clause set
    look broken while proving nothing about a real boolean channel.)"""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        with _DB_LOCK:
            try:
                rows = _DB.execute("SELECT id, name FROM users WHERE name = '" + q + "'").fetchall()
            except sqlite3.Error:
                rows = [("err", "err")]
        body = ("".join(f"id={i} {n}\n" for i, n in rows) or "no results").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# CRS 942130 "SQL Injection Attack: SQL Tautology Detected" — the operative shape is a BACKREFERENCE:
# a token, a comparison operator, and THE SAME TOKEN again. Purely lexical; no SQL is parsed.
_CRS_942130 = re.compile(
    r"""[\s'"`()]*?\b([\d\w]+)\b[\s'"`()]*?(?:=|<=>|R?LIKE|SOUNDS\s+LIKE|REGEXP)[\s'"`()]*?\b\1\b""",
    re.I | re.X)


_SQ, _DQ, _NUM = r"'[^']*'", r'"[^"]*"', r"\d+"
_LIT = f"(?:{_SQ}|{_DQ}|{_NUM})"


def _lit_val(tok: str):
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "'\"":
        return tok[1:-1]
    return int(tok)


def _fold_atom(atom: str, shapes: frozenset):
    """Constant-fold ONE literal-vs-literal comparison: True / False / None (undecidable).
    ``shapes`` selects which comparison forms this filter understands, so a DELIBERATELY INCOMPLETE
    filter can be built for the both-halves control."""
    m = re.fullmatch(rf"\s*({_LIT})\s*(<>|!=|>=|<=|=|>|<)\s*({_LIT})\s*", atom)
    if m and m.group(2) in shapes:
        try:
            a, b = _lit_val(m.group(1)), _lit_val(m.group(3))
        except ValueError:
            return None
        if type(a) is not type(b):
            return None
        return {"=": a == b, "<>": a != b, "!=": a != b, ">": a > b,
                "<": a < b, ">=": a >= b, "<=": a <= b}[m.group(2)]
    m = re.fullmatch(rf"\s*({_LIT})\s+LIKE\s+({_LIT})\s*", atom, re.I)
    if m and "LIKE" in shapes:
        a, pat = str(_lit_val(m.group(1))), str(_lit_val(m.group(2)))
        rx = "".join(".*" if c == "%" else "." if c == "_" else re.escape(c) for c in pat)
        return re.fullmatch(rx, a) is not None
    m = re.fullmatch(rf"\s*({_LIT})\s+BETWEEN\s+({_LIT})\s+AND\s+({_LIT})\s*", atom, re.I)
    if m and "BETWEEN" in shapes:
        try:
            x, lo, hi = (_lit_val(g) for g in m.groups())
        except ValueError:
            return None
        return lo <= x <= hi if type(x) is type(lo) is type(hi) else None
    # SUBQUERY MEMBERSHIP, and the THREE LINES that retract the claim this pair was shipped under.
    # `LIT IN (SELECT LIT)` over a one-row constant SELECT is literal equality — sqlite3 agrees:
    # `3 IN (SELECT 3)` -> 1, `3 IN (SELECT 5)` -> 0. No SQL engine is needed to decide it, so the
    # pair is a seventh COMPARISON SHAPE and nothing more. An earlier revision of this fixture had no
    # `IN` branch at all, which is how the "complete folder" regression came to be written BLIND to
    # the one shape it existed to defend.
    m = re.fullmatch(rf"\s*({_LIT})\s+IN\s*\(\s*SELECT\s+({_LIT})\s*\)\s*", atom, re.I)
    if m and "IN" in shapes:
        return m.group(1).strip() == m.group(2).strip()
    return None


_ALL_SHAPES = frozenset({"=", "<>", "!=", ">", "<", ">=", "<=", "LIKE", "BETWEEN", "IN"})
# the SAME folder with the three `IN` lines switched off — i.e. complete over the six literal
# comparison shapes and blind to the seventh. This is the leave-one-out control for that shape.
_NO_IN_SHAPES = frozenset(_ALL_SHAPES - {"IN"})


def _mask_literals(expr: str) -> "tuple[str, list[str]]":
    """Replace every quoted string literal with an opaque token BEFORE splitting on OR/AND, so the
    split can never cut inside a literal (without this, a clause literal that happens to contain the
    word "or" derails the filter — an artefact of the fixture, not a property of the clause set)."""
    lits: list[str] = []

    def _take(m: "re.Match[str]") -> str:
        lits.append(m.group(0))
        return f"\x01{len(lits) - 1}\x02"

    return re.sub(rf"(?:{_SQ}|{_DQ})", _take, expr), lits


def _folds_true(value: str, shapes: frozenset = _ALL_SHAPES) -> bool:
    """A CONSTANT-FOLDING request filter — no SQL engine, no DB, no parser generator. Tokenise the value
    in the three breakout contexts, split the tail on OR/AND, fold every literal-vs-literal comparison,
    and report whether any top-level disjunct folds TRUE. ~60 lines, and it is *complete* over the
    shipped shapes — every one of them, the subquery pair included — which is why comparison-shape
    diversity does not defeat it and why residual (a) is OPEN."""
    for wrapped in (value, "'" + value + "'", '"' + value + '"'):
        masked, lits = _mask_literals(wrapped)
        expr = re.sub(r"((?:\x01\d+\x02|\d+)\s+BETWEEN\s+(?:\x01\d+\x02|\d+))\s+AND\s+",
                      lambda m: m.group(1) + " \x00 ", masked, flags=re.I)   # BETWEEN owns its own AND
        for disj in re.split(r"\bOR\b", expr, flags=re.I):
            conj = [re.sub(r"\x01(\d+)\x02", lambda m: lits[int(m.group(1))], c.replace("\x00", "AND"))
                    for c in re.split(r"\bAND\b", disj, flags=re.I)]
            if conj and all(_fold_atom(c, shapes) is True for c in conj):
                return True
    return False


def _folding_app(shapes: frozenset = _ALL_SHAPES) -> type:
    """A STATIC, NON-VULNERABLE page behind the constant folder above."""

    class _App(_WafApp):
        _shapes = shapes

        def _blocked(self, q: str) -> bool:
            return _folds_true(q, type(self)._shapes)

    return _App


def _blocklist_app(strings: "frozenset[str] | set[str]") -> type:
    """A STATIC, NON-VULNERABLE page behind a plain EXACT-STRING blocklist — the cheapest filter of
    all, and the honest cost of shipping the clause set as a stable public constant."""

    class _App(_WafApp):
        _strings = frozenset(strings)

        def _blocked(self, q: str) -> bool:
            return q in type(self)._strings

    return _App


class _WafApp(BaseHTTPRequestHandler):
    """A STATIC, NON-VULNERABLE search page behind that rule. No SQL runs anywhere and the app never
    varies — there is NO boolean channel. But the rule is a function of SURFACE FORM only, and with a
    LITERAL-ONLY clause set (`X = X` true, `X = Y` false) it is PERFECTLY CORRELATED with truth value,
    so it hands back a flawless 2-cluster split: 403 for the whole TRUE side, 200 for the whole FALSE
    side. Raising K does not help — every extra `X = X` matches the same rule."""

    def log_message(self, *a: object) -> None:
        return

    def _blocked(self, q: str) -> bool:
        return bool(_CRS_942130.search(q))

    def do_GET(self) -> None:  # noqa: N802
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        blocked = self._blocked(q)
        body = (b"<html><body><h1>403 Forbidden</h1><p>Blocked by the web application firewall. "
                b"Reference WAF-942130-SQLI-TAUTOLOGY</p></body></html>" if blocked else
                b"<html><body><h1>Search</h1><p>No results found.</p><p>Try another term.</p></body></html>")
        self.send_response(403 if blocked else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SafeApp(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"constant page, injection ignored"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _DynamicApp(BaseHTTPRequestHandler):
    """A PURELY DYNAMIC page: a long per-request random token dominates the body, so ANY two
    responses (including two byte-identical repeats) diverge."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = (f"<html><body>session {secrets.token_hex(64)} — no results</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# An INPUT-INDEPENDENT page: the body is one of only K=2 distinct variants, chosen at random with
# NO dependence on the injected clause. There is no boolean channel, so every FACT here is FALSE.
_VARIANTS = [b"no results variant A" + b"A" * 60, b"no results variant B" + b"B" * 60]


class _CoarseApp(BaseHTTPRequestHandler):
    """UNIFORM 1-of-2 (p = 0.5)."""

    _rng = random.Random(1234)

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = _CoarseApp._rng.choice(_VARIANTS)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SkewedApp(BaseHTTPRequestHandler):
    """SKEWED 1-of-2 (dominant variant p = 0.9) — THE red-pen BLOCK class.

    A 16-sample identical-request determinism pre-gate passes ~0.9**16 ≈ 19% of the time on this
    page, and INSIDE that self-consistent window the "true" probe coincidentally draws the rare
    variant while the "false" probes stay dominant — so on every pre-fix commit (a97e982e,
    59dba95e and the determinism-gate commit 70c6b95a) the within-pair + stability controls all
    hold and the SPRT CONFIRMS a boolean_sqli FACT on a page with no boolean channel.

    Truth-value attribution kills it: with 3 distinct clauses per truth value each sent twice, a
    clean 2-cluster split needs all 6 true-side draws to be one variant and all 6 false-side draws
    the other — 2 * 0.9**6 * 0.1**6 ≈ 1.1e-6 per round.
    """

    _rng = random.Random(97531)

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = _SkewedApp._rng.choices(_VARIANTS, weights=[0.9, 0.1], k=1)[0]
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _send(req: HttpRequest) -> dict:
    # tolerant of error statuses: a 403 from a WAF is an OBSERVED RESPONSE the oracle must judge,
    # not a transport failure (this mirrors the gated executor, which returns the status it got).
    try:
        with urllib.request.urlopen(req.url, timeout=10) as r:  # noqa: S310 (loopback)
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", "replace")}


def _q_point(base: str):
    tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/search?q=x"))
    point = next(p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q")
    return tpl, point


def _check(trues=_TRUE_CLAUSES, falses=_FALSE_CLAUSES) -> BooleanInferenceCheck:
    try:
        return BooleanInferenceCheck(
            id="bool-sqli-sprt", bug_class="boolean_sqli",
            true_clauses=trues, false_clauses=falses,
        )
    except TypeError:  # pragma: no cover - see the note below
        # DELIBERATE pre-fix compatibility shim, and the only reason it exists: the skewed
        # regression below is the falsifiability claim for this fix, so it must be RUNNABLE
        # against a97e982e / 59dba95e / 70c6b95a (which take a single clause per truth value) and
        # FAIL there for the RIGHT reason — a real false FACT — rather than erroring on the
        # constructor. On this tree the multi-clause path above always succeeds.
        return BooleanInferenceCheck(
            id="bool-sqli-sprt", bug_class="boolean_sqli",
            true_clause=trues[0], false_clause=falses[0],
        )


def _confirm(ctx) -> object:
    return confirm_finding(
        finding={"bug_class": "boolean_sqli"}, context=ctx, verifier=OracleVerifier(),
    )


def _false_facts(handler: type[BaseHTTPRequestHandler], loops: int, **kw) -> int:
    facts = 0
    with _server(handler) as base:
        tpl, point = _q_point(base)
        for _ in range(loops):
            if _confirm(_check(**kw).probe(tpl, point, _send)) is not None:
                facts += 1
    return facts


def test_boolean_clause_families() -> None:
    """Every invariant the shipped clause families must hold, checked against a REAL SQL engine — not
    against a regex stand-in, because the properties are semantic.

      * SYNTAX + TRUTH: each clause parses in ITS OWN breakout context on sqlite3 and evaluates to the
        truth value it claims (a quote-breakout clause must end on an UNCLOSED quote so the origin's
        own trailing quote closes it — the easiest thing to get wrong when editing a shape).
      * LENGTH-MATCHED index-aligned TRUE[i] / FALSE[i]: a length-correlated set would re-open the hole
        through the ``length`` dimension, because an endpoint that merely ECHOES the parameter would
        then separate by truth value.
      * DISTINCT within and across the two sides (duplicates are not independent draws).
      * STABLE: two calls return the IDENTICAL set. The literals were randomised per run for one
        revision so the set would not be "a public constant an operator can paste into an exact-string
        blocklist"; that is retracted. It was measured worthless (a folder plus a nine-string blocklist
        over the one randomised atom partitioned 1500/1500 randomised draws) and it aimed at a
        DEFENDER's control on the operator's own estate, against constitution VI.4 "make yourself
        correlatable" and against this module's own contract that a run is replayable.
      * PARTITIONED BY THE COMPLETE CONSTANT FOLDER — asserted in the direction that is TRUE. This used
        to assert the opposite ("the folder must fail on at least one clause"), which passed only
        because the fixture folder had no ``IN`` branch: it was written blind to the very shape it
        existed to defend. With the three ``IN`` lines added, the folder partitions every family
        perfectly. Residual (a) is OPEN and this pins it; the leave-one-out half below pins what the
        shape diversity really buys."""
    ctxs = ["SELECT count(*) FROM users WHERE name = '%s'",
            "SELECT count(*) FROM users WHERE id = %s",
            'SELECT count(*) FROM users WHERE name = "%s"']
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users(id INTEGER, name TEXT)")
    db.execute("INSERT INTO users VALUES(7, 'widget')")   # the base value 'x' / 1 matches NOTHING
    families = boolean_clause_families()
    assert len(families) == len(ctxs)
    for fi, (trues, falses) in enumerate(families):
        assert len(trues) >= 4 and len(trues) == len(falses)
        assert len(set(trues)) == len(trues) and len(set(falses)) == len(falses)
        assert not set(trues) & set(falses)
        for want, clauses in ((1, trues), (0, falses)):
            for c in clauses:
                got = db.execute(ctxs[fi] % c).fetchone()[0]   # raises on a syntax error
                assert bool(got) == bool(want), f"fam {fi}: {c!r} is not {bool(want)}"
        for t, f in zip(trues, falses):
            assert len(t) == len(f), f"fam {fi}: {t!r} / {f!r} are not length-matched"
        # THE OPEN CLASS, PINNED: the complete folder decides every clause, correctly, with no SQL
        # engine and no database. If someone later makes this fail they have either changed the
        # clause set or broken the fixture — either way the disclosure has to be re-earned.
        assert all(_folds_true(c) for c in trues) and not any(_folds_true(c) for c in falses), (
            f"fam {fi}: the complete constant folder no longer partitions the family — residual (a) "
            "is documented as OPEN on this evidence; re-measure before changing the disclosure")
        # ...and the mechanism that IS real: blind the same folder to ONE shape and it stops
        # partitioning, which is why every incomplete real-world filter refutes.
        for blinded in ("=", ">", "<", "LIKE", "BETWEEN", "<>", "IN"):
            shapes = frozenset(_ALL_SHAPES - {blinded})
            bt = [_folds_true(c, shapes) for c in trues]
            bf = [_folds_true(c, shapes) for c in falses]
            assert not (all(bt) and not any(bf)), (
                f"fam {fi}: a folder blind to {blinded!r} still partitions the family perfectly")
    assert boolean_clause_families() == families, (
        "the clause set is not STABLE across calls — a run must be replayable and the operator must "
        "be able to grep their logs for exactly these strings (constitution VI.4)")


def test_sprt_check_confirms_boolean_sqli() -> None:
    # THE TRUE POSITIVE: an origin that really evaluates the clause. Every varied always-true
    # clause lands on the rows page, every always-false clause on "no results" — a clean
    # 2-cluster split by TRUTH VALUE, so the FACT still mints.
    with _server(_VulnApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm(_check().probe(tpl, point, _send))
        assert confirmed is not None
        assert confirmed.confirmed_by.value == "boolean_inference"


def test_a_truth_correlated_lexical_waf_does_not_mint_on_a_static_page() -> None:
    """RED-PEN BLOCK-1 REGRESSION — the decisive one, and the reason the clause SHAPE must vary.

    A STATIC, NON-VULNERABLE page (no SQL anywhere, no boolean channel) behind a CRS-942130-shape
    BACKREFERENCE rule. With the LITERAL-ONLY clause set the rule partitions the probes perfectly by
    truth value — 403 to every `X = X`, 200 to every `X = Y` — and the oracle mints a false FACT on
    essentially every attempt. That failure mode is NOT beaten by raising K (every extra `X = X`
    matches the same rule); it is beaten by varying the COMPARISON SHAPE, which makes the rule catch
    only part of the TRUE side and break within-truth agreement.

    Both halves are asserted, so the test cannot pass vacuously: the literal-only set MUST still mint
    here (the hazard is real) and the shipped shape-varied set MUST NOT."""
    literal_only = _false_facts(_WafApp, 20, trues=_LITERAL_ONLY_TRUE, falses=_LITERAL_ONLY_FALSE)
    assert literal_only == 20, (
        f"the literal-only clause set minted only {literal_only}/20 — the WAF fixture no longer "
        "reproduces the hazard, so the shape-varied result below proves nothing")
    shipped = _false_facts(_WafApp, 20)
    assert shipped == 0, (
        f"the shipped shape-varied clause set minted {shipped}/20 FALSE boolean_sqli FACTs behind a "
        "purely LEXICAL truth-correlated filter over a static page")


def test_a_complete_constant_folder_mints_on_a_static_page_residual_a_is_open() -> None:
    """THE OPEN CLASS, PINNED — this test measures a HAZARD and asserts it is STILL THERE.

    It replaces ``test_a_complete_constant_folder_does_not_mint_on_a_static_page``, which asserted the
    opposite and passed only because ``_fold_atom`` had no ``IN`` branch: the regression written to
    defend the ``IN (SELECT ...)`` pair was written BLIND to that exact shape. Three lines fixed the
    fixture and the result inverted.

    A ~60-line CONSTANT-FOLDING filter (still no SQL engine, no DB, no parser generator: tokenise,
    split on OR/AND, fold every literal-vs-literal comparison, block if any top-level disjunct folds
    TRUE) is COMPLETE over the SHIPPED shape set — the subquery pair included, because
    `LIT IN (SELECT LIT)` over a one-row constant select IS literal equality. Behind such a filter a
    STATIC, NON-VULNERABLE page mints a false boolean_sqli FACT on essentially every attempt.

    That is not a bug to be fixed by picking better clauses: the oracle needs clauses whose truth it
    knows A PRIORI, anything knowable a priori is a CONSTANT EXPRESSION, and a filter can fold any
    constant expression. THREE CELLS, so the ladder is pinned and none of them is vacuous:
      1. the complete folder DOES partition the shipped set  -> mints (residual (a) is OPEN);
      2. the SAME folder blinded to the seventh shape does NOT -> refutes (incompleteness is the real,
         and only, mechanism the clause set buys);
      3. a plain EXACT-STRING blocklist of the seven public TRUE clauses also partitions -> mints,
         which is the honest cost of the set being a stable public constant (and randomising the
         literals did not fix it either: a nine-string blocklist over the one randomised atom
         partitioned 1500/1500 randomised draws)."""
    complete = _false_facts(_folding_app(), 20)
    assert complete == 20, (
        f"the COMPLETE constant folder minted only {complete}/20 on a static page — residual (a) is "
        "documented as OPEN on exactly this measurement; if the hazard has really gone, re-measure "
        "and re-earn the disclosure rather than deleting this assertion")
    blind_to_in = _false_facts(_folding_app(_NO_IN_SHAPES), 20)
    assert blind_to_in == 0, (
        f"a folder blind to ONE shape still minted {blind_to_in}/20 — the incompleteness mechanism "
        "(the one thing clause-shape diversity actually buys) has broken")
    public = set(_TRUE_CLAUSES)
    blocklist = _false_facts(_blocklist_app(public), 10)
    assert blocklist == 10, (
        f"an exact-string blocklist of the public TRUE clauses minted only {blocklist}/10 — the "
        "stated cost of a stable public clause set is no longer what is measured")


def test_every_incomplete_filter_refutes_leave_one_shape_out() -> None:
    """The mechanism stated precisely, and it is the ONLY one the clause set buys: a filter must be
    COMPLETE over the whole shape set to partition. Blind it to any ONE comparison shape and the TRUE
    cluster stops agreeing, so the round refutes — which is the same reason a CRS-942130 backreference
    (equality-only, in effect) refutes. All seven shipped shapes, including ``IN``, are swept; the
    complete-folder cell above is the other half that stops this being a vacuous win."""
    for blinded in ("=", ">", "<", "LIKE", "BETWEEN", "<>", "IN"):
        shapes = frozenset(_ALL_SHAPES - {blinded})
        facts = _false_facts(_folding_app(shapes), 5)
        assert facts == 0, f"a filter blind to {blinded!r} still minted {facts}/5 on a static page"


def test_the_check_pins_the_boolean_discriminator_off_latency() -> None:
    """RED-PEN BLOCK-2 — the retained context must carry the PINNED dimension set. The oracle's own
    default includes `latency` (differing at +1000ms), which would let a FACT rest on timing over
    byte-identical bodies; the probe order is all-TRUE then all-FALSE, so any step slowdown crossing
    that boundary lands exactly on the truth partition."""
    with _server(_SafeApp) as base:
        tpl, point = _q_point(base)
        ctx = _check().probe(tpl, point, _send).to_verifier_context()
    assert ctx["discriminator"] == BOOLEAN_DISCRIMINATOR
    assert "latency" not in ctx["discriminator"]["dimensions"]


def test_sprt_check_refutes_non_injectable_target() -> None:
    with _server(_SafeApp) as base:
        tpl, point = _q_point(base)
        assert _confirm(_check().probe(tpl, point, _send)) is None


def test_sprt_check_refutes_a_dynamic_page_autonomous_path() -> None:
    # a purely-dynamic page (a per-request token) hard-refutes on the byte-identical repeats
    assert _false_facts(_DynamicApp, 5) == 0


def test_sprt_check_refutes_a_uniform_coarse_page_looped() -> None:
    # UNIFORM 1-of-2, input-independent. Kept as the cheap companion to the skewed loop below —
    # the red-pen showed this cell alone CANNOT catch the skewed class: it is 18/150 on a97e982e and
    # 5/150 on 59dba95e, but already 0/150 on 70c6b95a, which still mints on the skewed page.
    facts = _false_facts(_CoarseApp, 150)
    assert facts == 0, f"a uniform coarse K=2 page minted {facts}/150 FALSE boolean_sqli FACTs"


def test_sprt_check_refutes_a_skewed_input_independent_page_looped() -> None:
    # THE red-pen BLOCK regression, through the REAL mint path (BooleanInferenceCheck.probe →
    # confirm_finding → OracleVerifier). A SKEWED (p = 0.9) input-independent K=2 page minted
    # FALSE FACTs on a97e982e, 59dba95e AND 70c6b95a — the 16-sample determinism pre-gate passes
    # ~0.9**16 ≈ 19% of the time on it, and the coincidence lives INSIDE that self-consistent window.
    # The page RNG is SEEDED, so the outcome is deterministic per commit; this loop is sized so all
    # three fail it: measured 37/3000 on a97e982e, 24/3000 on 59dba95e, 3/3000 on 70c6b95a — and 0
    # here. (70c6b95a's own rate is only ~1.3e-3, so its margin is the thin one; the direct
    # Monte-Carlo sweep over p 0.5-0.95 x variant-count 2-4 at 5000 trials/cell is the wider evidence.)
    loops = 3000
    facts = _false_facts(_SkewedApp, loops)
    assert facts == 0, (
        f"a SKEWED (p=0.9) K=2 input-independent page minted {facts}/{loops} FALSE boolean_sqli "
        "FACTs — the response is not a function of the injected truth value")
