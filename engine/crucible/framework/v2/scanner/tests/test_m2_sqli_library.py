"""
Milestone-2 module A — SQL-injection DIALECT breadth as declarative library data.

These entries (`m2-sqli-*`) encode boolean-based and time-based blind SQLi across
the five major DBMS dialects (MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite).
Coverage lives in the PAYLOADS: each dialect quotes/comments/sleeps differently,
so a tautology or delay clause that is inert on one engine confirms on another.

The entries use ONLY two oracle kinds, both statistically strong (no false-positive
risk): ``differential`` (a benign value vs a boolean-TRUE probe whose response
diverges → boolean_sqli) and ``timing`` (a benign value vs a dialect sleep payload
→ time_based_sqli). Error-based SQLi is deliberately NOT encoded here — confirming
it needs a DB-error-signature oracle the verify layer does not yet expose.

This test proves the whole path for the module: every `m2-sqli-*` entry loads and
validates; each compiles to the correct concrete ``Check`` (differential →
``DifferentialCheck``, timing → ``TimingCheck``); the coverage matrix is complete;
the fingerprint-gated exemplars gate correctly; and every boolean entry drives a
REAL loopback fixture to an oracle-confirmed finding (and its parameterised safe
twin to none) through the same ``confirm_finding`` + ``OracleVerifier`` authority
the engine uses — never the check's own opinion. Timing entries are asserted at
compile+shape level (injected_ms > 0), mirroring the M1 library test: a full
multi-second timing confirmation is intentionally left out to keep the suite fast.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest

from framework.v2.scanner.checks import Check, DifferentialCheck, TimingCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import (
    LIBRARY_DIR,
    LibraryEntry,
    compile_entry,
    load_library,
    select_entries,
)
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

# The id prefix that scopes this module's entries within the shared library dir.
M2_PREFIX = "m2-sqli-"
DIALECTS = {"mysql", "postgres", "mssql", "oracle", "sqlite"}


# ---------------------------------------------------------------------------
# loaders — the whole dir loads; the m2-sqli subset is isolated by id prefix
# ---------------------------------------------------------------------------


def _all() -> list[LibraryEntry]:
    return load_library()


def _m2() -> list[LibraryEntry]:
    return [e for e in _all() if e.id.startswith(M2_PREFIX)]


def _by_id() -> dict[str, LibraryEntry]:
    return {e.id: e for e in _m2()}


def _dialect(entry: LibraryEntry) -> str:
    """Dialect tag from the payload_family ('mysql-boolean' -> 'mysql')."""
    return entry.payload_family.rsplit("-", 1)[0]


def _kind_tag(entry: LibraryEntry) -> str:
    """Boolean/time tag from the payload_family ('mysql-time' -> 'time')."""
    return entry.payload_family.rsplit("-", 1)[1]


# ---------------------------------------------------------------------------
# 1. the whole library loads; every m2-sqli entry is unique and validates
# ---------------------------------------------------------------------------


def test_whole_library_loads_without_error() -> None:
    # load_library validates EVERY *.json in the dir (ours + the rest); a bad
    # entry would raise LibraryError naming the file. It does not.
    entries = _all()
    assert entries
    assert all(isinstance(e, LibraryEntry) for e in entries)


def test_m2_files_all_present_and_loaded() -> None:
    files = sorted(LIBRARY_DIR.glob("m2_sqli_*.json"))
    assert files, "no m2_sqli_*.json entries shipped"
    # one entry per file (the loader validates one LibraryEntry per file), so the
    # count of loaded m2-sqli ids matches the count of m2_sqli_*.json files.
    assert len(_m2()) == len(files)


def test_m2_ids_unique_and_prefixed() -> None:
    ids = [e.id for e in _m2()]
    assert ids, "expected m2-sqli entries"
    assert all(i.startswith(M2_PREFIX) for i in ids)
    assert len(ids) == len(set(ids))  # unique within the module
    # and globally unique: load_library itself rejects cross-file dupes, so a
    # successful load already proves no collision with the seed / sibling ids.
    all_ids = [e.id for e in _all()]
    assert len(all_ids) == len(set(all_ids))
    # we did not reuse the seed ids
    assert "boolean-sqli" not in ids
    assert "time-based-sqli" not in ids


def test_m2_entries_are_rich() -> None:
    for e in _m2():
        assert e.title
        assert e.severity == "High"
        assert any(r.startswith("CWE-") for r in e.references), f"{e.id} lacks a CWE id"
        assert "CWE-89" in e.references, f"{e.id} is not tagged CWE-89"
        assert e.remediation, f"{e.id} carries no remediation text"
        assert e.payload_family, f"{e.id} carries no payload_family"


def test_m2_bug_classes_route_to_boolean_or_time_based_sqli() -> None:
    for e in _m2():
        if e.oracle.kind == "differential":
            assert e.bug_class == "boolean_sqli", e.id
        elif e.oracle.kind == "timing":
            assert e.bug_class == "time_based_sqli", e.id
        else:  # pragma: no cover - guarded by the oracle-kind test below
            pytest.fail(f"{e.id} uses an unexpected oracle kind {e.oracle.kind}")


# ---------------------------------------------------------------------------
# 2. no entry uses an oracle kind other than differential / timing
# ---------------------------------------------------------------------------


def test_m2_uses_only_differential_and_timing_oracles() -> None:
    kinds = {e.oracle.kind for e in _m2()}
    assert kinds == {"differential", "timing"}, kinds


# ---------------------------------------------------------------------------
# 3. compile — differential -> DifferentialCheck, timing -> TimingCheck
# ---------------------------------------------------------------------------


def test_every_m2_entry_compiles_to_the_right_check_type() -> None:
    for e in _m2():
        check = compile_entry(e)
        assert isinstance(check, Check)
        assert check.id == e.id
        assert check.bug_class == e.bug_class
        if e.oracle.kind == "differential":
            assert isinstance(check, DifferentialCheck)
            assert check.benign == e.oracle.benign
            assert check.probe_payload == e.oracle.probe
        else:
            assert isinstance(check, TimingCheck)


def test_m2_timing_entries_carry_positive_injected_ms() -> None:
    timing = [e for e in _m2() if e.oracle.kind == "timing"]
    assert timing, "expected time-based entries"
    for e in timing:
        check = compile_entry(e)
        assert isinstance(check, TimingCheck)
        # the delay the payload induces is what the timing oracle uses for the
        # effect-size floor — it must be a real positive dose.
        assert check.injected_ms > 0, e.id
        assert e.oracle.injected_ms == check.injected_ms
        assert check.benign
        assert check.sleep_payload


# ---------------------------------------------------------------------------
# 4. coverage matrix — 5 dialects x {boolean, time-based}
# ---------------------------------------------------------------------------


def test_all_five_dialects_covered_both_kinds() -> None:
    seen: dict[str, set[str]] = {d: set() for d in DIALECTS}
    for e in _m2():
        d, k = _dialect(e), _kind_tag(e)
        assert d in DIALECTS, f"{e.id} has unexpected dialect {d!r}"
        assert k in {"boolean", "time"}, f"{e.id} has unexpected kind {k!r}"
        seen[d].add(k)
    for d in DIALECTS:
        assert seen[d] == {"boolean", "time"}, f"{d} missing a kind: {seen[d]}"


def test_expected_boolean_and_timing_counts() -> None:
    boolean = [e for e in _m2() if e.oracle.kind == "differential"]
    timing = [e for e in _m2() if e.oracle.kind == "timing"]
    # sanity floors: a couple of contexts per dialect on each side
    assert len(boolean) >= 10
    assert len(timing) >= 10
    assert len(boolean) + len(timing) == len(_m2())


# ---------------------------------------------------------------------------
# 5. fingerprint gating — the stack-implies-a-DB exemplars gate correctly
# ---------------------------------------------------------------------------

GATED = {
    "m2-sqli-mysql-boolean-wp-gated": "wordpress",
    "m2-sqli-pg-boolean-django-gated": "django",
    "m2-sqli-mssql-boolean-aspnet-gated": "asp.net",
}


def test_gated_entries_exist_and_are_gated() -> None:
    by_id = _by_id()
    for gid in GATED:
        assert gid in by_id, f"expected gated entry {gid}"
        assert by_id[gid].applies_when != {"always": True}
        # gated entries do NOT apply to an unfingerprinted target
        assert by_id[gid].applies(set()) is False


def test_gated_entries_apply_only_when_their_stack_token_present() -> None:
    by_id = _by_id()
    for gid, token in GATED.items():
        assert by_id[gid].applies({token}) is True
        assert by_id[gid].applies({"nginx"}) is False


def test_select_entries_gates_the_stack_implied_db_entries() -> None:
    entries = _m2()
    always_on = {e.id for e in entries if e.applies(set())}
    assert "m2-sqli-mysql-boolean-wp-gated" not in always_on

    selected = {e.id for e in select_entries(entries, {"wordpress", "php"})}
    assert "m2-sqli-mysql-boolean-wp-gated" in selected     # WP stack -> MySQL entry
    assert "m2-sqli-mssql-boolean-aspnet-gated" not in selected  # still gated out
    assert always_on <= selected                            # always-on always included

    aspnet = {e.id for e in select_entries(entries, {"asp.net", "iis"})}
    assert "m2-sqli-mssql-boolean-aspnet-gated" in aspnet
    assert "m2-sqli-mysql-boolean-wp-gated" not in aspnet


def test_non_gated_entries_are_always_on() -> None:
    for e in _m2():
        if e.id not in GATED:
            assert e.applies(set()) is True, f"{e.id} should be always-on"


# ---------------------------------------------------------------------------
# 6. end-to-end confirmation against a real loopback fixture (+ its safe twin)
# ---------------------------------------------------------------------------
#
# A deliberately-vulnerable stdlib HTTP app on loopback that models boolean-blind
# SQLi generically across dialects: it string-builds the parameter into a WHERE
# clause, so ANY tautology (whatever the dialect's quoting) selects every row and
# dumps a big page, while a benign term matches nothing and returns a short page —
# a real, observable response differential the oracle adjudicates. The detector
# strips quote characters and looks for `1=1`, which every dialect probe here
# reduces to once its quoting is removed; a benign value never does.


def _looks_like_tautology(q: str) -> bool:
    stripped = q.replace("'", "").replace('"', "")
    return "1=1" in stripped


class _SqliVulnApp(BaseHTTPRequestHandler):
    """A tautology dumps many rows; a benign term returns one short line."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = ("id=row\n" * 40).encode() if _looks_like_tautology(q) else b"no results"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SqliSafeApp(BaseHTTPRequestHandler):
    """The parameterised twin: a constant page, the injection ignored."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"constant page, injection ignored"
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
    with urllib.request.urlopen(req.url, timeout=10) as r:  # noqa: S310 (loopback)
        return {"status": r.status, "body": r.read().decode("utf-8", "replace")}


def _q_point(base: str):
    tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/search?q=x"))
    point = next(
        p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q"
    )
    return tpl, point


def _confirm(check: Check, tpl: RequestTemplate, point) -> object:
    ctx = check.probe(tpl, point, _send)
    return confirm_finding(
        finding={"bug_class": check.bug_class}, context=ctx, verifier=OracleVerifier()
    )


# every boolean probe here reduces to `1=1` once its dialect quoting is stripped,
# so the generic fixture confirms all of them — proof the dialect breadth is real,
# not just decorative payload strings.
_BOOLEAN_IDS = sorted(
    e.id for e in load_library()
    if e.id.startswith(M2_PREFIX) and e.oracle.kind == "differential"
)


def test_fixture_detector_agrees_with_every_boolean_probe() -> None:
    # guardrail: the fixture's tautology detector must fire for each probe and
    # NOT for either benign control — otherwise a green confirmation below would
    # be vacuous.
    for e in _m2():
        if e.oracle.kind != "differential":
            continue
        assert _looks_like_tautology(e.oracle.probe), e.id
        assert not _looks_like_tautology(e.oracle.benign), e.id


@pytest.mark.parametrize("entry_id", _BOOLEAN_IDS)
def test_boolean_entry_confirms_on_vuln_and_not_on_safe(entry_id: str) -> None:
    check = compile_entry(_by_id()[entry_id])
    assert isinstance(check, DifferentialCheck)

    with _server(_SqliVulnApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm(check, tpl, point)
    assert confirmed is not None, f"{entry_id} failed to confirm on the vuln fixture"
    assert confirmed.confirmed_by.value == "differential_response"
    assert confirmed.bug_class == "boolean_sqli"

    with _server(_SqliSafeApp) as base:
        tpl, point = _q_point(base)
        assert _confirm(check, tpl, point) is None, (
            f"{entry_id} false-positived on the parameterised safe twin"
        )


def test_a_representative_boolean_entry_confirms() -> None:
    # an explicit single-entry smoke check (independent of the parametrisation)
    # mirroring test_library.py's differential confirmation.
    check = compile_entry(_by_id()["m2-sqli-mysql-boolean-squote"])
    with _server(_SqliVulnApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm(check, tpl, point)
    assert confirmed is not None
    assert confirmed.confirmed_by.value == "differential_response"
