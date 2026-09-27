"""Unit tests for the ONE raw-socket HTTP/1.1 response reader (``scanner.rawhttp``).

The reader had NO tests of its own and produced three framing defects on first pass, each
of which turned a BENIGN origin's echo of VIGIL's FIRST request into the reply to VIGIL's
SECOND request — i.e. into "evidence" of a desync. Two more surfaced while writing these.
Every case below is a measured defect or the behaviour that must not regress:

  1xx interim        — RFC 9112 §15: a 1xx has no body and the client keeps reading for the
                       FINAL response. Returning it as a complete response made the final
                       400 (echoing the canary) the SECOND response.
  under-declared CL  — the surplus is not a response; reporting it as one (``channel=True,
                       status=None``) leaked the echoed first request into the second leg.
  chunked trailers   — a trailer block left buffered became the head of "response 2".
  negative chunk     — ``int(b"-5", 16)`` is ``-5``, not a ValueError.
  truncated body     — a Content-Length the peer never satisfies is not a response.

Audit-A red-pen BLOCK-7 added five more MEASURED shapes, four of which produced a read #2
with ``channel=True, status=200`` whose body carried the canary — a second response
manufactured out of the FIRST response's leftover bytes:

  duplicate CL       — differing Content-Lengths were last-wins; RFC 9112 §6.3 requires
                       treating them as an UNRECOVERABLE error.
  204/304 + a body   — a bodyless status left the declared bytes buffered for read #2.
  101 + bytes        — after 101 the connection has left HTTP/1.1 entirely.
  lenient chunk size — ``+5`` / ``0x5`` / ``1_0`` parse for ``int(tok, 16)`` and for no HTTP
                       parser; that divergence IS a desync primitive.
  budget-truncated   — a close-delimited body cut off by the read budget came back as a
                       COMPLETE response, contradicting the reader's own correction #5.

The FIFTH shape is NOT fixed and is pinned as a stated limitation by
``test_the_narrowed_limit_of_the_status_line_rule_is_stated_honestly``: surplus that IS a
well-formed status line (an error page quoting a whole ``HTTP/1.1 200 OK`` block under a
short Content-Length) is still returned as read #2.

``test_the_raw_response_reader_is_not_duplicated`` is the DRIFT GUARD: it fails both if a
new copy of the reader appears and when the one documented pending copy is migrated (at
which point its allowlist entry must be deleted).
"""

from __future__ import annotations

import contextlib
import socket
import threading
from pathlib import Path
from typing import Callable, Iterator

import pytest

from framework.v2.scanner.rawhttp import RawResponseReader
from framework.v2.scanner.smuggling import _RawResponseReader as DesyncLegReader

_CANARY = "crsmug" + "a1b2c3d4e5f60718293a4b"


@contextlib.contextmanager
def _served(chunks: "list[bytes]", *, close: bool = True,
            timeout: float = 1.0) -> Iterator[socket.socket]:
    """Serve ``chunks`` verbatim on a loopback socket and yield the CLIENT socket."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    done = threading.Event()

    def _run() -> None:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            for ch in chunks:
                conn.sendall(ch)
            if not close:
                done.wait(timeout * 4)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()
            with contextlib.suppress(OSError):
                srv.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        yield s
    finally:
        done.set()
        with contextlib.suppress(OSError):
            s.close()
        t.join(timeout=3)


def _read(make: Callable[[socket.socket], object], chunks: "list[bytes]", n: int = 2,
          *, close: bool = True, timeout: float = 1.0) -> "list[tuple]":
    """``n`` successive reads, normalised to ``(channel, status, body)`` tuples so the shared
    reader (dicts) and the DesyncLeg view (models) are directly comparable."""
    out: list[tuple] = []
    with _served(chunks, close=close, timeout=timeout) as s:
        reader = make(s)
        for _ in range(n):
            r = reader.read_response()          # type: ignore[attr-defined]
            if isinstance(r, dict):
                out.append((r["channel"], r["status"], r["body"]))
            else:
                out.append((r.channel, r.status, r.body))
    return out


def _shared(s: socket.socket) -> RawResponseReader:
    return RawResponseReader(s)


# ---------------------------------------------------------------------------------------
# the framing corpus — shared by the unit tests and the drift guard
# ---------------------------------------------------------------------------------------
_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
#: a benign origin's 400 page that ECHOES the offending request, canary and all
_ECHO_400 = b"rejected: GET /vigil-reflect?c=" + _CANARY.encode() + b" xx"
#: a COMPLETE, well-formed 200 block carrying the canary, used as the bytes that must NOT
#: be re-framed as a second response when a first response wrongly leaves them buffered.
_QUOTED_200 = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(_CANARY)).encode()
               + b"\r\n\r\n" + _CANARY.encode())

CASES: "dict[str, tuple[list[bytes], int, bool]]" = {
    # name: (wire bytes, how many reads, keep the socket open)
    "simple_cl": ([_OK], 1, True),
    "two_pipelined": ([b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst" + _OK], 2, True),
    "interim_100_continue": ([b"HTTP/1.1 100 Continue\r\n\r\n",
                              b"HTTP/1.1 400 Bad Request\r\nContent-Length: "
                              + str(len(_ECHO_400)).encode() + b"\r\n\r\n" + _ECHO_400], 1, True),
    "switching_protocols_101": ([b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"], 1, True),
    "under_declared_cl": ([b"HTTP/1.1 400 Bad Request\r\nContent-Length: 5\r\n\r\nERROR\r\n\r\n"
                           b"echoed request was: GET /vigil-reflect?c=" + _CANARY.encode()
                           + b"\r\n\r\n"], 2, True),
    "chunked_trailers": ([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n"
                          b"X-Trailer: " + _CANARY.encode() + b"\r\n\r\n" + _OK], 2, True),
    "negative_chunk_size": ([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                             b"-5\r\nAAAAAAAAAAAAAAAA\r\n0\r\n\r\n"], 1, True),
    "huge_chunk_size": ([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                         b"FFFFFFFFFFFF\r\n" + b"A" * 8192], 1, True),
    "close_delimited": ([b"HTTP/1.1 200 OK\r\n\r\nbody runs to close"], 1, True),
    "no_content_204": ([b"HTTP/1.1 204 No Content\r\n\r\n" + _OK], 2, True),
    "junk_not_a_status_line": ([b"garbage: yes\r\nmore: junk\r\n\r\npayload"], 1, True),
    "bogus_status_code": ([b"HTTP/1.1 999 Nope\r\nContent-Length: 0\r\n\r\n"], 1, True),
    "truncated_cl": ([b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nshort"], 1, False),
    # --- audit-A red-pen BLOCK-7b: five wire shapes MEASURED to fabricate a read #2 that
    # carried a canary out of the FIRST response's bytes. Four are refused below; the fifth
    # (an under-declared CL whose surplus IS a well-formed status line) is the documented,
    # narrowed limit of correction #2 and is pinned as such by `_ECHOED_BLOCK_IS_READ_TWO`.
    "conflicting_duplicate_cl": ([b"HTTP/1.1 200 OK\r\nContent-Length: "
                                  + str(7 + len(_QUOTED_200)).encode()
                                  + b"\r\nContent-Length: 7\r\n\r\nrefused"
                                  + _QUOTED_200], 2, True),
    "no_content_204_with_a_body": ([b"HTTP/1.1 204 No Content\r\nContent-Length: "
                                    + str(len(_QUOTED_200)).encode() + b"\r\n\r\n"
                                    + _QUOTED_200], 2, True),
    "not_modified_304_with_a_body": ([b"HTTP/1.1 304 Not Modified\r\nContent-Length: "
                                      + str(len(_QUOTED_200)).encode() + b"\r\n\r\n"
                                      + _QUOTED_200], 2, True),
    "upgraded_101_then_bytes": ([b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n"
                                 + _QUOTED_200], 2, True),
    # `int(tok, 16)` accepts these; RFC 9112 §7.1 chunk-size does not.
    "plus_chunk_size": ([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                         b"+5\r\nAAAAA\r\n0\r\n\r\n"], 1, True),
    "hex_prefix_chunk_size": ([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                               b"0x5\r\nAAAAA\r\n0\r\n\r\n"], 1, True),
    "underscore_chunk_size": ([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                               b"1_0\r\n" + b"A" * 16 + b"\r\n0\r\n\r\n"], 1, True),
}

EXPECTED: "dict[str, list[tuple]]" = {
    "simple_cl": [(True, 200, "hi")],
    "two_pipelined": [(True, 200, "first"), (True, 200, "hi")],
    # the 1xx is INTERIM: the FINAL 400 is the response to the FIRST request
    "interim_100_continue": [(True, 400, _ECHO_400.decode())],
    "switching_protocols_101": [(True, 101, "")],
    # the surplus past an under-declared CL is NOT a response
    "under_declared_cl": [(True, 400, "ERROR"), (False, None, "")],
    "chunked_trailers": [(True, 200, "abcd"), (True, 200, "hi")],
    "negative_chunk_size": [(False, None, "")],
    "huge_chunk_size": [(False, None, "")],
    "close_delimited": [(True, 200, "body runs to close")],
    "no_content_204": [(True, 204, ""), (True, 200, "hi")],
    "junk_not_a_status_line": [(False, None, "")],
    "bogus_status_code": [(False, None, "")],
    "truncated_cl": [(False, None, "")],
    # the framing is unrecoverable (RFC 9112 §6.3), so the response is refused outright and
    # the connection is poisoned — the quoted 200 never becomes a response
    "conflicting_duplicate_cl": [(False, None, ""), (False, None, "")],
    # a 204/304 carries no body: the declared bytes are NOT this response's, and the
    # connection's framing is unrecoverable, so read #2 is NO CHANNEL
    "no_content_204_with_a_body": [(True, 204, ""), (False, None, "")],
    "not_modified_304_with_a_body": [(True, 304, ""), (False, None, "")],
    # after 101 the connection has left HTTP/1.1: the trailing bytes are protocol data
    "upgraded_101_then_bytes": [(True, 101, ""), (False, None, "")],
    "plus_chunk_size": [(False, None, "")],
    "hex_prefix_chunk_size": [(False, None, "")],
    "underscore_chunk_size": [(False, None, "")],
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_reader_frames_each_case(name: str) -> None:
    chunks, n, close = CASES[name]
    got = _read(_shared, chunks, n, close=close, timeout=0.6)
    assert got == EXPECTED[name], f"{name}: {got!r} != {EXPECTED[name]!r}"


def test_a_benign_first_response_echo_never_becomes_the_second_response() -> None:
    """The whole point, stated as one assertion: on every case where a benign origin echoes
    VIGIL's first request (canary and all), the canary must NOT appear in read #2.

    Audit-A red-pen BLOCK-7b added the last four. Each was MEASURED to hand back a read #2
    with ``channel=True, status=200`` whose body carried the canary — a second response
    manufactured entirely out of the FIRST response's leftover bytes."""
    refused = {"conflicting_duplicate_cl", "no_content_204_with_a_body",
               "not_modified_304_with_a_body", "upgraded_101_then_bytes"}
    for name in ("interim_100_continue", "under_declared_cl", "chunked_trailers", *sorted(refused)):
        chunks, n, close = CASES[name]
        got = _read(_shared, chunks, max(n, 2), close=close, timeout=0.6)
        assert _CANARY not in got[1][2], f"{name}: the canary leaked into the second response"
        if name in refused:
            # these four leave the connection unframeable, so read #2 is an honest
            # INCONCLUSIVE rather than a genuinely pipelined response
            assert got[1][0] is False, f"{name}: read #2 must establish no channel, got {got[1]!r}"


def test_the_narrowed_limit_of_the_status_line_rule_is_stated_honestly() -> None:
    """BLOCK-7b, the ONE shape that is NOT refused, pinned so the module docstring cannot
    drift back into claiming it is.

    Correction #2 bounds surplus that is NOT a status line. Surplus that IS one — an origin
    whose error page quotes a complete ``HTTP/1.1 200 OK`` block, under a Content-Length
    that stops before it — is still returned as read #2, because nothing on the wire
    separates that from a genuinely pipelined response. It is not a live false LEAD today
    (``smuggling._desync_leg`` runs the control leg over the same origin shape, so a reader
    artefact affecting both legs cancels), but it IS the trap for the named cross-connection
    follow-up, where the two legs are no longer same-shape. Asserted POSITIVELY so the
    limitation is visible, not merely absent."""
    wire = [b"HTTP/1.1 400 Bad Request\r\nContent-Length: 7\r\n\r\nrefused" + _QUOTED_200]
    got = _read(_shared, wire, 2, close=True, timeout=0.6)
    assert got[0] == (True, 400, "refused")
    assert got[1] == (True, 200, _CANARY), (
        "if this now refuses, the reader gained the sent-request watermark the docstring "
        "names as follow-up — delete this test and the 'exact limit' paragraph with it")


def test_no_channel_records_why() -> None:
    with _served(CASES["junk_not_a_status_line"][0], timeout=0.6) as s:
        reader = RawResponseReader(s)
        rec = reader.read_response()
    assert rec["channel"] is False
    assert "not an HTTP status line" in reader.last_error


def test_content_length_isdigit_but_not_ascii_digit_is_refused_without_raising() -> None:
    """audit-A red-pen BLOCK-B — the ``_DIGITS`` guard covering the gap between ``str.isdigit()``
    and RFC 9112 §6.3's 1*DIGIT (ASCII only).

    ``0xB2`` (superscript-two "²") is ``str.isdigit() == True`` but ``int("²")`` raises
    ``ValueError``. Without the guard, ``_read_head`` would accept it and ``_read_body``'s
    ``int(cl)`` would raise, ESCAPING ``read_response`` (an unframed crash, not an honest
    INCONCLUSIVE). The guard matches the value against ``^[0-9]+$``, refuses it as unrecoverable,
    poisons the connection, and ``read_response`` returns NO CHANNEL — no exception escapes.

    This test KILLS the mutant that deletes the ``_DIGITS`` guard: with the guard gone, the
    ``int(cl)`` below raises ``ValueError`` out of ``read_response`` and the test errors."""
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: \xb2\r\n\r\nAA"
    with _served([wire], timeout=0.6) as s:
        reader = RawResponseReader(s)
        rec = reader.read_response()          # must NOT raise
    assert rec["channel"] is False and rec["status"] is None and rec["body"] == ""
    assert "Content-Length is unrecoverable" in reader.last_error, reader.last_error
    assert "²" in reader.last_error


def test_budget_bounds_the_read() -> None:
    """The budget bounds the read AND the bounded read is honest about being partial.

    Audit-A red-pen (ALSO): this used to assert ``channel is True`` with the partial body,
    which contradicted documented correction #5 ("a truncated body is NOT a complete
    response") — the deviation was real and the test pinned the deviation. A close-delimited
    body is complete only when the PEER closed; cut off by the read budget (or a socket
    timeout) it is truncated exactly like a short Content-Length or a clipped chunked body,
    and all three framings now agree on NO CHANNEL."""
    with _served([b"HTTP/1.1 200 OK\r\n\r\n" + b"A" * 200000], timeout=0.6) as s:
        reader = RawResponseReader(s, budget=4096)
        rec = reader.read_response()
    assert rec["channel"] is False and rec["body"] == ""
    assert "truncated" in reader.last_error, reader.last_error


def test_a_close_delimited_body_the_peer_finished_is_still_a_response() -> None:
    """The negative control for the test above: the budget rule must not turn every
    close-delimited response into an INCONCLUSIVE."""
    with _served([b"HTTP/1.1 200 OK\r\n\r\nbody runs to close"], timeout=0.6) as s:
        rec = RawResponseReader(s, budget=4096).read_response()
    assert rec["channel"] is True and rec["body"] == "body runs to close"


def test_desync_leg_view_matches_the_shared_reader() -> None:
    """``smuggling._RawResponseReader`` must be the SAME reader, only typed as a DesyncLeg."""
    for name in sorted(CASES):
        chunks, n, close = CASES[name]
        assert (_read(_shared, chunks, n, close=close, timeout=0.6)
                == _read(DesyncLegReader, chunks, n, close=close, timeout=0.6)), name


# ---------------------------------------------------------------------------------------
# drift guard
# ---------------------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parents[6]

#: The ONE file allowed to define a raw HTTP response reader.
_CANONICAL = "engine/crucible/framework/v2/scanner/rawhttp.py"

#: Documented PENDING migration. `integration/.../smuggling_redrive.py` still carries a
#: verbatim copy of the pre-fix reader; it is owned by a concurrent change, so the follow-up
#: must switch it to `from framework.v2.scanner.rawhttp import RawResponseReader` (imported
#: function-locally, per FATAL-2). Until then this test PINS the copy as still-divergent, so
#: the day it is migrated this test fails and forces the allowlist entry to be deleted.
_PENDING = "integration/vigil_integration/live/smuggling_redrive.py"

#: The cases the pending copy gets WRONG today. Exactly this set — no more (new drift), no
#: fewer (a silent partial fix, or the migration itself).
_PENDING_DIVERGENT = {
    "interim_100_continue", "under_declared_cl", "chunked_trailers",
    "negative_chunk_size", "huge_chunk_size", "truncated_cl",
    "junk_not_a_status_line", "bogus_status_code",
    # audit-A red-pen BLOCK-7b — the pending copy fabricates a read #2 on all four of these
    # (measured: channel=True, status=200, canary in body) and shares the `int(tok, 16)`
    # chunk-size leniency.
    "conflicting_duplicate_cl", "no_content_204_with_a_body",
    "not_modified_304_with_a_body", "upgraded_101_then_bytes",
    "plus_chunk_size", "hex_prefix_chunk_size", "underscore_chunk_size",
}


def _reader_definitions() -> "set[str]":
    """Every file that DEFINES a raw response reader. Keyed by AST on the framing METHODS
    that make one (``_read_chunked`` + ``read_response`` on one class), so a renamed class
    cannot hide a copy and a mere mention in a docstring or a test corpus cannot false-fire."""
    import ast

    found: set[str] = set()
    for root in ("engine/crucible/framework/v2", "integration/vigil_integration"):
        base = _REPO / root
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                methods = {b.name for b in node.body
                           if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef))}
                if {"_read_chunked", "read_response"} <= methods:
                    found.add(str(path.relative_to(_REPO)))
    return found


def test_the_raw_response_reader_is_not_duplicated() -> None:
    defs = _reader_definitions()
    assert _CANONICAL in defs, f"the canonical reader moved: {sorted(defs)}"
    unexpected = defs - {_CANONICAL, _PENDING}
    assert not unexpected, (
        "a SECOND raw HTTP response reader was defined — this class of bug recurs at every "
        "unguarded site, so there is exactly ONE implementation and every consumer imports "
        f"it from {_CANONICAL}: {sorted(unexpected)}")


def test_the_pending_duplicate_is_still_exactly_as_divergent_as_documented() -> None:
    """A tripwire in BOTH directions. If the pending copy drifts further, the divergent set
    grows and this fails. If the follow-up migrates it to the shared reader, the set empties
    and this fails too — which is the signal to delete ``_PENDING``/``_PENDING_DIVERGENT``
    and let ``test_the_raw_response_reader_is_not_duplicated`` stand alone."""
    mod = pytest.importorskip(
        "vigil_integration.live.smuggling_redrive",
        reason="the integration tree is not on the path in the CRUCIBLE-core CI job")
    legacy = getattr(mod, "_RawResponseReader", None)
    if legacy is None:                    # already migrated -> the allowlist must go
        pytest.fail(f"{_PENDING} no longer defines its own reader — delete the _PENDING "
                    f"allowlist entry and this test")

    divergent = set()
    for name in sorted(CASES):
        chunks, n, close = CASES[name]
        got = _read(lambda s: legacy(s, budget=65536), chunks, n, close=close, timeout=0.6)
        if got != EXPECTED[name]:
            divergent.add(name)
    assert divergent == _PENDING_DIVERGENT, (
        f"the pending duplicate in {_PENDING} no longer diverges exactly as documented "
        f"(now={sorted(divergent)}, documented={sorted(_PENDING_DIVERGENT)}). Either it "
        f"drifted further, or it was migrated/partly fixed — in which case switch it to "
        f"framework.v2.scanner.rawhttp and delete this allowlist.")
