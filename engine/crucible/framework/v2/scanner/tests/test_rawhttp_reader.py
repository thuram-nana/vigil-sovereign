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
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_reader_frames_each_case(name: str) -> None:
    chunks, n, close = CASES[name]
    got = _read(_shared, chunks, n, close=close, timeout=0.6)
    assert got == EXPECTED[name], f"{name}: {got!r} != {EXPECTED[name]!r}"


def test_a_benign_first_response_echo_never_becomes_the_second_response() -> None:
    """The whole point, stated as one assertion: on every case where a benign origin echoes
    VIGIL's first request (canary and all), the canary must NOT appear in read #2."""
    for name in ("interim_100_continue", "under_declared_cl", "chunked_trailers"):
        chunks, n, close = CASES[name]
        got = _read(_shared, chunks, max(n, 2), close=close, timeout=0.6)
        assert _CANARY not in got[1][2], f"{name}: the canary leaked into the second response"


def test_no_channel_records_why() -> None:
    with _served(CASES["junk_not_a_status_line"][0], timeout=0.6) as s:
        reader = RawResponseReader(s)
        rec = reader.read_response()
    assert rec["channel"] is False
    assert "not an HTTP status line" in reader.last_error


def test_budget_bounds_the_read() -> None:
    with _served([b"HTTP/1.1 200 OK\r\n\r\n" + b"A" * 200000], timeout=0.6) as s:
        reader = RawResponseReader(s, budget=4096)
        rec = reader.read_response()
    assert rec["channel"] is True and len(rec["body"]) <= 4096


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
