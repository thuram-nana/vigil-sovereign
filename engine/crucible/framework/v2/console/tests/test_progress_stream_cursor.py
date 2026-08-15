"""W6c — the run progress stream (`/api/events?run=`) must be able to REPLAY a finished run's record,
and must never re-deliver what a client already has.

Both halves are load-bearing and each was a red-pen BLOCK:

  * without ``from_start`` the tailer opens at EOF, so a run that has ALREADY finished streams nothing —
    the Live view then shows "waiting for the first event" and a "Refusals 0" tile for a run WARDEN may
    have blocked many times, presenting the feed's ABSENCE as a measured zero;
  * with ``from_start`` but no cursor, every reconnect re-delivers the whole file — the same tiles then
    read a FABRICATED total (3 blocks counted as 9), which is no better.

So the stream emits ``id:`` (the event's true line number) + ``_seq`` in the payload, and honours
``Last-Event-ID``. These tests drive the REAL server over HTTP.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from contextlib import contextmanager

from framework.v2.console import actions, server

from .conftest import AUTH_HEADERS


@contextmanager
def _serve(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    httpd = server.serve(host="127.0.0.1", port=0)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _seed(tmp_path, run_id="run-abc", n=3):
    """A FINISHED run whose whole record is already on disk (the case that used to stream nothing)."""
    rd = tmp_path / "runs" / run_id
    rd.mkdir(parents=True)
    with (rd / "progress.jsonl").open("w", encoding="utf-8") as f:
        for i in range(n):
            f.write(json.dumps({"event": "warden.block", "gate": "warden",
                                "action_refused": f"exec_command_{i}", "reason": "queued"}) + "\n")
    return run_id


def _read_events(url, *, last_event_id=None, want=0, timeout=6.0):
    """Read SSE frames until `want` data lines have arrived (or the socket times out). Returns the parsed
    payloads plus the raw id: lines, then closes — exactly what a browser does before reconnecting."""
    req = urllib.request.Request(url, headers=dict(AUTH_HEADERS))
    if last_event_id is not None:
        req.add_header("Last-Event-ID", str(last_event_id))
    events, ids = [], []
    resp = urllib.request.urlopen(req, timeout=timeout)
    try:
        while len(events) < want or want == 0:
            try:
                line = resp.fp.readline()
            except (TimeoutError, OSError):
                break          # a live tail with nothing more to send — that IS the "no events" answer
            if not line:
                break
            s = line.decode("utf-8", "replace").strip()
            if s.startswith("id: "):
                ids.append(int(s[4:]))
            elif s.startswith("data: "):
                events.append(json.loads(s[6:]))
                if len(events) >= want:
                    break
    finally:
        try:
            resp.close()
        except OSError:
            pass
    return events, ids


def test_from_start_replays_a_finished_runs_whole_record(monkeypatch, tmp_path):
    """BLOCK-1: the record must actually be replayable — this is what makes the 'See what it did in Live'
    button truthful. Without from_start the tailer starts at EOF and this returns NOTHING."""
    run_id = _seed(tmp_path, n=3)
    with _serve(monkeypatch, tmp_path) as base:
        evs, ids = _read_events(f"{base}/api/events?run={run_id}&from_start=1", want=3)
    assert [e["action_refused"] for e in evs] == ["exec_command_0", "exec_command_1", "exec_command_2"]
    assert ids == [1, 2, 3], "every event must carry its true line number as the SSE id cursor"
    assert [e["_seq"] for e in evs] == [1, 2, 3], "the cursor must also ride in the payload for client dedup"


def test_without_from_start_a_finished_run_streams_nothing(monkeypatch, tmp_path):
    """The default stays a live TAIL — the replay is opt-in, so nothing else changes behaviour."""
    run_id = _seed(tmp_path, n=3)
    with _serve(monkeypatch, tmp_path) as base:
        evs, _ = _read_events(f"{base}/api/events?run={run_id}", want=1, timeout=2.0)
    assert evs == []


def test_a_live_tail_delivers_newly_appended_events(monkeypatch, tmp_path):
    """The POSITIVE half of the live tail, and the one that was missing: "streams nothing" is satisfied by
    a correct tail AND by a DEAD one, so on its own it lets a broken stream pass (a realistic partial
    revert killed the stream and survived the whole suite). This asserts a tail actually delivers what is
    appended after the client connects — the pre-existing behaviour of every loopback scan and of the
    legacy ?slug= view."""
    run_id = _seed(tmp_path, n=2)             # pre-existing lines must NOT be replayed...
    log = tmp_path / "runs" / run_id / "progress.jsonl"
    with _serve(monkeypatch, tmp_path) as base:
        req = urllib.request.Request(f"{base}/api/events?run={run_id}", headers=dict(AUTH_HEADERS))
        resp = urllib.request.urlopen(req, timeout=8.0)
        try:
            _drain_preamble(resp)             # the handler has entered its loop
            with log.open("a", encoding="utf-8") as f:   # ...but this one MUST arrive
                f.write(json.dumps({"event": "warden.block", "action_refused": "appended_live"}) + "\n")
            got = _next_data(resp, timeout=8.0)
        finally:
            resp.close()
    assert got is not None and got.get("action_refused") == "appended_live", \
        "a live tail delivered nothing — the stream is dead, not merely quiet"
    assert "_seq" not in got, "a live tail carries no cursor (it must not pay to number a whole file)"


def _drain_preamble(resp):
    """Read the `retry:` preamble so we know the handler has entered its loop."""
    while True:
        line = resp.fp.readline()
        if not line or line.decode("utf-8", "replace").startswith("retry:"):
            return


def _next_data(resp, *, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            line = resp.fp.readline()
        except (TimeoutError, OSError):
            return None
        if not line:
            return None
        s = line.decode("utf-8", "replace").strip()
        if s.startswith("data: "):
            return json.loads(s[6:])
    return None


def test_reconnect_with_last_event_id_never_re_delivers(monkeypatch, tmp_path):
    """BLOCK-B: the defect that made "3 blocks" render as "Refusals 9". A reconnect carrying the cursor
    must resume, not replay."""
    run_id = _seed(tmp_path, n=3)
    with _serve(monkeypatch, tmp_path) as base:
        url = f"{base}/api/events?run={run_id}&from_start=1"
        first, ids = _read_events(url, want=3)
        assert len(first) == 3 and ids[-1] == 3
        # the browser reconnects carrying the last id it saw — it must receive NOTHING more
        again, _ = _read_events(url, last_event_id=ids[-1], want=1, timeout=2.0)
    assert again == [], "a reconnect re-delivered events the client already had — counters would inflate"


def test_reconnect_mid_record_delivers_only_the_remainder(monkeypatch, tmp_path):
    run_id = _seed(tmp_path, n=4)
    with _serve(monkeypatch, tmp_path) as base:
        url = f"{base}/api/events?run={run_id}&from_start=1"
        rest, ids = _read_events(url, last_event_id=2, want=2)
    assert [e["action_refused"] for e in rest] == ["exec_command_2", "exec_command_3"]
    assert ids == [3, 4], "resume must continue the ORIGINAL numbering, not restart it"


def test_from_start_is_refused_for_a_slug_stream(monkeypatch, tmp_path):
    """`run` is validated; `slug` indexes straight into the targets root, so a full-file replay there
    would widen a bounded tail into a whole-file read down an unvalidated path. No caller needs it."""
    (tmp_path / "runs").mkdir(parents=True, exist_ok=True)
    log = tmp_path / "secret.log"
    log.write_text(json.dumps({"event": "historic", "note": "prior contents"}) + "\n", encoding="utf-8")
    monkeypatch.setattr(server, "stream_path", lambda run=None, slug=None: log)
    with _serve(monkeypatch, tmp_path) as base:
        evs, _ = _read_events(f"{base}/api/events?slug=anything&from_start=1", want=1, timeout=2.0)
    assert evs == [], "from_start must not replay a slug-addressed log"
    # NB: this bounds the REPLAY only. A slug live tail still streams what is appended next — the guard
    # is about not emitting a whole file addressed by an unvalidated name, not confidentiality.


def test_a_last_event_id_header_cannot_force_a_slug_replay(monkeypatch, tmp_path):
    """The SECOND door. `Last-Event-ID` is a request HEADER, so gating only the `from_start` query flag
    left the whole replay path — the full-file read AND the counter that cannot survive a rotation —
    reachable on any stream with one header. Both doors must share one gate.

    A test that checks only the query param green-washes the guard: it passes while the header walks in."""
    (tmp_path / "runs").mkdir(parents=True, exist_ok=True)
    log = tmp_path / "engagement.log"
    with log.open("w", encoding="utf-8") as f:
        for i in range(4):
            f.write(json.dumps({"event": "historic", "n": i}) + "\n")
    monkeypatch.setattr(server, "stream_path", lambda run=None, slug=None: log)
    with _serve(monkeypatch, tmp_path) as base:
        evs, ids = _read_events(f"{base}/api/events?slug=anything",
                                last_event_id=1, want=1, timeout=2.0)
    assert evs == [], "a Last-Event-ID header replayed a slug-addressed log"
    assert ids == [], "a non-replayable stream must emit no cursor at all"



def test_a_producer_supplied_seq_is_overwritten_by_the_stream_cursor(monkeypatch, tmp_path):
    """`_seq` must always be the stream's own cursor. If a line on disk carried its own `_seq`, it would
    DISAGREE with the emitted `id:` — and both UI consumers dedup on `_seq`, so a repeated value would
    silently suppress genuine rows."""
    rd = tmp_path / "runs" / "run-seq"
    rd.mkdir(parents=True)
    with (rd / "progress.jsonl").open("w", encoding="utf-8") as f:
        for i in range(2):
            f.write(json.dumps({"event": "warden.block", "_seq": "PRODUCER", "n": i}) + "\n")
    with _serve(monkeypatch, tmp_path) as base:
        evs, ids = _read_events(f"{base}/api/events?run=run-seq&from_start=1", want=2)
    assert [e["_seq"] for e in evs] == [1, 2], "a producer-supplied _seq survived and shadowed the cursor"
    assert ids == [1, 2] and [e["_seq"] for e in evs] == ids, "payload and id: cursor must agree"


def test_the_ambient_engagement_log_is_never_cursored(monkeypatch, tmp_path):
    """The LOAD-BEARING half of the gate. `stream_path` gives `run` precedence, so `not slug_q` is
    redundant — `run_q` is the only conjunct keeping the AMBIENT log (`log_path_for(None)`, which
    common.logging ROTATES at 64MB) out of replay. Rotation is exactly what a monotonic cursor cannot
    survive: ids run past the new file's length and every later event is suppressed permanently.

    The other two negative controls both pass `?slug=` with no `run`, so they are satisfied by the
    REDUNDANT conjunct and never execute this one — a mutant dropping it passed all 562 console tests."""
    (tmp_path / "runs").mkdir(parents=True, exist_ok=True)
    log = tmp_path / "ambient.log"
    with log.open("w", encoding="utf-8") as f:
        for i in range(4):
            f.write(json.dumps({"event": "historic", "n": i}) + "\n")
    monkeypatch.setattr(server, "stream_path", lambda run=None, slug=None: log)
    with _serve(monkeypatch, tmp_path) as base:
        # no query at all — the ambient stream — with a cursor header
        evs, ids = _read_events(f"{base}/api/events", last_event_id=1, want=1, timeout=2.0)
        assert evs == [] and ids == [], "the no-arg ambient stream was replayed/cursored"
        # ...and with the query flag
        evs2, ids2 = _read_events(f"{base}/api/events?from_start=1", want=1, timeout=2.0)
        assert evs2 == [] and ids2 == [], "from_start replayed the ambient stream"
        # ...and a BLANK run, which must not read as "a run"
        evs3, ids3 = _read_events(f"{base}/api/events?run=&from_start=1", last_event_id=1,
                                  want=1, timeout=2.0)
    assert evs3 == [] and ids3 == [], "a blank ?run= was treated as a replayable run"


def test_the_aegis_verdicts_stream_is_a_pure_tail(monkeypatch, tmp_path):
    """The second _sse call site passes no allow_replay and relies entirely on the signature default —
    nothing pinned it, so flipping that default to True survived the whole console suite. The AEGIS
    gateway's verdicts JSONL is unbounded and written in front of a live app; it must never become a
    whole-file read + cursored stream."""
    (tmp_path / "runs").mkdir(parents=True, exist_ok=True)
    verdicts = tmp_path / "verdicts.jsonl"
    with verdicts.open("w", encoding="utf-8") as f:
        for i in range(3):
            f.write(json.dumps({"verdict": "allow", "n": i}) + "\n")
    monkeypatch.setattr(actions, "aegis_verdicts_path", lambda: str(verdicts))
    with _serve(monkeypatch, tmp_path) as base:
        evs, ids = _read_events(f"{base}/api/aegis/verdicts?from_start=1",
                                last_event_id=1, want=1, timeout=2.0)
    assert evs == [], "the AEGIS verdicts stream replayed its history"
    assert ids == [], "the AEGIS verdicts stream emitted a cursor"


def test_a_cursor_alone_resumes_a_run_stream(monkeypatch, tmp_path):
    """`replay` is `from_start OR Last-Event-ID` — the OR term needs its own control. A client that
    reconnects carrying only the cursor (no from_start) must RESUME and get the remainder; ignoring the
    cursor would silently downgrade it to a tail and drop the rest of the record. Self-fuzz found this
    gap: `replay = allow_replay and from_start` survived the suite because every other test also passes
    from_start=1."""
    run_id = _seed(tmp_path, n=4)
    with _serve(monkeypatch, tmp_path) as base:
        rest, ids = _read_events(f"{base}/api/events?run={run_id}",   # NO from_start
                                 last_event_id=2, want=2)
    assert [e["action_refused"] for e in rest] == ["exec_command_2", "exec_command_3"], \
        "a cursor-only reconnect did not resume — the remainder of the record was lost"
    assert ids == [3, 4], "resume must continue the original numbering"
