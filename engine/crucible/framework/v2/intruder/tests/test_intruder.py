"""
Intruder engine — generators, attack combinatorics, outlier triage, and a live
credential brute-force whose valid row is found automatically.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.intruder import (
    AttackResult,
    AttackType,
    IntruderEngine,
    detect_outliers,
    generators,
    render_attack,
)
from framework.v2.intruder.engine import AttackResultRow
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate


# --- generators -------------------------------------------------------------


def test_generators() -> None:
    assert list(generators.simple_list([1, "a", 2])) == ["1", "a", "2"]
    assert list(generators.numbers(1, 4)) == ["1", "2", "3"]
    assert list(generators.null_payloads("x", 3)) == ["x", "x", "x"]
    assert list(generators.brute_force("ab", 1, 2)) == ["a", "b", "aa", "ab", "ba", "bb"]
    assert list(generators.case_variations("Ab")) == ["ab", "AB", "Ab"]
    assert list(generators.char_blocks("A", 1, 3)) == ["A", "AA", "AAA"]
    # bit_flipper flips exactly 8 bits per byte
    assert len(list(generators.bit_flipper("A"))) == 8


# --- attack combinatorics ---------------------------------------------------


def _login_template() -> RequestTemplate:
    return RequestTemplate(HttpRequest(method="GET", url="https://t/login?user=x&pass=y"))


def _points(t: RequestTemplate):
    pts = {p.name: p for p in t.insertion_points(kinds=[InsertionKind.QUERY_VALUE])}
    return pts["user"], pts["pass"]


def test_cluster_bomb_is_cartesian_product() -> None:
    t = _login_template()
    user, pw = _points(t)
    combos = list(render_attack(
        t, [user, pw],
        [generators.simple_list(["a", "b"]), generators.simple_list(["1", "2", "3"])],
        AttackType.CLUSTER_BOMB,
    ))
    assert len(combos) == 6  # 2 × 3
    payload_sets = {c[0] for c in combos}
    assert ("a", "1") in payload_sets and ("b", "3") in payload_sets
    # each rendered request carries both payloads at the right positions
    _, req = next(c for c in combos if c[0] == ("b", "3"))
    q = dict(urllib.parse.parse_qsl(req.url.split("?", 1)[1]))
    assert q == {"user": "b", "pass": "3"}


def test_sniper_hits_one_position_at_a_time() -> None:
    t = _login_template()
    user, pw = _points(t)
    combos = list(render_attack(t, [user, pw], [generators.simple_list(["Z"])], AttackType.SNIPER))
    assert len(combos) == 2  # 2 positions × 1 payload
    urls = [dict(urllib.parse.parse_qsl(r.url.split("?", 1)[1])) for _, r in combos]
    assert {"user": "Z", "pass": "y"} in urls and {"user": "x", "pass": "Z"} in urls


# --- outlier detection ------------------------------------------------------


def _row(i: int, status: int, length: int, grep=None) -> AttackResultRow:
    return AttackResultRow(index=i, payloads=(str(i),), status=status, length=length,
                           latency_ms=1.0, grep=grep or {})


def test_outlier_by_minority_status() -> None:
    rows = [_row(i, 401, 20) for i in range(7)] + [_row(7, 200, 55)]
    assert detect_outliers(rows) == [7]


def test_outlier_by_length_and_grep() -> None:
    rows = [_row(i, 200, 20) for i in range(6)]
    rows[3] = _row(3, 200, 2000)             # length outlier
    rows[5] = _row(5, 200, 20, {"flag": True})  # grep hit
    assert set(detect_outliers(rows)) == {3, 5}


def test_uniform_population_has_no_outliers() -> None:
    assert detect_outliers([_row(i, 200, 20) for i in range(5)]) == []


# --- end-to-end brute force -------------------------------------------------


class _Login(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        p = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        ok = p.get("user") == ["admin"] and p.get("pass") == ["secret"]
        body = b"welcome admin dashboard token=abc" if ok else b"denied"
        self.send_response(200 if ok else 401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Login)
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
    r = urllib.request.Request(req.url, method=req.method, headers=dict(req.headers))
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (loopback)
            return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", "replace")}


def test_cluster_bomb_brute_force_finds_valid_credentials() -> None:
    with _server() as base:
        t = RequestTemplate(HttpRequest(method="GET", url=f"{base}/login?user=x&pass=y"))
        user, pw = _points(t)
        result = IntruderEngine(_send, grep=("welcome",)).run(
            t, [user, pw],
            [generators.simple_list(["admin", "root", "guest"]),
             generators.simple_list(["wrong", "secret", "12345"])],
            AttackType.CLUSTER_BOMB,
        )
        assert isinstance(result, AttackResult)
        assert result.requests_sent == 9
        # exactly one row is anomalous, and it is (admin, secret)
        assert len(result.outliers) == 1
        hit = result.outliers[0]
        assert hit.payloads == ("admin", "secret") and hit.status == 200
        assert hit.grep.get("welcome") is True


def test_null_payloads_repeat_identical_requests_for_race() -> None:
    with _server() as base:
        t = RequestTemplate(HttpRequest(method="GET", url=f"{base}/login?user=admin&pass=secret"))
        pw = {p.name: p for p in t.insertion_points(kinds=[InsertionKind.QUERY_VALUE])}["pass"]
        result = IntruderEngine(_send).run(
            t, [pw], [generators.null_payloads("secret", 5)], AttackType.SNIPER)
        assert result.requests_sent == 5
        assert all(r.payloads == ("secret",) and r.status == 200 for r in result.rows)
