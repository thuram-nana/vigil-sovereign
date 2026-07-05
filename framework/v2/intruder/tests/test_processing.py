"""
Payload-processing pipeline — each rule, composition, drops, and a live attack
where only the encoded payloads bypass a filter.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.intruder import (
    AttackType,
    IntruderEngine,
    generators,
    processing,
)
from framework.v2.intruder.processing import PayloadProcessor, processed
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate


def test_individual_rules() -> None:
    assert processing.add_prefix("<")("x") == "<x"
    assert processing.add_suffix(">")("x") == "x>"
    assert processing.match_replace(r"\d", "#")("a1b2") == "a#b#"
    assert processing.to_case("upper")("aB") == "AB"
    assert processing.url_encode()("a b&c") == "a%20b%26c"
    assert processing.base64_encode()("hi") == base64.b64encode(b"hi").decode()
    assert processing.hex_encode()("AB") == "4142"
    assert processing.hash_with("sha256")("x") == hashlib.sha256(b"x").hexdigest()
    assert processing.skip_if(r"^admin$")("admin") is None
    assert processing.skip_if(r"^admin$")("user") == "user"


def test_ordered_pipeline_and_drops() -> None:
    proc = PayloadProcessor([
        processing.add_prefix("id="),        # id=alice
        processing.to_case("upper"),          # ID=ALICE
        processing.skip_if("BOB"),            # keep (no BOB)
    ])
    assert proc.process("alice") == "ID=ALICE"

    dropper = PayloadProcessor([processing.skip_if("secret")])
    assert dropper.process("secret") is None

    # signed-field style: value + its own sha256, via a match_replace after hash
    signer = PayloadProcessor([processing.hash_with("md5")])
    assert signer.process("v") == hashlib.md5(b"v").hexdigest()


def test_processed_generator_skips_dropped_payloads() -> None:
    gen = generators.simple_list(["keep1", "dropme", "keep2"])
    proc = PayloadProcessor([processing.skip_if("drop")])
    assert list(processed(gen, proc)) == ["keep1", "keep2"]


# --- live: only base64-encoded payloads get past a naive filter --------------


class _FilterApp(BaseHTTPRequestHandler):
    """Rejects any raw "'" it sees (a naive WAF), but base64-decodes `q` and runs
    the boolean-SQLi on the decoded value — so an encoded tautology gets through."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        raw = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("q", [""])[0]
        if "'" in raw:  # the "WAF": blocks obvious injection
            body, code = b"blocked", 403
        else:
            try:
                decoded = base64.b64decode(raw).decode("utf-8", "replace")
            except Exception:
                decoded = raw
            rows = "\n".join(f"r{i}" for i in range(9)) if "'1'='1" in decoded else "none"
            body, code = f"ok:{rows}".encode(), 200
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FilterApp)
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
    try:
        with urllib.request.urlopen(  # noqa: S310 (loopback)
            urllib.request.Request(req.url, method=req.method), timeout=5
        ) as resp:
            return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", "replace")}


def test_base64_processing_bypasses_the_filter() -> None:
    with _server() as base:
        t = RequestTemplate(HttpRequest(method="GET", url=f"{base}/s?q=x"))
        q = next(p for p in t.insertion_points(kinds=[InsertionKind.QUERY_VALUE]) if p.name == "q")

        payloads = ["benign", "x' OR '1'='1"]
        raw_gen = generators.simple_list(payloads)
        enc_gen = processed(generators.simple_list(payloads),
                            PayloadProcessor([processing.base64_encode()]))

        raw = IntruderEngine(_send, grep=("r8",)).run(t, [q], [raw_gen], AttackType.SNIPER)
        enc = IntruderEngine(_send, grep=("r8",)).run(t, [q], [enc_gen], AttackType.SNIPER)

        # raw tautology is blocked (403) -> the success row (grep r8) never appears
        assert not any(r.grep.get("r8") for r in raw.rows), "raw payload should be filtered"
        # base64-encoded tautology decodes server-side and dumps rows -> grep hit
        assert any(r.grep.get("r8") for r in enc.rows), "encoded payload should bypass the filter"
