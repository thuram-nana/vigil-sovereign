"""B1 — verify.poc_translate: CapturedExchange → FindingContext (or an honest None).

The translator reshapes executor-captured bytes into the FindingContext the oracle judges. It is a
TRANSLATOR, not a judge: it returns a context when the capture carries the needed STRUCTURE (the oracle
still decides whether to fire), and None when it does not — never a fabricated context.
"""

from __future__ import annotations

from framework.v2.verify.poc_translate import context_from_exchanges


class _Ex:
    def __init__(self, channel, role="", request_bytes_ref="", response_bytes_ref="", status=None):
        self.channel = channel
        self.role = role
        self.request_bytes_ref = request_bytes_ref
        self.response_bytes_ref = response_bytes_ref
        self.status = status


def test_request_payload_translates_to_a_context():
    exs = [_Ex("request_payload", role="q", request_bytes_ref="r")]
    ctx = context_from_exchanges(exs, bug_class="sqli_attempt", resolve=lambda r: b"' OR '1'='1")
    assert ctx is not None


def test_http_differential_translates_with_both_halves():
    exs = [_Ex("http_differential", role="baseline", response_bytes_ref="b", status=200),
           _Ex("http_differential", role="mutated", response_bytes_ref="m", status=200)]
    ctx = context_from_exchanges(exs, bug_class="sqli",
                                 resolve=lambda r: b"no results" if r == "b" else b"id=1\nid=2\nid=3 (all rows)")
    assert ctx is not None


def test_unknown_channel_is_none():
    exs = [_Ex("smoke_signals", request_bytes_ref="r")]
    assert context_from_exchanges(exs, bug_class="sqli_attempt", resolve=lambda r: b"x") is None


def test_unresolvable_ref_is_none():
    exs = [_Ex("request_payload", role="q", request_bytes_ref="r")]
    assert context_from_exchanges(exs, bug_class="sqli_attempt", resolve=lambda r: None) is None


def test_differential_missing_a_half_is_none():
    exs = [_Ex("http_differential", role="baseline", response_bytes_ref="b")]   # no mutated half
    assert context_from_exchanges(exs, bug_class="sqli", resolve=lambda r: b"x") is None


def test_empty_bug_class_or_no_exchanges_is_none():
    assert context_from_exchanges([], bug_class="sqli_attempt", resolve=lambda r: b"x") is None
    exs = [_Ex("request_payload", role="q", request_bytes_ref="r")]
    assert context_from_exchanges(exs, bug_class="", resolve=lambda r: b"x") is None
