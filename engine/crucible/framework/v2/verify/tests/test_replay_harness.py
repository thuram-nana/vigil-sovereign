"""B4 — verify.replay_harness: re-drive a stored PoC over its retained bytes, fail-closed.

``replay_poc`` re-fires the pure oracle over an artifact's captured exchanges. A firing capture re-passes; a
benign one, or one whose bytes no longer resolve, is a ``passed=False`` — never a spurious pass.
"""

from __future__ import annotations

from framework.v2.verify.replay_harness import replay_poc


class _Ex:
    def __init__(self, channel, role="", request_bytes_ref="", response_bytes_ref=""):
        self.channel = channel
        self.role = role
        self.request_bytes_ref = request_bytes_ref
        self.response_bytes_ref = response_bytes_ref
        self.status = None


class _Artifact:
    def __init__(self, bug_class, exchanges, finding_ref="poc-1"):
        self.finding_ref = finding_ref
        self.bug_class = bug_class
        self.exchanges = exchanges


def _sqli_artifact():
    return _Artifact("sqli_attempt", [_Ex("request_payload", role="q", request_bytes_ref="r")])


def test_replay_passes_for_a_still_reproducing_poc():
    res = replay_poc(_sqli_artifact(), resolve=lambda r: b"' OR '1'='1")
    assert res.passed is True and res.reproduced is True


def test_replay_fails_for_a_benign_capture():
    res = replay_poc(_sqli_artifact(), resolve=lambda r: b"O'Brien")
    assert res.passed is False


def test_replay_fails_closed_when_bytes_no_longer_resolve():
    res = replay_poc(_sqli_artifact(), resolve=lambda r: None)
    assert res.passed is False and "no longer translate" in res.note
