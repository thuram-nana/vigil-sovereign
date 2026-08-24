"""Unit tests for the shared proxy->offense role assertion (`vigil_core.hopauth`, W16-12).

This is the ONE construction the `vigil up` proxy STAMPS and BOTH offense backends (console + gated api)
VERIFY. The tests pin: the exact signed byte format (so the two sides cannot drift), a stamp/verify
round-trip, and every fail-closed branch (blank key, missing field, non-numeric/stale ts, wrong key,
tampered field). A single-reviewer near-zero-FP claim is not self-certifying, so the negative branches are
explicit and exhaustive.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

from vigil_core.hopauth import (
    DEFAULT_HOP_MAX_SKEW_S,
    hop_message,
    stamp_hop_assertion,
    verify_hop_assertion,
)

KEY = "hop-secret-key-abc123"
P, R, M, PATH, TS = "alice", "operator", "POST", "/api/v1/tool/invoke", "1700000000"


def test_message_is_the_documented_field_set():
    # principal\nrole\nmethod\npath\nts, UTF-8 — the format both offense backends recompute against.
    assert hop_message(P, R, M, PATH, TS) == b"alice\noperator\nPOST\n/api/v1/tool/invoke\n1700000000"


def test_stamp_matches_a_hand_computed_hmac():
    expected = base64.b64encode(
        hmac.new(KEY.encode(), hop_message(P, R, M, PATH, TS), hashlib.sha256).digest()).decode("ascii")
    assert stamp_hop_assertion(KEY, P, R, M, PATH, TS) == expected


def test_round_trip_verifies_within_the_window():
    sig = stamp_hop_assertion(KEY, P, R, M, PATH, TS)
    assert verify_hop_assertion(KEY, P, R, M, PATH, TS, sig, now=float(TS)) is True
    # at the exact skew boundary it still verifies; just past it, it does not.
    assert verify_hop_assertion(KEY, P, R, M, PATH, TS, sig,
                                now=float(TS) + DEFAULT_HOP_MAX_SKEW_S) is True
    assert verify_hop_assertion(KEY, P, R, M, PATH, TS, sig,
                                now=float(TS) + DEFAULT_HOP_MAX_SKEW_S + 1) is False


def test_fail_closed_on_missing_pieces():
    sig = stamp_hop_assertion(KEY, P, R, M, PATH, TS)
    assert verify_hop_assertion("", P, R, M, PATH, TS, sig, now=float(TS)) is False   # no key
    assert verify_hop_assertion(KEY, P, "", M, PATH, TS, sig, now=float(TS)) is False  # no role
    assert verify_hop_assertion(KEY, P, R, M, PATH, "", sig, now=float(TS)) is False   # no ts
    assert verify_hop_assertion(KEY, P, R, M, PATH, TS, "", now=float(TS)) is False    # no sig


def test_fail_closed_on_non_numeric_ts():
    sig = stamp_hop_assertion(KEY, P, R, M, PATH, "not-a-number")
    assert verify_hop_assertion(KEY, P, R, M, PATH, "not-a-number", sig, now=1700000000.0) is False


def test_wrong_key_or_tampered_field_is_rejected():
    sig = stamp_hop_assertion(KEY, P, R, M, PATH, TS)
    assert verify_hop_assertion("other-key", P, R, M, PATH, TS, sig, now=float(TS)) is False
    # a signature bound to one role/path/method cannot be re-aimed at another (each is in the MAC)
    assert verify_hop_assertion(KEY, P, "owner", M, PATH, TS, sig, now=float(TS)) is False
    assert verify_hop_assertion(KEY, P, R, "GET", PATH, TS, sig, now=float(TS)) is False
    assert verify_hop_assertion(KEY, P, R, M, "/api/v1/import", TS, sig, now=float(TS)) is False
    assert verify_hop_assertion(KEY, "eve", R, M, PATH, TS, sig, now=float(TS)) is False


def test_non_finite_ts_is_refused_even_when_signed_with_the_real_key():
    # `ts` is inside the HMAC, so only a hop-key holder can produce these — but a non-finite ts must STILL be
    # refused fail-closed: `abs(now - nan)` is nan and `nan > skew` is False, so WITHOUT the isfinite guard a
    # "nan"/"inf" ts would slip the freshness window entirely. Each is signed with the REAL key so the MAC
    # matches and ONLY the finiteness guard can reject it — a genuine negative control on that guard.
    for bad in ("nan", "NaN", "inf", "-inf", "Infinity", "-Infinity"):
        sig = stamp_hop_assertion(KEY, P, R, M, PATH, bad)
        assert verify_hop_assertion(KEY, P, R, M, PATH, bad, sig, now=1700000000.0) is False, bad


def test_default_now_uses_wall_clock_for_a_fresh_stamp():
    import time
    ts = str(int(time.time()))
    sig = stamp_hop_assertion(KEY, P, R, M, PATH, ts)
    # no explicit `now` → the wall clock; a just-minted stamp is inside the window.
    assert verify_hop_assertion(KEY, P, R, M, PATH, ts, sig) is True
