"""The PENDING (unconfirmed) TOTP store (ui/pending_totp.py) for confirm-before-activate.

Load-bearing invariants (fail-closed: the only thing a broken store can do is refuse to confirm):
  * a parked sealed secret is returned by peek WITHIN the TTL, and reads as ABSENT once the TTL lapses;
  * peek is per-account (another username never sees it) and clear removes it;
  * an absent / malformed / oversized marker reads as None, never a secret.
"""
from __future__ import annotations

from sigil.ui.pending_totp import PendingTotpEnrolments

NOW = 100000.0
U = "cust_pending000000000000000001"


def test_put_then_peek_returns_the_sealed_secret_within_ttl(tmp_path):
    store = PendingTotpEnrolments(tmp_path / "p", ttl_s=900.0)
    store.put(U, "SEALED-BLOB-B64", now=NOW)
    assert store.peek(U, now=NOW) == "SEALED-BLOB-B64"
    assert store.peek(U, now=NOW + 899) == "SEALED-BLOB-B64"           # still fresh


def test_expired_pending_reads_as_absent(tmp_path):
    store = PendingTotpEnrolments(tmp_path / "p", ttl_s=900.0)
    store.put(U, "SEALED-BLOB-B64", now=NOW)
    assert store.peek(U, now=NOW + 901) is None                        # past the TTL -> gone (fail-closed)


def test_peek_is_per_account_and_clear_removes_it(tmp_path):
    store = PendingTotpEnrolments(tmp_path / "p", ttl_s=900.0)
    store.put(U, "SEALED-BLOB-B64", now=NOW)
    assert store.peek("cust_other0000000000000000001", now=NOW) is None   # another account never sees it
    store.clear(U)
    assert store.peek(U, now=NOW) is None                              # cleared


def test_absent_and_malformed_marker_read_as_none(tmp_path):
    store = PendingTotpEnrolments(tmp_path / "p", ttl_s=900.0)
    assert store.peek(U, now=NOW) is None                              # nothing parked
    store.put(U, "SEALED-BLOB-B64", now=NOW)
    marker = store._marker(U)
    marker.write_text("not json at all")                              # corrupt the marker
    assert store.peek(U, now=NOW) is None                             # fail-closed, never a bogus secret
