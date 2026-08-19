"""W10-4 #476 sibling sweep — `spine_verify.verify_offense_ledger` must not be a weaker back door.

`vigil verify` (the per-segment offense verifier) audited the usage ledger with the same
`read_ledger → verify_ledger(no pin)` pattern the CLI had, so a present-but-TRUNCATED ledger verified clean
here too — a weaker back door than `vigil verify-ledger`. It now consults the same durable OUT-OF-BASE
head/count pin:

  * present ledger + matching pin → VERIFIED;
  * present ledger + pin, tail dropped → FAILED (truncation caught);
  * present ledger + NO pin → VERIFIED, reported UNPINNED (no false truncation-protection claim);
  * ABSENT ledger + NO pin → ABSENT (the honest never-ran state `vigil verify` legitimately reports);
  * ABSENT ledger + a pin exists → FAILED (the ledger was written and is now GONE — a wipe).

Fail-before / pass-after is provable by reverting the spine_verify hunk: the truncated ledger reports
VERIFIED again.
"""

from __future__ import annotations

from pathlib import Path

from vigil_integration.attestation import (
    MonotonicAnchor,
    OperatorIdentity,
    fingerprint,
    load_or_create_operator_keypair,
    make_ledger_writer,
    operator_signer,
    read_ledger,
    record_usage,
)
from vigil_integration.attestation import anchor as _anchor
from vigil_integration.attestation import head_pin as _head_pin
from vigil_integration.live.spine_verify import (
    ABSENT,
    FAILED,
    VERIFIED,
    verify_offense_ledger,
)


def _seed(base: Path, n: int):
    kp = load_or_create_operator_keypair(path=str(base / "operator.key"))
    op = OperatorIdentity(
        os_login="kali", git_name="Op", git_email="op@example.test",
        key_fingerprint=fingerprint(kp.public_key_b64), hostname="kali",
    )
    ledger = base / "usage-ledger.jsonl"
    signer = operator_signer(keypair=kp)
    writer = make_ledger_writer(str(ledger))
    prev = "0" * 64
    for i in range(n):
        att = record_usage(
            operator=op, action="nmap 127.0.0.1", target="http://127.0.0.1/",
            phase="informational", at=f"2026-07-21T00:0{i}:00Z", prev_hash=prev, signer=signer,
            seq=i, anchor=MonotonicAnchor(value=10 * (i + 1), grounded="software"),
        )
        assert att is not None
        writer(att)
        prev = att.record_hash
    return ledger


def test_present_ledger_with_matching_pin_verifies(tmp_path, monkeypatch):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "live"
    base.mkdir()
    ledger = _seed(base, 3)
    recs = read_ledger(ledger)
    _head_pin.write_head_pin(ledger, head=recs[-1].record_hash, count=len(recs))

    v = verify_offense_ledger(str(base))
    assert v.status == VERIFIED and "pinned head+count" in v.detail


def test_truncated_present_ledger_fails_closed_against_the_pin(tmp_path, monkeypatch):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "live"
    base.mkdir()
    ledger = _seed(base, 3)
    recs = read_ledger(ledger)
    _head_pin.write_head_pin(ledger, head=recs[-1].record_hash, count=len(recs))   # pin at 3

    lines = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")               # drop the tail
    assert len(read_ledger(ledger)) == 2

    v = verify_offense_ledger(str(base))
    assert v.status == FAILED and ("truncated" in v.detail or "dropped" in v.detail)


def test_present_ledger_without_pin_verifies_but_reports_unpinned(tmp_path, monkeypatch):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "live"
    base.mkdir()
    _seed(base, 2)                                                                  # no pin persisted
    v = verify_offense_ledger(str(base))
    assert v.status == VERIFIED and "UNPINNED" in v.detail


def test_absent_ledger_without_pin_is_absent_not_failed(tmp_path, monkeypatch):
    # the honest never-ran state — `vigil verify` over a base that never wrote a ledger must NOT fail.
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "live"
    base.mkdir()
    v = verify_offense_ledger(str(base))
    assert v.status == ABSENT


def test_absent_ledger_with_a_surviving_pin_fails_closed_as_a_wipe(tmp_path, monkeypatch):
    # ran-then-wiped: the pin survived `rm -rf <base>` but the ledger is gone → a wipe, not never-ran.
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "live"
    base.mkdir()
    ledger = _seed(base, 2)
    recs = read_ledger(ledger)
    _head_pin.write_head_pin(ledger, head=recs[-1].record_hash, count=len(recs))

    import shutil
    shutil.rmtree(base)                                                            # wipe the base dir
    base.mkdir()                                                                   # recreate empty (ledger gone)

    v = verify_offense_ledger(str(base))
    assert v.status == FAILED and "wipe detected" in v.detail
