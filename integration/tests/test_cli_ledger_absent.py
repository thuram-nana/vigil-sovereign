"""W10-4 — `vigil verify-ledger` must fail-closed on a DELETED (absent) ledger.

`read_ledger` returns ``[]`` for a MISSING file exactly as for a present-but-empty one, and
`verify_ledger([])` is vacuously ``ok`` — so verify-ledger on a wiped/never-written ledger printed
"0 records — VERIFIED", certifying a destroyed audit trail clean. An ABSENT ledger file must fail-closed
(exit non-zero, not VERIFIED); a present-but-empty ledger (a legitimate fresh state) and a real populated
ledger both still verify.

This exercises the exact buggy CLI path (`_cmd_verify_ledger` → `_load_and_verify_ledger`), which was
untested — the absence of coverage is why the bug survived. Fail-before / pass-after is provable by
reverting the absent-file guard in cli.py.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vigil_integration.attestation import (
    MonotonicAnchor,
    OperatorIdentity,
    fingerprint,
    load_or_create_operator_keypair,
    make_ledger_writer,
    operator_signer,
    record_usage,
)
from vigil_integration.cli import _cmd_verify_ledger


def _provision(base_dir: Path):
    kp = load_or_create_operator_keypair(path=str(base_dir / "operator.key"))
    op = OperatorIdentity(
        os_login="kali", git_name="Op", git_email="op@example.test",
        key_fingerprint=fingerprint(kp.public_key_b64), hostname="kali",
    )
    return kp, op


def _write_records(kp, op, ledger_path: Path, groundings) -> None:
    signer = operator_signer(keypair=kp)
    writer = make_ledger_writer(str(ledger_path))
    prev = "0" * 64
    for i, g in enumerate(groundings):
        att = record_usage(
            operator=op, action="nmap 127.0.0.1", target="http://127.0.0.1/",
            phase="informational", at=f"2026-07-21T00:0{i}:00Z", prev_hash=prev, signer=signer,
            seq=i, anchor=MonotonicAnchor(value=10 * (i + 1), grounded=g),
        )
        assert att is not None
        writer(att)
        prev = att.record_hash


def test_verify_ledger_absent_file_fails_closed(tmp_path, capsys) -> None:
    base = tmp_path / "base"
    base.mkdir()
    _provision(base)  # operator.key present, but NO ledger file was ever written
    missing = tmp_path / "does-not-exist" / "usage-ledger.jsonl"
    assert not missing.exists()

    rc = _cmd_verify_ledger(SimpleNamespace(path=str(missing), base_dir=str(base)))
    out = capsys.readouterr().out
    assert rc != 0                                    # fail-closed exit
    # the verdict token must be FAILED, never the VERIFIED verdict, for a wiped/never-written ledger
    assert out.startswith("ledger: 0 records — FAILED")
    assert "records — VERIFIED" not in out
    assert "ABSENT" in out                            # names the evidence-integrity failure


def test_verify_ledger_populated_still_verifies(tmp_path, capsys) -> None:
    base = tmp_path / "base"
    base.mkdir()
    kp, op = _provision(base)
    ledger = tmp_path / "usage-ledger.jsonl"
    _write_records(kp, op, ledger, ["software", "software", "tpm"])

    rc = _cmd_verify_ledger(SimpleNamespace(path=str(ledger), base_dir=str(base)))
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERIFIED" in out
    assert "3 records" in out


def test_verify_ledger_empty_but_present_still_verifies(tmp_path, capsys) -> None:
    # The absent-vs-empty distinction: a present-but-empty ledger is a legitimate fresh state and must
    # NOT be swept up by the absent-file fail-closed path.
    base = tmp_path / "base"
    base.mkdir()
    _provision(base)
    ledger = tmp_path / "usage-ledger.jsonl"
    ledger.write_text("", encoding="utf-8")  # present, zero records

    rc = _cmd_verify_ledger(SimpleNamespace(path=str(ledger), base_dir=str(base)))
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERIFIED" in out
    assert "0 records" in out
