"""W0-5 — `vigil ledger when` must render software vs hardware provenance distinctly.

The render truthiness-tested a STRING sentinel (``grounded`` is "tpm" | "software"; both non-empty ⇒
truthy), so it printed "TPM-anchored" for EVERY record — manufacturing hardware provenance for pure
software-counter entries, and leaving the "software-chain" branch dead. A software record must render
"software-chain"; only a genuine ``grounded == "tpm"`` record renders "TPM-anchored".

This exercises the exact buggy CLI path (`_cmd_ledger`), which was untested — the absence of coverage is
why the bug survived. Fail-before / pass-after is provable by reverting the render line in cli.py.
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
from vigil_integration.cli import _cmd_ledger


def _provision(base_dir: Path):
    """Persist the operator keypair under ``base_dir/operator.key`` (what `_load_and_verify_ledger`'s
    resolver re-loads) and return (keypair, bound identity)."""
    kp = load_or_create_operator_keypair(path=str(base_dir / "operator.key"))
    op = OperatorIdentity(
        os_login="kali", git_name="Op", git_email="op@example.test",
        key_fingerprint=fingerprint(kp.public_key_b64), hostname="kali",
    )
    return kp, op


def _write_records(kp, op, ledger_path: Path, groundings) -> None:
    """Mint + durably append a signed chain to ``ledger_path``, one record per grounding value."""
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


def test_ledger_when_renders_software_and_tpm_distinctly(tmp_path, capsys) -> None:
    base = tmp_path / "base"
    base.mkdir()
    kp, op = _provision(base)
    ledger = tmp_path / "usage-ledger.jsonl"
    _write_records(kp, op, ledger, ["software", "tpm"])  # seq0 software, seq1 tpm

    rc = _cmd_ledger(SimpleNamespace(path=str(ledger), base_dir=str(base), which="when"))
    assert rc == 0
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip().startswith("seq=")]
    assert len(lines) == 2
    seq0 = next(ln for ln in lines if "seq=0" in ln)
    seq1 = next(ln for ln in lines if "seq=1" in ln)
    # the software-counter record must NOT be dressed as hardware-anchored
    assert "software-chain" in seq0 and "TPM-anchored" not in seq0
    # the genuine tpm record is the only one that renders hardware-anchored
    assert "TPM-anchored" in seq1
