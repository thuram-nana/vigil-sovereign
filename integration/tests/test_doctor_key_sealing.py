"""`vigil doctor` per-key sealing state (audit W9-2 AC: "doctor reports the sealing state per key").

doctor is the OFFENSE/integration plane: it reports the at-rest sealing of the sovereign trust-root keys by
reading the FIRST BYTES on disk (the AEAD magic) — WITHOUT importing sigil or vigil_core (FATAL-2). This
proves the probe distinguishes SEALED (ciphertext at rest) from PLAINTEXT (the defect W9-2 closes) per key.
"""
from __future__ import annotations

from pathlib import Path

from vigil_integration import doctor

_SEALED_HEADER = b"VSL1\x01" + b"\x00" * 40   # magic + version 1 + a plausible sealed body


def _sigil_home(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.delenv("SIGIL_WARDEN_HOME", raising=False)
    (tmp_path / "spine" / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "warden").mkdir(parents=True, exist_ok=True)
    return tmp_path


def test_file_seal_state_distinguishes_sealed_plaintext_absent(tmp_path):
    sealed = tmp_path / "sealed.key"; sealed.write_bytes(_SEALED_HEADER)
    plain = tmp_path / "plain.key"; plain.write_bytes(b"RAW-32-BYTE-PLAINTEXT-KERNEL-KEY")
    assert doctor._file_seal_state(sealed) == "SEALED"
    assert doctor._file_seal_state(plain) == "PLAINTEXT"
    assert doctor._file_seal_state(tmp_path / "nope.key") == "ABSENT"


def test_posture_key_sealing_all_sealed(tmp_path, monkeypatch):
    home = _sigil_home(tmp_path, monkeypatch)
    (home / "spine" / "keys" / "owner.priv").write_bytes(_SEALED_HEADER)
    (home / "spine" / "keys" / "spine.dek").write_bytes(_SEALED_HEADER)
    (home / "warden" / "warden.key").write_bytes(_SEALED_HEADER)
    state, detail = doctor._posture_key_sealing()
    assert state == "SEALED"
    assert "owner.priv=SEALED" in detail and "spine.dek=SEALED" in detail and "warden.key=SEALED" in detail


def test_posture_key_sealing_flags_a_plaintext_key(tmp_path, monkeypatch):
    home = _sigil_home(tmp_path, monkeypatch)
    (home / "spine" / "keys" / "owner.priv").write_bytes(_SEALED_HEADER)
    (home / "warden" / "warden.key").write_bytes(b"PLAINTEXT-WARDEN-KERNEL-KEY-0600")   # the W9-2 defect
    state, detail = doctor._posture_key_sealing()
    assert state == "PLAINTEXT"
    assert "warden.key=PLAINTEXT" in detail


def test_posture_key_sealing_absent_when_no_keys(tmp_path, monkeypatch):
    _sigil_home(tmp_path, monkeypatch)
    state, _ = doctor._posture_key_sealing()
    assert state == "ABSENT"


def test_key_sealing_is_in_the_doctor_posture_block(tmp_path, monkeypatch):
    home = _sigil_home(tmp_path, monkeypatch)
    (home / "spine" / "keys" / "owner.priv").write_bytes(_SEALED_HEADER)
    posture = doctor._collect_posture(Path.cwd(), {})
    controls = {p["control"] for p in posture}
    assert "key-sealing" in controls


# --- red-pen W9-2 HIGH: an INCOMPLETE key rotation (a crash anchor / journal) must be surfaced --------


def test_posture_flags_incomplete_kek_rotation(tmp_path, monkeypatch):
    home = _sigil_home(tmp_path, monkeypatch)
    (home / "spine" / "keys" / "owner.priv").write_bytes(_SEALED_HEADER)
    (home / "vault").mkdir(parents=True, exist_ok=True)
    (home / "vault" / "kek.tpm.pub.prev").write_bytes(b"old-pub")     # a lingering `.prev` KEK anchor
    (home / "vault" / "kek.tpm.priv.prev").write_bytes(b"old-priv")
    state, detail = doctor._posture_key_sealing()
    assert state == "INCOMPLETE"
    assert "KEK(.prev)" in detail and "sigil key reconcile" in detail


def test_posture_flags_incomplete_dek_rotation(tmp_path, monkeypatch):
    home = _sigil_home(tmp_path, monkeypatch)
    (home / "spine" / "keys" / "owner.priv").write_bytes(_SEALED_HEADER)
    (home / "spine" / "keys" / "spine.dek.prev").write_bytes(_SEALED_HEADER)   # a lingering DEK anchor
    state, detail = doctor._posture_key_sealing()
    assert state == "INCOMPLETE"
    assert "DEK(.prev)" in detail


def test_posture_flags_incomplete_warden_rotation(tmp_path, monkeypatch):
    home = _sigil_home(tmp_path, monkeypatch)
    (home / "warden" / "warden.key").write_bytes(_SEALED_HEADER)
    (home / "warden" / "warden.rotation.pending").write_text("{}", encoding="utf-8")   # a dangling journal
    state, detail = doctor._posture_key_sealing()
    assert state == "INCOMPLETE"
    assert "WARDEN(pending)" in detail
