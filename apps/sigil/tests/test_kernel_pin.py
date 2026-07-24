"""G2 slice-1 — owner-signed WARDEN kernel-binary integrity pin.

The kernel binary IS the A0–A3 tier oracle; these tests prove the pin is fail-closed (a swapped binary
or forged manifest → the kernel is NEVER executed → the classifier resolves to A3, dispatch fails LOUD)
AND non-bricking (no manifest → today's behaviour, byte-identical). The owner key is injected the same
way the governor tests inject it — via a generated keypair whose public half is the trust anchor.
"""
from __future__ import annotations

import pytest

from sigil import config
from sigil.agents.base import Tier
from sigil.agents.kernel_classify import KernelClassifier
from sigil.governor import integrity
from sigil.reuse import generate_keypair
from sigil.voice.dispatch import _NO_KERNEL_MSG, _PIN_FAIL_MSG, KernelDispatch

OWNER = generate_keypair()


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Isolate SIGIL_HOME (→ manifest path) and pin the trust anchor to OWNER, resetting the
    once-per-process unpinned-warning latch so each test starts clean."""
    monkeypatch.setattr(config, "SIGIL_HOME", tmp_path)
    monkeypatch.setattr(integrity, "owner_pubkey", lambda: OWNER.public_key_b64)
    monkeypatch.setattr(integrity, "_warned_unpinned", False, raising=False)
    return tmp_path


def _make_bin(path, content: bytes) -> str:
    path.write_bytes(content)
    return str(path)


def _forbid_subprocess(monkeypatch):
    """Make any subprocess.run a hard failure, so a test that asserts A3 proves the binary was NEVER
    executed (not merely that an exec failed to a fail-closed A3)."""
    import subprocess

    def _boom(*a, **k):
        raise AssertionError("subprocess.run must NOT be reached — the kernel binary was executed")

    monkeypatch.setattr(subprocess, "run", _boom)


def _pin(home, kernel_path, *, owner=OWNER, scope="sigil", owner_key_id="owner"):
    m = integrity.build_manifest(kernel_path, owner, scope=scope, owner_key_id=owner_key_id)
    integrity.write_manifest(m)
    return m


# --- primitives ------------------------------------------------------------------------------------

def test_sha256_file_streams_and_missing(tmp_path):
    import hashlib
    f = tmp_path / "b"
    f.write_bytes(b"kernel-bytes" * 10000)          # multi-chunk
    assert integrity.sha256_file(f) == hashlib.sha256(b"kernel-bytes" * 10000).hexdigest()
    assert integrity.sha256_file(tmp_path / "nope") is None


# --- non-bricking ----------------------------------------------------------------------------------

def test_unpinned_is_nonbricking(home, tmp_path):
    kb = _make_bin(tmp_path / "sigil-kernel", b"real")
    v = integrity.verify_kernel_bin(kb)
    assert v.ok is True and v.status == "unpinned"


def test_resolved_none_is_ok_when_pinned(home, tmp_path):
    kb = _make_bin(tmp_path / "sigil-kernel", b"real")
    _pin(home, kb)
    v = integrity.verify_kernel_bin(None)            # nothing to run → not a mismatch
    assert v.ok is True and v.status == "unresolved"


# --- happy path ------------------------------------------------------------------------------------

def test_pin_roundtrip_verifies(home, tmp_path):
    kb = _make_bin(tmp_path / "sigil-kernel", b"real-kernel-content")
    m = _pin(home, kb)
    loaded = integrity.load_manifest()
    assert loaded == m and integrity._manifest_authentic(loaded) is True
    v = integrity.verify_kernel_bin(kb)
    assert v.ok is True and v.status == "verified"


# --- fail-closed -----------------------------------------------------------------------------------

def test_swapped_binary_fails_closed(home, tmp_path):
    good = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, good)
    evil = _make_bin(tmp_path / "evil", b"attacker-planted")   # different content
    v = integrity.verify_kernel_bin(evil)
    assert v.ok is False and v.status == "mismatch"


def test_forged_manifest_core_tamper_fails_closed(home, tmp_path):
    kb = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, kb)
    # tamper the signed field on disk — the signature no longer covers it
    p = integrity.manifest_path()
    import json
    obj = json.loads(p.read_text())
    obj["kernel_sha256"] = "0" * 64
    p.write_text(json.dumps(obj))
    v = integrity.verify_kernel_bin(kb)
    assert v.ok is False and v.status == "forged"


def test_manifest_signed_by_wrong_key_fails_closed(home, tmp_path):
    kb = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, kb, owner=generate_keypair())          # signed by an IMPOSTER, not the trust anchor
    v = integrity.verify_kernel_bin(kb)
    assert v.ok is False and v.status == "forged"


def test_manifest_present_but_no_owner_key_fails_closed(home, tmp_path, monkeypatch):
    kb = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, kb)
    monkeypatch.setattr(integrity, "owner_pubkey", lambda: None)   # owner.pub deleted, manifest remains
    v = integrity.verify_kernel_bin(kb)
    assert v.ok is False and v.status == "forged"


def test_truncated_manifest_fails_closed(home, tmp_path):
    # BLOCK-2 regression: a present-but-corrupt manifest (`> file` / truncate) must NOT downgrade to
    # 'unpinned' (fail-open). A truly-absent manifest is the only 'unpinned' case.
    kb = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, kb)
    integrity.manifest_path().write_text("")                      # 0-byte truncate — present but corrupt
    v = integrity.verify_kernel_bin(kb)
    assert v.ok is False and v.status == "corrupt"
    assert integrity.kernel_pin_status()[0] == "!!"               # doctor flags tamper, not '**' advisory
    assert integrity.config_drift() == ["security manifest is present but corrupt/unreadable (possible tamper)"]


def test_non_object_manifest_fails_closed(home, tmp_path):
    kb = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, kb)
    integrity.manifest_path().write_text("[]")                    # valid JSON, but not an object
    v = integrity.verify_kernel_bin(kb)
    assert v.ok is False and v.status == "corrupt"


# --- classifier / dispatch wiring ------------------------------------------------------------------

def test_classifier_blocks_on_mismatch_without_executing(home, tmp_path, monkeypatch):
    good = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, good)
    evil = _make_bin(tmp_path / "evil-kernel", b"attacker")
    monkeypatch.setenv("SIGIL_KERNEL_BIN", evil)      # env-injected swap (the real attack vector)
    _forbid_subprocess(monkeypatch)                   # prove the (attacker) binary is NEVER exec'd
    c = KernelClassifier()
    assert c._pin_blocked is True
    # even a normally-A0 read verb resolves to A3 — reached WITHOUT any subprocess
    assert c.classify("http.get") is Tier.A3


def test_classifier_unresolved_never_execs_bare_name(home, tmp_path, monkeypatch):
    # BLOCK-1 regression: when config.kernel_bin() is None at construction, the classifier must keep
    # None (not a bare 'sigil-kernel' PATH name) and fail-closed to A3 — so an attacker who plants a
    # `sigil-kernel` on PATH after construction can never have it exec'd at classify time.
    good = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, good)
    monkeypatch.setattr("sigil.agents.kernel_classify._resolve_kernel_bin", lambda: None)
    _forbid_subprocess(monkeypatch)
    c = KernelClassifier()
    assert c.kernel_bin is None                       # NOT the bare exe name
    assert c.classify("fs.delete_recursive") is Tier.A3


def test_classifier_not_pin_blocked_when_verified(home, tmp_path, monkeypatch):
    good = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, good)
    monkeypatch.setenv("SIGIL_KERNEL_BIN", good)
    c = KernelClassifier()
    assert c._pin_blocked is False                    # pin passes; (a fake bin still fails-closed at exec)


def test_explicit_bin_bypasses_pin(home, tmp_path, monkeypatch):
    good = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, good)
    monkeypatch.setenv("SIGIL_KERNEL_BIN", _make_bin(tmp_path / "evil", b"x"))
    c = KernelClassifier(kernel_bin="/trusted/explicit/path")   # trusted injection, not the env path
    assert c._pin_blocked is False


def test_dispatch_blocks_on_mismatch(home, tmp_path, monkeypatch):
    good = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, good)
    monkeypatch.setenv("SIGIL_KERNEL_BIN", _make_bin(tmp_path / "evil", b"attacker"))
    d = KernelDispatch()
    assert d._pin_blocked is True
    assert d.send("what time is it") == _PIN_FAIL_MSG


def test_dispatch_empty_string_never_execs_unverified_env_binary(home, tmp_path, monkeypatch):
    # symmetry with the classifier: an explicit '' must NOT fall back to the (attacker) env path unverified.
    good = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, good)
    monkeypatch.setenv("SIGIL_KERNEL_BIN", _make_bin(tmp_path / "evil", b"attacker-controlled"))
    _forbid_subprocess(monkeypatch)
    d = KernelDispatch(kernel_bin="")                          # '' honoured as-is → send() fails LOUD
    assert d.send("x") in (_PIN_FAIL_MSG, _NO_KERNEL_MSG)      # never execs the unverified env binary


# --- advisory config drift -------------------------------------------------------------------------

def test_config_drift_scope_change_is_advisory(home, tmp_path, monkeypatch):
    kb = _make_bin(tmp_path / "sigil-kernel", b"good")
    _pin(home, kb, scope="sigil", owner_key_id="owner")
    assert integrity.config_drift() == []                         # in agreement
    monkeypatch.setattr(config, "SCOPE", "different-scope")
    drift = integrity.config_drift()
    assert len(drift) == 1 and "SCOPE changed" in drift[0]
    # drift is advisory only — it does NOT fail the kernel verdict
    assert integrity.verify_kernel_bin(kb).ok is True
