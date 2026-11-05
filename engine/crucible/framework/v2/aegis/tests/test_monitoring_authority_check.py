"""AEGIS-SaaS AE-2 — the keyless per-request monitoring-authority check (verify-only, holds no key).

Pins: authentic in-window grant → ok with its signed mode; tampered org/host/mode/window → refused; a non-owner
signer → refused; a trust root embedded alongside the artifact is never used (only the pinned owner root);
window edges are half-open; a file for another (org, host) never matches; missing dir/file, malformed, oversized,
symlinked or non-regular files and an absent/unreadable owner root are fail-closed without raising; crafted
hosts cannot escape the directory; the check needs no private key; and the file-naming rule stays byte-identical
to the sovereign publisher's (lockstep).
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.monitoring_authority import MonitoringAuthority, MonitoringMode, sign_monitoring_authority

import framework.v2.aegis.monitoring_authority_check as M

OWNER = generate_keypair()
ATTACKER = generate_keypair()
ROOT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                         public_key_b64=OWNER.public_key_b64)])
NB, NA = 1000.0, 2000.0


def _ts(x):
    return datetime.fromtimestamp(x, tz=timezone.utc)


def _signed(org="org_a", host="apme.cm", mode="observe", nb=NB, na=NA, key=OWNER):
    doc = MonitoringAuthority(org_id=org, host=host, mode=MonitoringMode(mode),
                              not_before=_ts(nb), not_after=_ts(na), issued_by="owner")
    return sign_monitoring_authority(doc, {"owner": key.private_key_b64})


def _publish(d: Path, signed, *, org=None, host=None):
    org = org or signed.document.org_id
    host = host or signed.document.host
    d.mkdir(parents=True, exist_ok=True)
    p = d / M.monitoring_filename(org, host)
    p.write_bytes(signed.model_dump_json().encode("utf-8"))
    return p


@pytest.fixture
def pinned(monkeypatch):
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: ROOT)


def _check(d, org="org_a", host="apme.cm", now=1500.0):
    return M.check_monitoring_authority(org, host, publish_dir=d, now=now)


# ---- positive ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["observe", "block"])
def test_authentic_in_window_grant_is_authorized_with_its_mode(tmp_path, pinned, mode):
    _publish(tmp_path, _signed(mode=mode))
    r = _check(tmp_path)
    assert r.ok and r.mode == mode, r


def test_request_host_is_normalized_but_must_match_exactly(tmp_path, pinned):
    _publish(tmp_path, _signed())
    assert _check(tmp_path, host="APME.cm:443").ok
    assert _check(tmp_path, host="apme.cm.").ok
    assert not _check(tmp_path, host="www.apme.cm").ok                      # no subdomain inheritance


# ---- binding + signature ----------------------------------------------------------------------------
def test_wrong_tenant_or_host_never_matches(tmp_path, pinned):
    _publish(tmp_path, _signed())
    assert not _check(tmp_path, org="org_b").ok
    assert not _check(tmp_path, host="other.cm").ok


def test_artifact_swapped_into_another_pairs_slot_is_refused(tmp_path, pinned):
    # org_a's genuine grant copied into org_b's file slot: the signed document still names org_a.
    _publish(tmp_path, _signed(org="org_a"), org="org_b")
    r = _check(tmp_path, org="org_b")
    assert not r.ok and "different tenant" in r.reason
    _publish(tmp_path, _signed(host="apme.cm"), host="evil.cm")
    r = _check(tmp_path, host="evil.cm")
    assert not r.ok and "different host" in r.reason


@pytest.mark.parametrize("field,value", [("org_id", "org_b"), ("host", "evil.cm"), ("mode", "block"),
                                         ("not_after", "2999-01-01T00:00:00Z")])
def test_tampered_document_fails_signature(tmp_path, pinned, field, value):
    p = _publish(tmp_path, _signed(mode="observe"))
    data = json.loads(p.read_text())
    data["document"][field] = value
    org = data["document"]["org_id"]
    host = data["document"]["host"]
    (tmp_path / M.monitoring_filename(org, host)).write_text(json.dumps(data))
    r = _check(tmp_path, org=org, host=host)
    assert not r.ok and "does not verify" in r.reason, r


def test_non_owner_signer_refused(tmp_path, pinned):
    _publish(tmp_path, _signed(key=ATTACKER))
    r = _check(tmp_path)
    assert not r.ok and "does not verify" in r.reason


def test_embedded_trust_root_is_never_used(tmp_path, pinned):
    """An attacker-signed artifact that ships its OWN trust root naming the attacker key is still refused:
    only the pinned owner root is consulted (extra fields are rejected by the strict schema anyway)."""
    s = _signed(key=ATTACKER)
    data = json.loads(s.model_dump_json())
    data["trust_root"] = {"threshold": 1, "authorizers": [
        {"key_id": "owner", "name": "owner", "public_key_b64": ATTACKER.public_key_b64}]}
    (tmp_path / M.monitoring_filename("org_a", "apme.cm")).write_text(json.dumps(data))
    assert not _check(tmp_path).ok


# ---- window -----------------------------------------------------------------------------------------
def test_window_is_half_open(tmp_path, pinned):
    _publish(tmp_path, _signed())
    assert not _check(tmp_path, now=NB - 1).ok
    assert _check(tmp_path, now=NB).ok
    assert _check(tmp_path, now=NA - 0.001).ok
    r = _check(tmp_path, now=NA)
    assert not r.ok and "window" in r.reason


# ---- fail-closed --------------------------------------------------------------------------------------
def test_missing_dir_or_file_fail_closed(tmp_path, pinned):
    assert not _check(tmp_path / "nope").ok
    assert not _check(tmp_path).ok


def test_owner_root_absent_or_unreadable_fail_closed(tmp_path, monkeypatch):
    _publish(tmp_path, _signed())
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: None)
    r = _check(tmp_path)
    assert not r.ok and "no owner authority trust root" in r.reason

    def boom():
        raise RuntimeError("corrupt root")
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", boom)
    r = _check(tmp_path)
    assert not r.ok and "unreadable" in r.reason


@pytest.mark.parametrize("blob", [b"", b"not json", b"{}", b'{"document": 1, "signatures": []}', b"\xff\xfe"])
def test_malformed_artifact_fail_closed(tmp_path, pinned, blob):
    (tmp_path / M.monitoring_filename("org_a", "apme.cm")).write_bytes(blob)
    r = _check(tmp_path)
    assert not r.ok and r.mode is None


def test_oversized_symlink_and_non_regular_files_refused(tmp_path, pinned):
    name = M.monitoring_filename("org_a", "apme.cm")
    (tmp_path / name).write_bytes(b" " * (M._MAX_ARTIFACT_BYTES + 1))
    assert not _check(tmp_path).ok
    (tmp_path / name).unlink()
    real = _publish(tmp_path / "elsewhere", _signed())
    os.symlink(real, tmp_path / name)                                           # symlink is not followed
    assert not _check(tmp_path).ok
    (tmp_path / name).unlink()
    os.mkfifo(tmp_path / name)                                                  # a FIFO never blocks the gate
    assert not _check(tmp_path).ok


@pytest.mark.parametrize("bad", ["", " ", "../etc/passwd", "/abs/path", "a/b", "[::1]", "1.2.3.4:80:90",
                                 "x\x00y", "host?q", "h" * 300, None, 123,
                                 "apme.cm:evil", "apme.cm:", "apme.cm:44a"])
def test_crafted_hosts_are_refused_without_touching_the_fs(tmp_path, pinned, bad):
    r = M.check_monitoring_authority("org_a", bad, publish_dir=tmp_path, now=1500.0)
    assert not r.ok and r.reason == "invalid host", r            # refused BEFORE any filesystem lookup


@pytest.mark.parametrize("bad_org", ["", None, "o\nx", "o" * 300])
def test_invalid_tenant_refused(tmp_path, pinned, bad_org):
    r = M.check_monitoring_authority(bad_org, "apme.cm", publish_dir=tmp_path, now=1500.0)
    assert not r.ok and r.reason == "invalid tenant id", r


def test_never_raises_even_on_unexpected_errors(tmp_path, monkeypatch, pinned):
    monkeypatch.setattr(M, "_check", lambda *a, **k: (_ for _ in ()).throw(ValueError("x")))
    r = M.check_monitoring_authority("org_a", "apme.cm", publish_dir=tmp_path, now=1500.0)
    assert not r.ok and "fail-closed" in r.reason


# ---- keyless + FATAL-2 + lockstep ---------------------------------------------------------------------
def test_module_holds_no_key_and_imports_no_sovereign_code():
    src = Path(M.__file__).read_text(encoding="utf-8")
    assert "private_key" not in src and "owner_keypair" not in src and "sign_monitoring_authority" not in src
    assert not re.search(r"^\s*(from|import)\s+sigil\b", src, re.M)
    assert not re.search(r"from\s+\.\.\.+\s*sigil|apps\.sigil", src)


def test_published_dir_contract(monkeypatch, tmp_path):
    monkeypatch.setenv(M.PUBLISH_DIR_ENV, str(tmp_path / "x"))
    assert M.published_dir() == tmp_path / "x"
    monkeypatch.delenv(M.PUBLISH_DIR_ENV)
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    assert M.published_dir() == tmp_path / "base" / "aegis" / "monitoring_authority"


def test_filename_rule_is_byte_identical_to_the_sovereign_publisher():
    """Mirror-drift guard (FATAL-2 forbids importing the sovereign module here): the hashing expression in BOTH
    functions must be identical, so the gateway always reads the file the provisioner wrote."""
    repo = Path(M.__file__).resolve().parents[5]
    sov = (repo / "apps/sigil/sigil/governor/monitoring_authority.py").read_text(encoding="utf-8")
    eng = Path(M.__file__).read_text(encoding="utf-8")
    pat = re.compile(r'hashlib\.sha256\(f"\{org_id\}\\x00\{host\}"\.encode\("utf-8"\)\)\.hexdigest\(\) \+ "\.json"')
    assert pat.search(sov), "sovereign monitoring_filename changed — update the gateway mirror in lockstep"
    assert pat.search(eng), "gateway monitoring_filename drifted from the sovereign publisher"


def test_reader_refuses_non_regular_and_oversized_files_directly(tmp_path):
    """The reader's own guard (not merely the downstream parse failure): a FIFO / directory / oversized file
    yields None, never bytes."""
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert M._read_regular_file(fifo) is None
    assert M._read_regular_file(tmp_path) is None
    big = tmp_path / "big"
    big.write_bytes(b"x" * (M._MAX_ARTIFACT_BYTES + 1))
    assert M._read_regular_file(big) is None
    ok = tmp_path / "ok"
    ok.write_bytes(b"{}")
    assert M._read_regular_file(ok) == b"{}"
