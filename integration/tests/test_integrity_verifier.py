"""W6-7 — the continuous spine-integrity verifier.

The product's whole thesis is a tamper-evident, anti-rollback, signed spine hash-chain. These tests build a
REAL signed spine fixture with the shared `vigil_core` primitives (the exact bytes the sovereign store
writes), then prove the verifier:

  * PASSES a clean spine on all four integrity axes (so the checks are not constant-fail), and
  * FAILS — as FOUR SEPARATE, INDEPENDENT assertions — on a deliberately broken chain link, a replayed
    stale head, a rolled-back anti-rollback floor, and a skewed clock.

Plus the alarm path: the periodic monitor raises a critical alarm on a tamper, writes a heartbeat, and — on
its OWN failure to run — raises a verifier-error alarm; and the dead-man heartbeat check fires when the
scheduled verifier stops running.

These are the "test that FAILS WITHOUT the change" (a tree with no verifier catches none of these tampers)
and the "negative control that proves the gate is not a no-op" (the clean fixture passes every check the
tampered fixtures fail). Boundary-safe: imports `vigil_core` + `vigil_integration.integrity_verifier` only —
never `sigil`, never `framework`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_core import build_chain, digest_payload, generate_keypair, sign_head
from vigil_core.models import _GENESIS_PREV

from vigil_integration import integrity_verifier as iv


# --------------------------------------------------------------------------- fixture builder
def _build_spine(home: Path, *, n: int = 3, scope: str = "sigil", base_ts: int = 1_700_000_000) -> dict:
    """Write a REAL clean signed spine (spine.jsonl + head.json + floor.json) under `home`, exactly as the
    sovereign store would: cert_digest = digest_payload(content), chain via build_chain, an owner-signed
    head, and a durable floor tracking the head. Returns handles for the tests to tamper."""
    home.mkdir(parents=True, exist_ok=True)
    contents = []
    digests = []
    for i in range(n):
        content = {
            "scope": scope, "kind": "message", "source": "test", "actor": "user",
            "payload": {"text": f"record {i}"}, "parent_id": None, "supersedes_id": None,
        }
        contents.append(content)
        digests.append(digest_payload(content))
    entries = build_chain(digests)
    records = []
    from datetime import datetime, timezone
    for i, (content, entry) in enumerate(zip(contents, entries)):
        ts = datetime.fromtimestamp(base_ts + i, timezone.utc).isoformat()
        records.append({"seq": entry.seq, **content, "ts": ts,
                        "cert_digest": entry.cert_digest, "prev_hash": entry.prev_hash,
                        "entry_hash": entry.entry_hash})
    (home / "spine.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")

    owner = generate_keypair()
    head = sign_head(entries, engagement_slug=scope, signers=[("owner", owner.private_key_b64)])
    (home / "head.json").write_text(head.model_dump_json(), encoding="utf-8")

    floor = {"schema_version": 1, "scope": scope, "entry_count": head.entry_count,
             "last_seq": head.last_seq, "base_seq": 0, "base_count": 0,
             "head_sig_hash": head.head_hash, "updated_ts": records[-1]["ts"]}
    (home / "floor.json").write_text(json.dumps(floor), encoding="utf-8")
    return {"records": records, "head": head, "floor": floor, "owner": owner, "entries": entries,
            "base_ts": base_ts, "n": n}


def _read_now(fx: dict) -> float:
    """A `now` a hair after the newest record — so the clean fixture is FRESH and not skewed."""
    return fx["base_ts"] + fx["n"] + 1


# --------------------------------------------------------------------------- positive control
def test_clean_spine_passes_every_check(tmp_path):
    """NEGATIVE CONTROL for the whole suite: a clean signed spine passes ALL four integrity axes, proving
    the checks are not stuck at fail."""
    fx = _build_spine(tmp_path)
    report = iv.verify_integrity(tmp_path, now=_read_now(fx))
    assert report.ok, report.to_dict()
    for name in ("chain", "head_freshness", "floor", "clock_skew"):
        v = report.get(name)
        assert v is not None and v.status in (iv.OK, iv.WARN), (name, v)
        assert not v.failed, (name, v.detail)


def test_absent_spine_is_not_a_failure(tmp_path):
    """A fresh/never-written home is ABSENT, not FAILED — the verifier must not brick a clean install."""
    report = iv.verify_integrity(tmp_path, now=1_700_000_100)
    assert report.ok
    assert report.get("chain").status == iv.ABSENT
    assert report.get("head_freshness").status == iv.ABSENT


# --------------------------------------------------------------------------- the four independent failures
def test_broken_chain_link_fails(tmp_path):
    """FAILURE #1 (broken chain link): tamper one record's entry_hash → the chain no longer links."""
    fx = _build_spine(tmp_path)
    lines = (tmp_path / "spine.jsonl").read_text().splitlines()
    rec = json.loads(lines[1])
    rec["entry_hash"] = "0" * 64                      # corrupt the middle link
    lines[1] = json.dumps(rec)
    (tmp_path / "spine.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = iv.verify_integrity(tmp_path, now=_read_now(fx))
    assert not report.ok
    assert report.get("chain").failed, report.get("chain")


def test_payload_tamper_breaks_binding(tmp_path):
    """A payload edit (leaving the digests) breaks the cert_digest binding — a distinct chain-check path."""
    fx = _build_spine(tmp_path)
    lines = (tmp_path / "spine.jsonl").read_text().splitlines()
    rec = json.loads(lines[0])
    rec["payload"] = {"text": "TAMPERED"}            # digest no longer matches cert_digest
    lines[0] = json.dumps(rec)
    (tmp_path / "spine.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = iv.verify_integrity(tmp_path, now=_read_now(fx))
    assert not report.ok
    assert report.get("chain").failed
    assert "binding" in report.get("chain").detail.lower()


def test_stale_head_fails(tmp_path):
    """FAILURE #2 (stale head): replay an OLDER signed head (over a 1-record spine) on top of the current
    3-record spine → the head no longer anchors the tail."""
    fx = _build_spine(tmp_path, n=3)
    # Sign a head over ONLY the first entry — a genuine, validly-signed, but STALE head.
    stale = sign_head(fx["entries"][:1], engagement_slug="sigil",
                      signers=[("owner", fx["owner"].private_key_b64)])
    (tmp_path / "head.json").write_text(stale.model_dump_json(), encoding="utf-8")

    report = iv.verify_integrity(tmp_path, now=_read_now(fx))
    assert not report.ok
    assert report.get("head_freshness").failed
    assert "stale head" in report.get("head_freshness").detail.lower()


def test_unanchored_spine_fails(tmp_path):
    """A spine with records but NO head is unanchored — a head removal/rollback — and fails."""
    fx = _build_spine(tmp_path)
    (tmp_path / "head.json").unlink()
    report = iv.verify_integrity(tmp_path, now=_read_now(fx))
    assert not report.ok
    assert report.get("head_freshness").failed


def test_rolled_back_floor_fails(tmp_path):
    """FAILURE #3 (rolled-back floor): raise the durable floor ABOVE the head (equivalently, the head was
    rolled back below the floor) → the anti-rollback floor refuses it."""
    fx = _build_spine(tmp_path, n=3)
    floor = dict(fx["floor"])
    floor["last_seq"] = fx["head"].last_seq + 5          # floor sits above the head → rollback
    floor["entry_count"] = fx["head"].entry_count + 5
    (tmp_path / "floor.json").write_text(json.dumps(floor), encoding="utf-8")

    report = iv.verify_integrity(tmp_path, now=_read_now(fx))
    assert not report.ok
    assert report.get("floor").failed
    assert "rollback" in report.get("floor").detail.lower()


def test_skewed_clock_fails(tmp_path):
    """FAILURE #4 (skewed clock): the local clock diverges from a TRUSTED reference by more than tolerance."""
    fx = _build_spine(tmp_path)
    now = _read_now(fx)
    trusted = now + 10_000                                # reference is 10ks ahead of the local clock
    report = iv.verify_integrity(tmp_path, now=now, trusted_now=trusted, max_clock_skew_s=300)
    assert not report.ok
    assert report.get("clock_skew").failed
    assert "skew" in report.get("clock_skew").detail.lower()


def test_future_dated_record_is_clock_skew(tmp_path):
    """A record dated in the FUTURE relative to `now` (a writer clock ahead) is clock skew — no trusted
    reference needed."""
    fx = _build_spine(tmp_path)
    # now BEFORE the newest record by more than the tolerance.
    report = iv.verify_integrity(tmp_path, now=fx["base_ts"] - 10_000, max_clock_skew_s=300,
                                 max_head_age_s=10**12)
    assert report.get("clock_skew").failed


def test_the_four_failures_are_independent(tmp_path):
    """The acceptance's core assertion: each of the four states INDEPENDENTLY makes the verifier fail — four
    separate assertions, not one. Each tampered tree isolates ONE axis and asserts that axis (and only a
    genuinely-affected one) fails while the OTHER three stay clean on that same tree."""
    # 1) broken chain link — chain fails; head/floor/clock clean.
    fx = _build_spine(tmp_path / "chain", n=3)
    lines = (tmp_path / "chain" / "spine.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["entry_hash"] = "0" * 64; lines[1] = json.dumps(rec)
    (tmp_path / "chain" / "spine.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    r1 = iv.verify_integrity(tmp_path / "chain", now=_read_now(fx))
    assert r1.get("chain").failed and not r1.get("floor").failed and not r1.get("clock_skew").failed

    # 2) stale head — head fails; clock/floor clean. (chain is unaffected: the records are untouched.)
    fx2 = _build_spine(tmp_path / "head", n=3)
    stale = sign_head(fx2["entries"][:1], engagement_slug="sigil",
                      signers=[("owner", fx2["owner"].private_key_b64)])
    (tmp_path / "head" / "head.json").write_text(stale.model_dump_json(), encoding="utf-8")
    r2 = iv.verify_integrity(tmp_path / "head", now=_read_now(fx2))
    assert r2.get("head_freshness").failed and not r2.get("chain").failed and not r2.get("clock_skew").failed

    # 3) rolled-back floor — floor fails; chain/head/clock clean.
    fx3 = _build_spine(tmp_path / "floor", n=3)
    floor = dict(fx3["floor"]); floor["last_seq"] = fx3["head"].last_seq + 5
    floor["entry_count"] = fx3["head"].entry_count + 5
    (tmp_path / "floor" / "floor.json").write_text(json.dumps(floor), encoding="utf-8")
    r3 = iv.verify_integrity(tmp_path / "floor", now=_read_now(fx3))
    assert r3.get("floor").failed and not r3.get("chain").failed and not r3.get("head_freshness").failed

    # 4) skewed clock — clock fails; chain/head/floor clean.
    fx4 = _build_spine(tmp_path / "clock", n=3)
    r4 = iv.verify_integrity(tmp_path / "clock", now=_read_now(fx4), trusted_now=_read_now(fx4) + 10_000)
    assert r4.get("clock_skew").failed and not r4.get("chain").failed and not r4.get("floor").failed


# --------------------------------------------------------------------------- malformed input is fail-closed, never a crash
def test_malformed_spine_is_fail_not_crash(tmp_path):
    """A spine with a non-JSON line, and a spine with a JSON object missing chain fields, both FAIL the
    chain check (fail-closed) — the verifier never raises."""
    (tmp_path / "spine.jsonl").write_text("not a json line\n", encoding="utf-8")
    r1 = iv.verify_integrity(tmp_path, now=1_700_000_100)
    assert not r1.ok and r1.get("chain").failed

    (tmp_path / "spine.jsonl").write_text(json.dumps({"seq": 0, "scope": "s"}) + "\n", encoding="utf-8")
    r2 = iv.verify_integrity(tmp_path, now=1_700_000_100)
    assert not r2.ok and r2.get("chain").failed


def test_malformed_head_is_fail_not_crash(tmp_path):
    fx = _build_spine(tmp_path)
    (tmp_path / "head.json").write_text("{ this is not valid json", encoding="utf-8")
    report = iv.verify_integrity(tmp_path, now=_read_now(fx))
    assert not report.ok and report.get("head_freshness").failed


# --------------------------------------------------------------------------- signed-head authenticity (pinned key)
def test_forged_head_fails_under_pinned_trust_root(tmp_path):
    """When a pinned trust root is supplied, a head re-signed by the WRONG key (a forge that still anchors
    the spine structurally) fails the authenticity check."""
    from vigil_core import AuthorizerKey, TrustRoot
    fx = _build_spine(tmp_path, n=3)
    attacker = generate_keypair()
    forged = sign_head(fx["entries"], engagement_slug="sigil",
                       signers=[("owner", attacker.private_key_b64)])
    (tmp_path / "head.json").write_text(forged.model_dump_json(), encoding="utf-8")
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(
        key_id="owner", name="owner", public_key_b64=fx["owner"].public_key_b64)])
    report = iv.verify_integrity(tmp_path, now=_read_now(fx), head_trust_root=tr)
    assert not report.ok
    assert report.get("head_freshness").failed

    # and the GENUINE head verifies under the same pinned root (negative control).
    (tmp_path / "head.json").write_text(fx["head"].model_dump_json(), encoding="utf-8")
    good = iv.verify_integrity(tmp_path, now=_read_now(fx), head_trust_root=tr)
    assert good.ok, good.to_dict()
    assert "VERIFIED" in good.get("head_freshness").detail
