"""P5b — the sovereign spool watcher: drains the offense→sovereign inert-finding filesystem seam onto the
owner-signed spine, FAIL-CLOSED. The load-bearing invariants (a false-green here would let unverified or
laundered data onto the personal spine):
  * a genuine OWNER-DELEGATED finding/detection is ingested (spine seq) and moved to processed/;
  * a FORGED (non-delegated) signature, an OUT-OF-SCOPE label, malformed JSON, a wrong-kind delegation, and
    a MISSING delegation for a kind are ALL rejected — nothing is appended — and quarantined in rejected/;
  * verification crosses the boundary with vigil_core only (no framework/strix import).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration pytest apps/sigil/tests/test_spool_watcher.py -q
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil.governor.identity import delegate_offense_governance, delegate_offense_spine
from sigil.inbound import SpoolWatcher
from sigil.inbound.finding_receiver import FindingReceiver
from sigil.spine.store import SpineStore
from vigil_core import AuthorizerKey, evidence_signing_bytes, generate_keypair, sign
from vigil_integration.detection.certificate import build_certificate, sign_certificate
from vigil_integration.finding_spool import spool_envelope
from vigil_integration.inert_finding import build_detection_envelope, build_envelope
from vigil_integration.live.spine_identity import SPINE_KEY_ID

OWNER = generate_keypair()
GOV = generate_keypair()
SPINE = generate_keypair()
GOV_AUTH = AuthorizerKey(key_id="root0", name="root0", public_key_b64=GOV.public_key_b64)
SPINE_AUTH = AuthorizerKey(key_id=SPINE_KEY_ID, name=SPINE_KEY_ID, public_key_b64=SPINE.public_key_b64)
NOW = 1000


def _gov_deleg(*, owner=OWNER, scope="acme", not_after=9_999_999_999):
    return delegate_offense_governance(owner, authorizers=[GOV_AUTH], threshold=1,
                                       scope=scope, not_after=not_after)


def _spine_deleg(*, owner=OWNER, scope="*", not_after=9_999_999_999):
    return delegate_offense_spine(owner, authorizers=[SPINE_AUTH], scope=scope, not_after=not_after)


def _finding(*, signer=GOV, slug="acme", ref="sqli-001"):
    cert = {"schema_version": 1, "engagement_slug": slug, "finding_ref": ref,
            "bug_class": "sqli", "oracle_context_digest": "a" * 64, "confidence": 0.9}
    sig = sign(signer.private_key_b64, evidence_signing_bytes(cert))
    return build_envelope(cert, [{"key_id": "root0", "signature_b64": sig}])


def _detection(*, signer=SPINE, key_id=SPINE_KEY_ID):
    cert = build_certificate(oracle="cred.stuffing", signature_kind="per-account-failure-velocity",
                             bug_class="cred.stuffing", severity="high", evidence_kind="auth_log",
                             evidence_lines=["u=a fail"] * 3, summary="stuffing", seq=0)
    signed = sign_certificate(cert, lambda b: sign(signer.private_key_b64, b), key_id=key_id)
    return build_detection_envelope(signed.signing_payload(),
                                    [{"key_id": signed.key_id, "signature_b64": signed.signature}])


@pytest.fixture
def env(tmp_path):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    spool = tmp_path / "spool"
    return store, str(spool)


def _watcher(store, spool, *, scope="acme", gov=None, spine=None):
    return SpoolWatcher(store, spool_dir=spool, owner_pubkey=OWNER.public_key_b64, scope=scope,
                        governance_delegation=gov, spine_delegation=spine, now_fn=lambda: NOW)


def _kinds(store, kind):
    return [r for r in store.iter_records() if r.kind == kind]


# --- happy path ---------------------------------------------------------------

def test_genuine_finding_is_ingested_and_moved_to_processed(env):
    store, spool = env
    p = spool_envelope(spool, _finding())
    r = _watcher(store, spool, gov=_gov_deleg()).drain()
    assert r["ingested"] == 1 and r["rejected"] == 0
    assert len(_kinds(store, "finding")) == 1
    # the claimed file left incoming/ and working/, and exactly one content-hash marker landed in processed/
    assert not p.exists()
    assert list((Path(spool) / "working").glob("*.json")) == []
    assert len(list((Path(spool) / "processed").glob("*.json"))) == 1


def test_genuine_detection_is_ingested(env):
    store, spool = env
    spool_envelope(spool, _detection())
    r = _watcher(store, spool, scope="*", spine=_spine_deleg()).drain()
    assert r["ingested"] == 1
    assert _kinds(store, "detection")[0].payload["oracle"] == "cred.stuffing"


# --- fail-closed: nothing laundered onto the spine ----------------------------

def test_forged_finding_is_quarantined_not_spined(env):
    store, spool = env
    p = spool_envelope(spool, _finding(signer=generate_keypair()))   # attacker key, never delegated
    r = _watcher(store, spool, gov=_gov_deleg()).drain()
    assert r["ingested"] == 0 and r["rejected"] == 1
    assert _kinds(store, "finding") == []
    assert (Path(spool) / "rejected" / p.name).exists()
    assert (Path(spool) / "rejected" / (p.name + ".reason")).read_text().strip()


def test_malformed_json_is_rejected(env):
    store, spool = env
    inc = Path(spool) / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    (inc / "junk.json").write_text("{not json", encoding="utf-8")
    r = _watcher(store, spool, gov=_gov_deleg()).drain()
    assert r["ingested"] == 0 and r["rejected"] == 1 and _kinds(store, "finding") == []


def test_out_of_scope_finding_is_refused(env):
    store, spool = env
    # authentic signature by the delegated key, but the finding's OWN slug is a different engagement
    spool_envelope(spool, _finding(slug="megacorp-PROD-not-authorized"))
    r = _watcher(store, spool, scope="acme", gov=_gov_deleg(scope="acme")).drain()
    assert r["ingested"] == 0 and r["rejected"] == 1 and _kinds(store, "finding") == []


def test_detection_without_a_spine_delegation_is_refused(env):
    store, spool = env
    spool_envelope(spool, _detection())
    # only a governance delegation is configured → a detection has no owner tie → refused, nothing spined
    r = _watcher(store, spool, scope="*", gov=_gov_deleg(scope="*")).drain()
    assert r["ingested"] == 0 and r["rejected"] == 1 and _kinds(store, "detection") == []


def test_finding_without_a_governance_delegation_is_refused(env):
    store, spool = env
    spool_envelope(spool, _finding())
    r = _watcher(store, spool, scope="*", spine=_spine_deleg()).drain()   # only spine deleg present
    assert r["ingested"] == 0 and r["rejected"] == 1 and _kinds(store, "finding") == []


def test_expired_delegation_admits_nothing(env):
    store, spool = env
    spool_envelope(spool, _finding())
    w = SpoolWatcher(store, spool_dir=spool, owner_pubkey=OWNER.public_key_b64, scope="acme",
                     governance_delegation=_gov_deleg(not_after=NOW), now_fn=lambda: NOW + 1)  # expired
    r = w.drain()
    assert r["ingested"] == 0 and r["rejected"] == 1 and _kinds(store, "finding") == []


def test_mislabelled_kind_cannot_flip_the_validation_path(env):
    # an attacker relabels a FINDING as kind="detection" hoping to route it to the (different) spine
    # validator and slip past the governance check. Both delegations are present. The detection validator
    # rejects the finding-shaped body → nothing spined. (And the top-level allowlist rejects a finding
    # carrying "kind" anyway.) Neither path admits a mislabelled envelope.
    store, spool = env
    inc = Path(spool) / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    doctored = json.loads(_finding())
    doctored["kind"] = "detection"                       # lie about the kind to flip routing
    (inc / "evil.json").write_text(json.dumps(doctored), encoding="utf-8")
    r = _watcher(store, spool, scope="*",
                 gov=_gov_deleg(scope="*"), spine=_spine_deleg()).drain()
    assert r["ingested"] == 0 and r["rejected"] == 1
    assert _kinds(store, "finding") == [] and _kinds(store, "detection") == []


def test_non_utf8_file_is_rejected_not_crashing(env):
    # BLOCK-3: a non-UTF-8 .json blob must be quarantined fail-closed — it must NOT raise out of drain()
    # (which would crash the watch() loop and take the sovereign ingest down).
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    w.incoming.mkdir(parents=True, exist_ok=True)
    (w.incoming / "bad.json").write_bytes(b"\xff\xfe\x00\x01 not utf8 \xc3\x28")
    r = w.drain()   # must return, not raise
    assert r["ingested"] == 0 and r["rejected"] == 1 and _kinds(store, "finding") == []
    assert list((Path(spool) / "rejected").glob("*.reason"))   # quarantined with a reason


def test_dedup_keys_on_content_not_filename(env):
    # OBS-2 hardening: the dedup identity is the sha256 of the READ BYTES, not the producer's filename. A
    # producer cannot suppress a genuine finding by naming a DIFFERENT body after an already-processed file.
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    inc = w.incoming
    inc.mkdir(parents=True, exist_ok=True)
    (inc / "aaaa.json").write_text(_finding(ref="sqli-001"), encoding="utf-8")
    w.drain()                                              # first finding ingested
    # a DIFFERENT finding body, deliberately named to collide with the first file's name
    (inc / "aaaa.json").write_text(_finding(ref="sqli-999"), encoding="utf-8")
    r = w.drain()
    assert r["ingested"] == 1 and r["deduped"] == 0        # NOT suppressed — different content ingested
    refs = {rec.payload["finding_ref"] for rec in _kinds(store, "finding")}
    assert refs == {"sqli-001", "sqli-999"}


def test_owner_pubkey_required():
    with pytest.raises(ValueError):
        SpoolWatcher(SpineStore(tempfile.mktemp(suffix=".jsonl")),
                     spool_dir=tempfile.mkdtemp(), owner_pubkey="")


# --- boundary -----------------------------------------------------------------

def test_watcher_imports_no_offense_engine():
    import sys
    import sigil.inbound.spool_watcher  # noqa: F401
    leaked = [m for m in sys.modules if m.split(".")[0] in ("framework", "strix")]
    assert leaked == [], f"the sovereign watcher must import no offense engine: {leaked}"


def test_drain_twice_same_state_no_double_ingest(env):
    store, spool = env
    spool_envelope(spool, _finding())
    w = _watcher(store, spool, gov=_gov_deleg())
    w.drain()
    r2 = w.drain()   # incoming is now empty (claimed → processed) → a second drain ingests nothing
    assert r2["ingested"] == 0 and len(_kinds(store, "finding")) == 1


def test_lifecycle_respool_is_deduped_not_reingested(env):
    # BLOCK-2b: after a finding is ingested + archived, an offense worker re-emits the IDENTICAL envelope
    # (retry). spool_envelope makes a fresh incoming/ file (same content name). It must be DEDUPED against
    # the processed/ marker, NOT appended a second time.
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    spool_envelope(spool, _finding())
    w.drain()
    spool_envelope(spool, _finding())          # identical re-spool, AFTER the first was archived
    r2 = w.drain()
    assert r2["deduped"] == 1 and r2["ingested"] == 0
    assert len(_kinds(store, "finding")) == 1   # exactly one record on the spine


def test_archive_failure_does_not_double_ingest(env):
    # BLOCK-2a: even if the post-append archive move FAILS (processed/ unwritable), the file was already
    # CLAIMED out of incoming/ before the append, so the next drain cannot re-read and re-append it.
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    spool_envelope(spool, _finding())
    os.chmod(w.processed, 0o500)               # make the archive move fail
    try:
        r1 = w.drain()
        assert r1["ingested"] == 1
        r2 = w.drain()                          # must NOT re-append
        assert r2["ingested"] == 0
    finally:
        os.chmod(w.processed, 0o700)
    assert len(_kinds(store, "finding")) == 1


# --- crash-recovery durability (FDX-1 reclaim + FDX-4 idempotent append + FDX-6 watch survival) ---------

def test_reclaim_working_recovers_a_crash_stranded_finding(env):
    # FDX-1: a mid-drain crash can leave a file in working/ (claimed out of incoming/ but never archived).
    # drain() scans only incoming/, so without a reclaim that file — and its confirmed FACT — is LOST.
    # The reclaim sweep at the top of drain() moves it back to incoming/ and it is ingested.
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    w.working.mkdir(parents=True, exist_ok=True)
    (w.working / "stranded.json").write_text(_finding(ref="sqli-stranded"), encoding="utf-8")
    r = w.drain()
    assert r["ingested"] == 1
    assert "sqli-stranded" in {rec.payload["finding_ref"] for rec in _kinds(store, "finding")}
    assert list(w.working.glob("*.json")) == []          # reclaimed + archived, nothing left stranded


def test_reclaim_after_ingest_does_not_double_append(env):
    # FDX-1 + FDX-4 together (the load-bearing interaction). Simulate a crash AFTER the spine append but
    # BEFORE the processed/ archive: the finding is already on the spine, an identical copy sits in working/,
    # and NO processed marker exists. The reclaim re-ingests it, but the receiver's content dedup (dedup=True)
    # returns the existing seq instead of appending a SECOND identical finding. Without the dedup layer the
    # reclaim would double-ingest — which is exactly why FDX-1 and FDX-4 must co-land.
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    spool_envelope(spool, _finding(ref="sqli-dup"))
    w.drain()
    assert len(_kinds(store, "finding")) == 1
    for m in list(w.processed.glob("*.json")):
        m.unlink()                                       # the archive "never happened" (crash window)
    (w.working / "replay.json").write_text(_finding(ref="sqli-dup"), encoding="utf-8")
    w.drain()                                            # reclaim → re-ingest → dedup on content identity
    assert len(_kinds(store, "finding")) == 1            # STILL exactly one record — no double-append


def test_reclaim_dedups_beyond_the_bounded_window(env):
    # Red-pen fold: the reclaim path uses an UNBOUNDED dedup scan, so a finding whose append landed before a
    # crash is de-duplicated on reclaim even when MORE than the 256-record bounded default has since
    # accumulated on the shared spine during the restart gap. With only the bounded window this double-ingests.
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    spool_envelope(spool, _finding(ref="dup-beyond"))
    w.drain()                                            # F appended (near seq 0) + archived
    assert sum(1 for r in _kinds(store, "finding") if r.payload["finding_ref"] == "dup-beyond") == 1
    recv = FindingReceiver.from_delegation(store, owner_pubkey=OWNER.public_key_b64,
                                           delegation=_gov_deleg(), now=NOW, scope="acme")
    for i in range(300):                                 # push F's seq > 256 behind the tip
        recv.ingest(_finding(ref=f"noise-{i}"))
    for m in list(w.processed.glob("*.json")):           # F's archive "never happened" (crash window)
        m.unlink()
    (w.working / "f-replay.json").write_text(_finding(ref="dup-beyond"), encoding="utf-8")
    w.drain()                                            # reclaim F with the UNBOUNDED window
    assert sum(1 for r in _kinds(store, "finding") if r.payload["finding_ref"] == "dup-beyond") == 1


def test_receiver_ingest_is_idempotent_on_content(env):
    # FDX-4 at the receiver: two ingests of the SAME finding append exactly one spine record; the second
    # returns the first's seq (content-dedup), never a second identical finding.
    store, spool = env
    recv = FindingReceiver.from_delegation(store, owner_pubkey=OWNER.public_key_b64,
                                           delegation=_gov_deleg(), now=NOW, scope="acme")
    envelope = _finding(ref="idem-1")
    s1 = recv.ingest(envelope)
    s2 = recv.ingest(envelope)
    assert s1 == s2 and len(_kinds(store, "finding")) == 1


def test_detection_reclaim_after_ingest_does_not_double_append(env):
    # FDX-4 symmetry for the detection path (ingest_detection also uses dedup=True).
    store, spool = env
    w = _watcher(store, spool, scope="*", spine=_spine_deleg())
    spool_envelope(spool, _detection())
    w.drain()
    assert len(_kinds(store, "detection")) == 1
    for m in list(w.processed.glob("*.json")):
        m.unlink()
    (w.working / "det-replay.json").write_text(_detection(), encoding="utf-8")
    w.drain()
    assert len(_kinds(store, "detection")) == 1


def test_watch_loop_survives_a_drain_error(env):
    # FDX-6: an unexpected error from one drain() round must NOT kill the watch loop (which would silently
    # stop the results-delivery daemon and strand every subsequent finding). The loop reports and continues.
    import threading
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    stop = threading.Event()
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient spine/IO fault")
        stop.set()                                       # second round ends the loop
        return {"ingested": 0, "rejected": 0, "deduped": 0, "seqs": []}

    w.drain = flaky                                      # type: ignore[assignment]
    w.watch(interval=0.0, stop=stop)                     # must return, not raise
    assert calls["n"] >= 2                               # the loop continued past the first-round error


def test_fifo_and_symlink_in_incoming_are_rejected_without_hanging(env):
    # BLOCK-1: a compromised producer plants a named pipe (would block a naive read forever) and a symlink
    # (would follow to an arbitrary path). Both must be rejected fail-closed, drain must NOT hang, and
    # nothing crosses onto the spine.
    import threading
    store, spool = env
    w = _watcher(store, spool, gov=_gov_deleg())
    w.incoming.mkdir(parents=True, exist_ok=True)
    os.mkfifo(w.incoming / "pipe.json")                    # writer-less FIFO → a blocking read never returns
    secret = tmp_target = os.path.join(spool, "secret.txt")
    with open(secret, "w") as fh:
        fh.write("TOP-SECRET-SHOULD-NOT-BE-READ")
    os.symlink(secret, w.incoming / "link.json")           # symlink → must not be followed
    result = {}
    t = threading.Thread(target=lambda: result.update(w.drain()))
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "drain HUNG on a hostile non-regular file (FIFO DoS)"
    assert result.get("ingested", 0) == 0 and _kinds(store, "finding") == []
    assert os.path.exists(secret), "the symlink target must be untouched"
