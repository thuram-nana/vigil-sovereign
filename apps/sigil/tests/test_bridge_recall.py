"""SIGIL Phase 9 W2-G — read-only remote RECALL on the BridgeDaemon: "where did I last see X?"
answered over the tunnel from the owner's own GROUNDED on-screen OCR history. The daemon method
reuses the A0 perception-recall core wholesale — it serves the VERBATIM captured OCR line with its
spine provenance, never a paraphrase and never an advisory VLM lead, and appends nothing.
Run: ~/.sigil/venv/bin/python tests/test_bridge_recall.py"""
import tempfile

from sigil.bridge import BridgeDaemon
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64                       # an injected owner trust anchor (no ~/.sigil key needed)


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _seed_sighting(store, captured, *, frame_sha256="sha-test"):
    """Append a perception event exactly as recall.py scans for: kind='event', payload signal
    'perception', with the authoritative captured OCR text on `captured_text`."""
    return store.append(kind="event", source="agent", actor="PERCEPTION",
                        payload={"signal": "perception", "captured_text": captured,
                                 "frame_sha256": frame_sha256})


def test_daemon_recall_serves_verbatim_ocr_with_provenance():
    s = _store()
    _seed_sighting(s, "GitHub — pull requests")
    seq = _seed_sighting(s, "AWS console — S3 buckets dashboard")     # the sighting we expect back
    hit = BridgeDaemon(s, trusted_pubkey=OP).recall("AWS console")
    assert hit is not None, "a grounded on-screen sighting of the subject is recalled over the tunnel"
    assert hit["quote"] == "AWS console — S3 buckets dashboard", "serves the VERBATIM captured OCR line"
    assert hit["seq"] == seq and hit["entry_hash"], "carries spine provenance (seq + entry_hash)"
    assert hit["frame_sha256"] == "sha-test", "carries the frame reference of the sighting"


def test_daemon_recall_returns_the_most_recent_sighting():
    s = _store()
    _seed_sighting(s, "AWS console — EC2 dashboard")
    latest = _seed_sighting(s, "AWS console — S3 buckets")
    hit = BridgeDaemon(s, trusted_pubkey=OP).recall("AWS console")
    assert hit and hit["seq"] == latest and "S3" in hit["quote"], "the MOST RECENT grounded sighting wins"


def test_daemon_recall_unknown_subject_is_none():
    s = _store()
    _seed_sighting(s, "AWS console — S3 buckets")
    assert BridgeDaemon(s, trusted_pubkey=OP).recall("nonexistent thing") is None, \
        "an unseen subject recalls nothing (no fabrication)"


def test_daemon_recall_is_read_only_appends_nothing():
    s = _store()
    _seed_sighting(s, "AWS console — S3 buckets")
    before = [r.seq for r in s.iter_records()]
    BridgeDaemon(s, trusted_pubkey=OP).recall("AWS console")
    after = [r.seq for r in s.iter_records()]
    assert before == after, "recall is A0/read-only — it appends nothing to the spine"


def test_daemon_recall_grounds_on_captured_text_only_not_a_vlm_lead():
    s = _store()
    # 'kubernetes' lives ONLY in an advisory VLM reading field, never in the authoritative captured OCR
    s.append(kind="event", source="agent", actor="PERCEPTION",
             payload={"signal": "perception", "captured_text": "a plain terminal",
                      "vision_reading_advisory": "this looks like a kubernetes dashboard"})
    assert BridgeDaemon(s, trusted_pubkey=OP).recall("kubernetes") is None, \
        "recall grounds on captured OCR text only — never an advisory VLM lead"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-9 W2-G (read-only remote recall) guarantees hold")
