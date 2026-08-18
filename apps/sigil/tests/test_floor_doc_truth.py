"""W16-11 (#517) doc-truth guard — the durable anti-rollback floor is SIGNED, and the module must say so.

Context: `floor.json` was made owner-Ed25519-signed (commit G2 `0682fc87`) and its signature is verified on
the enforcing path (`checkpoint.classify_head`, reached by `sigil verify` and the live tail; residual closed
for a retaining verifier by `floor_witness.py`). But `floor.py`'s module docstring and a `classify_head`
comment still asserted the OLD, now-FALSE claim — "`floor.json` is an UNSIGNED file … a same-host attacker
… defeats the LOCAL verify path by rewriting head.json AND floor.json together" — which both contradicts the
implementation (a content rewrite now breaks `sig` → TAMPERING) and internally contradicts the `Floor`-class
docstring that describes the signature. A live security-claim that overstates a fixed weakness is a real
honesty defect.

This test FAILS if that false sentence returns, asserts the corrected claim is present, and — so the guard is
not mere word-matching — BACKS the corrected claim with the real behaviour it describes (`classify_head`
rejecting a content-tampered SIGNED floor). A negative control proves the docstring-reading harness is live.
"""
from __future__ import annotations

import inspect
import re
import tempfile
from pathlib import Path

from sigil.reuse import (
    AuthorizerKey,
    TrustRoot,
    build_chain,
    digest_payload,
    generate_keypair,
)
from sigil.reuse.chain import sign_head
from sigil.spine import floor as floor_mod
from sigil.spine.checkpoint import classify_head
from sigil.spine.floor import advance_floor

_OWNER = generate_keypair()


def _norm(s: str | None) -> str:
    """Collapse whitespace AND '#' comment-line prefixes, drop backticks, lowercase — so a claim is matched
    regardless of line wrapping OR being split across '#'-prefixed source-comment lines (else a false comment
    wrapped as `# …\n    # …` slips the guard because the '#' breaks the substring)."""
    return re.sub(r"[\s#]+", " ", (s or "").replace("`", " ")).strip().lower()


def _tmp_floor() -> Path:
    return Path(tempfile.mkdtemp()) / "floor.json"


# --- the fix: the stale UNSIGNED-floor claim must be GONE, the signed reality present -----------------

def test_floor_module_docstring_no_longer_claims_unsigned():
    doc = _norm(floor_mod.__doc__)
    # THE false sentence — fail if it ever returns:
    assert "floor.json is an unsigned file" not in doc, (
        "floor.py docstring still calls floor.json UNSIGNED — it is owner-Ed25519-signed since G2")
    assert "defeats the local verify path by rewriting head.json and floor.json together" not in doc, (
        "floor.py docstring still claims a plain floor.json rewrite defeats local verify — the signature "
        "now breaks on a content rewrite (TAMPERING)")


def test_floor_module_docstring_states_the_signed_reality():
    doc = _norm(floor_mod.__doc__)
    assert "owner-ed25519-signed" in doc
    assert "signature is verified on the enforcing path" in doc


def test_classify_head_comment_no_longer_claims_unsigned_floor():
    src = _norm(inspect.getsource(classify_head))
    assert "rewrite the unsigned floor.json" not in src, (
        "classify_head comment still calls floor.json UNSIGNED; it is signature-checked just below")


# --- the doc claim is BACKED by real behaviour (not word-matching) -----------------------------------

def test_content_tampered_signed_floor_is_tampering():
    """Grounds the docstring's 'a content rewrite breaks `sig` … TAMPERING' claim in the enforcing path."""
    chain = build_chain([digest_payload({"i": i}) for i in range(10)])
    head = sign_head(chain, engagement_slug="s", signers=[("owner", _OWNER.private_key_b64)])
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=_OWNER.public_key_b64)])
    signed = advance_floor(head, owner_key=_OWNER, path=_tmp_floor())
    # a legitimate signed floor certifies clean
    ok, _ = classify_head(head, chain, tr, floor=signed)
    assert ok is True
    # rolling its watermark DOWN under the old signature → the signature no longer verifies → TAMPERING
    tampered = signed.model_copy(update={"entry_count": 1})
    ok, msg = classify_head(head, chain, tr, floor=tampered)
    assert ok is False and "TAMPERING" in msg


# --- negative control: the harness is live and not vacuously passing ---------------------------------

def test_docstring_harness_negative_control():
    doc = _norm(floor_mod.__doc__)
    # stable true facts, present before AND after this fix — prove the read+match harness actually works
    assert "outside spine/" in doc
    assert "wireguard" in doc
    # a claim that was never in the docstring must be absent — proves the "not in" checks aren't matching all
    assert "stored in plaintext on a remote server" not in doc
