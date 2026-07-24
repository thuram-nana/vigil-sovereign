"""FIELD-LEVEL envelope encryption of spine record payloads at rest (audit G1 slice-4).

A spine payload MIXES keyless governance METADATA (``decision``/``tier``/``usage``/``signal``/
``promotion_key``/``folded_state``/…) with sensitive human CONTENT (``text``/``quote``/``body``/…) in
ONE dict — so a whole-record "encrypt this record?" rule cannot win: sealing an agent action record would
hide its ``usage`` from the keyless budget-cap fold (fail-OPEN), and exempting an archivist record would
leave its verbatim ``quote`` in cleartext (leak). This module therefore seals per FIELD: it encrypts only
the VALUES of the content fields, leaving every other key plaintext.

Result — the invariant that makes it safe:

  * KEYLESS governance stays keyless. The snapshot fold, kill-switch scanner, budget cap, and the
    device/nonce/promotion folds read only metadata keys (never a content field), so they work over the
    RAW record WITHOUT the key, even with a LOCKED vault. (The C18 self-audit's GOVERNANCE columns —
    ``decision``/``tier``/``entry_hash`` — are likewise plaintext metadata and stay keyless; its human
    "what" column shows the plaintext ``subject``/``summary`` labels, and ONLY its last-resort fallback to
    ``record.text()`` — a sealed content field — reads as ciphertext. Because the audit reads RAW to keep
    that governance invariant keyless, that fallback is ciphertext whenever the content is sealed,
    unlocked vault included — a cosmetic display detail on a rare fallback, never a fold break or a
    fail-open.)
  * The hash-chain's ``cert_digest`` is over the STORED payload (metadata plaintext + content ciphertext),
    so a KEYLESS verifier still verifies the whole chain / owner-signed head / floor / Merkle roots — only
    READING a content field's plaintext needs the DEK.
  * OPT-IN + non-bricking: no provisioned vault → no DEK → every field passes through PLAINTEXT
    (byte-identical to today). A mixed (legacy-plaintext + sealed) spine reads and verifies cleanly.

Each content field's ciphertext is bound (as AEAD associated data) to ``(scope, seq, field)``, so a
sealed value cannot be transplanted to another record, position, or field — defence-in-depth atop the
chain, which already changes ``cert_digest`` on any byte edit. The per-field AEAD nonce is written once
inside the sealed blob, so ``cert_digest`` is replay-stable (a field is NEVER re-sealed on read).
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any, Optional

from vigil_core.sealing import SealError, seal, unseal

from ..reuse import canonical_json

_ENC_VERSION = 1
_ALG = "chacha20poly1305"
_AAD_DOMAIN = b"sigil/spine-field/v1"
# AEAD context under which the DEK itself is sealed in the vault — DISTINCT from the owner-key context so
# a DEK blob can never be opened as the owner key (or vice versa).
_DEK_CONTEXT = b"sigil/spine.dek"

# The payload keys whose VALUES hold sensitive human content → their values are sealed (a dict/list value
# is canonical-JSON'd and sealed WHOLE, so nested content cannot partially leak). Everything else
# (governance metadata + the short descriptive labels `subject`/`summary`, which the keyless C18 audit
# reads for its "what" column) stays PLAINTEXT. Extend this set to seal a new content field; a field NOT
# listed here is left plaintext (a documented boundary — a leak, never a fold break).
#   * `tool_input`  — a tool_call's raw args (Write/Edit file contents, Bash commands) — sealed WHOLE.
#   * `vision_reading_advisory`/`grounded_objects`/`advisory_leads` — raw screen OCR / VLM reading.
#   * `statement` — an extractor's paraphrase of a grounded fact (near-verbatim of the sealed `quote`).
# DOCUMENTED plaintext BOUNDARIES (not covered, by design): a CRUCIBLE finding's opaque `certificate`
# (sealing it would break offline re-verification — finding evidence is stored plaintext); a commit /
# email `subject` (a short label, and a commit's body is duplicated inside the sealed `text`).
CONTENT_FIELDS = frozenset({
    "text", "content", "message", "body", "quote", "captured_text",
    "output", "answer", "title", "description",
    "tool_input", "vision_reading_advisory", "grounded_objects", "advisory_leads", "statement",
})


class SpinePayloadLocked(Exception):
    """A content field is sealed but no DEK is available to open it (the vault is locked / unreadable).
    Fail-closed — the plaintext is withheld. The chain still VERIFIES without the key."""


def _aad(scope: str, seq: int, field: str) -> bytes:
    return (_AAD_DOMAIN + b"\x00" + str(scope).encode("utf-8") + b"\x00"
            + int(seq).to_bytes(8, "big") + b"\x00" + field.encode("utf-8"))


def _is_field_envelope(v: Any) -> bool:
    """Is a payload VALUE a sealed field-envelope (vs a plaintext value)? The ``_enc`` sentinel is a
    shape a real content string never has."""
    return isinstance(v, dict) and v.get("_enc") == _ENC_VERSION and isinstance(v.get("b"), str)


def has_content(payload: Any) -> bool:
    """True iff the payload carries at least one non-empty content field to seal — so the write path
    loads the DEK ONLY for a content-bearing record (a pure-metadata / signal record never touches the
    vault → a kill-switch panic is never blocked by a locked vault)."""
    if not isinstance(payload, dict):
        return False
    return any(k in CONTENT_FIELDS and _sealable(payload[k]) for k in payload)


def _sealable(v: Any) -> bool:
    # seal non-empty strings and non-empty structured values; skip None / "" / already-an-envelope.
    if _is_field_envelope(v):
        return False
    if isinstance(v, str):
        return bool(v)
    return isinstance(v, (dict, list)) and bool(v)


def seal_payload(dek: Optional[bytes], payload: Any, *, scope: str, seq: int) -> Any:
    """Return the payload to STORE on disk: a COPY with every content field's value replaced by its sealed
    envelope, all other keys unchanged. With ``dek is None`` (vault off) or no content fields, the payload
    is returned UNCHANGED (plaintext passthrough). The caller computes ``cert_digest`` over the result."""
    if dek is None or not isinstance(payload, dict):
        return payload
    out: dict[str, Any] = {}
    changed = False
    for k, v in payload.items():
        if k in CONTENT_FIELDS and _sealable(v):
            blob = seal(dek, canonical_json(v), context=_aad(scope, seq, k))
            out[k] = {"_enc": _ENC_VERSION, "alg": _ALG, "b": base64.b64encode(blob).decode("ascii")}
            changed = True
        else:
            out[k] = v
    return out if changed else payload


def open_payload(dek: Optional[bytes], stored: Any, *, scope: str, seq: int) -> Any:
    """Return the PLAINTEXT payload for a stored value: a COPY with every sealed field-envelope decrypted,
    all other keys unchanged. A payload with no sealed field passes through unchanged (legacy plaintext /
    a pure-metadata record). A sealed field with no DEK, or a wrong-key / wrong-(scope,seq,field) AEAD
    failure, raises :class:`SpinePayloadLocked` (fail-closed / transplant defence)."""
    if not isinstance(stored, dict):
        return stored
    if not any(_is_field_envelope(v) for v in stored.values()):
        return stored
    out: dict[str, Any] = {}
    for k, v in stored.items():
        if not _is_field_envelope(v):
            out[k] = v
            continue
        if dek is None:
            raise SpinePayloadLocked(f"content field {k!r} is sealed but no DEK is available (vault locked)")
        try:
            raw = unseal(dek, base64.b64decode(v["b"]), context=_aad(scope, seq, k))
        except (SealError, ValueError, TypeError, OverflowError) as e:
            raise SpinePayloadLocked(f"sealed field {k!r} failed to open at seq {seq}: {e}") from e
        out[k] = json.loads(raw.decode("utf-8"))
    return out


def load_or_create_dek(vault: Any, *, create: bool) -> Optional[bytes]:
    """The per-spine DEK (32 bytes), sealed under the vault's TPM KEK. ``None`` when the vault is not
    enabled (opt-in passthrough). ``VaultLocked`` propagates (fail-closed). ``create=True`` mints it once,
    idempotent-refusing via a read-back so a race never orphans prior envelopes (the caller holds the
    append lock while minting; the read-back is belt-and-suspenders)."""
    from ..config import SPINE_DEK_PATH
    if not vault.enabled():
        return None
    existing = vault.read_text_secret(SPINE_DEK_PATH, context=_DEK_CONTEXT)  # VaultLocked propagates
    if existing:
        return base64.b64decode(existing)
    if not create:
        return None
    dek = os.urandom(32)
    vault.write_text_secret(SPINE_DEK_PATH, base64.b64encode(dek).decode("ascii"), context=_DEK_CONTEXT)
    back = vault.read_text_secret(SPINE_DEK_PATH, context=_DEK_CONTEXT)
    return base64.b64decode(back) if back else dek
