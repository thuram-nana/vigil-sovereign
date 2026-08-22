"""W5-2 (#446) — the spine RECORD-PAYLOAD evolution contract, and the machinery that ENFORCES it.

## Why a payload can only ever grow (the structural fact this contract exists for)

A record's `payload` is folded into `cert_digest` (`store.digest_payload(content)` over the stored
content, `content` includes `payload`), `cert_digest` is chained into `entry_hash`, and `entry_hash` is
what the owner's signed head anchors. So **an already-appended record cannot be rewritten without breaking
the hash chain and invalidating the owner signature** — records are structurally *un-migratable*. Unlike a
mutable table you can `ALTER`, the only ways a payload shape may evolve are:

  1. **Add** a NEW, OPTIONAL field (a reader of an old record fills its default — the read-time upcaster);
  2. mint a **new `kind`** with a fresh shape (an old record keeps its old kind + old shape forever).

Everything else — removing a committed field, renaming it, changing its type, changing what it *means*,
or adding a *required* field — is a **breaking** change: it would make some already-signed record read
wrong, and there is no migration that can fix it without a chain break. W5-1 (#445) made `kind` an
enforced, digested vocabulary and stamped an informational per-record `schema_version`; this slice writes
the rules for how the *payload under* a kind may evolve across those versions, and enforces them.

## The contract (normative)

For every `kind` with a registered payload model below:

  * **C1 — additive-only.** A newer `schema_version` may only ADD fields to a payload. A field that has
    ever been committed to `payload_shapes.json` MUST remain, with the SAME canonical type.
  * **C2 — no meaning change.** A committed field's type and meaning are frozen. To change either, choose
    a NEW field name (or a new `kind`) — never repurpose an existing one. (A repurpose is undetectable to
    a reader and silently corrupts every old record.)
  * **C3 — new fields are OPTIONAL with a default.** A record written under an older `schema_version`
    lacks any field added later; the reader upcasts it by supplying the default (`upcast_payload`). A new
    *required* field would make every old record read as invalid — forbidden.
  * **C4 — deprecation, never deletion.** A field that is no longer written is marked deprecated (kept in
    the model + committed shapes so old records still read); it is not removed. A genuinely incompatible
    shape is a NEW `kind`, leaving the old kind's records untouched.
  * **C5 — extra fields pass through.** The models set `extra="allow"`: a forward-compatible reader on an
    OLD build tolerates a field a NEWER writer added (it round-trips as an extra), rather than dropping or
    rejecting it. The committed shapes govern only the *declared* contract fields.

Enforcement: `payload_shapes.json` (committed) is the frozen baseline; `diff_shapes(committed, current)`
classifies every drift as breaking (C1/C2/C3 violation) or additive (allowed), and the required
`test_payload_evolution_contract` job fails the build on any breaking entry. The read-time upcaster is
`upcast_payload` (also reachable as `SpineRecord.typed_payload()`).

This module is a dependency-light LEAF over `pydantic` (already a spine dependency: `Manifest`,
`SnapshotState`, `Floor`). It imports nothing from `sigil.spine.store`/`models`, so it can be imported by
`models.py`'s `typed_payload` without a cycle, and it does NOT import any offense/`framework.*` module
(FATAL-2: this is sovereign-plane code).
"""
from __future__ import annotations

import json
import types
import typing
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

# The committed shape baseline lives next to this module and is loaded by the conformance test.
COMMITTED_SHAPES_PATH = Path(__file__).with_name("payload_shapes.json")


# --------------------------------------------------------------------------------------------------
# Per-kind payload models.
#
# Rules baked into every model, so the contract is structural, not just prose:
#   * ``extra="allow"``            -> C5: a field a newer writer adds round-trips as an extra.
#   * every field Optional+default -> C3: an OLD record missing a later-added field validates, and the
#                                    default is the upcast value (read-time upcaster).
# The declared fields are the ones a READER structurally depends on (consumes by name), taken from the
# real producers: ``ingest/git.py`` (commit), ``ingest/docs.py`` (document), ``scrape/researcher.py``
# (web_page), ``inbound/finding_receiver`` + ``vigil_integration.inert_finding`` (finding/detection), and
# ``spine/prune.snapshot_payload`` (snapshot). Free-form kinds (message/event/refusal/…) carry no
# structural contract and are intentionally NOT registered — their payload is opaque text/metadata.
# --------------------------------------------------------------------------------------------------
class PayloadModel(BaseModel):
    """Base for every per-kind payload model. Forward/backward compatible by construction (see rules)."""

    model_config = ConfigDict(extra="allow", frozen=False)


class CommitPayload(PayloadModel):
    text: Optional[str] = None
    hash: Optional[str] = None
    repo: Optional[str] = None
    subject: Optional[str] = None


class DocumentPayload(PayloadModel):
    text: Optional[str] = None
    title: Optional[str] = None
    chunk: Optional[int] = None
    path: Optional[str] = None
    project: Optional[str] = None


class WebPagePayload(PayloadModel):
    url: Optional[str] = None
    http_status: Optional[int] = None
    content_hash: Optional[str] = None
    robots_allowed: Optional[bool] = None
    depth: Optional[int] = None
    text: Optional[str] = None


class FindingPayload(PayloadModel):
    # the inert two-anchor finding envelope (vigil_integration.inert_finding.ValidatedFinding.to_spine_payload)
    # "schema" shadows pydantic's reserved BaseModel identifier, so it is declared as ``schema_`` bound to
    # the wire field "schema" via an alias (populate_by_name accepts either at read time).
    schema_: Optional[str] = Field(default=None, alias="schema")
    finding_ref: Optional[str] = None
    oracle_context_digest: Optional[str] = None
    certificate: Optional[dict] = None
    signatures: Optional[list] = None

    model_config = ConfigDict(extra="allow", frozen=False, populate_by_name=True)


class DetectionPayload(PayloadModel):
    schema_: Optional[str] = Field(default=None, alias="schema")
    oracle: Optional[str] = None
    evidence_digest_hex: Optional[str] = None
    bug_class: Optional[str] = None
    certificate: Optional[dict] = None
    signatures: Optional[list] = None

    model_config = ConfigDict(extra="allow", frozen=False, populate_by_name=True)


class SnapshotPayload(PayloadModel):
    # the owner-committed cold-archive fold (spine/prune.snapshot_payload). Security-critical: its
    # ``folded_state`` carries the anti-replay high-water. All fields frozen by C2.
    signal: Optional[str] = None
    base_seq: Optional[int] = None
    base_prev_hash: Optional[str] = None
    base_count: Optional[int] = None
    delta_merkle_root: Optional[str] = None
    cumulative_merkle_root: Optional[str] = None
    prev_snapshot_seq: Optional[int] = None
    snapshot_seq: Optional[int] = None          # stamped back by Slice E once the record is appended
    trusted_pubkey: Optional[str] = None
    folded_state: Optional[dict] = None


# The registry: kind -> payload model. A kind absent here is FREE-FORM (no structural contract).
PAYLOAD_MODELS: dict[str, type[PayloadModel]] = {
    "commit": CommitPayload,
    "document": DocumentPayload,
    "web_page": WebPagePayload,
    "finding": FindingPayload,
    "detection": DetectionPayload,
    "snapshot": SnapshotPayload,
}

# --------------------------------------------------------------------------------------------------
# Read-time upcaster (C3): an OLD payload reads correctly under the CURRENT model — missing fields take
# their default, extra fields survive. Tolerant by design: a typed VIEW on an already-verified record must
# never crash a read (record integrity is verify()'s fail-closed job, not this convenience view's).
# --------------------------------------------------------------------------------------------------
def upcast_payload(kind: str, payload: Any) -> Optional[PayloadModel]:
    """Return a typed, upcast view of ``payload`` for ``kind`` — or ``None`` for a free-form (unregistered)
    kind. An older payload missing a later-added field validates and the field takes its default; an extra
    field a newer writer added round-trips (``extra="allow"``). Never raises on a malformed legacy payload
    (falls back to a non-validating construct) — the chain/`verify()` remains the sole integrity gate."""
    model = PAYLOAD_MODELS.get(kind)
    if model is None:
        return None
    if not isinstance(payload, dict):
        payload = {}
    try:
        return model.model_validate(payload)
    except ValidationError:
        # tolerant read: preserve whatever is present without validating (a corrupt value must not crash a
        # read of an already-chain-verified record).
        try:
            return model.model_construct(**payload)
        except Exception:
            return model.model_construct()


# --------------------------------------------------------------------------------------------------
# Shape extraction + the additive-only schema diff (the enforcement engine).
# --------------------------------------------------------------------------------------------------
def _canonical_type(ann: Any) -> str:
    """Map a field annotation to a small, stable canonical-type string. ``Optional[T]``/``T | None`` folds
    to ``T`` (nullability is not the contract axis — presence + type is). Unknown -> ``"any"``."""
    origin = typing.get_origin(ann)
    if origin is typing.Union or origin is getattr(types, "UnionType", ()):  # Optional[T] / T | None
        args = [a for a in typing.get_args(ann) if a is not type(None)]
        if len(args) == 1:
            return _canonical_type(args[0])
        return "any"
    if origin in (list, tuple, set, frozenset):
        return "list"
    if origin is dict:
        return "dict"
    simple = {str: "str", int: "int", float: "float", bool: "bool", dict: "dict", list: "list"}
    if isinstance(ann, type) and ann in simple:
        return simple[ann]
    if ann is Any:
        return "any"
    return "any"


def shape_of(model: type[PayloadModel]) -> dict[str, dict[str, Any]]:
    """The contract shape of one model: wire-field-name -> {"type", "required"} (bool<int is distinct)."""
    out: dict[str, dict[str, Any]] = {}
    for name, f in model.model_fields.items():
        wire = f.alias or name        # the field's wire name (e.g. "schema" for the ``schema_`` field)
        out[wire] = {"type": _canonical_type(f.annotation), "required": bool(f.is_required())}
    return out


def current_shapes() -> dict[str, dict[str, dict[str, Any]]]:
    """The live contract shapes of every registered kind, keys sorted for a stable committed baseline."""
    return {kind: shape_of(PAYLOAD_MODELS[kind]) for kind in sorted(PAYLOAD_MODELS)}


def load_committed_shapes(path: Path | None = None) -> dict[str, dict[str, dict[str, Any]]]:
    p = path or COMMITTED_SHAPES_PATH
    return json.loads(p.read_text(encoding="utf-8"))


def dump_committed_shapes(path: Path | None = None) -> str:
    """Serialize the CURRENT shapes to the committed-baseline JSON form (used by the regen helper below)."""
    return json.dumps(current_shapes(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def diff_shapes(
    committed: dict[str, dict[str, dict[str, Any]]],
    current: dict[str, dict[str, dict[str, Any]]],
) -> list[str]:
    """Return the list of BREAKING changes going from ``committed`` -> ``current`` (empty == compatible).

    Breaking (a violation of C1/C2/C3 — would make some already-signed record read wrong):
      * a committed field REMOVED from a kind (C1/C4 — must stay, deprecate instead);
      * a committed field's canonical type CHANGED (C2 — meaning change);
      * a committed OPTIONAL field made REQUIRED (C3 — breaks old records that lack a value);
      * a NEW field that is REQUIRED (C3 — old records lack it → they'd read invalid);
      * an entire committed KIND model removed.
    Additive (allowed, NOT reported): a new OPTIONAL field, or a brand-new kind."""
    breaking: list[str] = []
    for kind, cfields in committed.items():
        cur = current.get(kind)
        if cur is None:
            breaking.append(f"{kind}: entire payload model removed (a committed kind's shape must remain)")
            continue
        for fname, cspec in cfields.items():
            if fname not in cur:
                breaking.append(
                    f"{kind}.{fname}: committed field REMOVED (non-additive — deprecate in place, never delete)")
                continue
            if cur[fname].get("type") != cspec.get("type"):
                breaking.append(
                    f"{kind}.{fname}: type changed {cspec.get('type')!r} -> {cur[fname].get('type')!r} "
                    f"(C2 meaning change — use a new field name instead)")
            if cur[fname].get("required") and not cspec.get("required"):
                breaking.append(
                    f"{kind}.{fname}: optional field made REQUIRED (breaks records written before it existed)")
    for kind, curfields in current.items():
        cfields = committed.get(kind, {})
        for fname, spec in curfields.items():
            if fname not in cfields and spec.get("required"):
                breaking.append(
                    f"{kind}.{fname}: new REQUIRED field (C3 — a new field must be OPTIONAL so old records "
                    f"still read)")
    return breaking


if __name__ == "__main__":  # regenerate the committed baseline: python -m sigil.spine.payload_contract
    COMMITTED_SHAPES_PATH.write_text(dump_committed_shapes(), encoding="utf-8")
    print(f"wrote {COMMITTED_SHAPES_PATH}")
