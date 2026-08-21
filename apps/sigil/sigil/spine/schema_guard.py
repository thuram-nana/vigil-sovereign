"""Shared REFUSE-NEWER gate for every VERSIONED artifact in the spine plane (W5-3, #447).

Refuse-newer used to exist for the signed head ALONE (``checkpoint._MAX_HEAD_SCHEMA`` +
``tail._resolve_head``): a head whose ``schema_version`` exceeds what this build understands is
"upgrade required", never treated as clean. Nothing gave the SAME protection to the other versioned
artifacts — the segment manifest, the snapshot state, the anti-rollback floor, the encrypted backup — so
each SILENTLY loaded a newer artifact as the old shape.

That silence is a security downgrade, not a cosmetic one. A newer writer may change a security-bearing
field's MEANING or drop a row this build folds over. The snapshot state is the sharpest case: its own
docstring warns that a hard prune which drops a fold row "would silently undo the anti-replay guard",
resetting a replay high-water to the bottom and making a captured owner-signed grant replay-resurrectable.
Loading a v(N+1) snapshot as vN — Pydantic fills every missing field with its empty default — is exactly
that failure. So every versioned artifact must FAIL CLOSED on a version newer than it understands.

This module is a dependency-free LEAF (stdlib only) so the head/manifest/floor/snapshot/backup modules can
all import it without a cycle. The per-artifact ``_MAX_*_SCHEMA`` constants stay defined in their own
modules (next to the writer that bumps them); this module only supplies the shared decision and the
enumeration the structural test (``test_spine_refuse_newer``) cross-checks so a NEW versioned artifact
added without a gate turns CI red.
"""
from __future__ import annotations


class SchemaTooNew(Exception):
    """A versioned artifact declares a schema/format version newer than this build understands.

    Fail-closed: the caller refuses to load it rather than silently downgrade it to the old shape. Raised
    by ``refuse_newer``; callers whose contract is to return a status tuple (e.g. ``verify_checkpoint``)
    keep their own inline gate instead of raising."""

    def __init__(self, artifact: str, found: int, max_understood: int) -> None:
        self.artifact = artifact
        self.found = found
        self.max_understood = max_understood
        super().__init__(
            f"{artifact} schema v{found} is newer than this build understands "
            f"(max v{max_understood}) — upgrade sigil; refusing to load (never treated as clean)")


def refuse_newer(version: object, max_understood: int, *, artifact: str) -> None:
    """Fail-closed refuse-newer gate. Raise ``SchemaTooNew`` if ``version`` > ``max_understood``.

    A same-or-older version returns (this build can load the artifact). ``version`` is coerced through
    ``int()`` so a non-integer / ``None`` field a hostile or corrupt artifact might carry cannot slip past
    as a comparison that silently succeeds — an uncoercible version is itself suspicious and fails CLOSED
    (treated as "too new / unrecognised"). Mirrors the head's ``schema_version > _MAX_HEAD_SCHEMA`` check
    and ``memory.migrate.apply``'s ``current > _CURRENT_VERSION`` refusal."""
    try:
        v = int(version)  # type: ignore[arg-type]
    except (TypeError, ValueError) as e:
        raise SchemaTooNew(artifact, -1, max_understood) from e  # uncoercible version -> fail closed
    if v > int(max_understood):
        raise SchemaTooNew(artifact, v, max_understood)


# ----------------------------------------------------------------------------------------------------
# Enumeration of the spine plane's versioned Pydantic artifacts (model class name -> human artifact name).
# The structural test reflects over ``sigil.spine`` for every BaseModel subclass that declares a
# ``schema_version`` field and asserts the set is a SUBSET of these keys — so a new versioned model
# committed WITHOUT registering (and gating) it fails CI. The other versioned artifacts this build refuses
# a NEWER version of are signed JSON DICTS, not spine Pydantic models, so they are gated at their load site
# and covered by explicit behavioural tests rather than by this reflection set:
#   * the signed head            — ``sigil.reuse`` head, gated in checkpoint/tail (``_MAX_HEAD_SCHEMA``);
#   * the encrypted backup       — gated in ``backup`` (``_MAX_BACKUP_SCHEMA``);
#   * the kernel security manifest — gated in ``governor.integrity`` (``_MAX_KERNEL_MANIFEST_SCHEMA``);
#   * the witness envelope + roster — gated in ``spine.witness`` (``_MAX_ENVELOPE_SCHEMA``/``_MAX_ROSTER_SCHEMA``).
# The vigil_core delegation cert + capability/identity objects already refuse a non-equal ``schema_version``
# (strict-equal ``!= _SCHEMA``) in their own plane; the offense blackboard DB has its own inline gate
# (``_MAX_BB_SCHEMA``) since the FATAL-2 boundary forbids it importing this sovereign helper.
# ----------------------------------------------------------------------------------------------------
SPINE_VERSIONED_MODELS: dict[str, str] = {
    "Manifest": "segment manifest",
    "SnapshotState": "snapshot state",
    "Floor": "anti-rollback floor",
}
