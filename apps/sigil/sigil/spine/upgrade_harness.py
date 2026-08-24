"""The N-1 → N upgrade / rollback + schema-compat HARNESS (W5-7, #451).

The defect this closes: there was no test that exercised a **version boundary** end to end. W5-5 (#449,
``upgrade.py``) shipped the crash-safe migrate/rollback ORCHESTRATOR and ``test_spine_upgrade.py`` proved
it preserves the UNKEYED chain (``store.verify()``); W5-1/W5-2 (#445/#446) shipped the per-record
``schema_version`` and the additive-only payload contract with their own diff/upcast tests. Nothing tied
them together into the property the operator actually cares about across a release:

    a spine of realistic OWNER-SIGNED data written by build N-1 upgrades to build N, its owner signature
    still verifies over the migrated store, and a rollback restores it with the signature and every record
    intact — AND the schema changes that made the upgrade safe are provably additive-only in both
    directions (an old build reads new data; a new build reads old data), so a NON-ADDITIVE change is
    caught rather than silently corrupting already-signed records.

This module is that harness. It is a reusable, importable verification tool (like ``migrate_runner`` /
``upgrade``), not only a test: ``python -m sigil.spine.upgrade_harness`` runs the full harness and prints
the verdict. The falsifiability lives here at the **schema/migration + signed-spine-record** level, which
is where a version boundary can actually go wrong; the required CI job runs it fast and deterministically.

## What "N-1" and "N" mean concretely

The spine plane versions along two axes, both exercised here:

  * **Structural layout** — legacy single-file (``spine.jsonl``, N-1) → retain-all segment layout (N).
    ``upgrade()`` performs this migration; it is the one that physically moves bytes.
  * **Per-record ``schema_version``** — a pre-W5-1 record carries NO ``schema_version`` key on its line
    (it reads back as ``LEGACY_SCHEMA_VERSION`` == 0, the N-1 record shape); a build-N writer stamps
    ``SCHEMA_VERSION`` == 1. Because ``schema_version`` sits OUTSIDE the digested ``content`` (like ``seq``
    /``ts``/the chain fields), the two shapes are chain- and signature-identical — that is *precisely* the
    property that makes the migration safe, and this harness proves it is load-bearing (a deliberately
    NON-ADDITIVE change that digested ``schema_version`` would break the owner signature; see
    :func:`schema_version_is_load_bearing`).

## Honest scope

This harness proves the **schema/migration + signed-record** core — the layer where a version boundary is
falsifiable on a PR runner. It signs with the same ``vigil_core`` primitives production uses
(``sign_head``/``verify_head``), but hermetically (a fresh keypair, temp dirs) rather than through the
global ``checkpoint()``/vault singletons, so it needs no ``SIGIL_HOME`` and stays deterministic. A true
cross-git-TAG install (check out the previous released tag, install it, write data, upgrade to HEAD) is the
heaviest variant; it is deferred until a released N-1 tag exists (the repo is pre-1.0) and is documented as
such in ``docs/decisions/W5-7-upgrade-rollback-harness.md``. A large-spine multi-segment SOAK variant is
wired to a scheduled job (honestly labelled), not the required one — see ``run_full_harness(records=...)``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..reuse import (
    AuthorizerKey,
    KeyPair,
    SignedChainHead,
    TrustRoot,
    digest_payload,
    generate_keypair,
    sign_head,
    verify_head,
)
from .manifest import read_manifest
from .models import LEGACY_SCHEMA_VERSION, SCHEMA_VERSION, SpineRecord
from .payload_contract import (
    current_shapes as _live_current_shapes,
    diff_shapes,
    load_committed_shapes,
    upcast_payload,
)
from .schema_guard import SchemaTooNew, refuse_newer
from .store import SpineStore
from .upgrade import restore_from_backup, upgrade

_OWNER_KEY_ID = "owner"


# ====================================================================================================
# signed-record helpers
# ====================================================================================================
def content_of(record: SpineRecord) -> dict:
    """The exact digested ``content`` of a record — the dict ``store.verify()`` re-hashes to check the
    binding. Deliberately EXCLUDES ``schema_version`` (and ``seq``/``ts``/the chain fields), because those
    are informational and NOT part of ``cert_digest``. Used by the negative control that proves this
    exclusion is load-bearing."""
    return {
        "scope": record.scope, "kind": record.kind, "source": record.source, "actor": record.actor,
        "payload": record.payload, "parent_id": record.parent_id, "supersedes_id": record.supersedes_id,
    }


def _trust_root_for(keypair: KeyPair) -> TrustRoot:
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id=_OWNER_KEY_ID, name="owner", public_key_b64=keypair.public_key_b64)])


def _sign(store: SpineStore, keypair: KeyPair, slug: str) -> SignedChainHead:
    return sign_head(store.entries(), engagement_slug=slug, signers=[(_OWNER_KEY_ID, keypair.private_key_b64)])


def verify_signed_spine(store: SpineStore, head: SignedChainHead, trust_root: TrustRoot) -> tuple[bool, str]:
    """Two-gate verification of SIGNED data: (1) the unkeyed chain binds + links (``store.verify()``), and
    (2) the owner's signed head still anchors the store's current entries (``verify_head``). Returns
    ``(ok, reason)``. This is the check the roundtrip runs at every version gate; a corrupted store or a
    head that no longer matches the chain fails it (the negative control exercises exactly that)."""
    ok, why = store.verify()
    if not ok:
        return False, f"chain integrity: {why}"
    ok, why = verify_head(head, store.entries(), trust_root)
    if not ok:
        return False, f"owner signature: {why}"
    return True, why


def _strip_schema_version(spine_dir: Path) -> int:
    """Rewrite every ``*.jsonl`` line under ``spine_dir`` removing the ``schema_version`` key, turning
    build-N records into TRUE build-(N-1) legacy records (pre-W5-1: no ``schema_version`` on the line).
    Because ``schema_version`` is not digested, the ``cert_digest``/chain/signature are byte-unaffected.
    Returns the number of records rewritten."""
    n = 0
    for jsonl in sorted(spine_dir.rglob("*.jsonl")):
        lines = jsonl.read_text(encoding="utf-8").splitlines()
        out: list[str] = []
        for ln in lines:
            if not ln.strip():
                continue
            obj = json.loads(ln)
            obj.pop("schema_version", None)
            out.append(json.dumps(obj, ensure_ascii=False))
            n += 1
        jsonl.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")
    return n


def build_n_minus_1_signed_spine(
    spine_dir: Path, *, records: int, keypair: Optional[KeyPair] = None,
    engagement_slug: str = "upgrade-harness", seg_max_records: int = 50,
) -> tuple[SpineStore, SignedChainHead, KeyPair, TrustRoot]:
    """Install realistic build-(N-1) SIGNED data: a legacy single-file spine of ``records`` hash-chained
    records that carry NO ``schema_version`` key (the pre-W5-1 record shape), anchored by a real
    owner-signed head. Returns ``(store, head, keypair, trust_root)``. The store is verified legacy (no
    segment manifest) and its signed head verifies before returning — so a caller starts from a known-good
    N-1 baseline."""
    spine_dir = Path(spine_dir)
    spine_dir.mkdir(parents=True, exist_ok=True)
    data = spine_dir / "spine.jsonl"
    writer = SpineStore(str(data), seg_max_bytes=0, seg_max_records=seg_max_records)
    for i in range(records):
        writer.append(kind="event", source="harness", actor="n-1-writer",
                      payload={"n": i, "text": f"realistic compressible record body {i} " * 3})
    _strip_schema_version(spine_dir)                                # -> true legacy (N-1) records
    store = SpineStore(str(data))
    if read_manifest(store._layout) is not None:
        raise AssertionError("precondition failed: build-(N-1) spine must be legacy (no segment manifest)")
    kp = keypair or generate_keypair()
    tr = _trust_root_for(kp)
    head = _sign(store, kp, engagement_slug)
    ok, why = verify_signed_spine(store, head, tr)
    if not ok:
        raise AssertionError(f"build-(N-1) baseline does not verify: {why}")
    return store, head, kp, tr


# ====================================================================================================
# the N-1 -> N -> rollback roundtrip
# ====================================================================================================
@dataclass(frozen=True)
class RoundtripResult:
    """The outcome of one N-1 → N → rollback roundtrip. ``ok`` is True IFF every gate held."""

    ok: bool
    detail: str
    steps: tuple[dict, ...] = ()
    count_n_minus_1: int = 0
    n_minus_1_layout: str = ""
    n_layout: str = ""
    signed_before: bool = False
    chain_ok_after_upgrade: bool = False
    signed_after_upgrade: bool = False
    schema_versions_after_n_write: tuple[int, ...] = ()
    signed_mixed_spine: bool = False
    chain_ok_after_rollback: bool = False
    signed_after_rollback: bool = False
    data_intact_after_rollback: bool = False
    rolled_back_to_legacy: bool = False


def run_upgrade_rollback_roundtrip(
    work_dir: Path, *, records: int = 12, n_writer_records: int = 3,
    keypair: Optional[KeyPair] = None, seg_max_records: int = 50,
) -> RoundtripResult:
    """The full version-boundary roundtrip on realistic SIGNED data:

      1. build a build-(N-1) legacy signed spine (``build_n_minus_1_signed_spine``) and verify it;
      2. **upgrade to N** with the real ``upgrade()`` orchestrator (legacy → segment, retain-all, its own
         verified backup) and re-verify the SAME owner signature over the migrated store — the signature
         survives because the migration is retain-all and ``schema_version``/layout are not digested;
      3. **build-N writer** appends ``schema_version`` == 1 records, giving a mixed {0,1} spine that a
         single re-signed head still anchors (forward+backward record shapes coexist under one signature);
      4. **roll back to N-1** by restoring the orchestrator's verified backup, and re-verify the ORIGINAL
         owner signature + record count over the restored legacy store — the data is intact.

    Returns a :class:`RoundtripResult`; ``ok`` is True only if every gate held."""
    work_dir = Path(work_dir)
    spine_dir = work_dir / "spine"
    backups = work_dir / "backups"
    data = spine_dir / "spine.jsonl"
    steps: list[dict] = []

    store, head, kp, tr = build_n_minus_1_signed_spine(
        spine_dir, records=records, keypair=keypair, seg_max_records=seg_max_records)
    count_before = store.count()
    n_minus_1_layout = "legacy" if read_manifest(store._layout) is None else "segment"
    signed_before, why = verify_signed_spine(store, head, tr)
    steps.append({"step": "build_n_minus_1", "records": count_before, "layout": n_minus_1_layout,
                  "signed": signed_before, "why": why})

    # 2. upgrade N-1 -> N (real orchestrator; takes + verifies its own backup, migrates, verifies).
    rep = upgrade(SpineStore(str(data), seg_max_bytes=0, seg_max_records=seg_max_records), backup_dir=backups)
    backup_path = Path(rep["backup"])
    migrated = SpineStore(str(data))
    n_layout = "segment" if read_manifest(migrated._layout) is not None else "legacy"
    chain_ok_after_upgrade, cwhy = migrated.verify()
    signed_after_upgrade, swhy = verify_signed_spine(migrated, head, tr)
    steps.append({"step": "upgrade", "migrated": rep.get("migrated"), "layout": n_layout,
                  "chain_ok": chain_ok_after_upgrade, "signed": signed_after_upgrade,
                  "chain_why": cwhy, "signed_why": swhy, "backup": str(backup_path)})

    # 3. build-N writer: stamp schema_version==1 records; a mixed {0,1} spine verifies under one head.
    for j in range(n_writer_records):
        migrated.append(kind="event", source="harness", actor="n-writer",
                        payload={"n": 1000 + j, "text": f"build-N record {j}"})
    after = SpineStore(str(data))
    schema_versions = tuple(sorted({r.schema_version for r in after.iter_records()}))
    mixed_head = _sign(after, kp, "upgrade-harness")
    signed_mixed, mwhy = verify_signed_spine(after, mixed_head, tr)
    steps.append({"step": "n_writer", "schema_versions": list(schema_versions),
                  "signed_mixed": signed_mixed, "why": mwhy})

    # 4. roll back to N-1 (restore the orchestrator's verified backup) and re-verify the ORIGINAL signature.
    restore_from_backup(spine_dir, backup_path)
    restored = SpineStore(str(data))
    rolled_back_to_legacy = read_manifest(restored._layout) is None
    chain_ok_after_rollback, rcwhy = restored.verify()
    signed_after_rollback, rswhy = verify_signed_spine(restored, head, tr)
    data_intact = (restored.count() == count_before
                   and [r.seq for r in restored.iter_records()] == list(range(count_before)))
    steps.append({"step": "rollback", "layout": "legacy" if rolled_back_to_legacy else "segment",
                  "chain_ok": chain_ok_after_rollback, "signed": signed_after_rollback,
                  "data_intact": data_intact, "chain_why": rcwhy, "signed_why": rswhy})

    ok = bool(signed_before and chain_ok_after_upgrade and signed_after_upgrade and signed_mixed
              and chain_ok_after_rollback and signed_after_rollback and data_intact
              and rolled_back_to_legacy and n_minus_1_layout == "legacy" and n_layout == "segment"
              and set(schema_versions) == {LEGACY_SCHEMA_VERSION, SCHEMA_VERSION})
    detail = ("N-1 -> N -> rollback: owner signature survived the migration and the rollback; every record "
              "intact") if ok else "roundtrip gate(s) failed — see steps"
    return RoundtripResult(
        ok=ok, detail=detail, steps=tuple(steps), count_n_minus_1=count_before,
        n_minus_1_layout=n_minus_1_layout, n_layout=n_layout, signed_before=signed_before,
        chain_ok_after_upgrade=chain_ok_after_upgrade, signed_after_upgrade=signed_after_upgrade,
        schema_versions_after_n_write=schema_versions, signed_mixed_spine=signed_mixed,
        chain_ok_after_rollback=chain_ok_after_rollback, signed_after_rollback=signed_after_rollback,
        data_intact_after_rollback=data_intact, rolled_back_to_legacy=rolled_back_to_legacy)


def schema_version_is_load_bearing(record: SpineRecord) -> bool:
    """Negative-control primitive: prove the additive property the upgrade relies on is real, not a no-op.

    ``schema_version`` being EXCLUDED from the digest is *why* an N-1 and an N record are signature-identical
    and the migration is safe. This returns True IFF that exclusion is load-bearing: the record's real
    ``cert_digest`` equals the digest of its ``content`` WITHOUT ``schema_version`` (additive, today), AND a
    hypothetical NON-ADDITIVE change that folded ``schema_version`` INTO the digest would produce a DIFFERENT
    digest (so it would break the chain + owner signature and be caught). If a future edit ever made
    ``schema_version`` digested, both halves could no longer hold together and the harness fails."""
    plain = digest_payload(content_of(record))
    versioned = digest_payload({**content_of(record), "schema_version": record.schema_version})
    return plain == record.cert_digest and versioned != record.cert_digest


# ====================================================================================================
# the forward/backward schema-compat matrix
# ====================================================================================================
@dataclass(frozen=True)
class CompatCell:
    """One cell of the compat matrix. ``direction`` is ``backward`` (a build-N reader reads build-(N-1)
    data) or ``forward`` (a build-(N-1) reader reads build-N data). ``change`` is ``additive`` (must be
    tolerated) or ``non-additive`` (must be refused, fail-closed). ``ok`` is ``observed == expected``."""

    direction: str
    change: str
    subject: str
    expected: str          # "compatible" | "refused"
    observed: str
    ok: bool
    detail: str = ""


def _cell(direction: str, change: str, subject: str, expected: str, observed: str, detail: str = "") -> CompatCell:
    return CompatCell(direction=direction, change=change, subject=subject, expected=expected,
                      observed=observed, ok=(observed == expected), detail=detail)


def run_compat_matrix(
    *, committed: Optional[dict] = None, current: Optional[dict] = None,
) -> list[CompatCell]:
    """Build the forward/backward × additive/non-additive compat matrix over the REAL enforcement
    primitives (``SpineRecord.from_dict``, ``upcast_payload``, ``refuse_newer``, ``diff_shapes``). Each
    cell records ``expected`` vs ``observed``; ``matrix_ok`` is True IFF every cell matches.

    ``committed`` / ``current`` default to the live committed baseline (``payload_shapes.json``) and the
    live models. The negative control passes a ``current`` that has been mutated NON-additively (e.g. a
    committed field removed) and asserts the corresponding cell flips to a mismatch."""
    committed = committed if committed is not None else load_committed_shapes()
    current = current if current is not None else _live_current_shapes()
    cells: list[CompatCell] = []

    # BACKWARD (build-N reader reads build-(N-1) data) -----------------------------------------------
    # A legacy record line with NO schema_version key must read back as LEGACY_SCHEMA_VERSION.
    legacy = SpineRecord.from_dict({
        "seq": 0, "scope": "s", "kind": "event", "source": "n-1", "actor": "a",
        "payload": {"n": 1}, "cert_digest": "d", "prev_hash": "p", "entry_hash": "e"})  # no schema_version
    cells.append(_cell(
        "backward", "additive", "legacy record (no schema_version) reads as LEGACY_SCHEMA_VERSION",
        "compatible", "compatible" if legacy.schema_version == LEGACY_SCHEMA_VERSION else "refused",
        f"schema_version={legacy.schema_version}"))

    # An OLD payload missing a later-added OPTIONAL field upcasts to the field's default. Read via
    # model_dump() (base-class-safe) so this does not depend on the concrete per-kind model's attributes.
    m = upcast_payload("commit", {"text": "t", "hash": "h", "repo": "r"})  # no "subject"
    dumped = m.model_dump() if m is not None else {}
    cells.append(_cell(
        "backward", "additive", "old payload missing a later-added optional field upcasts to default",
        "compatible",
        "compatible" if (dumped.get("text") == "t" and dumped.get("subject") is None) else "refused"))

    # FORWARD (build-(N-1) reader reads build-N data) -----------------------------------------------
    # A field a NEWER writer added, unknown to the old model, round-trips (extra="allow", C5).
    m2 = upcast_payload("commit", {"text": "t", "field_added_by_build_n": {"x": [1, 2]}})
    dumped2 = m2.model_dump() if m2 is not None else {}
    cells.append(_cell(
        "forward", "additive", "field a newer writer added round-trips (extra='allow')",
        "compatible",
        "compatible" if dumped2.get("field_added_by_build_n") == {"x": [1, 2]} else "refused"))

    # A versioned ARTIFACT one schema newer than this build understands is REFUSED (fail-closed).
    from .floor import _MAX_FLOOR_SCHEMA  # a representative gated versioned artifact
    try:
        refuse_newer(_MAX_FLOOR_SCHEMA + 1, _MAX_FLOOR_SCHEMA, artifact="anti-rollback floor")
        observed = "compatible"                                      # WRONG — should have refused
    except SchemaTooNew:
        observed = "refused"
    cells.append(_cell(
        "forward", "non-additive", "a versioned artifact newer than this build is refused (refuse-newer)",
        "refused", observed, f"max understood v{_MAX_FLOOR_SCHEMA}"))

    # ...and the same-version artifact is ACCEPTED — proving refuse_newer is not "refuse always".
    try:
        refuse_newer(_MAX_FLOOR_SCHEMA, _MAX_FLOOR_SCHEMA, artifact="anti-rollback floor")
        observed = "compatible"
    except SchemaTooNew:
        observed = "refused"
    cells.append(_cell(
        "forward", "additive", "a same-version versioned artifact is accepted (refuse-newer not a no-op)",
        "compatible", observed))

    # EITHER direction — the additive-only PAYLOAD contract: on the given (committed, current) pair there
    # must be NO breaking drift. Live -> compatible; a non-additively-mutated `current` -> refused (the
    # negative control drives exactly this cell to a mismatch against its "compatible" expectation).
    breaking = diff_shapes(committed, current)
    cells.append(_cell(
        "backward", "non-additive",
        "the payload contract permits no breaking (non-additive) drift vs the committed baseline",
        "compatible", "refused" if breaking else "compatible",
        "; ".join(breaking) if breaking else "no breaking drift"))

    return cells


def matrix_ok(cells: list[CompatCell]) -> bool:
    """True IFF every compat-matrix cell's observed behaviour matches its expected behaviour."""
    return all(c.ok for c in cells)


# ====================================================================================================
# the full harness verdict
# ====================================================================================================
@dataclass(frozen=True)
class HarnessResult:
    """The single verdict of the whole harness: the signed N-1→N→rollback roundtrip held AND every
    compat-matrix cell matched AND the live payload contract shows no breaking drift. ``ok`` is the one
    boolean the required test turns on; a deliberately NON-ADDITIVE change flips it to False."""

    ok: bool
    roundtrip: RoundtripResult
    matrix: tuple[CompatCell, ...]
    contract_breaking: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "detail": self.detail,
            "roundtrip": {"ok": self.roundtrip.ok, "detail": self.roundtrip.detail,
                          "count_n_minus_1": self.roundtrip.count_n_minus_1,
                          "n_minus_1_layout": self.roundtrip.n_minus_1_layout,
                          "n_layout": self.roundtrip.n_layout,
                          "schema_versions_after_n_write": list(self.roundtrip.schema_versions_after_n_write),
                          "steps": list(self.roundtrip.steps)},
            "matrix": [c.__dict__ for c in self.matrix],
            "contract_breaking": list(self.contract_breaking),
        }


def run_full_harness(
    work_dir: Path, *, records: int = 12, n_writer_records: int = 3,
    seg_max_records: int = 50, current_shapes_override: Optional[dict] = None,
) -> HarnessResult:
    """Run the whole harness and return its single verdict. ``ok`` is True IFF: the signed N-1→N→rollback
    roundtrip held, every compat-matrix cell matched, and the payload contract shows no breaking drift.

    ``current_shapes_override`` injects a substitute "current" shape set for the compat leg WITHOUT editing
    the live models — the negative control passes a NON-additively-mutated set (a committed field removed)
    and this verdict must flip to False."""
    work_dir = Path(work_dir)
    roundtrip = run_upgrade_rollback_roundtrip(
        work_dir, records=records, n_writer_records=n_writer_records, seg_max_records=seg_max_records)
    committed = load_committed_shapes()
    current = current_shapes_override if current_shapes_override is not None else _live_current_shapes()
    matrix = run_compat_matrix(committed=committed, current=current)
    contract_breaking = tuple(diff_shapes(committed, current))
    ok = roundtrip.ok and matrix_ok(matrix) and not contract_breaking
    detail = ("upgrade/rollback roundtrip held on signed data; forward+backward compat matrix all-green; "
              "additive-only payload contract holds") if ok else (
        "harness FAILED: "
        + ("roundtrip gate(s) failed; " if not roundtrip.ok else "")
        + ("compat-matrix cell mismatch; " if not matrix_ok(matrix) else "")
        + (f"non-additive schema drift: {'; '.join(contract_breaking)}" if contract_breaking else ""))
    return HarnessResult(ok=ok, roundtrip=roundtrip, matrix=tuple(matrix),
                         contract_breaking=contract_breaking, detail=detail)


def main(argv: Optional[list[str]] = None) -> int:  # pragma: no cover — CLI convenience / soak driver
    """``python -m sigil.spine.upgrade_harness [--records N] [--soak]`` — run the harness and print its
    JSON verdict. ``--soak`` uses a large multi-segment spine (the scheduled heavier variant). Exit 0 on a
    green verdict, 1 otherwise."""
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="VIGIL N-1 -> N upgrade/rollback + schema-compat harness")
    ap.add_argument("--records", type=int, default=12)
    ap.add_argument("--soak", action="store_true",
                    help="large multi-segment spine (heavier scheduled variant, not the required PR job)")
    args = ap.parse_args(argv)
    records = 3000 if args.soak else args.records
    seg = 200 if args.soak else 50
    with tempfile.TemporaryDirectory(prefix="vigil-upgrade-harness-") as tmp:
        result = run_full_harness(Path(tmp), records=records, seg_max_records=seg)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
