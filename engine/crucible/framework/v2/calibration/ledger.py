"""
calibration.ledger — the append-only outcome ledger.

Calibration is only as honest as the record it learns from. The ledger is
that record: an append-only log of `Prediction` -> `Outcome` pairs. A
prediction is written when a finding is scored; its outcome is filled in later,
once the operator (or a fix, or a dispute) resolves the finding. Calibrate.py
reads `pairs()` — the entries that have both — and fits the mapping that
replaces the old hardcoded 1.0.

Two invariants keep it trustworthy:

  * **Append-only.** A finding's prediction is written once; a second
    `add_prediction` for the same id is refused. An outcome is recorded once;
    a second `record_outcome` for the same id is refused. The log never
    silently rewrites history — a re-scored finding is a new finding id.

  * **No wallclock.** Ordering is a caller-supplied monotonic **sequence
    int** (`seq`), exactly like the world-model. The ledger never reads the
    clock, so serialisation is byte-stable and every fit is replayable.

Persistence is plain JSON — one document, entries sorted by seq — so it is
diffable and auditable, mirroring worldmodel.store.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..common import paths
from ..common.errors import CrucibleError
from .models import Outcome, Prediction

SCHEMA_VERSION = 1


class LedgerError(CrucibleError):
    """Recoverable ledger error — a duplicate prediction, an outcome for an
    unknown finding, a double-recorded outcome, or a corrupt document. The
    ledger records observations; it makes no trust decision, so this is a
    plain CrucibleError, never an EthicsViolation."""


class LedgerEntry(BaseModel):
    """One row: a prediction, the seq it was written at, and (once resolved)
    its outcome plus the seq the outcome was recorded at."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0, description="Monotonic sequence int of the prediction write.")
    prediction: Prediction
    outcome: Outcome | None = Field(default=None)
    outcome_seq: int | None = Field(
        default=None, ge=0, description="Monotonic sequence int of the outcome write."
    )


class OutcomeLedger:
    """Append-only store of Prediction -> Outcome pairs, keyed by finding_id.

    Deterministic and wallclock-free: the caller supplies a monotonic `seq`
    for each write. `pairs()` yields the resolved (prediction, outcome) tuples
    that calibrate.py learns from."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._index: dict[str, int] = {}  # finding_id -> position in _entries

    # -- mutation ----------------------------------------------------------

    def add_prediction(self, prediction: Prediction, *, seq: int) -> LedgerEntry:
        """Append a prediction. Refuses a second prediction for the same
        finding_id (append-only — a re-scored finding is a new id)."""
        if seq < 0:
            raise LedgerError(f"seq must be >= 0, got {seq}")
        fid = prediction.finding_id
        if fid in self._index:
            raise LedgerError(
                f"prediction for finding {fid!r} already in ledger (append-only)"
            )
        entry = LedgerEntry(seq=seq, prediction=prediction)
        self._index[fid] = len(self._entries)
        self._entries.append(entry)
        return entry

    def record_outcome(self, outcome: Outcome, *, seq: int) -> LedgerEntry:
        """Fill in the outcome for a previously-predicted finding. Refuses an
        outcome for an unknown finding or a finding whose outcome is already
        recorded."""
        if seq < 0:
            raise LedgerError(f"seq must be >= 0, got {seq}")
        fid = outcome.finding_id
        pos = self._index.get(fid)
        if pos is None:
            raise LedgerError(
                f"no prediction for finding {fid!r}; record its prediction first"
            )
        entry = self._entries[pos]
        if entry.outcome is not None:
            raise LedgerError(
                f"outcome for finding {fid!r} already recorded (append-only)"
            )
        # Rebuild the entry immutably so extra='forbid' invariants re-validate.
        self._entries[pos] = LedgerEntry(
            seq=entry.seq,
            prediction=entry.prediction,
            outcome=outcome,
            outcome_seq=seq,
        )
        return self._entries[pos]

    # -- read --------------------------------------------------------------

    def entries(self) -> list[LedgerEntry]:
        """All entries, ordered by prediction seq (stable, insertion-tie-free)."""
        return sorted(self._entries, key=lambda e: (e.seq, e.prediction.finding_id))

    def pairs(self) -> list[tuple[Prediction, Outcome]]:
        """The resolved (prediction, outcome) tuples, ordered by prediction
        seq. This is calibrate.py's training set."""
        return [
            (e.prediction, e.outcome)
            for e in self.entries()
            if e.outcome is not None
        ]

    def predictions(self) -> list[Prediction]:
        """Every prediction, resolved or not, ordered by seq."""
        return [e.prediction for e in self.entries()]

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def resolved_count(self) -> int:
        """How many predictions have an outcome recorded."""
        return sum(1 for e in self._entries if e.outcome is not None)

    # -- persistence -------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain, deterministic dict (entries sorted by seq)."""
        return {
            "schema_version": SCHEMA_VERSION,
            "entries": [e.model_dump(mode="json") for e in self.entries()],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Deterministic JSON string. `indent=None` gives a compact line."""
        return json.dumps(
            self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False
        )

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "OutcomeLedger":
        """Rebuild a ledger from a to_dict document, re-validating every row
        and re-enforcing the append-only (unique finding_id) invariant."""
        if not isinstance(data, dict):
            raise LedgerError("ledger document must be a JSON object")
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise LedgerError(
                f"unsupported ledger schema_version {version!r} (expected {SCHEMA_VERSION})"
            )
        raw_entries = data.get("entries", [])
        if not isinstance(raw_entries, list):
            raise LedgerError("ledger 'entries' must be an array")

        ledger = cls()
        try:
            rows = [LedgerEntry.model_validate(raw) for raw in raw_entries]
        except ValidationError as e:
            raise LedgerError(f"ledger record failed schema validation: {e}") from e
        for row in sorted(rows, key=lambda e: (e.seq, e.prediction.finding_id)):
            fid = row.prediction.finding_id
            if fid in ledger._index:
                raise LedgerError(
                    f"duplicate prediction for finding {fid!r} in document"
                )
            if row.outcome is not None and row.outcome.finding_id != fid:
                raise LedgerError(
                    f"entry outcome finding_id {row.outcome.finding_id!r} "
                    f"does not match prediction {fid!r}"
                )
            ledger._index[fid] = len(ledger._entries)
            ledger._entries.append(row)
        return ledger

    @classmethod
    def from_json(cls, text: str) -> "OutcomeLedger":
        """Rebuild a ledger from a JSON string produced by to_json."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise LedgerError(f"ledger document is not valid JSON: {e}") from e
        return cls.from_dict(data)

    def save(self, path: Path | str, *, indent: int | None = 2) -> None:
        """Write the ledger to `path` (parent dirs created)."""
        p = Path(path)
        paths.secure_write(p, self.to_json(indent=indent))   # X2: owner-only (outcome labels)

    @classmethod
    def load(cls, path: Path | str) -> "OutcomeLedger":
        """Read a ledger from `path`. Missing file -> LedgerError."""
        p = Path(path)
        if not p.is_file():
            raise LedgerError(f"no ledger file at {p}")
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as e:
            raise LedgerError(f"cannot read ledger at {p}: {e}") from e
        return cls.from_json(text)
