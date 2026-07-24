"""The ARCHIVIST orchestrator (SIGIL §6.3) — the nightly consolidation pass + its run cursor.

Over the window of records since the last run: EXTRACT candidates (in bounded batches, so the
gate's window is exactly what the extractor saw) → GATE each by re-execution → PROMOTE grounded
facts / record demoted ones → flag CONTRADICTIONS → write the BRIEF → CHECKPOINT (re-sign the
head). Append-only throughout; the gate — not model confidence — is the sole admission
authority. Default provider is the OFFLINE heuristic (zero Max spend); `--provider agent` opts
into the headless `claude -p` path."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterator

from ..config import CACHE_DIR, ensure_dirs
from ..spine.checkpoint import checkpoint
from ..spine.store import SpineStore
from .brief import write_brief
from .extract import ExtractionProvider, HeuristicProvider
from .gate import admit
from .promote import PromoteStats, promote_all

_CURSOR = CACHE_DIR / "consolidate_cursor.json"
_FEED_KINDS = {"message"}          # decisions/commitments live in messages, not tool noise
_BATCH = 30


@dataclass
class ConsolidationReport:
    window_from: int
    window_to: int
    records_fed: int
    candidates: int
    grounded: int
    ungrounded: int
    skipped: int
    contradictions: int
    brief_seq: int | None
    signed: bool

    def as_dict(self) -> dict:
        return asdict(self)


def _load_cursor() -> int:
    import json
    if _CURSOR.exists():
        try:
            return int(json.loads(_CURSOR.read_text(encoding="utf-8")).get("last_seq", -1))
        except (ValueError, OSError):
            return -1
    return -1


def _save_cursor(seq: int) -> None:
    import json
    ensure_dirs()
    _CURSOR.write_text(json.dumps({"last_seq": seq}), encoding="utf-8")


def _chunks(items: list, n: int) -> Iterator[list]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


def run_consolidation(provider: ExtractionProvider | None = None, *, store: SpineStore | None = None,
                      since_seq: int | None = None, batch_size: int = _BATCH, dry_run: bool = False,
                      do_brief: bool = True, sign: bool = True,
                      save_cursor: bool = True) -> ConsolidationReport:
    store = store or SpineStore()
    provider = provider or HeuristicProvider()
    since = since_seq if since_seq is not None else _load_cursor()
    head_before = store.next_seq - 1                       # never feed our own promotions
    window = [store.decrypted(r) for r in store.iter_records(since_seq=since)     # G1 slice-4: extract facts
              if r.seq <= head_before and r.kind in _FEED_KINDS]                  # from PLAINTEXT content

    admitted = []
    for batch in _chunks(window, batch_size):
        window_seqs = {r.seq for r in batch}               # exactly what the extractor saw
        for cand in provider.extract(batch):
            admitted.append((cand, admit(cand, window_seqs, store)))

    if dry_run or not window:
        g = sum(1 for _, v in admitted if v.grounded)
        return ConsolidationReport(
            window_from=(window[0].seq if window else since + 1),
            window_to=head_before, records_fed=len(window), candidates=len(admitted),
            grounded=g, ungrounded=len(admitted) - g, skipped=0, contradictions=0,
            brief_seq=None, signed=False)

    stats: PromoteStats = promote_all(store, admitted)
    # contradictions are EXTRACTOR-JUDGED (semantic) and gate-verified, promoted like any fact —
    # structural same-subject detection is unsound (can't tell opposition from reaffirmation).
    contras = stats.contradictions                     # actually-promoted this run (not admission-based)
    brief_seq = write_brief(store) if do_brief else None
    signed = False
    if sign:
        checkpoint(store)
        signed = True
    if save_cursor:
        _save_cursor(head_before)
    return ConsolidationReport(
        window_from=(window[0].seq if window else since + 1), window_to=head_before,
        records_fed=len(window), candidates=len(admitted), grounded=stats.grounded,
        ungrounded=stats.ungrounded, skipped=stats.skipped, contradictions=contras,
        brief_seq=brief_seq, signed=signed)
