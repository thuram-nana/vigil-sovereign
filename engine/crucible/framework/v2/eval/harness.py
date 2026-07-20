"""
eval.harness — orchestrate a scored run over a corpus, and persist it.

The harness is deliberately ignorant of *how* findings are produced. A
`FindingProducer` is anything callable that, given a benchmark target,
returns the findings the framework produced for it. In tests that is a
deterministic function; in production it is an adapter that runs the
planner against a target replica and maps blackboard findings to
`ProducedFinding`. Keeping that boundary clean is what makes the
harness itself deterministic and offline-testable.

A producer that raises aborts the run with an EvalError naming the
target: a crashed producer invalidates the measurement, and a silent
zero-score would lie about why detection fell.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from ..common.errors import EvalError
from .models import BenchmarkCorpus, BenchmarkTarget, EvalRun, ProducedFinding
from .scoring import score_run


class FindingProducer(Protocol):
    """Produces the findings the framework emitted for one target."""

    def __call__(self, target: BenchmarkTarget) -> list[ProducedFinding]: ...


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def run_harness(
    corpus: BenchmarkCorpus,
    producer: FindingProducer,
    *,
    run_id: str,
    created_at: datetime | None = None,
    label: str = "",
) -> EvalRun:
    """Run `producer` over every target, score, and return the EvalRun."""
    produced_by_slug: dict[str, list[ProducedFinding]] = {}
    for target in corpus.targets:
        try:
            produced = list(producer(target))
        except Exception as e:  # producer failure invalidates measurement
            raise EvalError(
                f"finding producer failed on target {target.slug!r}: "
                f"{type(e).__name__}: {e}"
            ) from e
        produced_by_slug[target.slug] = produced

    return score_run(
        run_id=run_id,
        corpus=corpus,
        produced_by_slug=produced_by_slug,
        created_at=created_at or now_utc(),
        label=label,
    )


# ---------------------------------------------------------------------------
# Run persistence
# ---------------------------------------------------------------------------


def save_run(run: EvalRun, path: str | Path) -> Path:
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(run.model_dump(mode="json"), indent=2), encoding="utf-8")
    return p


def load_run(path: str | Path) -> EvalRun:
    p = Path(path).expanduser()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise EvalError(f"cannot read run record {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise EvalError(f"run record {p} is not valid JSON: {e}") from e
    try:
        return EvalRun.model_validate(data)
    except ValidationError as e:
        raise EvalError(f"run record {p} is not a valid EvalRun: {e}") from e
