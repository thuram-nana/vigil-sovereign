"""
eval.cli — `python3 -m framework.v2 eval <subcommand>`.

Subcommands:

    score    --corpus <path> --produced <findings.json> --run-id <id>
             [--label L] [--out run.json]
                 Score a produced-findings file against a corpus and
                 print the aggregate. Optionally persist the EvalRun.

    regress  --baseline <run.json> --candidate <run.json>
             [--max-detection-drop F] [--max-precision-drop F]
                 Compare two persisted runs. Exit 1 on regression — so
                 the verb is usable directly as a CI / SIL merge gate.

    show     --run <run.json>
                 Print a per-target + aggregate summary of a run.

The produced-findings file is a JSON object mapping target slug -> list
of produced findings, e.g.
    {"acme-shop": [{"bug_class": "IDOR", "surface": "/api/orders/{id}"}]}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..common.errors import EvalError
from .corpus import load_corpus
from .harness import load_run, save_run
from .models import ProducedFinding
from .regression import compare_runs
from .scoring import score_run
from .harness import now_utc


def _load_produced(path: Path) -> dict[str, list[ProducedFinding]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise EvalError(f"cannot read produced-findings file {path}: {e}") from e
    except json.JSONDecodeError as e:
        raise EvalError(f"produced-findings file {path} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise EvalError("produced-findings file must be a JSON object {slug: [findings]}")
    out: dict[str, list[ProducedFinding]] = {}
    for slug, raw_list in data.items():
        if not isinstance(raw_list, list):
            raise EvalError(f"produced findings for {slug!r} must be a list")
        out[slug] = [ProducedFinding.model_validate(r) for r in raw_list]
    return out


def _score(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)
    produced = _load_produced(Path(args.produced))
    run = score_run(
        run_id=args.run_id,
        corpus=corpus,
        produced_by_slug=produced,
        created_at=now_utc(),
        label=args.label or "",
    )
    agg = run.aggregate
    print(json.dumps(
        {
            "run_id": run.run_id,
            "corpus": f"{run.corpus_name}@{run.corpus_version}",
            "targets": agg.targets,
            "ground_truth": agg.ground_truth_count,
            "true_positives": agg.true_positives,
            "false_positives": agg.false_positives,
            "false_negatives": agg.false_negatives,
            "detection_rate": agg.detection_rate,
            "precision": agg.precision,
            "f1": agg.f1,
        },
        indent=2,
    ))
    if args.out:
        p = save_run(run, args.out)
        print(f"\nrun saved to {p}")
    return 0


def _regress(args: argparse.Namespace) -> int:
    baseline = load_run(args.baseline)
    candidate = load_run(args.candidate)
    report = compare_runs(
        baseline,
        candidate,
        max_detection_drop=args.max_detection_drop,
        max_precision_drop=args.max_precision_drop,
    )
    print(json.dumps(report.model_dump(mode="json"), indent=2))
    return 0 if report.passed else 1


def _show(args: argparse.Namespace) -> int:
    run = load_run(args.run)
    for ts in run.per_target:
        print(
            f"{ts.slug:<24s} tp={ts.true_positives} fp={ts.false_positives} "
            f"fn={ts.false_negatives} det={ts.detection_rate:.3f} prec={ts.precision:.3f}"
        )
    agg = run.aggregate
    print(
        f"{'AGGREGATE':<24s} tp={agg.true_positives} fp={agg.false_positives} "
        f"fn={agg.false_negatives} det={agg.detection_rate:.3f} prec={agg.precision:.3f} "
        f"f1={agg.f1:.3f}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 eval",
        description="Evaluation harness — score runs against a benchmark corpus.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("score", help="score a produced-findings file against a corpus")
    p.add_argument("--corpus", required=True)
    p.add_argument("--produced", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--label", default="")
    p.add_argument("--out", default="")
    p.set_defaults(fn=_score)

    p = sub.add_parser("regress", help="compare two runs (exit 1 on regression)")
    p.add_argument("--baseline", required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--max-detection-drop", type=float, default=0.0)
    p.add_argument("--max-precision-drop", type=float, default=0.0)
    p.set_defaults(fn=_regress)

    p = sub.add_parser("show", help="print a run summary")
    p.add_argument("--run", required=True)
    p.set_defaults(fn=_show)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = args.fn  # type: ignore[attr-defined]
    return int(fn(args))


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main(sys.argv[1:]))
