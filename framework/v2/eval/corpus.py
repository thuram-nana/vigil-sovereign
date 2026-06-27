"""
eval.corpus — load a benchmark corpus from disk.

Two accepted layouts:

  1. Single file: a JSON document that is a whole BenchmarkCorpus.

  2. Directory: a `corpus.json` manifest (at minimum {name, version},
     optionally with inline `targets`), plus any number of
     `*.target.json` files each holding one BenchmarkTarget. Inline and
     file-based targets are merged; duplicate slugs are an error.

Loading validates against the schemas and raises EvalError with the
offending path on any problem. No network, no execution.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from ..common.errors import EvalError
from .models import BenchmarkCorpus, BenchmarkTarget


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise EvalError(f"cannot read {path}: {e}") from e
    except json.JSONDecodeError as e:
        raise EvalError(f"{path} is not valid JSON: {e}") from e


def _corpus_from_file(path: Path) -> BenchmarkCorpus:
    data = _read_json(path)
    try:
        return BenchmarkCorpus.model_validate(data)
    except ValidationError as e:
        raise EvalError(f"{path} is not a valid corpus: {e}") from e


def _target_from_file(path: Path) -> BenchmarkTarget:
    data = _read_json(path)
    try:
        return BenchmarkTarget.model_validate(data)
    except ValidationError as e:
        raise EvalError(f"{path} is not a valid benchmark target: {e}") from e


def _corpus_from_dir(directory: Path) -> BenchmarkCorpus:
    manifest_path = directory / "corpus.json"
    if not manifest_path.is_file():
        raise EvalError(
            f"corpus directory {directory} has no corpus.json manifest"
        )
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise EvalError(f"{manifest_path} must be a JSON object")

    targets: list[BenchmarkTarget] = []
    inline = manifest.get("targets", [])
    if not isinstance(inline, list):
        raise EvalError(f"{manifest_path} 'targets' must be a list")
    for i, raw in enumerate(inline):
        try:
            targets.append(BenchmarkTarget.model_validate(raw))
        except ValidationError as e:
            raise EvalError(f"{manifest_path} inline target #{i} invalid: {e}") from e

    for tf in sorted(directory.glob("*.target.json")):
        targets.append(_target_from_file(tf))

    payload = {
        "name": manifest.get("name", directory.name),
        "version": str(manifest.get("version", "0")),
        "targets": [t.model_dump(mode="json") for t in targets],
    }
    try:
        return BenchmarkCorpus.model_validate(payload)
    except ValidationError as e:
        raise EvalError(f"corpus assembled from {directory} is invalid: {e}") from e


def load_corpus(path: str | Path) -> BenchmarkCorpus:
    """Load a corpus from a JSON file or a corpus directory."""
    p = Path(path).expanduser()
    if p.is_dir():
        return _corpus_from_dir(p)
    if p.is_file():
        return _corpus_from_file(p)
    raise EvalError(f"corpus path does not exist: {p}")


def builtin_corpus() -> BenchmarkCorpus:
    """The shipped starter corpus: a few SYNTHETIC archetype targets with
    illustrative ground truth, so the eval/SIL loop is runnable out of the
    box. The ground truth is metadata describing typical bug classes per
    archetype — not a claim about any real system, and not exploit code.
    Operators replace it with authorised target replicas."""
    return _corpus_from_file(Path(__file__).parent / "corpus" / "starter.json")
