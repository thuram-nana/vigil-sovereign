"""Check or regenerate the golden embedding fixture under the LOCKED onnxruntime.

    python -m sigil.vectors.baseline --check     # exit 0 iff the fixture matches this environment
    python -m sigil.vectors.baseline --write     # re-baseline (keeps the replaced set as previous_vectors)

The golden vectors (``apps/sigil/tests/fixtures/bge_small_golden.json``) are a function of the pinned model
files AND the onnxruntime release that ran them: with the files fixed, the fp32 output still moves by ~2e-4
between onnxruntime releases, while one release is stable across x86 ISAs. So both modes REFUSE unless the
installed onnxruntime is exactly the version pinned in ``infra/supply-chain/sovereign.lock.txt`` (the release
a sovereign deployment runs), and ``--write`` records that version, the Hugging Face revision and the file
hashes next to the vectors. An onnxruntime bump re-runs ``--write`` in the same change; the fixture's
``atol`` is carried over unchanged (never loosened here). See
``docs/decisions/EMB-1-embedding-baseline-locked-ort.md``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

_APP = Path(__file__).resolve().parents[2]            # apps/sigil
_REPO = _APP.parents[1]                               # the repository root (source checkout)
FIXTURE = _APP / "tests" / "fixtures" / "bge_small_golden.json"
SOVEREIGN_LOCK = _REPO / "infra" / "supply-chain" / "sovereign.lock.txt"

# What the stored vectors may move by, at most, when a re-baseline replaces them, for the stored-vector
# store to stay valid without re-embedding (cosine distance per text). The measured shift of the 1.31.1
# re-baseline is ~2.4e-7.
REEMBED_COSINE_FLOOR = 1.0 - 1e-3


def locked_ort_version(lock: Path = SOVEREIGN_LOCK) -> str:
    m = re.search(r"^onnxruntime==([^\s\\;]+)", lock.read_text(encoding="utf-8"), re.M)
    if not m:
        raise SystemExit(f"no onnxruntime== pin in {lock}")
    return m.group(1)


def _installed_ort() -> str:
    import onnxruntime

    return str(onnxruntime.__version__)


def _require_locked_ort(lock: Path) -> str:
    want, have = locked_ort_version(lock), _installed_ort()
    if have != want:
        raise SystemExit(
            f"refusing: installed onnxruntime {have} != the sovereign-lock pin {want} ({lock}). The golden "
            "vectors are only meaningful under the locked release — install the sovereign lock first."
        )
    return want


def _cosines(a: Sequence[Sequence[float]], b: Sequence[Sequence[float]]) -> list[float]:
    import numpy as np

    x, y = np.array(a, dtype=float), np.array(b, dtype=float)
    num = (x * y).sum(axis=1)
    den = np.linalg.norm(x, axis=1) * np.linalg.norm(y, axis=1)
    return [float(v) for v in num / den]


def _emb_module() -> Any:
    # ``sigil.vectors`` binds the name ``embed`` to the FUNCTION, shadowing the submodule — import it by name
    import importlib

    return importlib.import_module("sigil.vectors.embed")


def _embed(texts: list[str]) -> list[list[float]]:
    return _emb_module().embed(list(texts))


def check(fixture: Path = FIXTURE, lock: Path = SOVEREIGN_LOCK) -> list[str]:
    """Problems with the fixture in THIS environment (empty == it matches)."""
    ort = _require_locked_ort(lock)
    g = json.loads(fixture.read_text(encoding="utf-8"))
    src = _emb_module()._source(g.get("model"))
    problems = []
    if g.get("ort_version") != ort:
        problems.append(f"fixture ort_version {g.get('ort_version')!r} != locked onnxruntime {ort!r}")
    for key in ("revision", "onnx_sha256", "tokenizer_sha256"):
        fkey = "hf_revision" if key == "revision" else key
        if g.get(fkey) != src[key]:
            problems.append(f"fixture {fkey} {g.get(fkey)!r} != the pin in sigil/vectors/embed.py {src[key]!r}")
    mine = _embed(g["texts"])
    worst = max(abs(a - b) for va, vb in zip(mine, g["vectors"]) for a, b in zip(va, vb))
    if worst > float(g["atol"]):
        problems.append(f"max|delta| {worst:.3e} > atol {g['atol']}")
    return problems


def write(fixture: Path = FIXTURE, lock: Path = SOVEREIGN_LOCK) -> dict[str, Any]:
    """Re-baseline the fixture under the locked onnxruntime; return the written document."""
    ort = _require_locked_ort(lock)
    old = json.loads(fixture.read_text(encoding="utf-8"))
    src = _emb_module()._source(old.get("model"))
    vectors = _embed(old["texts"])
    shift = min(_cosines(vectors, old["vectors"]))
    if shift < REEMBED_COSINE_FLOOR:
        raise SystemExit(
            f"refusing: the new vectors move by cosine {shift:.9f} (< {REEMBED_COSINE_FLOOR}) from the stored "
            "set — that is a vector-space change, which needs a re-embed migration, not a re-baseline."
        )
    doc: dict[str, Any] = {
        "_comment": (
            "Golden bge-small-en-v1.5 embeddings, computed under the onnxruntime release pinned in "
            "infra/supply-chain/sovereign.lock.txt with the pinned model files below. Locks the embedding "
            "vector space so a model/pooling/backend change that would invalidate stored Qdrant vectors fails "
            "loudly. Regenerate ONLY with `python -m sigil.vectors.baseline --write` (it refuses under any "
            "other onnxruntime); previous_vectors is the set it replaced. See "
            "docs/decisions/EMB-1-embedding-baseline-locked-ort.md."
        ),
        "model": old["model"],
        "dim": old["dim"],
        "atol": old["atol"],
        "ort_version": ort,
        "hf_repo": src["repo"],
        "hf_revision": src["revision"],
        "onnx_sha256": src["onnx_sha256"],
        "tokenizer_sha256": src["tokenizer_sha256"],
        "texts": old["texts"],
        "vectors": vectors,
        "previous_vectors": old["vectors"],
    }
    if old.get("ort_version"):
        doc["previous_ort_version"] = old["ort_version"]
    fixture.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    return doc


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m sigil.vectors.baseline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify the fixture against this environment")
    mode.add_argument("--write", action="store_true", help="re-baseline the fixture (locked onnxruntime only)")
    ap.add_argument("--fixture", type=Path, default=FIXTURE)
    ap.add_argument("--lock", type=Path, default=SOVEREIGN_LOCK)
    a = ap.parse_args(argv)
    if a.write:
        doc = write(a.fixture, a.lock)
        print(f"wrote {a.fixture} under onnxruntime {doc['ort_version']} "
              f"(min cosine vs previous {min(_cosines(doc['vectors'], doc['previous_vectors'])):.9f})")
        return 0
    problems = check(a.fixture, a.lock)
    for p in problems:
        print(f"MISMATCH: {p}", file=sys.stderr)
    if not problems:
        print(f"{a.fixture} matches this environment")
    return 1 if problems else 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    sys.exit(main())
