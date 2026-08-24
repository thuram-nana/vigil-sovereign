"""atheris coverage-guided fuzz harness — JSON canonicalisation parser family (W11-3, issue #484).

Target: ``vigil_core.canonical`` — the deterministic canonical-JSON + digest primitives every spine
signature is computed over. A bug here (a non-deterministic serialisation, a digest that disagrees with
the canonical bytes) silently breaks tamper-evidence, so it is squarely in the security-critical set.

The fuzzed INVARIANTS:
  * TOTALITY — arbitrary bytes are decoded/parsed and only the expected parse errors are raised; any
    other exception propagates as a libFuzzer crash (a finding).
  * FIXPOINT — for any JSON-parseable value, ``canonical_json`` is idempotent under a parse round-trip
    (canonicalise -> parse -> canonicalise is byte-identical): the property signatures rely on.
  * DIGEST CONSISTENCY — ``digest_payload(obj) == sha256_hex(canonical_json(obj))``.

Run under atheris (scheduled job): ``python fuzz_json.py <corpus_dir>``. atheris is imported lazily so
this module is importable — and its ``TestOneInput`` replayable over the committed corpus — WITHOUT
atheris installed (that is what the required fast test integration/tests/test_fuzz_corpus_replay.py does).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from vigil_core.canonical import canonical_json, digest_payload, sha256_hex

_PARSE_ERRORS = (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError)


def TestOneInput(data: bytes) -> None:  # noqa: N802 — the atheris entry-point name.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        obj = json.loads(text)
    except _PARSE_ERRORS:
        return  # malformed JSON is legitimately rejected — no OTHER exception is acceptable.
    try:
        once = canonical_json(obj)
        twice = canonical_json(json.loads(once.decode("utf-8")))
    except RecursionError:
        return  # pathological nesting is a resource bound, not a correctness bug.
    assert once == twice, f"canonical_json is not a parse-round-trip fixpoint for {text!r}"
    assert digest_payload(obj) == sha256_hex(once), "digest_payload disagrees with sha256(canonical_json)"


def _corpus_seeds(corpus_dir: str) -> list[bytes]:
    d = Path(corpus_dir)
    return [p.read_bytes() for p in sorted(d.iterdir()) if p.is_file()] if d.is_dir() else []


def _main() -> None:
    import atheris  # imported lazily: only the scheduled fuzz job has it installed.

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    _main()
