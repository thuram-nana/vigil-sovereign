"""atheris coverage-guided fuzz harness — spine-record parser + verifier family (W11-3, issue #484).

Target: ``vigil_core`` — ``ChainEntry`` (the pydantic RECORD PARSER for one hash-linked spine entry) and
``verify_chain`` / ``build_chain`` (the tamper-evidence VERIFIER). This is the substrate the whole
audit spine's integrity rests on, so it is in the security-critical set.

The fuzzed INVARIANTS:
  * PARSER TOTALITY — arbitrary parsed dicts go through ``ChainEntry.model_validate``; a malformed record
    raises only ``ValidationError`` (the parser doing its job), never another exception.
  * VERIFIER TOTALITY — ``verify_chain`` never raises on ANY list of parsed entries, however garbled.
  * VERIFIER SOUNDNESS — a chain assembled by ``build_chain`` from arbitrary digests ALWAYS verifies
    (the positive direction; the fast test asserts the negative direction — tampering is detected).

Run under atheris (scheduled job): ``python fuzz_spine.py <corpus_dir>``. atheris is imported lazily.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from vigil_core import ChainEntry, build_chain, verify_chain
from vigil_core.canonical import sha256_hex

_PARSE_ERRORS = (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError)
_MAX_ITEMS = 256


def TestOneInput(data: bytes) -> None:  # noqa: N802 — the atheris entry-point name.
    try:
        parsed = json.loads(data.decode("utf-8"))
    except _PARSE_ERRORS:
        return
    items = parsed if isinstance(parsed, list) else [parsed]
    items = items[:_MAX_ITEMS]

    # (A) parser totality + verifier totality over whatever records the fuzzer assembled.
    entries = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            entries.append(ChainEntry.model_validate(item))
        except ValidationError:
            continue  # a malformed record is rejected by the parser — expected.
    verify_chain(entries)  # MUST NOT raise on any parsed entry list (result is not asserted here).

    # (B) verifier soundness (positive direction): a freshly built chain must always verify.
    digests = [sha256_hex(json.dumps(x, sort_keys=True, ensure_ascii=False).encode("utf-8")) for x in items]
    built = build_chain(digests)
    ok, reason = verify_chain(built)
    assert ok, f"a freshly built chain must verify, got {reason!r}"


def _corpus_seeds(corpus_dir: str) -> list[bytes]:
    d = Path(corpus_dir)
    return [p.read_bytes() for p in sorted(d.iterdir()) if p.is_file()] if d.is_dir() else []


def _main() -> None:
    import atheris  # imported lazily: only the scheduled fuzz job has it installed.

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    _main()
