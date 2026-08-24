"""atheris coverage-guided fuzz harness — HTTP request parser family (W11-3, issue #484).

Target: ``framework.v2.aegis.inspect`` — the AEGIS Gateway's inline HTTP request inspector. It PARSES a
live request's injection surfaces (query string, Cookie header, JSON / urlencoded / multipart body,
curated free-text headers) via ``candidate_values`` and runs the deterministic request-side oracles via
``inspect_request``. This is the "provable firewall"'s front door — arbitrary attacker-controlled bytes
reach it — so it is in the security-critical set.

The fuzzed INVARIANTS:
  * TOTALITY — both ``candidate_values`` and ``inspect_request`` are documented pure/total; on ANY input
    they must return (never raise). A raise is a libFuzzer crash (a finding).
  * BOUNDEDNESS — the parser never emits more than the documented ``_MAX_VALUES`` insertion points, so a
    parameter/cookie/header flood cannot blow up downstream oracle work.
  * VERDICT SOUNDNESS — a CONFIRMED verdict always carries a re-runnable certificate (the model
    invariant, re-checked here as defence in depth against a parser path that fabricates a block).

Run under atheris (scheduled job): ``python fuzz_http.py <corpus_dir>``. atheris is imported lazily, and
``framework`` is imported at module load, so this harness is importable only where the offense engine is
on the path (the offense CI leg / the scheduled fuzz job) — matching the two-env boundary.
"""
from __future__ import annotations

import sys
from pathlib import Path

from framework.v2.aegis.inspect import _MAX_VALUES, candidate_values, inspect_request


def _split_request(data: bytes) -> tuple[str, list[tuple[str, str]], str | None]:
    """Deterministically carve fuzz bytes into (path, headers, body): line 0 -> path, line 1 -> one
    ``name:value`` header, remainder -> body."""
    blob = data.decode("utf-8", errors="replace")
    parts = blob.split("\n", 2)
    raw_path = parts[0]
    path = raw_path if raw_path.startswith("/") else "/" + raw_path
    headers: list[tuple[str, str]] = []
    if len(parts) > 1 and ":" in parts[1]:
        k, _, v = parts[1].partition(":")
        headers = [(k[:64], v[:1024])]
    body = parts[2] if len(parts) > 2 else None
    return path, headers, body


def TestOneInput(data: bytes) -> None:  # noqa: N802 — the atheris entry-point name.
    path, headers, body = _split_request(data)

    values = candidate_values(path, headers, body)          # parser: total + bounded
    assert isinstance(values, list)
    assert len(values) <= _MAX_VALUES, f"candidate_values exceeded the {_MAX_VALUES} bound: {len(values)}"

    verdict = inspect_request("POST", path, headers, body)  # detector: total, returns Verdict | None
    if verdict is not None and verdict.decision == "confirmed":
        assert verdict.certificate is not None, "a confirmed verdict MUST carry a re-runnable certificate"


def _corpus_seeds(corpus_dir: str) -> list[bytes]:
    d = Path(corpus_dir)
    return [p.read_bytes() for p in sorted(d.iterdir()) if p.is_file()] if d.is_dir() else []


def _main() -> None:
    import atheris  # imported lazily: only the scheduled fuzz job has it installed.

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    _main()
