#!/usr/bin/env python3
"""Fail the P5 job unless the LIVE OTLP export proof ACTUALLY executed (it must not silently skip).

``integration/tests/test_live_otel_export.py`` guards itself with ``pytest.importorskip("opentelemetry...")``.
Before the opt-in OTel hash lock (``infra/supply-chain/otel.lock.txt``) no CI job installed the exporter, so
that whole file — the emit-only / loopback-only / secret-free / deterministic proofs of the F11 OTLPSink, and
the one test that pushes a REAL span through the REAL exporter to a loopback endpoint — SKIPPED on every run.
A skipped proof and a passing proof are the same colour on a dashboard.

P5 now installs the lock under ``--require-hashes``. This reads the JUnit XML the sovereign pytest leg wrote
and exits non-zero unless every named export proof is present AND was not skipped/errored/failed — so if the
lock install, the exporter import, or the file itself ever regresses into a skip, the required job goes RED.

Usage: assert_otel_export_ran.py <junit.xml>

Matched by test-function NAME plus a classname substring (the same rule as assert_boundary_proof_ran.py).
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

_CLASS = "test_live_otel_export"

# (required test-function name, substring its JUnit classname must contain).
REQUIRED: tuple[tuple[str, str], ...] = (
    # a REAL span reaches a loopback OTLP endpoint through the REAL opentelemetry exporter (end to end)
    ("test_a_real_span_arrives_at_a_loopback_endpoint_through_the_real_exporter", _CLASS),
    # the records handed to the exporter are genuine opentelemetry ReadableSpans
    ("test_records_export_to_the_injected_exporter_as_readable_spans", _CLASS),
    # no secret survives to the exported span OR the OTLP wire encoding
    ("test_secrets_never_reach_the_exported_span_or_the_wire", _CLASS),
    # the composite sovereign invariant: emit-only, loopback-only, secret-free, deterministic, total
    ("test_sovereign_invariant_otlp_sink_emit_only_loopback_secret_free_deterministic_total", _CLASS),
)

_NON_EXECUTED = ("skipped", "error", "failure")


def _testcases(path: str) -> list[ET.Element]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        sys.exit(f"::error::cannot read the OTLP-export JUnit report {path!r}: {exc}")
    return list(root.iter("testcase"))


def evaluate(cases: list[ET.Element]) -> list[str]:
    """Human-readable problems; empty means every export proof executed cleanly."""
    problems: list[str] = []
    for name, classname_sub in REQUIRED:
        matches = [
            c
            for c in cases
            if (c.get("name") == name or (c.get("name") or "").startswith(name + "["))
            and classname_sub in (c.get("classname") or "")
        ]
        if not matches:
            problems.append(f"OTLP export proof {name!r} was NOT collected — it did not run at all")
            continue
        for c in matches:
            not_run = [child.tag for child in c if child.tag in _NON_EXECUTED]
            if not_run:
                problems.append(f"OTLP export proof {name!r} did not execute cleanly (found {not_run})")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.exit("usage: assert_otel_export_ran.py <junit.xml>")
    problems = evaluate(_testcases(argv[1]))
    if problems:
        for p in problems:
            print(f"::error::{p}")
        print(
            "::error::the live OTLP export proof did not actually execute — is infra/supply-chain/otel.lock.txt "
            "still installed in this job? Refusing to pass (a skipped proof is not a passing proof)"
        )
        return 1
    print(f"live OTLP export proof executed: {len(REQUIRED)}/{len(REQUIRED)} proofs ran, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
