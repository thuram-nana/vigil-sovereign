"""S2 — the ONE WARDEN classifier of record (`vigil_core.warden_tiers`), the byte-faithful Python port of
the Rust kernel classifier (`apps/sigil/kernel/src/tiers.rs`).

Pins the Python classifier to the SHARED golden vectors (`vigil_core/warden_golden.json`) — the SAME file
the Rust unit test (`tiers::tests::matches_shared_golden_vectors`) loads, so the two classifiers cannot
drift. Plus the danger-first / substring-collision / fail-closed / HID spec assertions mirrored from the
Rust tests, and the `has_danger_token` + `gate` contracts.

Run: pytest packages/core/vigil_core/tests/test_warden_tiers.py -q
"""
import json
from pathlib import Path

import vigil_core
from vigil_core.warden_tiers import Tier, classify, gate, has_danger_token

_GOLDEN = json.loads((Path(vigil_core.__file__).parent / "warden_golden.json").read_text())["vectors"]


def test_matches_the_shared_golden_vectors():
    """The Python port classifies every shared golden vector exactly as the tier the Rust kernel asserts."""
    mismatches = [(tool, want, classify(tool).label) for tool, want in _GOLDEN if classify(tool).label != want]
    assert not mismatches, f"drift from the shared golden: {mismatches}"
    assert len(_GOLDEN) >= 70, "the golden set must be comprehensive (incl. the tokenizer boundary)"


def test_c0_separator_cannot_hide_a_danger_token():
    """S2 red-pen BLOCK: a destructive token hidden behind a C0 information separator (U+001C..1F) must NOT
    smuggle past classification — the tokenizer splits on it (fail-safe direction), so the danger is
    exposed. Both the Python port AND the Rust kernel split on these now (pinned by the golden)."""
    for sep in ("\x1c", "\x1d", "\x1e", "\x1f"):
        assert classify(f"read.log{sep}delete") == Tier.A3, f"U+{ord(sep):04X} must expose the delete token"
        assert classify(f"get.x{sep}drop") == Tier.A3


def test_danger_first_and_substring_collisions():
    # a dangerous op must NOT ride a benign substring down a tier (whole-token matching)
    assert classify("config.overwrite") == Tier.A3        # overwrite != write
    assert classify("files.forget") == Tier.A3            # forget != get; fail-closed
    assert classify("budget.get") == Tier.A3              # financial target is A3 regardless of verb
    assert classify("iam.policy.write") == Tier.A3        # identity write is A3, not A1
    assert classify("transaction.sign") == Tier.A3
    assert classify("secrets.read") == Tier.A3            # secret read is A3, not A0
    assert classify("memory.encrypt") == Tier.A3          # ransomware-shaped op must NOT be A0
    assert classify("snapshot.restore") == Tier.A3        # a restore reverts state → A3
    # danger token wins regardless of order
    assert classify("read.then.delete") == Tier.A3
    assert classify("search.and.deploy") == Tier.A3


def test_a0_only_via_positive_allowlist_and_egress_is_a2():
    assert classify("memory.search") == Tier.A0
    assert classify("graph.entity") == Tier.A0            # exact-name allowlist
    assert classify("memory.write") == Tier.A1
    assert classify("email.send") == Tier.A2
    assert classify("memory.export") == Tier.A2           # full-store egress must be queued, not auto
    assert classify("calendar.write") == Tier.A2          # A2 token beats A1 token


def test_hid_input_tables_and_danger_wins():
    assert classify("hid.pointer.move") == Tier.A1
    assert classify("hid.type") == Tier.A2
    assert classify("hid.pointer.delete") == Tier.A3      # a danger token beats an input name
    assert classify("hid.unknown") == Tier.A3
    assert classify("file.move") == Tier.A3               # bare tokens are never classified → unaffected
    assert classify("data.type") == Tier.A3


def test_unknown_and_empty_fail_closed_a3():
    assert classify("") == Tier.A3
    assert classify("weird") == Tier.A3
    assert classify("something.unclassified") == Tier.A3


def test_has_danger_token_distinguishes_dangerous_from_unknown():
    assert has_danger_token("git.push") and has_danger_token("secrets.read")
    assert not has_danger_token("nmap"), "an unknown recon name carries no danger token"
    assert not has_danger_token("memory.search") and not has_danger_token("")
    # a recon-shaped name with a danger token IS flagged
    assert has_danger_token("nmap.delete")


def test_gate_decisions():
    assert gate(Tier.A0) == "auto" and gate(Tier.A1) == "auto"
    assert gate(Tier.A2) == "queued"
    assert gate(Tier.A3) == "explicit-required"


def test_tier_ordering_matches_rust():
    assert Tier.A0 < Tier.A1 < Tier.A2 < Tier.A3
    assert (Tier.A0 <= Tier.A1) and not (Tier.A2 <= Tier.A1)
