"""Doc-truth: three README/guard honesty claims must stay TRUE of the code (W0-8/#403, W0-10/#405, W0-12/#407).

WHY THIS TEST EXISTS. Three README claims had drifted from the code they describe:

  * W0-8 (#403) — the README called the protected-domain guard a "non-disableable hard block", but
    ``hard_guardrail.protected_guard_enabled()`` returns False (guard OFF) when the owner sets
    ``VIGIL_ALLOW_PROTECTED_DOMAINS`` to 1/true/yes/on. It IS owner-disableable (fail-safe default: on).
  * W0-10 (#405) — the README hand-enumerated ~18 terminal-allowlist binaries and said every writer is
    "simply absent", but ``executor._TERMINAL_ALLOWLIST`` is 56 and INCLUDES the write-capable
    ``sort``/``uniq``/``file`` (admitted only under read-only flag allowlists). executor.py's own comment
    even claimed those three are "simply NOT on the allowlist" while the literal below puts them on it.
    FIX: the README list is now GENERATED from ``_TERMINAL_ALLOWLIST`` and this test asserts it cannot drift.
  * W0-12 (#407) — the README said destructive offense tools (metasploit/sqlmap/hydra) require an m-of-n
    threshold sign-off "even against loopback" in the live engine. But ``live.wiring._build_gate`` wires NO
    ``destruction_authority``, so ``conjunctive_decide`` DENIES every destructive action outright there;
    the m-of-n quorum lives only on the code-fix / PR path (``vigil patch --open-pr`` + live-fire).

The test reads README.md + the three source files, derives the allowlist FROM the code so the README cannot
drift, asserts the false phrases are gone and the corrected anchors present, and grounds each correction in a
code fact it can check. Any regression — a false phrase returns, a correction is reverted, or the code the
correction cites stops being true — fails this test.
"""

from __future__ import annotations

import pathlib
import re

from vigil_integration.live.executor import _TERMINAL_ALLOWLIST
from vigil_core.hard_guardrail import protected_guard_enabled

REPO = pathlib.Path(__file__).resolve().parents[2]
README = REPO / "README.md"
EXECUTOR = REPO / "integration" / "vigil_integration" / "live" / "executor.py"
WIRING = REPO / "integration" / "vigil_integration" / "live" / "wiring.py"
GATE = REPO / "packages" / "core" / "vigil_core" / "vigil_core" / "gate.py"


def _text(p: pathlib.Path) -> str:
    assert p.is_file(), f"missing file: {p}"
    return p.read_text(encoding="utf-8")


def _collapsed(p: pathlib.Path) -> str:
    """File text with every run of whitespace collapsed to one space, so a claim the source wraps
    across several lines still matches as a single phrase."""
    return re.sub(r"\s+", " ", _text(p))


# ---------------------------------------------------------------------------
# W0-10 — the README allowlist is GENERATED from the code and cannot drift.
# ---------------------------------------------------------------------------
_BLOCK_RE = re.compile(
    r"BEGIN GENERATED: terminal-allowlist.*?-->(.*?)<!--\s*END GENERATED: terminal-allowlist",
    re.S,
)


def _readme_generated_allowlist() -> set:
    """Parse the machine-generated allowlist block out of the README: the single backtick code-span
    between the BEGIN/END markers, split on whitespace."""
    m = _BLOCK_RE.search(_text(README))
    assert m, "the BEGIN/END GENERATED terminal-allowlist markers are missing from README.md"
    span = re.search(r"`([^`]+)`", m.group(1))
    assert span, "no backtick code-span with the allowlist inside the generated markers"
    return set(span.group(1).split())


def test_readme_terminal_allowlist_is_generated_from_the_code():
    """The README's terminal allowlist must equal ``_TERMINAL_ALLOWLIST`` exactly — derived from the code,
    so a binary added to / removed from the code without regenerating the README fails here."""
    code = set(_TERMINAL_ALLOWLIST)
    readme = _readme_generated_allowlist()
    assert readme == code, (
        f"README terminal allowlist has drifted from executor._TERMINAL_ALLOWLIST — "
        f"only in code: {sorted(code - readme)}; only in README: {sorted(readme - code)}"
    )


def test_negative_control_the_equality_check_catches_drift():
    """Prove the equality assertion is NOT vacuous: the README set must differ from any mutation of the
    code set (drop one / add a foreign binary), and the code set is non-trivially large."""
    code = set(_TERMINAL_ALLOWLIST)
    readme = _readme_generated_allowlist()
    assert len(code) >= 40, f"allowlist implausibly small ({len(code)}) — the derivation is probably broken"
    assert readme != (code - {"ls"}), "equality check is vacuous: it accepted a code set missing 'ls'"
    assert readme != (code | {"curl"}), "equality check is vacuous: it accepted a code set with 'curl' added"


# ---------------------------------------------------------------------------
# The specific FALSE phrases must be GONE (collapsed-whitespace match).
# ---------------------------------------------------------------------------
_FORBIDDEN_README = [
    # W0-8 — the guard is owner-disableable, not a "non-disableable hard block".
    "a non-disableable hard block refuses categorically-forbidden targets",
    # W0-10 — the old hand-enumerated ~18-binary list + the "read/print binaries only" framing.
    "local read/print binaries only",
    "ls cat head tail wc stat pwd whoami id uname echo df du ps uptime grep cut tr",
    "no such binary is on the allowlist, so there is nothing to pin",
    # W0-12 — destructive offense tools are NOT m-of-n-signable in the live engine; they are DENIED.
    "m-of-n threshold sign-off** even against loopback",
]
_FORBIDDEN_EXECUTOR = [
    # the in-code safety comment that contradicted the literal right below it.
    "genuinely exec/write-capable; simply NOT on the allowlist",
    "So the exec/write-capable binaries (sort/uniq/file/env) are DROPPED",
]


def test_false_phrases_are_gone_from_readme():
    body = _collapsed(README)
    for phrase in _FORBIDDEN_README:
        assert phrase not in body, f"false README claim has returned: {phrase!r}"


def test_false_safety_comment_is_gone_from_executor():
    body = _collapsed(EXECUTOR)
    for phrase in _FORBIDDEN_EXECUTOR:
        assert phrase not in body, f"false executor.py safety comment has returned: {phrase!r}"


# ---------------------------------------------------------------------------
# The CORRECTED anchor sentences must be PRESENT (so reverting the fix fails).
# ---------------------------------------------------------------------------
_REQUIRED_README = [
    # W0-8
    "owner-disableable hard block (fail-safe default: on)",
    # W0-12
    "destructive tools are denied in the live engine",
    "vigil patch --open-pr",
]


def test_corrected_anchors_present_in_readme():
    body = _collapsed(README)
    for phrase in _REQUIRED_README:
        assert phrase in body, f"corrected README anchor is missing (fix reverted?): {phrase!r}"


# ---------------------------------------------------------------------------
# Each correction must be GROUNDED in a code fact this test verifies.
# ---------------------------------------------------------------------------
def test_w0_8_code_fact_guard_is_owner_disableable(monkeypatch):
    """The README's 'owner-disableable, fail-safe default: on' matches protected_guard_enabled():
    unset/junk ⇒ enabled (protected); an explicit affirmative ⇒ disabled."""
    monkeypatch.delenv("VIGIL_ALLOW_PROTECTED_DOMAINS", raising=False)
    assert protected_guard_enabled() is True, "fail-safe default must be ON when unset"
    monkeypatch.setenv("VIGIL_ALLOW_PROTECTED_DOMAINS", "banana")
    assert protected_guard_enabled() is True, "a non-affirmative value must stay ON (fail-safe)"
    for affirmative in ("1", "true", "yes", "on", "  ON  "):
        monkeypatch.setenv("VIGIL_ALLOW_PROTECTED_DOMAINS", affirmative)
        assert protected_guard_enabled() is False, f"{affirmative!r} must DISABLE the guard (owner-disableable)"


def test_w0_10_code_fact_write_capable_binaries_are_on_the_allowlist():
    """The README correction cites the truth: sort/uniq/file ARE on the allowlist; env/getent are NOT."""
    code = set(_TERMINAL_ALLOWLIST)
    assert {"sort", "uniq", "file"} <= code, "sort/uniq/file must be on the allowlist (guarded), per the fix"
    for absent in ("env", "printenv", "getent", "xxd", "curl", "bash"):
        assert absent not in code, f"{absent!r} must NOT be on the allowlist"


def test_w0_12_code_fact_live_engine_denies_destructive():
    """The README correction cites two code facts: (1) live.wiring._build_gate wires NO
    destruction_authority into build_offense_gate; (2) conjunctive_decide DENIES a destructive action when
    no destruction gate is wired. Both are asserted from source so they cannot silently regress."""
    wiring = _text(WIRING)
    # isolate the _build_gate function body (from its def to the next top-level def).
    start = wiring.index("def _build_gate(")
    nxt = wiring.index("\ndef ", start + 1)
    body = wiring[start:nxt]
    assert "build_offense_gate(" in body, "sanity: _build_gate must build the offense gate"
    assert "destruction_authority" not in body, (
        "_build_gate now passes a destruction_authority — the live-engine claim (destructive DENIED) is "
        "no longer true; update the README architecture sentence to match"
    )
    gate = _collapsed(GATE)
    assert "destructive action requires a threshold-destruction gate, but none was wired" in gate, (
        "conjunctive_decide no longer DENIES an unwired destructive action — the live-engine claim changed"
    )
