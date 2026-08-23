"""W16-STD-8 — the deliberate refusals are TRUE OF THE CODE, and stay true.

Issue #534 states seven refusals VIGIL makes on purpose and surfaces as strengths in
docs/DELIBERATE-REFUSALS.md:

  1. no detection-evasion / anti-defender / stealth
  2. no C2 / persistence / implants
  3. no lateral movement
  4. AEGIS defensive-only
  5. the scan stays serial
  6. hexstrike-ai vendored NON-RUNNABLE
  7. a JWT x5c (embedded-key) forgery oracle built and REJECTED in review as unsound

This guard makes the FIRST THREE (evasion / C2+persistence / lateral movement — the ones that would be
a *capability in the first-party code* if present) falsifiable by an AST **capability-absence** scan,
and pins the reviewer-facing doc + its surfacing so the claim can never drift away from the code.

Refusals 4-7 have their own live guards elsewhere (AEGIS defensive-only doctrine; the scan-serial
executor; test_vendor_hexstrike_quarantine.py; test_jwt_forgery.py's embedded-key non-fire tests); this
module additionally asserts the *structural marker* of each is still present so a reviewer sees one map.

STDLIB ONLY, imports NEITHER trust domain. It reads first-party source with `ast`/`pathlib` and never
imports `framework.*` or `sigil.*`, so it co-runs safely inside the required P5 job's single process
(the two-env boundary refuses co-loading offense + sovereign, so a source-only scan is the sound shape).

The negative control is in-run: the same scanner is pointed at a fixture that DOES carry an offensive
capability and MUST flag it, and at a benign gating/data twin (tool names in a denylist / a regex — the
shape VIGIL legitimately has) that it MUST NOT flag. That proves the scanner discriminates a real
capability from merely naming a tool, and is not a no-op.
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# First-party PRODUCTION source trees. Tests and fixtures are excluded by the walker (they legitimately
# contain offensive tokens as fixtures). vendor/ is deliberately NOT here — the vendored upstream is
# guarded by test_vendor_hexstrike_quarantine.py, and the whole point of refusal 6 is that it is inert.
_FIRST_PARTY = (
    _REPO / "integration" / "vigil_integration",
    _REPO / "engine" / "crucible" / "framework" / "v2",
    _REPO / "gateway",
    _REPO / "packages" / "core" / "vigil_core",
    _REPO / "apps" / "sigil" / "sigil",
)

# Offense-EXECUTION libraries. Importing one of these IS the capability — VIGIL imports none of them
# (it drives only nmap, via a fixed-argv `subprocess.run`, as a recon sensor).
_OFFENSE_IMPORT_LIBS = frozenset({
    "impacket", "pypsexec", "winrm", "pywinrm", "paramiko", "scapy",
    "pwn", "pwnlib", "pypykatz", "minidump", "empire", "cobaltstrike",
})

# Tokens that, as a STRING LITERAL inside a genuine process-spawn / exec CALL, evidence an actual
# C2 / lateral-movement / credential-theft / evasion / persistence capability being *executed*. Bare
# generic words (e.g. "beacon", "stealth" on their own) are deliberately excluded to stay near-zero-FP;
# the specific, unambiguous spellings below only ever appear in first-party code if the capability is
# real. A tool NAME sitting in a denylist frozenset or a re.compile() pattern is NOT an exec call and is
# correctly ignored — that is the gating/detection shape VIGIL legitimately has.
_EXEC_TOKENS = (
    # C2 / implants
    "cobaltstrike", "cobalt_strike", "sliver", "mythic", "havoc", "brute_ratel",
    "merlin", "covenant", "poshc2", "meterpreter",
    # lateral movement / relay / credential theft
    "psexec", "wmiexec", "smbexec", "crackmapexec", "netexec", "secretsdump",
    "mimikatz", "evil-winrm", "responder", "lsassy",
    # reverse / bind shells
    "reverse_shell", "reverse_tcp", "bind_shell", "reverse_https",
    # evasion knobs
    "--stealth", "--tamper", "space2comment", "--proxy-chains", "proxychains",
    # persistence
    "authorized_keys", "crontab -", "schtasks /create",
)

# Exec-primitive method names when called as `subprocess.<m>(...)` / `os.<m>(...)`.
_SUBPROCESS_METHODS = frozenset({"run", "popen", "call", "check_call", "check_output", "getoutput"})
_OS_EXEC_METHODS = frozenset({
    "system", "popen", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe", "spawnl", "spawnv", "posix_spawn",
})
# Bare exec-primitive names (imported directly).
_BARE_EXEC_NAMES = frozenset({"Popen", "run", "check_output", "check_call", "call"})


def _rel(p: Path) -> str:
    """Repo-relative display path, falling back to the absolute path for a fixture tree outside it."""
    try:
        return p.relative_to(_REPO).as_posix()
    except ValueError:
        return p.as_posix()


def _iter_first_party_py(roots=_FIRST_PARTY):
    """Every first-party production .py file, excluding tests/fixtures/pycache. Exclusion is computed
    relative to the scanned ROOT (not the repo), so it works for both the real trees and a tmp fixture
    tree in a negative-control run."""
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*.py"):
            parts = p.relative_to(root).parts
            if "tests" in parts or "test" in parts or "__pycache__" in parts:
                continue
            if p.name.startswith("test_") or p.name.startswith("conftest"):
                continue
            yield p


def _module_head(node: ast.AST) -> str | None:
    if isinstance(node, ast.Import):
        return node.names[0].name.split(".")[0] if node.names else None
    if isinstance(node, ast.ImportFrom):
        return (node.module or "").split(".")[0]
    return None


def _is_exec_call(call: ast.Call) -> bool:
    f = call.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        if f.value.id == "subprocess" and f.attr in _SUBPROCESS_METHODS:
            return True
        if f.value.id == "os" and f.attr in _OS_EXEC_METHODS:
            return True
    if isinstance(f, ast.Name) and f.id in _BARE_EXEC_NAMES:
        return True
    return False


def _string_constants(node: ast.AST):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            yield sub.value


def scan_tree_for_offense_capability(roots=_FIRST_PARTY) -> list[str]:
    """Return a list of human-readable offenders. Empty == the refusals hold.

    Flags exactly two things, AST-based so a comment / docstring / denylist / regex never trips it:
      (a) an import of an offense-EXECUTION library (`_OFFENSE_IMPORT_LIBS`);
      (b) a genuine process-spawn / exec call (`subprocess.*` / `os.*exec*` / bare `Popen`/`run`) whose
          literal string arguments name a C2 / lateral / credential-theft tool or an evasion knob
          (`_EXEC_TOKENS`).
    """
    offenders: list[str] = []
    for p in _iter_first_party_py(roots):
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        rel = _rel(p)
        for node in ast.walk(tree):
            head = _module_head(node)
            if head and head in _OFFENSE_IMPORT_LIBS:
                offenders.append(f"{rel}:{getattr(node, 'lineno', '?')}: imports offense-exec library {head!r}")
            if isinstance(node, ast.Call) and _is_exec_call(node):
                for s in _string_constants(node):
                    low = s.lower()
                    hit = next((t for t in _EXEC_TOKENS if t in low), None)
                    if hit is not None:
                        offenders.append(
                            f"{rel}:{getattr(node, 'lineno', '?')}: exec call passes offensive token {hit!r}")
    return offenders


# --------------------------------------------------------------------------------------------------
# The primary assertion — the refusals are TRUE of the first-party code, right now.
# --------------------------------------------------------------------------------------------------
def test_first_party_code_has_no_evasion_c2_or_lateral_capability():
    offenders = scan_tree_for_offense_capability()
    assert offenders == [], (
        "a stated deliberate refusal is now FALSE of the code — first-party source gained an "
        "evasion / C2 / persistence / lateral-movement / credential-theft execution capability:\n  "
        + "\n  ".join(offenders))


# --------------------------------------------------------------------------------------------------
# Negative controls — the scanner is not a no-op, and it discriminates capability from gating/data.
# --------------------------------------------------------------------------------------------------
_FIXTURE_OFFENSIVE = textwrap.dedent(
    '''
    import subprocess
    import impacket  # offense-exec library

    def move_laterally(host, cmd):
        # a real lateral-movement + evasion capability
        subprocess.run(["cobaltstrike", "--stealth", "--tamper=space2comment"])
        subprocess.Popen(["wmiexec", host, cmd])

    def persist():
        subprocess.run(["sh", "-c", "echo key >> ~/.ssh/authorized_keys"])
    '''
)

# The BENIGN twin: the *legitimate* shape VIGIL has — the exact same tool names, but only inside a
# denylist frozenset (to GATE them) and a regex (to DETECT them). No exec call, no offense import.
_FIXTURE_BENIGN_GATING = textwrap.dedent(
    '''
    import re

    _DESTRUCTIVE_TOOLS = frozenset({"cobaltstrike", "wmiexec", "psexec", "mimikatz", "responder"})
    _EVASION = re.compile(r"stealth|--tamper|space2comment|proxychains")

    def classify(tool_name):
        """A pure classifier — names the tools only to FLOOR/gate them; runs nothing."""
        return tool_name.lower() in _DESTRUCTIVE_TOOLS

    def note():
        return "reverse_shell and authorized_keys are refused; see docs/DELIBERATE-REFUSALS.md"
    '''
)


def test_negative_control_a_planted_capability_is_flagged(tmp_path):
    (tmp_path / "evil.py").write_text(_FIXTURE_OFFENSIVE, encoding="utf-8")
    offenders = scan_tree_for_offense_capability(roots=(tmp_path,))
    assert offenders, "scanner FAILED to flag a planted offensive capability — it is a no-op"
    joined = " ".join(offenders)
    assert "impacket" in joined            # (a) the offense-exec import
    assert "cobaltstrike" in joined or "wmiexec" in joined  # (b) the exec-of-tool
    # and it names the file/line, so a reviewer can find it
    assert "evil.py" in joined


def test_negative_control_benign_gating_and_detection_is_not_flagged(tmp_path):
    """The SAME tool names in a denylist frozenset + a regex must NOT be flagged. This is what proves
    the scanner discriminates a real capability from the gating/detection shape VIGIL legitimately has
    (tools/governance.py, proof/content_gate.py) — otherwise the primary assertion would be a
    false-positive machine, not a guard."""
    (tmp_path / "benign_gate.py").write_text(_FIXTURE_BENIGN_GATING, encoding="utf-8")
    offenders = scan_tree_for_offense_capability(roots=(tmp_path,))
    assert offenders == [], f"benign gating/detection code was wrongly flagged: {offenders}"


def test_negative_control_planting_into_a_real_first_party_style_tree(tmp_path):
    """End-to-end shape of the guard: a first-party-style package that is clean passes; the moment an
    offensive module is added to it, the SAME primary scan turns red."""
    pkg = tmp_path / "vigil_integration"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (pkg / "safe.py").write_text("import os\n\ndef f():\n    return os.getcwd()\n", encoding="utf-8")
    assert scan_tree_for_offense_capability(roots=(tmp_path,)) == []   # clean
    (pkg / "c2.py").write_text(_FIXTURE_OFFENSIVE, encoding="utf-8")
    assert scan_tree_for_offense_capability(roots=(tmp_path,)) != []   # capability added -> red


# --------------------------------------------------------------------------------------------------
# The doc is real, complete, and surfaced — so the "strength" claim can't drift from the code.
# --------------------------------------------------------------------------------------------------
_DOC = _REPO / "docs" / "DELIBERATE-REFUSALS.md"


def test_deliberate_refusals_doc_exists_and_states_all_seven():
    assert _DOC.is_file(), "docs/DELIBERATE-REFUSALS.md is missing"
    text = _DOC.read_text(encoding="utf-8")
    # the seven numbered refusal headings
    for n in range(1, 8):
        assert f"### {n}." in text, f"refusal #{n} heading missing from DELIBERATE-REFUSALS.md"
    # each refusal must carry its reasoning — a 'strength'/'why' rationale, not a bare list
    assert "strength" in text.lower()
    for kw in ("evasion", "C2", "persistence", "lateral", "defensive-only",
               "serial", "NON-RUNNABLE", "x5c"):
        assert kw in text, f"DELIBERATE-REFUSALS.md does not state refusal keyword {kw!r}"


def test_deliberate_refusals_doc_is_surfaced_from_readme_and_posture():
    readme = (_REPO / "README.md").read_text(encoding="utf-8")
    posture = (_REPO / "docs" / "POSTURE.md").read_text(encoding="utf-8")
    assert "DELIBERATE-REFUSALS" in readme, "README does not surface DELIBERATE-REFUSALS.md"
    assert "DELIBERATE-REFUSALS" in posture, "POSTURE.md does not surface DELIBERATE-REFUSALS.md"


# --------------------------------------------------------------------------------------------------
# Structural markers of refusals 4-7 — one map for the reviewer; each has its own live guard too.
# --------------------------------------------------------------------------------------------------
def test_refusal4_aegis_declares_defensive_only():
    gw = (_REPO / "engine/crucible/framework/v2/aegis/gateway.py").read_text(encoding="utf-8")
    assert "DEFENSIVE ONLY" in gw and "never attacks" in gw


def test_refusal5_scan_engine_declares_itself_serial():
    ex = (_REPO / "integration/vigil_integration/live/executor.py").read_text(encoding="utf-8")
    assert "the engine loop is serial" in ex


def test_refusal6_hexstrike_upstream_is_reference_only_and_not_runnable():
    vend = _REPO / "vendor" / "hexstrike-ai"
    assert (vend / "hexstrike_server.py.reference").is_file()
    assert not (vend / "hexstrike_server.py").exists()
    assert not (vend / "hexstrike_mcp.py").exists()


def test_refusal7_x5c_rejection_breadcrumb_is_recorded_in_the_oracle():
    oracles = (_REPO / "engine/crucible/framework/v2/verify/oracles.py").read_text(encoding="utf-8")
    assert "DELIBERATELY NOT a fire path" in oracles
    assert "x5c" in oracles and "RFC 7515" in oracles  # the unsoundness argument, recorded in code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
