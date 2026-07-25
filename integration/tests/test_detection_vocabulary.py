"""S3 — the Detection Mirror's shared, self-checked bug-class vocabulary + the `vigil detect` verb.

Proves: the detection vocabulary is CLOSED and self-checked (every registered oracle's bug_class is
declared; no orphan class) — the defensive analogue of aegis's verify_registration; the `vigil detect`
command runs the detection mirror standalone; and — the honest-fold guard — importing detection adds NO
bodyless `OracleKind` to CRUCIBLE (the unsound fold we deliberately did NOT do). The shared/specific NAMING
split is asserted EXACTLY: sqli/xss/path_traversal reuse CRUCIBLE's names (one taxonomy); crlf_injection/
cmd_injection are detection-SPECIFIC (CRUCIBLE has no CRLF class and uses `command_injection`); recon.*/
cred.* stay detection-namespaced.

Run: PYTHONPATH=integration python -m pytest integration/tests/test_detection_vocabulary.py -q
"""
import pytest

from vigil_integration.detection.registry import (
    DETECTION_BUG_CLASSES,
    ORACLE_CLASSES,
    detection_bug_classes,
    verify_registration,
)


def test_verify_registration_passes():
    verify_registration()   # every registered oracle's bug_class is declared + resolves; no orphan class


def test_every_registered_oracle_bug_class_is_declared():
    for name, cls in ORACLE_CLASSES.items():
        assert cls.bug_class in DETECTION_BUG_CLASSES, f"{name} bug_class {cls.bug_class!r} undeclared"
    # and every declared class is backed by an oracle (no dead vocabulary)
    covered = {cls.bug_class for cls in ORACLE_CLASSES.values()}
    assert set(DETECTION_BUG_CLASSES) == covered


def test_hallucinated_class_would_fail_the_selfcheck(monkeypatch):
    """A negative control: a registered oracle with an undeclared bug_class must make verify_registration
    raise — proving the self-check is not vacuous."""
    class _Rogue:
        name = "rogue"
        bug_class = "totally.made.up"

        def __init__(self):
            pass
    monkeypatch.setitem(ORACLE_CLASSES, "rogue", _Rogue)
    with pytest.raises(AssertionError, match="undeclared bug_class"):
        verify_registration()


def test_detection_classes_are_namespaced_or_injection_taxonomy():
    for c in DETECTION_BUG_CLASSES:
        assert c.startswith(("recon.", "cred.")) or c in {
            "sqli", "xss", "path_traversal", "crlf_injection", "cmd_injection"
        }, f"unexpected detection class {c!r}"


def test_vigil_detect_cli_runs(capsys):
    from vigil_integration import cli
    # a CLF access log with an unmistakable SQL-tautology injection-shaped request.
    log = ('127.0.0.1 - - [10/Oct/2024:13:55:36 +0000] '
           '"GET /item?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 2326 "-" "sqlmap/1.7"\n')
    import tempfile
    p = tempfile.mktemp(suffix=".log")
    open(p, "w").write(log)
    rc = cli.main(["detect", "--access-log", p])
    out = capsys.readouterr().out
    assert rc == 0
    assert "vigil detect (detection mirror)" in out
    assert "FACTS" in out and "LEADS" in out and "declared detection classes" in out


def test_no_bodyless_oraclekind_and_shared_taxonomy():
    """The honest-fold guard: importing the detection mirror must NOT grow CRUCIBLE's OracleKind/_ALL_ORACLES
    (we did not add bodyless kinds), the injection classes SHARE CRUCIBLE's names (one taxonomy), and
    recon.*/cred.* stay detection-namespaced (never collide with a CRUCIBLE offense class). Offense-side —
    skips when framework is absent (the sovereign suite)."""
    verifier = pytest.importorskip("framework.v2.verify.verifier")
    import vigil_integration.detection.registry  # noqa: F401 — the import under test
    assert len(verifier._ALL_ORACLES) == 15, "detection must add NO bodyless kind to the frozen fallback"
    known = verifier.known_bug_classes()
    # The EXACT shared/specific split (the honesty claim, now tested — not just asserted in a docstring):
    #   sqli/xss/path_traversal genuinely reuse CRUCIBLE's names (one taxonomy across offense + defense);
    for c in ("sqli", "xss", "path_traversal"):
        assert c in known, f"{c!r} is claimed shared with CRUCIBLE but is not a CRUCIBLE class"
    #   crlf_injection/cmd_injection are detection-SPECIFIC — CRUCIBLE has no CRLF class and uses
    #   `command_injection` (cmd_injection is not even aliased), so they must NOT be treated as shared;
    for c in ("crlf_injection", "cmd_injection"):
        assert c not in known, f"{c!r} is detection-specific but unexpectedly matched a CRUCIBLE class"
    #   recon.*/cred.* are detection-namespaced — never collide with a CRUCIBLE class (no conflation).
    for c in DETECTION_BUG_CLASSES:
        if c.startswith(("recon.", "cred.")):
            assert c not in known, f"detection-namespaced {c!r} must not collide with a CRUCIBLE class"
    assert detection_bug_classes() is DETECTION_BUG_CLASSES
