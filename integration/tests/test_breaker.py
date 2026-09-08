"""PCR / W6 — the adversarial anti-cheat breaker. A fix that clears the rule + passes the suite by GAMING
them (editing its tests, skipping tests, suppressing the rule) must be caught. Pure (stdlib) → both CI legs."""
from __future__ import annotations

from vigil_integration.remediation.breaker import inspect_fix


def test_clean_vuln_fix_is_not_a_cheat():
    diff = ("--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,1 +1,1 @@\n"
            "-    return hashlib.md5(p).hexdigest()\n+    return hashlib.sha256(p).hexdigest()\n")
    assert inspect_fix(diff).cheated is False


def test_editing_a_test_file_is_a_cheat():
    for path in ("tests/test_config.py", "svc/test_x.py", "app/x_test.py", "conftest.py", "ui/x.spec.ts"):
        diff = f"--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,1 @@\n-    assert bad()\n+    assert True\n"
        assert inspect_fix(diff).cheated, path


def test_adding_a_test_skip_is_a_cheat():
    diff = ("--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,0 +1,1 @@\n"
            "+@pytest.mark.skip(reason='later')\n")
    assert inspect_fix(diff).cheated
    diff2 = "--- a/svc/x.py\n+++ b/svc/x.py\n@@ -1,0 +1,1 @@\n+    pytest.skip('x')\n"
    assert inspect_fix(diff2).cheated


def test_adding_a_suppression_is_a_cheat():
    for supp in ("# nosec", "# noqa", "# type: ignore", "# semgrep:ignore", "pylint: disable=all", "// nosemgrep"):
        diff = f"--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,0 +1,1 @@\n+    x = md5(p)  {supp}\n"
        assert inspect_fix(diff).cheated, supp


def test_rule_named_suppression_is_a_cheat():
    diff = ("--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,0 +1,1 @@\n"
            "+    y = 1  # allow DAA-WEAK-HASH here\n")
    assert inspect_fix(diff, rule_id="DAA-WEAK-HASH").cheated


def test_empty_or_garbage_diff_is_not_a_cheat():
    assert inspect_fix("").cheated is False
    assert inspect_fix("not a diff at all").cheated is False


def test_removing_a_suppression_is_fine():
    # a fix that REMOVES a suppression (a `-` line) is not a cheat — only ADDED suppressions are
    diff = "--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,1 +1,1 @@\n-    x = md5(p)  # nosec\n+    x = sha256(p)\n"
    assert inspect_fix(diff).cheated is False
