"""PCR / W6 — the adversarial anti-cheat breaker (hardened per red-pen). A fix that clears the rule + passes
the suite by GAMING them must be caught, WITHOUT false-positiving legit code. Pure (stdlib) → both CI legs."""
from __future__ import annotations

from vigil_integration.remediation.breaker import inspect_fix


def _d(path, added_lines):
    body = "".join(f"+{ln}\n" for ln in added_lines)
    return f"--- a/{path}\n+++ b/{path}\n@@ -1,0 +1,{len(added_lines)} @@\n{body}"


# ---- legit fixes are NOT cheats (near-zero-FP) ----
def test_clean_vuln_fix_is_not_a_cheat():
    diff = ("--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,1 +1,1 @@\n"
            "-    return hashlib.md5(p).hexdigest()\n+    return hashlib.sha256(p).hexdigest()\n")
    assert inspect_fix(diff).cheated is False


def test_bare_dot_skip_is_not_a_cheat_BLOCK1(tmp_path=None):
    # red-pen BLOCK-1: `.skip(` is idiomatic pymongo/stream/iterator code, NOT a test skip
    for legit in ("    docs = db.users.find(scope(u)).skip(page*size).limit(size)",
                  "    self.stream.skip(min(n, MAX))",
                  "    cursor = it.skip(offset)"):
        assert inspect_fix(_d("svc/dao.py", [legit])).cheated is False, legit


def test_pragma_no_cover_on_defensive_code_is_not_a_cheat():
    assert inspect_fix(_d("svc/x.py", ["    raise AssertionError  # pragma: no cover"])).cheated is False


def test_removing_a_suppression_is_fine():
    diff = "--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,1 +1,1 @@\n-    x = md5(p)  # nosec\n+    x = sha256(p)\n"
    assert inspect_fix(diff).cheated is False


# ---- editing tests is a cheat, incl. header-evasion + odd layouts (BLOCK-2) ----
def test_editing_a_test_file_is_a_cheat():
    for path in ("tests/test_config.py", "svc/test_x.py", "app/x_test.py", "conftest.py",
                 "ui/x.spec.ts", "src/__tests__/x.js", "spec/thing_spec.rb", "Tests/FooTest.java"):
        assert inspect_fix(_d(path, ["    assert True"])).cheated, path


def test_header_trick_test_edit_is_caught_via_diff_and_canonical_paths():
    # tab-timestamp + git-quoted headers must NOT evade the test-file check
    tab = "--- a/svc/test_x.py\t2024-01-01\n+++ b/svc/test_x.py\t2024-01-01 00:00:01\n@@ -1,1 +1,1 @@\n-x\n+y\n"
    assert inspect_fix(tab).cheated
    quoted = '--- "a/svc/test_x.py"\n+++ "b/svc/test_x.py"\n@@ -1,1 +1,1 @@\n-x\n+y\n'
    assert inspect_fix(quoted).cheated
    # and when the CALLER supplies canonical paths, evasion in the raw header is irrelevant
    assert inspect_fix("+++ garbage\n+ noise\n", changed_paths=["svc/test_x.py"]).cheated


# ---- skips / config-disabling / suppressions ----
def test_test_skip_forms_are_cheats():
    for ln in ("@pytest.mark.skip(reason='later')", "@pytest.mark.xfail", "    pytest.skip('x')",
               "    self.skipTest('x')", "    raise unittest.SkipTest", "    raise SkipTest"):
        assert inspect_fix(_d("svc/x.py", [ln])).cheated, ln
    # jest it.skip in a NON-test file is a legit variable call, NOT a cheat (near-zero-FP)
    assert inspect_fix(_d("svc/dao.py", ["    it.skip('x')"])).cheated is False
    # but a jest skip in a TEST file is caught by the test-file-edit signal
    assert inspect_fix(_d("ui/x.test.ts", ["    it.skip('x', () => {})"])).cheated


def test_config_based_test_disabling_is_a_cheat():
    for ln in ("addopts = -k nomatch --ignore=tests/test_vuln.py", "    --deselect tests/test_vuln.py::t",
               "--ignore-glob=**/test_vuln*"):
        assert inspect_fix(_d("pyproject.toml", [ln])).cheated, ln


def test_argparse_ignore_flag_is_not_a_config_cheat():
    # a legit CLI flag named --ignore-case / --ignore-errors must NOT read as a pytest-collection disable
    for ln in ('    parser.add_argument("--ignore-case", action="store_true")',
               '    subprocess.run(["grep", "--ignore-case", pattern])',
               '    opts = ["-k", "aes"]  # a key-size list, not pytest -k'):
        assert inspect_fix(_d("svc/cli.py", [ln])).cheated is False, ln


def test_security_suppression_forms_are_cheats():
    for supp in ("# nosec", "# semgrep:ignore", "# nosemgrep",
                 "// nosemgrep", "// eslint-disable-next-line", "/* eslint-disable */"):
        assert inspect_fix(_d("svc/x.py", [f"    y = bad(p)  {supp}"])).cheated, supp


def test_type_and_style_directives_are_not_suppression_cheats_BLOCKB():
    # red-pen BLOCK-B: type/style directives have legit uses in a real fix — NOT cheats (near-zero-FP)
    for supp in ("# type: ignore[assignment]", "# noqa: E402", "# pragma: no cover", "# pylint: disable=too-many-locals"):
        assert inspect_fix(_d("svc/x.py", [f"    sock = cast(Sock, raw)  {supp}"])).cheated is False, supp


def test_rename_or_copy_of_a_test_file_is_a_cheat_BLOCKA():
    # red-pen BLOCK-A: a git-extended rename/copy carries NO +++/--- pair, so it evades changed_paths AND
    # _diff_targets — but `git apply` honors it, so renaming a test out of collection greens the suite.
    rename_away = ("diff --git a/svc/config.py b/svc/config.py\n"
                   "--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,1 +1,1 @@\n-md5\n+sha256\n"
                   "diff --git a/tests/test_x.py b/tests/x_disabled.txt\n"
                   "similarity index 100%\nrename from tests/test_x.py\nrename to tests/x_disabled.txt\n")
    v = inspect_fix(rename_away, changed_paths=["svc/config.py"])   # caller path set omits the renamed test
    assert v.cheated, v.reason
    assert "RENAME" in v.reason.upper()
    # a copy that duplicates a test file under a non-collected name is likewise flagged
    copy_diff = ("diff --git a/app/test_auth.py b/app/auth_bak.txt\n"
                 "similarity index 100%\ncopy from app/test_auth.py\ncopy to app/auth_bak.txt\n")
    assert inspect_fix(copy_diff, changed_paths=[]).cheated
    # a benign rename of a PRODUCTION module (no test involved) is NOT a cheat
    prod_rename = ("diff --git a/svc/old.py b/svc/new.py\nrename from svc/old.py\nrename to svc/new.py\n")
    assert inspect_fix(prod_rename, changed_paths=[]).cheated is False


def test_binary_patch_of_a_test_file_is_a_cheat_BLOCKA2():
    # red-pen 3rd-pass: a `GIT binary patch` block also carries NO +++/--- pair and git apply honors it, so a
    # fix could overwrite a test's assertions via binary bytes. Derived from the `diff --git` header, it is caught.
    binpatch = (
        "diff --git a/svc/config.py b/svc/config.py\n"
        "--- a/svc/config.py\n+++ b/svc/config.py\n@@ -1,1 +1,1 @@\n-x = 1\n+x = 2\n"
        "diff --git a/tests/test_x.py b/tests/test_x.py\n"
        "index 70a318c0346b5412bf480aac6c116389113c0e55..10bb558f92e2605d58a3af1a29ced7befe7f5dff 100644\n"
        "GIT binary patch\ndelta 12\nTcmY#VVq};g!x~aln#u(L4kZGi\n\nliteral 34\n"
        "ncmYdEO;adIEiQ>KE6vH%(6r)G0D{Eg;?$xN1-HbU;#4jG#*PZ`\n")
    # caller's canonical path set omits the binary-patched test (no +++/--- pair) — exactly the evasion
    v = inspect_fix(binpatch, changed_paths=["svc/config.py"])
    assert v.cheated, v.reason
    assert "test_x.py" in v.reason
    # a mode-change-only block targeting a test (no hunk) is likewise caught via the diff --git header
    modechg = ("diff --git a/tests/test_y.py b/tests/test_y.py\nold mode 100644\nnew mode 100755\n")
    assert inspect_fix(modechg, changed_paths=[]).cheated
    # a binary patch of a PRODUCTION asset (no test) is NOT a cheat
    prod_bin = ("diff --git a/assets/logo.png b/assets/logo.png\nGIT binary patch\ndelta 3\nzcmXyz\n")
    assert inspect_fix(prod_bin, changed_paths=["assets/logo.png"]).cheated is False


def test_spec_and_apidir_production_files_are_not_test_edits_BLOCKB():
    # red-pen BLOCK-B: a bare `spec/` dir is an OpenAPI/AsyncAPI spec tree, not RSpec — NOT a test edit
    for path in ("spec/openapi.yaml", "api/spec/schema.json", "contracts/spec/payments.yaml"):
        assert inspect_fix(_d(path, ["  title: x"])).cheated is False, path
    # ...but a real RSpec file (by filename) IS still caught
    assert inspect_fix(_d("spec/models/user_spec.rb", ["  it 'x'"])).cheated


def test_rule_named_suppression_is_a_cheat():
    assert inspect_fix(_d("svc/x.py", ["    z = 1  # allow DAA-WEAK-HASH here"]), rule_id="DAA-WEAK-HASH").cheated


# ---- totality ----
def test_total_on_non_string_and_garbage():
    for bad in (None, b"bytes", 123, ["a"], ""):
        assert inspect_fix(bad).cheated is False
    assert inspect_fix("not a diff at all").cheated is False
