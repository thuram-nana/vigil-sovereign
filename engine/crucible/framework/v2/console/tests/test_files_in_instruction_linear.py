"""``_files_in_instruction`` path-token scan: linear time, and EXACTLY the tokens the legacy ``findall`` gave.

The legacy pattern ``[A-Za-z0-9_][A-Za-z0-9_./-]*\\.[A-Za-z0-9_]+`` rescanned a long run of path characters
with no ``.``+word character in it from every start position: quadratic, so a 1 MiB paste (a base64 blob, a
hash list) into the dev-mode edit instruction froze the whole console for ~17 minutes with the GIL held. The
scan is now one pass per run of path characters; this file holds it to the legacy pattern, kept here as a
literal.
"""
from __future__ import annotations

import itertools
import json
import os
import random
import re
import subprocess
import sys
import types

import pytest

from framework.v2.console import actions

_LEGACY_PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]*\.[A-Za-z0-9_]+")

_TIME_BOUND_S = 2.0
_CHILD_TIMEOUT_S = 30.0

_CHILD = r"""
import json, sys, tempfile, time
from framework.v2.console import actions
case = sys.argv[1]
if case == "dot_free":
    text = "0" * (1 << 20)
elif case == "dots_without_extension":
    text = "a" + "." * (1 << 19) + "/" + "b" * (1 << 19)
elif case == "token_then_tail":
    text = "x.y" + "/a" * (1 << 19)
else:
    raise SystemExit("unknown case " + case)
with tempfile.TemporaryDirectory() as wd:
    t0 = time.perf_counter()
    out = actions._files_in_instruction(wd, text)
    print(json.dumps({"elapsed": time.perf_counter() - t0, "out": out}))
"""


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    return env


def test_every_short_string_tokenizes_as_the_legacy_findall_did():
    # Exhaustive: all 488,281 strings of length <= 8 over the character classes the pattern distinguishes.
    alphabet = ["a", ".", "/", "-", " "]
    total = found = 0
    for n in range(9):
        for chars in itertools.product(alphabet, repeat=n):
            text = "".join(chars)
            want = _LEGACY_PATH_TOKEN_RE.findall(text)
            assert actions._path_tokens(text) == want, repr(text)
            total += 1
            found += bool(want)
    assert total == 488281 and found > 40000


def test_random_instructions_tokenize_as_the_legacy_findall_did():
    rng = random.Random(0xF11E)
    alphabet = ["a", "B", "0", "_", ".", ".", "/", "-", " ", ",", "\n", "src/app.py", "..", "é", "'", ")", "x.y",
                "../etc/passwd", "README.md.", "\x00", "~", "١", ".a"]
    tokens = 0
    for _ in range(8000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        want = _LEGACY_PATH_TOKEN_RE.findall(text)
        assert actions._path_tokens(text) == want, repr(text)
        tokens += len(want)
    for n in range(60):                    # the adversarial shapes at sizes the legacy pattern finishes on
        for text in ("0" * n, "a" + "." * n + "/" + "b" * n, "x.y" + "/a" * n, ".x" * n + "-" * n, "a" * n + ".",
                     "a" * n + ".b", "." * n + "a.b" + "." * n):
            assert actions._path_tokens(text) == _LEGACY_PATH_TOKEN_RE.findall(text), repr(text)
    assert tokens > 8000


def _stub_codefix(monkeypatch) -> None:
    """``_files_in_instruction`` imports ``vigil_integration.remediation.codefix.confined_repo_file`` lazily (the
    console plane never imports the integration package at module load); the engine test leg does not install
    that package, so stand in a guard that refuses what the real one refuses for these inputs (the lexical
    ``is_safe_repo_path`` rule, then an existing regular file whose resolved path stays under the root)."""
    def is_safe_repo_path(path):
        p = path.strip() if isinstance(path, str) else ""
        if not p or p.startswith(("-", "/", "~", "\\")) or ".." in p.replace("\\", "/").split("/"):
            return False, "refused"
        return True, ""

    def confined_repo_file(root, rel):
        ok, _why = is_safe_repo_path(rel)
        if not ok:
            return ""
        local = os.path.join(root, rel.strip())
        if os.path.islink(local):
            return ""
        real_root, real_local = os.path.realpath(root), os.path.realpath(local)
        if os.path.commonpath([real_root, real_local]) != real_root or not os.path.isfile(real_local):
            return ""
        return real_local

    codefix = types.ModuleType("vigil_integration.remediation.codefix")
    codefix.__dict__["is_safe_repo_path"] = is_safe_repo_path
    codefix.__dict__["confined_repo_file"] = confined_repo_file
    monkeypatch.setitem(sys.modules, "vigil_integration", types.ModuleType("vigil_integration"))
    monkeypatch.setitem(sys.modules, "vigil_integration.remediation",
                        types.ModuleType("vigil_integration.remediation"))
    monkeypatch.setitem(sys.modules, "vigil_integration.remediation.codefix", codefix)


def test_named_files_that_exist_are_still_returned(tmp_path, monkeypatch):
    _stub_codefix(monkeypatch)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("hi\n", encoding="utf-8")
    text = "please fix src/app.py (and README.md), not missing.py or ../outside.txt " + "0" * 4096
    assert actions._files_in_instruction(str(tmp_path), text) == ["src/app.py", "README.md"]


def test_files_named_by_random_instructions_are_unchanged(tmp_path, monkeypatch):
    """End to end over a real tree: the token source is the only thing that changed, so the files found
    (order, dedup, the cap of 8) must equal what the legacy ``findall`` led to."""
    _stub_codefix(monkeypatch)
    names = ["a.py", "b.md", "src/app.py", "src/x.y", "x.y", "README.md", "lib/z.js", "c.txt", "d.cfg", "e.toml"]
    for name in names:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("", encoding="utf-8")
    rng = random.Random(0xF11F)
    parts = names + ["missing.py", "../a.py", "-a.py", "/etc/hosts", ".", "/", " ", ", ", "(", ")", "'", "\n", "a",
                     "src/", ".py", "x.y."]
    seps = ["", " ", " ", ", ", "\n", " (", ") ", "'"]
    corpus = ["".join(rng.choice(parts) + rng.choice(seps) for _ in range(rng.randint(0, 40))) for _ in range(1500)]
    got = [actions._files_in_instruction(str(tmp_path), text) for text in corpus]
    monkeypatch.setattr(actions, "_path_tokens", _LEGACY_PATH_TOKEN_RE.findall)
    want = [actions._files_in_instruction(str(tmp_path), text) for text in corpus]
    assert got == want
    assert sum(bool(w) for w in want) > 1000 and sum(len(w) == 8 for w in want) > 10


@pytest.mark.parametrize("case", ["dot_free", "dots_without_extension", "token_then_tail"])
def test_a_megabyte_paste_without_a_file_name_is_scanned_at_once(case):
    # 1 MiB of path characters with no further `.ext`: the legacy findall rescanned the run from every word
    # character (~17 minutes). Run in a child interpreter: a quadratic regex never returns to an assertion.
    try:
        proc = subprocess.run([sys.executable, "-c", _CHILD, case], capture_output=True, text=True,
                              timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"_files_in_instruction({case}) did not finish within {_CHILD_TIMEOUT_S:.0f} s")
    assert proc.returncode == 0, proc.stderr[-2000:]
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert res["out"] == []
    assert res["elapsed"] < _TIME_BOUND_S, f"_files_in_instruction({case}) took {res['elapsed']:.2f} s"


def test_child_harness_refuses_an_unknown_case():
    proc = subprocess.run([sys.executable, "-c", _CHILD, "no-such-case"], capture_output=True, text=True,
                          timeout=_CHILD_TIMEOUT_S, env=_child_env(), check=False)
    assert proc.returncode != 0
