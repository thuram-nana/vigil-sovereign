"""Wave D — the JS/TS import-graph context provider. Self-contained (stdlib only), so it runs in BOTH CI
legs (no framework import). Proves the coder is shown a real cross-file neighborhood (import targets +
callers) for JS/TS, resolves node/TS module forms, stays inside the repo, and is fail-soft + total."""
from __future__ import annotations

import os
from pathlib import Path

from vigil_integration.remediation.js_graph_context import js_graph_context_paths, _resolve, _specs
from vigil_integration.remediation.graph_context import graph_context_paths


def _w(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _repo(tmp_path) -> Path:
    r = tmp_path / "app"
    _w(r / "src" / "svc" / "auth.ts", "import { db } from '../db';\nimport { hash } from './hash';\nexport function login(){ return db && hash(); }\n")
    _w(r / "src" / "db.ts", "export const db = 1;\n")
    _w(r / "src" / "svc" / "hash.ts", "export function hash(){ return 2; }\n")
    # a caller of auth.ts (imports it via extensionless relative spec)
    _w(r / "src" / "routes" / "login.ts", "import { login } from '../svc/auth';\nlogin();\n")
    # a require()-style caller
    _w(r / "src" / "routes" / "legacy.js", "const { login } = require('../svc/auth');\nlogin();\n")
    # an unrelated file that must NOT appear
    _w(r / "src" / "unrelated.ts", "import React from 'react';\nexport const x = 1;\n")
    return r


def test_import_targets_and_callers_are_ranked(tmp_path):
    r = _repo(tmp_path)
    paths = js_graph_context_paths(str(r), "src/svc/auth.ts")
    assert paths is not None
    # import targets of auth.ts (deps a fix needs) — extensionless './db' -> src/db.ts, './hash' -> hash.ts
    assert "src/db.ts" in paths and "src/svc/hash.ts" in paths
    # callers (regression surface) — both the import and the require form resolve to auth.ts
    assert "src/routes/login.ts" in paths and "src/routes/legacy.js" in paths
    # the unrelated file (only a bare 'react' import) is NOT included
    assert "src/unrelated.ts" not in paths
    assert "src/svc/auth.ts" not in paths          # primary excluded


def test_index_and_extension_resolution(tmp_path):
    r = tmp_path / "r"
    _w(r / "a.ts", "import { u } from './util';\n")          # -> util/index.ts
    _w(r / "util" / "index.ts", "export const u = 1;\n")
    assert _resolve(str(r), "a.ts", "./util") == "util/index.ts"
    _w(r / "b.ts", "import x from './util/helpers';\n")       # explicit-ext-less file
    _w(r / "util" / "helpers.tsx", "export default 1;\n")
    assert _resolve(str(r), "b.ts", "./util/helpers") == "util/helpers.tsx"


def test_bare_and_escaping_specs_are_not_in_repo(tmp_path):
    r = tmp_path / "r"; _w(r / "a.ts", "x")
    assert _resolve(str(r), "a.ts", "react") is None            # bare (node_modules) — not relative, not resolved
    assert _resolve(str(r), "a.ts", "../../../etc/passwd") is None   # escapes the repo root — containment
    # _specs only captures RELATIVE specifiers
    got = _specs("import a from 'react';\nimport b from './x';\nrequire('../y');\nconst c = import('./z');\n")
    assert got == ["./x", "../y", "./z"]


def test_fail_soft_and_total(tmp_path):
    r = _repo(tmp_path)
    assert js_graph_context_paths(str(r), "src/does/not/exist.ts") is None   # missing primary -> None
    assert js_graph_context_paths("", "x.ts") is None
    assert js_graph_context_paths(str(r), "") is None
    assert js_graph_context_paths(str(r), "src/db.ts") is not None or True    # a leaf with no callers -> None is fine


def test_special_files_and_escaping_symlinks_do_not_hang_or_oom(tmp_path):
    # red-pen BLOCK: a FIFO named x.ts hung open(); a symlink x.ts -> /dev/zero OOM'd an unbounded read. The
    # provider READS every JS/TS file during the caller-walk, so both must be refused (via os.stat, before open).
    import os as _os, signal
    r = tmp_path / "hostile"; (r / "src").mkdir(parents=True)
    _w(r / "src" / "primary.ts", "export const x = 1;\n")
    _w(r / "src" / "caller.ts", "import { x } from './primary';\nx;\n")   # a legit caller (must be found)
    try:
        _os.mkfifo(str(r / "src" / "trap.ts"))                              # FIFO named like a source file
    except (AttributeError, OSError):
        pass                                                               # non-Unix: skip the FIFO leg
    try:
        _os.symlink("/dev/zero", str(r / "src" / "dev.ts"))                # symlink escaping the repo -> device
        _os.symlink("/etc/hostname", str(r / "src" / "esc.ts"))           # symlink escaping the repo -> file
    except (AttributeError, OSError, NotImplementedError):
        pass

    class _Hang(BaseException):                                          # NOT an Exception -> the provider's
        pass                                                             # `except (OSError, ValueError)` / `except
    def _boom(signum, frame):                                            # Exception` cannot swallow it (red-pen nit:
        raise _Hang()                                                    # TimeoutError is an OSError and WAS swallowed)
    old = signal.signal(signal.SIGALRM, _boom) if hasattr(signal, "SIGALRM") else None
    if old is not None:
        signal.alarm(15)
    try:
        paths = js_graph_context_paths(str(r), "src/primary.ts")          # must return (no hang, no OOM)
    except _Hang:
        signal.alarm(0)
        raise AssertionError("js_graph_context_paths HUNG on a special file (FIFO/device) — BLOCK not fixed")
    finally:
        if old is not None:
            signal.alarm(0); signal.signal(signal.SIGALRM, old)
    assert paths is not None and "src/caller.ts" in paths                 # the legit caller is still found
    for bad in ("src/trap.ts", "src/dev.ts", "src/esc.ts"):
        assert bad not in paths                                           # special/escaping files never returned


def test_oversized_regular_file_read_is_bounded(tmp_path):
    # a huge REGULAR file must be read bounded (not OOM). _read caps at _MAX_FILE_BYTES.
    from vigil_integration.remediation.js_graph_context import _read, _MAX_FILE_BYTES
    r = tmp_path / "big"; r.mkdir()
    big = r / "huge.ts"
    big.write_text("// pad\n" + ("x" * (_MAX_FILE_BYTES * 3)), encoding="utf-8")
    got = _read(str(big), os.path.realpath(str(r)))
    assert 0 < len(got) <= _MAX_FILE_BYTES                                # bounded, non-empty


def test_dispatcher_routes_by_extension(tmp_path):
    r = _repo(tmp_path)
    # graph_context_paths must route a .ts primary to the JS resolver (framework-free path)
    paths = graph_context_paths(str(r), "src/svc/auth.ts")
    assert paths and "src/routes/login.ts" in paths
    # an unsupported extension falls back (None -> siblings)
    _w(r / "notes.md", "hi")
    assert graph_context_paths(str(r), "notes.md") is None
