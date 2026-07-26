"""
WS-TOOLS — the external host-tool registry probe + the console ``GET /api/tools`` endpoint.

The load-bearing guarantees pinned here:

  * :func:`probe_tools` reports REAL, live status — a binary that genuinely exists on THIS box
    resolves to ``installed`` with a path; a bogus tool never does. No status is invented.
  * The ``failed`` state is layered from the installer's hint ONLY when the tool is not on PATH,
    and the live probe always overrides a stale ``failed`` hint for a tool that is present.
  * ``alt_binaries`` resolution finds a tool under an alternate name (chromium/zap family).
  * The console route ``/api/tools`` returns the probe shape as JSON, carries the strict CSP,
    and is resilient (never 500s the console).
"""

from __future__ import annotations

import json
import shutil
import threading
import urllib.request
from contextlib import contextmanager

from framework.v2.console import api, server
from framework.v2.tools import registry
from framework.v2.tools.registry import (
    HOST_TOOLS,
    ToolSpec,
    probe_tool,
    probe_tools,
)

# A binary that exists on effectively every POSIX box we run on (the test host included).
_REAL_BINARY = "sh" if shutil.which("sh") else ("ls" if shutil.which("ls") else "python3")
_BOGUS = "vigil-nonexistent-tool-zzz-000"


# ---------------------------------------------------------------------------
# probe_tool / probe_tools — real, live status
# ---------------------------------------------------------------------------


def _fake_bin(dirpath, name, banner):
    """Write an executable that prints `banner` to stdout for any args (a stand-in tool)."""
    p = dirpath / name
    p.write_text("#!/bin/sh\ncat <<'EOF'\n" + banner + "\nEOF\n")
    p.chmod(0o755)
    return str(p)


def test_name_collision_impostor_is_shadowed_not_installed(tmp_path, monkeypatch) -> None:
    # The offense `httpx` (ProjectDiscovery) is commonly shadowed on PATH by the same-named Python
    # httpx HTTP-client CLI. A which-hit whose version banner matches a wrong_markers pattern must be
    # reported `shadowed` (installed=False) — NEVER a false green for a required tool. This is the exact
    # BLOCK the red-pen found; the version banner is the disambiguator.
    import os
    _fake_bin(tmp_path, "collide", "The httpx command line client could not run because ...")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    markers = ("command line client could not run", "no such option")
    spec = ToolSpec(name="collide", binary="collide", optional=False, purpose="collision probe",
                    version_args=("-version",), wrong_markers=markers)
    d = probe_tool(spec, with_version=True, supported=True)
    assert d["status"] == "shadowed" and d["installed"] is False and d["shadowed"] is True
    # positive control: the SAME spec resolving to a binary whose banner does NOT match → installed.
    # (mutation guard: if the banner check were dropped, this stays installed but the impostor above
    #  would wrongly flip to installed too — so the pair pins the disambiguation as load-bearing.)
    _fake_bin(tmp_path, "clean", "clean-tool version 1.2.3")
    ok_spec = ToolSpec(name="clean", binary="clean", optional=False, purpose="clean probe",
                       version_args=("-version",), wrong_markers=markers)
    ok = probe_tool(ok_spec, with_version=True, supported=True)
    assert ok["status"] == "installed" and ok["installed"] is True and ok["shadowed"] is False


def test_probe_tool_installed_for_a_real_binary() -> None:
    spec = ToolSpec(name="realsh", binary=_REAL_BINARY,
                    purpose="a binary that exists on this box", version_args=None)
    d = probe_tool(spec, with_version=False, supported=True)
    assert d["installed"] is True
    assert d["path"] and shutil.which(_REAL_BINARY) == d["path"]
    assert d["status"] == "installed"


def test_probe_tool_missing_for_a_bogus_binary() -> None:
    spec = ToolSpec(name="bogus", binary=_BOGUS, purpose="does not exist")
    d = probe_tool(spec, with_version=True, supported=True)
    assert d["installed"] is False
    assert d["path"] is None
    assert d["status"] == "missing"
    assert d["install_hint"]  # a copyable hint is always present


def test_failed_hint_only_applies_when_not_on_path() -> None:
    # A bogus tool the installer marked 'failed' → status 'failed' (bootstrap tried, couldn't).
    bogus = ToolSpec(name="bogus", binary=_BOGUS, purpose="x")
    d = probe_tool(bogus, supported=True, install_state={"bogus": "failed"})
    assert d["status"] == "failed"
    # A REAL, present tool the hint (wrongly) marked 'failed' → live probe wins → 'installed'.
    real = ToolSpec(name="realsh", binary=_REAL_BINARY, purpose="x", version_args=None)
    d2 = probe_tool(real, supported=True, install_state={"realsh": "failed"})
    assert d2["status"] == "installed"


def test_unsupported_platform_reports_unsupported_never_faked() -> None:
    real = ToolSpec(name="realsh", binary=_REAL_BINARY, purpose="x", version_args=None)
    d = probe_tool(real, supported=False)
    # even though the binary IS on PATH, a non-Linux host reports unsupported (Linux packages).
    assert d["status"] == "unsupported"
    assert d["installed"] is True  # honest: the binary exists, it is just not the supported OS


def test_alt_binaries_resolution_finds_alternate_name() -> None:
    # primary name is bogus, an alternate is a real binary → resolves as installed under the alt.
    spec = ToolSpec(name="alt", binary=_BOGUS, alt_binaries=(_REAL_BINARY,),
                    purpose="x", version_args=None)
    d = probe_tool(spec, with_version=False, supported=True)
    assert d["installed"] is True and d["path"] == shutil.which(_REAL_BINARY)


def test_probe_tools_shape_and_counts_are_consistent() -> None:
    r = probe_tools(with_version=False, install_state={})
    assert set(r) >= {"platform", "tools", "summary", "sandbox", "doctrine"}
    assert isinstance(r["tools"], list) and len(r["tools"]) == len(HOST_TOOLS)
    s = r["summary"]
    assert s["total"] == len(HOST_TOOLS)
    # every tool lands in exactly one status bucket → counts sum to the total (incl. 'shadowed').
    assert s["installed"] + s["missing"] + s["failed"] + s["shadowed"] + s["unsupported"] == s["total"]
    # required_missing counts the non-optional tools that are absent, failed, OR shadowed.
    assert s["required_missing"] <= s["missing"] + s["failed"] + s["shadowed"]
    for t in r["tools"]:
        assert set(t) >= {"name", "binary", "purpose", "optional", "installed", "shadowed",
                          "path", "version", "status", "install_hint"}
        assert t["status"] in ("installed", "missing", "failed", "shadowed", "unsupported")
        # a shadowed tool is NEVER a false green.
        if t["status"] == "shadowed":
            assert t["installed"] is False and t["shadowed"] is True
    # the sandbox roster is informational and clearly separated from the host roster.
    assert r["sandbox"]["image"] and isinstance(r["sandbox"]["tools"], list)
    assert r["sandbox"]["tools"], "the Strix sandbox roster should be surfaced (informational)"


def test_offense_core_tools_are_marked_required() -> None:
    core = {t.name for t in HOST_TOOLS if not t.optional}
    assert core == {"nmap", "httpx", "nuclei", "ffuf", "sqlmap", "hydra"}


def test_emit_shell_preserves_every_field_and_covers_every_tool() -> None:
    dump = registry._emit_shell()
    lines = [ln for ln in dump.splitlines() if ln]
    assert len(lines) == len(HOST_TOOLS)
    sep = registry._SHELL_SEP
    assert sep == "\x1f"  # non-whitespace separator — bash `read` must not collapse empty fields
    for ln in lines:
        cols = ln.split(sep)
        # exactly len(_SHELL_COLUMNS) fields ALWAYS — even a tool with an empty apt/pip/alt keeps
        # its columns aligned (the whole reason the separator is 0x1F and not a tab).
        assert len(cols) == len(registry._SHELL_COLUMNS)
        assert cols[2] in ("0", "1")             # optional flag
        assert "\n" not in ln and "\t" not in ln  # single-line rows, no stray tabs
    # a tool with an EMPTY apt column (semgrep: pip-only) must still expose its manual in column 5.
    row = next(ln for ln in lines if ln.startswith("semgrep" + sep))
    cols = row.split(sep)
    assert cols[3] == "" and cols[4] == "semgrep"   # apt empty, pip=semgrep — not shifted
    assert "pipx install semgrep" in cols[5]         # manual column intact despite the empty apt


# ---------------------------------------------------------------------------
# console api.tools_data — resilient JSON
# ---------------------------------------------------------------------------


def test_tools_data_returns_probe_shape() -> None:
    d = api.tools_data()
    assert "tools" in d and "summary" in d and "platform" in d
    assert isinstance(d["tools"], list)
    assert d["summary"]["total"] == len(HOST_TOOLS)


# ---------------------------------------------------------------------------
# live server: /api/tools serves JSON with the strict CSP and never 500s
# ---------------------------------------------------------------------------


@contextmanager
def _running_server():
    httpd = server.serve(host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def test_api_tools_route_serves_json_with_csp() -> None:
    with _running_server() as base:
        with urllib.request.urlopen(base + "/api/tools", timeout=5) as r:  # noqa: S310 (loopback test)
            assert r.status == 200
            assert r.headers.get_content_type() == "application/json"
            # strict CSP parity with the other data routes (defense-in-depth on JSON).
            assert "default-src 'self'" in (r.headers.get("Content-Security-Policy") or "")
            body = json.loads(r.read())
    assert body["summary"]["total"] == len(HOST_TOOLS)
    assert isinstance(body["tools"], list) and len(body["tools"]) == len(HOST_TOOLS)
