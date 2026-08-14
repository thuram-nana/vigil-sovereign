"""A tool that is installed under an alternate name must be FOUND, not reported unusable.

THE DEFECT THIS PINS. `_resolve` returned the first name on PATH and stopped. On Kali the real
ProjectDiscovery `httpx` installs as `httpx-toolkit` — precisely because the plain `httpx` name is
taken by an unrelated Python HTTP client — so the resolver stopped at the Python one, matched a
`wrong_markers` banner, and reported a REQUIRED tool as shadowed and unusable. On a machine where
the genuine tool had been installed the whole time. `alt_binaries` existed and was never consulted
past the first hit, so it could not help the one case it was designed for.

WHY BOTH DIRECTIONS ARE TESTED. The obvious fix — prefer any alternate — would destroy something
valuable: when the impostor is the ONLY thing on PATH, "shadowed" is a far more useful thing to tell
an operator than "missing". It says *a decoy is sitting on this name*, which is a different problem
with a different fix. So the second test is not decoration; without it a future simplification could
turn every shadowed report into a missing one and still look green.

Read-only: no tool is executed. Both PATH lookup and version probing are replaced with fakes, so the
result does not depend on what happens to be installed on the machine running the tests.
"""

from __future__ import annotations

import pytest

registry = pytest.importorskip("framework.v2.tools.registry")

# The real banner the Python HTTP client prints — this is what makes it identifiable as the wrong
# tool. Kept verbatim rather than paraphrased: the detection is substring matching on this text.
PY_HTTPX_BANNER = "Usage: httpx [OPTIONS] URL\nTry 'httpx --help' for help.\nNo such option: -version"
REAL_HTTPX_BANNER = "[INF] Current Version: v1.9.0"


def _httpx_spec():
    for s in registry.HOST_TOOLS:
        if s.name == "httpx":
            return s
    raise AssertionError("the httpx entry vanished from the host roster")


def _fake_path(available: dict[str, str]):
    """shutil.which over a fixed set of names."""
    return lambda name: available.get(name)


def _fake_probe(banners: dict[str, str]):
    """_probe_raw keyed by resolved path. Mirrors the real signature, including the
    per-spec ``timeout_s`` override, so the double cannot drift from the function."""
    return lambda path, args, timeout_s=None: banners.get(path, "")


def test_the_real_tool_under_its_alternate_name_is_found(monkeypatch):
    """The impostor holds `httpx`; the genuine tool is installed as `httpx-toolkit`. This is the
    ordinary state of a correctly-provisioned Kali box, and it must read as installed."""
    spec = _httpx_spec()
    monkeypatch.setattr(registry.shutil, "which", _fake_path({
        "httpx": "/usr/bin/httpx",                    # the Python HTTP client
        "httpx-toolkit": "/usr/bin/httpx-toolkit",    # the genuine ProjectDiscovery binary
    }))
    monkeypatch.setattr(registry, "_probe_raw", _fake_probe({
        "/usr/bin/httpx": PY_HTTPX_BANNER,
        "/usr/bin/httpx-toolkit": REAL_HTTPX_BANNER,
    }))

    tool = registry.probe_tool(spec, with_version=True)
    assert tool["path"] == "/usr/bin/httpx-toolkit", "resolver stopped at the impostor again"
    assert tool["status"] == "installed", f"a present tool reported {tool['status']!r}"
    assert tool["shadowed"] is False


def test_an_impostor_alone_still_reports_shadowed_not_missing(monkeypatch):
    """MUTATION CONTROL for the test above.

    With only the wrong tool on PATH there is nothing to fall back to. The honest answer is
    `shadowed` — something is occupying the name — and NOT `missing`, which would send an operator
    off to install a tool whose name is already taken and watch it appear to change nothing.
    """
    spec = _httpx_spec()
    monkeypatch.setattr(registry.shutil, "which", _fake_path({"httpx": "/usr/bin/httpx"}))
    monkeypatch.setattr(registry, "_probe_raw", _fake_probe({"/usr/bin/httpx": PY_HTTPX_BANNER}))

    tool = registry.probe_tool(spec, with_version=True)
    assert tool["status"] == "shadowed", f"lost the shadowed signal — got {tool['status']!r}"
    assert tool["shadowed"] is True
    assert tool["path"] == "/usr/bin/httpx", "an operator needs to know WHICH binary is in the way"


def test_nothing_on_path_is_still_missing(monkeypatch):
    """The third state must stay distinct from the other two: absent is not the same as shadowed."""
    spec = _httpx_spec()
    monkeypatch.setattr(registry.shutil, "which", _fake_path({}))
    monkeypatch.setattr(registry, "_probe_raw", _fake_probe({}))

    tool = registry.probe_tool(spec, with_version=True)
    assert tool["status"] == "missing"
    assert tool["shadowed"] is False


def test_the_alternate_name_is_actually_registered():
    """The resolver fix is inert for httpx unless the packaged name is listed. Pin the pairing, so
    that removing either half fails here rather than silently reinstating the original defect."""
    spec = _httpx_spec()
    assert "httpx-toolkit" in spec.alt_binaries
    assert spec.wrong_markers, "shadow detection needs markers; without them the skip never triggers"
