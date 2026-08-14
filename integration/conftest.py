"""Make ``vigil_integration`` importable when pytest runs from the integration dir or repo root, and
pin the ONE thing in the executor that reads the host box: which security tool binary a tool NAME means.
"""

import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ---------------------------------------------------------------------------------------------------
# hermetic tool resolution — a unit test of an argv must not depend on what is installed on the box
# ---------------------------------------------------------------------------------------------------
#
# ``live.executor``'s httpx builder resolves ``argv[0]`` to a REAL binary on PATH instead of emitting the
# bare name, because the bare name cannot be trusted: on Kali — this framework's own platform — ``httpx``
# is the unrelated Python HTTP client's CLI and ProjectDiscovery's tool installs as ``httpx-toolkit``.
# Correct for production, but it makes an argv a function of the box, which a unit test must never be:
# the same test would pass on a provisioned Kali box, REFUSE in CI (where no security tool is installed),
# and quietly aim at the impostor on a laptop that has the Python client.
#
# So the suite pins that one seam, to the world of a correctly provisioned Kali box: ``httpx-toolkit``
# present and identified, ``httpx`` absent. Nothing else is faked and no refusal is suppressed — a test
# that wants the "nothing is installed" or "only the impostor is installed" world pins the same seam
# itself and wins (its ``monkeypatch`` is applied after this one), and those worlds ARE exercised, in
# ``tests/test_builder_binary_resolution.py``. This also keeps the promise the executor test module makes
# in its own docstring, that nothing there spawns a process: without it, every httpx build would spawn a
# real ``-version`` probe.
_FAKE_TOOLKIT_PATH = "/usr/bin/httpx-toolkit"
_FAKE_TOOLKIT_BANNER = "projectdiscovery.io\n\n[INF] Current Version: v1.9.0\n"


@pytest.fixture(autouse=True)
def _pin_declared_tool_binaries(monkeypatch):
    """Resolve the executor's DECLARED httpx binaries deterministically; leave every other name to the
    real PATH lookup. A no-op when the executor is not importable (the framework-free test legs)."""
    try:
        from vigil_integration.live import executor as _executor
    except Exception:  # noqa: BLE001 — a leg that cannot import the executor needs no pin
        yield
        return

    import shutil

    def _fake_which(name: str):
        if name == "httpx-toolkit":
            return _FAKE_TOOLKIT_PATH
        if name == "httpx":
            return None          # taken by the Python HTTP client on a real Kali box; declared absent here
        return shutil.which(name)

    def _fake_banner(path: str, version_args):
        return _FAKE_TOOLKIT_BANNER if path == _FAKE_TOOLKIT_PATH else ""

    monkeypatch.setattr(_executor, "_which", _fake_which)
    monkeypatch.setattr(_executor, "_version_banner", _fake_banner)
    yield
