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


@pytest.fixture(autouse=True)
def _isolate_attestation_state_dir(tmp_path_factory, monkeypatch):
    """Keep the HOST-LEVEL attestation state hermetic per test. W10-3/W10-4 moved the monotonic anchor
    counter and the durable head/count pin OUT of the engagement base dir (so ``rm -rf <base>`` cannot
    erase them) and into :data:`attestation.anchor.DEFAULT_STATE_DIR` (``~/.vigil/attestation`` in
    production). Without this redirect, every ``build_engine`` test would write the real user's
    ``~/.vigil/attestation/monotonic.counter`` and read a value carried over from prior runs — polluting the
    home dir and making anchor assertions flaky. Point that dir at a throwaway per test. A no-op where the
    attestation package is not importable (framework-free legs). A test that needs a SPECIFIC location
    monkeypatches ``anchor.DEFAULT_STATE_DIR`` in its own body — applied after this fixture, so it wins."""
    try:
        from vigil_integration.attestation import anchor as _anchor
    except Exception:  # noqa: BLE001 — a leg without the attestation package needs no redirect
        yield
        return
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path_factory.mktemp("attest-state"))
    yield


@pytest.fixture(autouse=True)
def _isolate_backup_trust_anchor(tmp_path_factory, monkeypatch):
    """Keep the HOST-LEVEL backup trust anchor hermetic per test. W7-6 (PR #630) records the trusted
    governance pubkey + a monotonic backup_seq to ``~/.vigil/backup-trust-anchor.json`` (the same ``~/.vigil``
    host-state convention as the attestation anchor above). Without this redirect, any test that drives a real
    ``vigil backup`` (e.g. the push-transport CLI tests) would write the real user's home anchor AND read a
    key/seq carried over from prior runs — polluting the home dir and letting one test's key rotation refuse
    the next. Point it at a throwaway per test via the documented override env. A test that needs a specific
    location sets ``VIGIL_BACKUP_TRUST_ANCHOR`` in its own body (applied after this fixture, so it wins)."""
    monkeypatch.setenv("VIGIL_BACKUP_TRUST_ANCHOR",
                       str(tmp_path_factory.mktemp("backup-anchor") / "trust-anchor.json"))
    yield
