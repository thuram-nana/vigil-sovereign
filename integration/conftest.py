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


@pytest.fixture(autouse=True)
def _isolate_crucible_root_cache():
    """Keep CRUCIBLE_ROOT resolution hermetic per test (B4). ``framework.v2.common.paths.crucible_root`` is an
    ``@lru_cache(maxsize=1)`` — the FIRST caller in the process FREEZES the resolved root for every later
    caller. So a test that monkeypatches ``CRUCIBLE_ROOT`` (or merely triggers the eager
    ``tool_intake``/``brain_engine`` path resolution) leaks its root into every subsequent test, making the
    suite ORDER-DEPENDENT — the exact fragility the ``test_brain_fact_path_tripwire`` subprocess trampoline
    was working around. Clear the cache BEFORE each test — that is what delivers order-independence (no prior
    test's monkeypatched root survives into this one) — and AFTER as belt-and-suspenders (covering any
    session/module-scoped teardown or plugin hook that resolves the root while this test's env is still live).
    Behaviour-preserving: production sets CRUCIBLE_ROOT once
    and never mutates it mid-process, so ``crucible_root()`` re-resolves to the identical value; this only makes
    tests order-independent. A no-op in the framework-free (sovereign) leg where ``paths`` cannot be imported."""
    try:
        from framework.v2.common import paths
    except Exception:  # noqa: BLE001 — the sovereign leg has no framework; nothing to reset
        yield
        return
    paths._reset_cache()
    yield
    paths._reset_cache()


@pytest.fixture(autouse=True)
def _isolate_entitlement_dir(tmp_path_factory, monkeypatch):
    """Keep the HOST-LEVEL entitlement store hermetic per test. The entitlement CAPABILITY gate keys
    "enforcement active" on the presence of a trust-root file under ``CRUCIBLE_ENTITLEMENT_DIR`` (default
    ``<v2_root>/.entitlement/trust-root.json``). Phase 0.1's ``provision_authority`` / ``build_engine``
    PERSIST that trust root, so without this redirect the FIRST provisioning test in the process writes the
    SHARED in-tree ``.entitlement/trust-root.json`` and flips capability enforcement ON for every LATER test —
    which then fails "no entitlement provisioned (trust root present, grant absent)" on capabilities
    (deep_static_analysis / active_recon) it never governed and minted no grant for. Point the dir at a
    throwaway per test: each provisioning test gets its own fresh governed dir; each non-provisioning test sees
    a clean UNGOVERNED dir (→ ALLOW). This isolates host state exactly like the attestation / backup-anchor /
    CRUCIBLE_ROOT fixtures above — it weakens NO gate. A no-op in the framework-free (sovereign) leg where the
    entitlement package cannot be imported. A test that needs a specific dir sets ``CRUCIBLE_ENTITLEMENT_DIR``
    in its own body (applied after this fixture, so it wins)."""
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(tmp_path_factory.mktemp("entitlement")))
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    monkeypatch.delenv("CRUCIBLE_ATTESTED_IDENTITY", raising=False)
    try:
        from framework.v2.entitlement import policy as _entpolicy
    except Exception:  # noqa: BLE001 — the sovereign leg has no framework entitlement package
        yield
        return
    _entpolicy.reset_policy()
    yield
    _entpolicy.reset_policy()
