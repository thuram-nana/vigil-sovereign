"""
Pytest root conftest for v2.

By default tests run with CRUCIBLE_LLM_BACKEND=dryrun so they neither
require an API key nor hit a network endpoint.  A live-path test
wanting to exercise the real kernel can set CRUCIBLE_LLM_BACKEND in
the environment BEFORE invoking pytest, e.g.

    CRUCIBLE_LLM_BACKEND=claude-code pytest framework/v2/...

When that variable is set to anything other than "dryrun" or empty,
the conftest leaves it alone and the configured backend is used.
"""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest


def pytest_configure(config: pytest.Config) -> None:
    # Respect an operator override; only force dryrun when nothing was set.
    current = os.environ.get("CRUCIBLE_LLM_BACKEND", "").strip().lower()
    if current in ("", "dryrun"):
        os.environ["CRUCIBLE_LLM_BACKEND"] = "dryrun"
    # invalidate the kernel's cached backend if anything imported it before
    try:
        from framework.v2.kernel.llm import reset_cache
        reset_cache()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _unbind_engagement_after_test() -> Generator[None, None, None]:
    """`logging.bind_engagement(slug)` sets a module-level slug that
    routes subsequent log writes to `targets/<slug>/.crucible-v2.log`.
    Tests that exercise intake/agents/planner pipelines call it, but
    nothing resets it, so logs from later tests (after monkeypatches
    revert) leak to the real `targets/`. Reset after every test."""
    yield
    try:
        from framework.v2.common.logging import bind_engagement
        bind_engagement(None)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _zero_http_rate_floor(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Generator[None, None, None]:
    """CI SPEED (ci/crucible-core-ratefloor): zero the HTTP-executor rate-throttle SLEEP for the
    duration of each test — so the whole suite stays per-PR at full fidelity without the wall clock.

    The "CRUCIBLE core on vigil_core" leg crept to ~44-45 min and hits GitHub's 45-min ceiling. The
    dominant cost is NOT the statistical-volume tests: it is the ~23 functional engage integration
    tests, each of which drives ~222 loopback requests through the gated ``HttpExecutor`` and pays the
    TEST posture's 0.2 s minimum inter-request interval on every one (~43 s/test, ~19 min in total).

    This fixture patches the MODULE-LEVEL ``_RATE_PROFILES`` dict VALUES (TEST/AUDIT/EMULATE) to a zero
    floor ``(0.0, 0.0)`` for the duration of each test; ``monkeypatch.setitem`` auto-restores after.
    The throttle MECHANISM still runs and stays covered: ``HttpExecutor._sleep_for_rate_limit`` still
    takes the lock, still reads ``_RATE_PROFILES[posture]`` at sleep time, still computes
    ``floor = max(profile_floor, self._operator_min_interval)`` and still RESERVES the request's start
    instant on the anchor. Only the wall-clock wait vanishes: with the profile at 0.0 and the default
    operator interval 0.0 the floor is 0.0, so ``total <= 0`` and the ``if total > 0: time.sleep(total)``
    branch is never taken. (Verified against agents/http_executor.py:1182 ``_sleep_for_rate_limit``.)

    NO PRODUCTION CODE CHANGES. The existing ``VIGIL_MIN_REQUEST_INTERVAL_S`` operator hook cannot be
    used to reach zero: it can only TIGHTEN (raise) the floor, never lower it. Monkeypatching the
    profile is the only test-side path to a zero floor.

    A test whose assertions depend on the GENUINE throttle/timing/spacing opts OUT with
    ``@pytest.mark.real_rate_floor`` (registered in framework/v2/pyproject.toml): this fixture detects
    the marker and leaves the real profiles untouched, so those tests exercise the genuine floor and take
    real wall-clock. Every such test is marked; see them for the per-test justification."""
    if request.node.get_closest_marker("real_rate_floor") is not None:
        # Genuine-throttle test: leave the real posture rate profiles in place.
        yield
        return
    try:
        from framework.v2.agents import http_executor
    except Exception:  # noqa: BLE001 — no executor imported ⇒ no throttle to zero; nothing to do
        yield
        return
    for posture in ("TEST", "AUDIT", "EMULATE"):
        if posture in http_executor._RATE_PROFILES:
            monkeypatch.setitem(http_executor._RATE_PROFILES, posture, (0.0, 0.0))
    yield


@pytest.fixture(autouse=True)
def _isolate_crucible_root_cache() -> Generator[None, None, None]:
    """Keep CRUCIBLE_ROOT resolution hermetic per test (B4). ``common.paths.crucible_root`` is an
    ``@lru_cache(maxsize=1)`` — the FIRST caller freezes the resolved root for the whole process, so a test
    that monkeypatches ``CRUCIBLE_ROOT`` leaks its root into every later test and makes the wholesale
    ``crucible-core`` run ORDER-DEPENDENT. Clear the cache BEFORE each test (this delivers the
    order-independence) and AFTER as belt-and-suspenders. Behaviour-preserving:
    production sets CRUCIBLE_ROOT once, so it re-resolves to the identical value; this only makes tests
    order-independent (the individual paths tests already reset locally — this is the global autouse guard)."""
    try:
        from framework.v2.common import paths
    except Exception:  # noqa: BLE001 — defensive; paths is always importable in this leg
        yield
        return
    paths._reset_cache()
    yield
    paths._reset_cache()
