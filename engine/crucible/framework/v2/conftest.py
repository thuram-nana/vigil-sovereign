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
