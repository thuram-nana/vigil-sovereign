"""
Pytest root conftest for v2.

Tests run with CRUCIBLE_LLM_BACKEND=dryrun so they neither require an
API key nor hit a network endpoint. A test wanting to exercise live
behaviour can override the env on a per-test basis.
"""

from __future__ import annotations

import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    os.environ["CRUCIBLE_LLM_BACKEND"] = "dryrun"
    # invalidate the kernel's cached backend if anything imported it before
    try:
        from framework.v2.kernel.llm import reset_cache
        reset_cache()
    except Exception:
        pass
