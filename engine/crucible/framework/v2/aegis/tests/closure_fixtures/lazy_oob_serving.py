"""FLIP FIXTURE (never imported): a FUNCTION-LOCAL (lazy) offense import inside an AEGIS serving module.

The module-level import closure correctly does NOT follow this (it does not run at import time), so the
conservative serving-module lazy-offense overlay is what must catch it.
"""
from __future__ import annotations


def _enable_oob() -> object:
    from framework.v2.verify.oob import OOBReceiver  # deny-listed offense, smuggled lazily into the serve path
    return OOBReceiver()
