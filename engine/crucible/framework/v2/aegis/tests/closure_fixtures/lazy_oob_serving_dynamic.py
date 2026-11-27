"""FLIP FIXTURE (never imported): a FUNCTION-LOCAL DYNAMIC-STRING offense import in an AEGIS serving module.

``importlib.import_module("framework.v2.verify.oob")`` (and the ``__import__`` twin) loads the deny-listed
offense submodule at SERVE time from a STRING LITERAL — so neither the module-level closure (it is lazy,
not an import-time edge) nor a literal ``from ... import`` scan sees it. The conservative serving-module
overlay must capture the ``import_module``/``__import__`` string argument and deny it (same as the
module-level walk's dynamic-string handling), or a denied module hides behind the dynamic form.
"""
from __future__ import annotations

import importlib


def _enable_oob() -> object:
    mod = importlib.import_module("framework.v2.verify.oob")  # deny-listed offense, smuggled via dynamic string
    return mod.OOBReceiver()


def _enable_oob_dunder() -> object:
    mod = __import__("framework.v2.verify.oob", fromlist=["OOBReceiver"])  # the ``__import__`` twin
    return mod.OOBReceiver()
