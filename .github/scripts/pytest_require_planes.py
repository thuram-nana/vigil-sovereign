"""pytest plugin: in a leg that HAS a plane, a test may not skip because that plane "is missing".

WHY THIS EXISTS. The test suites are split across CI legs that each see only part of the repository
(the two-env boundary): the engine leg has no ``vigil_integration`` or ``vigil_gateway``, the sovereign
leg has no ``framework``. A test that needs a plane its home leg lacks guards itself with
``pytest.importorskip("<plane>…")`` and SKIPS there — by design. It is then supposed to run in the leg
that has every plane. But ``importorskip`` cannot tell "this leg deliberately lacks the plane" from
"the module was renamed", "its import now raises" or "the path is wrong": all of them skip, and a
skipped proof and a passing proof are the same colour on a dashboard. Two engine suites that guard
the pause/halt money path sat in exactly that state — skipped in every leg, so they had never run in
CI at all.

So the leg that has every plane says which planes it REQUIRES, and there a skip for one of them is a
FAILURE:

    VIGIL_REQUIRE_PLANES=vigil_integration,vigil_gateway,framework,vigil_core \\
        python -m pytest -p pytest_require_planes …

What it catches:
  * ``pytest.importorskip("<required plane>…")`` that cannot import does not skip: it FAILS, naming the
    real import error (the module is imported again to recover it, because pytest's ``Skipped`` carries
    only the reason text). Module level → a collection error; inside a test or fixture → a failure.
    The failure message names the plane, so even if an ``xfail`` mark reclassifies the failure as a green
    ``xfailed``, the reason pass below still sees it and fails the run.
  * ANY other skip (not an xfail) whose reason names a required plane — the canonical import errors
    (``could not import '<plane>…'``, ``No module named '<plane>…'``) and, for the unambiguous plane
    identifiers (``vigil_gateway``, ``vigil_integration``, ``vigil_core``, ``strix`` …), any mention of
    the identifier; for ``framework``, which is also an English word, only the dotted module form
    (``framework.v2…``) or the quoted name. Those skips turn the session's exit status non-zero and are
    listed by test id. This is the backstop for hand-rolled guards (``skipif(find_spec(...) is None)``,
    ``try: import … except: pytest.skip(...)``); the repository's own guards use ``importorskip``.

What it does NOT catch: a skip whose reason never names the plane and that is not an importorskip. Write
plane guards as ``pytest.importorskip``.

The patch is applied when this module is IMPORTED (``-p`` plugins load before any conftest), so an alias
taken in a conftest (``need = pytest.importorskip``) is the patched function too. Without the variable the
plugin does nothing at all, so loading it anywhere else is inert. It is stdlib + pytest only and imports
nothing from the repository.
"""
from __future__ import annotations

import importlib
import os
import re

import pytest

ENV = "VIGIL_REQUIRE_PLANES"

_ORIGINAL_IMPORTORSKIP = pytest.importorskip
# Every failure the wrapper raises carries this, so it can be told apart from any other failure.
_MARKER = "would SKIP, but this leg requires"


def required_planes(environ=None) -> frozenset[str]:
    raw = (os.environ if environ is None else environ).get(ENV, "")
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


def _skip_reason_pattern(planes: frozenset[str]) -> re.Pattern[str] | None:
    """A skip reason that says a REQUIRED plane could not be imported, or names the plane at all."""
    if not planes:
        return None
    alts = []
    for plane in sorted(planes):
        q = re.escape(plane)
        # The canonical import-error texts, for any plane, exact module or below it.
        alts.append(rf"(?:could not import|No module named) ['\"]{q}(?:\.[\w.]*)?['\"]")
        if "_" in plane or plane == "strix":
            # An identifier no English sentence contains by accident: any whole-word mention.
            alts.append(rf"(?<![\w.]){q}(?![\w])")
        else:
            # An ordinary word (`framework`): only the dotted module path or the quoted module name.
            alts.append(rf"(?<![\w.]){q}\.\w")
            alts.append(rf"['\"`]{q}['\"`]")
    return re.compile("|".join(alts))


def _real_import_error(modname: str, fallback: str) -> str:
    try:
        importlib.import_module(modname)
    except BaseException as exc:  # noqa: BLE001 - we are REPORTING whatever stopped the import
        return f"{type(exc).__name__}: {exc}"
    return fallback


def _make_importorskip(planes: frozenset[str]):
    def importorskip(modname, *args, **kwargs):
        __tracebackhide__ = True   # a skip/fail is reported at the CALLER's line, not here
        if str(modname).split(".", 1)[0] not in planes:
            return _ORIGINAL_IMPORTORSKIP(modname, *args, **kwargs)
        try:
            return _ORIGINAL_IMPORTORSKIP(modname, *args, **kwargs)
        except pytest.skip.Exception as skipped:
            plane = str(modname).split(".", 1)[0]
            detail = _real_import_error(str(modname), str(skipped))
            msg = (f"importorskip({modname!r}) {_MARKER} the {plane!r} plane "
                   f"({ENV}) — a required plane that cannot be imported is a failure here, not a skip. "
                   f"Underlying error: {detail} (skip reason: {skipped})")
            pytest.fail(msg, pytrace=False)
    importorskip.__wrapped__ = _ORIGINAL_IMPORTORSKIP  # type: ignore[attr-defined]
    return importorskip


class _RequirePlanes:
    def __init__(self, planes: frozenset[str], offenders: list):
        self.planes = planes
        self.pattern = _skip_reason_pattern(planes)
        self.offenders = offenders

    def _note(self, report) -> None:
        if not report.skipped or self.pattern is None:
            return
        if hasattr(report, "wasxfail"):
            # An xfailed test is reported as skipped, with the whole failure traceback as its "reason". Only a
            # failure the wrapper itself raised counts: a deliberate strict-xfail placeholder whose traceback
            # merely MENTIONS a plane (`from framework.v2.<not built yet> import …`) is not a missing plane.
            if _MARKER in str(report.longrepr):
                self.offenders.append((report.nodeid, f"xfail swallowed: {_MARKER} (see the test's traceback)"))
            return
        longrepr = report.longrepr
        reason = longrepr[2] if isinstance(longrepr, tuple) and len(longrepr) == 3 else str(longrepr)
        if self.pattern.search(str(reason)):
            self.offenders.append((report.nodeid, str(reason)))

    def pytest_collectreport(self, report) -> None:
        self._note(report)

    def pytest_runtest_logreport(self, report) -> None:
        self._note(report)

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session, exitstatus) -> None:
        if self.offenders and session.exitstatus == 0:
            session.exitstatus = 1

    def pytest_terminal_summary(self, terminalreporter) -> None:
        if not self.offenders:
            return
        terminalreporter.section(f"skipped for a REQUIRED plane ({ENV}) — failing the run", sep="=", red=True)
        for nodeid, reason in self.offenders:
            terminalreporter.line(f"{nodeid}: {reason}")


# Patch at IMPORT time: `-p` plugins are imported before the initial conftests, so a conftest that takes an
# alias (`need = pytest.importorskip`, `from pytest import importorskip`) gets the patched function.
_PLANES = required_planes()
_OFFENDERS: list = []
if _PLANES:
    pytest.importorskip = _make_importorskip(_PLANES)


def pytest_configure(config) -> None:
    if not _PLANES:
        return
    config.pluginmanager.register(_RequirePlanes(_PLANES, _OFFENDERS), "vigil-require-planes")
    config.add_cleanup(lambda: setattr(pytest, "importorskip", _ORIGINAL_IMPORTORSKIP))
