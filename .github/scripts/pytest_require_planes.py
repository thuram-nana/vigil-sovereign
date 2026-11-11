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

    VIGIL_REQUIRE_PLANES=vigil_integration,vigil_gateway,framework,vigil_core \
        python -m pytest -p pytest_require_planes …

  * ``pytest.importorskip("<required plane>…")`` that cannot import does not skip: it fails, with the
    underlying import error, whether it is called at module level (a collection error) or inside a
    test.
  * Any OTHER skip whose reason names a required plane as unimportable (a hand-rolled
    ``try: import … except ImportError: pytest.skip(…)`` or a ``skipif(find_spec(…) is None)``) is
    collected and turns the session's exit status non-zero, listed by test id.

Without the variable the plugin does nothing at all, so loading it anywhere else is inert. It is
stdlib + pytest only and imports nothing from the repository.
"""
from __future__ import annotations

import os
import re

import pytest

ENV = "VIGIL_REQUIRE_PLANES"

_ORIGINAL_IMPORTORSKIP = pytest.importorskip


def required_planes(environ=None) -> frozenset[str]:
    raw = (os.environ if environ is None else environ).get(ENV, "")
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


def _skip_reason_pattern(planes: frozenset[str]) -> "re.Pattern[str] | None":
    if not planes:
        return None
    alt = "|".join(re.escape(p) for p in sorted(planes))
    # pytest's own importorskip text ("could not import 'x.y': …") and CPython's ImportError text
    # ("No module named 'x.y'"), for the plane itself or anything under it.
    return re.compile(rf"(?:could not import|No module named) ['\"](?:{alt})(?:\.[\w.]*)?['\"]")


def _make_importorskip(planes: frozenset[str]):
    def importorskip(modname, *args, **kwargs):
        __tracebackhide__ = True   # a skip/fail is reported at the CALLER's line, not here
        if str(modname).split(".", 1)[0] not in planes:
            return _ORIGINAL_IMPORTORSKIP(modname, *args, **kwargs)
        try:
            return _ORIGINAL_IMPORTORSKIP(modname, *args, **kwargs)
        except pytest.skip.Exception as skipped:
            cause = skipped.__cause__ or skipped.__context__
            detail = f"{type(cause).__name__}: {cause}" if cause is not None else str(skipped)
            pytest.fail(
                f"importorskip({modname!r}) would SKIP, but this leg requires the "
                f"{str(modname).split('.', 1)[0]!r} plane ({ENV}) — a required plane that cannot be "
                f"imported is a failure here, not a skip. Underlying error: {detail}",
                pytrace=False,
            )
    importorskip.__wrapped__ = _ORIGINAL_IMPORTORSKIP  # type: ignore[attr-defined]
    return importorskip


class _RequirePlanes:
    def __init__(self, planes: frozenset[str]):
        self.planes = planes
        self.pattern = _skip_reason_pattern(planes)
        self.offenders: list[tuple[str, str]] = []

    def _note(self, report) -> None:
        if not report.skipped or self.pattern is None:
            return
        longrepr = report.longrepr
        reason = longrepr[2] if isinstance(longrepr, tuple) and len(longrepr) == 3 else str(longrepr)
        if self.pattern.search(reason):
            self.offenders.append((report.nodeid, reason))

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


def pytest_configure(config) -> None:
    planes = required_planes()
    if not planes:
        return
    pytest.importorskip = _make_importorskip(planes)
    config.pluginmanager.register(_RequirePlanes(planes), "vigil-require-planes")
    config.add_cleanup(lambda: setattr(pytest, "importorskip", _ORIGINAL_IMPORTORSKIP))
