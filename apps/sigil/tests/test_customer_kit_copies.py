"""The customer app carries copies of the operator console's UI kit (packages/vigil-ui). This pins them:

* tokens.css and components.css are byte-identical copies — a kit change reaches both UIs or the test fails;
* ui.js is a FORK: it may differ from the console's only inside its two customer regions — the request helpers
  (read retries and the "updating" answers while VIGIL restarts) and extra icons — and it exports exactly the
  console's VUI names. Any other edit to either file, without the same edit to the other, fails here.
"""
from __future__ import annotations

import difflib
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
KIT = REPO / "packages" / "vigil-ui"
APP = REPO / "apps" / "sigil" / "sigil" / "ui" / "customer_app"


@pytest.mark.parametrize("name", ["tokens.css", "components.css"])
def test_the_shared_stylesheets_are_byte_identical(name):
    assert (APP / name).read_bytes() == (KIT / name).read_bytes(), \
        f"customer_app/{name} differs from packages/vigil-ui/{name}: copy the kit file over"


def _lines(p: Path) -> list[str]:
    return p.read_text(encoding="utf-8").splitlines()


def _region(lines: list[str], start: str, end: str) -> range:
    a = next(i for i, ln in enumerate(lines) if ln.strip().startswith(start))
    b = next(i for i in range(a + 1, len(lines)) if lines[i].strip().startswith(end))
    return range(a, b)


def _fork_regions(console: list[str], customer: list[str]):
    # the request helpers: from the first helper the fork touches to the chunked-upload section that follows them
    kit_fetch = _region(console, "async function getJSON(url)", "// -- chunked upload:")
    app_fetch = _region(customer, "// While VIGIL restarts,", "// -- chunked upload:")
    kit_icons = _region(console, "const P = {", "};")
    app_icons = _region(customer, "const P = {", "};")
    return kit_fetch, app_fetch, kit_icons, app_icons


def fork_violations(console: list[str], customer: list[str]) -> list[str]:
    kit_fetch, app_fetch, kit_icons, app_icons = _fork_regions(console, customer)
    bad = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, console, customer, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        kit_side = range(i1, i2)
        app_side = range(j1, j2)
        in_fetch = all(i in kit_fetch for i in kit_side) and all(j in app_fetch for j in app_side)
        icon_added = tag == "insert" and all(j in app_icons for j in app_side) and i1 in kit_icons
        if not (in_fetch or icon_added):
            bad.append(f"{tag} console {i1 + 1}-{i2} / customer {j1 + 1}-{j2}: "
                       + " | ".join((console[i1:i2] + customer[j1:j2])[:2]))
    return bad


def _exports(lines: list[str]) -> set[str]:
    text = "\n".join(lines)
    block = text[text.index("window.VUI = {"):]
    block = block[: block.index("};")]
    return set(re.findall(r"(\w+):\s*\w+", block))


def test_the_ui_js_fork_differs_only_in_its_customer_regions():
    console, customer = _lines(KIT / "ui.js"), _lines(APP / "ui.js")
    assert fork_violations(console, customer) == []


def test_the_fork_exports_the_consoles_names():
    assert _exports(_lines(APP / "ui.js")) == _exports(_lines(KIT / "ui.js"))


def test_the_fork_check_catches_an_edit_outside_the_regions():
    # negative control: a change to the shared toast() in only one copy is reported
    console, customer = _lines(KIT / "ui.js"), _lines(APP / "ui.js")
    i = next(k for k, ln in enumerate(customer) if "function toast(msg, isErr)" in ln)
    edited = customer[:i + 1] + ["    console.log('drift');"] + customer[i + 1:]
    assert fork_violations(console, edited)
    j = next(k for k, ln in enumerate(customer) if "async function postJSON(url, body)" in ln)
    inside = customer[:j + 1] + ["    // a customer-only helper note"] + customer[j + 1:]
    assert fork_violations(console, inside) == []
