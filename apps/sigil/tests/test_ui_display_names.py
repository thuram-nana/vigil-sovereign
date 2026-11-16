"""The vendored agentic engine is shown as "NYX" on every screen — the UI only (owner, 2026-11-16).

The backend keeps its own identifiers (the strix modules and routes, STRIX_* settings, signed ``strix.*`` ids, the
vendored Strix package and its licence credit), so the rename happens in the shared UI kit
(``packages/vigil-ui/ui.js``) at render time: TEXT a person reads — text nodes, ``text`` props and the visible
attributes ``title`` / ``aria-label`` / ``placeholder`` / ``alt`` — never an attribute the code keys on (ids, classes,
option values, URLs, data-*), never raw ``<pre>`` / ``<code>`` evidence, never a lower-case identifier or a setting name.
The customer app's fork of the kit (``customer_app/ui.js``, pinned to the kit by ``test_customer_kit_copies``) carries
the same rule. Executed from the shipped source under node, with a minimal DOM.

Mutation-verify targets (each neuter reds a NAMED test here):
  * displayText is the identity (kit / customer fork)  -> test_what_a_person_reads_says_nyx[console / customer]
  * the raw-text exemption is dropped                  -> test_evidence_and_identifiers_read_exactly_as_recorded
  * every attribute is renamed (option values too)     -> test_attributes_the_code_keys_on_are_untouched
  * the visible attributes are not renamed             -> test_what_a_person_reads_says_nyx
  * lower-case identifiers renamed too                 -> test_evidence_and_identifiers_read_exactly_as_recorded
  * the drawer title bypasses the rule                 -> test_the_operator_app_routes_its_direct_text_writes_through_the_rule
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_UI = _REPO / "packages" / "vigil-ui" / "ui.js"
#: the customer app's fork of the kit (``test_customer_kit_copies``) renders by the same rule
_CUSTOMER_UI = _REPO / "apps" / "sigil" / "sigil" / "ui" / "customer_app" / "ui.js"

# A minimal DOM: just what ui.js's h() / toast() touch.
_DOM = r"""
class Node {}
class Text extends Node { constructor(t) { super(); this.nodeValue = String(t); } get textContent() { return this.nodeValue; } }
class El extends Node {
  constructor(tag) { super(); this.tagName = String(tag).toUpperCase(); this.attrs = {}; this.children = [];
                     this.dataset = {}; this.style = {}; this.className = ""; this.id = ""; this._text = null; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener() {}
  remove() {}
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text !== null ? this._text : this.children.map(c => c.textContent).join(""); }
  querySelector() { return null; }
}
globalThis.Node = Node;
globalThis.window = globalThis;
globalThis.document = { createElement: t => new El(t), createTextNode: t => new Text(t), body: new El("body"),
                        querySelector: () => null };
"""


def _need_node() -> str:
    """The node binary (callers use it as argv[0]), or a SKIP where node is absent — except in CI (GITHUB_ACTIONS) or
    where VIGIL_REQUIRE_NODE is set (every CI job that runs this file sets it): there a missing node FAILS, so these
    executed-JS proofs can never go green unrun."""
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH: this job must "
                        "EXECUTE these JS tests")
        pytest.skip("node not installed")
    return node


def _render(cases: "list[list]", ui: Path = _UI) -> list:
    """Each case is [tag, props, children]; returns [{text, attrs, id, className}] per rendered element."""
    prog = (_DOM + "\nrequire(process.argv[1]);\nconst V = globalThis.VUI;\n"
            "const out = JSON.parse(process.argv[2]).map(([t, p, c]) => { const el = V.h(t, p, c);\n"
            "  return { text: el.textContent, attrs: el.attrs, id: el.id, className: el.className }; });\n"
            "process.stdout.write(JSON.stringify(out));")
    r = subprocess.run([_need_node(), "-e", prog, str(ui), json.dumps(cases)], capture_output=True, text=True,
                       timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@pytest.mark.parametrize("ui", [_UI, _CUSTOMER_UI], ids=["console", "customer"])
def test_what_a_person_reads_says_nyx(ui):
    out = _render([
        ["span", None, "Strix agent — Docker + LLM, broader"],
        ["h1", {"text": "Strix Control"}, None],
        ["span", None, ["NO STRIX RUN", " · ", "STRIX RUN"]],
        ["button", {"title": "Stop the Strix host process", "aria-label": "Stop Strix",
                    "placeholder": "Strix run", "alt": "Strix"}, "Stop Strix process"],
        ["div", None, "The vendored Strix agent chooses its own passes (Strix's model)."],
    ], ui)
    assert out[0]["text"] == "NYX agent — Docker + LLM, broader"
    assert out[1]["text"] == "NYX Control"
    assert out[2]["text"] == "NO NYX RUN · NYX RUN"
    assert out[3]["text"] == "Stop NYX process"
    assert out[3]["attrs"] == {"title": "Stop the NYX host process", "aria-label": "Stop NYX",
                               "placeholder": "NYX run", "alt": "NYX"}
    assert out[4]["text"] == "The vendored NYX agent chooses its own passes (NYX's model)."


def test_evidence_and_identifiers_read_exactly_as_recorded():
    raw = "STRIX_LLM=anthropic/claude-opus-4-8  # Strix sandbox"
    out = _render([
        ["pre", None, raw],
        ["code", None, "Strix"],
        ["span", None, "strix.graph · vigil/strix-sandbox · STRIX_LLM · /api/strix/control · cust_strix"],
        ["span", None, "Strixx and AStrix are not the name"],
    ])
    assert out[0]["text"] == raw and out[1]["text"] == "Strix"          # evidence reads as recorded
    assert out[2]["text"] == "strix.graph · vigil/strix-sandbox · STRIX_LLM · /api/strix/control · cust_strix"
    assert out[3]["text"] == "Strixx and AStrix are not the name"      # whole words only


def test_attributes_the_code_keys_on_are_untouched():
    out = _render([
        ["option#strix-opt.Strix", {"value": "Strix", "data-x": "Strix", "href": "/Strix", "name": "Strix"},
         "Strix agent"],
    ])
    el = out[0]
    assert el["text"] == "NYX agent"
    assert el["id"] == "strix-opt" and el["className"] == "Strix"
    assert el["attrs"] == {"value": "Strix", "data-x": "Strix", "href": "/Strix", "name": "Strix"}


def test_the_display_rule_is_exported_for_direct_text_writes():
    prog = (_DOM + "\nrequire(process.argv[1]);\n"
            "process.stdout.write(JSON.stringify([VUI.displayText('Strix Control'), VUI.displayText('strix.core')]));")
    r = subprocess.run([_need_node(), "-e", prog, str(_UI)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == ["NYX Control", "strix.core"]


def test_the_operator_app_routes_its_direct_text_writes_through_the_rule():
    """The few places app.js writes text without h() (the drawer title, graph labels) use VUI.displayText; the
    kill-switch reason it POSTs is backend data and keeps the backend's name."""
    app = (_UI.parent / "app.js").read_text(encoding="utf-8")
    assert 'V.$("#drawer-title").textContent = V.displayText(' in app
    assert "t.textContent = V.displayText(l.label)" in app
    assert "label.textContent = V.displayText(m.label || e.kind)" in app
    assert '{ reason: "tripped from Strix Control" }' in app
