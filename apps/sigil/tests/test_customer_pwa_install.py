"""Installing the customer app (customer_app/pwa.js), executed under node:

* Chromium: beforeinstallprompt is always kept from the browser's own banner; at the customer origin's root an
  "Install app" button appears, a tap opens the browser's dialog once and removes the button, and appinstalled
  removes it too. Under /customer/ on the console origin nothing is offered.
* iOS: the "Share -> Add to Home Screen" banner appears only when the edge's flag is on (VIGIL_CUSTOMER_IOS_
  INSTALL_BANNER, OFF by default pending the owner's sign-in test in the installed app on a real iPhone), on an
  iPhone/iPad, not already installed, not dismissed before, at the root; dismissing it is remembered.
* The edge writes the flag into the page at startup (default "0"), and the deploy example ships it off.
"""
from __future__ import annotations

import http.client
import json
import re
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from sigil import config
from sigil.ui.custui import build_customer_server

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
ENV_EXAMPLE = Path(__file__).resolve().parents[1] / "deploy" / "customer.env.example"
_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile Safari"
ANDROID = "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36"

_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const [CFG, PWA] = process.argv.slice(-2);
const cfg = JSON.parse(CFG);
const out = { prevented: 0, prompts: 0, stored: {} };
function El(tag) { const e = { tagName: tag.toUpperCase(), children: [], attrs: {}, listeners: {}, textContent: "",
  appendChild(c) { c.parentEl = this; this.children.push(c); return c; }, setAttribute(k, v) { this.attrs[k] = v; },
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
  remove() { if (this.parentEl) this.parentEl.children = this.parentEl.children.filter(x => x !== this); } };
  return e; }
const body = El("body"); body.dataset = { build: "", iosInstall: cfg.flag };
const winL = {};
const store = Object.assign({}, cfg.storage || {});
const ctx = { console, Promise, JSON, String, RegExp, Date: { now: () => 1 },
  document: { body, hidden: false, createElement: El, addEventListener() {} },
  window: { addEventListener: (t, f) => { (winL[t] = winL[t] || []).push(f); },
            matchMedia: (q) => ({ matches: q === "(display-mode: standalone)" && !!cfg.standaloneMedia }) },
  navigator: { userAgent: cfg.ua, platform: cfg.platform || "", maxTouchPoints: cfg.touch || 0,
               standalone: !!cfg.navStandalone },
  localStorage: { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
  location: { pathname: cfg.path, reload() {} },
  setInterval() {}, setTimeout() {}, fetch: async () => ({ ok: false }) };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(PWA, "utf8"), ctx);
const find = (id) => body.children.find(c => c.id === id);
(async () => {
  for (const a of cfg.actions || []) {
    if (a === "bip") (winL.beforeinstallprompt || []).forEach(f => f({
      preventDefault: () => { out.prevented++; },
      prompt: () => { out.prompts++; if (out.prompts > 1) throw new Error("prompt() may only be called once"); return Promise.resolve(); },
      userChoice: Promise.resolve({ outcome: "accepted" }) }));
    else if (a === "click-install") find("vigil-install").listeners.click.forEach(f => f());
    else if (a === "installed") (winL.appinstalled || []).forEach(f => f());
    else if (a === "dismiss-ios") find("vigil-ios-install").children[1].listeners.click.forEach(f => f());
    await new Promise(r => setImmediate(r));
  }
  const btn = find("vigil-install"), ios = find("vigil-ios-install");
  out.button = btn ? btn.textContent : null;
  out.ios = ios ? ios.children[0].textContent : null;
  out.iosRole = ios ? ios.attrs.role : null;
  out.stored = store;
  console.log(JSON.stringify(out));
})();
"""


def _run(**cfg):
    base = {"flag": "0", "ua": ANDROID, "path": "/", "actions": []}
    base.update(cfg)
    r = subprocess.run(["node", "-e", _HARNESS, json.dumps(base), str(APP / "pwa.js")], capture_output=True,
                       text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@_node
def test_chromium_gets_an_install_button_that_opens_the_dialog_once():
    out = _run(actions=["bip"])
    assert out["prevented"] == 1 and out["button"] == "Install app"
    out = _run(actions=["bip", "click-install"])
    assert out["prompts"] == 1 and out["button"] is None
    out = _run(actions=["bip", "installed"])
    assert out["button"] is None and out["prompts"] == 0


@_node
def test_nothing_is_offered_under_the_console_mount():
    out = _run(path="/customer/", actions=["bip"])
    assert out["prevented"] == 1 and out["button"] is None


@_node
def test_the_ios_banner_needs_the_flag_an_ios_browser_and_no_install_yet():
    shown = _run(flag="1", ua=IPHONE)
    assert shown["ios"] == "Install VIGIL: tap Share, then Add to Home Screen." and shown["iosRole"] == "note"
    ipad = _run(flag="1", ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", platform="MacIntel", touch=5)
    assert ipad["ios"]                                            # iPadOS reports itself as a Mac with touch
    for cfg in ({"flag": "0", "ua": IPHONE}, {"flag": "__VIGIL_IOS_INSTALL__", "ua": IPHONE},
                {"flag": "1", "ua": ANDROID}, {"flag": "1", "ua": IPHONE, "navStandalone": True},
                {"flag": "1", "ua": IPHONE, "standaloneMedia": True}, {"flag": "1", "ua": IPHONE, "path": "/customer/"},
                {"flag": "1", "ua": IPHONE, "storage": {"vigil.ios_install.dismissed": "1"}}):
        assert _run(**cfg)["ios"] is None, cfg


@_node
def test_dismissing_the_ios_banner_is_remembered():
    out = _run(flag="1", ua=IPHONE, actions=["dismiss-ios"])
    assert out["ios"] is None and out["stored"] == {"vigil.ios_install.dismissed": "1"}


def test_the_flag_is_off_unless_affirmative(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_IOS_INSTALL_BANNER", raising=False)
    assert config.customer_ios_install_banner_enabled() is False
    for v in ("0", "", "no", "false", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_IOS_INSTALL_BANNER", v)
        assert config.customer_ios_install_banner_enabled() is False, v
    for v in ("1", "true", "yes", "on"):
        monkeypatch.setenv("VIGIL_CUSTOMER_IOS_INSTALL_BANNER", v)
        assert config.customer_ios_install_banner_enabled() is True, v


def _page_and_build(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
        r = c.getresponse()
        return r.read().decode(), r.getheader("X-Vigil-Build")
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_edge_writes_the_flag_into_the_page_at_startup(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_IOS_INSTALL_BANNER", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-ios-install="0"' in off and "__VIGIL_IOS_INSTALL__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_IOS_INSTALL_BANNER", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-ios-install="1"' in on
    assert build_on != build_off                                  # a different page is a different build


def test_the_deploy_example_ships_the_banner_off():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert re.search(r"^VIGIL_CUSTOMER_IOS_INSTALL_BANNER=0$", text, re.M)
    assert "real iPhone" in text
