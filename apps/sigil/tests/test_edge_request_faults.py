"""A request that makes an edge's handler fail gets one clean answer — never a connection closed with no response.

nginx counts a connection an edge drops as that edge failing, and a POST that reached an edge is never sent again,
so a dropped connection is the worst answer an edge can give. Reproduced cases:
  * custui: a POST body nested deeper than the JSON parser can follow (RecursionError, not a ValueError) — 400;
  * pubui: /api/cve?page=² — '²'.isdigit() is True but int('²') raises — and a page number longer than int()
    converts; a bad number is ignored like any other non-number;
  * pubui: any other fault inside a GET or HEAD — 500, no-store, no internals.
"""
from __future__ import annotations

import http.client
import json
import socket
import threading

import pytest

from sigil.ui.custui import build_customer_server
from sigil.ui.pubui import PublicHandler, PublicServer


def _serve(srv):
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return srv.server_address[1]


def _req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers={"Host": f"127.0.0.1:{port}", **(headers or {})})
    r = c.getresponse()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()


@pytest.fixture()
def customer(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "sessions"))
    port = _serve(srv)
    yield port
    srv.shutdown()
    srv.server_close()


def test_custui_answers_a_body_nested_too_deeply_for_the_parser(customer):
    port = customer
    body = b"[" * 40000                                   # under the 64 KiB body cap
    status, h, raw = _req(customer, "POST", "/api/customer/login", body,
                          {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
    assert status == 400 and h.get("cache-control") == "no-store"
    assert json.loads(raw)["error"].startswith("bad request")
    assert _req(port, "GET", "/healthz")[0] == 200


def test_custui_answers_any_other_fault_in_a_post(customer, monkeypatch):
    from sigil.ui import custui

    def _boom(self):
        raise RuntimeError("internal detail that must not leak")

    monkeypatch.setattr(custui.CustomerHandler, "_origin_host_ok", _boom)
    status, h, raw = _req(customer, "POST", "/api/customer/login", b"{}", {"Content-Type": "application/json"})
    assert status == 500 and json.loads(raw) == {"error": "request failed"}
    assert b"internal detail" not in raw and h.get("cache-control") == "no-store"


@pytest.fixture()
def public(tmp_path):
    from sigil.cve.catalog import CveCatalogStore
    db = tmp_path / "cat.db"
    CveCatalogStore(str(db)).merge_many([{"id": "CVE-2021-44228", "title": "Log4Shell", "cvss_base": 10.0}])
    srv = PublicServer(("127.0.0.1", 0), PublicHandler, catalog_path=str(db))
    port = _serve(srv)
    yield port
    srv.shutdown()
    srv.server_close()


@pytest.mark.parametrize("query", [
    "page=%C2%B2", "per_page=%C2%B2", "year=%C2%B2", "page=%D9%A3",                 # '²', and an Arabic-Indic 3
    pytest.param("page=" + "9" * 5000, id="page-5000-digits"),                      # beyond int()'s digit limit
    pytest.param("per_page=" + "9" * 5000, id="per_page-5000-digits"),
    pytest.param("year=" + "1" * 5000, id="year-5000-digits")])
def test_pubui_ignores_a_number_it_cannot_use(public, query):
    status, _h, raw = _req(public, "GET", "/api/cve?" + query)
    d = json.loads(raw)
    assert status == 200 and d["populated"] is True and d["total"] == 1 and d["page"] == 1


def test_pubui_still_reads_ordinary_numbers(public):
    d = json.loads(_req(public, "GET", "/api/cve?page=1&per_page=5&year=2021")[2])
    assert (d["page"], d["per_page"], d["total"]) == (1, 5, 1)


@pytest.mark.parametrize("method,path,ctype", [("GET", "/api/cve", "application/json"),
                                               ("GET", "/", "text/plain"), ("HEAD", "/", "text/plain")])
def test_pubui_answers_any_other_fault(public, monkeypatch, method, path, ctype):
    from sigil.ui import pubui

    def _boom(*_a, **_k):
        raise RuntimeError("internal detail that must not leak")

    monkeypatch.setattr(pubui.PublicHandler, "_cve_api", _boom)
    monkeypatch.setattr(pubui.PublicHandler, "_serve", _boom)
    status, h, raw = _req(public, method, path)
    assert status == 500 and h.get("cache-control") == "no-store" and h["content-type"].startswith(ctype)
    assert b"internal detail" not in raw
    assert (raw == b"") if method == "HEAD" else raw
    assert h.get("content-security-policy") and h.get("x-vigil-build")


def test_a_fault_never_closes_the_connection_without_an_answer(public, monkeypatch):
    from sigil.ui import pubui
    monkeypatch.setattr(pubui.PublicHandler, "_serve", lambda *_a, **_k: 1 / 0)
    s = socket.create_connection(("127.0.0.1", public), timeout=10)
    s.sendall(f"GET / HTTP/1.0\r\nHost: 127.0.0.1:{public}\r\n\r\n".encode())
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    s.close()
    assert data.startswith(b"HTTP/1.0 500 ")
