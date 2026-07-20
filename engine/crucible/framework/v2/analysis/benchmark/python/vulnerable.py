"""
DAA taint benchmark — VULNERABLE variant.

Every function has a real source->sink dataflow: attacker-controlled
request input reaches a dangerous sink. Ground truth in ground-truth.json.
This is a benchmark fixture, not a runnable app.
"""

from __future__ import annotations

import os
import sqlite3

import requests
from flask import render_template_string, request


def cmd_injection() -> None:
    name = request.args.get("name")            # source
    os.system("ping -c1 " + name)              # sink: CWE-78


def sql_injection(cur: sqlite3.Cursor) -> None:
    uid = request.args.get("uid")              # source
    cur.execute("SELECT * FROM users WHERE id = " + uid)  # sink: CWE-89


def ssrf() -> None:
    url = request.args.get("url")              # source
    requests.get(url, timeout=5)               # sink: CWE-918


def code_injection() -> None:
    expr = request.args.get("expr")            # source
    eval(expr)                                 # sink: CWE-95


def path_traversal() -> str:
    name = request.args.get("file")            # source
    with open(name) as fh:                     # sink: CWE-22
        return fh.read()


def ssti() -> str:
    tmpl = request.args.get("tmpl")            # source
    return render_template_string(tmpl)        # sink: CWE-1336
