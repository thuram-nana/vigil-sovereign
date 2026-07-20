"""
DAA taint benchmark — SANITIZED variant.

The SAME sink functions as vulnerable.py, but the dangerous dataflow is
broken: input is parameterised, validated, sanitised, or replaced by a
constant. A regex/pattern scanner flags these too (it still sees
os.system, execute, eval, open, requests.get, render_template_string); a
taint analysis must NOT — that is the whole point of the benchmark.
"""

from __future__ import annotations

import os
import shlex
import sqlite3

import requests
from flask import render_template_string, request

_INTERNAL_HEALTH = "https://internal.svc.local/health"


def cmd_injection() -> None:
    name = request.args.get("name")
    os.system("ping -c1 " + shlex.quote(name))      # sanitizer breaks taint


def sql_injection(cur: sqlite3.Cursor) -> None:
    uid = request.args.get("uid")
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))  # parameterised


def ssrf() -> None:
    requests.get(_INTERNAL_HEALTH, timeout=5)        # constant URL, untainted


def code_injection() -> None:
    expr = "1 + 1"
    eval(expr)                                       # constant


def path_traversal() -> str:
    with open("/etc/app/config.ini") as fh:          # constant path
        return fh.read()


def ssti() -> str:
    return render_template_string("<b>status: ok</b>")  # constant template
