"""Sessions + the five-role RBAC ladder.

S1 uses this for login (writes auth.log) and session issuance. S2 adds the *broken* authorization checks
(BOLA/BFLA/priv-esc) and the weak-JWT surface on top of it. Session tokens are plain opaque cookies stored
in the DB — deliberately simple; the interesting weaknesses are the missing authorization checks, not the
session mechanism.
"""

from __future__ import annotations

import http.cookies
import secrets
import sqlite3
from typing import Optional

# citizen < clerk < inspector < registrar < admin — the authority ladder the back office should enforce.
ROLES = ["citizen", "clerk", "inspector", "registrar", "admin"]
COOKIE_NAME = "session"


def role_rank(role: str) -> int:
    try:
        return ROLES.index(role)
    except ValueError:
        return -1


def authenticate(con: sqlite3.Connection, username: str, password: str) -> Optional[sqlite3.Row]:
    """Return the account row on a correct username+password, else None. (Plaintext compare — weak by design.)"""
    cur = con.execute("SELECT * FROM accounts WHERE username = ?", (username,))
    row = cur.fetchone()
    if row is not None and row["password"] == password:
        return row
    return None


def create_session(con: sqlite3.Connection, *, kind: str, subject_id: int, username: str, role: str) -> str:
    token = secrets.token_hex(16)
    con.execute("INSERT INTO sessions (token, kind, subject_id, username, role) VALUES (?,?,?,?,?)",
                (token, kind, subject_id, username, role))
    con.commit()
    return token


def parse_cookies(cookie_header: str) -> dict[str, str]:
    jar: http.cookies.SimpleCookie = http.cookies.SimpleCookie()
    try:
        jar.load(cookie_header or "")
    except http.cookies.CookieError:
        return {}
    return {k: m.value for k, m in jar.items()}


def session_from_cookies(con: sqlite3.Connection, cookie_header: str) -> Optional[sqlite3.Row]:
    token = parse_cookies(cookie_header).get(COOKIE_NAME)
    if not token:
        return None
    return con.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()


def set_cookie_header(token: str) -> tuple[str, str]:
    """A Set-Cookie header value for the session token (HttpOnly; loopback lab, so no Secure)."""
    return ("Set-Cookie", f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax")
