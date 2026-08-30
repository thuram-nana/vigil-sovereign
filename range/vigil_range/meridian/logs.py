"""Detection-Mirror-compatible log writers.

MERIDIAN emits two log files whose line shapes are byte-compatible with VIGIL's `vigil detect` parsers
(integration/vigil_integration/detection/logs.py):

  * access.log — Apache/nginx Combined Log Format (one line per request). The recon / forced-browsing /
    scanner-UA / in-path SQLi-XSS-traversal signatures live here.
  * auth.log   — `<ts> src= user= result=success|failure` (one line per /login attempt). The brute-force /
    password-spray signatures live here.

A third plane, conn.log (`<ts> src= dst= dport= proto=`), is flow telemetry the app itself cannot produce;
the Range Control ships a synthetic conn.log for the port_scan demo.
"""

from __future__ import annotations

import datetime
import threading

_ACCESS_LOCK = threading.Lock()
_AUTH_LOCK = threading.Lock()


def clf_now() -> str:
    """A Combined-Log-Format timestamp, e.g. `29/Aug/2026:15:26:30 +0000`."""
    return datetime.datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")


def write_access(path: str, client_ip: str, requestline: str, status: int, size: int,
                 referer: str = "-", user_agent: str = "-") -> None:
    """Append one CLF line. Matches detection/logs.py `_CLF_RE`:
    `%h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-agent}i"`."""
    line = (f'{client_ip} - - [{clf_now()}] "{requestline}" {status} {size} '
            f'"{referer or "-"}" "{user_agent or "-"}"\n')
    with _ACCESS_LOCK:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)


def write_auth(path: str, client_ip: str, user: str, result: str) -> None:
    """Append one auth line. Matches detection/logs.py `_kv` tokens; result must be success|failure."""
    res = "success" if str(result).lower() == "success" else "failure"
    line = f'{clf_now()} src={client_ip} user={user or "-"} result={res}\n'
    with _AUTH_LOCK:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
