"""Network diagnostics — the OS command-injection surface (CWE-78).

Vuln mode: the `host` value is string-concatenated into a shell command (`ping -c1 -w2 <host>`) that runs
via `subprocess.run(..., shell=True)`, and the command's combined stdout/stderr is reflected back into the
page. So `host=127.0.0.1; id` runs `id` and its output appears — the injection is confirmable from the
response body alone (achieved-state / side-effect), with NO out-of-band collector. Hardened mode: the SAME
route + SAME `host` param is validated to a strict hostname/IP, run with `shell=False` (an argv list, so no
shell metacharacter is ever interpreted), and the output is fixed to a reachable/unreachable summary. Same
route, same param — so VIGIL's oracle fires in vuln and goes silent (a sound CLEAN) in hardened.

Safe to run: it only ever pings loopback by default, one packet with a short deadline, bounded output.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess

from .. import theme
from ..router import Ctx, Response, Router

_DEFAULT_HOST = "127.0.0.1"
_PING_TIMEOUT = 4.0        # subprocess wall-clock cap (seconds) — the box cannot be hung
_OUTPUT_CAP = 4000         # max chars of command output reflected back

# A strict RFC-1123 hostname (the hardened allow-rule, alongside ipaddress for IPv4/IPv6). No space, ';',
# '|', '&', '$' or backtick can match — which is precisely why the hardened twin cannot be injected.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Module-level synthetic fleet — CLEARLY-FAKE labels, all pointed at loopback so every quick-check is safe.
_NODES = [
    {"id": "node-01", "label": "Permit register DB (primary)", "host": "127.0.0.1"},
    {"id": "node-02", "label": "Records cache", "host": "localhost"},
    {"id": "node-03", "label": "PermitBot gateway (edge)", "host": "127.0.0.1"},
    {"id": "node-04", "label": "Document store (replica)", "host": "127.0.0.1"},
]


def _valid_host(host: str) -> bool:
    """True iff `host` is a bare IP literal or a strict hostname (the hardened validation gate)."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


def _run_vuln(host: str) -> tuple[str, str]:
    """INTENTIONAL CWE-78: `host` is concatenated into a shell string and executed with shell=True."""
    cmd = "ping -c1 -w2 " + host
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True,  # noqa: S602 — the planted sink
                              timeout=_PING_TIMEOUT)
        out = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        out = "(diagnostic timed out)\n"
    except Exception as exc:  # noqa: BLE001 — a target must never crash on a bad probe
        out = f"(diagnostic error: {type(exc).__name__})\n"
    return cmd, out[:_OUTPUT_CAP]


def _run_hardened(host: str) -> str:
    """Safe twin: argv list, shell=False (no injection), output fixed to a reachable/unreachable summary."""
    try:
        proc = subprocess.run(["ping", "-c1", "-w2", host], shell=False,  # noqa: S603 — argv, no shell
                              capture_output=True, text=True, timeout=_PING_TIMEOUT)
        reachable = proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        reachable = False
    return (f"Host {host} is reachable — 1 packet transmitted, 1 received."
            if reachable else f"Host {host} did not respond within the probe window.")


def _form(host: str) -> str:
    """The ad-hoc probe form, pre-filled with the submitted host (escaped — this is the CMDi screen only)."""
    return (
        '<div class="card"><form method="get" action="/diagnostics/ping">'
        '<label class="field"><span>Host or IP to probe</span>'
        f'<input name="host" value="{theme.esc(host)}" placeholder="127.0.0.1"></label>'
        '<button class="btn primary" type="submit">Run diagnostic</button></form></div>'
    )


def _diagnostics_home(ctx: Ctx) -> Response:
    rows = "".join(
        f'<tr><td class="mono">{theme.esc(n["id"])}</td><td>{theme.esc(n["label"])}</td>'
        f'<td class="mono">{theme.esc(n["host"])}</td>'
        f'<td><a class="btn sm" href="/diagnostics/ping?host={theme.esc(n["host"])}">Ping</a></td></tr>'
        for n in _NODES
    )
    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Operations</span>'
        '<h1>Network diagnostics</h1>'
        '<p class="sub">Run a reachability probe against a monitored node, or enter an ad-hoc host.</p></div>'
        f'{_form(_DEFAULT_HOST)}'
        '<div class="card scroll-x" style="margin-top:var(--sp-4)"><div class="card-h">'
        '<span class="label">Monitored nodes</span><h3>Fleet reachability</h3></div>'
        '<table><thead><tr><th>Node</th><th>Description</th><th>Host</th><th></th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div></main>'
    )
    return Response.html(theme.page("Network diagnostics", body, active="diagnostics", mode=ctx.mode))


def _diagnostics_ping(ctx: Ctx) -> Response:
    host = ctx.q1("host") or _DEFAULT_HOST

    if ctx.hardened:
        if not _valid_host(host):
            panel = ('<div class="notice danger" style="margin-top:var(--sp-4)">'
                     f'Refused: <code>{theme.esc(host)}</code> is not a valid hostname or IP address.</div>')
        else:
            panel = ('<div class="notice" style="margin-top:var(--sp-4)">'
                     f'{theme.esc(_run_hardened(host))}</div>')
    else:
        # VULNERABLE: build + run the shell command, reflect its output. An injected `; id` / `; echo MARKER`
        # executes and its stdout appears below — confirmable with no out-of-band collector.
        cmd, out = _run_vuln(host)
        panel = ('<div class="card" style="margin-top:var(--sp-4)"><div class="card-h">'
                 '<span class="label">Diagnostic output</span><h3>Probe result</h3></div>'
                 f'<pre class="console">$ {theme.esc(cmd)}\n{theme.esc(out)}</pre></div>')

    body = (
        '<main class="wrap"><div class="screen-head"><span class="label">Operations</span>'
        f'<h1>Diagnostic: {theme.esc(host)}</h1>'
        '<p class="sub"><a href="/diagnostics">New diagnostic</a></p></div>'
        f'{_form(host)}{panel}</main>'
    )
    return Response.html(theme.page("Diagnostic result", body, active="diagnostics", mode=ctx.mode))


def register(r: Router) -> None:
    r.add("GET", "/diagnostics", _diagnostics_home)
    r.add("GET", "/diagnostics/ping", _diagnostics_ping)
