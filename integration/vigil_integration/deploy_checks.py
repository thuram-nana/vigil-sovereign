"""Deployment-layout checks `vigil doctor` runs against the systemd USER units the host actually has installed.

Three checks, each silent (``{"configured": False}``, no issue, no note) until the units or files it reads exist;
on a development checkout with no sovereign unit installed they add at most a note, never a hard issue:

* :func:`cockpit_port_report` — the operator console (``vigil-command.service``) and the sovereign cockpit
  (``sigil-cockpit.service``) must not both start a cockpit. A plain ``vigil up`` starts its own cockpit on
  127.0.0.1:8733, which is where ``sigil-cockpit`` listens too, so with both enabled the second to start cannot
  bind and restart-loops. Production runs the console ``--proxy-only`` against the cockpit unit
  (``infra/systemd/vigil-command.service.d/production.conf``); the console must then federate ``/sovereign/*``
  to the address the cockpit unit binds.
* :func:`sovereign_venv_report` — ``~/.sigil/venv`` (the path every sovereign unit executes) must exist and be
  the symlink to a hash-locked ``.venv-sovereign`` that ``./bootstrap.sh`` builds, not a separately installed
  virtualenv: a HARD issue while an installed unit runs it, a note on a development install with no such unit.
* :func:`must_match_report` — the settle and money settings that must hold the SAME value in every process that
  settles a customer launch (``config.settle_spine_record_enabled``, OWNER DECISION OD-4, and the metered
  settle's pricing) agree across the cockpit, the customer edge and the settle drain (a HARD issue when they do
  not), and a shell running ``sigil ops-sweep`` that reads only ``sigil.env`` under the cockpit's ``SIGIL_HOME``
  agrees with them (a note naming what that shell must export when it does not).
* :func:`customer_signin_report` — customer Google sign-in agrees between the customer edge and the cockpit.
* :func:`edge_stop_timeout_report` — every installed edge unit (``sigil-{customer,public}{,@}.service``) lets
  systemd wait for that edge's drain before it kills a stopping edge; a unit installed by an older release keeps
  its shorter timeout until it is re-installed.

:func:`unit_process_environment` gives one unit's process environment the same way (``sigil latch`` reads the
cockpit's SIGIL_HOME and the ceilings of its customer latches from it).

Every value is read from the files the units load: the installed unit and its drop-ins under
``~/.config/systemd/user`` (``Environment=`` and ``EnvironmentFile=``, ``%h`` expanded), then ``sigil.env`` under
the process's own ``SIGIL_HOME`` layered beneath it exactly as ``sigil.config`` does at import. Nothing is read
from the environment `vigil doctor` itself runs in, so the verdict is the same from an operator's shell and from
``vigil-ready.service``. stdlib only — no sigil or framework import (FATAL-2). Never raises: an unreadable file reads
as absent.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Callable, Optional

COMMAND_UNIT = "vigil-command.service"
COCKPIT_UNIT = "sigil-cockpit.service"
CUSTOMER_UNIT = "sigil-customer.service"
SETTLE_DRAIN_UNIT = "vigil-settle-drain.service"
PRODUCTION_DROPIN = Path("infra") / "systemd" / "vigil-command.service.d" / "production.conf"

#: Where each unit ships in the repo (read when it is not installed, so its env file paths are still known).
_REPO_UNIT_DIRS = (Path("infra") / "systemd", Path("apps") / "sigil" / "deploy" / "systemd")
#: The cockpit address a plain `vigil up` binds and `--sovereign-addr` defaults to (uiproxy.SOVEREIGN_PORT).
_DEFAULT_SOVEREIGN = ("127.0.0.1", 8733)
_AFFIRMATIVE = frozenset({"1", "true", "yes", "on", "enabled"})   # = sigil.config's affirmative set

#: The settings every process that settles a customer launch must read identically, with the processes that
#: read each. VIGIL_SETTLE_SPINE_RECORD: config.settle_spine_record_enabled (OD-4) names the cockpit, the
#: customer server, the settle drain and ops-sweep. The pricing a metered settle charges by
#: (vigil_core.model_metering.billing_markup / run_floor_credits / cancel_settlement) is read by every process
#: that settles: the cockpit (customer cancel), the settle drain and `ops-sweep reservations --apply`.
_SETTLERS = ("cockpit", "settle-drain", "ops-sweep")
MUST_MATCH: "tuple[tuple[str, str, tuple[str, ...]], ...]" = (
    ("VIGIL_SETTLE_SPINE_RECORD", "switch", ("cockpit", "customer", "settle-drain", "ops-sweep")),
    ("VIGIL_BILLING_TARGET_MARGIN", "value", _SETTLERS),
    ("VIGIL_RUN_FLOOR_CREDITS", "value", _SETTLERS),
    ("VIGIL_BILLING_CANCEL_SETTLEMENT", "value", _SETTLERS),
)
#: Process name → the unit whose files define its environment (ops-sweep runs from the operator's shell).
_PROCESS_UNITS = (("cockpit", COCKPIT_UNIT), ("customer", CUSTOMER_UNIT), ("settle-drain", SETTLE_DRAIN_UNIT))


def user_unit_dir(home: Path) -> Path:
    return Path(home) / ".config" / "systemd" / "user"


def _display(p: "Path | str", home: Path) -> str:
    s = str(p)
    h = str(home)
    return "~" + s[len(h):] if h and (s == h or s.startswith(h.rstrip("/") + "/")) else s


# ── unit file parsing ───────────────────────────────────────────────────────────────────────────────────────
def _logical_lines(text: str) -> "list[str]":
    """Comment-free logical lines, with systemd's backslash continuations folded (joined by a space)."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith(("#", ";"))):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append((buf + line).strip())
        buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out


def _service_directives(text: str) -> "list[tuple[str, str]]":
    """Every ``KEY=value`` under ``[Service]``, in file order."""
    section = ""
    out: list[tuple[str, str]] = []
    for line in _logical_lines(text):
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section == "Service" and "=" in line:
            k, _, v = line.partition("=")
            out.append((k.strip(), v.strip()))
    return out


def _read(p: Path) -> "str | None":
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


class UnitView:
    """One unit as systemd would load it for this user: the installed file plus its drop-ins (or, when it is not
    installed, the copy the repo ships, so the env file paths it names are still known)."""

    def __init__(self, name: str, *, home: Path, repo: Optional[Path] = None) -> None:
        self.name = name
        self.home = Path(home)
        udir = user_unit_dir(self.home)
        installed = udir / name
        self.masked = False
        try:
            self.masked = installed.is_symlink() and os.readlink(installed) == "/dev/null"
        except OSError:
            self.masked = False
        text = None if self.masked else _read(installed)
        self.installed = text is not None
        self.source: "Path | None" = installed if self.installed else None
        if text is None and repo is not None:
            for d in _REPO_UNIT_DIRS:
                cand = Path(repo) / d / name
                text = _read(cand)
                if text is not None:
                    self.source = cand
                    break
        self.directives: list[tuple[str, str]] = _service_directives(text or "")
        self.dropins: list[Path] = []
        if self.installed:
            try:
                drop = sorted((udir / f"{name}.d").glob("*.conf"))
            except OSError:
                drop = []
            for p in drop:
                body = _read(p)
                if body is not None:
                    self.dropins.append(p)
                    self.directives += _service_directives(body)

    # systemd specifiers: only %h (and %%) appear in these units' paths.
    def expand(self, value: str) -> str:
        return value.replace("%%", "\0").replace("%h", str(self.home)).replace("\0", "%")

    def enabled(self) -> bool:
        """True iff enabled for this user: a ``<target>.wants/<unit>`` (or ``.requires``) link under the user
        unit dir — where `systemctl --user enable` records it."""
        if not self.installed:
            return False
        udir = user_unit_dir(self.home)
        try:
            return any(p.name == self.name for pat in ("*.wants", "*.requires") for d in udir.glob(pat)
                       for p in d.iterdir())
        except OSError:
            return False

    def exec_commands(self) -> "list[str]":
        """Every effective ``Exec*=`` command line (ExecStartPre, ExecStart, ExecStop, ...): an empty assignment
        resets that directive's list, as systemd does."""
        cur: dict = {}
        for k, v in self.directives:
            if k.startswith("Exec"):
                cur[k] = [] if not v else cur.get(k, []) + [v]
        return [c for cmds in cur.values() for c in cmds]

    def exec_start(self) -> str:
        """The effective ExecStart: the last one after the most recent empty reset (``ExecStart=``)."""
        cur = ""
        for k, v in self.directives:
            if k == "ExecStart":
                cur = v
        return cur

    def env_files(self) -> "list[tuple[Path, bool]]":
        """``EnvironmentFile=`` entries in order, as ``(path, optional)``; an empty assignment resets the list."""
        out: list[tuple[Path, bool]] = []
        for k, v in self.directives:
            if k != "EnvironmentFile":
                continue
            if not v:
                out = []
                continue
            optional = v.startswith("-")
            out.append((Path(self.expand(v[1:] if optional else v)), optional))
        return out

    def environment(self) -> dict:
        """The environment systemd hands the unit: the user manager's own (``~/.config/environment.d/*.conf``),
        then the ``Environment=`` assignments, then every ``EnvironmentFile=`` in order (a value from an env file
        takes precedence over ``Environment=``). Missing files read empty."""
        env: dict = manager_environment(self.home)
        for k, v in self.directives:
            if k != "Environment":
                continue
            if not v:
                env = {}
                continue
            try:
                words = shlex.split(v)
            except ValueError:
                words = v.split()
            for w in words:
                if "=" in w:
                    a, _, b = w.partition("=")
                    env[a.strip()] = self.expand(b)
        for path, _optional in self.env_files():
            env.update(parse_env_file(path) or {})
        return env


def manager_environment(home: Path) -> dict:
    """``~/.config/environment.d/*.conf`` in name order — the environment the systemd user manager passes to every
    unit it starts (beneath each unit's own settings)."""
    env: dict = {}
    try:
        confs = sorted((Path(home) / ".config" / "environment.d").glob("*.conf"))
    except OSError:
        confs = []
    for c in confs:
        env.update(parse_env_file(c) or {})
    return env


def parse_env_file(path: Path) -> "dict | None":
    """systemd EnvironmentFile lines: ``KEY=VALUE``, ``#``/``;`` comments, optional matching quotes. ``None`` when
    the file is absent or unreadable. Never raises."""
    text = _read(Path(path))
    if text is None:
        return None
    out: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def _layer_sigil_env(env: dict, home: Path) -> dict:
    """``$SIGIL_HOME/sigil.env`` beneath ``env`` (the real environment wins), as ``sigil.config`` loads it at
    import — at THIS process's ``SIGIL_HOME`` (default ``~/.sigil``)."""
    out = dict(env)
    sh = Path(out.get("SIGIL_HOME") or (Path(home) / ".sigil"))
    raw = _read(sh / "sigil.env")
    if raw is None:
        return out
    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out.setdefault(k.strip(), v.strip())
    return out


def _expand_vars(argv: "list[str]", env: dict) -> "list[str]":
    """systemd's ``${VAR}`` / ``$VAR`` substitution in an ExecStart word (unset ⇒ empty)."""
    out: list[str] = []
    for w in argv:
        if w.startswith("${") and w.endswith("}"):
            out.append(env.get(w[2:-1], ""))
        elif w.startswith("$") and w[1:].replace("_", "").isalnum():
            out += (env.get(w[1:], "") or "").split()
        else:
            out.append(w)
    return out


def _argv(unit: UnitView, env: dict) -> "list[str]":
    line = unit.exec_start().lstrip("-@:+!")
    try:
        words = shlex.split(unit.expand(line))
    except ValueError:
        words = unit.expand(line).split()
    return _expand_vars(words, env)


def _opt(argv: "list[str]", flag: str) -> "str | None":
    for i, w in enumerate(argv):
        if w == flag and i + 1 < len(argv):
            return argv[i + 1]
        if w.startswith(flag + "="):
            return w.split("=", 1)[1]
    return None


def _hostport(raw: str, default: "tuple[str, int]") -> "tuple[str, int] | None":
    raw = (raw or "").strip()
    if not raw:
        return default
    host, sep, port = raw.rpartition(":")
    if not sep:
        return (raw, default[1])
    try:
        return (host.strip("[]") or default[0], int(port))
    except ValueError:
        return None


def _canon_host(h: str) -> str:
    h = (h or "").strip().strip("[]").lower()
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return h


def _same_host(client: str, server: str) -> bool:
    """True iff a connection to ``client`` reaches a listener bound to ``server``: the same address (IP literals
    compared canonically), or ``localhost`` against 127.0.0.1 / ::1 (a client tries each address ``localhost``
    resolves to). 127.0.0.1 and ::1 are different addresses: a listener on one refuses a connection to the other."""
    a, b = _canon_host(client), _canon_host(server)
    if a == b:
        return True
    loop = {"127.0.0.1", "::1"}
    return (a == "localhost" and b in loop) or (b == "localhost" and a in loop)


def _fmt_addr(host: str, port: int) -> str:
    h = _canon_host(host)
    return f"[{h}]:{port}" if ":" in h else f"{h}:{port}"


# ── 0.3: one cockpit on 127.0.0.1:8733 ──────────────────────────────────────────────────────────────────────
def _systemctl_active(unit: str) -> "bool | None":
    try:
        cp = subprocess.run(["systemctl", "--user", "is-active", unit], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    state = (cp.stdout or "").strip()
    if not state or cp.returncode not in (0, 3):
        return None
    return state in ("active", "activating", "reloading")


def _empty_domain_issue(cmd: UnitView, argv: "list[str]", home: Path) -> "str | None":
    """A console unit that passes ``--domain`` with no value (``${VIGIL_CONSOLE_DOMAIN}`` unset): `vigil up` refuses
    it, so the console does not start."""
    dom = _opt(argv, "--domain")
    if dom is None or dom.strip():
        return None
    files = ", ".join(_display(p, home) for p, _o in cmd.env_files()) or "its EnvironmentFile"
    return (f"{COMMAND_UNIT} passes an empty --domain: VIGIL_CONSOLE_DOMAIN is not set in its environment "
            f"({files}), and `vigil up` refuses an empty --domain, so the console does not start. Set "
            f"VIGIL_CONSOLE_DOMAIN=<the console's hostname> there (GO-LIVE §6), then `systemctl --user restart "
            f"{COMMAND_UNIT}`.")


def cockpit_port_report(home: Path, repo: Path, *,
                        is_active: Callable[[str], "bool | None"] = _systemctl_active) -> "tuple[dict, list, list]":
    """(section, issues, notes). Configured when BOTH units are installed for this user, or when the console unit
    alone passes an empty ``--domain``."""
    cmd = UnitView(COMMAND_UNIT, home=home)
    cockpit = UnitView(COCKPIT_UNIT, home=home)
    if not cmd.installed:
        return {"configured": False}, [], []
    cmd_env = cmd.environment()
    argv = _argv(cmd, cmd_env)
    proxy_only = "--proxy-only" in argv
    domain_issue = _empty_domain_issue(cmd, argv, Path(home))
    if not cockpit.installed:
        if domain_issue is None:
            return {"configured": False}, [], []
        return ({"configured": True, "console_mode": "proxy-only" if proxy_only else "starts its own cockpit",
                 "cockpit_addr": None, "cockpit_installed": False, "domain": "empty", "ok": False},
                [domain_issue], [])
    ck_env = cockpit.environment()
    ck_argv = _argv(cockpit, ck_env)
    ck_addr = (_opt(ck_argv, "--host") or ck_env.get("SIGIL_UI_BIND") or _DEFAULT_SOVEREIGN[0],
               _opt(ck_argv, "--port") or ck_env.get("SIGIL_UI_PORT") or str(_DEFAULT_SOVEREIGN[1]))
    try:
        cockpit_addr: "tuple[str, int] | None" = (ck_addr[0], int(ck_addr[1]))
    except ValueError:
        cockpit_addr = None

    def _running(u: UnitView) -> bool:
        return u.enabled() or bool(is_active(u.name))

    both = _running(cmd) and _running(cockpit)
    section: dict = {"configured": True, "console_mode": "proxy-only" if proxy_only else "starts its own cockpit",
                     "cockpit_addr": _fmt_addr(*cockpit_addr) if cockpit_addr else None,
                     "cockpit_installed": True, "both_enabled": both}
    issues: list = [domain_issue] if domain_issue else []
    notes: list = []
    if domain_issue:
        section["domain"] = "empty"
    fix = (f"install the production drop-in: mkdir -p {_display(user_unit_dir(home) / (COMMAND_UNIT + '.d'), home)} "
           f"&& cp {PRODUCTION_DROPIN} {_display(user_unit_dir(home) / (COMMAND_UNIT + '.d'), home)}/ && "
           f"systemctl --user daemon-reload && systemctl --user restart {COMMAND_UNIT} (GO-LIVE §6)")
    if not proxy_only:
        section["ok"] = not (both or issues)
        if both:
            same_port = cockpit_addr is not None and cockpit_addr[1] == _DEFAULT_SOVEREIGN[1]
            what = ("the second to start cannot bind 127.0.0.1:8733 and restart-loops" if same_port else
                    "two cockpits would then write the same spine")
            issues.append(f"{COMMAND_UNIT} runs `vigil up` without --proxy-only, so it starts its own sovereign "
                          f"cockpit on 127.0.0.1:8733, and {COCKPIT_UNIT} runs the cockpit too "
                          f"({section['cockpit_addr'] or 'unknown address'}): {what}. Run the console proxy-only "
                          f"against the cockpit unit — {fix}.")
        return section, issues, notes
    sov_raw = _opt(argv, "--sovereign-addr")
    if sov_raw is None:
        sov_raw = cmd_env.get("VIGIL_SOVEREIGN_ADDR", "")
    sov = _hostport(sov_raw, _DEFAULT_SOVEREIGN)
    section["sovereign_addr"] = _fmt_addr(*sov) if sov else sov_raw
    if both and cockpit_addr is not None and (sov is None or not (_same_host(sov[0], cockpit_addr[0])
                                                                 and sov[1] == cockpit_addr[1])):
        issues.append(f"{COMMAND_UNIT} federates /sovereign/* to {section['sovereign_addr']} but {COCKPIT_UNIT} "
                      f"listens on {section['cockpit_addr']}: every sovereign request from the console fails. "
                      f"Point --sovereign-addr at the cockpit's SIGIL_UI_BIND:SIGIL_UI_PORT.")
    section["ok"] = not issues
    if not _running(cockpit):
        notes.append(f"{COMMAND_UNIT} runs proxy-only but {COCKPIT_UNIT} is neither enabled nor running, so the "
                     f"console's /sovereign/* has no cockpit behind it (`systemctl --user enable --now "
                     f"{COCKPIT_UNIT}`).")
    return section, issues, notes


# ── 0.4: ~/.sigil/venv is the hash-locked sovereign venv ─────────────────────────────────────────────────────
def units_running_the_sovereign_venv(home: Path) -> "list[str]":
    """The installed (not masked) user units whose ``Exec*=`` commands run ``~/.sigil/venv`` — every sigil-* unit
    and money drain, read from the unit and its drop-ins."""
    udir = user_unit_dir(home)
    venv = str(Path(home) / ".sigil" / "venv") + "/"
    try:
        names = sorted(p.name for p in udir.glob("*.service"))
    except OSError:
        return []
    out: list[str] = []
    for name in names:
        u = UnitView(name, home=home)
        if u.installed and any(venv in u.expand(c) for c in u.exec_commands()):
            out.append(name)
    return out


def sovereign_venv_report(home: Path, repo: Path) -> "tuple[dict, list, list]":
    """(section, issues, notes) for ``~/.sigil/venv`` — the path every sovereign unit executes
    (``%h/.sigil/venv/bin/sigil``). A finding is a HARD issue when an installed unit runs it, and a note when none
    does (a development install). Absent with no such unit ⇒ not configured (silent)."""
    venv = Path(home) / ".sigil" / "venv"
    shown = _display(venv, Path(home))
    locked = Path(repo) / ".venv-sovereign"
    runners = units_running_the_sovereign_venv(Path(home))
    relink = f"mv {shown} {shown}.unlocked; ln -s {locked} {shown} (or re-run ./bootstrap.sh with SIGIL_HOME unset)"

    def _finding(section: dict, msg: str) -> "tuple[dict, list, list]":
        section["units"] = runners
        if runners:
            section["ok"] = False
            return section, [msg + f" It is run by {', '.join(runners)}."], []
        section["ok"] = True
        return section, [], [msg + " No installed unit runs it yet; fix it before installing the sovereign units."]

    if not venv.is_symlink():
        if not venv.exists():
            if not runners:
                return {"configured": False}, [], []
            return ({"configured": True, "path": shown, "symlink": False, "exists": False, "units": runners,
                     "ok": False},
                    [f"{shown} does not exist, so no installed unit that runs {shown}/bin/sigil can start "
                     f"({', '.join(runners)}). Run ./bootstrap.sh with SIGIL_HOME unset (it links {shown} to the "
                     f"hash-locked .venv-sovereign), or ln -s {locked} {shown}."], [])
        return _finding({"configured": True, "path": shown, "symlink": False},
                        f"{shown} is a separately installed virtualenv, not the symlink to the hash-locked "
                        f".venv-sovereign that ./bootstrap.sh builds (envs/build_envs.sh installs it from "
                        f"hash-pinned requirements); a unit that runs {shown}/bin/sigil runs whatever was installed "
                        f"into it. Replace it: {relink}.")
    try:
        target = venv.resolve(strict=True)
    except (OSError, RuntimeError):
        return _finding({"configured": True, "path": shown, "symlink": True, "target": None},
                        f"{shown} is a symlink to a directory that does not exist, so nothing can run "
                        f"{shown}/bin/sigil. Relink it: ln -sfn {locked} {shown} (or re-run ./bootstrap.sh with "
                        f"SIGIL_HOME unset).")
    section = {"configured": True, "path": shown, "symlink": True, "target": _display(target, Path(home)),
               "ok": True}
    if target.name != ".venv-sovereign" or not (target / "bin" / "sigil").exists():
        return _finding(section, f"{shown} links to {_display(target, Path(home))}, which is not a built "
                                 f".venv-sovereign (the hash-locked sovereign venv ./bootstrap.sh builds, with "
                                 f"bin/sigil). Relink it: ln -sfn {locked} {shown}.")
    section["units"] = runners
    try:
        same = target == locked.resolve()
    except (OSError, RuntimeError):
        same = False
    notes = [] if same else [f"{shown} links to {_display(target, Path(home))}, not this checkout's .venv-sovereign "
                             f"({_display(locked, Path(home))}): the sovereign units run that other checkout."]
    return section, [], notes


# ── 0.5: settle / money settings that must match ────────────────────────────────────────────────────────────
def _norm(kind: str, raw: "str | None") -> "str | None":
    v = (raw or "").strip()
    if kind == "switch":
        return "on" if v.lower() in _AFFIRMATIVE else "off"
    return v or None


def _sigil_home_of(env: dict, home: Path) -> Path:
    """The ``SIGIL_HOME`` a process with environment ``env`` reads ``sigil.env`` from (``sigil.config``'s rule)."""
    return Path(env.get("SIGIL_HOME") or (Path(home) / ".sigil"))


def unit_process_environment(unit_name: str, home: Path, repo: "Path | None" = None) -> "dict | None":
    """The environment a process started by ``unit_name`` runs with, read only from the files it loads (the unit and
    its drop-ins, the user manager's environment.d, its env files, then ``sigil.env`` beneath them), with
    ``SIGIL_HOME`` always set to the home that process resolves (its environment's, else ``~/.sigil``; ``sigil.env``
    cannot move it). ``None`` when no such unit is configured for this user: it is not installed and none of the env
    files it names exists. Never raises."""
    try:
        u = UnitView(unit_name, home=Path(home), repo=repo)
        if not (u.installed or any(p.exists() for p, _o in u.env_files())):
            return None
        env = u.environment()
        out = _layer_sigil_env(env, Path(home))
        out["SIGIL_HOME"] = str(_sigil_home_of(env, Path(home)))
        return out
    except Exception:  # noqa: BLE001 — an unreadable unit reads as not configured
        return None


def process_environments(home: Path, repo: Path) -> "tuple[dict, dict]":
    """``({process: effective env}, {process: description})`` for every process that takes part, read only from
    files — never from the environment `vigil doctor` itself runs in, so the verdict is the same from an operator's
    shell and from ``vigil-ready.service``.

    A unit-backed process (the cockpit, the customer edge, the settle drain) takes part when its unit is installed
    or one of the env files it names exists. ``ops-sweep`` runs from an operator's shell, not a unit: it is read as
    a shell that exports the cockpit's ``SIGIL_HOME`` (the first unit-backed process that takes part, when the
    cockpit does not) and nothing else, so it reads ``sigil.env`` there. It takes part only beside a unit-backed
    process."""
    envs: dict = {}
    where: dict = {}
    for proc, unit_name in _PROCESS_UNITS:
        u = UnitView(unit_name, home=home, repo=repo)
        files = u.env_files()
        present = [p for p, _o in files if p.exists()]
        if not (u.installed or present):
            continue
        envs[proc] = _layer_sigil_env(u.environment(), Path(home))
        where[proc] = {"unit": unit_name, "installed": u.installed,
                       "env_files": [_display(p, Path(home)) for p in present]}
    if envs:
        sh = _sigil_home_of(next(iter(envs.values())), Path(home))
        envs["ops-sweep"] = _layer_sigil_env({"SIGIL_HOME": str(sh)}, Path(home))
        where["ops-sweep"] = {"env": f"a shell with SIGIL_HOME={_display(sh, Path(home))}",
                              "sigil_env": _display(sh / "sigil.env", Path(home))}
    return envs, where


def _state(kind: str, vals: dict) -> str:
    """Which processes hold which state, never the value itself."""
    if kind == "switch":
        groups: dict = {}
        for p, v in vals.items():
            groups.setdefault(v, []).append(p)
        return "; ".join(f"{v} in {', '.join(ps)}" for v, ps in sorted(groups.items()))
    unset = [p for p, v in vals.items() if v is None]
    distinct: dict = {}
    for p, v in vals.items():
        if v is not None:
            distinct.setdefault(v, []).append(p)
    parts = [f"unset in {', '.join(unset)}"] if unset else []
    if len(distinct) == 1:
        parts.insert(0, f"set in {', '.join(next(iter(distinct.values())))}")
    elif distinct:
        parts.insert(0, "different values in " + " / ".join(", ".join(ps) for ps in distinct.values()))
    return "; ".join(parts)


def must_match_report(home: Path, repo: Path) -> "tuple[dict, list, list]":
    """(section, issues, notes). A disagreement between the UNITS that settle (read from the files they load) is a
    HARD issue naming the setting and which processes hold which state — never the value itself. ``ops-sweep`` is
    run by hand from a shell the doctor cannot see, so a difference between the units and what a shell reads from
    ``sigil.env`` (:func:`process_environments`) is a note naming what that shell must export; the doctor's own
    environment never decides either."""
    envs, where = process_environments(home, repo)
    units = [p for p in envs if p != "ops-sweep"]
    if not units:
        return {"configured": False}, [], []
    homes = {p: _sigil_home_of(envs[p], Path(home)) for p in units}
    distinct_homes = sorted({str(h) for h in homes.values()})
    if len(distinct_homes) == 1:
        once = (f"Set it once in {_display(Path(distinct_homes[0]) / 'sigil.env', Path(home))} (each of them reads it "
                f"beneath its own env file) and remove it from the unit env files")
    else:
        once = ("They read sigil.env under different SIGIL_HOMEs ("
                + "; ".join(f"{p}: {_display(h, Path(home))}" for p, h in homes.items())
                + "): set the same SIGIL_HOME in each unit's env file, then set it once in that sigil.env")
    flags: dict = {}
    issues: list = []
    notes: list = []
    for name, kind, readers in MUST_MATCH:
        present = [p for p in readers if p in envs]
        vals = {p: _norm(kind, envs[p].get(name)) for p in present}
        flags[name] = (dict(vals) if kind == "switch" else
                       {p: ("set" if v is not None else "unset") for p, v in vals.items()})
        unit_vals = {p: v for p, v in vals.items() if p != "ops-sweep"}
        if len(set(unit_vals.values())) > 1:
            issues.append(f"{name} must be the same in every process that settles customer launches, and it is not "
                          f"({_state(kind, unit_vals)}). A process with a different value settles differently from "
                          f"the others. {once}, or set the same value in each: ~/.sigil/cockpit.env, "
                          f"~/.sigil/customer.env and ~/.config/vigil/settle-drain.env (and export it in the shell "
                          f"that runs `sigil ops-sweep`). Restart the units after the change.")
            continue
        if "ops-sweep" not in vals or not unit_vals or vals["ops-sweep"] == next(iter(unit_vals.values())):
            continue
        sweep_file = where["ops-sweep"]["sigil_env"]
        want = next(iter(unit_vals.values()))
        if want is None or want == "off":
            fix = (f"Remove it from {sweep_file} (the units' env files override it there), or "
                   + (f"`export {name}=0`" if kind == "switch" else f"`unset {name}`")
                   + " in that shell before every `sigil ops-sweep`")
        elif kind == "switch":
            fix = f"Set it once in {sweep_file}, or `export {name}=1` in that shell before every `sigil ops-sweep`"
        else:
            fix = (f"Set it once in {sweep_file}, or export the same {name} as ~/.sigil/cockpit.env in that shell "
                   f"before every `sigil ops-sweep`")
        notes.append(f"{name} differs between the units that settle and `sigil ops-sweep` run from a shell that "
                     f"reads only {sweep_file} ({_state(kind, vals)}): a sweep from such a shell settles differently "
                     f"from the units. {fix}.")
    section = {"configured": True, "processes": where, "flags": flags, "ok": not issues,
               "ops_sweep_agrees": not notes}
    return section, issues, notes


# ── customer sign-in: Google, and Google inside the installed app ───────────────────────────────────────────────────
#: Read by BOTH the customer edge (the button, the redirect to Google) and the cockpit's provisioner (the token
#: exchange): with different values in the two, the button is shown and every Google sign-in fails, or the reverse.
_OIDC_SHARED = ("VIGIL_CUSTOMER_OIDC_ENABLED", "VIGIL_CUSTOMER_OIDC_CLIENT_ID", "VIGIL_CUSTOMER_OIDC_REDIRECT_URI")
_OIDC_FILES = {"customer": "~/.sigil/customer.env", "cockpit": "~/.sigil/cockpit.env"}


def customer_signin_report(home: Path, repo: Path) -> "tuple[dict, list, list]":
    """(section, issues, notes) for customer Google sign-in, from the env files the customer edge and the cockpit
    units load (values are never printed). Silent until one of the two takes part.

    HARD: the Google switch, client id or redirect URI differ between the edge and the cockpit; Google sign-in is on
    in one of them without its client id or redirect URI; on in the cockpit without the client secret.
    NOTE: Google sign-in is on at the edge without VIGIL_CUSTOMER_OIDC_HANDOFF — in an app installed to an iPhone
    Home Screen, Google sign-in then finishes in another browser and the person is not signed in to the app."""
    envs, _where = process_environments(home, repo)
    procs = [p for p in ("customer", "cockpit") if p in envs]
    if not procs:
        return {"configured": False}, [], []

    def get(proc: str, name: str) -> "str | None":
        v = (envs[proc].get(name) or "").strip()
        return v or None

    google = {p: _norm("switch", get(p, "VIGIL_CUSTOMER_OIDC_ENABLED")) for p in procs}
    issues: list = []
    notes: list = []
    if len(procs) == 2:
        for name in _OIDC_SHARED:
            a = _norm("switch", get("customer", name)) if name == _OIDC_SHARED[0] else get("customer", name)
            b = _norm("switch", get("cockpit", name)) if name == _OIDC_SHARED[0] else get("cockpit", name)
            if name != _OIDC_SHARED[0] and "on" not in google.values():
                continue
            if a != b:
                state = (f"{a} in the customer edge, {b} in the cockpit" if name == _OIDC_SHARED[0]
                         else "set differently in the customer edge and the cockpit" if a and b
                         else f"set in the {'customer edge' if a else 'cockpit'} only")
                issues.append(f"{name} must be the same for the customer edge and the cockpit, and it is not "
                              f"({state}). The edge shows the Google button and sends people to Google; the cockpit "
                              f"finishes the sign-in: with different values every Google sign-in fails or the button "
                              f"is missing. Set it once in $SIGIL_HOME/sigil.env, or the same value in "
                              f"{_OIDC_FILES['customer']} and {_OIDC_FILES['cockpit']}; restart both units.")
    for proc in procs:
        if google[proc] != "on":
            continue
        need = ["VIGIL_CUSTOMER_OIDC_CLIENT_ID", "VIGIL_CUSTOMER_OIDC_REDIRECT_URI"]
        if proc == "cockpit":
            need.append("VIGIL_CUSTOMER_OIDC_CLIENT_SECRET")
        missing = [n for n in need if get(proc, n) is None]
        if missing:
            issues.append(f"Customer Google sign-in is on in the {'customer edge' if proc == 'customer' else 'cockpit'} "
                          f"but {', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not set there "
                          f"({_OIDC_FILES[proc]}): Google sign-in cannot complete. Set "
                          f"{'it' if len(missing) == 1 else 'them'} (the client secret in the cockpit only, from your "
                          f"secret manager) and restart the unit, or turn VIGIL_CUSTOMER_OIDC_ENABLED off.")
    handoff = "customer" in procs and _norm("switch", get("customer", "VIGIL_CUSTOMER_OIDC_HANDOFF")) == "on"
    if google.get("customer") == "on" and not handoff:
        notes.append("Customer Google sign-in is on but VIGIL_CUSTOMER_OIDC_HANDOFF is off in "
                     f"{_OIDC_FILES['customer']}: in an app installed to an iPhone Home Screen, Google sign-in finishes "
                     "in another browser and the person is not signed in to the app. Set VIGIL_CUSTOMER_OIDC_HANDOFF=1 "
                     "there and restart the customer edge.")
    section = {"configured": True, "google": google, "handoff": handoff, "ok": not issues}
    return section, issues, notes


# ── the edges' stop timeout ───────────────────────────────────────────────────────────────────────────────────────
#: The stop timeout each edge's units must allow: the edge's drain deadline (custui.drain_deadline_s 75 s for the
#: customer edge; ui/graceful.DRAIN_DEADLINE_S 10 s for the public site) + the handshake grace + 5 s. The same floor
#: tools/deploy/edge-swap.sh enforces; a sovereign test pins both to the servers' deadlines.
EDGE_STOP_FLOOR_S = {"customer": 81, "public": 16}
_EDGE_UNITS = (("customer", "sigil-customer.service"), ("customer", "sigil-customer@.service"),
               ("public", "sigil-public.service"), ("public", "sigil-public@.service"))
#: systemd's default stop timeout (DefaultTimeoutStopSec) when a unit sets none.
_SYSTEMD_DEFAULT_STOP_S = 90.0
_SPAN_UNITS = {"": 1.0, "s": 1.0, "sec": 1.0, "second": 1.0, "seconds": 1.0, "us": 1e-6, "usec": 1e-6,
               "ms": 1e-3, "msec": 1e-3, "m": 60.0, "min": 60.0, "minute": 60.0, "minutes": 60.0,
               "h": 3600.0, "hr": 3600.0, "hour": 3600.0, "hours": 3600.0, "d": 86400.0, "day": 86400.0,
               "days": 86400.0}
_SPAN_PART = re.compile(r"\s*(\d+(?:\.\d+)?)\s*([a-z]*)")


def parse_timespan(raw: str) -> "float | None":
    """A systemd time span as a unit file writes it ("90", "90s", "1min 30s", "1min30s", "infinity") in seconds;
    None when it cannot be read."""
    v = (raw or "").strip()
    if v == "infinity":
        return float("inf")
    total, pos = 0.0, 0
    for m in _SPAN_PART.finditer(v):
        if m.start() != pos or m.group(2) not in _SPAN_UNITS:
            return None
        total += float(m.group(1)) * _SPAN_UNITS[m.group(2)]
        pos = m.end()
    return total if v and pos == len(v) else None


def edge_stop_timeout_report(home: Path, repo: Path) -> "tuple[dict, list, list]":
    """(section, issues, notes) for the stop timeout of every INSTALLED edge unit (with its drop-ins; the last
    ``TimeoutStopSec=``/``TimeoutSec=`` wins, none means systemd's default 90 s). Silent until one is installed.

    HARD: below ``EDGE_STOP_FLOOR_S`` — systemd would kill a stopping edge while it still finishes an action it
    accepted (the action done, the customer told it failed, a retry doing it twice). NOTE: a value it cannot read."""
    del repo                                           # only the installed units matter (never the repo's copies)
    units: dict = {}
    issues: list = []
    notes: list = []
    for edge, name in _EDGE_UNITS:
        u = UnitView(name, home=home)
        if not u.installed:
            continue
        raw = None
        for k, v in u.directives:
            if k in ("TimeoutStopSec", "TimeoutSec"):
                raw = v
        secs = _SYSTEMD_DEFAULT_STOP_S if raw is None or raw == "" else parse_timespan(raw)
        floor = EDGE_STOP_FLOOR_S[edge]
        if secs is None:
            units[name] = "unreadable"
            notes.append(f"{name}: TimeoutStopSec={raw!r} could not be read; a stopping {edge} edge needs systemd to "
                         f"wait at least {floor} s. Install this release's unit (RELEASE-UPGRADE-ROLLBACK.md §2.6).")
            continue
        units[name] = secs
        if secs < floor:
            issues.append(f"{name} lets systemd stop the {edge} edge after {secs:g} s (TimeoutStopSec), but a "
                          f"stopping {edge} edge may need {floor} s to finish the requests it accepted: systemd would "
                          f"kill it part way through an action (the action done, the customer told it failed). "
                          f"Install this release's unit: cp apps/sigil/deploy/systemd/{name} ~/.config/systemd/user/ "
                          f"&& systemctl --user daemon-reload (RELEASE-UPGRADE-ROLLBACK.md §2.6).")
    if not units:
        return {"configured": False}, [], []
    return {"configured": True, "units": units, "ok": not issues}, issues, notes
