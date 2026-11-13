"""E3a — do the configured MONEY-SEAM units agree on ONE seam base? (`vigil doctor` reads this)

The cross-plane seam (published credit leases, target authorizations, pause + settlement markers, the offense
engine's floor and attempt markers) only works if every process that touches it resolves the SAME directory.
Each shipped unit now sets ``VIGIL_BASE_DIR`` explicitly; this reconstructs, per configured unit, the directory
that unit's process would actually use — the way systemd builds its environment and the way the shared resolver
(``vigil_core.seam_base``) picks a winner — so a unit left on an older copy, or an env-file override applied to
only some units, is caught before it makes the settle drain miss every lease:

* the unit text is the INSTALLED copy (``~/.config/systemd/user/<unit>``), else the repo's shipped copy;
* ``Environment=`` values expand ``%h``; ``EnvironmentFile=`` values do NOT (systemd never expands a specifier
  there) and override ``Environment=``;
* the seam is ``--base-dir`` on the ``ExecStart`` line (after ``${VAR}`` substitution) > ``VIGIL_BASE_DIR`` >
  ``.vigil-live``, made absolute against the unit's ``WorkingDirectory`` (default: the home directory);
* a unit is CONFIGURED when its installed copy exists or one of its env files does — a host with neither
  reports nothing (default-OFF).

stdlib only; imports neither ``framework`` nor ``sigil`` (FATAL-2) and never raises from its public entry.
"""
from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Callable, Optional

#: Every shipped unit that reads or writes the money seam, and where the repo ships it.
SEAM_UNITS: "tuple[tuple[str, str], ...]" = (
    ("sigil-cockpit.service", "apps/sigil/deploy/systemd"),
    ("vigil-settle-drain.service", "infra/systemd"),
    ("vigil-backup.service", "infra/systemd"),
    ("vigil-backup-push.service", "infra/systemd"),
    ("vigil-backup-drill.service", "infra/systemd"),
    ("vigil-command.service", "infra/systemd"),
)
_LEGACY_ALIAS = "VIGIL_SETTLE_BASE_DIR"


def _spec(value: str, home: Path) -> str:
    """Expand the systemd specifiers a seam path can carry in a unit directive (``%h``; ``%%`` is a literal %)."""
    return value.replace("%%", "\0").replace("%h", str(home)).replace("\0", "%")


def _directives(text: str) -> "list[tuple[str, str]]":
    """``(key, value)`` per directive line of a unit file (comments dropped, ``\\`` continuations joined)."""
    out: "list[tuple[str, str]]" = []
    buf = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buf and (not line or line[0] in "#;"):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        line, buf = buf + line, ""
        if "=" in line and not line.startswith("["):
            k, v = line.split("=", 1)
            out.append((k.strip(), v.strip()))
    return out


def _subst(word: str, env: dict) -> str:
    """systemd's ``${VAR}`` / ``$VAR`` substitution in an ExecStart word (unset ⇒ empty)."""
    if word.startswith("${") and word.endswith("}"):
        return str(env.get(word[2:-1], ""))
    if word.startswith("$") and len(word) > 1:
        return str(env.get(word[1:], ""))
    return word


def unit_seam_base(text: str, home: Path, parse_env: Callable[[Path], Optional[dict]],
                   *, installed: bool = False) -> "Optional[dict]":
    """The seam base the process of the unit ``text`` would use, or ``None`` when the unit is not configured
    here. Returns ``{"seam": <abs path>, "legacy": <abs VIGIL_SETTLE_BASE_DIR or None>}``."""
    env: dict = {}
    files: "list[Path]" = []
    workdir = str(home)
    base_arg: Optional[str] = None
    for key, value in _directives(text):
        if key == "Environment":
            for tok in shlex.split(value):
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    env[k] = _spec(v, home)
        elif key == "EnvironmentFile":
            files.append(Path(_spec(value.lstrip("-"), home)))
        elif key == "WorkingDirectory":
            wd = _spec(value.lstrip("-"), home)
            workdir = str(home) if wd == "~" else wd
        elif key == "ExecStart":
            words = shlex.split(value)
            for i, w in enumerate(words):
                if w == "--base-dir" and i + 1 < len(words):
                    base_arg = words[i + 1]
                elif w.startswith("--base-dir="):
                    base_arg = w.split("=", 1)[1]
    present = [f for f in files if f.is_file()]
    if not installed and not present:
        return None
    for f in present:
        env.update(parse_env(f) or {})

    def _abs(raw: str) -> str:     # the resolver's expanduser + abspath, for THIS unit's home and working dir
        p = home / raw[2:] if raw == "~" or raw.startswith("~/") else Path(raw)
        return os.path.normpath(str(p if p.is_absolute() else Path(workdir) / p))

    raw = (_subst(base_arg, env) if base_arg is not None else "") or env.get("VIGIL_BASE_DIR") or ".vigil-live"
    legacy = env.get(_LEGACY_ALIAS) or ""
    return {"seam": _abs(raw), "legacy": _abs(legacy) if legacy else None}


def seam_base_agreement(repo: "Path | str", home: "Path | None" = None, *,
                        parse_env: Callable[[Path], Optional[dict]],
                        display: Callable[[str], str] = str) -> "tuple[dict, list]":
    """Return ``(section, hard_issues)``. ``section["units"]`` maps each CONFIGURED seam unit to the seam base it
    resolves; ``hard_issues`` names every unit when two of them disagree (or a unit's own legacy
    ``VIGIL_SETTLE_BASE_DIR`` contradicts it). Nothing configured ⇒ ``({"units": {}}, [])``."""
    h = Path(home) if home is not None else Path.home()
    seams: dict = {}
    issues: list = []
    for unit, shipped_dir in SEAM_UNITS:
        installed = h / ".config" / "systemd" / "user" / unit
        src = installed if installed.is_file() else Path(repo) / shipped_dir / unit
        try:
            got = unit_seam_base(src.read_text(encoding="utf-8"), h, parse_env, installed=installed.is_file())
        except (OSError, ValueError):     # unreadable / unparsable unit text: nothing to compare for it
            continue
        if got is None:
            continue
        seams[unit] = got["seam"]
        if got["legacy"] is not None and os.path.realpath(got["legacy"]) != os.path.realpath(got["seam"]):
            issues.append(
                f"seam base: {unit} sets the retired {_LEGACY_ALIAS}={display(got['legacy'])} but its seam base "
                f"is {display(got['seam'])} — the settle drain REFUSES to run on that contradiction (completions "
                f"stay unsettled). Remove {_LEGACY_ALIAS} from its env file, or set VIGIL_BASE_DIR to that path "
                f"for every seam unit.")
    section = {"units": {u: display(s) for u, s in seams.items()}}
    if len({os.path.realpath(s) for s in seams.values()}) > 1:
        listed = "; ".join(f"{u} -> {display(s)}" for u, s in seams.items())
        issues.append(
            f"seam base: the configured units disagree on the seam base ({listed}). A lease the cockpit "
            f"publishes in one tree is never seen by a drain or engine reading another: completions settle "
            f"nothing (credits held), a cancel's started-check and settlement marker land in a different tree, "
            f"and backups miss the live one. Set VIGIL_BASE_DIR to ONE absolute directory for all of them (the "
            f"shipped units default it to %h/.sigil/credit-lease) and re-copy any unit installed from an older "
            f"checkout.")
    return section, issues
