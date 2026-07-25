"""The `vigil` super-CLI dispatcher (unification S1) — ONE control plane over TWO isolated processes.

`vigil <subsystem> …` forwards to the subsystem's own console-script, EXEC'd in its OWN environment:
sovereign verbs run in `.venv-sovereign`, offense verbs in `.venv-offense`. This is how the fused system
gets a single command surface WITHOUT ever co-loading both trust domains — the boundary that a single
interpreter holding the owner key AND able to import `framework`/`strix` would violate (FATAL-2).

CRITICAL boundary property: this module is PURE STDLIB and EXEC-ONLY. It imports NEITHER `framework`/
`strix` NOR `sigil`; it only resolves a static verb→environment path and `subprocess.run`s it. The
verb→environment table is hardcoded, so an offense verb can NEVER be routed into the sovereign venv (or
vice-versa) — routing is by construction, not by inspection.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# verb -> (environment, console-script). The environment is FIXED per verb: sovereign verbs never resolve
# into the offense venv and offense verbs never resolve into the sovereign venv. `sigil` is the sovereign
# personal core (holds the owner key); the rest are offense-side (keyless).
_ENV = {
    "sigil":   ("sovereign", "sigil"),
    "crucible": ("offense",  "crucible"),        # the raw CRUCIBLE arsenal (its own engage/scan/plan/…)
    "aegis":    ("offense",  "aegis"),           # the defensive dual (detect/gateway/demo)
    "strix":    ("offense",  "strix"),           # the agent body
    "gateway":  ("offense",  "vigil-gateway"),   # the host egress gate
}

PASSTHROUGH_VERBS = frozenset(_ENV)


class DispatchError(RuntimeError):
    """The target environment/console-script could not be located (env not built, or root not found)."""


def _repo_root() -> Path:
    """Locate the repo root that holds the two sibling venvs (`.venv-sovereign` / `.venv-offense`).

    Resolution order, all filesystem-only (no imports of the subsystems): (1) an explicit `VIGIL_ROOT`;
    (2) if we are running inside one of the two venvs, its parent IS the root; (3) walk up from this file to
    a directory carrying the `.venv-offense` dir or the `envs/offense.txt` marker."""
    env = os.environ.get("VIGIL_ROOT")
    if env:
        return Path(env)
    prefix = Path(sys.prefix)
    if prefix.name in (".venv-sovereign", ".venv-offense") and (prefix.parent / ".venv-offense").exists():
        return prefix.parent
    here = Path(__file__).resolve()
    for d in (here, *here.parents):
        if (d / ".venv-offense").exists() or (d / "envs" / "offense.txt").exists():
            return d
    raise DispatchError("cannot locate the VIGIL repo root (set VIGIL_ROOT to the dir holding "
                        ".venv-sovereign / .venv-offense)")


def resolve(verb: str) -> Path:
    """The absolute path to the console-script `verb` routes to, in its FIXED environment. Raises
    DispatchError for an unknown verb (should be gated by PASSTHROUGH_VERBS before calling)."""
    if verb not in _ENV:
        raise DispatchError(f"unknown passthrough verb {verb!r}")
    env_name, script = _ENV[verb]
    return _repo_root() / f".venv-{env_name}" / "bin" / script


def dispatch(verb: str, argv: list[str]) -> int:
    """EXEC `verb`'s console-script (in its own venv) with `argv`, inheriting stdio, and return its exit
    code. Never imports the subsystem — a separate OS process in the correct trust domain runs it."""
    try:
        path = resolve(verb)
    except DispatchError as e:
        print(f"vigil: {verb}: {e}", file=sys.stderr)
        return 2
    env_name = _ENV[verb][0]
    if not path.exists():
        print(f"vigil: {verb}: the {env_name} environment is not built ({path} missing) — "
              f"run envs/build_envs.sh, or set VIGIL_ROOT.", file=sys.stderr)
        return 127
    # Present a CLEAN environment to the cross-venv child: strip PYTHONPATH / PYTHONHOME so a value from
    # the PARENT's invocation (e.g. an offense-side `PYTHONPATH=engine/crucible`) can NEVER inject the other
    # trust domain's modules into the child interpreter — so NO other-trust-domain module is reachable, and
    # the STRUCTURAL two-env isolation holds across the exec. (A present console-script implies its package
    # is installed in that venv, so PYTHONPATH is never needed for the child; the residual env vectors are
    # neutralised by the venv itself — no system/user site, so framework/strix stay unimportable.)
    child_env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    # inherit stdin/stdout/stderr so interactive/long-running sub-CLIs (sigil serve, sigil voice --mic,
    # crucible …) work; the child runs in its own venv → no co-loading of the two trust domains. `argv` is
    # a LIST (no shell), so subsystem args pass through verbatim with no shell-injection surface.
    try:
        return subprocess.run([str(path), *argv], env=child_env).returncode
    except OSError as e:
        # the console-script exists but cannot be executed (e.g. a half-built venv whose shebang interpreter
        # is missing). Fail CLEAN + non-zero, never a raw traceback out of main().
        print(f"vigil: {verb}: cannot execute {path} ({e}) — the {env_name} environment looks "
              f"corrupt/half-built; rebuild with envs/build_envs.sh.", file=sys.stderr)
        return 127
