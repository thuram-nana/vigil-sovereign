#!/usr/bin/env python3
"""Commit-signing configuration check for [W12-4] #493 (enforce signed commits).

This module is the *code-side, testable* half of "enforce signed commits". It answers one question,
locally and offline: **is this working copy configured so that the commits it produces will be
signed?** It is the check a contributor runs before pushing, and the enforcing symbol behind the
claims-registry entry for #493.

WHAT IT DELIBERATELY DOES NOT DO. It does not, and cannot, make the *server* reject an unsigned push.
That is the branch-protection setting "Require signed commits" on `main`, a repository-administration
flip made through the GitHub UI/API — a human/admin action documented in
docs/decisions/W12-4-enforce-signed-commits.md and NOT claimed here. This module only proves the local
side is set up correctly (or reports exactly what is missing), which is what a contributor controls.

Pure standard library. `signing_config_defects` is a pure function over a parsed git-config mapping, so
a test can drive it with synthetic good/bad configs; `read_git_config` shells out to `git config
--list` for the CLI path.
"""
from __future__ import annotations

import subprocess
import sys

# Git config keys that decide whether a commit is signed. `commit.gpgsign` turns signing on for every
# commit; `user.signingkey` names the key; `gpg.format` selects the signature format (openpgp default,
# or ssh / x509). These are the keys `git commit -S` and `commit.gpgsign` consult.
_KEY_GPGSIGN = "commit.gpgsign"
_KEY_SIGNINGKEY = "user.signingkey"
_KEY_FORMAT = "gpg.format"

# Signature formats git understands. Unset means the openpgp default, which is valid.
_VALID_FORMATS = {"openpgp", "gpg", "ssh", "x509"}

_TRUE = {"true", "yes", "on", "1"}


def read_git_config(cwd: str | None = None, env: dict[str, str] | None = None) -> dict[str, str]:
    """Return the effective git config as a {key: value} map (last value wins, git's own precedence).

    Uses `git config --list`, which merges system/global/local. Returns {} if git is unavailable or the
    directory is not a repository — the caller treats an empty map as "nothing configured", which the
    defect check then reports, so a missing git never masquerades as a passing signing setup.

    `env` overrides the child process environment; a test passes an isolated env (GIT_CONFIG_GLOBAL /
    GIT_CONFIG_SYSTEM pinned to an empty file) so the check sees only the repo-local config and does not
    inherit whatever signing the developer's machine happens to have set globally.
    """
    try:
        out = subprocess.run(
            ["git", "config", "--list"],
            cwd=cwd, capture_output=True, text=True, check=False, env=env,
        )
    except (OSError, ValueError):
        return {}
    if out.returncode != 0:
        return {}
    cfg: dict[str, str] = {}
    for line in out.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            cfg[key.strip().lower()] = value.strip()
    return cfg


def signing_config_defects(config: dict[str, str]) -> list[str]:
    """Return a list of human-readable reasons this config will NOT produce signed commits; empty means
    it will. Pure over its input.

    A working copy signs its commits iff:
      * `commit.gpgsign` is a truthy value (true/yes/on/1), AND
      * `user.signingkey` is set to a non-empty value, AND
      * `gpg.format`, if set, is one git recognises (an unset format is the valid openpgp default).
    """
    defects: list[str] = []

    gpgsign = config.get(_KEY_GPGSIGN, "").strip().lower()
    if gpgsign not in _TRUE:
        defects.append(
            f"{_KEY_GPGSIGN} is {config.get(_KEY_GPGSIGN)!r}, not true — commits will NOT be signed by "
            f"default. Set: git config {_KEY_GPGSIGN} true"
        )

    signingkey = config.get(_KEY_SIGNINGKEY, "").strip()
    if not signingkey:
        defects.append(
            f"{_KEY_SIGNINGKEY} is unset — git has no key to sign with. Set it to your GPG key id or "
            f"SSH public key path: git config {_KEY_SIGNINGKEY} <key>"
        )

    fmt = config.get(_KEY_FORMAT, "").strip().lower()
    if fmt and fmt not in _VALID_FORMATS:
        defects.append(
            f"{_KEY_FORMAT} is {config.get(_KEY_FORMAT)!r}, not one of {sorted(_VALID_FORMATS)}"
        )

    return defects


def main(argv: list[str]) -> int:
    """CLI: `commit_signing.py --verify` (default) checks the current repo's config and exits non-zero
    with guidance if it will not sign commits."""
    cwd = None
    for a in argv:
        if a not in ("--verify", "-v", ""):
            # allow an explicit directory argument for testing
            cwd = a
    defects = signing_config_defects(read_git_config(cwd))
    if defects:
        print("commit signing is NOT configured in this working copy:", file=sys.stderr)
        for d in defects:
            print(f"  - {d}", file=sys.stderr)
        print(
            "\nRun tools/governance/setup-commit-signing.sh to configure it, then re-run this check.\n"
            "Note: the SERVER-SIDE 'Require signed commits' rule on main is a separate branch-protection\n"
            "admin flip (see docs/decisions/W12-4-enforce-signed-commits.md).",
            file=sys.stderr,
        )
        return 1
    print("OK — this working copy is configured to sign commits (commit.gpgsign=true, user.signingkey set).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
