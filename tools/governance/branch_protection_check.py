#!/usr/bin/env python3
"""Compare LIVE GitHub branch protection against the committed canonical policy ([W0-1] #554).

This is the logic behind `.github/workflows/branch-protection-verify.yml`. It used to live inline in
the workflow as a `python3 - <<'PY'` heredoc, which meant it could never be unit-tested — the only way
to exercise it was to run the workflow against a live repo with an admin-scoped token. Extracting it
here gives a SINGLE source of truth that both the workflow and a required offline test drive, so the
negative control ("drop a required check from the committed policy and the compare fails") runs in CI.

It reads two inputs and prints GitHub-Actions `::error::` annotations on drift:
  * `protection.json` — the JSON body of `GET repos/{repo}/branches/{branch}/protection`; and
  * `.github/required-status-checks.txt` — the committed canonical required-check set.

It FAILS (exit 1) if the live contexts differ from canonical (as a set), if `strict` is not true, or if
force-pushes / branch deletions are allowed. `enforce_admins` is reported informationally only
(deliberately false in the audited config — the owner keeps an attributable override).

TOKEN. Reading branch protection needs "Administration: read", which the default GITHUB_TOKEN cannot
have, so the workflow no-ops without the fine-grained PAT secret BRANCH_PROTECTION_TOKEN. Provisioning
that PAT is a human/admin action; this module does not need it — it compares whatever JSON it is given,
which is exactly what makes it testable offline.

Pure standard library.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def load_canonical(text: str) -> list[str]:
    """One context per line; blank lines and `#`-comment lines ignored. Matches the reader in
    docs/tests/test_required_checks_canonical.py so the two never disagree."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def compare_protection(protection: dict, canonical: list[str]) -> list[str]:
    """Return a list of human-readable problems; empty == the live protection matches the committed
    policy. Pure over its inputs, so a test can perturb either side in-process.

    Checks:
      * required_status_checks.contexts, compared as a SET, equals `canonical`;
      * required_status_checks.strict is True (branch must be up to date);
      * required signed commits are enabled (W12-4 #493);
      * force-pushes are not allowed;
      * branch deletions are not allowed.
    """
    problems: list[str] = []
    canon = sorted(canonical)

    rsc = protection.get("required_status_checks") or {}
    live = sorted(rsc.get("contexts") or [])
    if live != canon:
        missing = sorted(set(canon) - set(live))
        extra = sorted(set(live) - set(canon))
        problems.append(
            "required_status_checks.contexts drifted from .github/required-status-checks.txt:\n"
            f"    missing from live (committed but not required): {missing}\n"
            f"    extra on live (required but not committed):    {extra}"
        )

    if rsc.get("strict") is not True:
        problems.append(
            f"required_status_checks.strict is {rsc.get('strict')!r}, expected True (branch must be up to date)"
        )

    # W12-4 (#493): require signed commits. The GET-protection body carries a `required_signatures`
    # object ({url, enabled}); the flip is applied via the dedicated required_signatures sub-resource.
    if (protection.get("required_signatures") or {}).get("enabled") is not True:
        problems.append(
            "required_signatures.enabled is "
            f"{(protection.get('required_signatures') or {}).get('enabled')!r}, expected True "
            "(W12-4 #493 — unsigned commits must be rejected on main)"
        )

    if (protection.get("allow_force_pushes") or {}).get("enabled") is True:
        problems.append("allow_force_pushes is enabled — main history can be rewritten to sidestep the checks")

    if (protection.get("allow_deletions") or {}).get("enabled") is True:
        problems.append("allow_deletions is enabled — main can be deleted to sidestep the checks")

    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: branch_protection_check.py <protection.json> <required-status-checks.txt>", file=sys.stderr)
        return 2
    protection = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    canonical = load_canonical(Path(argv[1]).read_text(encoding="utf-8"))

    problems = compare_protection(protection, canonical)

    rsc = protection.get("required_status_checks") or {}
    live = sorted(rsc.get("contexts") or [])
    ea = (protection.get("enforce_admins") or {}).get("enabled")
    print(f"enforce_admins.enabled = {ea} (informational; deliberately false in the audited config)")
    print(f"live required checks ({len(live)}): {live}")

    if problems:
        print("::error::live branch protection does not match the committed policy:")
        for p in problems:
            print("::error::" + p.replace("\n", "%0A"))
        return 1
    print("OK — live branch protection matches the committed canonical policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
