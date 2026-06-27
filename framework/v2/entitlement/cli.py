"""
entitlement.cli — `python3 -m framework.v2 entitlement <subcommand>`.

Subcommands:

    status                  show enforcement state and the active grant
    capabilities            list every capability and whether it is available
    verify                  re-read provisioned material and report verdict

Read-only. Issuance (minting trust roots / signing entitlements) is a
governance ceremony handled by `entitlement.provision`, deliberately
not exposed as a casual CLI verb.
"""

from __future__ import annotations

import argparse
import json

from .models import Capability
from .policy import EntitlementPolicy, reset_policy
from .registry import required_tier


def _status(_args: argparse.Namespace) -> int:
    reset_policy()
    policy = EntitlementPolicy.from_provisioned()
    print("CRUCIBLE entitlement status")
    print("---------------------------")
    print(f"  enforced     : {policy.enforced}")
    tier = policy.granted_tier
    print(f"  granted tier : {tier.value if tier is not None else '—'}")
    print(f"  summary      : {policy.explain()}")
    return 0


def _capabilities(_args: argparse.Namespace) -> int:
    reset_policy()
    policy = EntitlementPolicy.from_provisioned()
    rows = []
    for cap in Capability:
        rows.append(
            {
                "capability": cap.value,
                "required_tier": required_tier(cap).value,
                "available": policy.is_capability_available(cap),
            }
        )
    print(json.dumps(rows, indent=2))
    return 0


def _verify(_args: argparse.Namespace) -> int:
    reset_policy()
    policy = EntitlementPolicy.from_provisioned()
    print(policy.explain())
    # Exit non-zero when enforcement is active but no tier is granted, so
    # the verb is usable as a deployment health check.
    if policy.enforced and policy.granted_tier is None:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 entitlement",
        description="Inspect the entitlement / capability-gating state.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status", help="enforcement state and active grant")
    p.set_defaults(fn=_status)

    p = sub.add_parser("capabilities", help="per-capability availability")
    p.set_defaults(fn=_capabilities)

    p = sub.add_parser("verify", help="re-verify provisioned material (health check)")
    p.set_defaults(fn=_verify)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = args.fn  # type: ignore[attr-defined]
    return int(fn(args))


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main(sys.argv[1:]))
