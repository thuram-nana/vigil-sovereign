"""
plugins.cli — `python3 -m framework.v2 capabilities`.

Print the UNIFIED, read-only capability catalog: every installed sensor, internal
tool, oracle (with the bug_classes it confirms), technique operator, and CLI
subcommand — with its gating tier / entitlement and what it produces. This is the
human/JSON face of ``plugins.registry.capability_registry``; it is the surface a
Wave-6 MCP server or HTTP API would expose.

    capabilities                     grouped human-readable catalog
    capabilities --json              deterministic JSON (for an MCP/API/SDK consumer)
    capabilities --kind sensor       show only one kind
    capabilities --no-commands       omit the CLI-subcommand group

Read-only throughout — it never runs a capability. Deterministic — the same
installed set always prints the same bytes.
"""

from __future__ import annotations

import argparse
import json
import sys

from .registry import CapabilityCatalog, capability_registry

# CLI --kind value (singular) -> catalog group name (plural).
_KIND_GROUP = {
    "sensor": "sensors",
    "tool": "tools",
    "oracle": "oracles",
    "operator": "operators",
    "command": "commands",
}


def _fmt_gate(d) -> str:
    """A compact gating annotation for one descriptor: tier, entitlement (or
    'ungated'), destructive/egress flags."""
    bits: list[str] = []
    if d.tier:
        bits.append(d.tier)
    if d.kind in ("sensor", "tool"):
        bits.append(d.entitlement if d.entitlement else "ungated")
    if d.destructive:
        bits.append("destructive")
    if d.egress_hosts:
        bits.append("egress:" + ",".join(d.egress_hosts))
    return " ".join(bits)


def _print_group(name: str, descriptors) -> None:
    print(f"{name} ({len(descriptors)}):")
    if not descriptors:
        print("  (none)")
        return
    width = max((len(d.name) for d in descriptors), default=0)
    for d in descriptors:
        gate = _fmt_gate(d)
        line = f"  {d.name:<{width}}"
        if gate:
            line += f"  {gate}"
        if d.provable_by:
            line += f"  provable_by:{','.join(d.provable_by)}"
        if d.produces:
            label = "confirms" if d.kind == "oracle" else "produces"
            line += f"  {label}:{','.join(d.produces)}"
        if d.origin != "builtin":
            line += f"  [{d.origin}]"
        print(line)
        if d.summary:
            print(f"  {' ' * width}    {d.summary}")


def _print_human(catalog: CapabilityCatalog, *, kind_filter: str | None) -> None:
    print("CRUCIBLE capability catalog")
    print("===========================")
    target_group = _KIND_GROUP.get(kind_filter) if kind_filter else None
    first = True
    for group_name, descriptors in catalog.groups():
        if target_group is not None and group_name != target_group:
            continue
        if not descriptors:
            # an omitted (--no-commands) or empty group prints nothing
            continue
        if not first:
            print()
        first = False
        _print_group(group_name, descriptors)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 capabilities",
        description="Enumerate CRUCIBLE's unified capability catalog (read-only, deterministic).",
    )
    parser.add_argument("--json", action="store_true",
                        help="emit the catalog as deterministic JSON (for an MCP/API/SDK consumer)")
    parser.add_argument("--kind", choices=sorted(_KIND_GROUP),
                        help="restrict the output to a single capability kind")
    parser.add_argument("--no-commands", action="store_true",
                        help="omit the CLI-subcommand group from the catalog")
    args = parser.parse_args(argv)

    catalog = capability_registry(include_commands=not args.no_commands)

    if args.json:
        # sort_keys makes the JSON a byte-stable function of the installed set.
        print(json.dumps(catalog.to_dict(), indent=2, sort_keys=True))
        return 0

    _print_human(catalog, kind_filter=args.kind)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
