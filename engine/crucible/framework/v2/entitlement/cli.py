"""
entitlement.cli — `python3 -m framework.v2 entitlement <subcommand>`.

Read-only inspection:

    status                  show enforcement state and the active grant
    capabilities            list every capability and whether it is available
    verify                  re-read provisioned material and report verdict

Provisioning (the governance ceremony — moves a deployment from
UNGOVERNED to governed WITHOUT hand-writing Python against
`entitlement.provision`):

    provision               single-host one-shot: mint authoriser(s), a
                            trust root, and a signed entitlement in one step
    new-authorizer          generate one authoriser keypair (public card +
                            private key file) for a distributed ceremony
    build-trust-root        assemble a trust root from authoriser public cards
    sign-entitlement        sign an entitlement document with authoriser
                            private keys

The runbook is `framework/v2/docs/ENTITLEMENT-PROVISIONING.md`.

NOTE (deliberate coupling an operator must know): while a deployment is
UNGOVERNED (no trust root), gated capabilities — including AEGIS
Gateway active enforcement, `AEGIS_RESPOND` — are PERMITTED with a
logged warning. The moment a trust root exists, enforcement is ACTIVE
and those capabilities require a valid entitlement that grants them. In
particular `aegis serve --mode enforce` keeps working today only
because the deployment is ungoverned; after you provision, AEGIS enforce
silently downgrades to observe unless the entitlement grants
AEGIS_RESPOND (STANDARD tier). Provision the standard tier (or list
AEGIS_RESPOND explicitly) if you rely on blocking.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import ValidationError

from ..common import paths
from . import provision as prov
from .models import (
    AuthorizerKey,
    Capability,
    CapabilityTier,
    EntitlementDocument,
    EntitlementSubject,
    HardwareBinding,
)
from .policy import EntitlementPolicy, reset_policy
from .registry import required_tier

# The read-only inspection verbs. Everything else the parser registers is a
# provisioning verb, and the runbook drift-guard derives that set by
# subtracting these, so a new provisioning verb cannot ship undocumented.
_READONLY_VERBS = frozenset({"status", "capabilities", "verify"})

_AEGIS_NOTE = (
    "note: provisioning a trust root turns enforcement ACTIVE. Gated "
    "capabilities (incl. AEGIS_RESPOND, which 'aegis serve --mode enforce' "
    "needs) now require an entitlement that grants them — an ungoverned "
    "deployment permitted them with only a warning. Grant the STANDARD tier "
    "(or list AEGIS_RESPOND) if you rely on AEGIS blocking."
)


# ---------------------------------------------------------------------------
# Read-only inspection verbs
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Provisioning helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _add_document_args(p: argparse.ArgumentParser) -> None:
    """Flags that describe an EntitlementDocument, shared by `provision`
    and `sign-entitlement`. Signing/authoriser flags are added per-verb."""
    p.add_argument("--institution-id", required=True, help="stable id of the institution the grant is for")
    p.add_argument("--institution-name", required=True, help="human-readable institution name")
    p.add_argument(
        "--tier",
        required=True,
        choices=[t.value for t in CapabilityTier],
        help="clearance tier the grant confers (monotone ladder)",
    )
    p.add_argument(
        "--capability",
        action="append",
        default=[],
        choices=[c.value for c in Capability],
        metavar="CAP",
        help="restrict the grant to these capabilities (repeatable); omit to "
        "confer every capability the tier permits (least-privilege within tier)",
    )
    p.add_argument("--issuer", default="CRUCIBLE operator ceremony", help="issuing authority name (recorded in the signed core)")
    p.add_argument("--entitlement-id", default=None, help="stable unique id; a uuid4 is generated if omitted")
    p.add_argument("--valid-days", type=int, default=365, help="validity window length in days from now (default 365)")
    p.add_argument(
        "--operator-constraint",
        default=None,
        help="bind the grant to an operator identity/prefix (matched against "
        "CRUCIBLE_OPERATOR_IDENTITY at evaluation time; unset = any operator)",
    )
    p.add_argument(
        "--bind-identifier",
        action="append",
        default=[],
        metavar="ID",
        help="host-attestation identifier to bind the grant to (repeatable); "
        "the host must present one of these (CRUCIBLE_ATTESTED_IDENTITY / "
        "machine-id / hostname) at evaluation time. Omit = unbound (runs anywhere).",
    )


def _document_from_args(args: argparse.Namespace) -> EntitlementDocument:
    if args.valid_days <= 0:
        raise SystemExit("--valid-days must be a positive integer")
    now = _utcnow()
    binding = (
        HardwareBinding(binding_type="host_attestation", bound_identifiers=list(args.bind_identifier))
        if args.bind_identifier
        else HardwareBinding()
    )
    return EntitlementDocument(
        entitlement_id=args.entitlement_id or str(uuid.uuid4()),
        issuer=args.issuer,
        subject=EntitlementSubject(
            institution_id=args.institution_id,
            institution_name=args.institution_name,
            operator_constraint=args.operator_constraint,
        ),
        capability_tier=CapabilityTier(args.tier),
        granted_capabilities=[Capability(c) for c in args.capability],
        binding=binding,
        # A one-minute backdated not_before absorbs benign clock skew between
        # the issuing host and the runtime host; the window is otherwise
        # --valid-days long.
        issued_at=now,
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(days=args.valid_days),
    )


def _refuse_overwrite(path: Path, force: bool) -> bool:
    """Return True (and print) if writing `path` must be refused because it
    already exists and --force was not given. Governance material is never
    silently clobbered."""
    if path.exists() and not force:
        print(
            f"refusing to overwrite existing {path.name} at {path.parent} "
            f"— re-run with --force to replace it",
            file=sys.stderr,
        )
        return True
    return False


# ---------------------------------------------------------------------------
# Provisioning verbs
# ---------------------------------------------------------------------------


def _provision(args: argparse.Namespace) -> int:
    """One-shot single-host ceremony: mint authoriser(s), build the trust
    root, and sign + write an entitlement. This is the fast path from
    UNGOVERNED to governed. The authoriser private keys it generates are
    the deployment's crown jewels; they are written owner-only and must be
    moved off this host (or into an HSM) after issuance."""
    if args.authorizers < 1:
        print("--authorizers must be >= 1", file=sys.stderr)
        return 2
    if args.threshold < 1 or args.threshold > args.authorizers:
        print(
            f"--threshold must be between 1 and --authorizers ({args.authorizers})",
            file=sys.stderr,
        )
        return 2
    if _refuse_overwrite(paths.trust_root_path(), args.force):
        return 2
    if _refuse_overwrite(paths.entitlement_path(), args.force):
        return 2

    authorizers: list[AuthorizerKey] = []
    privs: dict[str, str] = {}
    for i in range(args.authorizers):
        key_id = f"authorizer-{i}"
        ak, priv = prov.new_authorizer(key_id, f"{args.institution_name} authoriser {i}")
        authorizers.append(ak)
        privs[key_id] = priv

    trust_root = prov.build_trust_root(authorizers, args.threshold)
    tr_path = prov.write_trust_root(trust_root)

    doc = _document_from_args(args)
    # Sign with every authoriser (>= threshold), so the grant verifies under
    # the trust root regardless of threshold.
    signed = prov.sign_entitlement(doc, privs)
    ent_path = prov.write_entitlement(signed)

    keys_out = Path(args.keys_out) if args.keys_out else (paths.entitlement_dir() / "authorizer-keys.json")
    paths.secure_write(
        keys_out,
        json.dumps(
            {
                "_WARNING": (
                    "authoriser PRIVATE keys — the deployment's crown jewels. Anyone "
                    "holding these can mint or revoke entitlements. Move this file OFF "
                    "the runtime host (ideally into an HSM) and delete it here. It is "
                    "NOT read by the runtime; it exists only so you can reissue/revoke."
                ),
                "threshold": args.threshold,
                "private_keys_b64": privs,
            },
            indent=2,
        ),
    )

    reset_policy()
    print("provisioned — deployment is now GOVERNED (enforcement ACTIVE)")
    print(f"  trust root      : {tr_path}")
    print(f"  entitlement     : {ent_path}  (id {doc.entitlement_id})")
    print(f"  authoriser keys : {keys_out}  (owner-only — MOVE OFF-HOST, see warning inside)")
    print(f"  tier            : {doc.capability_tier.value}   authorisers {args.authorizers}, threshold {args.threshold}")
    print("  next            : python3 -m framework.v2 entitlement verify")
    print(f"  {_AEGIS_NOTE}")
    return 0


def _new_authorizer(args: argparse.Namespace) -> int:
    """Generate one authoriser: a public card (goes into a trust root) and a
    private key (stays with the authoriser, never distributed). For a
    distributed / multi-signer ceremony where keys live on separate hosts."""
    ak, priv = prov.new_authorizer(args.key_id, args.name)
    card_json = json.dumps(ak.model_dump(mode="json"), indent=2)
    if args.card_out:
        paths.secure_write(Path(args.card_out), card_json)
        print(f"authoriser public card written to {args.card_out}")
    else:
        print(card_json)
    paths.secure_write(Path(args.key_out), priv)
    print(
        f"authoriser PRIVATE key (base64) written owner-only to {args.key_out} — "
        f"keep it off the runtime host; feed it to `sign-entitlement --signer "
        f"{args.key_id}={args.key_out}`.",
        file=sys.stderr,
    )
    return 0


def _build_trust_root(args: argparse.Namespace) -> int:
    """Assemble a trust root from one or more authoriser public cards
    (produced by `new-authorizer`) and a threshold, and write it. Writing a
    trust root is what turns enforcement ON."""
    out = Path(args.out) if args.out else paths.trust_root_path()
    if _refuse_overwrite(out, args.force):
        return 2
    authorizers: list[AuthorizerKey] = []
    for card_path in args.card:
        try:
            raw = Path(card_path).read_text(encoding="utf-8")
        except OSError as e:
            print(f"cannot read authoriser card {card_path}: {e}", file=sys.stderr)
            return 2
        try:
            authorizers.append(AuthorizerKey.model_validate_json(raw))
        except ValidationError as e:
            print(f"authoriser card {card_path} is not a valid AuthorizerKey: {e}", file=sys.stderr)
            return 2
    try:
        trust_root = prov.build_trust_root(authorizers, args.threshold)
    except ValidationError as e:
        print(f"invalid trust root (threshold vs authoriser count / duplicate ids): {e}", file=sys.stderr)
        return 2
    written = prov.write_trust_root(trust_root, out)
    reset_policy()
    print(f"trust root written to {written} ({len(authorizers)} authoriser(s), threshold {args.threshold})")
    print("deployment is now GOVERNED. Provide an entitlement with `sign-entitlement`.")
    print(f"{_AEGIS_NOTE}")
    return 0


def _sign_entitlement(args: argparse.Namespace) -> int:
    """Build an entitlement document from flags and sign it with authoriser
    private keys, then write it. Supply at least the trust root's threshold
    of authorised signers with repeated `--signer key_id=PATH`."""
    out = Path(args.out) if args.out else paths.entitlement_path()
    if _refuse_overwrite(out, args.force):
        return 2
    signers: dict[str, str] = {}
    for spec in args.signer:
        if "=" not in spec:
            print(f"--signer must be key_id=PATH (got {spec!r})", file=sys.stderr)
            return 2
        key_id, key_path = spec.split("=", 1)
        key_id = key_id.strip()
        if not key_id:
            print(f"--signer has an empty key_id (got {spec!r})", file=sys.stderr)
            return 2
        try:
            signers[key_id] = Path(key_path).read_text(encoding="utf-8").strip()
        except OSError as e:
            print(f"cannot read signer private key {key_path}: {e}", file=sys.stderr)
            return 2
    doc = _document_from_args(args)
    signed = prov.sign_entitlement(doc, signers)
    written = prov.write_entitlement(signed, out)
    reset_policy()
    print(f"entitlement written to {written} (id {doc.entitlement_id}, tier {doc.capability_tier.value})")
    print(f"  signed by       : {', '.join(sorted(signers))}")
    print("  next            : python3 -m framework.v2 entitlement verify")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 entitlement",
        description="Inspect and provision the entitlement / capability-gating state. "
        "Runbook: framework/v2/docs/ENTITLEMENT-PROVISIONING.md",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status", help="enforcement state and active grant")
    p.set_defaults(fn=_status)

    p = sub.add_parser("capabilities", help="per-capability availability")
    p.set_defaults(fn=_capabilities)

    p = sub.add_parser("verify", help="re-verify provisioned material (health check)")
    p.set_defaults(fn=_verify)

    # --- provisioning ------------------------------------------------------
    p = sub.add_parser(
        "provision",
        help="single-host one-shot: mint authoriser(s) + trust root + signed entitlement",
    )
    _add_document_args(p)
    p.add_argument("--authorizers", type=int, default=1, help="number of authoriser keypairs to mint (default 1)")
    p.add_argument("--threshold", type=int, default=1, help="m in m-of-n signatures required (default 1)")
    p.add_argument("--keys-out", default=None, help="where to write the generated authoriser private keys (default <entitlement-dir>/authorizer-keys.json, owner-only)")
    p.add_argument("--force", action="store_true", help="overwrite existing trust root / entitlement")
    p.set_defaults(fn=_provision)

    p = sub.add_parser("new-authorizer", help="generate one authoriser keypair (public card + private key)")
    p.add_argument("--key-id", required=True, help="stable authoriser id")
    p.add_argument("--name", required=True, help="human-readable authoriser name")
    p.add_argument("--card-out", default=None, help="write the public AuthorizerKey card here (default: print to stdout)")
    p.add_argument("--key-out", required=True, help="write the base64 private key here (owner-only)")
    p.set_defaults(fn=_new_authorizer)

    p = sub.add_parser("build-trust-root", help="assemble a trust root from authoriser public cards")
    p.add_argument("--card", action="append", required=True, metavar="PATH", help="path to an authoriser public card (repeatable)")
    p.add_argument("--threshold", type=int, required=True, help="m in m-of-n signatures required")
    p.add_argument("--out", default=None, help="output path (default: the deployment's trust-root.json)")
    p.add_argument("--force", action="store_true", help="overwrite an existing trust root")
    p.set_defaults(fn=_build_trust_root)

    p = sub.add_parser("sign-entitlement", help="sign an entitlement document with authoriser private keys")
    _add_document_args(p)
    p.add_argument("--signer", action="append", required=True, metavar="KEY_ID=PATH", help="authoriser key_id and its private-key file (repeatable; supply >= threshold)")
    p.add_argument("--out", default=None, help="output path (default: the deployment's entitlement.json)")
    p.add_argument("--force", action="store_true", help="overwrite an existing entitlement")
    p.set_defaults(fn=_sign_entitlement)

    return parser


def main(argv: list[str]) -> int:
    paths.tighten_umask()   # X2: owner-only files even when this CLI is run standalone
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = args.fn  # type: ignore[attr-defined]
    return int(fn(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
