#!/usr/bin/env python3
"""Emit / verify the SIGNED BUILD MANIFEST over every shipped artifact (W4-3 #443 + W9-7 #440).

The product signs what it emits — findings, remediation certificates, the audit spine — but until now the
*build of the product* recorded no identity for three of the four things it ships: the only build id covered
the browser bundle. This tool produces ONE signed manifest over ALL shipped artifacts (the Python code, the
Rust WARDEN kernel, the browser bundle, the gateway image), each with a content-addressed sha-256 digest and
a manifest-wide ``build_id`` derived from them, so a running install can be asked whether its own files are
the ones that shipped — and get one of six explicit integrity states back, never an optimistic default.

The signing + verification MECHANISM lives in ``vigil_core.signed_build_manifest`` (reused by ``vigil
doctor`` and the health endpoint); this file is only the provisioning CLI around it. Signing is
provisioning-only, exactly like the rest of vigil_core's crypto.

    # generate + sign a release manifest (m-of-n: pass --key once per signer)
    python3 tools/build_manifest.py generate \
        --root . --channel release --version 1.5.0 \
        --specs tools/build-manifest.artifacts.json \
        --image gateway-image=sha256:<digest-from-docker-inspect> \
        --key rel1=keys/rel1.ed25519 \
        --out build-manifest.json

    # verify a tree against a manifest + a pinned trust root, OFFLINE (exit 0 iff VALID)
    python3 tools/build_manifest.py verify \
        --root . --manifest build-manifest.json --trust-root build-trust-root.json

The private key files are raw base64 Ed25519 private keys (as ``vigil_core.generate_keypair`` emits). They
are NEVER read by the runtime — only here, at build time.

DETERMINISM: the signed region carries no wall-clock and no rng (``build_id`` is derived from the artifact
digests; artifacts are sorted by name), so re-running ``generate`` over the same tree with the same key
yields a byte-identical manifest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# vigil_core is a first-party dependency of the operator tools (installed in the offense/sovereign venvs).
from vigil_core.signed_build_manifest import (
    BuildIntegrityState,
    BuildManifestError,
    build_manifest_from_specs,
    evaluate_build_integrity,
    sign_manifest,
)


def _load_specs(specs_path: Path, image_digests: "dict[str, str]") -> list:
    """Read the committed artifact-spec file and inject the supplied image digests. Fail-closed: an image
    artifact with no supplied digest is refused (a manifest that silently omits an artifact's identity is
    the defect this closes)."""
    raw = json.loads(specs_path.read_text(encoding="utf-8"))
    specs = raw["artifacts"] if isinstance(raw, dict) else raw
    out = []
    for spec in specs:
        spec = dict(spec)
        if spec.get("kind") == "image":
            digest = image_digests.get(spec["name"])
            if not digest:
                raise SystemExit(
                    f"image artifact {spec['name']!r} needs a digest — pass "
                    f"--image {spec['name']}=sha256:<hex> (from `docker inspect --format "
                    f"'{{{{index .RepoDigests 0}}}}'`)")
            spec["digest"] = digest
        out.append(spec)
    return out


def _parse_kv(pairs: "list[str]", what: str) -> "dict[str, str]":
    out: "dict[str, str]" = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"--{what} expects NAME=VALUE, got {p!r}")
        k, v = p.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _generate(args: argparse.Namespace) -> int:
    root = Path(args.root)
    image_digests = _parse_kv(args.image, "image")
    specs = _load_specs(Path(args.specs), image_digests)
    try:
        manifest = build_manifest_from_specs(product_version=args.version, channel=args.channel,
                                             specs=specs, tree_root=root)
    except BuildManifestError as e:
        raise SystemExit(f"cannot build manifest: {e}")

    signers: "list[tuple[str, str]]" = []
    for kid, keypath in _parse_kv(args.key, "key").items():
        priv = Path(keypath).read_text(encoding="utf-8").strip()
        signers.append((kid, priv))
    if signers:
        manifest = sign_manifest(manifest, signers)
    elif args.channel == "release":
        sys.stderr.write("[build-manifest] WARNING: no --key given; emitting an UNSIGNED release manifest "
                         "(it will verify as UNSIGNED_BUILD, never VALID)\n")

    payload = json.dumps(manifest.to_disk(), indent=2, sort_keys=True) + "\n"
    out = Path(args.out)
    out.write_text(payload, encoding="utf-8")
    sys.stderr.write(f"[build-manifest] wrote {out}: build_id={manifest.build_id()} "
                     f"channel={manifest.channel} artifacts={len(manifest.artifacts)} "
                     f"signatures={len(manifest.signatures)}\n")
    return 0


# States that a `verify` invocation accepts as success. VALID is always acceptable; a development build is
# acceptable ONLY with --allow-development (so a release pipeline cannot pass on a dev manifest by accident).
def _verify(args: argparse.Namespace) -> int:
    result = evaluate_build_integrity(Path(args.root), manifest_path=args.manifest,
                                      trust_root_path=args.trust_root,
                                      observed_image_digests=_parse_kv(args.image, "image") or None)
    acceptable = {BuildIntegrityState.VALID}
    if args.allow_development:
        acceptable.add(BuildIntegrityState.DEVELOPMENT_BUILD)
    ok = result.state in acceptable
    report = result.to_dict()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"build integrity: {result.state} — {result.detail}")
        print(f"  build_id={result.build_id or '(none)'} channel={result.channel or '(none)'} "
              f"version={result.product_version or '(none)'}")
        for a in result.artifacts:
            print(f"  [{a['status']:>13}] {a['name']} ({a['kind']}) — {a['detail']}")
    return 0 if ok else 1


def main(argv: "list[str]") -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="hash + sign the shipped artifacts into a build manifest")
    g.add_argument("--root", default=".", help="the tree/install root the paths are relative to")
    g.add_argument("--channel", choices=("release", "development"), required=True)
    g.add_argument("--version", required=True, help="product version recorded in the manifest")
    g.add_argument("--specs", required=True, help="the committed artifact-spec JSON")
    g.add_argument("--image", action="append", default=[], metavar="NAME=sha256:HEX",
                   help="an image artifact's content digest (repeatable)")
    g.add_argument("--key", action="append", default=[], metavar="KEY_ID=PRIVKEY_FILE",
                   help="an Ed25519 signer (repeatable for m-of-n)")
    g.add_argument("--out", default="build-manifest.json")
    g.set_defaults(fn=_generate)

    v = sub.add_parser("verify", help="evaluate a tree's integrity against a manifest + trust root")
    v.add_argument("--root", default=".", help="the tree/install root to verify")
    v.add_argument("--manifest", default=None, help="path to build-manifest.json (default: <root>/…)")
    v.add_argument("--trust-root", default=None, help="path to build-trust-root.json (default: <root>/…)")
    v.add_argument("--image", action="append", default=[], metavar="NAME=sha256:HEX",
                   help="an OBSERVED image digest to check against the manifest (repeatable)")
    v.add_argument("--allow-development", action="store_true",
                   help="treat DEVELOPMENT_BUILD as success (default: only VALID succeeds)")
    v.add_argument("--json", action="store_true", help="emit the full result as JSON")
    v.set_defaults(fn=_verify)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
