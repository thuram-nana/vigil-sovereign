"""
sovereign_deploy.bundle — offline, signed DEPLOYMENT bundles that install + verify with NO network (W13-8).

Property 1 of the sovereign / air-gapped deployment slice (#501): a customer can transfer a signed bundle
to an air-gapped host and INSTALL it — verify that every shipped artifact matches a manifest signed under a
trust anchor the CUSTOMER holds — without the box ever touching the network.

FACADE, NOT A SECOND MECHANISM. This module adds NO new signing/verification math. It is a thin facade over
the already-reviewed :mod:`vigil_core.signed_build_manifest` (the m-of-n signed build manifest with its six
explicit, fail-closed integrity states and the same ``verify_threshold`` the signed spine head uses). The
only things this module contributes are:

  * :func:`assemble_bundle` — the PROVISIONING side: hash + sign the artifacts and lay the manifest and the
    customer trust root down beside them, so the whole directory is one transferable air-gap bundle.
  * :func:`install_bundle` — the AIR-GAPPED side: verify that bundle OFFLINE, and (default) enforce the
    no-network posture in code, not merely by assertion — the verification runs inside :func:`no_network`,
    which makes any outbound socket call RAISE. If verification tried to phone home (a licence check, a
    revocation fetch, a vendor callback) the install would fail loudly instead of silently depending on a
    network the air-gapped host does not have. It does not, because the reused verifier is pure
    filesystem + Ed25519.

FAIL-CLOSED. ``install_bundle`` inherits the fail-closed state machine of ``verify_build_integrity``: only a
manifest that VERIFIES under the pinned customer trust root AND whose every artifact matches on disk yields
``installed`` True. A tampered artifact (MODIFIED), an absent one (MISSING), an unsigned manifest
(UNSIGNED_BUILD), or any manifest whose signatures do not satisfy the customer trust root (UNKNOWN_BUILD) is
NOT installed — the default is never an optimistic pass.

Import-clean (FATAL-2): stdlib + ``vigil_core`` only, so this loads in the sovereign process exactly like
``vigil_core.gate``; it imports nothing from ``framework`` / ``strix`` / ``sigil``.
"""

from __future__ import annotations

import json
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Optional, Sequence

from vigil_core.models import TrustRoot
from vigil_core.signed_build_manifest import (
    CHANNEL_RELEASE,
    MANIFEST_FILENAME,
    TRUST_ROOT_FILENAME,
    BuildIntegrityResult,
    BuildIntegrityState,
    SignedBuildManifest,
    build_signed_manifest,
    evaluate_build_integrity,
)

__all__ = [
    "NetworkAccessError",
    "no_network",
    "BundleInstallResult",
    "assemble_bundle",
    "install_bundle",
    "MANIFEST_FILENAME",
    "TRUST_ROOT_FILENAME",
]


# ── the enforced no-network posture ─────────────────────────────────────────────────────────────────────


class NetworkAccessError(RuntimeError):
    """Raised the instant any outbound network primitive is used inside a :func:`no_network` block. An
    air-gapped install that trips this is a BUG (a phone-home crept into the verify path) — the exception
    surfaces it loudly rather than letting the install silently depend on a network the host does not have."""


@contextmanager
def no_network() -> Iterator[None]:
    """Enforce, IN CODE, that the enclosed work performs no outbound network I/O.

    Every outbound-connection primitive on the ``socket`` module (``socket``, ``create_connection``,
    ``getaddrinfo``, ``create_server``) is swapped for one that raises :class:`NetworkAccessError`, then
    restored on exit (even on error). ``urllib`` / ``http.client`` / ``requests`` all bottom out on these,
    so a hidden HTTP call anywhere in the enclosed code path raises instead of connecting. This is the
    load-bearing proof of the "installs with NO network" property: the offline verifier runs INSIDE this
    block, so the property is enforced, not merely claimed. (Loopback-only local IPC is not needed by the
    pure verifier, so the block forbids ALL socket use for simplicity and strength.)"""
    saved = {
        name: getattr(socket, name)
        for name in ("socket", "create_connection", "getaddrinfo", "create_server")
        if hasattr(socket, name)
    }

    def _forbidden(*_a: object, **_k: object) -> object:
        raise NetworkAccessError(
            "outbound network access is forbidden during an air-gapped operation (no_network) — "
            "the sovereign install/verify path must not phone home"
        )

    try:
        for name in saved:
            setattr(socket, name, _forbidden)
        yield
    finally:
        for name, orig in saved.items():
            setattr(socket, name, orig)


# ── the install result (a thin, honest wrapper over the reused integrity result) ────────────────────────


@dataclass(frozen=True)
class BundleInstallResult:
    """The outcome of an offline bundle install. ``installed`` is True IFF the reused fail-closed state
    machine returned VALID (every locally verifiable artifact matches a manifest signed under the pinned
    customer trust root). Every non-VALID state is NOT installed, and ``state``/``detail`` carry the exact
    reason. ``offline_enforced`` records that the verification ran inside :func:`no_network`."""

    installed: bool
    state: str
    detail: str
    build_id: str
    product_version: str
    channel: str
    offline_enforced: bool
    integrity: Optional[BuildIntegrityResult] = None

    @property
    def ok(self) -> bool:
        return self.installed

    def to_dict(self) -> dict:
        return {
            "installed": self.installed,
            "state": self.state,
            "detail": self.detail,
            "build_id": self.build_id,
            "product_version": self.product_version,
            "channel": self.channel,
            "offline_enforced": self.offline_enforced,
        }


# ── provisioning: lay down a transferable, signed air-gap bundle ─────────────────────────────────────────


def assemble_bundle(
    *,
    bundle_root,
    product_version: str,
    artifact_specs: "Sequence[Mapping[str, object]]",
    trust_root: TrustRoot,
    signers: "Sequence[tuple[str, str]]",
    channel: str = CHANNEL_RELEASE,
) -> SignedBuildManifest:
    """PROVISIONING-side: hash + sign ``artifact_specs`` (relative to ``bundle_root``) into a manifest and
    write both the manifest (``build-manifest.json``) and the CUSTOMER trust root (``build-trust-root.json``)
    at ``bundle_root``, so the whole directory is one transferable bundle. The customer's private keys sign
    here (``signers`` = ``[(key_id, private_key_b64), ...]``); the air-gapped host only ever VERIFIES against
    the trust root's PUBLIC keys.

    The manifest and trust-root files are written at ``bundle_root`` (NOT inside a hashed artifact tree), so
    a ``tree``-kind artifact rooted at e.g. ``payload/`` never self-includes them. Returns the signed
    manifest for the caller's records."""
    manifest = build_signed_manifest(
        product_version=str(product_version),
        channel=str(channel),
        specs=artifact_specs,
        tree_root=bundle_root,
        signers=list(signers),
    )
    root = Path(bundle_root)
    root.mkdir(parents=True, exist_ok=True)
    (root / MANIFEST_FILENAME).write_text(
        json.dumps(manifest.to_disk(), sort_keys=True, indent=2), encoding="utf-8"
    )
    # Public-key material only — safe to ship inside the bundle. The trust root is the CUSTOMER's; the
    # vendor never holds a key that gates this deployment (see sovereign_deploy.trust).
    (root / TRUST_ROOT_FILENAME).write_text(
        trust_root.model_dump_json(indent=2), encoding="utf-8"
    )
    return manifest


# ── the air-gapped side: install == verify OFFLINE, fail-closed ─────────────────────────────────────────


def install_bundle(
    bundle_root,
    *,
    trust_root_path=None,
    manifest_path=None,
    observed_image_digests: "Optional[Mapping[str, str]]" = None,
    offline: bool = True,
) -> BundleInstallResult:
    """AIR-GAPPED side: verify the bundle at ``bundle_root`` and report whether it installs.

    Reuses :func:`vigil_core.signed_build_manifest.evaluate_build_integrity` — the pinned customer trust
    root and the on-disk manifest decide the outcome through the six fail-closed states. When ``offline``
    (the default air-gap posture) the verification runs INSIDE :func:`no_network`, so any outbound network
    call in the verify path raises :class:`NetworkAccessError` — the install cannot silently depend on a
    network the host does not have. ``installed`` is True IFF the state is VALID; every other state is a
    fail-closed non-install with the reason in ``detail``.

    Total: never raises for a malformed/absent manifest or trust root (those resolve to the fail-closed
    UNKNOWN_BUILD state). The one thing that DOES raise is a genuine network attempt under ``offline`` —
    that is a bug we want surfaced, not swallowed."""

    def _evaluate() -> BuildIntegrityResult:
        return evaluate_build_integrity(
            bundle_root,
            manifest_path=manifest_path,
            trust_root_path=trust_root_path,
            observed_image_digests=observed_image_digests,
        )

    if offline:
        with no_network():
            result = _evaluate()
    else:
        result = _evaluate()

    return BundleInstallResult(
        installed=(result.state == BuildIntegrityState.VALID),
        state=result.state,
        detail=result.detail,
        build_id=result.build_id,
        product_version=result.product_version,
        channel=result.channel,
        offline_enforced=bool(offline),
        integrity=result,
    )
