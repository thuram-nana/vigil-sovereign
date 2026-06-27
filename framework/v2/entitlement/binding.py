"""
entitlement.binding — host/workload attestation check.

An entitlement bound with binding_type='host_attestation' runs only
where at least one of its `bound_identifiers` is present on the host.
This makes a stolen entitlement file useless off its attested machine.

Identifiers gathered, in order of trust:

  1. CRUCIBLE_ATTESTED_IDENTITY — explicit attested identity injected by
     the deployment (e.g. a SPIFFE SVID id, an HSM-attested host id, a
     TPM quote digest). Comma-separated; each entry is an identifier.
     This is the production path: a SPIRE agent or attestation sidecar
     sets it after verifying the workload.
  2. /etc/machine-id — the systemd machine id, stable per install.
  3. hostname — weakest; present as a last resort and for low-assurance
     'none' deployments that still want a soft label.

The framework does not itself perform remote attestation — that is the
deployment's responsibility (SPIRE, a TPM stack, a cloud instance
identity document). The framework *consumes* the attested identity via
CRUCIBLE_ATTESTED_IDENTITY and refuses to run gated capability off an
identity the entitlement was not bound to. That division is deliberate:
attestation infrastructure is institutional; identity *enforcement* is
the framework's job.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

from .models import HardwareBinding

_ATTESTED_ENV = "CRUCIBLE_ATTESTED_IDENTITY"
_MACHINE_ID_PATHS = ("/etc/machine-id", "/var/lib/dbus/machine-id")


def _read_machine_ids() -> list[str]:
    ids: list[str] = []
    for p in _MACHINE_ID_PATHS:
        try:
            text = Path(p).read_text(encoding="utf-8").strip()
        except (OSError, ValueError):
            continue
        if text:
            ids.append(text)
    return ids


def current_host_identifiers() -> frozenset[str]:
    """The set of identifiers the running host can present. Compared,
    case-sensitively, against an entitlement's bound_identifiers."""
    ids: list[str] = []

    raw = os.environ.get(_ATTESTED_ENV, "")
    for part in raw.split(","):
        token = part.strip()
        if token:
            ids.append(token)

    ids.extend(_read_machine_ids())

    try:
        host = socket.gethostname().strip()
    except OSError:
        host = ""
    if host:
        ids.append(host)

    return frozenset(ids)


def binding_satisfied(
    binding: HardwareBinding,
    host_identifiers: frozenset[str] | None = None,
) -> tuple[bool, str]:
    """Return (ok, reason). A 'none' binding is always satisfied. A
    'host_attestation' binding is satisfied iff at least one bound
    identifier is present on the host."""
    if binding.binding_type == "none":
        return True, "binding_type=none (unbound)"

    present = current_host_identifiers() if host_identifiers is None else host_identifiers
    matched = [b for b in binding.bound_identifiers if b in present]
    if matched:
        # Do not echo the full matched identifier (it may be a sensitive
        # workload id); report the count and a stable prefix only.
        return True, f"host attestation matched {len(matched)} bound identifier(s)"
    return False, (
        f"no bound identifier present on host "
        f"(entitlement binds {len(binding.bound_identifiers)} identifier(s); "
        f"set {_ATTESTED_ENV} on the attested host)"
    )
