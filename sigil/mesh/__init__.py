"""SIGIL mesh (Phase 7, WS-D D-iii/iv) — "distributed compute, centralized authority". Host
capabilities and phone/device authorizations are owner-SIGNED spine records, so the mesh topology
is itself provable, tamper-evident memory; compute (vision/VLM) can run on the best-capable online
host, but authority still flows through the one signed spine + WARDEN. Offense-free."""
from ..reuse import assert_no_offense

assert_no_offense()

from .registry import (  # noqa: E402
    DeviceApprover,
    advertise_capability,
    authorize_device,
    authorized_devices,
    capability_map,
    revoke_device,
)

__all__ = ["advertise_capability", "capability_map", "authorize_device", "revoke_device",
           "authorized_devices", "DeviceApprover"]
