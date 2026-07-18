"""Action gate (Phase 8, WS-G G-iii) — a near-verbatim mirror of `perception/egress.py`, but for web
ACTIONS. `action_token = sha256(service|step|page_sha256|field_binding)` binds an approval to ONE
exact action (a page-change or a vault-version bump changes the token → re-approval). `action_approved`
requires a VERIFIED owner/authorized-device approval whose signed `target_seq` IS that step — a
replay onto a different action, a wrong token, an unsigned/denied approval → False (fail-closed)."""
from __future__ import annotations

from ..reuse import sha256_hex
from .approvals import SIGNAL as _APPROVAL_SIGNAL
from .approvals import verify_approval

ACTION_SIGNAL = "web.actor.step"


def action_token(service: str, step_kind: str, page_sha256: str, field_binding: str) -> str:
    return sha256_hex(f"{service}|{step_kind}|{page_sha256}|{field_binding}".encode("utf-8"))


def action_approved(store, seq: int, token: str, trusted_pubkey) -> bool:
    rec = store.get(seq)
    if rec is None or rec.payload.get("signal") != ACTION_SIGNAL or rec.payload.get("action_token") != token:
        return False
    from ..mesh import authorized_devices
    devices = authorized_devices(store, trusted_pubkey)
    for r in store.iter_records(since_seq=seq):
        p = r.payload
        if (p.get("signal") == _APPROVAL_SIGNAL and p.get("target_seq") == seq
                and p.get("approval") == "approved" and verify_approval(r, trusted_pubkey, extra_pubkeys=devices)):
            return True
    return False
