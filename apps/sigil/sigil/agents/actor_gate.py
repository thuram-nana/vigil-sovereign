"""Action gate (Phase 8, WS-G G-iii) — a near-verbatim mirror of `perception/egress.py`, but for web
ACTIONS. `action_token = sha256(service|step|url|page_sha256|field_binding)` binds an approval to ONE
exact action — the destination URL is IN the preimage (so an approval can never be rebound to a
different URL, even one serving identical bytes), alongside the page hash (a page-change aborts) and
the field binding (a vault-version bump / literal edit aborts). `action_approved` requires a VERIFIED
owner/authorized-device approval whose signed `target_seq` IS that step — a replay onto a different
action, a wrong token, an unsigned/denied approval → False (fail-closed)."""
from __future__ import annotations

from ..reuse import sha256_hex
from .approvals import SIGNAL as _APPROVAL_SIGNAL
from .approvals import verify_approval

ACTION_SIGNAL = "web.actor.step"


def action_token(service: str, step_kind: str, url: str, page_sha256: str, field_binding: str) -> str:
    return sha256_hex(f"{service}|{step_kind}|{url}|{page_sha256}|{field_binding}".encode("utf-8"))


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
