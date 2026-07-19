"""SIGIL mobile bridge (Phase 7, WS-D D-v/vi) — the phone as an owner-authorized remote-control +
approval surface over WireGuard. The engine stays on the owned desktop; the phone approves (with its
own authorized device key), panic-halts, and relays KERNEL commands. Push carries only {seq,tier,kind}
over the tunnel — no subject, no secret, no cloud. Offense-free."""
from ..reuse import assert_no_offense

assert_no_offense()

from .daemon import BridgeDaemon, bind_ok  # noqa: E402
from .envelope import (  # noqa: E402
    ACTIONS,
    RECEIPT_SIGNAL,
    build_core,
    consume,
    device_nonce_highwater,
    envelope_message,
    record_receipt,
    sign_envelope,
    verify_envelope,
)
from .notifier import PushNotifier  # noqa: E402
from .server import BridgeServer, build_server, serve  # noqa: E402

__all__ = ["BridgeDaemon", "PushNotifier", "bind_ok",
           "ACTIONS", "RECEIPT_SIGNAL", "envelope_message", "build_core", "sign_envelope",
           "verify_envelope", "record_receipt", "device_nonce_highwater", "consume",
           "BridgeServer", "build_server", "serve"]
