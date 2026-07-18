"""SIGIL mobile bridge (Phase 7, WS-D D-v/vi) — the phone as an owner-authorized remote-control +
approval surface over WireGuard. The engine stays on the owned desktop; the phone approves (with its
own authorized device key), panic-halts, and relays KERNEL commands. Push carries only {seq,tier,kind}
over the tunnel — no subject, no secret, no cloud. Offense-free."""
from ..reuse import assert_no_offense

assert_no_offense()

from .daemon import BridgeDaemon, bind_ok  # noqa: E402
from .notifier import PushNotifier  # noqa: E402

__all__ = ["BridgeDaemon", "PushNotifier", "bind_ok"]
