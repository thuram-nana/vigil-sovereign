"""SIGIL local UI (Phase 7, WS-C) — a loopback-only "glass cockpit". Read-only by construction over
the spine (`dashboard.snapshot`, `SpineTailer`, `graph.*`), with a CSRF-proof owner-signed action
plane. Offense-free by doctrine (perceive/observe + owner-gated actions only)."""
from ..reuse import assert_no_offense

assert_no_offense()
