"""vigil_range — the VIGIL cyber-range.

MERIDIAN is a deliberately-vulnerable, loopback-only, government-themed target application used as the
authorized lab/environment for exercising VIGIL end-to-end (offense and defense). The companion Range
Control cockpit drives the real VIGIL verbs against MERIDIAN and streams the results.

Safety invariants (see LAB-MANIFEST.json and targets/meridian/charter.md):
  * binds 127.0.0.1 ONLY — a public/LAN bind is refused;
  * holds ONLY synthetic data (no real PII, no real secrets);
  * every "leak" is a decoy (path traversal returns a fake passwd string, never a real file);
  * this package is STDLIB-ONLY and never imports framework.*/strix.* (the runner shells them).
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
