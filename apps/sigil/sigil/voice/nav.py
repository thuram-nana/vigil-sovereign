"""voice.nav (S2) — turn a spoken utterance into a UI NAVIGATION intent, as an ADDITIONAL intent class
layered ahead of the untouched cognition path.

SIGIL already routes recognized speech through the KERNEL (T0 router + WARDEN gate + signed log). This
adds a thin, gated front-step: if an utterance clearly names a known UI screen ("open settings", "show
the findings"), emit a ``sigil.nav`` record on the owner-signed spine (which the cockpit's
``/api/sigil/hud`` tails → tells the browser to switch screens) and speak a short confirmation. Anything
that is NOT an unambiguous navigation command falls straight through to the existing KERNEL dispatch —
cognition is unchanged.

Safety posture:
  * **A1, injects nothing.** Navigation only changes which already-authorized screen the owner's own
    browser shows. It emits a spine SIGNAL; it runs no tool, touches no target, and cannot type or launch.
  * **Gated.** A nav is emitted ONLY when the ``voice`` capability latch is ON and the kill-switch is OFF.
    When either fails, the utterance is delegated to the KERNEL dispatch (which itself returns the
    disabled message / applies its own gate) — a nav can never bypass the latch or the kill-switch.
  * **Strict, unambiguous resolver.** Exact match against a screen's id / label / synonyms (after stripping
    a leading nav verb / "the "); zero or ambiguous matches resolve to NO nav (fall through to cognition),
    so it never hijacks a real question. The browser only ever navigates to a manifest-known screen id.
  * **Manifest-driven.** The known screens come from the S1 ``system-map.json`` (drift-checked against the
    real UI in CI), so SIGIL can only navigate to screens that actually exist.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .components import Dispatch

_log = logging.getLogger(__name__)

# leading phrases a nav command may carry; stripped before the exact match so "open settings" resolves.
_NAV_VERBS = ("open ", "go to ", "go ", "show me ", "show ", "navigate to ", "take me to ", "switch to ")


def _normalize(s: str) -> str:
    """lowercase, drop surrounding punctuation, collapse internal whitespace."""
    s = "".join(c if (c.isalnum() or c.isspace()) else " " for c in str(s or "").lower())
    return " ".join(s.split())


def _default_manifest_paths() -> list[Path]:
    """Candidate locations for the committed system-map.json (env override first, then repo-relative)."""
    out: list[Path] = []
    env = os.environ.get("VIGIL_SYSTEM_MAP", "").strip()
    if env:
        out.append(Path(env))
    # apps/sigil/sigil/voice/nav.py → repo root is parents[4]
    here = Path(__file__).resolve()
    for up in (here.parents[4] if len(here.parents) > 4 else here.parent,):
        out.append(up / "knowledge" / "system-map" / "system-map.json")
    out.append(Path.cwd() / "knowledge" / "system-map" / "system-map.json")
    return out


@dataclass(frozen=True)
class Screen:
    id: str
    label: str
    synonyms: tuple[str, ...]


class NavResolver:
    """Resolve an utterance to a known screen id, or ``None`` (not an unambiguous nav command).

    Loads the S1 manifest once. Missing/unreadable manifest → no screens → every resolve returns ``None``
    (fail-safe: navigation simply never fires; cognition is unaffected)."""

    def __init__(self, manifest_path: Optional[Path] = None, *, screens: Optional[list[Screen]] = None):
        if screens is not None:
            self._screens = list(screens)
            return
        self._screens = []
        paths = [manifest_path] if manifest_path is not None else _default_manifest_paths()
        for p in paths:
            if p and Path(p).is_file():
                try:
                    data = json.loads(Path(p).read_text(encoding="utf-8"))
                    for s in data.get("screens", []):
                        self._screens.append(Screen(
                            id=str(s.get("id", "")),
                            label=str(s.get("label", "")),
                            synonyms=tuple(str(x) for x in (s.get("synonyms") or [])),
                        ))
                    break
                except (OSError, ValueError):
                    continue

    @property
    def screen_ids(self) -> set[str]:
        return {s.id for s in self._screens if s.id}

    def _candidates(self, sc: Screen) -> set[str]:
        return {sc.id, _normalize(sc.label), *(_normalize(x) for x in sc.synonyms)} - {""}

    def resolve(self, utterance: str) -> Optional[Screen]:
        """Exact, unambiguous match only. Returns the Screen, or None (no/ambiguous match → cognition)."""
        u = _normalize(utterance)
        if not u:
            return None
        for v in _NAV_VERBS:                       # strip ONE leading nav verb, if present
            if u.startswith(v):
                u = u[len(v):].strip()
                break
        if u.startswith("the "):
            u = u[4:].strip()
        for suffix in (" screen", " page", " tab"):
            if u.endswith(suffix):
                u = u[: -len(suffix)].strip()
        if not u:
            return None
        hits = [sc for sc in self._screens if u in self._candidates(sc)]
        return hits[0] if len(hits) == 1 else None     # 0 or ambiguous (>1) → no nav


class RoutingDispatch(Dispatch):
    """A Dispatch that navigates on an unambiguous UI command, else delegates to the wrapped KERNEL
    dispatch (cognition). Wrap — never modify — ``KernelDispatch``; the nav path is gated on the voice
    latch + kill-switch and emits an A1 ``sigil.nav`` signal that injects nothing."""

    def __init__(self, delegate: Dispatch, *, store=None, resolver: Optional[NavResolver] = None):
        self._delegate = delegate
        self._store = store
        self._resolver = resolver if resolver is not None else NavResolver()

    # -- gates (fail-closed toward "do not nav") ------------------------------------------------------
    def _spine(self):
        if self._store is None:
            from ..spine.store import SpineStore
            self._store = SpineStore()
        return self._store

    def _voice_enabled(self) -> bool:
        try:
            from ..governor.capability import CapabilityGate
            return CapabilityGate(self._spine()).is_enabled("voice")
        except Exception:  # noqa: BLE001 — cannot read the latch ⇒ fail-closed toward disabled
            return False

    def _killswitch_engaged(self) -> bool:
        try:
            from ..governor.killswitch import KillSwitch
            return KillSwitch(self._spine()).is_engaged()
        except Exception:  # noqa: BLE001 — cannot read the kill-switch ⇒ fail-closed toward engaged (no nav)
            return True

    def _emit_nav(self, screen: Screen) -> Optional[int]:
        """Append the A1 sigil.nav SIGNAL (fully-plaintext payload — no CONTENT_FIELDS, so no vault
        dependency). Returns the seq, or None on any spine error (→ the utterance falls through)."""
        try:
            return self._spine().append(
                kind="event", source="voice", actor="OWNER",
                payload={"signal": "sigil.nav", "screen_id": screen.id, "label": screen.label,
                         "tier": "A1", "decision": "auto"})
        except Exception as e:  # noqa: BLE001 — a spine hiccup must never crash the voice loop
            _log.warning("sigil.nav emit failed: %s", type(e).__name__)
            return None

    def send(self, text: str) -> str:
        raw = (text or "").strip()
        if raw:
            screen = self._resolver.resolve(raw)
            # emit a nav ONLY on an unambiguous match with the latch ON and the kill-switch OFF; otherwise
            # the utterance is a real question (or voice is disabled/halted) → the cognition path handles it.
            if screen is not None and self._voice_enabled() and not self._killswitch_engaged():
                if self._emit_nav(screen) is not None:
                    return f"Opening {screen.label}."
        return self._delegate.send(text)
