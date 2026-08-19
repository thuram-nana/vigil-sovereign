"""sigil.sovereignty — the SIGIL (sovereign) plane's own model-egress gate (W16-9).

The offense engine gates every model call at backend *construction* through
`kernel.sovereignty` (`CRUCIBLE_SOVEREIGNTY_TIER`). But the SIGIL plane runs in a
SEPARATE process and, historically, its OWN model calls — vision (`ClaudeVision`),
memory consolidation (`consolidate.extract.ApiProvider`) and voice
(`voice.backends.ElevenLabsTts`/`ElevenLabsAsr`) — read `SIGIL_ANTHROPIC_API_KEY` /
`ANTHROPIC_API_KEY` / `ELEVENLABS_API_KEY` and reached the cloud INDEPENDENTLY of the
tier. That is fatal to an air-gap claim: an operator who set `AIR_GAPPED` for the
offense engine still had voice/vision/memory silently egressing.

FATAL-2 boundary: the SIGIL plane must NOT import the offense engine
(`framework.*` / `vigil_integration.*`). So this is a self-contained, pure-stdlib
re-read of the SAME env vars the offense `kernel.sovereignty` reads, giving the
sovereign plane its own gate that latches to the same operator decision.

What it validates — the RESOLVED ENDPOINT, not a declared backend label
================================================================================
A caller-injected client that declares `backend="ollama"` while actually pointing
at a cloud endpoint must NOT slip past the gate. So the classification key is the
URL the code is about to open — `classify_endpoint(url)` — never a trusted
in-process label. A host is `local` iff it is loopback / RFC-1918 private /
link-local / IPv6-ULA, or the literal name ``localhost``; every other host
(including any public DNS name we do not resolve) is conservatively `cloud`.

Tier semantics (mirrors `kernel.sovereignty` for these direct/third-party endpoints)
================================================================================
The SIGIL cloud endpoints in question — `api.anthropic.com` reached with a direct
consumer key, and `api.elevenlabs.io` — have NO jurisdictional or ZDR variant, so
they classify exactly as the offense engine classifies a direct consumer
`anthropic` backend: `cloud_only`, permitted at PERMISSIVE only. Therefore:

    * a `local` endpoint is permitted under EVERY tier (a local Ollama/vLLM/Whisper
      backend keeps working air-gapped); and
    * a `cloud` endpoint is REFUSED under every non-PERMISSIVE tier
      (AIR_GAPPED / SOVEREIGN_CLOUD / TRUSTED_CLOUD) and permitted only under
      PERMISSIVE (the development default — unchanged behaviour).

HONEST LIMIT — a tier is not a network control
================================================================================
This gate guarantees the SIGIL plane will not *attempt* a disallowed model call; it
is enforced in in-process Python and can be bypassed by code running in the same
process. It is NOT a packet filter. For an enforced boundary combine it with host
firewalling / the egress gateway (see `engine/crucible/SECURITY.md` and
[W0-6] #401). A hostname we cannot classify as local is treated as cloud
(fail-closed): under an air-gapped tier that refuses it rather than resolving DNS
(itself an egress) to decide.
"""
from __future__ import annotations

import enum
import ipaddress
import os
from urllib.parse import urlsplit

__all__ = [
    "SovereigntyRefusal",
    "Tier",
    "current_tier",
    "is_permissive",
    "classify_endpoint",
    "assert_endpoint_permitted",
    "explain",
]


class SovereigntyRefusal(RuntimeError):
    """Raised (fail-closed) when the active sovereignty tier forbids a cloud model
    egress from the SIGIL plane. Must NOT be silently swallowed — it is the sovereign
    plane refusing to leak."""


class Tier(str, enum.Enum):
    AIR_GAPPED = "AIR_GAPPED"
    SOVEREIGN_CLOUD = "SOVEREIGN_CLOUD"
    TRUSTED_CLOUD = "TRUSTED_CLOUD"
    PERMISSIVE = "PERMISSIVE"


# Kept byte-identical to `kernel.sovereignty`: the same env vars, the same truthy
# vocabulary, the same fail-closed-to-AIR_GAPPED on an unknown tier name — so BOTH
# planes read ONE operator decision identically.
_TIER_ENV = "CRUCIBLE_SOVEREIGNTY_TIER"
_LEGACY_ENV = "CRUCIBLE_SOVEREIGN_MODE"
_TRUTHY = ("1", "true", "yes", "on")


def current_tier() -> Tier:
    """Resolve the active tier from the environment on each call (mirrors the offense
    engine's env resolution). Unknown tier name → fail closed to AIR_GAPPED."""
    raw = os.environ.get(_TIER_ENV, "").strip().upper()
    if raw:
        try:
            return Tier(raw)
        except ValueError:
            return Tier.AIR_GAPPED
    if os.environ.get(_LEGACY_ENV, "").strip().lower() in _TRUTHY:
        return Tier.AIR_GAPPED
    return Tier.PERMISSIVE


def is_permissive() -> bool:
    """True only under the PERMISSIVE (development default) tier."""
    return current_tier() == Tier.PERMISSIVE


def _host_of(url: str) -> str:
    """The bare hostname of a URL/host string, IPv6 brackets stripped. A value with
    no scheme (e.g. ``127.0.0.1:11434``) is tolerated by prefixing a scheme."""
    s = (url or "").strip()
    if "://" not in s:
        s = "//" + s
    host = urlsplit(s).hostname or ""
    return host.strip().rstrip(".").lower()


def classify_endpoint(url: str) -> str:
    """Classify an endpoint by its RESOLVED HOST — ``"local"`` or ``"cloud"``.

    ``local`` iff the host is the literal name ``localhost`` OR an IP literal that is
    loopback / private (RFC-1918) / link-local / IPv6 unique-local / unspecified.
    Every other host — crucially every public DNS name we do not resolve, e.g.
    ``api.anthropic.com`` — is ``cloud`` (fail-closed). The classification is on the
    ENDPOINT, never on a caller-declared backend label."""
    host = _host_of(url)
    if not host:
        return "cloud"  # no resolvable host → fail closed
    if host == "localhost" or host.endswith(".localhost"):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "cloud"  # a DNS name we do not resolve — conservatively cloud
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
        return "local"
    return "cloud"


def assert_endpoint_permitted(url: str, *, purpose: str = "model call") -> None:
    """Raise `SovereigntyRefusal` if the active tier forbids reaching `url`.

    Called at the SIGIL plane's model-egress sites just before the request is opened,
    with the ACTUAL url being reached. A `local` endpoint is permitted under every
    tier; a `cloud` endpoint is refused under every non-PERMISSIVE tier."""
    tier = current_tier()
    if tier == Tier.PERMISSIVE:
        return
    if classify_endpoint(url) == "local":
        return
    host = _host_of(url) or "<unknown>"
    raise SovereigntyRefusal(
        f"SIGIL-plane {purpose} to cloud endpoint {host!r} is refused under "
        f"sovereignty tier {tier.value!r}. This endpoint classifies 'cloud' "
        f"(no jurisdictional/ZDR variant), permitted only under PERMISSIVE. "
        f"Use a LOCAL backend (Ollama/vLLM/Whisper/Piper on localhost), or set "
        f"{_TIER_ENV}=PERMISSIVE to allow it. NOTE: a tier is not a network "
        f"control — it stops the engine ATTEMPTING the call; enforce the boundary "
        f"with host firewalling / the egress gateway (see engine/crucible/SECURITY.md)."
    )


def explain() -> str:
    """One-line human-readable summary of the SIGIL-plane egress posture."""
    tier = current_tier()
    if tier == Tier.PERMISSIVE:
        return "tier=PERMISSIVE: SIGIL-plane cloud model calls allowed (dev default)"
    return (
        f"tier={tier.value}: SIGIL-plane cloud model calls (vision/voice/memory) "
        f"REFUSED at egress; only local (on-box/LAN) backends permitted"
    )
