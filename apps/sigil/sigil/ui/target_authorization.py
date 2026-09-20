"""Owner-sign an ENGAGEMENT AUTHORIZATION for a live external target, from the sovereign cockpit.

"Add a site I own -> authorize it in the UI (the owner key never leaves this process) -> the offense
console can then run a scoped, time-boxed, signed engagement against it." This is the sovereign half of
the UI-driven live-external spine (Phase 1). It mints an owner-signed ``EngagementAuthority`` — scope =
the authorized host(s), a bounded validity window, GET-only / non-destructive by default — and drops the
signed bundle on the shared seam. The OFFENSE console reads it back, VERIFIES the owner signature against
the pinned owner key, writes the charter, and persists the authority + owner trust-root; the launch gate
(``_has_verified_authority``) then refuses any remote run whose authority does not cryptographically
verify.

Operator model (mirrors the offense-approvals ceremony):
  * KEY MODEL = the sovereign owner key. The authority is signed by the SAME owner keypair the cockpit
    holds (``governor.identity.ensure_owner_keypair``); the trust root is that owner's PUBLIC key.
  * SIGNING POSTURE = sign in-process on click, using the already-unsealed owner key.

BOUNDARY (FATAL-2): sovereign-side, importing ONLY the import-clean shared core (``vigil_core.authority``
for the schema + owner signer; ``vigil_core.hard_guardrail`` for the categorical safety floor) and the
import-clean seam broker (``vigil_integration.live.authorization_broker``) — it touches no
``framework``/``strix`` module (proven framework-free the same way as ``offense_approvals``). The PRIVATE
key is used only inside :func:`sign_engagement_authority` and never leaves this process; only the
signed bundle (public keys + signatures + the owner-authored scope) crosses the seam. The offense side
still independently verifies the signature against the pinned owner key, so a forged or tampered bundle
dropped in the seam is refused regardless.

Deliberate refusals (fail-closed, honest):
  * a ``.gov`` / ``.mil`` / ``.edu`` / ``.int`` (or ``*.gov.cm``-class) host is REFUSED here — the
    categorical hard floor. Lifting it is a separate, explicit owner act (VIGIL_ALLOW_PROTECTED_DOMAINS),
    never a silent authorization from this screen.
  * ``environment="live"`` is REFUSED for now — a live-production authorization needs a deliberate,
    separately-acknowledged flow (the schema carries ``live_destructive_acknowledged`` for it); this
    ceremony issues TWIN / STAGING authorizations. Named, not hidden.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

# A conservative default validity window and action budget for a UI-issued authorization. The operator
# widens deliberately; a short window bounds a forgotten authorization.
_DEFAULT_DURATION_HOURS = 8.0
_MAX_DURATION_HOURS = 24.0 * 30                # a UI authorization caps at 30 days; longer is a CLI act
_ALLOWED_ENVIRONMENTS = ("twin", "staging")   # "live" needs a deliberate, separately-acknowledged flow

# A valid DNS hostname: 1-63-char labels (alnum + hyphen, no leading/trailing hyphen), dot-separated,
# total <= 253. No scheme, no path, no port, no wildcard, no "..", no whitespace — the scope must be a
# single literal host the offense scope matcher (which has no CIDR) can match exactly.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _base_dir() -> str:
    """The shared engagement base dir both planes agree on (``vigil up`` sets VIGIL_BASE_DIR for both);
    matches the offense console's own resolution and the offense-approvals ceremony."""
    return os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"


def _owner_keypair():
    from ..governor.identity import ensure_owner_keypair
    return ensure_owner_keypair()


def _slug_for(host: str, explicit: Optional[str]) -> str:
    """A path-safe engagement slug: the explicit slug if given, else derived from the host.

    CRITICAL: this must produce the SAME slug the offense console derives (``console.actions._slugify``),
    or the seam bundle is written under a slug the console never looks up and the whole UI->launch flow
    silently breaks. That algorithm is: lowercase, keep alnum + ``-_`` (every other char — notably the dot
    — becomes ``-``), strip leading/trailing ``-``, cap at 48. So ``apme.cm`` -> ``apme-cm`` on BOTH planes.
    Kept as a small verbatim copy (the sovereign plane cannot import the offense ``_slugify``)."""
    raw = str(explicit or host or "").strip().lower()
    return "".join(c if (c.isalnum() or c in "-_") else "-" for c in raw).strip("-")[:48]


def _validate_host(host: str) -> tuple[bool, str]:
    """(ok, host_or_error). A single literal DNS hostname, not categorically hard-blocked. Fail-closed."""
    from vigil_core.hard_guardrail import HardBlockError, assert_not_hard_blocked

    h = str(host or "").strip().lower()
    if not h:
        return False, "a host is required"
    if "://" in h or "/" in h or ":" in h or " " in h:
        return False, ("give a bare hostname (e.g. apme.cm), not a URL, path, or host:port — the scope is "
                       "a single literal host")
    if not _HOSTNAME_RE.match(h):
        return False, f"{h!r} is not a valid hostname"
    # An IPv4 literal passes the hostname regex; refuse the ranges that are never a legitimate LIVE EXTERNAL
    # target — loopback, link-local (incl. the cloud metadata address 169.254.169.254), multicast, reserved,
    # unspecified. (RFC-1918 private space is left to twin/staging and is independently blocked by the
    # never-liftable egress floor at runtime; IPv6 literals are already rejected by the ':' check above.)
    import ipaddress as _ip
    try:
        _addr = _ip.ip_address(h)
    except ValueError:
        _addr = None
    if _addr is not None and (_addr.is_loopback or _addr.is_link_local or _addr.is_multicast
                              or _addr.is_reserved or _addr.is_unspecified):
        return False, (f"{h!r} is a loopback / link-local / reserved address (e.g. cloud metadata) — not a "
                       f"live external target")
    try:
        assert_not_hard_blocked(h)
    except HardBlockError as e:
        return False, (f"{h!r} is on the categorical safety floor (.gov/.mil/.edu/.int and *.gov.cm-class): "
                       f"{e}. Lifting it is a separate, explicit owner act, never a silent authorization here.")
    return True, h


def authority_status(slug: str) -> dict:
    """Whether an owner-signed authorization exists on the seam for ``slug``, and whether its signer is
    THIS cockpit's owner key (so the offense side will accept it). Read-only; never raises."""
    from vigil_integration.live.authorization_broker import read_authorization

    s = _slug_for("", slug)
    ta = None
    try:
        ta = read_authorization(_base_dir(), s)
    except Exception:  # noqa: BLE001 — an unreadable/absent bundle is simply "not authorized"
        ta = None
    if ta is None:
        return {"ok": True, "slug": s, "present": False, "bound": False}
    kp = _owner_keypair()
    owner_ids = {a.public_key_b64 for a in ta.trust_root.authorizers}
    bound = kp.public_key_b64 in owner_ids
    doc = ta.signed_authority.document
    return {
        "ok": True, "slug": s, "present": True, "bound": bound,
        "scope": list(doc.scope), "environment": doc.environment.value,
        "not_before": doc.not_before.isoformat(), "not_after": doc.not_after.isoformat(),
    }


def add_target(
    host: str,
    *,
    slug: Optional[str] = None,
    environment: str = "staging",
    duration_hours: Any = _DEFAULT_DURATION_HOURS,
    note: str = "",
    now: Optional[Any] = None,
) -> dict:
    """Owner-sign an engagement authorization for ``host`` and write the signed bundle to the seam.

    Fail-closed: refuses an invalid / hard-blocked host, a non twin|staging environment, or a
    non-positive / over-cap duration. GET-only / non-destructive by default (``allow_destructive=False``).
    The owner PRIVATE key is used only inside the signer and is never written or returned."""
    from vigil_core import (
        AuthorizerKey, EngagementAuthority, TargetEnvironment, TrustRoot, sign_engagement_authority,
    )
    from vigil_integration.live.authorization_broker import write_authorization

    ok, host_or_err = _validate_host(host)
    if not ok:
        return {"ok": False, "error": host_or_err}
    h = host_or_err

    env = str(environment or "").strip().lower()
    if env not in _ALLOWED_ENVIRONMENTS:
        if env == "live":
            return {"ok": False, "error": "a LIVE-production authorization needs a deliberate, separately "
                                          "acknowledged flow; this ceremony issues twin / staging only"}
        return {"ok": False, "error": f"environment must be one of {_ALLOWED_ENVIRONMENTS}, got {env!r}"}

    try:
        dur = float(duration_hours)
    except (TypeError, ValueError):
        return {"ok": False, "error": "duration_hours must be a number"}
    if not (0 < dur <= _MAX_DURATION_HOURS):
        return {"ok": False, "error": f"duration_hours must be in (0, {_MAX_DURATION_HOURS}]"}

    s = _slug_for(h, slug)
    # Reject an empty or dot-only slug HERE with the {ok:false} contract — a dot-only value (".", "..") would
    # otherwise reach the broker and raise ValueError (an uncaught 500 rather than an honest error). The
    # broker's own _safe_component stays as the defence-in-depth backstop.
    if not s or all(c == "." for c in s):
        return {"ok": False, "error": "could not derive a path-safe slug (try an explicit slug)"}

    t = now() if callable(now) else (now if now is not None else datetime.now(timezone.utc))
    if not isinstance(t, datetime):
        t = datetime.fromtimestamp(float(t), tz=timezone.utc)
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)

    doc = EngagementAuthority(
        engagement_slug=s,
        environment=TargetEnvironment(env),
        scope=[h],
        not_before=t,
        not_after=t + timedelta(hours=dur),
        allow_destructive=False,          # GET-only / non-destructive by default; widened deliberately
        issued_by="owner",
        note=str(note or ""),
    )
    kp = _owner_keypair()
    signed = sign_engagement_authority(doc, {"owner": kp.private_key_b64})
    trust_root = TrustRoot(
        threshold=1,
        authorizers=[AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)],
    )
    try:
        path = write_authorization(_base_dir(), s, signed, trust_root)
    except ValueError as e:  # broker path-safety backstop — honor the {ok:false} contract, don't 500
        return {"ok": False, "error": f"could not write the authorization ({e})"}
    return {
        "ok": True, "action": "target_add", "slug": s, "host": h, "environment": env,
        "scope": [h], "not_before": doc.not_before.isoformat(), "not_after": doc.not_after.isoformat(),
        "signed_path": str(path),
    }


def list_targets() -> dict:
    """Every owner-signed authorization on the seam (public-safe fields only). Read-only; total."""
    from vigil_integration.live.authorization_broker import list_authorizations

    kp = None
    try:
        kp = _owner_keypair()
    except Exception:  # noqa: BLE001 — listing must not require an unsealed key
        kp = None
    targets = []
    try:
        for ta in list_authorizations(_base_dir()):
            doc = ta.signed_authority.document
            owner_ids = {a.public_key_b64 for a in ta.trust_root.authorizers}
            targets.append({
                "slug": ta.slug, "scope": list(doc.scope), "environment": doc.environment.value,
                "not_before": doc.not_before.isoformat(), "not_after": doc.not_after.isoformat(),
                "bound": bool(kp and kp.public_key_b64 in owner_ids),
            })
    except Exception:  # noqa: BLE001 — an unreadable dir is simply "nothing authorized"
        targets = []
    return {"ok": True, "base_dir": _base_dir(), "targets": targets}
