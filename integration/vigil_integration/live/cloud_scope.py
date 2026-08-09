"""
cloud_scope — the Track B (live cloud / Kubernetes) authorization gate.

Track B authorises by CLOUD-NATIVE IDENTITY, not by a URL host. Authorising the
API endpoint ``ec2.amazonaws.com`` (or ``*.amazonaws.com``) must NOT authorise
every AWS account that shares that endpoint — the host is one shared front door
to millions of tenants. So this gate never consults the host denylist / scope
table (that is :class:`~vigil_integration.live.external_tool.ScopeGate`'s job for
Track A URL targets); it consults a separate, explicit CLOUD SCOPE the operator
signs into the charter, keyed on (provider, account/project/subscription).

Charter schema addition (documented, small, additive)
-----------------------------------------------------
A charter that authorises Track B adds a section titled exactly::

    ## 2b. Cloud scope (Track B — cloud / Kubernetes)

    | Provider | Account / Project / Subscription | Region | Resource (glob) |
    |----------|----------------------------------|--------|-----------------|
    | `aws`    | `123456789012`                   | `us-east-1` | `*`        |
    | `gcp`    | `my-prod-project`                | `*`    | `bucket/app-*`  |
    | `azure`  | `d1e2...-guid`                   | `westus2` | `rg-app/*`   |
    | `k8s`    | `prod-cluster`                   |        | `ns/payments/*` |

Column semantics (this is the whole schema):
  * **Provider** — a cloud-native provider token (``aws`` / ``gcp`` / ``azure`` /
    ``k8s`` / …). Matched EXACTLY (case-insensitive). A wildcard here authorises
    nothing.
  * **Account / Project / Subscription** — the tenant identity (AWS account id,
    GCP project id, Azure subscription id, k8s cluster name). Matched EXACTLY
    (case-insensitive). A wildcard / blank / ``*`` / ``any`` here authorises
    NOTHING — the tenant must be named explicitly. This is the whole point of the
    gate: broad tenant wildcards are refused.
  * **Region** — OPTIONAL. Blank ⇒ any region. Set ⇒ the requested region must
    match this glob (``fnmatch``); an empty requested region is refused when the
    entry constrains region (cannot confirm we stayed in-region).
  * **Resource (glob)** — OPTIONAL. Blank ⇒ any resource. Set ⇒ the requested
    resource must match this glob; an empty requested resource is refused when the
    entry constrains resource.

Invariants
----------
  * **FAIL-CLOSED.** Unknown / empty / unparseable scope ⇒ refuse. Empty provider
    or empty account in the REQUEST ⇒ refuse. A kill-switch check that raises ⇒
    refuse.
  * **KILL-SWITCH honoured**, using the SAME check the Track A pre-flight uses
    (``framework.v2.authority.KillSwitch(slug).is_tripped()``), imported
    function-locally (FATAL-2).
  * **No self-authorisation (the R4 lesson).** The allow-set is derived ONLY from
    the signed charter. The gate NEVER folds the requested (provider, account)
    into the allow-set — a target does not authorise itself.
  * **Only-ahead / bounded honesty.** :class:`CaptureScope` records requested vs
    returned identities and whether the capture was truncated, so a Track B
    certificate can state COMPLETE vs BOUNDED honestly (a bounded capture is not
    a CLEAN negative).

Purity
------
Pure sovereign, stdlib only at module scope. The two framework touch-points
(the kill-switch class and the charter path helper) are imported function-locally
with ``# noqa: PLC0415`` so importing this module co-loads no offense engine.
"""

from __future__ import annotations

import fnmatch
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

# Values in a provider/account cell that name NO concrete identity: they authorise
# nothing (an entry that uses one is inert; a request that uses one is refused).
_WILDCARD_SENTINELS = frozenset(
    {"", "*", "**", "?", "any", "all", "n/a", "n\\/a", "none", "-", "—", "<provider>",
     "<account>", "<account / project / subscription>", "<project>", "<subscription>"}
)
# Glob metacharacters that make a provider/account cell non-explicit.
_GLOB_CHARS = ("*", "?", "[")


def _norm(value: Optional[str]) -> str:
    """Lower-cased, whitespace- and backtick-stripped cell value. Total (None → "")."""
    return (value or "").strip().strip("`").strip().casefold()


def _is_wildcarded(value: str) -> bool:
    """True iff a normalised provider/account value names no explicit identity."""
    if value in _WILDCARD_SENTINELS:
        return True
    return any(ch in value for ch in _GLOB_CHARS)


# ---------------------------------------------------------------------------
# The charter schema object.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CloudScopeEntry:
    """One signed row of the charter's cloud scope. ``region``/``resource`` are
    optional globs; ``provider``/``account`` are explicit identities."""

    provider: str
    account: str
    region: str = ""
    resource: str = ""

    def is_explicit(self) -> bool:
        """A row authorises something only if BOTH provider and account name an
        explicit (non-wildcard) identity. A row with a wildcard tenant is inert."""
        return not _is_wildcarded(_norm(self.provider)) and not _is_wildcarded(_norm(self.account))


# The charter section header for cloud scope. Parsed permissively; err toward refusing.
_CLOUD_HEADER = re.compile(
    r"^##\s*2b\.\s*Cloud scope\b", re.MULTILINE | re.IGNORECASE
)
_NEXT_H2 = re.compile(r"^##\s+", re.MULTILINE)


def parse_cloud_scope(charter_text: str) -> list[CloudScopeEntry]:
    """Extract the cloud-scope table rows from a charter's markdown. Pure stdlib.

    Returns [] when the section is absent or empty (⇒ the gate fails closed). Header
    and separator rows, and rows whose provider/account is blank, are skipped.
    """
    m = _CLOUD_HEADER.search(charter_text or "")
    if not m:
        return []
    after = charter_text[m.end():]
    nxt = _NEXT_H2.search(after)
    block = after if nxt is None else after[: nxt.start()]

    entries: list[CloudScopeEntry] = []
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cols = [c.strip().strip("`").strip() for c in line.strip("|").split("|")]
        if len(cols) < 2:
            continue
        provider = cols[0]
        # skip the markdown separator (---) and header rows
        if not provider or set(provider) <= {"-", " ", ":"}:
            continue
        if provider.strip().lower() in {"provider"}:
            continue
        account = cols[1] if len(cols) > 1 else ""
        region = cols[2] if len(cols) > 2 else ""
        resource = cols[3] if len(cols) > 3 else ""
        # drop trailing parentheticals a human might append, e.g. "us-east-1 (primary)"
        region = re.sub(r"\s*\(.*?\)\s*$", "", region).strip()
        resource = re.sub(r"\s*\(.*?\)\s*$", "", resource).strip()
        entries.append(CloudScopeEntry(provider=provider, account=account,
                                       region=region, resource=resource))
    return entries


# ---------------------------------------------------------------------------
# Scope sources — a static one for tests, a charter-backed one for production.
# ---------------------------------------------------------------------------
class CloudScopeSource(ABC):
    """The gate's view of the signed cloud scope."""

    @abstractmethod
    def entries(self) -> list[CloudScopeEntry]:
        """The cloud-scope rows the operator signed into the charter."""


class StaticCloudScopeSource(CloudScopeSource):
    """A fixed cloud-scope list — for injection and hermetic tests."""

    def __init__(self, entries: list[CloudScopeEntry]):
        self._entries = list(entries)

    def entries(self) -> list[CloudScopeEntry]:
        return list(self._entries)


class CharterCloudScopeSource(CloudScopeSource):
    """Cloud scope read live from a signed charter's ``## 2b. Cloud scope`` table.

    Reads the charter each call so a mid-engagement re-sign is picked up. The
    charter PATH comes from CRUCIBLE's path helper (imported function-locally —
    FATAL-2); the PARSE is pure sovereign stdlib. A missing charter file yields
    [] ⇒ the gate fails closed (it does not raise, so an absent Track-B section
    simply authorises nothing)."""

    def __init__(self, slug: str):
        self.slug = slug

    def entries(self) -> list[CloudScopeEntry]:
        from framework.v2.common import paths  # noqa: PLC0415 — offense-side path helper only
        cp = paths.charter_path(self.slug)
        if not cp.is_file():
            return []
        return parse_cloud_scope(cp.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The gate.
# ---------------------------------------------------------------------------
@dataclass
class CloudScopeGate:
    """Authorise a Track B action by cloud-native identity against the signed
    charter cloud scope. FAIL-CLOSED; honours the kill-switch; never self-adds
    the target's own identity."""

    scope: CloudScopeSource
    engagement_slug: str

    def _killswitch_refusal(self) -> "str | None":
        """Return a refusal reason if the run is not permitted to proceed, else None.

        Mirrors the Track A pre-flight gate order (charter context → kill-switch),
        using the SAME kill-switch check. A missing slug or a check that RAISES
        refuses (fail-closed)."""
        if not self.engagement_slug:
            return "a cloud action requires an engagement slug (no charter context = no authorization)"
        try:
            from framework.v2.authority import KillSwitch  # noqa: PLC0415 — offense-side only
            if KillSwitch(self.engagement_slug).is_tripped():
                return "kill-switch tripped"
        except Exception as e:  # noqa: BLE001 — a failing kill-switch check REFUSES (fail-closed)
            return f"kill-switch check failed (fail-closed): {e}"
        return None

    def authorize(
        self, provider: str, account: str, region: str = "", resource: str = ""
    ) -> tuple[bool, str]:
        """``(allowed, reason)`` for acting on (provider, account[, region][, resource]).

        Refuses unless a signed charter row matches provider EXACTLY and account
        EXACTLY (case-insensitive; wildcards in either field authorise nothing),
        and — where the row constrains them — region/resource match the row's glob.
        """
        # 0. kill-switch + charter-context pre-flight (fail-closed).
        refusal = self._killswitch_refusal()
        if refusal is not None:
            return False, refusal

        # 1. the REQUEST must name explicit identities (no wildcard self-request).
        p = _norm(provider)
        a = _norm(account)
        if _is_wildcarded(p):
            return False, "empty or wildcard provider (fail-closed — name the provider explicitly)"
        if _is_wildcarded(a):
            return False, "empty or wildcard account (fail-closed — name the account explicitly)"

        # 2. the signed allow-set (charter ONLY — never the request itself: the R4 lesson).
        entries = [e for e in self.scope.entries() if e.is_explicit()]
        if not entries:
            return False, "no explicit cloud scope in the signed charter (fail-closed)"

        r = _norm(region)
        res = (resource or "").strip()

        # Fail-closed on a path-traversal segment in the requested resource: fnmatch '*' spans '/', so a
        # glob like 'ns/payments/*' would otherwise also match 'ns/payments/../admin/root'. Cloud resource
        # IDs (ARNs, k8s ns/name) are canonical and never contain a '..' segment; a request that does is
        # refused rather than risk a downstream path-normalizer escaping the scoped prefix (red-pen D5-LOW).
        # '*' is NOT '/'-anchored — a resource glob must be written to match the full canonical id.
        if res and ".." in res.split("/"):
            return False, (f"requested resource {resource!r} contains a '..' path-traversal segment "
                           "(resource IDs must be canonical; refusing fail-closed)")

        for e in entries:
            if _norm(e.provider) != p:
                continue
            if _norm(e.account) != a:      # EXACT tenant match — never a wildcard
                continue
            # region: blank entry ⇒ any; set entry ⇒ glob-match a NON-empty request.
            e_region = _norm(e.region)
            if e_region:
                if not r:
                    return False, (f"charter scope for {p}/{a} constrains region to "
                                   f"{e.region!r} but no region was requested (fail-closed)")
                if not fnmatch.fnmatch(r, e_region):
                    continue
            # resource: blank entry ⇒ any; set entry ⇒ glob-match a NON-empty request.
            e_res = (e.resource or "").strip()
            if e_res:
                if not res:
                    return False, (f"charter scope for {p}/{a} constrains resource to "
                                   f"{e.resource!r} but no resource was requested (fail-closed)")
                if not fnmatch.fnmatch(res, e_res):
                    continue
            reason = f"{provider}/{account}"
            if region:
                reason += f" region={region}"
            if resource:
                reason += f" resource={resource}"
            return True, f"{reason} authorised by signed charter cloud scope"

        return False, (f"{provider}/{account} (region={region or '-'}, resource={resource or '-'}) "
                       f"is not in the signed charter cloud scope")


# ---------------------------------------------------------------------------
# CaptureScope — requested vs returned + completeness, for Track B certificates.
# ---------------------------------------------------------------------------
@dataclass
class CaptureScope:
    """Bounded-honesty record for a Track B capture: what identities we ASKED the
    cloud API to enumerate vs what it RETURNED, and whether the listing was
    truncated. A Track B negative certificate ("no exposed bucket in account X")
    is only a CLEAN/CONCLUSIVE negative when the capture is COMPLETE — otherwise it
    is BOUNDED and the oracle must not assert the negative (INCONCLUSIVE, never
    CLEAN — the governance charter). Deterministic bytes: sorted, empties dropped."""

    requested: list[str] = field(default_factory=list)
    returned: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def missing(self) -> list[str]:
        """Requested identities the API did not return (sorted, de-duplicated)."""
        return sorted(set(self.requested) - set(self.returned))

    @property
    def conclusive(self) -> bool:
        """True iff the capture is COMPLETE: not truncated, at least one identity
        requested, and every requested identity returned. A truncated or partial
        capture is inconclusive by construction."""
        if self.truncated or not self.requested:
            return False
        return not self.missing

    def completeness(self) -> str:
        """A human/label view: ``complete`` | ``bounded`` | ``empty``."""
        if not self.requested:
            return "empty"
        return "complete" if self.conclusive else "bounded"

    def to_dict(self) -> dict:
        """Deterministic, drop-when-empty dict for embedding in a signed cert."""
        out: dict = {"completeness": self.completeness()}
        if self.requested:
            out["requested"] = sorted(set(self.requested))
        if self.returned:
            out["returned"] = sorted(set(self.returned))
        if self.truncated:
            out["truncated"] = True
        missing = self.missing
        if missing:
            out["missing"] = missing
        return out
