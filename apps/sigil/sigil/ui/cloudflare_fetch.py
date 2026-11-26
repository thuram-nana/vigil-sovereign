"""The LIVE cloud-connect fetcher for CLOUDFLARE (consumer PR-C, the connect screen's cloud leg — Cloudflare leg):
the trusted sovereign reader that produces the observation the cloud-connect verdict
(``governor.cloud_connect.cloud_grant_refusal``) judges for a Cloudflare provider. SHIPPED OFF BY DEFAULT —
``config.cloud_connect_cloudflare_fetcher`` builds it only when the cloud leg is on.

A DIFFERENT TRUST MODEL (critical). AWS/GCP/Azure connect by DELEGATED access: the customer creates a role VIGIL can
assume, and VIGIL stores NO customer secret. A Cloudflare API token, by contrast, IS a bearer secret the customer
hands over. VIGIL's posture is "never store a customer secret", so this fetcher:
  * receives the token as the ``role_ref``-equivalent SECRET parameter (same ``assume`` signature as the AWS fetcher;
    ``role_ref`` carries the token), uses it as a Bearer credential for exactly two read-only GET calls, and then
    drops it — it is NEVER logged, NEVER put in the return, NEVER put in an error ``detail``, NEVER stored;
  * returns only the token's PUBLIC id plus the booleans the verdict needs. The caller (``ui.provision``) records a
    grant carrying the token's public id and a sha256 of the token (so a re-presented token is recognisable without
    storing it) — never the token.

WHAT IT OBSERVES. With the customer's token as Bearer it:
  1. ``GET /client/v4/user/tokens/verify`` → the token must be ``{success:true, result:{status:"active", id:…}}``.
     A 401 / ``success:false`` → the token is wrong/expired (the customer's fix); any other status / 5xx / transport
     fault is INCONCLUSIVE and fails closed (never counted as a pass).
  2. ``GET /client/v4/user/tokens/{id}`` → read the token's OWN definition to BIND the challenge and confirm scope:
     its ``name`` (must ct-equal ``vigil-verify-{external_id}``), its ``policies`` (every permission group must be a
     READ-ONLY group — any write/edit/admin group REFUSES: VIGIL holds a read-only token only), and the account id
     in its resources (``com.cloudflare.api.account.{account_id}``) which must be EXACTLY the claimed account and
     never ``*``/all-accounts. Self-introspection of the calling token's own definition needs the read-only
     ``User API Tokens Read`` group, which the connect screen asks the customer to include; a token that cannot
     read its own definition fails CLOSED here (never over-accepted).
It returns ``{token_id, account, name_matched, external_id, read_only, single_account}`` and decides NOTHING: the
deterministic verdict lives in ``governor.cloud_connect._cloudflare_grant_refusal``.

THE ADAPTED NEGATIVE CONTROL. AWS proves the role ENFORCES VIGIL's external id by a same-shape DENIED control assume.
Cloudflare has no second principal; the equivalent proof that the token is not over-privileged is STRUCTURAL —
``read_only`` (no write/edit/admin permission group) AND ``single_account`` (the resource scope is the specific
account, not ``*``/all-accounts). A token that can WRITE, or is account-global, is REFUSED by the verdict: VIGIL will
not hold a powerful customer secret even briefly.

EGRESS (mirrors ``ui.cloud_fetch`` / ``governor.github_app_egress``): stdlib ``urllib`` only (FATAL-2 clean, no
vendor SDK); an https-only + exact-host allowlist guard BEFORE any socket opens (``config.CLOUDFLARE_API_EGRESS_ALLOWLIST``
— no endpoint override, so the token-bearing egress can only reach the Cloudflare API); a redirect-BLOCKING opener (a
3xx can never relay a Bearer request); a bounded response read; a strict JSON parse. The token travels only in the
``Authorization`` header, never in a URL; the token id placed in the URL path is format-checked (32 hex) first.

ERRORS: every failure is a ``CloudFetchError`` (reused from ``ui.cloud_fetch``, so the provisioner's existing
``except CloudFetchError`` carries this fetcher's fixed, customer-facing wording). The ``detail`` (for the operator
audit only) carries HTTP statuses and Cloudflare error CODES — NEVER the token, never a raw exception string.

VIGIL-LIMIT:LIMIT-cloud-connect-cloudflare-livefire — live Cloudflare API calls cannot run in CI, so the live-fire
leg of this fetcher (the exact minimal read-only permission groups, whether self-introspection needs
``User API Tokens Read``, and the precise ``policies``/``resources`` JSON shapes) is an honestly-registered residual
proven against a live customer token; the pure-protocol layer here (guard, parse, policy evaluation, verdict wiring)
is fully covered offline through the injectable ``transport`` seam.

FATAL-2: sovereign-side, stdlib only, ``assert_no_offense()`` at import; no framework/strix import.
"""
from __future__ import annotations

import hmac
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

from ..reuse import assert_no_offense, sha256_hex

assert_no_offense()

# Reuse the AWS fetcher's error type (so provision's ``except CloudFetchError`` catches us) and its redirect-blocker.
from .cloud_fetch import CloudFetchError, _NoRedirect  # noqa: E402

_CF_HOST = "api.cloudflare.com"                 # the only host this fetcher may reach (the allowlist pins it)
_CF_API_BASE = f"https://{_CF_HOST}/client/v4"
_CF_VERIFY_URL = f"{_CF_API_BASE}/user/tokens/verify"
_USER_AGENT = "VIGIL-cloud-connect"             # a generic, non-identifying client name (never a person/org)
_DEFAULT_TIMEOUT_S = 5.0                        # per blocking socket op of a Cloudflare call (connect, read)
_MAX_RESPONSE_BYTES = 256 * 1024               # a token-definition answer is a few KB; bounded well above it

_CF_TOKEN_NAME_PREFIX = "vigil-verify-"         # the name the customer's token must carry (the challenge binding)
# A Cloudflare account id / token id: exactly 32 lowercase hex.
_CF_ACCOUNT_ID_RE = re.compile(r"[0-9a-f]{32}")
_CF_TOKEN_ID_RE = re.compile(r"[0-9a-f]{32}")
# A Cloudflare API token is ~40 chars of [A-Za-z0-9_-]; accept a bounded URL/header-safe charset (no CR/LF/space/colon
# → no header injection), a conservative length window.
_CF_TOKEN_RE = re.compile(r"[A-Za-z0-9_.~-]{20,160}")
# The external ids VIGIL issues are URL-safe base64 (secrets.token_urlsafe); the control id is the same shape.
_EXTERNAL_ID_RE = re.compile(r"[A-Za-z0-9+=,.@:/_-]{2,1224}")

# Cloudflare resource-key prefixes. An account-scoped resource names the account; a user-scoped resource is the
# token's own self-introspection scope (``User API Tokens Read``) and does NOT broaden the account reach.
_CF_ACCOUNT_RES = "com.cloudflare.api.account."
_CF_USER_RES = "com.cloudflare.api.user."

# Read-only permission-group detection (fail-closed). A group is read-only iff its name carries a read indicator AND
# carries no write/edit/admin indicator. An unknown/odd group name (neither) is treated as NOT read-only → refused.
_CF_WRITE_WORDS = ("write", "edit", "admin", "manage", "delete", "create", "update", "revoke", "purge",
                   "configure", "change", "owner", "send", "publish", "deploy")
_CF_READ_WORDS = ("read", "list", "analytics", "view", "report", "monitor")


def _ct_eq(a: str, b: str) -> bool:
    """Constant-time equality over UTF-8 bytes (never raises on non-ASCII, unlike compare_digest on a str)."""
    return hmac.compare_digest(str(a or "").encode("utf-8"), str(b or "").encode("utf-8"))


# ---------------------------------------------------------------------------------------------------------------
# The guarded egress (mirrors ui.cloud_fetch: guard -> redirect-blocking open -> bounded read)
# ---------------------------------------------------------------------------------------------------------------

_OPENER = urllib.request.build_opener(_NoRedirect)


def _do_open(req, timeout):
    """The single outbound open point (redirects blocked) — also the seam the tests patch to stand in a fake API."""
    return _OPENER.open(req, timeout=timeout)   # noqa: S310 — https + host pinned by _guard; redirects blocked


def _allowlist() -> frozenset:
    """The Cloudflare egress host allowlist, read from ``config`` at call time. Empty ⇒ every host refused."""
    from .. import config
    return frozenset(h.lower() for h in config.CLOUDFLARE_API_EGRESS_ALLOWLIST)


def _guard(url: str) -> None:
    """Refuse a non-https scheme, userinfo, a non-default port, or an off-allowlist host BEFORE any socket opens."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise CloudFetchError("the cloud check could not be made", detail=f"non-https Cloudflare URL {parts.scheme!r}")
    if "@" in (parts.netloc or ""):
        raise CloudFetchError("the cloud check could not be made", detail="Cloudflare URL carries userinfo")
    try:
        port = parts.port
    except ValueError:
        raise CloudFetchError("the cloud check could not be made", detail="malformed Cloudflare port") from None
    if port not in (None, 443):
        raise CloudFetchError("the cloud check could not be made", detail="non-default Cloudflare port")
    host = (parts.hostname or "").lower()
    if host not in _allowlist():
        raise CloudFetchError("the cloud check could not be made", detail=f"non-allowlisted Cloudflare host {host!r}")


def _get(url: str, headers: Mapping[str, str], timeout: float) -> "tuple[int, bytes]":
    """One guarded GET: ``(status, body)``, the body bounded. An HTTP error status is RETURNED (its Cloudflare error
    document tells an invalid token from a fault); only a transport failure raises. The token rides in ``headers``
    (never in ``url``); no part of ``headers`` is ever echoed into an error."""
    _guard(url)
    req = urllib.request.Request(url, method="GET", headers=dict(headers))
    try:
        with _do_open(req, timeout) as r:
            raw = r.read(_MAX_RESPONSE_BYTES + 1)
            status = int(getattr(r, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(_MAX_RESPONSE_BYTES + 1) or b""
        except Exception:  # noqa: BLE001 — an unreadable error body is an empty one
            raw = b""
        status = int(exc.code) if isinstance(exc.code, int) else 0
    except Exception as exc:  # noqa: BLE001 — any transport fault fails closed; only the exception TYPE (never its
        #                       message, which must never risk echoing a header) rides in the audit detail
        raise CloudFetchError("Cloudflare could not be reached to make the cloud check; try again shortly",
                              detail=type(exc).__name__) from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise CloudFetchError("the cloud check could not be made", detail="Cloudflare response exceeded the size cap")
    return status, raw


def _json(raw: bytes) -> Optional[dict]:
    """Parse a Cloudflare JSON answer into a dict, or None on any fault / non-object. Bounded."""
    if len(raw) > _MAX_RESPONSE_BYTES:
        return None
    try:
        doc = json.loads(bytes(raw or b"").decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _cf_error_codes(doc: Optional[dict]) -> str:
    """The Cloudflare error CODES from an answer (e.g. ``1000,9109``) for the operator audit — never a message, never
    an echo of input. Empty on anything unexpected."""
    try:
        errs = doc.get("errors") if isinstance(doc, dict) else None
        codes = [str(e.get("code")) for e in (errs or []) if isinstance(e, dict) and e.get("code") is not None]
        return ",".join(codes[:5])
    except Exception:  # noqa: BLE001 — audit detail is best-effort, never the failure
        return ""


def _is_read_only_group(name: str) -> bool:
    """A permission group is READ-ONLY iff its name carries a read indicator and NO write/edit/admin indicator.
    Fail-closed: an unknown/odd name (neither indicator) is NOT read-only."""
    n = " ".join(str(name or "").lower().split())
    if not n or any(w in n for w in _CF_WRITE_WORDS):
        return False
    return any(w in n for w in _CF_READ_WORDS)


def _evaluate_policies(policies: list) -> "tuple[bool, bool, str]":
    """Reduce a token's ``policies`` to ``(read_only, single_account, scoped_account)``. FAIL-CLOSED: any unexpected
    shape, any broadening resource (``*``, all-accounts, or a non-account/non-user resource), or any non-read-only
    permission group narrows the proof. Only ``allow`` policies grant; ``deny``/other policies are ignored."""
    accounts: set[str] = set()
    broad = False
    writeish = False
    for pol in policies:
        if not isinstance(pol, dict):
            broad = True
            continue
        if str(pol.get("effect") or "") != "allow":
            continue
        resources = pol.get("resources")
        if not isinstance(resources, dict) or not resources:
            broad = True
            continue
        for key in resources:
            k = str(key)
            if k == "*":
                broad = True
            elif k.startswith(_CF_ACCOUNT_RES):
                acct = k[len(_CF_ACCOUNT_RES):].split(".", 1)[0]
                if _CF_ACCOUNT_ID_RE.fullmatch(acct):
                    accounts.add(acct)
                else:                                   # "*" (all accounts) or any non-32-hex remainder → broad
                    broad = True
            elif k.startswith(_CF_USER_RES):
                continue                                # the token's own self-introspection scope; not an account
            else:
                broad = True                            # zone-global / organization / unknown resource → fail closed
        for g in (pol.get("permission_groups") or []):
            name = str(g.get("name") or "") if isinstance(g, dict) else ""
            if not _is_read_only_group(name):
                writeish = True
    single_account = (not broad) and len(accounts) == 1
    scoped_account = next(iter(accounts)) if len(accounts) == 1 else ""
    return (not writeish), single_account, scoped_account


class CloudflareTokenConnectFetcher:
    """Observe a Cloudflare read-only, single-account API token under the token itself (see the module docstring).
    VIGIL holds NO Cloudflare credential of its own — the customer's token is the only secret and it arrives per
    ``assume`` call, is used for the two verify reads, and is then dropped (NEVER stored/logged/returned).

    ``transport`` is an injectable ``(url, headers, body, timeout) -> (status, body)`` for offline tests (a fake
    Cloudflare API that still goes through the guard); ``clock`` is accepted for interface symmetry with the AWS
    fetcher (this fetcher signs nothing)."""

    def __init__(self, *, timeout: float = _DEFAULT_TIMEOUT_S,
                 transport: "Optional[Callable[[str, Mapping[str, str], bytes, float], tuple[int, bytes]]]" = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._timeout = float(timeout)
        self._transport = transport
        self._clock = clock

    def __repr__(self) -> str:                    # the fetcher holds no stored secret; nothing to redact
        return "CloudflareTokenConnectFetcher()"

    def _call(self, url: str, token: str) -> "tuple[int, Optional[dict]]":
        headers = {"Authorization": f"Bearer {token}", "User-Agent": _USER_AGENT, "Accept": "application/json"}
        if self._transport is not None:
            _guard(url)                            # a fake API still exercises the egress pin
            try:
                status, raw = self._transport(url, headers, b"", self._timeout)
            except CloudFetchError:
                raise
            except Exception as exc:  # noqa: BLE001 — a transport fault fails closed (type only, never the message)
                raise CloudFetchError("Cloudflare could not be reached to make the cloud check; try again shortly",
                                      detail=type(exc).__name__) from None
        else:
            status, raw = _get(url, headers, self._timeout)
        return int(status), _json(bytes(raw or b""))

    def _verify(self, token: str) -> "tuple[str, str]":
        """``GET /user/tokens/verify`` → ``(token_id, status)``. A 401 / ``success:false`` → the token is wrong or
        expired (the customer's fix); any other status / 5xx / transport fault is INCONCLUSIVE → raise (fail closed,
        never a pass)."""
        status, doc = self._call(_CF_VERIFY_URL, token)
        if status == 200 and isinstance(doc, dict) and doc.get("success") is True:
            raw_result = doc.get("result")
            result = raw_result if isinstance(raw_result, dict) else {}
            tid, st = str(result.get("id") or ""), str(result.get("status") or "")
            if not _CF_TOKEN_ID_RE.fullmatch(tid):
                raise CloudFetchError("the cloud check could not be made", detail="verify answer carried no token id")
            return tid, st
        if status in (400, 401, 403) and isinstance(doc, dict) and doc.get("success") is False:
            raise CloudFetchError("the Cloudflare API token was rejected — it may be wrong or expired; create a fresh "
                                  "read-only token as shown and try again",
                                  detail=f"verify HTTP {status} cf={_cf_error_codes(doc)}")
        raise CloudFetchError("Cloudflare could not be reached to make the cloud check; try again shortly",
                              detail=f"verify HTTP {status}")

    def _token_scope(self, token: str, token_id: str) -> "tuple[str, bool, bool, str]":
        """``GET /user/tokens/{id}`` → ``(name, read_only, single_account, scoped_account)``. A token that cannot read
        its OWN definition (any non-200 / ``success`` not true) fails CLOSED — VIGIL never over-accepts a token whose
        scope it could not read."""
        status, doc = self._call(f"{_CF_API_BASE}/user/tokens/{token_id}", token)
        if not (status == 200 and isinstance(doc, dict) and doc.get("success") is True):
            raise CloudFetchError("VIGIL could not read the token's own definition to confirm it is read-only and "
                                  "scoped to one account — include the read-only 'User API Tokens Read' permission "
                                  "shown on the connect screen, then try again",
                                  detail=f"token-detail HTTP {status} cf={_cf_error_codes(doc)}")
        assert isinstance(doc, dict)                    # narrowed by the guard above (no-op at runtime; for mypy)
        raw_result = doc.get("result")
        result = raw_result if isinstance(raw_result, dict) else {}
        name = str(result.get("name") or "")
        policies = result.get("policies")
        if not isinstance(policies, list):
            raise CloudFetchError("the cloud check could not be made", detail="token definition carried no policies")
        read_only, single_account, scoped_account = _evaluate_policies(policies)
        return name, read_only, single_account, scoped_account

    def assume(self, *, provider: str, account_id: str, role_ref: str, external_id: str, control_external_id: str,
               now: Any = None) -> dict:
        """Observe the Cloudflare token (module docstring): ``{token_id, account, name_matched, external_id,
        read_only, single_account}``. Raises ``CloudFetchError`` (fail closed) on a malformed input, a rejected /
        inactive token, a token whose definition cannot be read, or any inconclusive answer. ``role_ref`` carries the
        SECRET token (the ``role_ref``-equivalent for Cloudflare) — it is used for the two reads and then dropped;
        it is NEVER logged, returned, stored, or placed in an error detail. ``now`` is accepted for interface
        symmetry with the other fetchers."""
        if str(provider or "") != "cloudflare":
            raise CloudFetchError("only Cloudflare accounts can be connected", detail=f"provider {provider!r}")
        acct = str(account_id or "").strip()
        if not _CF_ACCOUNT_ID_RE.fullmatch(acct):
            raise CloudFetchError("give the Cloudflare account id (32 hex characters) you are connecting")
        ext, ctl = str(external_id or ""), str(control_external_id or "")
        if not _EXTERNAL_ID_RE.fullmatch(ext) or not _EXTERNAL_ID_RE.fullmatch(ctl) or hmac.compare_digest(ext, ctl):
            raise CloudFetchError("the cloud check could not be made", detail="bad external id / control id")
        token = str(role_ref or "").strip()
        if not _CF_TOKEN_RE.fullmatch(token):
            raise CloudFetchError("paste the read-only Cloudflare API token you created (it looks empty or malformed)")
        try:
            token_id, status = self._verify(token)
            if status != "active":
                raise CloudFetchError("the Cloudflare API token is not active — create a fresh read-only token and "
                                      "try again", detail=f"token status {status!r}")
            name, read_only, single_account, scoped_account = self._token_scope(token, token_id)
            tok_sha = sha256_hex(token.encode("utf-8"))   # hash the EXACT bytes verified above (log-safe; never stored)
        finally:
            # Drop the token reference as early as possible. NOTE: a Python ``str`` is immutable, so this cannot
            # truly zero the bytes in memory — the caller likewise never stores it, and it is dropped here so it is
            # not held past the two reads. (The immutable-str caveat is the honest limit of in-process zeroing.)
            token = ""  # noqa: F841 — deliberate: shed the reference, do not use it again
            del token
        name_matched = _ct_eq(name, f"{_CF_TOKEN_NAME_PREFIX}{ext}")
        return {"token_id": token_id, "account": scoped_account, "name_matched": name_matched,
                "external_id": ext, "read_only": bool(read_only), "single_account": bool(single_account),
                "token_sha256": tok_sha}
