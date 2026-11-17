"""The customer-facing GitHub App — SOVEREIGN auth for Red-Pen (R2), SHIPPED OFF BY DEFAULT.

This module mints the credentials VIGIL needs to review a connected repository's pull requests, and it does so
ENTIRELY sovereign-side (Red-Pen decision O-5): the App PRIVATE KEY is a NEW sovereign-only secret (Stripe-key
discipline — read at call time from the environment or AWS SSM, never on the offense plane, never logged, repr
hidden). It:

  * signs a short-lived App JWT (RS256, iss = App id, <10-minute window) with the App private key;
  * exchanges it for a SHORT-LIVED per-installation ACCESS TOKEN
    (``POST /app/installations/{id}/access_tokens``) — :func:`mint_installation_token` is the documented accessor
    R3's nonce-bound 0600 broker seam calls; THIS slice mints it sovereign-side and hands R3 nothing more;
  * lists an installation's repositories (``GET /installation/repositories``);
  * writes the "VIGIL Red-Pen" CHECK RUN (``POST/PATCH /repos/{owner}/{repo}/check-runs``) — written
    SOVEREIGN-side from an inert review outcome (only reproduced-FACT severities ever cross; LEADs never leave the
    dashboard).

The App private key NEVER reaches the offense plane: only a per-repo-scoped installation token does (R3's broker),
never the App key. Every call is gated DEFAULT-OFF behind the master flag ``config.redpen_enabled()`` AND the App
credentials (``VIGIL_GITHUB_APP_ID`` + ``VIGIL_GITHUB_APP_PRIVATE_KEY`` / its SSM ref): unset ⇒ nothing is wired and
no GitHub egress exists, so the server is byte-identical to a build without Red-Pen.

Crypto uses the vendored ``cryptography`` library (a sovereign dep; same one ``ui/oidc.py`` uses), NOT a hand-rolled
JWT signer. Imports are stdlib + ``cryptography`` + ``vigil_core`` + ``sigil`` sovereign siblings — no
``framework`` / ``strix`` (FATAL-2 clean)."""
from __future__ import annotations

import base64
import json
import os
import re
import time
from typing import Any, Mapping, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import github_app_egress as _egress  # noqa: E402

_APP_ID_ENV = "VIGIL_GITHUB_APP_ID"
_PRIVATE_KEY_ENV = "VIGIL_GITHUB_APP_PRIVATE_KEY"            # the PEM inline
_PRIVATE_KEY_SSM_ENV = "VIGIL_GITHUB_APP_PRIVATE_KEY_SSM"    # or an AWS SSM SecureString parameter name
_REGION_ENV = "VIGIL_AWS_REGION"
_WEBHOOK_SECRET_ENV = "VIGIL_GH_WEBHOOK_SECRET"             # the shared repo-connect webhook HMAC secret (R3's route)

# An App id is a short positive integer (GitHub assigns it). A numeric App id can never smuggle a path segment.
_APP_ID_RE = re.compile(r"[1-9][0-9]{0,18}")
# The App JWT must sit inside GitHub's 10-minute ceiling; we use a conservative 9 minutes and backdate iat 60s to
# tolerate minor clock skew between this host and GitHub (GitHub's own recommendation).
_JWT_LIFETIME_S = 9 * 60
_JWT_BACKDATE_S = 60
# The default merge-blocking check name the owner registered the App's ``checks:write`` for (decision §12).
CHECK_RUN_NAME = "VIGIL Red-Pen"
_MAX_INSTALLATION_ID = 10 ** 12   # a sane upper bound on a GitHub installation id (defence-in-depth path bound)


class GitHubAppError(RuntimeError):
    """A fail-closed Red-Pen GitHub-App refusal (flag off, a missing/malformed credential, an unusable key, or an
    egress failure surfaced up). The message NEVER contains the App private key or a minted token."""


class _Secret:
    """A repr-hidden holder for the App private-key PEM, so the key can never land in a log line, a traceback
    frame-locals dump or a ``repr()`` by accident. Read at call time, used only to sign, never persisted."""

    __slots__ = ("_pem",)

    def __init__(self, pem: str) -> None:
        self._pem = pem

    def reveal(self) -> str:
        return self._pem

    def __repr__(self) -> str:
        return "<redacted GitHub App private key>"

    __str__ = __repr__


# ---------------------------------------------------------------------------------------------------
# Credentials — read at CALL TIME (never cached, never persisted, never printed). Presence-only gates.
# ---------------------------------------------------------------------------------------------------

def _app_id(env: "Optional[Mapping[str, str]]" = None) -> str:
    e = os.environ if env is None else env
    raw = (e.get(_APP_ID_ENV) or "").strip()
    if not _APP_ID_RE.fullmatch(raw):
        raise GitHubAppError(f"{_APP_ID_ENV} is unset or not a positive integer App id (fail-closed)")
    return raw


def _private_key(env: "Optional[Mapping[str, str]]" = None, *, runner=None) -> _Secret:
    """The App private key PEM, from ``VIGIL_GITHUB_APP_PRIVATE_KEY`` or, when ``VIGIL_GITHUB_APP_PRIVATE_KEY_SSM``
    is set, from that AWS SSM SecureString (SSM is then the ONLY source — an inline value is ignored, mirroring
    ``provider_key``). Read at call time; wrapped repr-hidden. Any failure is a fail-closed ``GitHubAppError``
    whose message names the source, never the key."""
    e = os.environ if env is None else env
    ssm = (e.get(_PRIVATE_KEY_SSM_ENV) or "").strip()
    if ssm:
        from vigil_core.aws_ssm import SsmParameterError, read_secure_string
        region = (e.get(_REGION_ENV) or "").strip()
        try:
            return _Secret(read_secure_string(region, ssm, runner=runner))
        except SsmParameterError as exc:        # names the parameter only, never the CLI output
            raise GitHubAppError(f"the GitHub App private key ({_PRIVATE_KEY_SSM_ENV}): {exc}") from None
    pem = (e.get(_PRIVATE_KEY_ENV) or "").strip()
    if not pem:
        raise GitHubAppError(f"the GitHub App needs its private key ({_PRIVATE_KEY_ENV} or "
                             f"{_PRIVATE_KEY_SSM_ENV})")
    return _Secret(pem)


def credential_source(env: "Optional[Mapping[str, str]]" = None) -> str:
    """Where the App key comes from — ``"ssm"``, ``"env"``, or ``""`` (no key configured). Never the value."""
    e = os.environ if env is None else env
    if (e.get(_PRIVATE_KEY_SSM_ENV) or "").strip():
        return "ssm"
    return "env" if (e.get(_PRIVATE_KEY_ENV) or "").strip() else ""


def github_app_configured(env: "Optional[Mapping[str, str]]" = None) -> bool:
    """True iff BOTH the App id and a private-key source are present: the DEFAULT-OFF credential gate (mirrors
    ``stripe_egress.stripe_secret_configured``). A presence check only; the values are read afresh at each call.
    Independent of the master flag — ``vigil doctor`` uses both to report "key present iff Red-Pen on"."""
    e = os.environ if env is None else env
    return bool((e.get(_APP_ID_ENV) or "").strip()) and bool(credential_source(e))


def webhook_secret_configured(env: "Optional[Mapping[str, str]]" = None) -> bool:
    """True iff the repo-connect webhook HMAC secret is set (presence only; the value is never read here)."""
    e = os.environ if env is None else env
    return bool((e.get(_WEBHOOK_SECRET_ENV) or "").strip())


def _require_enabled() -> None:
    from .. import config
    if not config.redpen_enabled():
        raise GitHubAppError("Red-Pen is off (VIGIL_REDPEN_ENABLED): refusing any GitHub App call (fail-closed)")


# ---------------------------------------------------------------------------------------------------
# The App JWT (RS256) — signed with the App private key. iss = App id, <10-minute window.
# ---------------------------------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_rs256(signing_input: bytes, pem: str) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception as exc:  # noqa: BLE001 — any unreadable/encrypted/garbage PEM is a fail-closed refusal
        raise GitHubAppError(f"the GitHub App private key is not a readable unencrypted PEM "
                             f"({type(exc).__name__})") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubAppError("the GitHub App private key is not an RSA key (GitHub App JWTs are RS256)")
    return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def build_app_jwt(*, now: Optional[float] = None, env: "Optional[Mapping[str, str]]" = None, runner=None) -> str:
    """A signed App JWT for ``api.github.com`` App endpoints: header ``{alg:RS256, typ:JWT}``, claims
    ``{iat: now-60, exp: now+540, iss: App id}`` (inside GitHub's 10-minute ceiling, iat backdated 60 s for clock
    skew). The App private key is read at call time and discarded; it never leaves this process. Fail-closed
    ``GitHubAppError`` on a missing/unusable credential."""
    _require_enabled()
    t = int(time.time() if now is None else now)
    app_id = _app_id(env)
    secret = _private_key(env, runner=runner)
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iat": t - _JWT_BACKDATE_S, "exp": t + _JWT_LIFETIME_S, "iss": app_id}
    seg = _b64url(json.dumps(header, separators=(",", ":")).encode("ascii")) + "." + \
        _b64url(json.dumps(claims, separators=(",", ":")).encode("ascii"))
    try:
        sig = _sign_rs256(seg.encode("ascii"), secret.reveal())
    finally:
        del secret                              # drop the key holder as soon as the signature is made
    return seg + "." + _b64url(sig)


# ---------------------------------------------------------------------------------------------------
# The App endpoints (all sovereign-side; the egress transport is injectable for offline tests).
# ---------------------------------------------------------------------------------------------------

def _check_installation_id(installation_id: Any) -> int:
    try:
        iid = int(installation_id)
    except (TypeError, ValueError):
        raise GitHubAppError("installation id must be an integer") from None
    if not (1 <= iid <= _MAX_INSTALLATION_ID):
        raise GitHubAppError("installation id out of range")
    return iid


def mint_installation_token(installation_id: Any, *, now: Optional[float] = None,
                            env: "Optional[Mapping[str, str]]" = None, runner=None, transport=None) -> dict:
    """Exchange a fresh App JWT for a SHORT-LIVED installation access token
    (``POST /app/installations/{id}/access_tokens``). Returns GitHub's response ``{token, expires_at,
    permissions, repository_selection, ...}`` — the ``token`` is the per-installation bearer the Red-Pen worker
    presents (R3 scopes it per-repo and hands it to the offense plane over a nonce-bound 0600 seam; the App KEY
    never crosses). THE documented accessor R3 calls. Fail-closed on any refusal; the message carries no secret."""
    _require_enabled()
    iid = _check_installation_id(installation_id)
    jwt = build_app_jwt(now=now, env=env, runner=runner)
    try:
        resp = _egress.request("POST", f"/app/installations/{iid}/access_tokens", bearer=jwt, scheme="Bearer",
                               json_body={}, transport=transport)
    except _egress.GitHubEgressError as exc:
        raise GitHubAppError(f"could not mint an installation token for installation {iid}: {exc}") from None
    if not isinstance(resp, Mapping) or not isinstance(resp.get("token"), str) or not resp.get("token"):
        raise GitHubAppError("the installation-token exchange returned an unexpected object (no token)")
    return dict(resp)


def list_installation_repositories(installation_token: str, *, transport=None) -> dict:
    """``GET /installation/repositories`` with an installation token (NOT the App JWT): the repositories the
    installation can see (``{total_count, repositories:[{full_name, ...}]}``). The registry's connect flow uses it
    to confirm a repo a tenant asks to connect is actually in their installation before the owner signs the
    record. Fail-closed on any refusal."""
    _require_enabled()
    try:
        resp = _egress.request("GET", "/installation/repositories", bearer=_require_token(installation_token),
                               scheme="token", transport=transport)
    except _egress.GitHubEgressError as exc:
        raise GitHubAppError(f"could not list installation repositories: {exc}") from None
    if not isinstance(resp, Mapping):
        raise GitHubAppError("the installation-repositories list returned an unexpected object")
    return dict(resp)


def post_check_run(installation_token: str, repo: str, *, head_sha: str, status: str, conclusion: Optional[str] = None,
                   title: str = "", summary: str = "", name: str = CHECK_RUN_NAME, check_run_id: Optional[int] = None,
                   now: Optional[float] = None, transport=None) -> dict:
    """Create (``POST``) or update (``PATCH`` with ``check_run_id``) the "VIGIL Red-Pen" CHECK RUN on
    ``github.com/<owner>/<repo>`` at ``head_sha``. SOVEREIGN-side per O-5: the sovereign writes it from an inert
    review outcome (only reproduced-FACT severities decide ``conclusion``; a blocking review uses ``failure``).
    ``status`` ∈ {queued, in_progress, completed}; a completed run carries a ``conclusion`` (success | failure |
    neutral | ...). Fail-closed on a malformed repo / status / conclusion or any egress refusal."""
    _require_enabled()
    from vigil_core import check_connected_repo, repo_owner_name
    owner, repo_name = repo_owner_name(check_connected_repo(repo))
    sha = str(head_sha or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", sha):
        raise GitHubAppError("head_sha must be a hex commit sha")
    if status not in ("queued", "in_progress", "completed"):
        raise GitHubAppError("check-run status must be queued | in_progress | completed")
    body: "dict[str, Any]" = {"name": str(name), "head_sha": sha, "status": status}
    if status == "completed":
        if conclusion not in ("success", "failure", "neutral", "cancelled", "timed_out", "action_required",
                              "stale", "skipped"):
            raise GitHubAppError("a completed check run needs a valid conclusion")
        body["conclusion"] = conclusion
    if title or summary:
        body["output"] = {"title": str(title), "summary": str(summary)}
    path = f"/repos/{owner}/{repo_name}/check-runs"
    method = "POST"
    if check_run_id is not None:
        try:
            crid = int(check_run_id)
        except (TypeError, ValueError):
            raise GitHubAppError("check_run_id must be an integer") from None
        path, method = f"{path}/{crid}", "PATCH"
    try:
        resp = _egress.request(method, path, bearer=_require_token(installation_token), scheme="token",
                               json_body=body, transport=transport)
    except _egress.GitHubEgressError as exc:
        raise GitHubAppError(f"could not write the {name} check run on {repo}: {exc}") from None
    if not isinstance(resp, Mapping):
        raise GitHubAppError("the check-run write returned an unexpected object")
    return dict(resp)


def _require_token(installation_token: str) -> str:
    if not isinstance(installation_token, str) or not installation_token:
        raise GitHubAppError("an installation access token is required")
    return installation_token
