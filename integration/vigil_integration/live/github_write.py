"""github_write — the GATED review-COMMENT write-back (repo-connect Slice 3b), OFF BY DEFAULT.

The FIRST GitHub WRITE capability: post a PR review comment carrying an oracle-verified finding. It is the
narrow, reversible write — SEPARATE from the higher-risk fix-PR capability (Slice 3c, m-of-n-gated). Every post
must clear the full authorization chain, FAIL-CLOSED at each step, BEFORE a byte leaves for api.github.com:

  1. ``comment_enabled`` is OFF by default — a write happens ONLY when the owner explicitly enables it.
  2. an owner-signed, repo-EXACT ``GitWriteGrant`` authorizes the ``"comment"`` capability for THIS repo
     (``authority.gate.authorize_repo_write``, Slice 3-authz-A) — no grant / wrong repo / revoked / expired /
     out-of-window ⇒ refuse.
  3. a per-action WARDEN A2 owner approval authorizes THIS specific comment (``github_comment`` →
     ``default_classify`` A2 → the single-use owner-signed approval broker) — no valid owner token ⇒ refuse.
  4. the POST rides the SAME gated, host-pinned ``api.github.com`` transport the read client uses, token
     off-spine (``GITHUB_TOKEN`` / config, ``repr=False``), ``follow_redirects=False``, ``trust_env=False``.
  5. a cryptographically-signed audit record is emitted for the write; if the audit sink raises, the whole
     call RAISES — a write is never silently left un-audited.

These are the write-capability mandate's controls (1) comment/PR separation, (3) off-by-default, (4) WARDEN
-before-write, and (7) signed audit records. The m-of-n destruction quorum is NOT required for a comment (a
reversible write); it gates the fix-PR path in Slice 3c.

FATAL-2: httpx + framework are imported LAZILY, so this module is import-clean in either venv and is
constructed only by the OFFENSE worker. The signed-audit sink is ``vigil_core``-only (sovereign-safe).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .github_client import GitHubReadError, _owner_repo   # REUSE the one REST-traversal guard (no drift)

_API_BASE = "https://api.github.com"
_API_VERSION = "2022-11-28"
_USER_AGENT = "OBSIDIAN-VIGIL/1.0 (authorized owner-test)"
#: Domain-separates the signed git-write audit record from every other vigil_core-signed artifact.
_AUDIT_DOMAIN = b"vigil-git-write-audit-v1\x00"

# An (owner-approval) callable: (tool_name, target, args) -> approved? — the single-use owner-signed broker
# leg (``broker_comment_approver``) or, in tests, a double. A write NEVER proceeds on a falsy/absent approver.
Approver = Callable[[str, str, Any], bool]
# A signed-audit sink: (record: dict) -> None — appends a cryptographically-signed audit line. MUST raise on
# any failure so an un-audited write is impossible (``post_review_comment`` re-raises).
AuditSink = Callable[[dict], None]


class GitHubWriteError(RuntimeError):
    """A refused or failed GitHub write. Raised (fail-closed): a refused authorization, a non-201 POST, or an
    audit-sink failure. Never swallowed — the caller records the refusal and does not proceed."""


@dataclass
class GitHubCommentConfig:
    """Review-comment write config. ``comment_enabled`` is OFF by default (a write needs an explicit opt-in).
    The token is OFF-SPINE (``repr=False``), from here or ``GITHUB_TOKEN``; an empty token FAILS CLOSED."""

    slug: str = ""
    github_token: str = field(default="", repr=False)
    api_base: str = _API_BASE
    timeout_s: float = 30.0
    comment_enabled: bool = False    # OFF BY DEFAULT — control (3): activate only with explicit owner opt-in


class GitHubWriteClient:
    """The gated POST mechanism for a PR review comment. Mirrors the read client's gated transport (lazy httpx
    + ``SovereignHttpxTransport`` single-apex ``api.github.com`` allowlist + host-pin + token off-spine); only
    the verb (POST) + endpoint differ. Authorization is enforced by :func:`post_review_comment`, NOT here —
    this class is the raw transport and never decides whether a write is allowed."""

    def __init__(self, config: GitHubCommentConfig, *, http: Any = None) -> None:
        self.config = config
        self._http = http   # injected httpx-like double (tests); None ⇒ lazily built + gated

    def _token(self) -> str:
        return (self.config.github_token or os.environ.get("GITHUB_TOKEN", "")).strip()

    def _headers(self) -> dict:
        token = self._token()
        if not token:   # FAIL CLOSED — never make an unauthenticated write
            raise GitHubWriteError("no GitHub token configured (set GITHUB_TOKEN or GitHubCommentConfig.github_token)")
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": _USER_AGENT,
        }

    def _client(self) -> Any:
        if self._http is None:
            import httpx   # lazy (offense dep)
            # lazy (FATAL-2: never import framework at module scope in an integration module)
            from framework.v2.agents.egress_guard import SovereignHttpxTransport, build_engagement_allowlist
            allowlist = build_engagement_allowlist(slug=self.config.slug, collector_hosts=("api.github.com",))
            transport = SovereignHttpxTransport(allowlist, slug=self.config.slug, sovereign_only=False)
            self._http = httpx.Client(transport=transport, follow_redirects=False, trust_env=False,
                                      timeout=self.config.timeout_s)
        return self._http

    def post_issue_comment(self, repo: str, pr_number: int, body: str) -> dict:
        """POST one PR review comment (the GitHub *issue-comment* endpoint, which PRs share). HOST-PINNED to
        api.github.com; the repo is validated to EXACTLY ``owner/repo`` (``_owner_repo`` — no REST-path
        traversal). Returns ``{"id", "html_url"}`` on HTTP 201; any other status raises GitHubWriteError."""
        try:
            owner_repo = _owner_repo(repo)   # reused traversal guard
        except GitHubReadError as e:         # normalize to THIS module's documented write-error type
            raise GitHubWriteError(f"refusing a comment to an unsafe repo identity {repo!r}: {e}") from e
        path = f"/repos/{owner_repo}/issues/{int(pr_number)}/comments"
        url = self.config.api_base.rstrip("/") + path
        if not url.startswith("https://api.github.com/"):   # HOST-PIN: writes ONLY ever reach api.github.com
            raise GitHubWriteError(f"refusing a non-api.github.com URL: {url!r}")
        resp = self._client().post(url, headers=self._headers(), json={"body": str(body)})
        status = getattr(resp, "status_code", 0)
        if status != 201:   # GitHub returns 201 Created for a new comment
            raise GitHubWriteError(f"POST {path} returned HTTP {status} (expected 201)")
        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001 — a malformed body is a write error, not a crash
            raise GitHubWriteError(f"POST {path} body is not JSON: {type(exc).__name__}") from exc
        if not isinstance(data, dict):
            return {"id": None, "html_url": None}
        return {"id": data.get("id"), "html_url": data.get("html_url")}

    def close(self) -> None:
        http = self._http
        if http is not None and hasattr(http, "close"):
            try:
                http.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass


def post_review_comment(
    *,
    slug: str,
    trust_root: Any,
    repo: str,
    pr_number: int,
    body: str,
    config: GitHubCommentConfig,
    approve: Approver,
    audit: AuditSink,
    http: Any = None,
    now: Any = None,
    grant_path: Any = None,
    epoch_path: Any = None,
) -> dict:
    """Post a PR review comment ONLY if the full fail-closed authorization chain clears, then emit a signed
    audit record. The ONLY sanctioned way to post a comment — the raw :class:`GitHubWriteClient` is never
    called directly by a worker. Each step refuses (raises GitHubWriteError) rather than proceeding:

      1. ``config.comment_enabled`` is True (OFF by default);
      2. an owner-signed repo-EXACT GitWriteGrant authorizes ``"comment"`` for ``repo``
         (``authorize_repo_write`` over ``load_verified_git_write_grant`` — Slice 3-authz-A);
      3. ``approve("github_comment", target, {...})`` returns True (per-action WARDEN A2 owner approval);
      4. the POST succeeds (gated transport, host-pinned, token off-spine);
      5. ``audit(record)`` records a signed audit line — if it raises, THIS call raises (no un-audited write).

    ``now`` is a TRUSTED-caller value for the grant window (datetime/None → real clock); never request data.
    ``grant_path`` / ``epoch_path`` are optional TRUSTED-caller overrides for the signed-grant + epoch-floor
    locations (None → the framework's default per-engagement paths), mirroring ``load_verified_git_write_grant``.
    Returns the ``{"id", "html_url"}`` of the posted comment."""
    # 1. OFF BY DEFAULT — control (3).
    if not getattr(config, "comment_enabled", False):
        raise GitHubWriteError("github comment write is OFF by default (comment_enabled=False) — refusing")

    # Coerce `body` to a string ONCE, so the owner-APPROVED body, the POSTED body, and the AUDITED body are the
    # SAME bytes — a non-idempotent __str__ (adversarial, or a lazy finding-renderer stamping a timestamp /
    # counter) must never make them diverge (red-pen MEDIUM: approval-binding + audit-faithfulness).
    body = str(body)

    # 2. repo-EXACT git-write grant for the "comment" capability — control (1)+(2), Slice 3-authz-A. Lazy
    #    (framework, offense-side). load_verified_git_write_grant verifies the owner signature + epoch-replay
    #    floor and returns None when unprovisioned; authorize_repo_write denies None/revoked/out-of-window/
    #    wrong-repo/not-"comment" — so an unauthorized write never reaches the approval step. A verification
    #    failure (tampered / replayed / unsigned grant) raises AuthorityError, normalized here to the documented
    #    GitHubWriteError (still fail-closed, no POST) so a caller catches ONE refusal type (red-pen LOW).
    from framework.v2.authority.gate import authorize_repo_write
    from framework.v2.authority.store import AuthorityError, load_verified_git_write_grant

    try:
        grant = load_verified_git_write_grant(slug, trust_root, path=grant_path, epoch_path=epoch_path)
    except (AuthorityError, AttributeError, TypeError) as e:
        # AuthorityError = tampered/replayed/unsigned grant; AttributeError/TypeError = a None / non-TrustRoot
        # trust_root — both fail-closed, normalized to the documented GitHubWriteError (red-pen LOW, shared with 3c).
        raise GitHubWriteError(f"git-write grant for {slug!r} failed verification — refusing: {e}") from e
    if not authorize_repo_write(grant, repo, "comment", now=now):
        raise GitHubWriteError(
            f"no owner-signed git-write grant authorizes a COMMENT on {repo!r} for engagement {slug!r} — refusing")

    # 3. per-action WARDEN A2 owner approval for THIS comment — control (4). github_comment classifies A2
    #    (default_classify: no danger token) ⇒ QUEUE ⇒ the single-use owner-signed approval broker. The write
    #    ALWAYS requires an owner approval (>= the A2 posture); a falsy/absent approver refuses. _owner_repo can
    #    raise GitHubReadError on a weird (owner-signed-but-unsafe) repo — normalized to GitHubWriteError.
    try:
        target = f"github:comment:{_owner_repo(repo)}#{int(pr_number)}"
    except GitHubReadError as e:
        raise GitHubWriteError(f"refusing a comment to an unsafe repo identity {repo!r}: {e}") from e
    if not callable(approve) or not approve("github_comment", target, {"body": body}):
        raise GitHubWriteError(f"no owner approval for the comment on {target} — refusing (WARDEN A2 owner-approval)")

    # 4. POST (gated, host-pinned, token off-spine).
    client = GitHubWriteClient(config, http=http)
    result = client.post_issue_comment(repo, pr_number, body)

    # 5. signed audit record for the write — control (7). Fail-closed: if the sink raises, the whole call
    #    raises so a posted-but-un-audited write is surfaced loudly (never swallowed).
    record = {
        "action": "github_comment",
        "slug": slug,
        "repo": _owner_repo(repo),
        "pr_number": int(pr_number),
        "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),   # body already coerced once, above
        "comment_id": result.get("id"),
        "comment_url": result.get("html_url"),
    }
    if not callable(audit):
        raise GitHubWriteError("no audit sink supplied — refusing to leave a write un-audited (control 7)")
    audit(record)
    return result


def signed_comment_audit_sink(path: Any, *, key_id: str, private_key_b64: str) -> AuditSink:
    """A signed :data:`AuditSink`: Ed25519-sign the canonical, domain-tagged audit record and append it as ONE
    JSONL line ``{"record", "key_id", "sig"}``. Genuinely tamper-evident (``vigil_core.crypto.sign`` over
    ``canonical_json`` under a distinct domain) and ``vigil_core``-only, so it is sovereign-safe and verifiable
    offline. The worker binds the engagement's governance key here. Any failure propagates (control 7)."""
    from vigil_core.canonical import canonical_json
    from vigil_core.crypto import sign

    p = Path(path)

    def _sink(record: dict) -> None:
        # Bind key_id INTO the signed pre-image (like approval_token) so relabeling the signer id invalidates
        # the signature — not only tampering the record content (red-pen LOW). On-disk JSONL shape is unchanged.
        signed_obj = {"key_id": str(key_id), "record": record}
        sig = sign(private_key_b64, _AUDIT_DOMAIN + canonical_json(signed_obj))
        line = json.dumps({"record": record, "key_id": str(key_id), "sig": sig},
                          separators=(",", ":"), sort_keys=True)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    return _sink


def broker_comment_approver(base_dir: Any) -> Optional[Approver]:
    """The production :data:`Approver`: bind the comment action, publish a pending request, (bounded) wait for
    the owner-signed single-use token, verify it against the deployment-pinned owner key, and spend its nonce
    ONCE. Returns None when no approval authority is provisioned ⇒ the caller refuses (fail-safe). Mirrors
    ``warden_gate._build_strix_approver``; verification uses the PUBLIC key only; imports are offense-side."""
    try:
        import time

        from .approval_broker import ApprovalBroker, approvals_root, load_authority
        from .approval_token import ApprovalAction, action_digest, consume_token
        from .nonce_ledger import NonceLedger
    except Exception:  # noqa: BLE001 — integration/SDK not importable ⇒ no approver ⇒ hard-refuse (safe)
        return None
    authority = load_authority(base_dir)
    if authority is None:
        return None
    _approvals_root = approvals_root(base_dir)
    ledger = NonceLedger(Path(base_dir) / "approval-nonces")

    def approve(tool_name: str, target: str, args: Any) -> bool:
        try:
            act = ApprovalAction(tool_name, target, action_digest(tool_name, target, args))
        except Exception:  # noqa: BLE001 — a non-serialisable action can't be bound ⇒ deny (fail-closed)
            return False
        broker = ApprovalBroker(_approvals_root)   # per-call broker (concurrent writes don't clobber)
        broker.bind(act, args_preview=args)
        pend = broker.token_source()   # publish pending + (bounded) poll for a signed token
        if not (isinstance(pend, tuple) and len(pend) == 2):
            return False
        token, action = pend
        return bool(consume_token(token, action, authority=authority, now=time.time(), ledger=ledger).authorized)

    return approve


__all__ = [
    "GitHubWriteError",
    "GitHubCommentConfig",
    "GitHubWriteClient",
    "post_review_comment",
    "signed_comment_audit_sink",
    "broker_comment_approver",
]
