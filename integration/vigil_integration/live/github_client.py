"""github_client — a GATED, READ-ONLY api.github.com client (repo-connect Slice 3a).

The REAL reconciliation lister (replacing jobs.reconciliation.empty_lister): it lists a connected repo's
open PRs changed since a checkpoint and the changed files of a PR, so the safety-net poller can produce
diff-scoped SecurityJobs. READ-ONLY — only HTTP GET; it never posts a comment, opens a PR, or writes
anything (those are Slice 3b/3c, separately gated and OFF by default).

Egress is GATED + FATAL-2-safe:
  * The httpx client rides :class:`framework.v2.agents.egress_guard.SovereignHttpxTransport` with a
    single-apex allowlist ``collector_hosts=("api.github.com",)`` (a concrete apex — never a wildcard) and
    ``sovereign_only=False`` so the NAME allowlist is enforced in every mode; the never-liftable L3/L4 floor
    (loopback/RFC1918/metadata always denied) is inherited. This mirrors the MCP evidence connector.
  * httpx + framework are imported LAZILY inside the client build, so this module stays import-clean in
    either venv; it is constructed only by the OFFENSE worker and INJECTED into the Reconciler.
  * The token is OFF-SPINE: resolved from the config (``repr=False``) or ``GITHUB_TOKEN``, sent only as an
    ``Authorization: Bearer`` header, never logged, never on the spine. An empty token FAILS CLOSED.

Tests inject a fake HTTP double (``http=``), so the request/paging/cursor logic is exercised without any
network or framework; the gated transport itself is the evidence connector's already-tested wiring.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..jobs.reconciliation import ChangedPR   # pure stdlib — no framework pulled

_API_BASE = "https://api.github.com"
#: Exactly ``owner/repo`` with GitHub-safe segment chars (no extra ``/``, no ``.``/``..`` segment). A crafted
#: repo must never traverse the REST path to another api.github.com endpoint with the operator token.
_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_API_VERSION = "2022-11-28"
_USER_AGENT = "OBSIDIAN-VIGIL/1.0 (authorized owner-test)"
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024   # bound a page body (defense; GitHub pages are far smaller)


class GitHubReadError(RuntimeError):
    """A non-200 / malformed / oversized GitHub read. Raised so the reconciliation driver SKIPS the repo
    this cycle (fail-open, cursor held) — a transient 5xx/network error is recovered next cycle."""


@dataclass
class GitHubReadConfig:
    """Read-client config. The token is off-spine (``repr=False``), from here or ``GITHUB_TOKEN``."""

    slug: str = ""
    github_token: str = field(default="", repr=False)
    api_base: str = _API_BASE
    timeout_s: float = 30.0
    per_page: int = 100          # GitHub's max page size
    max_pages: int = 30          # bound total work per repo per cycle (→ up to 3000 PRs/files before truncation)


def _owner_repo(repo: str) -> str:
    """``github.com/org/repo`` (or a full URL) → ``org/repo``; already-bare ``org/repo`` passes through.
    SECURITY: the result must be EXACTLY ``owner/repo`` with safe chars (``_OWNER_REPO_RE``) — a crafted
    repo with extra segments or a ``..`` segment raises GitHubReadError (never traverses the REST path)."""
    r = str(repo or "").strip()
    if "://" in r:
        r = r.split("://", 1)[1]
    if r.lower().startswith("github.com/"):
        r = r[len("github.com/"):]
    r = r.strip("/")
    if not _OWNER_REPO_RE.match(r):
        raise GitHubReadError(f"not a safe org/repo identity (refusing REST-path traversal): {repo!r}")
    return r


class GitHubReadClient:
    """A gated, READ-ONLY GitHub REST client. ``list_open_prs`` is the reconciliation ``RepoLister``."""

    def __init__(self, config: GitHubReadConfig, *, http: Any = None) -> None:
        self.config = config
        self._http = http   # an injected httpx-like client (tests); None ⇒ lazily built + gated

    # -- token + gated client (lazy; FATAL-2) ----------------------------------------------------------

    def _token(self) -> str:
        return (self.config.github_token or os.environ.get("GITHUB_TOKEN", "")).strip()

    def _headers(self) -> dict:
        token = self._token()
        if not token:   # FAIL CLOSED — never make an unauthenticated call
            raise GitHubReadError("no GitHub token configured (set GITHUB_TOKEN or GitHubReadConfig.github_token)")
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

    def _get(self, path: str, params: dict) -> list:
        """GET one page and return its JSON array (bounded). Any non-200 / oversized / non-list body raises
        GitHubReadError (→ the reconciliation driver fail-open-skips the repo)."""
        url = self.config.api_base.rstrip("/") + path
        if not url.startswith("https://api.github.com/"):   # HOST-PIN: this client ONLY ever reaches api.github.com
            raise GitHubReadError(f"refusing a non-api.github.com URL: {url!r}")
        resp = self._client().get(url, headers=self._headers(), params=params)
        status = getattr(resp, "status_code", 0)
        if status != 200:
            raise GitHubReadError(f"GET {path} returned HTTP {status}")
        headers = getattr(resp, "headers", {}) or {}   # reject an oversized body by its declared length too
        try:
            declared = int(headers.get("content-length") or 0)
        except (TypeError, ValueError):
            declared = 0
        body = getattr(resp, "content", b"") or b""
        if declared > _MAX_RESPONSE_BYTES or len(body) > _MAX_RESPONSE_BYTES:
            raise GitHubReadError(f"GET {path} response exceeds {_MAX_RESPONSE_BYTES} bytes")
        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001 — a malformed body is a read error, not a crash
            raise GitHubReadError(f"GET {path} body is not JSON: {type(exc).__name__}") from exc
        return data if isinstance(data, list) else []

    # -- the RepoLister: (repo, since_cursor) -> (list[ChangedPR], new_cursor) --------------------------

    def list_open_prs(self, repo: str, since_cursor: str = "") -> "tuple[list[ChangedPR], str]":
        """List the repo's OPEN PRs updated since ``since_cursor`` (an ``updated_at`` ISO-8601-Z token that
        sorts lexically). Walks ``?state=open&sort=updated&direction=desc`` pages, emitting every PR updated
        after the cursor; it processes each FULL page and does NOT trust the remote order to early-break (a
        mis-ordered page cannot hide a newer PR). Returns ``(ChangedPR[], new high-water cursor)``; a
        non-200/network error raises (the driver skips the repo this cycle). READ-ONLY (GET)."""
        owner_repo = _owner_repo(repo)   # raises GitHubReadError on an unsafe identity
        prs: list[ChangedPR] = []
        high = since_cursor
        for page in range(1, self.config.max_pages + 1):
            rows = self._get(f"/repos/{owner_repo}/pulls",
                             {"state": "open", "sort": "updated", "direction": "desc",
                              "per_page": self.config.per_page, "page": page})
            if not rows:
                break
            new_on_page = 0
            for row in rows:
                if not isinstance(row, dict):
                    continue
                updated = str(row.get("updated_at") or "")
                if since_cursor and updated and updated <= since_cursor:
                    continue   # already covered — skip, but do NOT break (don't trust the remote ordering)
                number = row.get("number")
                head = row.get("head") if isinstance(row.get("head"), dict) else {}
                sha = str(head.get("sha") or "")
                if number is None:
                    continue
                try:
                    prs.append(ChangedPR(pr_number=int(number), head_sha=sha, cursor=updated))
                except (TypeError, ValueError):
                    continue   # a malformed row is skipped, not fatal (the driver also drops bad jobs)
                new_on_page += 1
                if updated and (not high or updated > high):
                    high = updated
            # stop on a short page (last page) or a FULL page with zero new PRs (past the cursor region) —
            # NOT on the first at/under-cursor row, so a mis-ordered page can't hide a newer PR.
            if len(rows) < self.config.per_page or (since_cursor and new_on_page == 0):
                break
        return prs, (high or since_cursor)

    # -- changed files of a PR (for diff-scoping) ------------------------------------------------------

    def changed_files(self, repo: str, pr_number: int, head_sha: str = "") -> "set[str]":
        """The repo-root-relative POSIX paths changed by a PR (matches the scanner's ``finding.path``), for
        diff-scoping a scan. READ-ONLY (GET). Raises GitHubReadError on a non-200/network error, AND — unlike
        the safety-net PR listing — on TRUNCATION (a PR whose file list exceeds ``per_page*max_pages``): a
        truncated changed-files set would silently drop findings in the dropped tail (a false clean), so the
        diff scope must fail CLOSED rather than be treated as complete."""
        owner_repo = _owner_repo(repo)   # raises GitHubReadError on an unsafe identity
        files: set[str] = set()
        truncated = True   # becomes False only when a short/empty page proves we reached the end
        for page in range(1, self.config.max_pages + 1):
            rows = self._get(f"/repos/{owner_repo}/pulls/{int(pr_number)}/files",
                             {"per_page": self.config.per_page, "page": page})
            if not rows:
                truncated = False
                break
            for row in rows:
                if isinstance(row, dict) and row.get("filename"):
                    files.add(str(row["filename"]))
            if len(rows) < self.config.per_page:
                truncated = False
                break
        if truncated:
            raise GitHubReadError(
                f"PR #{pr_number} changed-files list exceeds {self.config.per_page * self.config.max_pages} "
                "files — refusing an INCOMPLETE diff scope (would silently drop findings in the tail)")
        return files

    def close(self) -> None:
        http = self._http
        if http is not None and hasattr(http, "close"):
            try:
                http.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass


def make_github_lister(config: GitHubReadConfig, *, http: Any = None):
    """Build the reconciliation ``RepoLister`` (``(repo, since_cursor) -> (list[ChangedPR], new_cursor)``)
    backed by a gated read client — injected into ``Reconciler(lister=...)`` by the offense worker. Also
    returns the client so the caller can reuse it for ``changed_files`` + close it."""
    client = GitHubReadClient(config, http=http)
    return client.list_open_prs, client
