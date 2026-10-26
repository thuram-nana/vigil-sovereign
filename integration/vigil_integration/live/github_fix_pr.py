"""github_fix_pr — the GATED fix-PR write-back (repo-connect Slice 3c), OFF by default.

The higher-risk write: open a pull request carrying an oracle-VERIFIED fix. SEPARATE from the reversible comment
write (3b). It REUSES the proof-carrying-remediation ladder that already exists in
``codefix_runner.autopatch_live`` — propose → clone → apply-in-sandbox → build/test gate → fix-oracle re-fire →
(iff ``pr_enabled`` AND the m-of-n quorum passes AND a token is provisioned) open a PR from a FIX BRANCH via
``open_pr`` (never the base/protected branch, never a merge). That ladder already enforces the WARDEN A3 tier +
kill-switch + the m-of-n destruction quorum; Slice 3c ADDS the two controls codefix_runner predates:

  * the repo-EXACT git-write grant ``"pr"`` capability (``authority.gate.authorize_repo_write`` over
    ``load_verified_git_write_grant``, Slice 3-authz-A) — no owner-signed ``"pr"`` grant for THIS repo ⇒ refuse;
  * a cryptographically-signed audit record per write (control 7), reusing 3b's signed audit sink.

and it CLOSES the grant-vs-target seam: the grant authorizes a PR to ``github.com/org/repo``, while ``open_pr``
pushes to the clone's ``origin`` — 3c verifies the clone's origin IS the granted repo BEFORE running the
(writing) ladder, so a grant for repo A can never open a PR to repo B.

Controls delivered: (1) PR separate from comment, (3) ``pr_enabled`` OFF by default, (4) WARDEN A3 + m-of-n (both
in the autopatch_live gate), (5) feature-branch-only / no protected-branch write + (6) no auto-merge/deploy (both
``open_pr``), (7) signed audit. FATAL-2: framework + codefix_runner are imported LAZILY, so this module is
import-clean in either venv and is constructed only by the OFFENSE worker.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .github_write import AuditSink, GitHubWriteError, _owner_repo   # reuse the write-error type + repo label


def _normalize_remote(url: str) -> str:
    """Normalize a git remote (``https://github.com/o/r.git`` / ``git@github.com:o/r.git`` / ``github.com/o/r``)
    to a canonical lowercased ``host/owner/repo`` for an EXACT compare — strips the scheme, ``git@`` SSH prefix,
    userinfo, a trailing ``/`` and a ``.git`` suffix. So the clone's origin can be matched against the grant's
    ``host/org/repo`` regardless of URL form; divergence ⇒ the write is refused."""
    s = str(url or "").strip()
    if s.startswith("git@"):
        s = s[len("git@"):].replace(":", "/", 1)      # git@github.com:o/r → github.com/o/r
    if "://" in s:
        s = s.split("://", 1)[1]
    first = s.split("/", 1)[0]
    if "@" in first:                                   # strip userinfo in https://user@host/…
        s = s.split("@", 1)[1]
    s = s.rstrip("/")
    if s.endswith(".git"):
        s = s[:-4]
    return s.lower()


def _default_remote_of(target_repo: Any, git_bin: str = "git") -> str:
    """The ``origin`` remote URL of the local clone ``open_pr`` will push to. Raises GitHubWriteError when it
    cannot be read (fail-closed: an unknown push target must never be treated as the granted repo)."""
    import subprocess
    try:
        r = subprocess.run([git_bin, "-C", str(target_repo), "remote", "get-url", "origin"],
                           capture_output=True, text=True, timeout=30)
    except Exception as exc:  # noqa: BLE001 — git missing / unrunnable ⇒ fail-closed
        raise GitHubWriteError(f"cannot read the origin remote of {target_repo!r}: {type(exc).__name__}") from exc
    if r.returncode != 0:
        raise GitHubWriteError(f"cannot read the origin remote of {target_repo!r}: {(r.stderr or '').strip()[:160]}")
    return (r.stdout or "").strip()


def authorized_fix_pr(
    *,
    slug: str,
    trust_root: Any,
    repo: str,
    finding: Any,
    config: Any,                       # codefix_runner.CodefixConfig
    audit: AuditSink,
    quorum: Optional[Callable[[Any], Any]] = None,
    verify_oracle: Optional[Callable[[Any, Any], Any]] = None,
    client: Any = None,
    killswitch: Any = None,
    now: Any = None,
    grant_path: Any = None,
    epoch_path: Any = None,
    remote_of: Optional[Callable[..., str]] = None,
    _autopatch: Any = None,
) -> Any:
    """Open a fix PR ONLY if the full fail-closed chain clears, then emit a signed audit record. The sanctioned
    repo-connect entrypoint to the fix-PR capability. Each step refuses (raises GitHubWriteError) rather than
    proceeding, and the (writing) PCR ladder is not even started until the grant + the grant-vs-target check pass:

      1. ``config.pr_enabled`` is True (OFF by default — control 3);
      2. an owner-signed repo-EXACT GitWriteGrant authorizes ``"pr"`` for ``repo`` (Slice 3-authz-A — controls
         1+2); a verification failure (tampered / replayed / unsigned) is normalized to GitHubWriteError;
      3. the clone's ``origin`` IS the granted ``repo`` (grant-vs-target seam closed) — else refuse;
      4. ``codefix_runner.autopatch_live`` runs the PCR ladder; its ``open_pr`` opens a PR from a FIX BRANCH only
         after the WARDEN A3 tier + kill-switch + the m-of-n ``quorum`` all pass (controls 4/5/6);
      5. a signed audit record is emitted (control 7); if the sink raises, THIS call raises (no un-audited write).

    ``now`` is a TRUSTED-caller value for the GRANT window (datetime/None → real clock). ``quorum`` is the m-of-n
    destruction-quorum check forwarded to autopatch_live (absent ⇒ its deny-quorum ⇒ no PR). ``remote_of`` /
    ``_autopatch`` are injection seams for offline tests. Returns autopatch_live's ``PatchResult``."""
    # 1. OFF BY DEFAULT — control (3). (autopatch_live's open_pr re-checks this; refuse early, before any clone.)
    if not getattr(config, "pr_enabled", False):
        raise GitHubWriteError("fix-PR write is OFF by default (pr_enabled=False) — refusing")

    # 2. repo-EXACT git-write grant for the "pr" capability — controls (1)+(2), Slice 3-authz-A. Lazy framework
    #    (offense). A verification failure raises AuthorityError, normalized to the documented GitHubWriteError.
    from framework.v2.authority.gate import authorize_repo_write
    from framework.v2.authority.store import AuthorityError, load_verified_git_write_grant

    try:
        grant = load_verified_git_write_grant(slug, trust_root, path=grant_path, epoch_path=epoch_path)
    except AuthorityError as e:
        raise GitHubWriteError(f"git-write grant for {slug!r} failed verification — refusing: {e}") from e
    if not authorize_repo_write(grant, repo, "pr", now=now):
        raise GitHubWriteError(
            f"no owner-signed git-write grant authorizes a PR on {repo!r} for engagement {slug!r} — refusing")

    # 3. grant-vs-target seam — the PR opens to the clone's origin; it MUST be the granted repo, else a grant for
    #    repo A could open a PR to repo B. Checked BEFORE the writing PCR ladder runs (fail-closed).
    remote = (remote_of or _default_remote_of)(config.target_repo, getattr(config, "git_bin", "git"))
    if _normalize_remote(remote) != _normalize_remote(repo):
        raise GitHubWriteError(
            f"clone origin {remote!r} is not the granted repo {repo!r} — refusing (grant-vs-target mismatch)")

    # 4. run the PCR ladder (propose → clone → apply-in-sandbox → build/test → fix-oracle → gated open_pr). The
    #    WARDEN A3 tier + kill-switch + m-of-n quorum are enforced INSIDE autopatch_live's gate/open_pr.
    autopatch_live = _autopatch
    if autopatch_live is None:
        from .codefix_runner import autopatch_live as _al   # lazy (offense)
        autopatch_live = _al
    result = autopatch_live(finding, config=config, client=client, killswitch=killswitch,
                            quorum=quorum, verify_oracle=verify_oracle)

    # 5. signed audit record of the write — control (7). Fail-closed: an un-audited write surfaces loudly.
    record = {
        "action": "github_pr",
        "slug": slug,
        "repo": _owner_repo(repo),
        "finding_ref": str(getattr(finding, "ref", "") or getattr(finding, "id", "") or ""),
        "status": str(getattr(result, "status", "") or ""),
        "pr_ref": str(getattr(result, "pr_ref", "") or ""),
        "remediated": bool(getattr(result, "remediated", False)),
    }
    if not callable(audit):
        raise GitHubWriteError("no audit sink supplied — refusing to leave a fix-PR write un-audited (control 7)")
    audit(record)
    return result


__all__ = ["authorized_fix_pr"]
