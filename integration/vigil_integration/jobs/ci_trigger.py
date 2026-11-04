"""
jobs.ci_trigger — the CI trigger adapter (workstream W4).

A GitHub Action runs ``vigil ci-scan``, which uses this adapter to normalize the CI run's coordinates
into the ONE :class:`SecurityJob` event the queue understands — exactly as ``webhook_drain`` and the
``reconciliation`` poller do. Like every trigger adapter it ONLY PRODUCES a job (the CLI then enqueues
it); it NEVER runs one. Execution stays solely behind the queue + the authorized worker (``jobs.runner``
→ ``authorize_job``), so a CI trigger grants no bypass — a repo with no cryptographically-verified
``EngagementAuthority`` is REFUSED, not scanned, regardless of being "from CI".

Pure stdlib + ``.model`` — no ``framework`` import, no ``sigil`` import, no network, no execution
(two-env boundary; registered in ``integration/tests/test_two_env_boundary.py``).

``repo`` is spelled ``<host>/<owner>/<repo>`` to MATCH the webhook path's ``github.com/<full_name>``, and
the ``delivery_id`` is the SHARED content-addressed :func:`work_delivery_id` over ``(repo, pr, commit)``
— NOT the CI run id — so a CI job and a webhook job for the same ``(repo, pr, commit)`` carry the IDENTICAL
delivery key. That coalesces them in the queue's permanent delivery seen-set **to the extent the queue is
shared** — i.e. exactly-once across the CI/webhook/reconcile paths holds only when they enqueue into the
SAME durable ``queue-root``. The W4 Action's default ``queue-root`` is a per-run, ephemeral path under the
Actions workspace, so there it gives idempotency WITHIN a run (a duplicate enqueue is a no-op), not
cross-run/cross-path dedup — point ``queue-root`` at a persisted/shared store to get that.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

from .model import SecurityJob, work_delivery_id

_EVENT_READ_CAP = 2_000_000  # bound the untrusted event-payload file read (a PR author controls its contents)
_PULL_REF_RE = re.compile(r"^refs/pull/(\d+)/(?:merge|head)$")


def _host_from_server_url(server_url: str) -> str:
    """The bare host of ``GITHUB_SERVER_URL`` (``https://github.com`` → ``github.com``), defaulting to
    ``github.com`` so the CI repo identity matches the webhook path's ``github.com/<full_name>`` on the
    public cloud (cross-path dedup). Pure; never raises; GitHub-Enterprise hosts carry through verbatim."""
    s = str(server_url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].strip().rstrip("/")
    return s or "github.com"


def _read_capped(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read(_EVENT_READ_CAP)


def _coords_from_event(event_path: str) -> "tuple[int | None, str]":
    """``(pr_number, head_sha)`` from a GitHub Actions event payload file (``$GITHUB_EVENT_PATH``), or
    ``(None, "")``. TOTAL + bounded — a missing/unreadable/oversized/garbage file yields the empty answer,
    never raises (``SecurityJob.normalize`` is the authoritative validator). The PR HEAD sha
    (``pull_request.head.sha``) is preferred for ``commit`` so a CI job on a PR coalesces with the webhook
    path, which keys off the head commit — not the merge sha ``GITHUB_SHA`` carries on ``pull_request``."""
    try:
        raw = _read_capped(event_path)
        payload = json.loads(raw) if raw else {}
    except (OSError, ValueError, TypeError):
        return None, ""
    if not isinstance(payload, dict):
        return None, ""
    pr = payload.get("pull_request")
    pr = pr if isinstance(pr, dict) else {}
    num_raw = pr.get("number", payload.get("number"))
    try:
        num = int(num_raw) if num_raw is not None else None
    except (TypeError, ValueError):
        num = None
    head = pr.get("head")
    head_sha = head.get("sha") if isinstance(head, dict) else ""
    return num, str(head_sha or "")


def _pr_from_ref(ref: str) -> "int | None":
    """The PR number from a ``refs/pull/<n>/merge`` (or ``/head``) ``GITHUB_REF``, else ``None``."""
    m = _PULL_REF_RE.match(str(ref or "").strip())
    return int(m.group(1)) if m else None


def ci_job_from_inputs(*, repo: str, commit: str = "", pr_number: "int | None" = None,
                       tenant_id: str = "", ci_run_id: str = "") -> SecurityJob:
    """Normalize explicit CI coordinates into a validated ``SecurityJob(source="ci")``.

    The ``delivery_id`` is the SHARED content-addressed work key :func:`work_delivery_id(repo, pr, commit)`
    — never the CI run id — so a CI re-run of the same ``(repo, pr, commit)`` and a webhook-handled commit
    coalesce in the queue's permanent seen-set (exactly-once across paths; a changed ``commit`` yields a
    new key, so new code re-scans). The CI run id travels only as audit telemetry in ``extra``. Raises
    ``ValueError`` (via ``normalize``) on an empty ``repo`` — no repo means nothing to scan."""
    extra: dict[str, Any] = {"ci_run": str(ci_run_id)} if ci_run_id else {}
    return SecurityJob.normalize(
        source="ci", repo=repo, commit=commit, pr_number=pr_number, tenant_id=tenant_id,
        delivery_id=work_delivery_id(repo, pr_number, commit), extra=extra)


def ci_job_from_github_env(env: "dict[str, str] | None" = None) -> SecurityJob:
    """Build a ``SecurityJob(source="ci")`` from the standard GitHub Actions environment: ``GITHUB_REPOSITORY``
    (``owner/repo``), ``GITHUB_SERVER_URL`` (host), the PR number + HEAD sha from ``GITHUB_EVENT_PATH``
    (PR number falling back to ``GITHUB_REF``), ``GITHUB_SHA`` (commit fallback), ``GITHUB_RUN_ID`` (audit).
    Raises ``ValueError`` when ``GITHUB_REPOSITORY`` is absent (no repo = nothing to scan)."""
    e = dict(os.environ if env is None else env)
    full = str(e.get("GITHUB_REPOSITORY") or "").strip().strip("/")
    host = _host_from_server_url(e.get("GITHUB_SERVER_URL", ""))
    repo = f"{host}/{full}" if full else ""
    pr_number, head_sha = _coords_from_event(str(e.get("GITHUB_EVENT_PATH") or ""))
    if pr_number is None:
        pr_number = _pr_from_ref(str(e.get("GITHUB_REF") or ""))
    commit = head_sha or str(e.get("GITHUB_SHA") or "").strip()
    return ci_job_from_inputs(repo=repo, commit=commit, pr_number=pr_number,
                              ci_run_id=str(e.get("GITHUB_RUN_ID") or ""))


@dataclass
class CiTrigger:
    """A one-shot ``TriggerSource`` for a single CI run: ``poll()`` returns exactly the one job for this run,
    or ``[]`` when the environment names no repo (nothing to scan). Mirrors ``ManualTrigger`` — it PRODUCES,
    it never executes."""

    env: "dict[str, str] | None" = None

    def poll(self) -> "list[SecurityJob]":
        try:
            return [ci_job_from_github_env(self.env)]
        except ValueError:
            return []
