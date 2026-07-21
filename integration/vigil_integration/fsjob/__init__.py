"""
vigil_integration.fsjob — governed agent fs / job / traffic tooling (VIGIL-FUSION F9).

Three composable agent-tool building blocks ported from redamon (workspace_fs / job_runner /
traffic_tools; MIT, see NOTICE) and subordinated to the sovereign core:

  * :mod:`~fsjob.sandbox` — the race-free path-confinement kernel (:func:`resolve_within` /
    :func:`walk_to_parent`). Traversal / absolute / symlink / SYMLINK-RACE / NUL are all refused via an
    ``openat`` walk with ``O_NOFOLLOW``, and every fs operation runs over the safe fd, not a re-resolved
    string — closing the TOCTOU the source's ``.resolve()`` approach left open.
  * :mod:`~fsjob.fs` — :class:`WorkspaceFS`: reads plus signed, append-only, REVERSIBLE mutations
    (write/edit/delete/move/mkdir/extract), each a :class:`~fsjob.spine.SpineEvent` with pre/post
    content hashes; hardened archive extraction (tar-slip / symlink-member / zip-bomb).
  * :mod:`~fsjob.jobs` — :class:`JobRegistry`: escalation-proof ``spawn`` (RE-checks the target tool
    through ``tools.authorize_tool_call`` → ``is_tool_allowed_in_phase`` before the conjunctive gate),
    deterministic ids, witnessed on-disk provenance, fail-closed crash recovery.
  * :mod:`~fsjob.traffic` — :class:`TrafficCorpus`: read-only search/get/grep/sitemap/params over a
    static captured-HTTP corpus (no live proxy / replay / fuzz); every result is a redacted LEAD.

The sovereign invariant (what the red-pen attacks): a path can NEVER escape the sandbox root; a job can
NEVER be backgrounded if a direct call would be refused for the current phase; every fs mutation is a
signed, reversible spine event; traffic tools are read-only over the corpus; and every public function
is total on malformed input.

Import-clean: pydantic + stdlib + the F1 safety / F3 tools helpers only (no framework/strix/network).
"""

from .fs import FsResult, WorkspaceFS
from .jobs import JobActionResult, JobRegistry, JobSpawnResult
from .sandbox import (
    PathEscapeError,
    canonical_root,
    is_within_sandbox,
    lexical_components,
    resolve_within,
    walk_to_parent,
)
from .spine import EventLogError, NextSeq, Signer, SpineEvent, SpineEventLog, sha256_hex
from .traffic import CapturedTxn, TrafficCorpus

__all__ = [
    # sandbox kernel
    "PathEscapeError", "resolve_within", "is_within_sandbox", "lexical_components",
    "walk_to_parent", "canonical_root",
    # signed spine events
    "Signer", "NextSeq", "SpineEvent", "SpineEventLog", "EventLogError", "sha256_hex",
    # workspace fs
    "WorkspaceFS", "FsResult",
    # jobs
    "JobRegistry", "JobSpawnResult", "JobActionResult",
    # traffic
    "TrafficCorpus", "CapturedTxn",
]
