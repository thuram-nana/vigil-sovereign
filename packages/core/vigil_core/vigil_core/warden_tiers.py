"""WARDEN autonomy tiers — the ONE classifier of record (unification S2).

A BYTE-FAITHFUL Python port of the Rust WARDEN kernel classifier (`apps/sigil/kernel/src/tiers.rs`), so
the sovereign kernel (SIGIL's live enforcement) and the offense-side gate (`vigil engage`) classify a tool
name to a tier by the SAME rules instead of two drifting implementations. Both are pinned to one shared
golden vector set (`warden_golden.json`), loaded by BOTH this module's tests AND the Rust unit test — a
divergence fails one side's parity test, so they cannot silently drift.

FAIL-CLOSED and TOKEN-BASED: the tool name is split into whole tokens (on ``.``/``_``/``-``/``/``/space)
and matched against whole-token sets — never a raw substring, so "overwrite" is not "write" and "forget"
is not "get". Danger is checked FIRST, and A0 (auto, un-queued) is reachable ONLY via a positive safe-verb
allowlist; anything not positively classified — unknown, empty, or dangerous-target — is A3.

Pure stdlib (re + enum), so it imports cleanly in BOTH the sovereign and the offense environment.
"""
from __future__ import annotations

import re
from enum import IntEnum

__all__ = ["Tier", "classify", "gate", "tokens", "has_danger_token"]


class Tier(IntEnum):
    """Ordered exactly as the Rust enum (A0 < A1 < A2 < A3): a lower tier is less dangerous. `<= A1` may
    auto-run."""
    A0 = 0
    A1 = 1
    A2 = 2
    A3 = 3

    @property
    def label(self) -> str:
        return self.name


# ---- the token sets — transcribed VERBATIM from tiers.rs (keep in lockstep; the golden test guards it) ----

# A3 — destructive verbs, financial ops, crypto/restore ops, and DANGEROUS TARGETS (secret/identity/
# network/prod material is A3 regardless of the verb).
_A3_TOKENS = frozenset({
    "push", "deploy", "delete", "destroy", "drop", "remove", "purge", "wipe", "truncate",
    "overwrite", "erase", "format", "kill", "shutdown", "reboot", "reset", "disable", "enable",
    "override", "force", "sudo", "exec", "eval", "chmod", "chown", "patch", "install", "uninstall",
    "encrypt", "decrypt", "restore", "revert", "rollback", "recover",
    "spend", "purchase", "pay", "payment", "transaction", "transfer", "refund", "invoice",
    "allocate", "budget", "release", "sign",
    "secret", "secrets", "credential", "credentials", "token", "tokens", "key", "keys", "iam",
    "policy", "firewall", "acl", "role", "grant", "revoke", "rotate", "escalate", "infra",
    "prod", "production", "env", "master", "root", "admin",
    "vault", "keyring", "keychain", "keystore", "hsm",
})

# A2 — external-visible / semi-reversible: communication, publishing, and bulk DATA EGRESS.
_A2_TOKENS = frozenset({
    "send", "email", "smtp", "publish", "post", "message", "outbound", "webhook", "sms", "notify",
    "share", "upload", "invite", "calendar", "tweet", "dm", "export", "dump", "download", "sync",
})

# A1 — reversible internal writes (drafts, notes, memory writes, non-push commits).
_A1_TOKENS = frozenset({
    "write", "note", "brief", "report", "draft", "alert", "consolidate", "commit", "branch",
    "annotate", "tag", "label",
})

# A0 — POSITIVE allowlist of known-safe observe/answer VERBS only (NO target nouns).
_A0_VERBS = frozenset({
    "read", "search", "query", "get", "list", "status", "recall", "observe", "answer",
    "view", "show", "find", "frame", "peek", "describe", "inspect", "lookup",
})

# A0 — exact-name allowlist for read-only memory tools whose names are not verb-clean.
_A0_TOOLS = frozenset({
    "memory.search", "graph.query", "graph.entity", "episodic.range", "ingest.status",
    "threads.open", "commitments.due", "contradictions.pending",
})

# EXACT-NAME input-authorization tables (gesture control). Checked AFTER the danger-first pass.
_INPUT_A1 = frozenset({"hid.pointer.move", "hid.pointer.click", "hid.pointer.scroll", "hid.pointer.drag"})
_INPUT_A2 = frozenset({"hid.type", "hid.combo", "hid.app.launch"})

# Split delimiters: `.` `_` `-` `/` and whitespace (`\s`). Python's `\s` ALSO matches the C0 information
# separators U+001C..U+001F — and the Rust port explicitly splits on them too (its `is_whitespace()` does
# not), so the two tokenizers are byte-identical AND a hidden control-char separator can never smuggle a
# danger token past classification (`read.log\x1cdelete` → tokens include `delete` → A3). The golden
# vectors pin this boundary. Every A3/A2/A1/A0 dictionary token is itself delimiter-free, so more splitting
# can only ever EXPOSE a danger token, never break one apart or hide it — danger exposure is MONOTONE.
_SPLIT = re.compile(r"[._/\s-]")
# lowercase ASCII A-Z ONLY (matching Rust `to_ascii_lowercase`; non-ASCII bytes are left unchanged so a
# non-ASCII tool name can never masquerade as a safe token).
_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


def _ascii_lower(s: str) -> str:
    return s.translate(_ASCII_LOWER)


def tokens(tool: str) -> list[str]:
    """Split a tool name into whole tokens on ``.``/``_``/``-``/``/``/whitespace, lowercased (ASCII)."""
    return [_ascii_lower(t) for t in _SPLIT.split(tool) if t]


def classify(tool: str) -> Tier:
    """Classify a tool name into a tier. Danger FIRST, then A2, A1; the exact-name HID input tables; A0
    only via a positive safe-verb or an exact safe-tool name; everything else → A3 (fail-closed)."""
    full = _ascii_lower(tool)
    tk = tokens(tool)
    if not tk:
        return Tier.A3
    tkset = set(tk)
    if tkset & _A3_TOKENS:
        return Tier.A3
    if tkset & _A2_TOKENS:
        return Tier.A2
    if tkset & _A1_TOKENS:
        return Tier.A1
    if full in _INPUT_A1:
        return Tier.A1
    if full in _INPUT_A2:
        return Tier.A2
    if full in _A0_TOOLS or (tkset & _A0_VERBS):
        return Tier.A0
    return Tier.A3   # not positively classified → fail-closed to the most-gated tier


def has_danger_token(tool: str) -> bool:
    """True iff the name carries an A3 DANGER token (a destructive/financial/secret-target verb-or-noun) —
    i.e. ``classify`` returns A3 because the name is DANGEROUS, not merely unknown. Lets a caller with its
    OWN vocabulary (e.g. the offense recon set) safely auto-eligible an UNKNOWN name without EVER lowering a
    dangerous one — the danger determination stays the ONE shared vocabulary."""
    return bool(set(tokens(tool)) & _A3_TOKENS)


def gate(tier: Tier) -> str:
    """The gate decision for a tier: A0/A1 auto, A2 queued, A3 explicit-required (mirrors the Rust `gate`)."""
    if tier <= Tier.A1:
        return "auto"
    if tier == Tier.A2:
        return "queued"
    return "explicit-required"
