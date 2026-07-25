//! WARDEN autonomy tiers (SIGIL §5). Every tool invocation is classified A0–A3; the gate
//! decision follows from the tier. FAIL-CLOSED and TOKEN-BASED: the tool name is split into
//! whole tokens (on `.`/`_`/`-`/`/`/space) and matched against whole-token sets — never a raw
//! substring, so "overwrite" is not "write" and "forget" is not "get". Danger is checked FIRST,
//! and A0 (auto, un-queued) is reachable ONLY via a positive safe-verb allowlist; anything not
//! positively classified — including any unknown or dangerous-target tool — is A3.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    /// Observe / answer — memory queries, screen read, voice reply. Auto.
    A0,
    /// Reversible internal act — write a report/brief, draft-branch, raise an alert. Auto + logged.
    A1,
    /// External-visible / semi-reversible — send email, calendar write, purchase < cap. Queued.
    A2,
    /// Destructive / financial / security — push protected branch, deploy, delete, spend > cap. Explicit.
    A3,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::A0 => "A0",
            Tier::A1 => "A1",
            Tier::A2 => "A2",
            Tier::A3 => "A3",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Auto,
    Queued,
    ExplicitRequired,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Auto => "auto",
            Decision::Queued => "queued",
            Decision::ExplicitRequired => "explicit-required",
        }
    }
    pub fn may_run(&self) -> bool {
        matches!(self, Decision::Auto)
    }
}

/// A3 — destructive verbs, financial ops, crypto/restore ops, and DANGEROUS TARGETS
/// (secret/identity/network/prod material is A3 regardless of the verb: `secrets.read`,
/// `iam.policy.write`, `budget.get`, `vault.read`).
const A3_TOKENS: &[&str] = &[
    // destructive verbs
    "push", "deploy", "delete", "destroy", "drop", "remove", "purge", "wipe", "truncate",
    "overwrite", "erase", "format", "kill", "shutdown", "reboot", "reset", "disable", "enable",
    "override", "force", "sudo", "exec", "eval", "chmod", "chown", "patch", "install", "uninstall",
    // crypto + restore/rollback (a restore silently reverts current state)
    "encrypt", "decrypt", "restore", "revert", "rollback", "recover",
    // financial
    "spend", "purchase", "pay", "payment", "transaction", "transfer", "refund", "invoice",
    "allocate", "budget", "release", "sign",
    // security / identity / infra / secret-store TARGETS (dangerous no matter the verb)
    "secret", "secrets", "credential", "credentials", "token", "tokens", "key", "keys", "iam",
    "policy", "firewall", "acl", "role", "grant", "revoke", "rotate", "escalate", "infra",
    "prod", "production", "env", "master", "root", "admin",
    "vault", "keyring", "keychain", "keystore", "hsm",
];

/// A2 — external-visible / semi-reversible: communication, publishing, and bulk DATA EGRESS
/// (export/dump of a private store must be human-seen, never auto).
const A2_TOKENS: &[&str] = &[
    "send", "email", "smtp", "publish", "post", "message", "outbound", "webhook", "sms", "notify",
    "share", "upload", "invite", "calendar", "tweet", "dm", "export", "dump", "download", "sync",
];

/// A1 — reversible internal writes (drafts, notes, memory writes, non-push commits). NOTE:
/// "snapshot" is intentionally NOT here — a snapshot RESTORE is destructive (caught by A3
/// "restore"), and snapshot-create alone falls to fail-closed A3 rather than risk auto-run.
const A1_TOKENS: &[&str] = &[
    "write", "note", "brief", "report", "draft", "alert", "consolidate", "commit", "branch",
    "annotate", "tag", "label",
];

/// A0 — POSITIVE allowlist of known-safe observe/answer VERBS only (NO target nouns — a target
/// noun here would let e.g. `memory.encrypt` auto-run). A tool reaches A0 only by a read-verb
/// here, or an exact name in `A0_TOOLS`; absence of danger alone is NOT sufficient → fail-closed A3.
const A0_VERBS: &[&str] = &[
    "read", "search", "query", "get", "list", "status", "recall", "observe", "answer",
    "view", "show", "find", "frame", "peek", "describe", "inspect", "lookup",
];

/// A0 — exact-name allowlist for the known read-only memory tools whose names are not verb-clean
/// (`graph.entity`, `episodic.range`, `threads.open`, `commitments.due`, `contradictions.pending`,
/// `ingest.status`). Matched on the whole lowercased tool name.
const A0_TOOLS: &[&str] = &[
    "memory.search", "graph.query", "graph.entity", "episodic.range", "ingest.status",
    "threads.open", "commitments.due", "contradictions.pending",
];

/// EXACT-NAME input-authorization tables (Phase 8, WS-F gesture control). Input injection has NO
/// honest verb in the token sets (so it is fail-closed A3 by default). These exact `hid.*` names
/// authorize gesture-driven input at the correct tier — checked AFTER the danger-first A3/A2/A1
/// token pass, so a danger token ALWAYS wins (`hid.pointer.delete` → A3). Bare tokens (`move`/`type`/
/// `click`) are DELIBERATELY never added to the token sets, so `file.move`/`data.type` stay A3. The
/// keyboard tools avoid the token `key` (which is an A3 secret-target). Session-boundedness — A1
/// injection ONLY inside an owner-armed session — is enforced in Python (`gesture/session.py`), and
/// the raise-only registry (`registry.rs`) can only ever make an input tool MORE gated, never less.
const INPUT_A1: &[&str] = &["hid.pointer.move", "hid.pointer.click", "hid.pointer.scroll", "hid.pointer.drag"];
const INPUT_A2: &[&str] = &["hid.type", "hid.combo", "hid.app.launch"];

/// Split a tool name into whole tokens on `.`/`_`/`-`/`/` and whitespace, lowercased. The C0 information
/// separators U+001C..=U+001F are ALSO split delimiters: `char::is_whitespace()` (Unicode White_Space)
/// does NOT include them, but they ARE separators — and, critically, they are what the Python port's
/// `\s`-based tokenizer splits on, so splitting on them here keeps the two classifiers byte-identical
/// (S2 parity) and closes a hidden-separator evasion (`read.log\x1cdelete` must not hide the `delete`
/// token behind an invisible control char and auto-run). Every A3/A2/A1/A0 DICTIONARY token is itself
/// delimiter-free, so more splitting can only ever EXPOSE a danger token, never break one apart or hide it
/// — danger exposure is MONOTONE, which is the property that closes this evasion. (The golden vectors pin
/// the boundary.)
fn tokens(tool: &str) -> Vec<String> {
    tool.split(|c: char| c == '.' || c == '_' || c == '-' || c == '/'
                         || c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}'))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

/// Classify a tool name into a tier. Danger FIRST, then A2, A1; A0 only via a positive safe-verb
/// or an exact safe-tool name; everything else (unknown / not-positively-safe / empty) → A3.
pub fn classify(tool: &str) -> Tier {
    let full = tool.to_ascii_lowercase();
    let tk = tokens(tool);
    if tk.is_empty() {
        return Tier::A3;
    }
    let has = |set: &[&str]| tk.iter().any(|t| set.contains(&t.as_str()));
    if has(A3_TOKENS) {
        return Tier::A3;
    }
    if has(A2_TOKENS) {
        return Tier::A2;
    }
    if has(A1_TOKENS) {
        return Tier::A1;
    }
    // Exact-name input tables — reached ONLY after the danger-first pass, so `hid.pointer.delete`
    // already returned A3. Bare `move`/`type` are never token-classified, so `file.move` stays A3.
    if INPUT_A1.contains(&full.as_str()) {
        return Tier::A1; // reversible pointer input (session-bounded in gesture/session.py)
    }
    if INPUT_A2.contains(&full.as_str()) {
        return Tier::A2; // keystrokes / combos / app-launch → queued for owner/device approval
    }
    if A0_TOOLS.contains(&full.as_str()) || has(A0_VERBS) {
        return Tier::A0;
    }
    Tier::A3 // not positively classified → fail-closed to the most-gated tier
}

pub fn gate(tier: Tier) -> Decision {
    match tier {
        Tier::A0 | Tier::A1 => Decision::Auto,
        Tier::A2 => Decision::Queued,
        Tier::A3 => Decision::ExplicitRequired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_shared_golden_vectors() {
        // The SINGLE source of truth (packages/core/vigil_core/vigil_core/warden_golden.json), ALSO loaded
        // by the Python port's parity test (test_warden_tiers.py). This Rust classifier and the Python
        // classifier are both pinned to it, so a divergence fails one side's test — they cannot drift (S2).
        let raw = include_str!("../../../../packages/core/vigil_core/vigil_core/warden_golden.json");
        let doc: serde_json::Value = serde_json::from_str(raw).expect("golden json parses");
        let vectors = doc["vectors"].as_array().expect("golden has a 'vectors' array");
        for v in vectors {
            let tool = v[0].as_str().expect("golden [tool, tier] — tool is a string");
            let want = v[1].as_str().expect("golden [tool, tier] — tier is a string");
            assert_eq!(classify(tool).as_str(), want, "golden mismatch for tool {tool:?}");
        }
    }

    #[test]
    fn classification_matches_spec_examples() {
        assert_eq!(classify("memory.search"), Tier::A0);
        assert_eq!(classify("graph.query"), Tier::A0);
        assert_eq!(classify("memory.write"), Tier::A1);
        assert_eq!(classify("brief.compose"), Tier::A1);
        assert_eq!(classify("email.send"), Tier::A2);
        assert_eq!(classify("calendar.write"), Tier::A2); // "calendar" (A2) beats "write" (A1)
        assert_eq!(classify("git.push"), Tier::A3);
        assert_eq!(classify("deploy.prod"), Tier::A3);
        assert_eq!(classify("data.delete"), Tier::A3);
    }

    #[test]
    fn unknown_and_empty_are_fail_closed_a3() {
        assert_eq!(classify("something.unclassified"), Tier::A3);
        assert_eq!(classify(""), Tier::A3);
        assert_eq!(classify("weird"), Tier::A3);
        assert_eq!(gate(classify("something.unclassified")), Decision::ExplicitRequired);
    }

    #[test]
    fn substring_collisions_do_not_lower_the_tier() {
        // the exact review findings: a dangerous op must NOT ride a benign substring down a tier
        assert_eq!(classify("config.overwrite"), Tier::A3, "overwrite != write");
        assert_eq!(classify("db.overwrite"), Tier::A3);
        assert_eq!(classify("files.forget"), Tier::A3, "forget != get; fail-closed");
        assert_eq!(classify("budget.override"), Tier::A3, "financial + override");
        assert_eq!(classify("budget.get"), Tier::A3, "financial target is A3 regardless of verb");
        assert_eq!(classify("iam.policy.write"), Tier::A3, "identity write is A3, not A1");
        assert_eq!(classify("firewall.rule.write"), Tier::A3);
        assert_eq!(classify("transaction.sign"), Tier::A3, "financial signing is A3, not A1");
        assert_eq!(classify("secrets.read"), Tier::A3, "secret read is A3, not A0");
        assert_eq!(classify("credentials.get"), Tier::A3);
        assert_eq!(classify("account.disable"), Tier::A3);
    }

    #[test]
    fn dangerous_ops_on_safe_targets_do_not_auto_run() {
        // the CRITICAL re-check finding: a target noun must NOT grant A0 to a dangerous verb
        assert_eq!(classify("memory.encrypt"), Tier::A3, "ransomware-shaped op must NOT be A0");
        assert_eq!(classify("graph.destroy"), Tier::A3);
        assert_eq!(classify("entity.merge"), Tier::A3, "irreversible rewrite → fail-closed, not A0");
        assert_eq!(classify("memory.export"), Tier::A2, "full-store egress must be queued, not auto");
        assert_eq!(classify("memory.dump"), Tier::A2);
        assert_eq!(classify("snapshot.restore"), Tier::A3, "a restore reverts state → A3");
        assert_eq!(classify("vault.read"), Tier::A3, "secret-store read is A3 regardless of verb");
        assert_eq!(classify("keyring.get"), Tier::A3);
    }

    #[test]
    fn safe_memory_tools_still_reach_a0() {
        for t in [
            "memory.search", "graph.query", "graph.entity", "episodic.range", "ingest.status",
            "threads.open", "commitments.due", "contradictions.pending",
        ] {
            assert_eq!(classify(t), Tier::A0, "{t} is a read-only memory tool → A0");
        }
    }

    #[test]
    fn danger_token_wins_over_safe_token_regardless_of_order() {
        assert_eq!(classify("read.then.delete"), Tier::A3);
        assert_eq!(classify("delete.and.list"), Tier::A3);
        assert_eq!(classify("search.and.deploy"), Tier::A3);
    }

    #[test]
    fn hid_input_tables_tier_correctly_and_danger_wins() {
        // exact HID input names authorize input at the right tier
        assert_eq!(classify("hid.pointer.move"), Tier::A1);
        assert_eq!(classify("hid.pointer.click"), Tier::A1);
        assert_eq!(classify("hid.pointer.scroll"), Tier::A1);
        assert_eq!(classify("hid.pointer.drag"), Tier::A1);
        assert_eq!(classify("hid.type"), Tier::A2, "keystrokes are queued");
        assert_eq!(classify("hid.combo"), Tier::A2);
        assert_eq!(classify("hid.app.launch"), Tier::A2, "app-launch is queued");
        // danger-first ALWAYS wins over an input name
        assert_eq!(classify("hid.pointer.delete"), Tier::A3, "a danger token beats an input name");
        assert_eq!(classify("hid.pointer.sudo"), Tier::A3);
        // unknown hid.* fails closed; the exact-name approach does NOT leak to token-named tools
        assert_eq!(classify("hid.unknown"), Tier::A3, "unknown hid.* → fail-closed A3");
        assert_eq!(classify("file.move"), Tier::A3, "file.move is UNAFFECTED (never auto)");
        assert_eq!(classify("data.type"), Tier::A3, "data.type is UNAFFECTED");
        assert_eq!(classify("content.type"), Tier::A3);
    }

    #[test]
    fn gates_are_correct() {
        assert!(gate(Tier::A0).may_run());
        assert!(gate(Tier::A1).may_run());
        assert!(!gate(Tier::A2).may_run());
        assert!(!gate(Tier::A3).may_run());
    }
}
