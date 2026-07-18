//! WARDEN — the authorization kernel (SIGIL §5). The single choke point every tool invocation
//! crosses: classify the tool into a tier, derive the fail-closed gate decision, and (after the
//! caller executes-or-blocks) append a signed, chained action-log record. WARDEN never executes
//! tools itself; it decides and it records.

use std::io;
use std::path::Path;

use crate::actionlog::{ActionLog, ActionRecord};
use crate::crypto::WardenKey;
use crate::registry::Registry;
use crate::tiers::{gate, Decision, Tier};

pub struct Warden {
    log: ActionLog,
    key: WardenKey,
    registry: Registry,
}

pub struct Verdict {
    pub tier: Tier,
    pub decision: Decision,
}

impl Warden {
    /// Open (or initialize) WARDEN under `dir`: the signing key lives in `dir/keys`, the action
    /// log at `dir/actionlog.jsonl`.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let key = WardenKey::load_or_create(&dir.join("keys"))?;
        let log = ActionLog::new(dir.join("actionlog.jsonl"));
        let registry = Registry::load(&dir.join("tools.json"));
        Ok(Warden { log, key, registry })
    }

    /// Classify + derive the gate decision (pure — no logging, no side effects). The tier is the
    /// raise-only registry result (an explicit pin can only make a tool MORE gated than inferred).
    pub fn decide(&self, tool: &str) -> Verdict {
        let tier = self.registry.tier(tool);
        Verdict { tier, decision: gate(tier) }
    }

    /// Append a signed action-log record for a completed (or blocked) invocation.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        agent: &str,
        tool: &str,
        args_hash: &str,
        verdict: &Verdict,
        approver: &str,
        result_hash: &str,
        ts_epoch: u64,
    ) -> io::Result<ActionRecord> {
        self.log.append(
            &self.key, agent, tool, args_hash,
            verdict.tier.as_str(), verdict.decision.as_str(),
            approver, result_hash, ts_epoch,
        )
    }

    pub fn verify(&self) -> Result<usize, String> {
        self.log.verify(&self.key.public_hex())
    }

    pub fn records(&self) -> io::Result<Vec<ActionRecord>> {
        self.log.records()
    }

    /// The on-disk signed head as (count, head_hash) — for the anti-rollback anchor.
    pub fn head(&self) -> io::Result<Option<(u64, String)>> {
        self.log.head()
    }

    pub fn public_hex(&self) -> String {
        self.key.public_hex()
    }

    /// Sign a message with the WARDEN key (hex) — used to authenticate anchor-set to the spine.
    pub fn sign_hex(&self, msg: &[u8]) -> String {
        self.key.sign_hex(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256_hex;

    fn tmp_dir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("sigil-warden-{}", sha256_hex(format!("{:?}", std::thread::current().id()).as_bytes())));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn a0_a1_auto_run_a2_a3_blocked() {
        let w = Warden::open(&tmp_dir()).unwrap();
        assert!(w.decide("memory.search").decision.may_run(), "A0 must auto-run");
        assert!(w.decide("memory.write").decision.may_run(), "A1 must auto-run");
        assert!(!w.decide("email.send").decision.may_run(), "A2 must NOT auto-run");
        assert!(!w.decide("git.push").decision.may_run(), "A3 must NOT auto-run");
        assert!(!w.decide("unknown.thing").decision.may_run(), "unknown must fail closed");
    }

    #[test]
    fn recorded_actions_verify_and_survive_reopen() {
        let dir = tmp_dir();
        {
            let w = Warden::open(&dir).unwrap();
            let v = w.decide("memory.search");
            w.record("KERNEL", "memory.search", "b3:aa", &v, "auto", "b3:res", 1000).unwrap();
        }
        // reopen (loads the same persisted key) and append + verify
        let w2 = Warden::open(&dir).unwrap();
        let v = w2.decide("email.send");
        w2.record("ENVOY", "email.send", "b3:bb", &v, "none", "blocked:queued", 1001).unwrap();
        assert_eq!(w2.verify().unwrap(), 2, "the whole log must verify under the persisted key");
    }
}
