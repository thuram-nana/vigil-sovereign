//! The WARDEN signed action spine (SIGIL §5, Appendix A). Every tool invocation appends
//! `{ts, agent, tool, args_hash, tier, decision, approver, result_hash, prev_hash, sig}` — the
//! same hash-chain + Ed25519 construction as the Phase-0 episodic spine, pointed inward. Each
//! record is individually signed AND chained, so a tampered field, a reorder, or a middle
//! deletion is caught at the exact seq; `ts` IS bound into the digest (timestamps are
//! tamper-evident). A separately-signed HEAD (count + tip entry_hash + high-water seq) anchors
//! the log's LENGTH, catching a tail-truncation or wipe THAT IS NOT ACCOMPANIED by a matching head.
//!
//! ROLLBACK: because THIS local verify() is stateless and heads are non-secret, an attacker with
//! file-write who retained an OLDER validly-signed head can overwrite both the log (old valid
//! prefix) and the head (old signed head) — the shorter log then equals the old head's count and
//! this local check passes. A signature proves authenticity, not FRESHNESS. That gap is closed at
//! the KERNEL layer (`anchor` + `sigil-kernel verify`): each head {count, head_hash} is
//! cross-checkpointed, keyed by the WARDEN pubkey, into the append-only, separately-signed,
//! ACTIVELY-GROWING Phase-0 spine, and the KERNEL's verify rejects any on-disk head whose count is
//! below the highest ever anchored. Rolling THAT back too means rolling back the spine — loud (the
//! owner's recent memory vanishes, ingest cursors break). Residual: a full double-wipe + fresh key
//! evades detection but changes the visible WARDEN pubkey; hardware/remote monotonic state is the
//! only absolute defense for a local audit log.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{sha256_hex, verify_hex, WardenKey};

const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// An exclusive advisory file lock (A10 — unlocked-sequence-counter fix). Held for the whole
/// read-seq → append → write-head critical section so two concurrent `append()`s (separate
/// processes OR threads — each `acquire` opens a fresh file description) can never both read the
/// same last seq and mint a DUPLICATE seq / a torn head. `flock(LOCK_EX)` is auto-released by the
/// kernel if the holder dies (no stale lock, unlike an O_EXCL lockfile). Advisory: it only
/// serialises callers that also take the lock — which is every writer here (`append`).
struct FileLock {
    file: std::fs::File,
}

impl FileLock {
    fn acquire(lock_path: &Path) -> io::Result<FileLock> {
        let file = OpenOptions::new().create(true).write(true).truncate(false).open(lock_path)?;
        // SAFETY: fd is valid for the lifetime of `file`; LOCK_EX blocks until the lock is ours.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileLock { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Explicit unlock (closing the fd would release it too, but be explicit + robust).
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// The digested content of an action — everything the signature must commit to. `ts` IS
/// included (an audit log's "when" must be tamper-evident). Fixed field order ⇒ deterministic.
#[derive(Serialize)]
struct Content<'a> {
    ts: &'a str,
    agent: &'a str,
    tool: &'a str,
    args_hash: &'a str,
    tier: &'a str,
    decision: &'a str,
    approver: &'a str,
    result_hash: &'a str,
}

#[derive(Serialize)]
struct ChainInput<'a> {
    cert_digest: &'a str,
    prev_hash: &'a str,
    seq: u64,
}

#[derive(Serialize)]
struct HeadContent<'a> {
    count: u64,
    last_seq: u64,
    head_hash: &'a str,
}

#[derive(Serialize, Deserialize)]
struct HeadRecord {
    count: u64,
    last_seq: u64,
    head_hash: String,
    sig: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ActionRecord {
    pub seq: u64,
    pub ts: String,
    pub agent: String,
    pub tool: String,
    pub args_hash: String,
    pub tier: String,
    pub decision: String,
    pub approver: String,
    pub result_hash: String,
    pub cert_digest: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub sig: String,
}

impl ActionRecord {
    fn compute_digest(&self) -> String {
        let c = Content {
            ts: &self.ts, agent: &self.agent, tool: &self.tool, args_hash: &self.args_hash,
            tier: &self.tier, decision: &self.decision, approver: &self.approver, result_hash: &self.result_hash,
        };
        sha256_hex(&serde_json::to_vec(&c).expect("content serializes"))
    }

    fn compute_entry_hash(&self) -> String {
        let ci = ChainInput { cert_digest: &self.cert_digest, prev_hash: &self.prev_hash, seq: self.seq };
        sha256_hex(&serde_json::to_vec(&ci).expect("chain input serializes"))
    }
}

pub struct ActionLog {
    path: PathBuf,
}

impl ActionLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        ActionLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn head_path(&self) -> PathBuf {
        self.path.with_extension("head.json")
    }

    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("lock")
    }

    pub fn records(&self) -> io::Result<Vec<ActionRecord>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<ActionRecord>(line) {
                Ok(r) => out.push(r),
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
        }
        Ok(out)
    }

    fn write_head(&self, key: &WardenKey, count: u64, last_seq: u64, head_hash: &str) -> io::Result<()> {
        let hc = HeadContent { count, last_seq, head_hash };
        let digest = sha256_hex(&serde_json::to_vec(&hc).expect("head content serializes"));
        let hr = HeadRecord {
            count, last_seq, head_hash: head_hash.to_string(),
            sig: key.sign_hex(digest.as_bytes()),
        };
        let body = serde_json::to_string(&hr).expect("head serializes");
        // ATOMIC head write (A10 — non-atomic-head fix): write a temp beside the head, fsync it, then
        // rename over the head. rename(2) within a dir is atomic on POSIX, so a crash mid-write can never
        // leave a torn/empty head that verify() would read as a rollback. The temp is per-dir (same
        // filesystem, so rename is a metadata op, never a cross-device copy).
        let head = self.head_path();
        let tmp = head.with_extension("json.tmp");
        {
            let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &head)
    }

    /// The on-disk signed head as (count, head_hash), or None if no head file. For the
    /// anti-rollback anchor comparison; use `verify` for trust (it checks the head signature).
    pub fn head(&self) -> io::Result<Option<(u64, String)>> {
        Ok(self.read_head()?.map(|h| (h.count, h.head_hash)))
    }

    fn read_head(&self) -> io::Result<Option<HeadRecord>> {
        match std::fs::read_to_string(self.head_path()) {
            Ok(t) => serde_json::from_str(&t)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Append a signed, chained action record and re-anchor the signed head. `ts_epoch` is
    /// passed in (kept pure of wallclock for deterministic tests) and IS bound into the digest.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &self,
        key: &WardenKey,
        agent: &str,
        tool: &str,
        args_hash: &str,
        tier: &str,
        decision: &str,
        approver: &str,
        result_hash: &str,
        ts_epoch: u64,
    ) -> io::Result<ActionRecord> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Hold the exclusive lock across read-seq → append → write-head so two concurrent appends can
        // never both read the same last seq and mint a DUPLICATE seq (A10). Released when `_lock` drops.
        let _lock = FileLock::acquire(&self.lock_path())?;

        let existing = self.records()?;
        let (seq, prev_hash) = match existing.last() {
            Some(last) => (last.seq + 1, last.entry_hash.clone()),
            None => (0, GENESIS_PREV.to_string()),
        };
        let mut rec = ActionRecord {
            seq,
            ts: ts_epoch.to_string(),
            agent: agent.to_string(),
            tool: tool.to_string(),
            args_hash: args_hash.to_string(),
            tier: tier.to_string(),
            decision: decision.to_string(),
            approver: approver.to_string(),
            result_hash: result_hash.to_string(),
            cert_digest: String::new(),
            prev_hash,
            entry_hash: String::new(),
            sig: String::new(),
        };
        rec.cert_digest = rec.compute_digest();
        rec.entry_hash = rec.compute_entry_hash();
        rec.sig = key.sign_hex(rec.entry_hash.as_bytes());

        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&rec).expect("record serializes"))?;
        f.sync_all()?;
        self.write_head(key, seq + 1, seq, &rec.entry_hash)?;
        Ok(rec)
    }

    /// Full verification: (1) each record's content re-hashes to its cert_digest and entry_hash;
    /// (2) prev_hash links and seq is contiguous; (3) each entry_hash's Ed25519 signature; (4)
    /// the signed HEAD anchors the log's length — a chain shorter than the head is a rollback.
    /// Returns the verified record count, or an error naming the exact defect.
    pub fn verify(&self, pub_hex: &str) -> Result<usize, String> {
        let recs = self.records().map_err(|e| format!("read error: {e}"))?;
        let mut prev = GENESIS_PREV.to_string();
        for (i, r) in recs.iter().enumerate() {
            if r.seq != i as u64 {
                return Err(format!("chain break at index {i}: seq is {} (expected {i})", r.seq));
            }
            if r.prev_hash != prev {
                return Err(format!("chain break at seq {}: prev_hash mismatch (reorder/delete)", r.seq));
            }
            if r.compute_digest() != r.cert_digest {
                return Err(format!("binding break at seq {}: content does not match cert_digest (tampered)", r.seq));
            }
            if r.compute_entry_hash() != r.entry_hash {
                return Err(format!("binding break at seq {}: entry_hash mismatch (tampered)", r.seq));
            }
            if !verify_hex(r.entry_hash.as_bytes(), &r.sig, pub_hex) {
                return Err(format!("signature invalid at seq {} (forged/unsigned)", r.seq));
            }
            prev = r.entry_hash.clone();
        }

        // anchor the LENGTH against the signed head (catches tail-truncation / wipe / rollback)
        let head = self.read_head().map_err(|e| format!("head read error: {e}"))?;
        match head {
            None => {
                if recs.is_empty() {
                    Ok(0)
                } else {
                    Err("records present but NO signed head — the head was deleted (truncation/tamper)".into())
                }
            }
            Some(h) => {
                let hc = HeadContent { count: h.count, last_seq: h.last_seq, head_hash: &h.head_hash };
                let digest = sha256_hex(&serde_json::to_vec(&hc).map_err(|e| e.to_string())?);
                if !verify_hex(digest.as_bytes(), &h.sig, pub_hex) {
                    return Err("signed head signature invalid (forged/foreign key)".into());
                }
                let n = recs.len() as u64;
                if n < h.count {
                    return Err(format!(
                        "TRUNCATED: {n} record(s) on disk but the signed head anchors {} (rollback/wipe)",
                        h.count
                    ));
                }
                if h.count == 0 {
                    if n > 0 {
                        return Err("signed head says empty but records exist".into());
                    }
                    return Ok(0);
                }
                let anchor = &recs[(h.count - 1) as usize];
                if anchor.entry_hash != h.head_hash || anchor.seq != h.last_seq {
                    return Err(format!(
                        "signed head does not match the chain at seq {} (history rewritten)", h.last_seq
                    ));
                }
                // n == count ⇒ current; n > count ⇒ benign crash-appended (extras are validly signed)
                Ok(n as usize)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_log() -> (ActionLog, WardenKey) {
        let mut p = std::env::temp_dir();
        p.push(format!("sigil-al-{}.jsonl", sha256_hex(format!("{:?}", std::thread::current().id()).as_bytes())));
        let log = ActionLog::new(p);
        let _ = std::fs::remove_file(log.path());
        let _ = std::fs::remove_file(log.head_path());
        (log, WardenKey::generate())
    }

    fn add(log: &ActionLog, key: &WardenKey, tool: &str, tier: &str, ts: u64) {
        log.append(key, "KERNEL", tool, "b3:a", tier, "auto", "auto", "b3:r", ts).unwrap();
    }

    #[test]
    fn append_and_verify_clean() {
        let (log, key) = tmp_log();
        add(&log, &key, "memory.search", "A0", 1000);
        add(&log, &key, "memory.write", "A1", 1001);
        assert_eq!(log.verify(&key.public_hex()).unwrap(), 2);
    }

    #[test]
    fn field_tamper_is_caught() {
        let (log, key) = tmp_log();
        add(&log, &key, "memory.search", "A0", 1000);
        add(&log, &key, "email.send", "A2", 1001);
        let text = std::fs::read_to_string(log.path()).unwrap();
        std::fs::write(log.path(), text.replacen("\"tier\":\"A2\"", "\"tier\":\"A0\"", 1)).unwrap();
        let err = log.verify(&key.public_hex()).unwrap_err();
        assert!(err.contains("binding break") && err.contains("seq 1"), "{err}");
    }

    #[test]
    fn ts_tamper_is_caught() {
        // regression for the forgeable-timestamp finding — ts is now in the signed digest
        let (log, key) = tmp_log();
        add(&log, &key, "email.send", "A2", 1700000000);
        let text = std::fs::read_to_string(log.path()).unwrap();
        std::fs::write(log.path(), text.replacen("\"ts\":\"1700000000\"", "\"ts\":\"9999999999\"", 1)).unwrap();
        let err = log.verify(&key.public_hex()).unwrap_err();
        assert!(err.contains("binding break"), "a rewritten ts must break the digest: {err}");
    }

    #[test]
    fn middle_delete_is_caught() {
        let (log, key) = tmp_log();
        for i in 0..3 {
            add(&log, &key, "memory.search", "A0", 1000 + i);
        }
        let t = std::fs::read_to_string(log.path()).unwrap();
        let v: Vec<&str> = t.lines().collect();
        std::fs::write(log.path(), format!("{}\n{}\n", v[0], v[2])).unwrap();
        let err = log.verify(&key.public_hex()).unwrap_err();
        assert!(err.contains("chain break"), "{err}");
    }

    #[test]
    fn tail_truncation_is_caught() {
        // the CRITICAL finding: removing the LAST record(s) must fail via the signed head anchor
        let (log, key) = tmp_log();
        for i in 0..4 {
            add(&log, &key, "memory.search", "A0", 1000 + i);
        }
        let t = std::fs::read_to_string(log.path()).unwrap();
        let v: Vec<&str> = t.lines().collect();
        // keep only the first 2 records (drop seq 2 and 3) — a valid chain PREFIX
        std::fs::write(log.path(), format!("{}\n{}\n", v[0], v[1])).unwrap();
        let err = log.verify(&key.public_hex()).unwrap_err();
        assert!(err.contains("TRUNCATED"), "tail truncation must be caught by the head anchor: {err}");
    }

    #[test]
    fn log_wipe_is_caught() {
        // wiping the log while the signed head remains must fail (not report a clean empty log)
        let (log, key) = tmp_log();
        add(&log, &key, "git.push", "A3", 1000);
        std::fs::write(log.path(), "").unwrap();
        let err = log.verify(&key.public_hex()).unwrap_err();
        assert!(err.contains("TRUNCATED"), "a wiped log must be caught while the head stands: {err}");
    }

    #[test]
    fn head_deletion_is_caught() {
        let (log, key) = tmp_log();
        add(&log, &key, "memory.search", "A0", 1000);
        std::fs::remove_file(log.head_path()).unwrap();
        let err = log.verify(&key.public_hex()).unwrap_err();
        assert!(err.contains("NO signed head"), "deleting the head must be caught: {err}");
    }

    #[test]
    fn foreign_key_fails() {
        let (log, key) = tmp_log();
        add(&log, &key, "memory.search", "A0", 1000);
        let other = WardenKey::generate();
        let err = log.verify(&other.public_hex()).unwrap_err();
        assert!(err.contains("signature invalid"), "{err}");
    }

    #[test]
    fn concurrent_appends_get_unique_contiguous_seqs() {
        // A10 regression: WITHOUT the flock, two threads read the same last seq and mint a DUPLICATE
        // seq (a chain break). With the exclusive lock, N concurrent appenders serialise, so the seqs
        // are exactly 0..N with no gap/dup and verify() passes.
        use std::sync::Arc;
        let mut p = std::env::temp_dir();
        p.push(format!("sigil-al-concurrent-{}.jsonl",
            sha256_hex(format!("{:?}", std::thread::current().id()).as_bytes())));
        let log = ActionLog::new(&p);
        let _ = std::fs::remove_file(log.path());
        let _ = std::fs::remove_file(log.head_path());
        let _ = std::fs::remove_file(log.lock_path());
        let key = Arc::new(WardenKey::generate());

        let threads = 8u64;
        let per = 6u64;
        let handles: Vec<_> = (0..threads).map(|t| {
            let path = p.clone();
            let key = Arc::clone(&key);
            std::thread::spawn(move || {
                let log = ActionLog::new(&path);
                for i in 0..per {
                    log.append(&key, "KERNEL", "memory.search", "b3:a", "A0", "auto", "auto", "b3:r",
                               t * 1000 + i).unwrap();
                }
            })
        }).collect();
        for h in handles {
            h.join().unwrap();
        }

        let recs = log.records().unwrap();
        assert_eq!(recs.len() as u64, threads * per, "every append must have landed");
        let mut seqs: Vec<u64> = recs.iter().map(|r| r.seq).collect();
        seqs.sort_unstable();
        let expected: Vec<u64> = (0..threads * per).collect();
        assert_eq!(seqs, expected, "seqs must be unique + contiguous — a duplicate proves the lock failed");
        assert_eq!(log.verify(&key.public_hex()).unwrap() as u64, threads * per,
                   "the concurrently-built chain must verify (chain + signatures + head anchor)");
    }

    #[test]
    fn head_write_is_atomic_and_leaves_no_tmp() {
        // A10: the head is written temp+rename. After an append the head verifies and NO stale
        // `.head.json.tmp` is left behind (a torn temp must never be mistaken for the head).
        let (log, key) = tmp_log();
        add(&log, &key, "memory.search", "A0", 1000);
        add(&log, &key, "email.send", "A2", 1001);
        assert_eq!(log.verify(&key.public_hex()).unwrap(), 2);
        let tmp = log.head_path().with_extension("json.tmp");
        assert!(!tmp.exists(), "the atomic head write must not leave a temp file: {tmp:?}");
        assert!(log.head_path().exists(), "the head must exist after append");
    }
}
