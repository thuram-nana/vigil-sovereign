//! Anti-rollback anchor (Phase 1.1). Cross-checkpoints the WARDEN action-log head into the
//! append-only, separately-signed, ACTIVELY-GROWING Phase-0 episodic spine. A file-write
//! attacker who rolls the WARDEN log back to an older (validly-signed) head must ALSO roll the
//! spine back below the anchored high-water — which is loud: the owner's recent memory would
//! vanish and ingest cursors would break. `verify` rejects an on-disk head whose count is below
//! the highest ever anchored. (Local-only audit logs cannot be made fully rollback-proof without
//! hardware/remote monotonic state; this ties WARDEN's freshness to the loudly-growing spine.)

use std::io;
use std::path::Path;
use std::process::Command;

/// Resolve the sigil Python interpreter (A10 — de-hardcode `/home/kali/.sigil/venv/bin/python`).
/// Order: an explicit `SIGIL_KERNEL_PYTHON` override, then the venv under `SIGIL_HOME` (mirroring
/// the kernel's `warden_dir()`), then the default `~/.sigil/venv`, then `python3` on PATH — so the
/// kernel runs under any operator's home/venv layout, not just the build machine's.
fn python() -> String {
    if let Ok(p) = std::env::var("SIGIL_KERNEL_PYTHON") {
        if !p.is_empty() {
            return p;
        }
    }
    let home = std::env::var("SIGIL_HOME")
        .unwrap_or_else(|_| format!("{}/.sigil", std::env::var("HOME").unwrap_or_else(|_| ".".into())));
    let venv = format!("{home}/venv/bin/python");
    if Path::new(&venv).exists() {
        return venv;
    }
    "python3".to_string()
}

fn sigil(args: &[&str]) -> io::Result<String> {
    let out = Command::new(python()).arg("-m").arg("sigil.cli").args(args).output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("sigil error").to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// The message the WARDEN key signs to authenticate an anchor (must match the Python verifier).
pub fn anchor_msg(count: u64, head_hash: &str, pubkey: &str) -> String {
    format!("{count}:{head_hash}:{pubkey}")
}

/// Anchor the current WARDEN head {count, head_hash} into the spine (monotonic high-water),
/// scoped to `pubkey`. `sig` is the WARDEN key's Ed25519 signature over `anchor_msg(...)`, so the
/// spine accepts anchors only from the KERNEL that holds the key (no high-water poisoning).
pub fn set(count: u64, head_hash: &str, pubkey: &str, sig: &str) -> io::Result<()> {
    sigil(&["warden-anchor-set", &count.to_string(), head_hash, pubkey, sig]).map(|_| ())
}

/// The highest WARDEN head ever anchored FOR `pubkey`: (count, head_hash). (0, "") if none.
pub fn high_water(pubkey: &str) -> io::Result<(u64, String)> {
    let out = sigil(&["warden-anchor-get", pubkey])?;
    Ok(parse_high_water(&out))
}

fn parse_high_water(stdout: &str) -> (u64, String) {
    let line = stdout.lines().rev().find(|l| l.trim_start().starts_with('{')).unwrap_or("{}");
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(v) => (
            v.get("count").and_then(|c| c.as_u64()).unwrap_or(0),
            v.get("head_hash").and_then(|h| h.as_str()).unwrap_or("").to_string(),
        ),
        Err(_) => (0, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::{anchor_msg, parse_high_water, python};

    #[test]
    fn python_is_de_hardcoded_and_env_configurable() {
        // A10: the interpreter is no longer a hardcoded build-machine `const`; an explicit override is
        // honored, proving it resolves from the environment. (The venv/PATH fallbacks are box-dependent,
        // so we assert only the deterministic override here.)
        std::env::set_var("SIGIL_KERNEL_PYTHON", "/opt/custom/python");
        assert_eq!(python(), "/opt/custom/python");
        std::env::remove_var("SIGIL_KERNEL_PYTHON");
    }

    #[test]
    fn parses_the_json_line_ignoring_warnings() {
        let out = "some warning\n{\"count\": 7, \"head_hash\": \"deadbeef\"}\n";
        assert_eq!(parse_high_water(out), (7, "deadbeef".to_string()));
        assert_eq!(parse_high_water("garbage"), (0, String::new()));
        assert_eq!(parse_high_water("{}"), (0, String::new()));
    }

    #[test]
    fn anchor_msg_matches_the_python_verifier_format() {
        // must equal Python's f"{count}:{head_hash}:{pubkey}" or the signature won't verify
        assert_eq!(anchor_msg(5, "abc", "pk"), "5:abc:pk");
    }
}
