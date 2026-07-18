//! Cognition cascade dispatch (SIGIL §7). T1/T2 escalations run against Claude via the headless
//! `claude -p` CLI on the Max plan (the same zero-API-cost path SIGIL uses everywhere) — T1 a
//! fast model, T2 a deep one. T0 is the router (see `router`); T3 specialists are later phases.

use std::io;
use std::process::Command;

const CLAUDE: &str = "/home/kali/.local/bin/claude";

/// A fast frontier model (Haiku-class) — drafts, triage, short answers.
pub const FAST: &str = "claude-haiku-4-5-20251001";
/// A deep frontier model (Sonnet-class) — planning, hard reasoning, code.
pub const DEEP: &str = "claude-sonnet-5";

/// Run a prompt through `claude -p --model <model>` and return its text. The KERNEL treats the
/// output as advisory content; anything with external effect must still cross WARDEN.
pub fn run(prompt: &str, model: &str) -> io::Result<String> {
    let out = Command::new(CLAUDE).args(["-p", prompt, "--model", model]).output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("claude error").to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
