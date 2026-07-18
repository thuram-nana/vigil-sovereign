//! Memory bridge — the KERNEL reaches the Phase-0 memory substrate (the Python `sigil` package)
//! by shelling out to its CLI. Read-only from the KERNEL's side; the memory owns its own
//! integrity + provenance. A clean process boundary keeps the Rust KERNEL decoupled from the
//! Python memory (which can evolve independently).

use std::io;
use std::process::Command;

const PY: &str = "/home/kali/.sigil/venv/bin/python";

fn sigil(args: &[&str]) -> io::Result<String> {
    let out = Command::new(PY).arg("-m").arg("sigil.cli").args(args).output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("sigil error").to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Cited recall from the episodic spine (A0). Returns the ranked, provenance-tagged results.
pub fn search(query: &str, k: usize) -> io::Result<String> {
    sigil(&["search", query, "-k", &k.to_string()])
}

/// Memory health (record/vector counts + integrity), for `ingest.status`-style answers.
pub fn status() -> io::Result<String> {
    sigil(&["status"])
}
