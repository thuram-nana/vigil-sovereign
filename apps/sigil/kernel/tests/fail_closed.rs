//! A10 fail-closed integration tests (red-pen regression). When the action-log append fails, the
//! kernel must NOT print a false success and exit 0 — it must fail closed (exit non-zero) so an
//! unauditable action is never swallowed. Covers BOTH paths:
//!   * `finish()`  — the A0/A1 auto-run path (a safe tool ran);
//!   * `block()`   — the A2/A3 dangerous path (the more security-sensitive one the first fix missed).
//!
//! We force the record failure deterministically by pre-creating the action-log PATH as a DIRECTORY
//! under a throwaway SIGIL_HOME: `Warden::open` still succeeds (it only creates `warden/keys`), but the
//! first `append()` reads/opens `warden/actionlog.jsonl` — a directory — and errors, so `record()` fails.

use std::path::PathBuf;
use std::process::Command;

fn broken_home(tag: &str) -> PathBuf {
    let mut home = std::env::temp_dir();
    home.push(format!("sigil-failclosed-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let warden = home.join("warden");
    std::fs::create_dir_all(&warden).unwrap();
    // the action-log path is a DIRECTORY -> append()'s read/open of it errors -> record() fails
    std::fs::create_dir_all(warden.join("actionlog.jsonl")).unwrap();
    home
}

fn run(home: &PathBuf, tool: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil-kernel"))
        .env("SIGIL_HOME", home)
        // isolate the anti-rollback bridge from a real venv so the anchor never interferes with the exit code
        .env("SIGIL_KERNEL_PYTHON", "/nonexistent/python")
        .args(["do", tool])
        .output()
        .expect("kernel binary runs")
}

#[test]
fn dangerous_a3_attempt_fails_closed_when_audit_write_fails() {
    let home = broken_home("a3");
    let out = run(&home, "git.push"); // A3 -> block()
    let _ = std::fs::remove_dir_all(&home);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(4),
        "a BLOCKED A3 attempt whose audit write fails must fail-closed (exit 4); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout.contains("Logged as awaiting-approval"),
        "must NOT print a false 'Logged as awaiting-approval' when the audit write failed; stdout={stdout}"
    );
}

#[test]
fn safe_a0_action_fails_closed_when_audit_write_fails() {
    let home = broken_home("a0");
    let out = run(&home, "memory.search"); // A0 -> finish()
    let _ = std::fs::remove_dir_all(&home);
    assert_eq!(
        out.status.code(),
        Some(4),
        "an A0 auto-run whose audit write fails must fail-closed (exit 4); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_healthy_home_does_not_fail_closed() {
    // Control: with a WRITABLE home the same commands succeed (exit 0), proving exit 4 is caused by the
    // audit-write failure, not by the command itself.
    let mut home = std::env::temp_dir();
    home.push(format!("sigil-ok-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("warden")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sigil-kernel"))
        .env("SIGIL_HOME", &home)
        .env("SIGIL_KERNEL_PYTHON", "/nonexistent/python") // no anchor bridge, but the append SUCCEEDS
        .args(["do", "git.push"])
        .output()
        .expect("kernel binary runs");
    let _ = std::fs::remove_dir_all(&home);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a healthy home must exit 0 (the block is logged, not fail-closed); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Logged as awaiting-approval"),
        "a healthy block must log the awaiting-approval record"
    );
}
