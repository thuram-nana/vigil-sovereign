//! SIGIL KERNEL — the palette (Phase 1). A command interface to the KERNEL: route an intent
//! through the cognition cascade (T0 → answer/escalate/dispatch), gate every tool invocation
//! through WARDEN (tier A0–A3, fail-closed), and append a signed, chained action-log record. The
//! self-audit replays that log verbatim ("what did you do and why", C18). A global hotkey +
//! voice daemon are Phase 1.5/2; this CLI meets the acceptance bar: a full task round-trip,
//! logged & tiered.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use sigil_kernel::crypto::sha256_hex;
use sigil_kernel::router::{route, Route};
use sigil_kernel::tiers::Tier;
use sigil_kernel::warden::{Verdict, Warden};
use sigil_kernel::{anchor, cascade, memory};

#[derive(Parser)]
#[command(name = "sigil-kernel", about = "SIGIL KERNEL — routed, gated, logged intent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Route an intent through the cascade (T0 classify → dispatch), gated + logged by WARDEN.
    Ask {
        #[arg(required = true, trailing_var_arg = true)]
        intent: Vec<String>,
    },
    /// Invoke a named tool directly through WARDEN — demonstrates tier classification + gating.
    Do {
        tool: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Classify a tool name → its WARDEN tier + gate decision, and return it. This is an A0
    /// OBSERVATION: it writes NO action-log record. It is the authoritative tiering oracle the
    /// Python mesh consults so a Proposal's tier is DERIVED from the fail-closed Rust classifier
    /// (via the raise-only registry) rather than self-declared.
    Classify {
        tool: String,
        /// Emit machine-readable JSON ({"tier":"A3","decision":"explicit-required"}).
        #[arg(long)]
        json: bool,
    },
    /// Replay the signed action log verbatim (self-audit, C18).
    Audit,
    /// Verify the action log's chain + signatures + the spine-anchored anti-rollback high-water.
    /// FAILS CLOSED if the anchor is unreachable/unestablished; pass --allow-unanchored for a
    /// genuine first run / offline check (weaker: local integrity only).
    Verify {
        #[arg(long)]
        allow_unanchored: bool,
    },
    /// Cross-anchor the current action-log head into the append-only Phase-0 spine (anti-rollback).
    Checkpoint,
    /// Print the WARDEN public key.
    Pubkey,
}

fn warden_dir() -> PathBuf {
    let home = std::env::var("SIGIL_HOME")
        .unwrap_or_else(|_| format!("{}/.sigil", std::env::var("HOME").unwrap_or_else(|_| ".".into())));
    PathBuf::from(home).join("warden")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn args_hash(s: &str) -> String {
    format!("b3:{}", &sha256_hex(s.as_bytes())[..12])
}

fn main() {
    let cli = Cli::parse();
    let w = Warden::open(&warden_dir()).unwrap_or_else(|e| {
        eprintln!("cannot open WARDEN: {e}");
        std::process::exit(1);
    });

    match cli.cmd {
        Cmd::Ask { intent } => cmd_ask(&w, &intent.join(" ")),
        Cmd::Do { tool, args } => cmd_do(&w, &tool, &args.join(" ")),
        Cmd::Classify { tool, json } => cmd_classify(&w, &tool, json),
        Cmd::Audit => cmd_audit(&w),
        Cmd::Verify { allow_unanchored } => cmd_verify(&w, allow_unanchored),
        Cmd::Checkpoint => cmd_checkpoint(&w),
        Cmd::Pubkey => println!("{}", w.public_hex()),
    }
}

fn anchor_set(w: &Warden, count: u64, head_hash: &str) -> std::io::Result<()> {
    let pubkey = w.public_hex();
    let sig = w.sign_hex(anchor::anchor_msg(count, head_hash, &pubkey).as_bytes());
    anchor::set(count, head_hash, &pubkey, &sig)
}

/// Anchor the current head into the spine — best-effort, never fatal to the hot path.
fn anchor_head(w: &Warden) {
    if let Ok(Some((count, head_hash))) = w.head() {
        if count > 0 {
            let _ = anchor_set(w, count, &head_hash);
        }
    }
}

fn cmd_checkpoint(w: &Warden) {
    match w.head() {
        Ok(Some((count, head_hash))) => match anchor_set(w, count, &head_hash) {
            Ok(()) => println!("anchored action-log head into the spine: count={count} head={}", &head_hash[..16.min(head_hash.len())]),
            Err(e) => eprintln!("anchor failed: {e}"),
        },
        Ok(None) => println!("nothing to anchor (action log empty)"),
        Err(e) => eprintln!("cannot read head: {e}"),
    }
}

fn cmd_ask(w: &Warden, intent: &str) {
    let r = route(intent);
    // Route → the tool the KERNEL will invoke. Cognition (answer/plan) is A0-class (no external
    // effect); a real agent dispatch is recorded as an A1 intent note (the mesh is Phase 3).
    let tool = match r {
        Route::AnswerLocal => "memory.search",
        Route::EscalateT1 => "cascade.answer.t1",
        Route::EscalateT2 => "cascade.answer.t2",
        Route::DispatchAgent => "agent.dispatch.note",
    };
    let v = w.decide(tool);
    println!("[T0 {} → {}]  WARDEN: {} {}", r.as_str(), tool, v.tier, v.decision.as_str());

    if !v.decision.may_run() {
        block(w, "KERNEL", tool, intent, &v);
        return;
    }

    let output = match r {
        Route::AnswerLocal => memory::search(intent, 5).unwrap_or_else(|e| format!("(memory unavailable: {e})")),
        Route::EscalateT1 => cascade::run(intent, cascade::FAST).unwrap_or_else(|e| format!("(T1 unavailable: {e})")),
        Route::EscalateT2 => cascade::run(intent, cascade::DEEP).unwrap_or_else(|e| format!("(T2 unavailable: {e})")),
        Route::DispatchAgent => format!(
            "[dispatch] the agent mesh (ARTIFICER/SCHOLAR/ENVOY) is Phase 3; the KERNEL recorded this intent:\n  {intent}"
        ),
    };
    finish(w, "KERNEL", tool, intent, &v, &output);
}

fn cmd_do(w: &Warden, tool: &str, args: &str) {
    let v = w.decide(tool);
    println!("[direct tool {}]  WARDEN: {} {}", tool, v.tier, v.decision.as_str());
    if !v.decision.may_run() {
        block(w, "KERNEL", tool, args, &v);
        return;
    }
    // v1 has no real tool executors (those are the Phase-3 agents) — record an executed stub so
    // the round-trip + tiering + signed log are demonstrable end-to-end.
    let output = format!("[executed] {tool} {args}").trim_end().to_string();
    finish(w, "KERNEL", tool, args, &v, &output);
}

/// Classify a tool name and return its tier + gate decision. Reuses `Warden::decide` (registry
/// raise-only pins over `tiers::classify`) so it can NEVER disagree with the enforced path, and
/// writes NO action-log record — classification is a pure A0 observation, not an action. The
/// `tier`/`decision` values are the enum `as_str()` forms (fixed ASCII), so the manual JSON needs
/// no escaping.
fn cmd_classify(w: &Warden, tool: &str, json: bool) {
    let v = w.decide(tool);
    if json {
        println!("{{\"tier\":\"{}\",\"decision\":\"{}\"}}", v.tier.as_str(), v.decision.as_str());
    } else {
        println!("[classify {}] {} {}", tool, v.tier, v.decision.as_str());
    }
}

fn finish(w: &Warden, agent: &str, tool: &str, args: &str, v: &Verdict, output: &str) {
    let rh = format!("b3:{}", &sha256_hex(output.as_bytes())[..12]);
    match w.record(agent, tool, &args_hash(args), v, "auto", &rh, now()) {
        Ok(rec) => {
            println!("\n{output}\n");
            println!(
                "[WARDEN {} {} — logged @ action spine seq {} · {}]",
                v.tier, v.decision.as_str(), rec.seq, &rec.entry_hash[..16]
            );
        }
        Err(e) => eprintln!("action-log write failed: {e}"),
    }
}

fn block(w: &Warden, agent: &str, tool: &str, args: &str, v: &Verdict) {
    let need = if v.tier == Tier::A3 { "explicit per-action approval (no promotion)" } else { "one-tap approval" };
    let _ = w.record(agent, tool, &args_hash(args), v, "none", "blocked:awaiting-approval", now());
    println!("[BLOCKED — {} requires {}; not executed. Logged as awaiting-approval.]", v.tier, need);
    anchor_head(w); // protect the evidence that a dangerous action was attempted (anti-rollback)
}

fn cmd_audit(w: &Warden) {
    match w.records() {
        Ok(recs) if recs.is_empty() => println!("(action log empty — no actions yet)"),
        Ok(recs) => {
            println!("SIGIL action spine — {} record(s), verbatim (C18 self-audit):\n", recs.len());
            for r in recs {
                println!(
                    "  seq {:<3} {:<4} {:<20} {:<10} agent={:<10} approver={:<12} ts={}",
                    r.seq, r.tier, r.tool, r.decision, r.agent, r.approver, r.ts
                );
            }
        }
        Err(e) => eprintln!("audit failed: {e}"),
    }
}

fn cmd_verify(w: &Warden, allow_unanchored: bool) {
    let n = match w.verify() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("action log FAIL: {e}");
            std::process::exit(2);
        }
    };
    let on_disk = w.head().ok().flatten().map(|(c, _)| c).unwrap_or(0);

    // Cross-check the spine-anchored monotonic high-water. The anchor read itself FAILS CLOSED:
    // a bridge error, a tampered spine (the bridge exits non-zero), OR an established-but-now-zero
    // high-water are all treated as UNVERIFIABLE — because the checker (bridge + spine) is under
    // the same file-write attacker the anchor defends against, resolving its failure as "OK" would
    // hand the attacker a clean bill. `--allow-unanchored` is the explicit escape for a genuine
    // first run / offline check.
    match anchor::high_water(&w.public_hex()) {
        Ok((hw, _)) if on_disk < hw => {
            eprintln!("action log FAIL: ROLLBACK — on-disk head count {on_disk} < spine-anchored high-water {hw} (recent records erased)");
            std::process::exit(2);
        }
        Ok((hw, _)) if hw > 0 => {
            println!("action log OK: {n} record(s) verify — chain + signatures + anti-rollback anchor (spine high-water {hw})");
        }
        // hw == 0 (never anchored for this key) or Err (bridge/spine unavailable) → unverifiable
        other => {
            if allow_unanchored {
                let why = if other.is_ok() { "no anchor established yet" } else { "anchor bridge unavailable" };
                println!("action log OK (LOCAL ONLY): {n} record(s) verify — chain + signatures; anti-rollback UNVERIFIED ({why}, --allow-unanchored)");
            } else if n == 0 {
                println!("action log OK: empty log, nothing to anchor");
            } else {
                eprintln!("action log UNVERIFIABLE: {n} record(s) pass local checks but the anti-rollback anchor is unreachable/unestablished — cannot certify freshness (a rollback+bridge-sabotage looks identical). Re-run with --allow-unanchored only if this is a genuine first run/offline.");
                std::process::exit(3);
            }
        }
    }
}
