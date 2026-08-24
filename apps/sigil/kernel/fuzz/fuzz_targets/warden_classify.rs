#![no_main]
//! Coverage-guided fuzz target for the WARDEN tool-name classifier (W11-3, issue #484).
//!
//! The classifier is the single choke point every tool invocation crosses; a bug that lowers a
//! dangerous name below A3, or reaches A0 without a positive allowlist match, is a fail-OPEN. This
//! target drives arbitrary bytes through `classify` and asserts, on EVERY input, the fail-closed
//! safety invariants defined ONCE in `tiers::invariant_violation` (shared with the required smoke
//! test tests/fuzz_smoke.rs, so the two cannot drift). A libFuzzer "crash" here is a real safety bug.
use libfuzzer_sys::fuzz_target;
use sigil_kernel::tiers::{classify, invariant_violation};

fuzz_target!(|data: &[u8]| {
    // Lossy so ALL bytes are exercised (a non-UTF-8 name still reaches classify() as a &str in prod
    // paths that decode leniently); totality means classify must never panic on any of them.
    let tool = String::from_utf8_lossy(data);
    let tier = classify(&tool);
    if let Some(reason) = invariant_violation(&tool, tier) {
        panic!("WARDEN classifier invariant violated for {tool:?} -> {tier}: {reason}");
    }
});
