//! FAST, deterministic counterpart to the coverage-guided WARDEN fuzz target (W11-3, issue #484).
//!
//! cargo-fuzz needs a nightly libFuzzer runtime and cannot run on the ordinary PR runner, so the SLOW
//! coverage-guided fuzz is a SCHEDULED job (.github/workflows/mutation-fuzz.yml). This file is its
//! required-job stand-in: it runs in the required `WARDEN Rust kernel (A10 durability)` job via
//! `cargo test`, and it exercises the SAME invariant oracle the fuzz target asserts
//! (`tiers::invariant_violation`) over (a) the committed seed corpus and (b) a bounded, RNG-free
//! generated space — plus a NEGATIVE CONTROL proving the oracle actually bites.

use sigil_kernel::tiers::{classify, invariant_violation, Tier};

#[test]
fn committed_corpus_satisfies_the_classifier_invariants() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/warden_classify");
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("fuzz corpus dir {dir} unreadable: {e}"));
    let mut n = 0usize;
    for e in entries {
        let p = e.expect("dir entry").path();
        if !p.is_file() {
            continue;
        }
        let bytes = std::fs::read(&p).expect("read corpus seed");
        // Lossy decode: the corpus deliberately includes a non-UTF-8 seed, matching the fuzz target.
        let tool = String::from_utf8_lossy(&bytes);
        let tier = classify(&tool);
        assert!(
            invariant_violation(&tool, tier).is_none(),
            "corpus seed {p:?} ({tool:?}) -> {tier} violates an invariant: {:?}",
            invariant_violation(&tool, tier)
        );
        n += 1;
    }
    assert!(n >= 8, "expected the committed fuzz corpus to seed >=8 inputs, found {n}");
}

#[test]
fn deterministic_generated_space_never_violates_the_invariants() {
    // A bounded, exhaustive, RNG-free sweep — verb x target x separator, in both orders and with a
    // trailing token — so a regression that (say) let a danger token ride a separator down a tier is
    // caught fast in the required job, without waiting for the scheduled fuzz to rediscover it.
    let verbs = [
        "read", "search", "write", "commit", "send", "export", "push", "delete", "encrypt",
        "restore", "overwrite", "get", "forget", "sign", "unknownverb",
    ];
    let targets = [
        "memory", "graph", "budget", "secrets", "vault", "iam", "prod", "file", "config", "",
    ];
    let seps = [".", "_", "-", "/", " ", "\u{1c}"];
    for v in verbs {
        for t in targets {
            for s in seps {
                for name in [
                    format!("{t}{s}{v}"),
                    format!("{v}{s}{t}"),
                    format!("{t}{s}{v}{s}extra"),
                ] {
                    let tier = classify(&name);
                    assert!(
                        invariant_violation(&name, tier).is_none(),
                        "generated name {name:?} -> {tier} violates an invariant"
                    );
                }
            }
        }
    }
}

#[test]
fn negative_control_a_broken_always_a0_classifier_is_flagged() {
    // Prove the invariant oracle is not a no-op. A deliberately-broken classifier that returns A0 for
    // EVERYTHING must be flagged the instant it mislabels a danger-token name — otherwise the fuzz
    // target (which panics on `Some(reason)`) would rubber-stamp a fail-open regression.
    fn broken_classify(_tool: &str) -> Tier {
        Tier::A0
    }
    for danger in ["git.push", "secrets.read", "budget.get", "config.overwrite"] {
        assert!(
            invariant_violation(danger, broken_classify(danger)).is_some(),
            "a danger-token name mislabelled A0 MUST be reported by the invariant oracle: {danger:?}"
        );
        // control for the control: the REAL classifier is NOT flagged on the same input.
        assert!(
            invariant_violation(danger, classify(danger)).is_none(),
            "the real classifier must satisfy its own invariants for {danger:?}"
        );
    }
}
