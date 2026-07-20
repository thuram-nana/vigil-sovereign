//! Per-tool tier registry (Phase 1.1) — the auditable complement to name-inference. A pin makes
//! classification EXPLICIT for a named tool. Crucially it is **RAISE-ONLY**: the effective tier
//! is `max(pin, inferred)`, so the override file (`~/.sigil/warden/tools.json`, plain text a
//! file-write attacker could edit) can only ever make a tool MORE gated, never less — it can
//! never downgrade `git.push` to auto. Legitimate de-escalation is intentionally NOT available
//! via an unsigned file (that would need a signed mechanism; a future addition).

use std::collections::HashMap;
use std::path::Path;

use crate::tiers::{classify, Tier};

pub struct Registry {
    pins: HashMap<String, Tier>,
}

fn parse_tier(s: &str) -> Option<Tier> {
    match s.trim().to_ascii_uppercase().as_str() {
        "A0" => Some(Tier::A0),
        "A1" => Some(Tier::A1),
        "A2" => Some(Tier::A2),
        "A3" => Some(Tier::A3),
        _ => None,
    }
}

impl Registry {
    pub fn empty() -> Self {
        Registry { pins: HashMap::new() }
    }

    /// Load raise-only pins from a JSON object `{ "tool.name": "A2", ... }`. Unreadable/absent
    /// file or malformed entries are ignored (the inference engine still governs). Never fails.
    pub fn load(path: &Path) -> Self {
        let mut r = Registry::empty();
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&text) {
                for (tool, tier_s) in map {
                    if let Some(t) = parse_tier(&tier_s) {
                        // case-colliding keys resolve to the HIGHER tier (deterministic +
                        // raise-only-consistent), never last-writer-wins by hash order.
                        let key = tool.to_ascii_lowercase();
                        let eff = r.pins.get(&key).map_or(t, |&e| e.max(t));
                        r.pins.insert(key, eff);
                    }
                }
            }
        }
        r
    }

    /// The effective tier: `max(pin, inferred)`. A pin can only RAISE (never lower) the
    /// token-inference result, so the override file is not a downgrade attack surface.
    pub fn tier(&self, tool: &str) -> Tier {
        let inferred = classify(tool);
        match self.pins.get(&tool.to_ascii_lowercase()) {
            Some(&pinned) => pinned.max(inferred),
            None => inferred,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_can_raise_but_never_lower() {
        let mut r = Registry::empty();
        r.pins.insert("custom.report".into(), Tier::A3); // owner marks a report tool extra-sensitive
        assert_eq!(r.tier("custom.report"), Tier::A3, "pin raises A1→A3");

        // an ATTACKER pinning a dangerous tool to A0 must NOT downgrade it
        r.pins.insert("git.push".into(), Tier::A0);
        assert_eq!(r.tier("git.push"), Tier::A3, "raise-only: a pin can never lower git.push below its inferred A3");

        // a pin at/below the inferred tier is a no-op
        r.pins.insert("memory.search".into(), Tier::A0);
        assert_eq!(r.tier("memory.search"), Tier::A0);
    }

    #[test]
    fn case_colliding_pins_resolve_to_the_higher_tier_deterministically() {
        let mut p = std::env::temp_dir();
        p.push(format!("sigil-reg-{}.json", std::process::id()));
        // both keys lowercase to "note.write"; last-writer-wins would be nondeterministic
        std::fs::write(&p, r#"{"Note.Write":"A2","note.write":"A1"}"#).unwrap();
        let r = Registry::load(&p);
        assert_eq!(r.tier("note.write"), Tier::A2, "collision → max pin (A2), raised from inferred A1");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unregistered_tools_fall_through_to_inference() {
        let r = Registry::empty();
        assert_eq!(r.tier("memory.search"), Tier::A0);
        assert_eq!(r.tier("memory.encrypt"), Tier::A3);
        assert_eq!(r.tier("totally.unknown"), Tier::A3); // fail-closed inference
    }
}
