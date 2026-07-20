//! SIGIL KERNEL library (Phase 1). The Rust core: WARDEN authorization + signed action log,
//! the cognition-cascade router, and the memory bridge. Offense-free by doctrine — it
//! orchestrates and gates; it never scans, exploits, or targets third parties.

pub mod actionlog;
pub mod anchor;
pub mod cascade;
pub mod crypto;
pub mod memory;
pub mod registry;
pub mod router;
pub mod tiers;
pub mod warden;
