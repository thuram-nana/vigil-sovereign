//! Cryptographic substrate for WARDEN — the same construction as the Phase-0 episodic spine
//! (canonical JSON → SHA-256 digest → hash chain → Ed25519 signature), pointed INWARD at the
//! action log. Self-consistent: the KERNEL signs and verifies its own log; a tampered or
//! reordered action record fails verification at the exact seq.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// The owner's WARDEN signing key. Lives locally, 0600 — a deliberate single-owner
/// simplification appropriate to this personal, local-first threat model (SIGIL §1.3).
pub struct WardenKey {
    signing: SigningKey,
}

impl WardenKey {
    pub fn generate() -> Self {
        use rand_core::OsRng;
        WardenKey { signing: SigningKey::generate(&mut OsRng) }
    }

    /// Load the persisted key (validated), or create + persist one (0600) on first use.
    pub fn load_or_create(dir: &Path) -> io::Result<Self> {
        let key_path = dir.join("warden.key");
        let pub_path = dir.join("warden.pub");
        if key_path.exists() {
            let bytes = fs::read(&key_path)?;
            // exactly 32 bytes, and not the all-zero seed (fail closed on a garbage/truncated key)
            if bytes.len() != 32 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "warden.key must be exactly 32 bytes"));
            }
            if bytes.iter().all(|&b| b == 0) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "warden.key is the all-zero seed (invalid)"));
            }
            let arr: [u8; 32] = bytes[..32].try_into().expect("checked len == 32");
            let kp = WardenKey { signing: SigningKey::from_bytes(&arr) };
            // if a public key was persisted, the private key MUST derive it (detects a swap)
            if let Ok(stored_pub) = fs::read_to_string(&pub_path) {
                if stored_pub.trim() != kp.public_hex() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        "warden.key does not derive warden.pub — key mismatch (refusing to sign)"));
                }
            }
            Ok(kp)
        } else {
            fs::create_dir_all(dir)?;
            let kp = WardenKey::generate();
            // create the file with 0600 ALREADY SET, before any secret bytes land — never a
            // window where the private seed is group/world-readable.
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&key_path)?;
            f.write_all(&kp.signing.to_bytes())?;
            f.sync_all()?;
            fs::write(&pub_path, kp.public_hex())?;
            Ok(kp)
        }
    }

    pub fn sign_hex(&self, msg: &[u8]) -> String {
        hex::encode(self.signing.sign(msg).to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }
}

/// Verify an Ed25519 signature (all hex) — returns false on any malformed input (fail-closed).
pub fn verify_hex(msg: &[u8], sig_hex: &str, pub_hex: &str) -> bool {
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pub_bytes = match hex::decode(pub_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = match sig_bytes.as_slice().try_into().map(|b: [u8; 64]| Signature::from_bytes(&b)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk_arr: [u8; 32] = match pub_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_stable() {
        assert_eq!(sha256_hex(b"sigil"), sha256_hex(b"sigil"));
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = WardenKey::generate();
        let sig = kp.sign_hex(b"action");
        assert!(verify_hex(b"action", &sig, &kp.public_hex()));
        assert!(!verify_hex(b"tampered", &sig, &kp.public_hex()), "wrong message must fail");
        assert!(!verify_hex(b"action", &sig, "deadbeef"), "malformed pubkey must fail closed");
    }
}
