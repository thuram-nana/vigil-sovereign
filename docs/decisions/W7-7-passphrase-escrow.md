# W7-7 (#465) — Optional m-of-n passphrase escrow (split-knowledge recovery)

Status: implemented. Programme item W7-7. Supersedes the absolute "there is no escrow, by design"
statement in the plain-English chapters with an honest, OPT-IN, off-by-default capability.

## The problem

The off-box backup passphrase is the ONLY key to the encrypted backup and is NEVER stored — this is the
right default for a sovereignty tool (nobody but the operator can ever decrypt the backup), but it makes
passphrase loss **total and permanent**: a forgotten passphrase means the backup — client evidence, the
signed offense spine, the identity keys — is gone. A government deployment that must survive the loss of a
single person's memory needs an alternative that does not hand a recovery copy to a vendor.

## What W7-7 adds

An **optional** m-of-n escrow of the passphrase (Shamir split-knowledge recovery). The operator may split
the passphrase into `n` shares under a threshold `m`, hand each share to a distinct holder, and later have
**any `m`** holders jointly reconstruct the passphrase — while **any `m-1`** learn nothing and cannot
reconstruct. It is **opt-in and off by default**: a deployment that declines it keeps the original
lose-it-and-it-is-gone guarantee, byte-for-byte unchanged.

### The construction (be precise about what is and is not proven)

Splitting the passphrase bytes directly is unsafe: Shamir alone cannot tell a below-threshold or tampered
share set from a valid one — it would return a *wrong* passphrase silently — and storing any commitment to
the passphrase (a hash) next to the shares would expose a weak passphrase to offline guessing. So instead
(`vigil_core.escrow`):

1. mint a fresh, uniformly-random **32-byte master `R`** (high entropy — not the passphrase);
2. **Shamir-split `R`** (m-of-n over GF(2^8), the AES field, with a constant-time table-free field
   multiply) into the shares that go to the holders;
3. **seal the passphrase under `R`** with the already-reviewed AEAD (`vigil_core.sealing.seal`,
   ChaCha20-Poly1305) into a public `sealed_passphrase` blob — safe to store beside the backup.

Recovery reconstructs `R` from `m` shares and **opens the sealed blob under it**. Because the AEAD
authenticates, recovery is **fail-closed**: an insufficient / mismatched / tampered share set reconstructs
the wrong `R`, the tag fails, and recovery raises — a wrong passphrase is *never* surfaced. Because `R` is
32 uniformly-random bytes, the stored blob is **not** subject to offline passphrase guessing: below
threshold `R` is information-theoretically hidden, so the blob is a ciphertext under an unknown uniform key
and leaks nothing about the passphrase.

The share-distribution ceremony (`vigil escrow-passphrase` / `vigil recover-passphrase`) **reuses** the
#438 (W9-5) secure per-host share writer: each share is written 0600, `O_EXCL`, refuse-to-clobber — the
same primitive that keeps a co-signer's destruction key on its own host — because a share is the same kind
of object (secret material that belongs with exactly one holder).

<!-- CLAIM:W7-7 -->

**Registered claim (W7-7, id `W7-7`):** the optional m-of-n passphrase escrow reconstructs the passphrase
only when at least the threshold `m` genuine shares are supplied and NEVER from fewer, fail-closed: below
threshold — or from a mismatched or tampered share set — the reconstructed master fails the
sealed-passphrase AEAD and `recover_passphrase` raises, so no passphrase (not even a wrong one) is ever
returned; the shares are information-theoretically indistinguishable below threshold; and escrow is opt-in
and off by default, so declining it changes nothing.

## The sovereignty trade-off (the honest part)

Escrow is a **named, deliberate trust concession**, not free survivability. With it enabled, **any `m` of
the `n` share-holders can collectively recover the passphrase and thus decrypt the backup.** The
sole-custody property — "only the operator, holding the one passphrase, can ever recover" — is knowingly
traded for survivability of passphrase loss. Concretely:

- The recovery quorum is exactly as trustworthy as the *weakest colluding subset of `m` holders*. Choosing
  `m` and `n`, and **who** holds shares, is the operator's risk decision; the tooling only makes the shares
  easy to keep apart (one per holder, each 0600 on its own host).
- The public `sealed_passphrase` blob is a genuine confidentiality reduction *only* if `R` is protected by
  the threshold — which is exactly the Shamir guarantee. It is safe to store beside the backup **as long as
  fewer than `m` shares are compromised**. If `m` shares AND the blob are compromised, the passphrase is
  recovered; that is the definition of the escrow, not a defect.
- This does **not** weaken the *default* posture. A deployment that never runs `vigil escrow-passphrase`
  has no shares, no sealed blob, and the identical original guarantee. The concession exists only for
  deployments that explicitly choose it.

### What is NOT claimed

- The tooling does **not** prove *where* a share physically lives or that a holder kept it apart — host
  separation is an operational property the one-share-per-file, 0600, `O_EXCL` writer makes the easy path,
  not a fact the cryptography attests (the same honest boundary as W9-5 co-signer enrolment).
- Escrow does not add any recovery path for the *sovereign* owner key or the TPM-sealed KEK; it is strictly
  the off-box **backup passphrase**. The owner-key story is unchanged (re-issue from a new identity).

## Testing

- `packages/core/vigil_core/tests/test_escrow.py` (required job `vigil_core — shared integrity substrate`):
  exhaustive GF(2^8) known-answer vs a textbook reference, a committed split known-answer vector,
  reconstruct-at-threshold for every subset, the **negative control** that every `m-1` subset is refused
  and that a forged below-threshold share fails the AEAD (never a wrong passphrase), an exhaustive
  information-theoretic indistinguishability proof, and the opt-in/default-off gate.
- `integration/tests/test_passphrase_escrow.py` (required job `integration two-env boundary (P5)`): the
  file-distribution ceremony end-to-end against the **real** offense-backup KDF + AEAD context — a
  threshold set of share files recovers a passphrase that opens a body sealed exactly as the backup seals
  it; m-1 files are refused.

## Residuals

- Live use is an operator ceremony: the operator chooses `m`/`n`/holders and distributes the share files;
  nothing here fabricates or transmits a holder's share for them.
- A recovered passphrase is written 0600 and should be used to restore and then deleted; the tooling prints
  that instruction but cannot enforce the deletion.
