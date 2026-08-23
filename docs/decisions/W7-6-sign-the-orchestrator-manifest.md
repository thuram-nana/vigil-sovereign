# W7-6 — Sign the orchestrator MANIFEST.json, and make the default restore authenticated

Issue: [#464](https://github.com/thuram-nana/vigil-sovereign/issues/464) ·
Milestone: W7 — BACKUP / DISASTER RECOVERY ·
Reworked under PR #630 (red-pen NEEDS-REWORK on the original W7-6).
Feeds [W7-4](https://github.com/thuram-nana/vigil-sovereign/issues/462) (destination verification checks a
signed manifest).

## The defect

The two-plane `vigil backup` orchestrator writes a **plaintext, unsigned `MANIFEST.json`** alongside the two
encrypted plane parts. That file is the *index* of what a backup contains — which encrypted file is which
plane, and each part's `sha256` — and `vigil restore` reads those values to **locate and integrity-check every
part before it invokes any leg**. Unsigned, the index could be edited by anyone who can reach the backup at
rest:

- redirect a part's `file` to a different blob;
- **downgrade a `sha256`** *within the index* so an OLD legitimate part is accepted in place of the current
  one (a substitution to a pre-revocation part; the passphrase and the part's *own* inner governance signature
  both still check out, because it is a genuine older part);
- tamper the retention hint or host/metadata.

Each encrypted part already carries its own inner governance signature sealed inside the AEAD body, but that
protects **the part**, not the orchestrator's **index of parts**. The old `_cmd_restore` performed no
signature check at all (observed directly on `origin/main` — an unsigned, attacker-substituted manifest
restored with exit 0 and the offense leg invoked).

## Two threats a bare signature does NOT close by itself

Signing the index closes index-EDIT attacks (part redirect, in-index `sha256` downgrade, retention tamper): an
attacker who reaches the backup at rest cannot alter the signed bytes without invalidating the signature. But
signing alone leaves two threats open, and the honest posture must name them:

1. **Re-mint under a fresh key (authenticity).** A self-describing signature — one that ships the signer
   pubkey next to the signature — proves only integrity to a verifier that does not already know *which* key
   to expect. An attacker who holds NEITHER the governance key NOR the passphrase can still edit
   `MANIFEST.json`, RE-SIGN it under a key **they** generated, rewrite the self-describing sidecar, and a
   verify that does not pin a key will ACCEPT it (returning the attacker's pubkey). This is the exact ATTACK 1
   the red-pen reproduced against the first cut of W7-6.
2. **Rollback to a genuine older signed backup (freshness).** Neither the signature nor an authenticity pin
   makes a backup *fresh*: a whole earlier backup directory — genuinely signed by the real key — still
   verifies. Restoring it rolls the system back to pre-revocation / pre-patch state.

## What this change does

### 1. Domain-separated signature (LOW-4)

`sign_orchestrator_manifest` signs `b"vigil-orch-manifest-v1\x00"` followed by the exact `MANIFEST.json` bytes
(the sidecar schema is bumped `1 -> 2`), consistent with `vigil_core.canonical.evidence_signing_bytes`. A
same-key signature minted by another emitter over some other artifact therefore cannot be replayed as a
manifest signature, and vice-versa. Ed25519 over fixed bytes — deterministic, no wallclock/rng.

### 2. TOFU trust anchor — the default restore is AUTHENTICATED

At backup time the trusted offense-governance pubkey is recorded to a **host-local trust anchor**, by default
`~/.vigil/backup-trust-anchor.json` (`$XDG_DATA_HOME/vigil/…`, or `$VIGIL_BACKUP_TRUST_ANCHOR`), written
atomically `0600`. It lives **outside the backup dir** and is **never transported off-host** by `--push`, so
the MED-1 actor (who can reach only the backup at rest) cannot touch it. At restore, when no
`--expect-governance-pubkey` is given, the manifest signature is **pinned against the anchor's recorded key by
default** — so ATTACK 1 is refused once an anchor exists on the host.

- **No anchor on this host** (e.g. an off-host disaster recovery): **refused fail-closed under
  `VIGIL_POSTURE=production`** (establish/confirm the anchor first, or pass the out-of-band pin); outside
  production it proceeds **integrity-only with a loud warning** — integrity-only does NOT authenticate the
  signer.
- **`--expect-governance-pubkey` always overrides** the anchor (the way to authenticate an off-host recovery).
- **Honest limit** (mirrors `vigil_core.highwater`): the anchor is a LOCAL, unsigned `0600` file. A same-host
  attacker with the operator's UID already holds the governance private key, so the anchor's protection reduces
  exactly to that key's — it defends against the reach-the-backup-at-rest attacker, not a host-root one.
- **Key rotation** changes the pubkey; backup then REFUSES to overwrite the anchor silently and requires the
  deliberate, logged `vigil backup --reset-trust-anchor` to re-establish it.

### 3. Rollback resistance — a monotonic freshness marker

The manifest carries a monotonic `backup_seq` (a **persisted** counter from the trust anchor — never derived
from the wallclock), and the anchor records the latest. At restore, a backup whose `backup_seq` is older than
the recorded latest is **refused as a rollback**; `--allow-rollback` overrides deliberately (loud, logged).
Without an anchor there is no local counter, so freshness is honestly *unverifiable* on that host (the pin /
production gate governs that case) — this is stated, not implied closed.

## The claim (register in the claims registry, [W0-3] #398)

<!-- CLAIM:W7-6 -->
> **Registered claim (W0-3 #398):** The orchestrator `MANIFEST.json` is signed with the offense governance key over domain-separated bytes and `vigil restore` verifies it before trusting the index; the DEFAULT restore is AUTHENTICATED by pinning a host-local trust anchor recorded on first backup (production refuses fail-closed when neither the anchor nor `--expect-governance-pubkey` is present, and non-production falls back to integrity-only with a warning), and a rollback to a genuine older signed backup is refused via a monotonic `backup_seq` marker.

## FATAL-2 boundary

The orchestrator runs in the **offense** venv and signs with the **offense governance key only**. The
sovereign owner key never enters this process (the two-env boundary), so — exactly as for the inner offense
manifest — the index is **governance-signed, not owner-signed**. This is honest and intentional: a keyless
offense plane cannot owner-sign. Every `framework`/`sigil` touch stays function-local; `vigil_core` (the
crypto + posture parse) is namespace-pure and importable from either plane.

## Residuals (for the maintainer)

- The trust anchor is an unsigned local file (the honest limit above). A same-host root attacker who rewrites
  BOTH the backup AND the anchor is out of scope for this slice — closing that needs an out-of-band witness of
  the anchor (the `vigil_core.highwater` VF-1c direction), not a local file.
- An **operator-owned / rotated** governance signing key (so authenticity does not rest on TOFU capture of
  whatever key the offense plane first minted) remains [W9-1] #434. This change makes the default authenticated
  *against the recorded key*; W9-1 is about *provisioning and rotating* that key with an owner delegation.

## Tests + negative controls

`integration/tests/test_backup_manifest_signature.py` (runs in the required `integration two-env boundary
(P5)` job):

- **Unit:** sign→verify round-trip; determinism; refuse tampered bytes; refuse a missing/incomplete envelope
  (unsigned); refuse a wrong-key pin; refuse a NON-domain-tagged signature (LOW-4); the anchor helpers
  (establish / advance / refuse-rotation-without-reset); `resolve_manifest_pin` modes; `check_backup_freshness`.
- **CLI (several FAIL on the pre-rework code):** the backup establishes the anchor; the DEFAULT restore
  authenticates against it; the **attacker re-mint (ATTACK 1) is refused by default once an anchor exists**
  (pre-rework the default accepted it and ran the leg — observed, not assumed); **production with no anchor
  fails closed** while an explicit pin still restores; **a rollback to an older backup is refused** (with an
  `--allow-rollback` override); a tampered / unsigned manifest is refused before the leg runs; an explicit pin
  mismatch is refused and the correct pin restores.
