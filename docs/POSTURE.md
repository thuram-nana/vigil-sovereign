# Proof of Posture — the Certificate of Non-Exploitability (and the Authority-Envelope twin)

Security has cryptographic proof for *integrity* (signatures), *identity* (certs), *inclusion* (Merkle),
and *correct computation* (ZK) — but **no proof primitive for the negative**: *"this running system is
provably not exploitable in way X, right now."* Every incumbent (AEV/autonomous-pentest, CSPM/CTEM, VEX,
SOC 2, pentest letters) either proves the *positive*, *infers* from config, or is *self-asserted*. VIGIL
mints the **sound negative** — and, uniquely, states exactly what it does *not* cover.

## The artifact
A **PostureCertificate** is a signed, deterministic projection of VIGIL's coverage oracle into a posture
vocabulary, per `(surface, parameter, vuln-class)`:

| status | meaning |
|---|---|
| **CLOSED** | an applicable deterministic oracle had a **live channel** to the real target and did **not** fire (coverage verdict `clean`, with a non-empty `oracle_kinds_run`) |
| **OPEN** | an oracle **fired** — a confirmed finding |
| **UNPROVEN** | the payload was sent but no oracle adjudicated (`inconclusive`), or the surface was never reached (out of the denominator) |

bound to a specific target (an owner-signed `IdentityAttestation`), carrying its **coverage denominator**
and honest **residual** verbatim in the signed bytes. Freshness (an external RFC 3161 time anchor) and
independent attestation (a witness quorum) attach to the certificate's digest as sidecars at the bundle
layer, so the certificate core stays byte-deterministic.

`integration/vigil_integration/posture/` — `certificate.py` (build/sign/verify), `bundle.py`
(portable bundle), `series.py` (anti-rollback attestation series), `reprove.py` (continuous re-proof),
`endpoint.py` (read-only queryable endpoint), `cli.py` (`python -m vigil_integration.posture …`).

## Verification tiers (honest, in the signed bytes)
- **`binding`** (shipped) — a third party re-checks the m-of-n signature, the out-of-band fingerprint pin,
  the coverage-projection binding (claims re-project byte-identically from the embedded coverage cert; a
  CLOSED with no conclusive oracle is refused), and the owner target-binding — **offline, with no VIGIL
  installed** (`docs/proof-carrying-finding/verify_vf.py`). It does **not** re-fire the oracle; re-firing
  needs VIGIL (a coverage re-run) — the same residual as the H4 audit package.
- **`re-executable`** (marked enhancement) — for a flagship class, the certificate additionally embeds the
  probe's raw request/response bytes + the TLS channel-binding transcript, and the standalone verifier
  ships a pinned oracle kernel that **re-derives** `clean`/`fired` from the bytes — a producer-independent
  sound negative. The certificate's summary counts claims per tier so a reader sees exactly how much of the
  negative is re-executable vs binding-only. (Requires retaining clean-probe bytes through the coverage
  layer; the binding tier is the complete, verifiable artifact today.)

## The honest boundary (this is the feature, not a footnote)
CLOSED means *non-exploitability by the oracle family, over the reached surface, as of the freshness
bound* — **never** "secure against everything." Undiscovered endpoints/parameters are discovery/recall
(out of the denominator). Freshness is only as current as the last re-proof cycle; the target must be
reachable. That denominator-on-the-face is what makes the negative believable where SOC 2 / VEX / pentest
letters are not.

## Reproduce / operate
```bash
# mint a certificate + portable bundle from a live scan of an authorized target
python -m vigil_integration.posture attest --out ./run --engagement my-engagement
# a counterparty re-verifies OFFLINE (no VIGIL), with the out-of-band pins
python -m vigil_integration.posture verify --bundle ./run/bundle
# serve it read-only so a counterparty can poll + verify
python -m vigil_integration.posture endpoint --bundle ./run/bundle --host 127.0.0.1 --port 8787
# continuously re-prove on a cadence (systemd: infra/systemd/vigil-posture.{service,timer})
python -m vigil_integration.posture.reprove --series-dir ./series --cycles 1
```
`verify_vf.py verify --bundle bundle.json --posture-fingerprint … --posture-owner-pubkey …
--posture-engagement … --posture-now $(date +%s)` — exit 0 iff SOUND; a flipped byte anywhere → NOT SOUND.

## The accountability twin — Authority-Envelope certificate
`posture/authority.py` mints a signed, third-party-verifiable proof that an autonomous agent took **only**
actions its owner-signed authority permitted: an owner-signed **envelope** (engagement + scope hosts +
action allowlist + window) + the run's action ledger + a re-derivable **conformance** proof (every
*executed* action inside the envelope). The standalone `verify_vf.py authority` component re-derives
conformance offline; a forged "conformant" verdict, or an executed action that left the envelope, is
refused. Honest residual: it proves conformance over the append-only **recorded** ledger — a
tamper-evident record, not omniscient capture. As autonomous agents proliferate, this is the
"prove your AI stayed in bounds" primitive liability/insurance/regulation will demand.
