# The sovereign plane (SIGIL + vigil_core)

> Sibling pages: [`architecture.md`](architecture.md) (the two-plane map) · the offense plane, the
> gate-of-record, and the audit-chain each have their own page in this directory. Read
> [`architecture.md`](architecture.md) first if you have not.

## 1. What it is / its job

The **sovereign plane** is the owner-key half of VIGIL. It runs in its own interpreter
(`.venv-sovereign`) and is the *only* place the owner's Ed25519 private key ever lives. Its code is
`apps/sigil` (SIGIL: the WARDEN classifier, the Governor, the approval queue, the append-only signed
spine, the glass-cockpit and phone-bridge UIs, voice/gesture embodiment) plus `packages/core/vigil_core`
(the neutral, dependency-minimal integrity substrate: hash-chain, canonical JSON, Ed25519 + m-of-n
threshold crypto, and the pure gate-of-record core) plus the parts of `integration` it is allowed to
load. Its job is to be the trust anchor and the human-in-the-loop: it holds the owner identity, signs
every governance decision and every spine checkpoint, decides which agent actions may auto-run vs. queue
for the owner, and ingests oracle-confirmed findings that cross from the offense plane as inert signed
data. It is **offense-free by construction** — it must never import the CRUCIBLE engine or the Strix
agent body (`framework.*` / `strix.*`).

## 2. Authoritative code paths

### 2.1 The neutral core — `packages/core/vigil_core`

| Concern | File · symbol |
|---|---|
| Package purity contract (imports NO `framework.*`/`strix.*`/`sigil.*`) | `vigil_core/__init__.py` (module docstring) |
| Ed25519 + m-of-n threshold verify; weak-key rejection | `vigil_core/crypto.py` — `verify_one`, `verify_threshold`, `load_public_key`, `_reject_weak_public_key` |
| Hash-chain / canonical JSON / signed head | `vigil_core/chain.py`, `vigil_core/canonical.py`, `vigil_core/models.py` (`SignedChainHead`, `TrustRoot`, `ChainEntry`) |
| **Gate of record** (pure conjunction) | `vigil_core/gate.py` — `conjunctive_decide`, `GateVerdict` |
| WARDEN tiers (Python port of the Rust kernel) | `vigil_core/warden_tiers.py` — `classify`, `Tier`, `gate`, golden vectors `warden_golden.json` |
| Owner-signed delegation certs | `vigil_core/delegation.py` — `sign_delegation`, `verify_delegation` |
| At-rest sealing / vault | `vigil_core/sealing.py`, `vigil_core/vault.py` |

`vigil_core` is a **leaf**: it imports only stdlib + `cryptography` + `pydantic`. That purity is the
whole reason both planes can share it without the offense engine ever being reachable from the owner-key
process. The offense-free guard itself lives in SIGIL, *not* here (see below), precisely because CRUCIBLE
(an offense engine) also depends on this core.

### 2.2 The offense-free guard + re-export shim

- `apps/sigil/sigil/reuse/__init__.py` re-exports the `vigil_core` primitives and adds
  `assert_no_offense()` — fail-closed: it raises if any `framework.*` or `strix.*` module is loaded in a
  SIGIL process. All SIGIL code imports crypto/chain primitives from `..reuse`, never from `vigil_core`
  directly, so the sovereignty guard stays attached.

### 2.3 SIGIL kernel / WARDEN classifier

- **The classifier of record** is `vigil_core/warden_tiers.py:classify` — a byte-faithful Python port of
  the Rust kernel `apps/sigil/kernel/src/tiers.rs`. Both are pinned to one shared golden-vector set
  (`warden_golden.json`) so they cannot silently drift. It is **token-based** (splits on `._-/`+whitespace
  into whole tokens, never a raw substring) and **danger-first**: A3 danger tokens checked first, then A2,
  A1, the exact-name HID input tables, and A0 only via a *positive* safe-verb allowlist. Anything not
  positively classified — unknown, empty, non-ASCII, control-char-smuggled — is **A3** (fail-closed to the
  most-gated tier).
- **The bridge to the enforcing kernel** is `apps/sigil/sigil/agents/kernel_classify.py:KernelClassifier`.
  It shells out to the Rust `sigil-kernel classify` binary so the mesh derives a tool's tier from the same
  fail-closed oracle that enforces at the kernel. Any failure — missing/unpinned binary, timeout, non-zero
  exit, unparseable or non-object JSON — resolves to **A3**. It verifies the resolved binary against the
  owner-signed integrity pin (`governor/integrity.py:verify_kernel_bin`) *before* it can be executed, and
  pins the exact resolved path (never a bare `PATH` name) so no attacker-planted `sigil-kernel` runs.

### 2.4 The Governor and its latches (`apps/sigil/sigil/governor/`)

- `core.py:Governor.decide()` — the single decision point the agent-dispatch gate consults for **every**
  proposal. Composes kill switch + budget + promotion into one fail-closed verdict `AUTO | QUEUE | DENY`.
  Order is deliberately conservative: A0 observe/read is **always** allowed (even under a kill); a kill
  halts everything above observe; budget is fail-closed (at cap → DENY); A0/A1 within ceiling → AUTO; A2
  auto-approves *only* under an explicit per-scope promotion; A3 always queues. Kill/promotion are read
  **fresh per decision**.
- `killswitch.py:KillSwitch` — a latch that halts the mesh while leaving A0 perception/memory alive.
  **Asymmetric authentication**: halting is the safe direction, so *any* engage record halts (a forged
  engage is at worst a fail-safe DoS); un-halting is dangerous, so a `release` is honored **only** if it
  carries a valid owner signature verified against the trusted pubkey. Verdict is cached on the store's
  rotation-aware `change_token()`.
- `capability.py:CapabilityGate` — the same asymmetric latch for the `gesture`, `voice`, and `autolearn`
  capabilities: default ENABLED, *any* disable takes effect (even unsigned), re-enable requires an owner
  signature. A read/scan error resolves to DISABLED (fail-closed), and the error path is never cached.
- `promotion.py:PromotionPolicy` — owner-signed per-scope A2 promotions. `NO_PROMOTION_AGENTS =
  {"ENVOY", "DELEGATE"}` can never be promoted (outbound + account actions stay human-gated forever).
- `identity.py` — the owner identity: `owner_pubkey()`/`owner_keypair()` **read** the anchor
  (`KEYS_DIR/owner.priv|pub`, the 1-of-1 trust root) and never generate (verification must not mint trust);
  `ensure_owner_keypair()` is the only path that generates+persists, and only on an owner *signing* action.
  The private key routes through the vault (TPM-sealable KEK). `delegate_offense_governance` /
  `delegate_offense_spine` mint owner-signed `DelegationCert`s — the cryptographic tie that lets the
  sovereign side derive the offense trust roots it accepts (see §2.8).
- `authn.py` — `signed_payload()` / `verify_signed()`: the Ed25519-over-canonical-core primitive every
  governance event uses. Fail-closed; a non-`str` `sig` is rejected before the decoder can raise.

### 2.5 The approval queue (`apps/sigil/sigil/agents/approvals.py`)

The human gate for A2/A3. An agent QUEUEs; the owner `approve`/`deny`s here with an Ed25519 signature over
the canonical `(target_seq, decision, approver)`. Hardening that must not regress:
- The trusted pubkey is the **persisted owner identity**, never the key handed to the queue — an attacker
  cannot self-certify with their own key (`_decide` checks `owner_key.public_key_b64 == trusted_pubkey`).
- `pending()` treats an item resolved **only** when a superseding approval *verifies* against the trusted
  owner key, and keys resolution off the **signed** `target_seq` — so an unsigned/forged approval cannot
  silently drop an item, and a genuine approval of one item cannot be replayed onto another.
- `verify_approval` also accepts an owner-authorized **device** key (`extra_pubkeys`, from the
  owner-signed device-authorization ledger in `sigil.mesh`) — this is how the phone approves.

### 2.6 The signed action spine (`apps/sigil/sigil/spine/`)

- `store.py:SpineStore.append()` — the append-only, hash-chained JSONL spine. Every write serializes under
  an in-process re-entrant lock **and** a cross-process `flock` on an inode-stable lockfile; it re-reads
  the true chain tip, **truncates any torn tail** from an interrupted write before appending (so a lost
  record can't merge into garbage and pass `verify()`), seals content fields at rest under a spine DEK
  (metadata stays plaintext so keyless folds work), computes `cert_digest` over the *stored* payload, and
  `fsync`s before ack. The chain digest is over content **only, never the wallclock `ts`**, so it is
  replay-stable.
- `store.py:SpineStore.verify()` — two-layer **unkeyed** integrity (payload↔`cert_digest` binding + chain
  linkage). This proves internal consistency, not authenticity; authenticity is the signed head's job.
- `checkpoint.py:checkpoint()` / `verify_checkpoint()` — the owner-signed head. `sign_head` (from
  `vigil_core`) signs the chain head with the 1-of-1 owner trust root; `classify_head` detects TAMPERING
  (front-truncation, tail-truncation, rewrite) and enforces the monotonic `last_seq`. Head + durable
  anti-rollback **floor** (`spine/floor.py`) advance together under one `floor_lock`.
- `floor.py` — the durable, **never-liftable** anti-rollback floor. Monotonic `entry_count` (owner-signed,
  audit G2); a routine `sigil ingest --reset` (which rmtrees the spine dir) can never lower it;
  `FloorDowngrade` is the intended refusal on a deliberate reset.

### 2.7 The cockpit UI + companion PWA

- **Glass cockpit** — `apps/sigil/sigil/ui/server.py` (`UIServer`, `Handler`, `serve`). A non-public,
  stdlib-only HTTP server. It binds a `bind_ok` address **only** (loopback default, or a private
  WireGuard/Tailscale address) — the constructor *raises* on `0.0.0.0` / unspecified / public. A session
  **token** is minted at startup and printed to the terminal; the served page embeds it, a cross-origin
  page cannot read it. The **read plane** (`GET /api/*`) needs the token; the **action plane**
  (`POST /api/action`, and `/api/ask` which dispatches a kernel subprocess) additionally needs an
  exact-match `Origin`/`Referer` and an allowlisted `Host` (anti DNS-rebinding). The browser never holds
  key material — the server signs with the persisted owner key. Strict `'self'` CSP + `nosniff` +
  `no-referrer`; `/api/record/<seq>` re-verifies the atom live (prove-don't-guess).
- **Action broker** — `apps/sigil/sigil/ui/actions.py:do_action`. The single funnel for gated actions; a
  **closed set** (`approve`, `deny`, `kill`, `release`, `promote`, `revoke`, `queue_learn`, `start_learn`,
  plus capability + settings actions). Anything else is refused. It calls only the existing owner-signed
  cores (`ApprovalQueue`, `KillSwitch`, `PromotionPolicy`, `CapabilityGate`, settings) — no new authority
  path — with the owner key from `ensure_owner_keypair()`.
- **Companion phone bridge (PWA)** — `apps/sigil/sigil/bridge/server.py` (`BridgeServer`, `serve`,
  `ensure_bridge_cert`). Forks the cockpit's shape but changes three things: (1) it binds a `bind_ok`
  WireGuard/loopback address only; (2) there is **no wire bearer secret** — authentication *is* a
  per-request Ed25519 signature the phone makes with its **own** owner-authorized device key
  (`bridge/envelope.py`), verified against the owner-minted authorized-device set recomputed per request
  (a revoke takes effect at once), with the envelope `action` bound to the endpoint, a wallclock freshness
  window, and — for effectful `panic`/`relay` — a strict monotonic-nonce replay gate
  (`consume(effectful=True)`); (3) the anti-rebind allowlist derives from the real bound address. Frames
  carry only `{seq, tier, kind}` — never a subject, payload, or secret. `serve()` wraps the transport in an
  **owner-pinned self-signed TLS cert** whose sha256 fingerprint is stable across restarts (pin once; a
  later change means MITM). The owner trust root **never signs** here — the phone signs, the server only
  verifies.

### 2.8 The inbound bridge from the offense plane

The planes bridge only by subprocess or a **signed inert file spool**. On the sovereign side:
- `apps/sigil/sigil/inbound/finding_receiver.py:FindingReceiver` — ingests an oracle-confirmed finding
  that crossed as an inert JSON envelope, **without importing any offense module**. Two anchors make it
  trustworthy: **anchor 1** = the offense governance root's m-of-n signature over the finding's evidence
  certificate, verified here with `vigil_core` alone; **anchor 2** = the owner-signed spine head that
  chains the appended record. Production wiring must use `from_delegation` / `from_spine_delegation`, which
  *derive* the trust root from an owner-signed `DelegationCert` (owner tie, S4) and bind each finding's own
  signed `engagement_slug` to the delegated scope. Fail-closed at every step — an unverified/out-of-scope
  finding is never written.
- `apps/sigil/sigil/inbound/spool_watcher.py:SpoolWatcher` — drains the inert spool directory into the
  receiver.

## 3. Invariants this plane must preserve (and why)

1. **Two-env boundary / FATAL-2.** Nothing in this plane may cause `framework.*` or `strix.*` to load in
   the owner-key interpreter. `reuse.assert_no_offense()` enforces it, and `vigil_core` stays a pure leaf
   so it can be shared with the offense side without dragging the engine along. *Any* module that must
   touch the offense integration seam imports it **lazily** (function-local). Why: the owner private key
   lives here; co-loading offensive code in the same process is the single catastrophic failure the whole
   architecture is built to prevent.
2. **Oracle authority (this plane never mints a FACT).** SIGIL signs *governance* and *provenance*, not
   findings. A finding becomes a spine record only via `FindingReceiver`, and only after the offense
   oracle's deterministic signature (anchor 1) verifies. LLM/critic/voice/gesture signals only advise or
   navigate — none of them promote. Why: "the machine cannot lie about a finding" depends on the sovereign
   side refusing to write anything it cannot verify with `vigil_core` alone.
3. **Gate of record — conjunctive, first-failure-wins, fail-closed.** `conjunctive_decide` ALLOWs only if
   the domain authority is in-envelope **and** WARDEN returns an explicit `"auto"` **and** (for a
   destructive action) an owner-inclusive m-of-n threshold authorization is present. A raised conjunct is a
   DENY; an unrecognized WARDEN outcome is a DENY; the destructive conjunct uses a **strict `is True`**
   check (a truthy-but-not-`True` value must not open an irreversible action). The sovereign side supplies
   the Governor + shared classifier as its thunks; the offense side supplies `build_offense_gate`
   (`integration/vigil_integration/conjunctive_gate.py`). Why: one shared, provable authorization primitive
   means "zero unauthorized A2/A3" is provable from the log, not promised.
4. **Determinism + append-only.** The spine chain digest excludes the wallclock; kill/capability/floor
   folds do no rng/wallclock math; secrets are sealed off the spine (content fields under the DEK, owner
   key in the vault); the cockpit and bridge **never** bind a public address and always serve a strict
   `'self'` CSP. Why: a replay-stable, tamper-evident, offline-verifiable record is the product.
5. **Asymmetric authentication (safe direction is free, dangerous direction needs the owner).** Halt /
   disable / queue take effect regardless of signature; release / re-enable / approve require a valid
   owner (or owner-authorized device) signature. Why: a forged event can only ever fail *safe*.

## 4. How to extend it safely

- **Adding a gated action to the cockpit or bridge.** Add it to the closed set in
  `ui/actions.py:ACTIONS` (or the bridge's endpoint→action map) and route it to an **existing** owner-signed
  core — do not invent a new authority path. Sign with `ensure_owner_keypair()` server-side; the browser/
  phone sends a *request*, never key material. Add a test that (a) the action verifies against the persisted
  owner identity and (b) a request signed by a non-owner key is refused. Copy the pattern in
  `ui/actions.py:do_action` and `agents/approvals.py`.
- **Adding a governance latch** (a new kill-switch-like control). Copy `governor/capability.py`:
  a distinct `SIGNAL` string (domain separation), the asymmetric latch (unsigned disable / owner-signed
  enable), the rotation-aware `change_token` cache, the fail-closed-on-error contract, and the
  hard-prune snapshot fold. Include the `capability` (or equivalent) inside the signed core so one
  owner-signed enable can't be replayed onto another target. Add tests mirroring
  `apps/sigil/tests/test_capability_*` and the kill-switch fold tests.
- **Adding a new spine record kind or fold.** Append via `SpineStore.append(kind=…)`; keep content in the
  `payload` (it is sealed at rest) and any keyless-fold discriminators (`signal`, `decision`, `tier`) in
  plaintext metadata. Never digest the wallclock. If you add a security state-scanner, it must **fail
  closed** on a read error (raise or return the safe value), never fail open. Seed folds from the snapshot
  prefix and window the live tail, exactly like `killswitch._scan_engaged`.
- **Accepting new cross-plane data.** Ingest it as inert signed data through a receiver modeled on
  `FindingReceiver` — validate shape, verify a signature against an **owner-delegated** trust root
  (`from_delegation`), bind scope, then append. Never import an offense module to interpret it; if you need
  offense types, they cross as data, not code.
- **Touching crypto.** Do not roll your own. Use `vigil_core/crypto.py`. If you accept a new public key
  from anywhere, it flows through `load_public_key` so the non-canonical / low-order-point rejections apply.

## 5. Gotchas

- **Import direction.** SIGIL code imports crypto/chain primitives from `apps/sigil/sigil/reuse`, *not*
  from `vigil_core` directly — that shim is what keeps `assert_no_offense()` attached. `vigil_core` must
  never grow a `sigil.*`/`framework.*`/`strix.*` import (it would break both the leaf property and the
  boundary).
- **`vigil_integration` is installed in BOTH venvs.** A sovereign module importing anything that touches
  `framework.v2` must do it **function-locally**, never at module top level, or it risks pulling the engine
  into the owner-key process.
- **`bind_ok` is non-negotiable.** Both `ui/server.py` and `bridge/server.py` raise on a public bind. To
  serve a real domain, terminate TLS in a reverse proxy / tunnel and forward to the private bind; add the
  proxy's `Host`/`Origin` to the allowlist (`extra_hosts`/`extra_origins`) — do not relax `bind_ok`.
- **Owner key reads never mint.** `owner_pubkey()`/`owner_keypair()` return `None` when absent (fail-closed
  — nothing forged is trusted). Only `ensure_owner_keypair()` and the checkpoint's `_owner_keys()` create.
  A locked vault → `owner_keypair()` returns `None`, so governance verification fails closed.
- **Kill/capability/killswitch verdict caches key on `change_token()`, not file size.** A same-size
  in-place rewrite or a segment rotation must still invalidate the cache; that is why the token includes the
  manifest generation + resolved active segment inode. If you add a cached state-scanner, reuse
  `SpineStore.change_token()` — a bare `stat().st_size` will serve a stale (un-halting) verdict after a
  migration renames `spine.jsonl` away.
- **`SpineStore.verify()` is unkeyed** and a recompute-capable writer can forge a self-consistent chain;
  tamper-*evidence* is `checkpoint.verify_checkpoint()` (owner signature + monotonic floor), not `verify()`.
- **The destructive conjunct is `is True`, not truthy.** When wiring a destruction gate into
  `conjunctive_decide`, its result object's `.authorized` must be the literal `True`; any other value is a
  DENY by design.
- **Detection FACTs currently cross under a wildcard scope.** The Detection Mirror cert does not yet declare
  a signed `engagement_slug`, so a non-wildcard `from_spine_delegation` receiver refuses every detection
  FACT. The scope check in `ingest_detection` is already wired for the day the cert declares one.
