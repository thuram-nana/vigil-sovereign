# Proof Studio — Strix PoC → oracle-confirmed signed FACT → offline bundle

## What it is / its job

The **Proof Studio** is the seam that turns a Strix proof-of-concept into something the machine
**cannot lie about**: an oracle-confirmed, cryptographically signed, replayable, offline-verifiable **FACT**
— or, honestly, a labelled **LEAD**. Strix (the LLM-driven web agent in `vendor/strix`) *finds* a candidate
bug and writes a free-text report. That report alone carries only the model's words, so by itself it can
never mint a FACT. The Proof Studio takes the **raw request/response bytes the target actually produced**
(captured by Strix's Caido proxy), re-fires a **deterministic oracle** over those bytes, and only then mints
a signed certificate. The whole backend lives in `integration/vigil_integration/proof/` and is installed in
**both** venvs (see the two-plane model in [`architecture.md`](./architecture.md)), so every module here that
touches `framework.v2` imports it **lazily** — importing anything under `proof/` in the sovereign env must
never pull `framework` (FATAL-2).

The end-to-end pipeline:

```
 Strix report + Caido bytes                proof.sink (content gate)          proof.engine (mint)
 vendor/strix/.../proof_capture.py  ──►  proof/sink.py:ProofSink  ──►  proof/run.py:mint  ──►  proof/engine.py:mint_proof
   build_error_signature_capture           screen_poc_content            build_report_mint        3 gates → signed FACT
        _vigil_capture (raw bytes)              ALLOW/DENY                _persist_record          ──► finding_spool → spine
                                                                         _persist_reverifiable ──►  proofs/reverifiable.json
                                                                                                          │
                                                          `vigil proof-export` ──► proof/bundle.py:export_bundle ──► offline bundle
                                                          A6a remediation      ──► remediation/fix_oracle.py (silence = remediated)
```

## Authoritative code paths

### 1. Capture — `vendor/strix/strix/report/proof_capture.py` (import-clean, offense-side)

Turns Caido-captured raw bytes into the plain-dict `_vigil_capture` structure. It imports **only stdlib** and
(lazily) strix's own `tools.proxy.caido_api` — **never** `vigil_integration` or `framework`, so vendored
Strix stays import-clean.

- `build_error_signature_capture(...)` (`proof_capture.py:34`) — pure/synchronous; builds the capture from
  already-fetched bytes. Returns `None` on no usable exploit body or no `bug_class` (an honest "nothing to
  prove", never a guessed capture).
- `capture_for_report(report, ...)` (`proof_capture.py:92`) — async, best-effort, **never raises**. Resolves
  the exploit exchange (an explicitly cited Caido request id, else the most recent request matching the
  finding's endpoint+method), fetches the response, and builds the capture. A benign control request can ride
  along as a second exchange.
- **The `error_signature` channel** — `_ERROR_SIGNATURE = "error_signature"` (`proof_capture.py:31`) must equal
  `framework.v2.verify.poc_translate.ERROR_SIGNATURE` (`poc_translate.py:36`). It is a **response-side**
  channel: the bytes are what the *target* returned (a datastore/parser error the payload provoked), so it is
  a sound *standalone* proof channel. The model never supplies these bytes — it can at most point at a Caido
  request id, and the oracle still judges the real captured bytes.
- `CAPTURE_KEY = "_vigil_capture"` (`proof_capture.py:26`) is a bare literal (not an import) so Strix stays
  import-clean; it **must** equal `proof.sink.CAPTURE_KEY` (`sink.py:34`).

Wiring into Strix: `report/state.py` declares a module-level `proof_sink` hook (`state.py:34`) and attaches
the capture under `CAPTURE_KEY` just before persistence (`state.py:303-304`). Absent the hook, vendored Strix
behaviour is byte-identical.

### 2. The sink — `proof/sink.py:ProofSink`

The duck-typed `proof_sink` callable Strix invokes with each finished report. `ProofSink.__call__`
(`sink.py:91`) does exactly two things, **fail-closed, never raising into Strix**:

1. Screen `poc_script_code` (+ `evidence` / `poc_description`) through `content_gate.screen_poc_content`. A
   **DENY** quarantines the content and the finding stays a LEAD — no mint, no replay.
2. On **ALLOW**, if an executor capture is attached (`report.get(CAPTURE_KEY) is not None`) **and** a `mint`
   callback is wired, invoke it. `minted` is `True` only when the mint returned a real FACT
   (`bool(getattr(result, "is_fact", False))`, `sink.py:111`).

The `mint` callback is **injected** by the wiring layer, never imported here — so importing `proof.sink` in
the sovereign env pulls no offense engine.

### 3. Bootstrap — `proof/bootstrap.py`

`install(...)` (`bootstrap.py:45`) assigns `strix.report.state.proof_sink` to a `ProofSink` whose `mint` is
`proof.run.build_report_mint`. `install_from_env()` (`bootstrap.py:71`) is the zero-arg entry the Strix
bootstrap calls best-effort: **NO-OP unless `VIGIL_PROOF_RUN_DIR` is set** (standalone Strix keeps running
unchanged), and any failure is swallowed (the sink must never break Strix startup). It runs **in the keyless
offense process**; signers default to the run's provisioned governance authority (`provision_authority`,
lazy) over loopback scope `_DEFAULT_SCOPE = ("127.0.0.1",)` (`bootstrap.py:33`) — a remote engagement's
authority is a deliberate out-of-band ceremony, never minted implicitly.

### 4. Run seam — `proof/run.py:build_report_mint`

Returns the `mint(report)` callback. It reads the attached `_vigil_capture`, builds
`evidence.poc.CapturedExchange` objects (**lazy** framework import, `run.py:186`), calls
`proof.engine.mint_proof`, then persists two artifacts:

- `_persist_record` (`run.py:95`) writes a small **deterministic** proof record under `<run_dir>/proofs/`.
  The `proof_id` is a **content address** of the finding identity (`sha256(finding_ref:bug_class:confirmed_by)`,
  no wallclock/rng) so re-minting overwrites the same record. The console reads these as plain JSON with **no
  import of this package** (no framework→integration dependency).
- `_persist_reverifiable` (`run.py:135`), on a FACT only, appends (dedup by `check_id`) to
  `<run_dir>/proofs/reverifiable.json` the re-verifiable material: the `oracle_context`, the `action_id`, and
  the **`channel`** (the oracle family the FACT was confirmed on). This is the exact `{active_findings:[...]}`
  shape a scan's `reverifiable.json` carries, so `framework.v2 evidence verify` re-fires it byte-identically —
  and it is what both the offline bundle and the A6a remediation oracle read.

`_oracle_bug_class` (`run.py:70`) is a small honest hint map from a Strix finding's taxonomy onto the oracle's
`bug_class` vocabulary (CWE-89 / SQLi / LDAP / XPath → `error_based_sqli`, the error-signature oracle's class).
It only picks **which** oracle to try — a wrong hint simply fails to fire (→ an honest LEAD), never fabricates
a FACT.

### 5. The mint — `proof/engine.py:mint_proof`

The deterministic reproduce-from-raw mint. It enforces **three independent gates in order** before any FACT
exists (`engine.py:133`):

1. **Content gate** — `screen_poc_content` on the PoC. A DENY quarantines and returns `status="denied"`
   **without minting, even if the oracle would fire**.
2. **Reproduction** — `verify.poc_translate.context_from_exchanges` builds the `oracle_context` **only from
   the captured bytes** (lazy import). A capture with no reproducible structure → `None` → `status="lead"`.
3. **Oracle authority + provenance (G4)** — `oracle_adapter.confirm_and_certify(..., provenance=_REPRODUCED)`
   where `_REPRODUCED = "reproduced"` is a **module constant, not a parameter** (`engine.py:52`), so a caller
   cannot relax it. A signed FACT is minted **only** when a deterministic oracle fires over the reproduced
   context AND the class is oracle-mapped AND the provenance is non-LLM. See
   `oracle_adapter.confirm_and_certify` (`oracle_adapter.py:81`): the default `provenance="llm"` is demoted to
   a LEAD *even if the oracle fires* (`_REPRODUCED_PROVENANCE = {"reproduced", "live_redrive"}`,
   `oracle_adapter.py:48`), because a crafted-but-firing LLM context must never mint a FACT. Empty `signers`
   is refused fail-closed.

On a FACT, the mint additionally: materialises the raw bytes under `evidence_root/action_id` (`_materialize`,
`engine.py:93` — the exact dir `build_certificate` hashes), builds + signs the certificate, **re-proves
replay from the retained on-disk bytes** (`reverify_context`; a certificate that will not re-confirm is
**demoted to a LEAD**, `engine.py:245`), and crosses the `SignedEvidence` to the sovereign spine via
`KeylessOffenseWorker.emit_finding_envelope` → `finding_spool.spool_envelope` (which refuses an unsigned
envelope — a LEAD can never cross). `MintResult.status` is `"fact"` | `"lead"` | `"denied"`; only a `"fact"`
carries a `signed` certificate or an `envelope_path`.

### 6. Content gate — `proof/content_gate.py:screen_poc_content`

The one **new** safety layer of the Proof Studio, stdlib-only, fail-closed. WARDEN gates tool *calls*; the
destruction gate gates irreversible *actions*; neither looks at the **content** of a generated PoC. This does:
before a PoC is stored, surfaced, replayed, or minted, it is screened for five payload classes that must never
be persisted or re-run — `detection_evasion`, `persistence`, `destructive`, `self_propagating`,
`credential_exfil` (`content_gate.py:65`). It is a **DENY-only floor** (it can never bless): a non-`str`
input, oversized content (>1 MiB), any category match, or any internal error is a DENY. Ordinary injection
PoCs (a SQLi tautology, a reflected-XSS `<script>`, an SSRF URL) are **not** flagged.

### 7. Minimizer — `proof/minimize.py:minimize_payload` (optional, B6)

A classic ddmin reduction of a reproducing payload, kept **deliberately separate from the mint path** — it
never mints, signs, or spools; it just shrinks a payload and hands the reduction back to re-certify. A kept
reduction must satisfy two invariants: it **still fires** (via an injected `still_reproduces` predicate, so
this module needs no framework import) and it **re-passes content-gating** (so minimization can never launder
a payload past the safety floor). Bounded by a test budget; deterministic given a deterministic predicate.

### 8. Offline bundle — `proof/bundle.py:export_bundle` (C1)

Driven by `vigil proof-export` (`cli.py:_cmd_proof_export`, `cli.py:462`). Assembles a self-contained
directory a third party verifies **offline with zero trust in VIGIL**:

- `evidence-bundle.json` — the signed `EvidenceCertificate`s + hash chain + governance-signed head.
- `trust-root.json` — the **public** governance keys + m-of-n threshold (a *convenience copy*).
- `TRUST-ROOT-FINGERPRINT.txt` — the authenticity anchor the client must pin **out-of-band**.
- `reverifiable.json` — each finding's `oracle_context`, to re-fire the same deterministic oracle.
- `evidence/<action_id>/…` — the raw executor-captured bytes the certificate binds by sha256.
- `README.md` — the one-command verify.

The verify command carries `--trust-root-fingerprint`. **Exit 0 iff SOUND**: every certificate's signature
validates m-of-n against the *pinned* trust root, its `oracle_context` re-fires the same oracle, its bound raw
bytes re-hash, and the chain/head bind the whole set so none was suppressed, injected, or reordered. The
file-supplied `action_id` is confined to a single in-tree path segment before it is manifested (`bundle.py:130`).
The private key is only ever a Python argument (`provision_authority`), **never argv/spine**; only the public
trust root is written to disk.

### 9. A6a remediation — `remediation/fix_oracle.py`

A remediation is proven the **same** way a finding is: by re-execution, never by assertion. `remediated=True`
is earned the only sound way — by re-firing the **same** deterministic oracle that confirmed the driving FACT
against the **patched build**, and signing a remediation certificate **only when that oracle goes SILENT** over
the patched build's freshly re-captured bytes.

- `build_fix_oracle(...)` (`fix_oracle.py:65`) returns `oracle(request, patched_build) -> FixVerdict`. **Every
  path where silence cannot be soundly confirmed RAISES** (→ the caller maps a raise to `unverified`): no
  re-drive capability, a re-drive that returns nothing, an unbuildable `oracle_context`, a **request-side**
  channel (`_REQUEST_SIDE = {"request_payload"}` — a patch changes the server's response, not the attacker's
  request, so that class is simply not oracle-provable), or silence with no signer wired. Only genuine
  silence + a signature yields `FixVerdict(fired=False, cert=...)`.
- **`expected_channel` pins the oracle family** — it is the authoritative request-vs-response signal, resolved
  from the retained re-verifiable material, **not** the re-drive's self-reported channel (untrusted). A
  mismatch would build a context for the wrong oracle family whose input field the resolved oracle never
  reads, so a `reproduced=False` would be a **vacuous** non-fire (an adversarial-review fix, `fix_oracle.py:110`).
- `build_run_fix_oracle(...)` (`fix_oracle.py:184`) resolves the exact `bug_class` **and** `channel` from
  `<run_dir>/proofs/reverifiable.json` (keyed by `check_id`) and wires the signer. It is threaded into
  `codefix_runner.autopatch` as `verify_oracle` (`live/codefix_runner.py:410`); absent the caller-provided
  `redrive`, `remediated` stays `False` and the PR opens as a plain proposal.

## Invariants it must preserve (and why)

1. **FATAL-2 / lazy framework imports.** `proof/` is installed in both venvs. Every `framework.v2` /
   `strix.*` import is function-local; module-scope imports are import-clean only (`content_gate`,
   `oracle_adapter`, `offense_worker`, `finding_spool`, sibling `.run`/`.engine`/`.sink`). *Why:* a
   module-scope `framework` import here would let the sovereign interpreter co-load offense code — the exact
   FATAL-2 violation the two-plane boundary exists to prevent. `proof_capture.py` additionally must import
   **nothing** from `vigil_integration`/`framework` to keep vendored Strix clean.
2. **Only reproduced, non-LLM bytes mint a FACT.** The mint fixes `provenance="reproduced"` as a constant and
   builds the context solely from executor-captured bytes. *Why:* this is the moat — "the machine cannot lie
   about a finding." An LLM-authored context that happens to fire the oracle is still an LLM-influenced route
   to a FACT, and is demoted to a LEAD.
3. **Content gate is a fail-closed floor, checked before mint/replay.** *Why:* a "proof" that disables the
   defender, installs a backdoor, wipes the disk, worms, or exfils credentials must never be stored or re-run.
   The gate can only DENY; an allow is *not* a claim of safety.
4. **Sink/capture/bootstrap never break Strix.** Every hook path swallows its own errors and, absent the
   env/hook, leaves vendored behaviour byte-identical. *Why:* the Proof Studio is an additive seam; a proof
   failure means "no proof (an honest LEAD)", never a broken scan.
5. **Determinism + append-only.** No wallclock/rng in the mint, record id, bundle order, or fix oracle;
   `seq` is passed in; the proof record id is a content address; `reverifiable.json` dedups by `check_id`.
   *Why:* the offline verifier must re-derive identical results, and re-mints must be idempotent.
6. **A FACT re-confirms or it is not a FACT.** The mint re-proves replay from the retained on-disk bytes and
   demotes on failure; the bundle re-fires every context; remediation is earned by measured silence, not
   assertion. *Why:* every downstream consumer (spine, bundle, retest) trusts the label, so the label must
   survive independent re-execution.

## How to extend it safely

- **New proof channel (beyond `error_signature`).** Add the channel constant to
  `framework.v2.verify.poc_translate` (the translator + `_ORACLE_CHANNELS`), give it a `FindingContext.from_*`
  builder and an oracle, then emit that channel from a capture builder. Response-side channels can stand
  alone; a **request-side** channel is not remediation-provable (add it to `fix_oracle._REQUEST_SIDE`). Copy
  the `build_error_signature_capture` shape: keep the capture builder pure/synchronous and import-clean, and
  keep the `channel` literal identical on both sides.
- **New Strix→oracle class hint.** Extend `run.py:_oracle_bug_class`. It is only a "which oracle to try" hint
  — never a promotion — so a wrong entry costs an honest LEAD, not a false FACT.
- **Never** add a `provenance=` parameter to `mint_proof`, relax `_REPRODUCED`, sign with an empty signer
  list, or mint from `report`/model text. Never move a `framework`/`strix` import to module scope.
- **Tests to add** (mirror the existing suite): `integration/tests/test_proof_engine.py` (the 3-gate ladder:
  DENY quarantines-not-mints, non-fire → LEAD, replay-demotion, LLM-provenance → LEAD),
  `test_proof_run.py` (record + `reverifiable.json` persistence, content-addressed id idempotence),
  `test_proof_bundle.py` (a flipped byte / re-signed root fails verify), `test_proof_bootstrap.py` (NO-OP
  without `VIGIL_PROOF_RUN_DIR`; sink never raises), `test_fix_oracle.py` (silence→signed cert; every
  non-silent path RAISES; channel-mismatch and request-side refuse). Add a content-gate regression whenever
  you touch a pattern (an ordinary injection PoC must stay ALLOW).

## Gotchas

- **`CAPTURE_KEY` is duplicated as a literal** in `proof_capture.py:26` and `proof.sink.py:34`. They must stay
  equal; there is no shared import (that would break Strix's import-cleanliness). Same for the `error_signature`
  channel string across `proof_capture.py`, `poc_translate.py`, and `fix_oracle`'s pinning.
- **A report alone never mints.** Only the presence of `_vigil_capture` (attached solely by the trusted
  capture path, never the model) makes a report mint-eligible. No capture ⇒ LEAD.
- **`reverifiable.json` is the sibling, not a proof record.** `read_proofs` skips it by name
  (`run.py:54`); `read_reverifiable` reads it. Confusing the two loses the C1 bundle/remediation material.
- **The bundle is only zero-trust with the out-of-band fingerprint pin.** `trust-root.json` is a convenience
  copy; without `--trust-root-fingerprint`, exit 0 proves internal consistency + reproduction but **not
  authenticity** (any key could have signed it). Always publish the fingerprint out-of-band.
- **Remediation `unverified` ≠ `still-vulnerable`.** `fix_oracle` RAISES (→ `unverified`) whenever silence
  can't be *soundly* confirmed; it returns `fired=True` only when the exploit genuinely still fires. Don't
  collapse the two — an unexercised or request-side finding is honestly unprovable, not "fixed" and not "still
  broken".
- **`install_from_env` runs in the offense process only.** It needs `strix.report.state` and `framework`
  importable; it must never run in the sovereign env, and the sovereign key is never present where it runs.

See also [`architecture.md`](./architecture.md) for the two-plane boundary, oracle authority, and the gate.
