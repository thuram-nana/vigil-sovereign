# W9-7 / W4-3 — A signed build manifest over every shipped artifact, with explicit integrity states

Issues: [#440](https://github.com/thuram-nana/vigil-sovereign/issues/440) (W9-7) ·
[#443](https://github.com/thuram-nana/vigil-sovereign/issues/443) (W4-3) ·
Milestones: W9 — KEY LIFECYCLE & PRODUCTION POSTURE · W4 — RELEASE ENGINEERING.

## The defect this closes

Two gaps, one mechanism.

- **#443** — the only build identifier the product carried covered the **browser bundle only** (a content
  hash stamped by `uiproxy.assemble_serve_dir`, served at `/__vigil/version`). Three of the four things
  that ship — the Python code, the Rust WARDEN kernel, the gateway image — had **no identity at all**.
- **#440** — nothing let an operator ask a running install *"are my own files the ones that shipped?"*
  There was no signed manifest and no notion of an integrity **state** — so the honest answer ("I don't
  know") could never even be given.

## The decision

There is now **one signed build manifest** (`build-manifest.json`) over **every** shipped artifact. Each
artifact — a `file` (the Rust kernel binary), a `tree` (a Python package or the browser bundle) or an
`image` (the gateway container, by content digest) — carries a content-addressed sha-256 digest, and the
manifest carries a `build_id` **derived** from those digests. The manifest is signed with Ed25519 and
verified by the **same** m-of-n `verify_threshold` the signed spine head uses (`vigil_core.chain`) — no
parallel crypto. Verification is **offline**: signature + digests, no network.

Asked about a running install, the verifier returns exactly **one of six explicit states, never an
optimistic default**:

| state | meaning |
|-------|---------|
| `VALID` | signed manifest verifies under the pinned trust root **and** every locally verifiable artifact matches |
| `MODIFIED` | the manifest verifies, but a shipped artifact's on-disk content differs |
| `MISSING` | the manifest verifies, but a shipped artifact is absent from disk |
| `UNSIGNED_BUILD` | a release-channel manifest is present but carries **no** signatures |
| `UNKNOWN_BUILD` | no manifest, an unreadable/too-new one, or signatures that do **not** satisfy the trust root — i.e. nothing can be attested. **This is the fail-closed default**, never `VALID`. |
| `DEVELOPMENT_BUILD` | the manifest declares itself a development build — an un-attested working tree, honestly labelled |

The mechanism lives in `vigil_core.signed_build_manifest` (stdlib + vigil_core crypto, so both trust planes
may reach it without crossing the FATAL-2 boundary). The provisioning CLI is `tools/build_manifest.py`
(`generate` / `verify`); the shipped artifact set is declared in `tools/build-manifest.artifacts.json`.

## Determinism

The signed region — `{manifest_schema, channel, product_version, build_id, artifacts}` — contains **no
wall-clock and no rng**. `build_id` is derived from the sorted artifact digests and `artifacts` is sorted by
name, so two independent builds of the same tree produce byte-identical signing bytes and the same
`build_id`. A **rebuilt artifact with different content** therefore produces a **different** `build_id` and
**fails** verification against the old manifest — #443's negative control.

## Where the state is surfaced

- **`vigil doctor`** reads the manifest at the install root and prints the headline state plus a
  per-artifact breakdown. A tampered **signed release** (`MODIFIED` / `MISSING`) is a **hard** issue that
  flips the doctor exit code; a source checkout (`UNKNOWN_BUILD`) or a dev/unsigned build is an
  informational note — a checkout must not read as broken.
- **The health endpoint** (`/readyz`, the W6-7 readiness probe in `vigil_integration.posture.endpoint`)
  includes the state in its body and turns a node **NOT ready** on `MODIFIED` / `MISSING`, so an
  orchestrator drains a tampered install rather than serving files that do not match what shipped.

## Honest scope — READ THIS (the limitation, registered here per #440)

This is **user-space self-verification**. It proves the files on disk match a manifest signed by a key the
**running process trusts**. It **does not, and cannot, defend against a hostile administrator** who controls
the same host: such an admin can replace the shipped files, the manifest, the trust root **and this verifier
together**, then re-sign a manifest under their own key, and every check here would pass. The one mitigation
this layer offers is an **out-of-band pinned trust-root fingerprint** (`VIGIL_BUILD_TRUST_ROOT_SHA256`): a
trust-root file whose bytes do not match the pin is refused fail-closed — but that is only as strong as the
channel that delivered the pin, which the admin also does not control **only if** it came from outside the
host. Genuine tamper-resistance against a privileged local attacker requires a hardware root of trust /
measured boot / remote attestation, which is **outside** this user-space install. This is a
tamper-**detection** aid for an honest operator against accidental or naive modification — **not** a
containment boundary against a privileged attacker. The fail-closed default (`UNKNOWN_BUILD`) is what keeps
an un-attestable install from ever reading as clean.

## The claims (registered in the claims registry — [W0-3] #398)

<!-- CLAIM:W9-7 -->
> **Registered claim (W0-3 #398):** A running install verifies its own shipped files against a signed build manifest and reports one of six explicit integrity states — VALID, MODIFIED, MISSING, UNSIGNED_BUILD, UNKNOWN_BUILD or DEVELOPMENT_BUILD — never an optimistic default, failing closed to UNKNOWN_BUILD when nothing can be attested, and this is user-space self-verification that a hostile administrator can defeat.

<!-- CLAIM:W4-3 -->
> **Registered claim (W0-3 #398):** One signed build manifest records a content-addressed build id for every shipped artifact — the Python code, the Rust WARDEN kernel, the browser bundle and the gateway image — and is verifiable offline, so a rebuilt artifact with different content produces a different id and fails verification against the old manifest.

Why these are TRUE of the code:

- `vigil_core.signed_build_manifest.verify_build_integrity` is the fail-closed state machine that returns
  exactly one of the six states, defaulting to `UNKNOWN_BUILD` whenever nothing can be attested (no
  manifest, an unauthenticated signature, a too-new format).
- `vigil_core.signed_build_manifest.build_manifest_from_specs` hashes every declared artifact into one
  manifest whose `build_id` is content-addressed over the artifact digests.
- `packages/core/vigil_core/tests/test_signed_build_manifest.py` proves the six states with negative
  controls in the same run (modify → `MODIFIED`, delete → `MISSING`, unsigned → `UNSIGNED_BUILD`, no
  manifest → `UNKNOWN_BUILD`, forged/below-threshold signature → `UNKNOWN_BUILD`), the four-kind coverage,
  the rebuilt-artifact negative control, and determinism.
- `integration/tests/test_build_integrity_surfaced.py` proves `vigil doctor` and `/readyz` surface the
  state and fail closed on a tampered signed release.

## Related

- W4-1 (#441) — one product version, the number this manifest records.
- W6-7 (#458) — the `/readyz` health endpoint this state now rides.
- The release workflow (`.github/workflows/release.yml`) signs the *wheel* via Sigstore/SLSA; this manifest
  is the complementary **in-product** identity a running install self-verifies against.
