# W8-6 — Encrypt the proxy→cockpit hop (TLS), fail-closed on a plaintext remote hop in production

Issue: milestone W8, item **W8-6** · [#472](https://github.com/thuram-nana/vigil-sovereign/issues/472) ·
Registered in the claims registry ([W0-3] #398, id `W8-6`).

## The defect

The reverse proxy (`integration/vigil_integration/uiproxy.py`) is the authenticating boundary in front of
the sovereign cockpit. In the HA / k8s profile it federates `/sovereign/*` to a **remote** cockpit
(`vigil up --proxy-only --sovereign-addr vigil-sovereign:8733`), and that hop crossed the pod network in
**cleartext HTTP**, carrying the per-user bearer and the substituted owner console credential. The
`NetworkPolicy` ([`infra/ha/k8s/networkpolicy.yaml`](../../infra/ha/k8s/networkpolicy.yaml)) bounds *who*
may connect to the cockpit; it does not make the hop **confidential**. A cluster whose pod network an
attacker can sniff could read those credentials off the wire.

## What ships (the mechanism)

A stdlib-`ssl` TLS **client** on the hop, wired into the proxy's two data-carrying hop sites — the request
forward (`_proxy`) and the delegated per-user auth (`_whoami`) — through one helper (`_hop_connection`):

- **`build_hop_tls_context`** builds the hop's client `ssl.SSLContext` from the environment
  (`VIGIL_HOP_TLS` to enable; `VIGIL_HOP_CA` to verify the backend cert; the
  `VIGIL_HOP_CLIENT_CERT` / `VIGIL_HOP_CLIENT_KEY` pair for **mutual TLS**). Verification is **always on**
  and never relaxed: `CERT_REQUIRED` + hostname check + TLS ≥ 1.2. A configured CA/cert/key that is
  missing or invalid **raises** (fail-closed); a half-configured mTLS pair (exactly one of cert/key) is
  **refused**.
- **Trust anchor — `VIGIL_HOP_CA` PINS.** When `VIGIL_HOP_CA` is **set**, the context is
  `ssl.SSLContext(PROTOCOL_TLS_CLIENT)` + `load_verify_locations(cafile=CA)` — which does **NOT** load the
  system trust store, so **only the operator CA is trusted**. A leaf mis-issued (or coerced) from any of
  the ~120 public CAs the OS trusts is **rejected**; this is the point for a hop reached over a public
  FQDN — without the pin, any public CA could vouch for the backend and MITM the control-plane hop. When
  `VIGIL_HOP_CA` is **unset** (but hop TLS is enabled), the context is `create_default_context` and the hop
  verifies against the **system trust store** — the documented default, honestly weaker (any OS-trusted CA
  can vouch for the backend), correct only when the cockpit presents a publicly-trusted certificate.
- **`resolve_hop_tls`** resolves that context AND enforces the production fail-closed rule, then
  `make_proxy_server` stores it on the server and every request handler reads `self.server.hop_tls`.

The two-env boundary (FATAL-2) is preserved: `ssl` is stdlib and `vigil_core.posture` is the neutral,
namespace-pure, pure-stdlib `VIGIL_POSTURE` parser **both** trust planes already share — never
`framework`/`strix`/`sigil`. The boundary guard `test_control_plane_boundary.py::test_uiproxy_is_pure_stdlib`
was widened to admit exactly those two (and re-proves `vigil_core.posture` is itself pure stdlib).

## The claim (registered in the claims registry — [W0-3] #398, id `W8-6`)

<!-- CLAIM:W8-6 -->
> **Registered claim (W0-3 #398):** Under the PRODUCTION posture (VIGIL_POSTURE=production/prod) the reverse proxy REFUSES TO START with a plaintext proxy->backend hop to a remote (non-loopback) backend: resolve_hop_tls raises unless hop TLS is enabled, so the per-user bearer and the substituted owner console credential never cross a network in cleartext; a loopback hop stays plaintext because its bytes never traverse a network, and outside the production posture the default hop is unchanged (byte-identical). When hop TLS is enabled, VIGIL_HOP_CA PINS certificate verification to that operator CA alone (ssl.SSLContext(PROTOCOL_TLS_CLIENT) does not load the system trust store, so a leaf mis-issued or coerced from any public CA is rejected); with VIGIL_HOP_CA unset the hop verifies against the system trust store (the documented, honestly-weaker default). check_hostname, CERT_REQUIRED and TLS 1.2+ are never relaxed.

## Why this is TRUE of the code — and where it is scoped

`resolve_hop_tls` (`integration/vigil_integration/uiproxy.py`), called by `make_proxy_server` before the
listener is built (both `run_up` call sites already turn its `ValueError` into a clean exit 2):

- **Opt-in selector, honestly scoped.** The gate is armed only by `is_production_posture()` (the shared
  `vigil_core.posture` parse). Outside the production posture the hop is plaintext exactly as before —
  byte-identical to the historical `vigil up`.
- **Scoped to the real threat.** The refusal fires only for a **remote (non-loopback)** backend. A single-
  host `vigil up` (the loopback trio, `127.0.0.1`) stays plaintext even in production: its bytes never
  traverse a network, so it is not the pod-network cleartext the gate exists to reject, and forcing TLS
  there would break the single-host deployment for no confidentiality gain. `_hop_is_loopback` is
  **fail-closed** — a DNS name or any unparseable/unknown host is treated as REMOTE, never assumed local.
- **Real encryption when enabled.** With `VIGIL_HOP_TLS=require` and `VIGIL_HOP_CA` (and a TLS-terminating
  cockpit), the forward and the auth hop both ride HTTPS with certificate + hostname verification against
  the **pinned operator CA** (system store not trusted); a client cert turns on mutual TLS.

## The residual (stated honestly, not buried)

**This change ships the CLIENT half — the mechanism that USES cert material and fails closed without it.**
The following is the operator/deployment residual, wired but not self-provided:

- **Cert material.** The CA, the cockpit's server leaf/key, and (for mTLS) the proxy's client leaf/key are
  operator-provided (a k8s `Secret`, cert-manager, or a mesh CA). No key is generated or committed by this
  change.
- **Server-side TLS termination.** The hop is TLS only if the cockpit **serves** TLS. `sigil serve` binds
  plaintext by design (a single-owner, on-host surface — see `networkpolicy.yaml`), so in-cluster the
  cockpit must be fronted by a TLS-terminating sidecar (or an equivalent mesh mTLS). The k8s manifests
  template the cert-material env + Secret mount (commented, operator-provided) but **ship
  `VIGIL_POSTURE=production` ARMED (uncommented)** in the remote-federating HA proxy manifest
  (`infra/ha/k8s/proxy-deployment.yaml`): applying it as shipped — before that cert material exists — makes
  the proxy **refuse to start** (the pod crashloops on `resolve_hop_tls`'s `ValueError`) rather than run
  the credential-bearing hop in cleartext. The refusal is the fail-closed default; the operator clears it
  by provisioning the hop-TLS Secret and uncommenting the four `VIGIL_HOP_*` env vars + the volume mount.
  This is deliberately **not** on-by-default *TLS* (an on-by-default TLS hop with no cert material would
  fail every request); it is on-by-default *refusal* of a plaintext remote hop — the correct posture for a
  government deployment.
- **Defense in depth — a plaintext remote hop is never silent.** Even OUTSIDE the production posture (where
  a remote plaintext hop is still allowed, byte-identical to before), `make_proxy_server` emits a structured
  start-time WARNING to stderr (`event=hop_plaintext_remote …`) whenever it builds a server that federates
  to a remote backend with hop TLS disabled — so a cleartext remote hop can never go unnoticed.

## Alternatives considered

- **Refuse ALL plaintext in production, loopback included.** Rejected: it would break the supported single-
  host production deployment for no confidentiality gain (loopback never leaves the host), and the issue's
  own defect statement is "cleartext HTTP on the *pod network*" — a remote hop.
- **Terminate/generate TLS inside `uiproxy`.** Rejected: uiproxy is the hop **client**; the server side is
  the cockpit, which lives in the other trust plane. Generating certs would also pull a non-stdlib crypto
  dependency into a module the boundary guard keeps pure-stdlib. A mesh/sidecar or operator CA is the sound
  server-side answer; uiproxy owns only the verifying client.

## Tests (required job: `integration two-env boundary (P5)`)

`integration/tests/test_uiproxy_hop_tls.py` — real, offline, each gate paired with a negative control in
the same run:

- production + a remote plaintext hop → `resolve_hop_tls` / `make_proxy_server` **refuse** (the latter is
  the test observed to **fail without this change** — the unfixed `make_proxy_server` never raises);
- negative controls: a loopback hop is still allowed in production, and a non-production remote hop is
  still allowed — the gate is scoped, not a blanket block;
- a TLS hop **round-trips** through `_hop_connection` and `_whoami`; a plaintext hop to the TLS backend
  **fails closed**; an untrusted server cert is **rejected**;
- **mutual TLS** round-trips with a client cert, and a peer **without** one is refused by the backend;
- cert/key loading **fails closed** on a missing/invalid CA or client cert, and on a half-configured pair;
- **the CA PIN (the MITM defence).** `test_operator_ca_pin_rejects_a_same_host_cert_from_a_DIFFERENT_ca` —
  with `VIGIL_HOP_CA` pinned to an operator CA, a server cert for the SAME backend hostname issued by a
  DIFFERENT CA is **rejected** at the handshake (the exact MITM), while a cert issued by the operator CA is
  accepted; and `test_operator_ca_pin_does_not_trust_the_system_store` proves the pinned context trusts
  **exactly one** CA (the operator's) — the ~120-CA system store is not loaded (this assertion fails on the
  old `create_default_context`-plus-add-the-operator-CA code);
- **default posture armed.** `test_ha_proxy_manifest_arms_production_posture_by_default` asserts the shipped
  HA proxy manifest carries `VIGIL_POSTURE=production` as an ACTIVE env var while federating to a remote
  cockpit, and `test_remote_plaintext_hop_build_warns` asserts a remote-plaintext build emits the
  `event=hop_plaintext_remote` WARNING (and a loopback build does not);
- **SSE over the TLS hop.** `test_sse_over_tls_streams_through_a_reauth_interval` streams an SSE response
  over the TLS hop across a quiet re-auth interval and asserts both frames arrive, the bearer is re-checked,
  and the stream does not hang.
