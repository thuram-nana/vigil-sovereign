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
  (`VIGIL_HOP_TLS` to enable; `VIGIL_HOP_CA` to verify the backend cert against an operator CA; the
  `VIGIL_HOP_CLIENT_CERT` / `VIGIL_HOP_CLIENT_KEY` pair for **mutual TLS**). Verification is **always on**
  and never relaxed: `CERT_REQUIRED` + hostname check + TLS ≥ 1.2. A configured CA/cert/key that is
  missing or invalid **raises** (fail-closed); a half-configured mTLS pair (exactly one of cert/key) is
  **refused**.
- **`resolve_hop_tls`** resolves that context AND enforces the production fail-closed rule, then
  `make_proxy_server` stores it on the server and every request handler reads `self.server.hop_tls`.

The two-env boundary (FATAL-2) is preserved: `ssl` is stdlib and `vigil_core.posture` is the neutral,
namespace-pure, pure-stdlib `VIGIL_POSTURE` parser **both** trust planes already share — never
`framework`/`strix`/`sigil`. The boundary guard `test_control_plane_boundary.py::test_uiproxy_is_pure_stdlib`
was widened to admit exactly those two (and re-proves `vigil_core.posture` is itself pure stdlib).

## The claim (registered in the claims registry — [W0-3] #398, id `W8-6`)

<!-- CLAIM:W8-6 -->
> **Registered claim (W0-3 #398):** Under the PRODUCTION posture (VIGIL_POSTURE=production/prod) the reverse proxy REFUSES TO START with a plaintext proxy->backend hop to a remote (non-loopback) backend: resolve_hop_tls raises unless hop TLS is enabled, so the per-user bearer and the substituted owner console credential never cross a network in cleartext; a loopback hop stays plaintext because its bytes never traverse a network, and outside the production posture the default hop is unchanged (byte-identical).

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
- **Real encryption when enabled.** With `VIGIL_HOP_TLS=require` and a CA (and a TLS-terminating cockpit),
  the forward and the auth hop both ride HTTPS with certificate + hostname verification; a client cert
  turns on mutual TLS.

## The residual (stated honestly, not buried)

**This change ships the CLIENT half — the mechanism that USES cert material and fails closed without it.**
The following is the operator/deployment residual, wired but not self-provided:

- **Cert material.** The CA, the cockpit's server leaf/key, and (for mTLS) the proxy's client leaf/key are
  operator-provided (a k8s `Secret`, cert-manager, or a mesh CA). No key is generated or committed by this
  change.
- **Server-side TLS termination.** The hop is TLS only if the cockpit **serves** TLS. `sigil serve` binds
  plaintext by design (a single-owner, on-host surface — see `networkpolicy.yaml`), so in-cluster the
  cockpit must be fronted by a TLS-terminating sidecar (or an equivalent mesh mTLS). The k8s manifests
  document and template this; they do not force it on by default, because an on-by-default TLS hop with no
  cert material provisioned would fail every request. Under `VIGIL_POSTURE=production` the proxy **refuses
  to start** rather than run the hop in cleartext — which is the correct fail-closed posture for a
  government deployment.

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
- cert/key loading **fails closed** on a missing/invalid CA or client cert, and on a half-configured pair.
