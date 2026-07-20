# Coverage roadmap — the service-mesh posture domain (Wave-G3)

*Wave-G3 design note. Status: first slice shipped (Istio/Linkerd config LEAD ingest + achieved-state
oracle); the rest is roadmap.*

CRUCIBLE is a reasoning OS: every external tool / config export enters the ONE world-model as a
provenance-tagged **observation — a LEAD (`GROUNDING_INTEL`), never a fact**. A LEAD becomes a FACT only
when a deterministic **oracle re-verifies** it, fail-closed. This note maps the **service-mesh** surface
onto that spine and ships the first, safest slice.

The exemplars we mirror are the two prior achieved-state posture oracles:
`verify/k8s_posture.py::confirm_k8s_posture` (a kube-bench CIS control FAILED with a concrete insecure
setting) and `verify/cloud_posture.py::confirm_cloud_posture` (a retained cloud/CSPM control whose achieved
state carries an insecure fact). The mesh oracle is their **twin**: it judges ONE retained mesh-config
control over its achieved state alone — offline, ZERO mesh/kubectl calls, **NO attack** — and promotes a
LEAD to a FACT only on a deterministic membership/parse-proof that a hardened mesh cannot exhibit. Both
halves are pure, offline, and JSON-safe, so a confirmed finding re-verifies from its certificate.

---

## 1. Why service-mesh is its own domain

A microservice target's real intra-cluster trust boundary is its **mesh posture** — mutual-TLS mode,
authorization policies, and inbound-policy defaults. This is orthogonal to the Kubernetes control-plane
posture (kube-bench, already covered) and to the container supply-chain (SBOM, covered). It is the
east-west trust layer: whether service-to-service traffic is authenticated/encrypted and whether a
workload will accept an unauthenticated caller. The coverage doctrine already lists
`16-microservices.md` as a first-class surface.

---

## 2. What shipped (first slice)

**Oracle** — `verify/oracles.py::mesh_posture_oracle`, wired via the `mesh_misconfiguration` bug-class row
and the new `OracleKind.MESH_POSTURE` (held OUT of the frozen `_ALL_ORACLES`, reachable only via the
`mesh_control` ctx field no benchmark/scan/engage finding carries — so `make gate` stays byte-identical).
It fires (0.9) on exactly three achieved states a hardened mesh cannot exhibit:

1. `permissive_mtls` — an Istio **PeerAuthentication** whose effective `mtls.mode` is `PERMISSIVE` or
   `DISABLE` (plaintext transport is accepted; a STRICT mesh cannot).
2. `authz_allow_all` — an Istio **AuthorizationPolicy** with `action: ALLOW` (or unset — Istio's default)
   whose rules provably admit **every** caller: an empty catch-all rule, or a `*` wildcard principal named
   in a `from.source.principals` clause.
3. `linkerd_unauthenticated` — a **Linkerd** server whose `default-inbound-policy` is
   `all-unauthenticated` (any client, even unmeshed/unauthenticated, may connect).

A STRICT PeerAuthentication, a scoped/`DENY` AuthorizationPolicy, an ALLOW policy with **no** rules
(deny-all), an authenticated Linkerd policy, an explicit compliant status, or any control with only
absent/unknown fields do **not** fire — near-zero-FP by construction.

**Ingestion** — no mesh substrate existed in the tree (no `sensors`/`intel`/`producers` ingest
Istio/Linkerd config), so `verify/mesh_posture.py::ingest_mesh_config` is a minimal, offline, read-only
parser: a canonical Istio PeerAuthentication + AuthorizationPolicy (or a Linkerd `default-inbound-policy`
annotation) manifest — dict / list / JSON string / YAML string (SAFE loader; PyYAML optional, no new heavy
dep) — mapped into the canonical mesh-control LEAD shape. It recognises the two Istio security kinds plus
the Linkerd annotation and **skips everything else**; it never raises, never calls a mesh/kubectl API, and
never attacks.

**Seam** — `confirm_mesh_posture` / `mesh_posture_context` mirror the k8s/cloud seams; a confirmed fact
re-verifies offline (`verify.reverify`, `confirmed_by == "mesh_posture"`).

---

## 3. Deliberate near-zero-FP conservatism (honest caveats)

- **`to`-only ALLOW rules do NOT fire.** An ALLOW rule that restricts by `to` (path/method) but omits
  `from` admits any principal to those paths — but operators legitimately publish public endpoints this
  way, so firing would risk a FP. We fire only on the unambiguous allow-all (empty catch-all rule or an
  explicit `*` principal).
- **An absent mTLS mode does NOT fire.** An unset `mtls.mode` inherits a parent policy; without the parent
  in view we cannot prove the effective mode, so it stays a LEAD.
- **Workload-scoped and mesh-wide both fire, at the same confidence.** Severity/scope is recorded in
  `observed.scope` but not (yet) reflected in confidence.

---

## 4. Roadmap (deferred, in EV order)

1. **A real sensor/producer.** Promote `ingest_mesh_config` into a gated `sensors`/`intel` producer that
   mints the LEADs into the world-model (matching `sensors/k8s_runtime.py` and `sensors/cloud.py`), so the
   engagement loop discovers mesh config the operator has exported.
2. **Effective-policy resolution.** Resolve inherited/overriding PeerAuthentication + port-level `mtls`
   overrides and namespace-vs-mesh precedence, so an absent mode can be proven from the effective policy.
3. **`to`-only public-endpoint nuance.** Fire on a `to`-only ALLOW rule only when corroborated (e.g. the
   endpoint also carries sensitive data), keeping near-zero-FP.
4. **Scope-weighted severity.** A mesh-wide PERMISSIVE PeerAuthentication is graver than a workload-scoped
   one; reflect scope in the contextual severity, not the oracle's fire/no-fire.
5. **Linkerd ServerAuthorization graphs + Consul/Kuma.** Extend beyond the inbound-policy annotation to the
   full Linkerd authorization graph and to other meshes (Consul intentions, Kuma traffic-permissions).
6. **GraphQL/HTTPRoute-level authz** where the mesh delegates L7 policy.

Every deferred item stays on the same doctrine: a LEAD is minted by a gated, offline sensor; a FACT is
promoted only by a deterministic oracle re-verifying it; nothing here ever attacks the mesh.
