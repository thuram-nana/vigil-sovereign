# Playbook 16 — Microservices and service mesh

**Goal:** find security gaps specific to distributed-service
architectures — service-to-service auth, internal API exposure, mTLS
gaps, message-queue security.

Applicable when target is decomposed into independently deployed
services, often with API gateway, service mesh, message bus, and
shared data layer.

---

## 16.1 Architecture mapping

If operator can share architecture diagram or you can infer from
external behavior:

- API gateway in front (Kong, Tyk, AWS API Gateway, Apigee, NGINX,
  Traefik)?
- Service mesh (Istio, Linkerd, Consul Connect, App Mesh)?
- Message broker (Kafka, RabbitMQ, NATS, SQS, Pub/Sub)?
- Service discovery (Consul, etcd, Kubernetes DNS)?
- Shared data stores or per-service data stores?

External signals:
- HTTP response headers (`x-served-by`, `via`, `x-envoy-upstream-service-time`).
- API versioning patterns suggesting BFF (backend-for-frontend).

---

## 16.2 API gateway as auth boundary

Common pattern: the gateway authenticates, internal services trust
the gateway. This is fine *if* internal services aren't reachable
externally.

Test:
- Find internal service hosts (DNS records, IP scans of cluster's
  egress, IPs published in error messages).
- Try direct request to internal service bypassing gateway.
- If reachable → bypassing gateway = bypassing auth.

```bash
# Often internal services have direct IPs
curl -sk -H "Host: internal-svc.local" "http://<cluster-ip>:8080/admin/users"
```

If a service is internal-only, it should:
- Not be on a public IP.
- Reject requests where `X-Forwarded-By: gateway` (or equivalent)
  is missing.
- Validate JWTs from gateway (mTLS preferred).

---

## 16.3 Service-to-service authentication

For each pair of communicating services:

- **mTLS** with both server and client cert validation? Best.
- **Shared bearer token / API key** in `Authorization`? Acceptable
  if rotation happens.
- **No auth** because "they're inside the cluster"? Vulnerable to
  lateral movement (one compromised pod → all others).

If service mesh:
- Verify mTLS is in `STRICT` mode, not `PERMISSIVE`.
- AuthorizationPolicies in place for sensitive services?
- DestinationRules and VirtualServices reviewed for misconfig.

---

## 16.4 Identity propagation

When request flows through multiple services, the original user
identity should be propagated:

- JWT signed by gateway, verified by each service.
- Or `X-User-ID` / `X-User-Roles` headers (only acceptable with
  mTLS, otherwise spoofable).

Findings:
- Service trusts `X-User-ID` from any source.
- Backend service can be told "this is admin user 1" by any caller.
- Tracing IDs (`X-Request-ID`) used as auth (they're not auth!).

---

## 16.5 Internal API discovery

Look for internal endpoints that leak through:

- API gateway routes (admin / debug / metrics).
- Error messages mentioning internal hostnames.
- Distributed tracing endpoints (Jaeger, Zipkin).
- Service mesh dashboards (Kiali for Istio).
- Health-check endpoints (`/health`, `/healthz`, `/ready`,
  `/actuator/health` Spring) — sometimes leak version info.
- Metrics endpoints (`/metrics` Prometheus, `/stats` Envoy).
- Debug / admin endpoints (Spring Boot Actuator `/env`, `/heapdump`).

Spring Boot Actuator findings have been Critical many times — full
heap dump can include credentials.

---

## 16.6 Message queue security

For Kafka / RabbitMQ / NATS / SQS / PubSub:

- Auth required to produce/consume?
- Topic / queue ACLs in place per service?
- Encryption in transit?
- Sensitive data in messages (PII, secrets)?
- DLQ (dead-letter queue) accessible to many services?
- Replay attack possible (no idempotency)?

External: rarely reachable. White-box (operator-shared) gives
visibility.

---

## 16.7 gRPC inter-service

Many microservices use gRPC for service-to-service. Test:

- TLS / mTLS on gRPC channels?
- Reflection enabled in production (info leak)?
- Server-side authorization per RPC method?
- Streaming RPCs: per-message auth or just connection auth?

```bash
grpcurl -plaintext <service>:50051 list
grpcurl -plaintext <service>:50051 list <package>.<service>
```

---

## 16.8 Distributed tracing security

- Tracing IDs propagating sensitive data (user info, tokens)?
- Trace samples retaining PII?
- Tracing UI (Jaeger, Tempo) exposed without auth?

---

## 16.9 Sidecar / proxy patterns

Envoy / Linkerd-proxy / Cilium:

- Admin port (9901 Envoy admin) exposed?
- Sidecar bypass attacks (traffic that doesn't go through sidecar)?
- xDS server reachable by non-sidecars?

---

## 16.10 Output

Findings filed. Phase summary:
- Architecture (gateway, mesh, queues identified).
- Service-to-service auth posture.
- Direct internal access bypass possibilities.
- Identity propagation gaps.
- Internal endpoint exposure findings.
