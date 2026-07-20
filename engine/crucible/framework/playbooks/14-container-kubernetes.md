# Playbook 14 — Container and Kubernetes

**Goal:** assess container images, runtime, and Kubernetes / orchestrator
configuration for security gaps.

Applicable when target uses Docker, Kubernetes, ECS, EKS, GKE, AKS,
Cloud Run, OpenShift, Nomad, or similar.

Many tests require operator-provided access (image registry, kubeconfig,
read-only API access). Without those, you assess from external behavior
and any visible image / manifest leaks.

---

## 14.1 Container image security

### 14.1.1 Image scanning

```bash
# Trivy — vulns + misconfigs + secrets
trivy image <registry>/<image>:<tag> --format json -o trivy.json

# Grype
grype <registry>/<image>:<tag> -o json > grype.json

# Snyk (requires token)
snyk container test <image>

# Docker Scout (built-in)
docker scout cves <image>
```

Findings:
- Critical / High CVEs in base image.
- Outdated base image (>6 months).
- Embedded secrets (`docker history` and image-layer diff).
- Running as root.
- Excessive packages (use distroless / alpine).
- No `.dockerignore` → secrets shipped in build context.
- `latest` tag in production (no version pinning).

### 14.1.2 Dockerfile review

Anti-patterns:
- `FROM ubuntu:latest` (use specific version).
- `RUN apt-get install ... && curl ... | bash` (untrusted code).
- `ADD <url>` instead of `COPY` (no integrity check).
- `USER root` (or no `USER` at all).
- `--privileged` in compose / run.
- Secrets in `ENV` (visible in `docker history`).
- No `HEALTHCHECK`.
- Combining `RUN` poorly (large image layers).

### 14.1.3 Image registry hygiene

- Public registry with private images (auth misconfig).
- Tag mutability (someone overwrote `v1.2.3`).
- Signed images? (Cosign / Notary v2).
- SBOM available?

---

## 14.2 Kubernetes — control plane

```bash
# Cluster info (with kubeconfig)
kubectl cluster-info
kubectl get nodes
kubectl version

# API server access from outside (anonymous auth?)
curl -sk https://<api-server>:6443/api/v1/namespaces
curl -sk https://<api-server>:6443/version

# kubelet exposure
curl -sk -k https://<node-ip>:10250/pods
```

Findings:
- API server reachable publicly without auth.
- Kubelet exposed (10250) and accepting anonymous.
- etcd exposed (2379) — full cluster compromise.
- Dashboard exposed without auth.
- Outdated K8s version.

---

## 14.3 RBAC

```bash
# All cluster-wide roles and bindings
kubectl get clusterroles,clusterrolebindings -o json > clusterroles.json
kubectl get roles,rolebindings -A -o json > roles.json

# What can a service account do?
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>

# Excessive permissions
kubectl get clusterrolebindings -o json \
  | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
```

Findings:
- `cluster-admin` bound to default service account.
- Broad verbs (`*`) on `*` resources.
- Bindings to `system:authenticated` group (anyone with token wins).
- `system:masters` group used for non-emergency access.

`kubescape`, `kube-bench`, `kube-hunter` automate.

---

## 14.4 Pod security

### 14.4.1 Pod Security Standards / Admission

- Privileged containers allowed?
- `hostNetwork`, `hostPID`, `hostIPC` permitted?
- `hostPath` mounts to sensitive paths (`/var/run/docker.sock`,
  `/etc`, `/`)?
- Capabilities (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`)?
- `runAsRoot: true`?
- `readOnlyRootFilesystem: false`?
- Service-account token automount on pods that don't need it?

### 14.4.2 Workload review

```bash
# Workloads with potentially-sensitive configs
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | {ns: .metadata.namespace, name: .metadata.name}'

kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork == true) | {ns: .metadata.namespace, name: .metadata.name}'

kubectl get pods -A -o json | jq '.items[] | select(.spec.volumes[]?.hostPath) | {ns: .metadata.namespace, name: .metadata.name}'
```

---

## 14.5 Secrets management

- Secrets stored as plaintext in manifests committed to git?
- `kubectl get secret <name> -o yaml` decodable (base64 only, not
  encrypted at rest)?
- Encryption at rest enabled (`--encryption-provider-config` on API
  server)?
- External secrets (External Secrets Operator, Sealed Secrets,
  Vault Agent Injector) used for sensitive values?

---

## 14.6 Network policies

- Default deny? Or default allow (most clusters)?
- Egress policies preventing pod → metadata (169.254.169.254) and
  pod → external internet (where unneeded)?
- Service mesh (Istio, Linkerd) with mTLS?
- Ingress controllers with TLS termination, headers hardened?

---

## 14.7 Container escape vectors

If you have shell in a container (operator-authorized):

- Mounted Docker socket → control host.
- `--privileged` → kernel exploitation.
- `cap_sys_admin` → cgroup release-agent escape.
- Procfs writable → mod-loading via `/proc/sysrq-trigger`.
- Old kernels (Dirty Pipe, Dirty COW).

`kubectl-who-can`, `peirates` automate.

---

## 14.8 Supply chain on container builds

- BuildKit / kaniko / Buildah used securely?
- CI/CD has signing keys in plaintext (see playbook 15)?
- Image tags signed (Cosign)?
- Admission controllers verify signatures (Connaisseur, Kyverno,
  Sigstore Policy Controller)?

---

## 14.9 Service mesh

If Istio / Linkerd / Consul Connect:
- mTLS enforced between services?
- AuthorizationPolicies in place?
- Egress traffic to external services routed and authenticated?

---

## 14.10 Output

Findings filed. Phase summary:
- Image vulns / misconfigs.
- RBAC gaps (especially over-privileged service accounts).
- Pod security gaps.
- Secrets management posture.
- Network policy posture.
