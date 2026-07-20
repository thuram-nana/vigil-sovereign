# Kubernetes Security Checklist

> Reference checklist for engagements where Kubernetes (k8s, EKS, GKE, AKS, OpenShift, Rancher) is in scope. This is **reference material**, not a script to run top-to-bottom. Cross-reference with `playbooks/14-container-kubernetes.md`. Aligned with NSA/CISA Kubernetes Hardening Guide, CIS Kubernetes Benchmark, and MITRE ATT&CK for Containers.

---

## How to Use This Checklist

- Each item is phrased as a question OBSIDIAN must answer with evidence.
- Mark each: ✅ verified secure | ❌ vulnerable (open finding) | ⚠️ partial / cannot fully verify | ⏭ out of scope | 🚫 not applicable.
- Where an item is `❌` or `⚠️`, link to the finding ID or note ID that documents it.
- Do not check ✅ without evidence in `evidence/` or a command in `notes/command-log.md`.
- **Authorization:** confirm `targets/<name>/charter.md` explicitly authorizes cluster-level testing before any item beyond external surface enumeration. Pod escape, node compromise, and cluster-admin actions are extremely high impact and require explicit written approval.

---

## 0. Pre-Cluster: Reconnaissance & Surface

- [ ] Cluster API server endpoint identified (FQDN, IP, port — typically 6443 or 443).
- [ ] API server reachability from internet tested (`curl -k https://<api>:6443/version`, `kubectl --server=... version`).
- [ ] Anonymous access to API server tested (`curl -k https://<api>/api`, `/api/v1/namespaces`).
- [ ] `/healthz`, `/livez`, `/readyz`, `/metrics`, `/version` exposure checked (info disclosure).
- [ ] kubelet ports (10250 read/write, 10255 read-only) reachable on worker nodes from internet.
- [ ] etcd port (2379, 2380) reachable from internet (catastrophic if yes).
- [ ] Kubernetes Dashboard exposed (`/api/v1/namespaces/kubernetes-dashboard/services/...`).
- [ ] Service mesh control plane (Istio, Linkerd) ports exposed.
- [ ] Cloud metadata service reachable from inside pods (169.254.169.254 — IMDSv1 vs IMDSv2).
- [ ] Container registry endpoints fingerprinted (Harbor, ECR, GCR, ACR, Quay).
- [ ] Helm tiller (legacy v2) exposed (port 44134 — RCE if yes).

## 1. Cluster Authentication

- [ ] Authentication mechanisms enumerated (X.509 certs, static tokens, OIDC, webhook, service accounts).
- [ ] Anonymous auth enabled (`--anonymous-auth=true`)?
- [ ] `system:anonymous` and `system:unauthenticated` group bindings checked.
- [ ] Static token file in use (deprecated, plaintext credentials)?
- [ ] Service account tokens auto-mounted into pods (`automountServiceAccountToken`)?
- [ ] Service account token TTL bounded (BoundServiceAccountTokenVolume) or legacy infinite tokens?
- [ ] OIDC provider configuration verified (issuer, audience, signature validation).
- [ ] kubeconfig files exposed in repos, S3 buckets, container images, or developer workstations.
- [ ] Cloud IAM ↔ k8s RBAC mapping (aws-auth ConfigMap, GKE IAM, AKS AAD) reviewed for over-broad bindings.

## 2. Authorization (RBAC)

- [ ] Authorization mode (`--authorization-mode`) — must be `RBAC` or `Node,RBAC`. ABAC alone or AlwaysAllow = critical.
- [ ] `cluster-admin` ClusterRoleBindings enumerated (`kubectl get clusterrolebindings -o wide`).
- [ ] Subjects bound to `cluster-admin` justified (each one).
- [ ] Wildcard verbs (`verbs: ["*"]`) on Roles/ClusterRoles found and reviewed.
- [ ] Wildcard resources (`resources: ["*"]`) reviewed.
- [ ] `system:masters` group membership (bypasses RBAC entirely).
- [ ] Default service accounts with permissions beyond defaults (`get pods`, etc.).
- [ ] RoleBindings/ClusterRoleBindings for `system:authenticated` or `system:unauthenticated` (privilege to all users).
- [ ] Privilege escalation paths via `escalate`, `bind`, `impersonate` verbs.
- [ ] `create pods` permission in any namespace (path to mounting any secret, any service account).
- [ ] `get/list secrets` cluster-wide (credential harvesting path).
- [ ] `exec` / `attach` / `portforward` on pods (lateral movement / data exfil).
- [ ] `nodes/proxy` permission (kubelet API access via API server).
- [ ] `pods/eviction`, `pods/exec` mismatches (operator backdoors).
- [ ] CSR (CertificateSigningRequest) approval permissions (issuance of cluster-trusted certs).
- [ ] Custom resource RBAC (CRDs may not be covered by org-wide policies).

## 3. Pod Security

- [ ] Pod Security Standards in use (Privileged / Baseline / Restricted) per namespace.
- [ ] Pod Security Admission enabled (`enforce`, `audit`, `warn` labels on namespaces).
- [ ] Pod Security Policy (deprecated 1.25) replacements (Kyverno, OPA Gatekeeper, Pod Security Admission).
- [ ] Privileged containers (`privileged: true`) — full host access if escaped.
- [ ] `hostNetwork: true` containers (network namespace = host).
- [ ] `hostPID: true` containers (process namespace = host, can see/kill host processes).
- [ ] `hostIPC: true` containers.
- [ ] hostPath volumes mounting sensitive paths (`/`, `/etc`, `/var/run/docker.sock`, `/var/lib/kubelet`).
- [ ] `runAsUser: 0` (running as root) when not justified.
- [ ] `allowPrivilegeEscalation: true` (default true if not set).
- [ ] Capabilities granted (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH` are dangerous).
- [ ] Capabilities not dropped (`drop: ["ALL"]` should be the baseline).
- [ ] `readOnlyRootFilesystem: false` (writable root = persistence).
- [ ] AppArmor / SELinux / seccomp profiles applied (or `Unconfined`?).
- [ ] Container images pulled by mutable tag (`:latest`) vs immutable digest (`@sha256:...`).
- [ ] Image registry signature verification (Cosign, Notary).
- [ ] `imagePullSecrets` exposure (registry credentials in cleartext secrets).

## 4. Network Policy

- [ ] CNI in use (Calico, Cilium, Flannel, Weave, AWS VPC CNI) and whether it supports NetworkPolicy.
- [ ] NetworkPolicies present at all (`kubectl get netpol -A`)? Default-deny ingress/egress?
- [ ] Pods can reach API server (`kubernetes.default`) when not needed?
- [ ] Pods can reach cloud metadata (169.254.169.254) — credential theft path?
- [ ] Cross-namespace traffic restricted?
- [ ] Egress to internet allowed from sensitive workloads (data exfil risk)?
- [ ] Service mesh (Istio, Linkerd) authorization policies in place?
- [ ] mTLS enforced between pods (PeerAuthentication STRICT)?

## 5. Secrets Management

- [ ] etcd encryption at rest (`--encryption-provider-config`)? AES-CBC vs AES-GCM vs identity (none).
- [ ] Secrets stored as plain `Secret` objects (base64, not encrypted)?
- [ ] Sealed Secrets, External Secrets Operator, Vault, AWS Secrets Manager / Parameter Store integration?
- [ ] Secrets mounted as env vars (visible in `/proc/<pid>/environ`, less safe than files)?
- [ ] Secrets mounted into pods that don't need them?
- [ ] Service account tokens mounted in pods that don't call the API?
- [ ] Image pull secrets scoped per namespace (or shared cluster-wide)?
- [ ] Secret rotation cadence and process.
- [ ] Secrets in container env (via `kubectl describe pod`) leaked to logs.
- [ ] Secrets in helm values committed to git.

## 6. API Server Hardening

- [ ] `--anonymous-auth=false`.
- [ ] `--insecure-port=0` (no insecure plaintext port; default since 1.20).
- [ ] `--profiling=false` (disable pprof endpoint unless needed).
- [ ] `--audit-log-path` set, audit policy configured for sensitive actions.
- [ ] `--audit-log-maxage`, `--audit-log-maxbackup`, `--audit-log-maxsize` configured.
- [ ] Admission controllers enabled: `NodeRestriction`, `PodSecurity`, `ServiceAccount`, `ResourceQuota`, `LimitRanger`, `AlwaysPullImages` where appropriate.
- [ ] `AlwaysAdmit` admission controller — must be disabled.
- [ ] `--tls-min-version=VersionTLS12` (or higher).
- [ ] `--tls-cipher-suites` restricted to strong suites.
- [ ] `--service-account-lookup=true`.
- [ ] `--service-account-key-file` and signing key segregation.
- [ ] etcd encryption key rotation procedure.

## 7. Kubelet Hardening

- [ ] `--anonymous-auth=false` on kubelet.
- [ ] `--authorization-mode=Webhook` (not `AlwaysAllow`).
- [ ] `--read-only-port=0` (port 10255 disabled).
- [ ] `--make-iptables-util-chains=true`.
- [ ] `--protect-kernel-defaults=true`.
- [ ] `--event-qps=0` (or limited) and audit considerations.
- [ ] kubelet client cert rotation (`--rotate-certificates`).
- [ ] kubelet server cert (`--rotate-server-certificates` + manual CSR approval).
- [ ] kubelet config file permissions (`/var/lib/kubelet/config.yaml` not world-readable).
- [ ] Container runtime socket (containerd, CRI-O, dockershim) permissions on host.

## 8. Container Runtime

- [ ] Runtime in use (containerd, CRI-O, gVisor, Kata Containers).
- [ ] Runtime socket exposed (`/var/run/docker.sock`, `/run/containerd/containerd.sock`) inside any pod via hostPath.
- [ ] Image vulnerability scanning in CI and at admission (Trivy, Grype, Clair).
- [ ] Runtime threat detection (Falco, Tetragon, Tracee) — if applicable to client visibility.
- [ ] Runtime sandboxing for untrusted workloads (gVisor, Kata, Firecracker).

## 9. etcd

- [ ] etcd reachability from outside control plane network (must be no).
- [ ] etcd peer/client TLS (`--peer-cert-file`, `--cert-file`, `--client-cert-auth=true`).
- [ ] etcd client cert authentication enforced.
- [ ] etcd backups encrypted at rest, access restricted.
- [ ] etcd snapshot exposure (S3 bucket misconfig, scp leak).

## 10. Ingress & Service Exposure

- [ ] Ingress controllers in use (NGINX, Traefik, HAProxy, Istio gateway, ALB/NLB, GCE).
- [ ] Ingress controller version and known CVEs (`CVE-2022-4886` NGINX path traversal, etc.).
- [ ] LoadBalancer services exposing internal services to internet (intentional?).
- [ ] NodePort services on public worker nodes.
- [ ] Default backend exposing version info.
- [ ] TLS termination configuration; cert validity and rotation.
- [ ] HTTP→HTTPS redirect.
- [ ] Server-snippet / configuration-snippet / auth-snippet annotations (NGINX) — RCE class CVEs.

## 11. Workload Configuration

- [ ] Resource requests/limits set on every pod (DoS resistance).
- [ ] LimitRange and ResourceQuota per namespace.
- [ ] Liveness/readiness probes — and whether they expose sensitive info.
- [ ] Init containers reviewed (often run as root).
- [ ] Sidecars (especially logging, monitoring) reviewed for permissions.
- [ ] Operators / controllers in cluster — their RBAC reviewed.

## 12. Supply Chain (CI/CD into Cluster)

- [ ] How does code get into the cluster? CI runner permissions enumerated.
- [ ] CI service accounts with `cluster-admin` (very common, very bad).
- [ ] GitOps tools (ArgoCD, Flux) RBAC and exposure.
- [ ] Image signing verified at admission (Sigstore Cosign + Kyverno/policy-controller).
- [ ] SBOM generation and storage.
- [ ] Base image provenance.

## 13. Logging, Monitoring, Observability

- [ ] Audit log shipping (where do API server audit logs go?).
- [ ] Log retention period.
- [ ] PII/secrets in log streams.
- [ ] Prometheus metrics endpoints exposed (and what they leak — pod names, env vars).
- [ ] Grafana exposed with default creds.
- [ ] Jaeger / Zipkin / OpenTelemetry collectors exposed.
- [ ] kube-state-metrics exposed externally.

## 14. Cloud-Specific (when on EKS/GKE/AKS)

### EKS
- [ ] aws-auth ConfigMap reviewed for IAM principal mappings.
- [ ] IAM Roles for Service Accounts (IRSA) — pod identity binding.
- [ ] IMDSv2 enforced on worker nodes.
- [ ] EKS control plane public endpoint vs private endpoint.
- [ ] EKS control plane logging enabled (api, audit, authenticator, controllerManager, scheduler).

### GKE
- [ ] Workload Identity enabled (vs node-level service accounts).
- [ ] Private cluster mode (control plane public endpoint disabled).
- [ ] Master Authorized Networks configured.
- [ ] Binary Authorization enabled.
- [ ] Shielded GKE Nodes.
- [ ] GKE Sandbox (gVisor) for untrusted workloads.

### AKS
- [ ] Azure AD integration with RBAC (vs local accounts).
- [ ] Managed Identity vs pod identity vs Workload Identity (preview/GA).
- [ ] Private cluster mode.
- [ ] Azure Policy for AKS.
- [ ] Defender for Containers.

### OpenShift (when applicable)
- [ ] SecurityContextConstraints (SCC) — `privileged`, `anyuid` bindings.
- [ ] Routes vs Ingress, edge termination.
- [ ] OAuth integration and identity providers.

## 15. Multi-tenancy (if applicable)

- [ ] Namespace isolation (RBAC, NetworkPolicy, ResourceQuota).
- [ ] Hierarchical namespaces or vCluster usage.
- [ ] Tenant ↔ tenant escape paths (shared CRDs, shared admission webhooks, shared storage classes).
- [ ] Shared service accounts across tenants.

## 16. Backup, DR, Data

- [ ] PV/PVC encryption at rest (storage class encryption).
- [ ] Backup tooling permissions (Velero, Kasten) — backups can include secrets.
- [ ] Backup destination security (S3 bucket policy, access logging).

## 17. Common Misconfiguration Patterns to Hunt

- [ ] `serviceAccountName: default` with `automountServiceAccountToken: true` and broad RBAC.
- [ ] kubeconfig stored in `~/.kube/config` on shared dev VM.
- [ ] Kubernetes Dashboard with `cluster-admin` and no auth.
- [ ] `kubectl proxy` left running on a workstation, exposed via reverse SSH or port-forward in production.
- [ ] `kubectl exec` allowed broadly without audit.
- [ ] etcd snapshot in a public S3 bucket.
- [ ] CI pipeline using long-lived `cluster-admin` token in env var.
- [ ] Helm chart values with hardcoded secrets in git.
- [ ] Operator with `cluster-admin` for convenience.

## 18. Active Exploitation Paths to Test (with authorization)

- [ ] **Pod-to-node escape:** privileged pod → mount host filesystem → write SSH key → SSH as root.
- [ ] **Pod-to-cluster:** service account with `create pods` → mount privileged pod → escape.
- [ ] **Pod-to-cloud:** pod can reach IMDS → steal node IAM credentials → cloud account compromise.
- [ ] **etcd dump:** read all secrets, all configmaps, all RBAC.
- [ ] **kubelet API:** anonymous kubelet → exec into any pod → read secrets.
- [ ] **CSR escalation:** `create CSRs` + `approve CSRs` → mint cluster-admin cert.
- [ ] **Admission webhook hijack:** modify or create validating/mutating webhook → cluster-wide control.
- [ ] **Ephemeral container injection:** `pods/ephemeralcontainers` → exec into running pod.
- [ ] **NodeRestriction bypass:** node label/taint manipulation, pod scheduling abuse.
- [ ] **Token replay:** stolen service account token → API server access from outside cluster.

## 19. Cross-References

- Playbook: `framework/playbooks/14-container-kubernetes.md`
- Playbook: `framework/playbooks/13-cloud-native.md`
- Playbook: `framework/playbooks/15-cicd-supply-chain.md`
- MITRE ATT&CK for Containers: https://attack.mitre.org/matrices/enterprise/containers/
- NSA/CISA Kubernetes Hardening Guidance.
- CIS Kubernetes Benchmark (version-specific).
- OWASP Kubernetes Top 10.

---

**Authorization reminder.** Items in §18 (Active Exploitation) are by definition disruptive or privilege-escalating. None of them runs without explicit written approval in `targets/<name>/charter.md`. Default posture is **TEST** — observe and document the path, do not execute it, unless the charter says otherwise.
