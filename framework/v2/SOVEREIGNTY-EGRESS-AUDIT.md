# SOVEREIGNTY-EGRESS-AUDIT — every code path that leaves the host

Source-level audit of every network-I/O call site in
`framework/v2/`. Sovereign reviewers verify this document by
re-running the audit commands and checking the residue is empty.

The categorisation is binary: a code path is either an
**expected** egress (target HTTP, in-policy LLM call) or it is a
**defect**. The "anything else" category is the defect bucket; it
must be empty.

This audit covers production code only. Test code is excluded
because tests run in CI / dev environments where the egress profile
differs from a sovereign deployment, and because tests can use mock
HTTP fixtures (`pytest-httpserver`) that don't issue real network
I/O.

---

## 1. Audit commands (re-run for verification)

```bash
# Network-I/O imports + call sites in production code:
grep -rn "httpx\.\|requests\.\|urllib\.request\|socket\.\|aiohttp\|urlopen" \
    framework/v2 --include="*.py" \
    --exclude-dir=__pycache__ --exclude-dir=tests \
    | grep -v "urllib.parse"

# Telemetry / analytics endpoints:
grep -rn "telemetry\|metrics\|sentry\|datadog\|posthog\|amplitude\|usage_statistics" \
    framework/v2 --include="*.py" \
    --exclude-dir=__pycache__ --exclude-dir=tests
```

The first command must list only call sites covered in § 2 below.
The second must produce zero hits in code (matches in docstrings or
comments are documented in § 3).

---

## 2. Expected egress paths

Every entry below is either (a) a target HTTP request bounded by
the engagement charter, or (b) an LLM API call bounded by
`SovereigntyPolicy`.

### 2.1 Target HTTP

| Call site | Purpose | Bound by |
|---|---|---|
| [`framework/v2/agents/http_executor.py:357`](framework/v2/agents/http_executor.py#L357) | HttpExecutor — exploit-agent's live-HTTP path | Six safety gates: charter signature, scope, destructive prompt, request budget, posture rate-limit, posture UA |
| [`framework/v2/agents/http_executor.py:386`](framework/v2/agents/http_executor.py#L386) | HttpExecutor manual redirect-chain follow | Same gates as above; redirects capped at 5 |
| [`framework/v2/intake/http.py:160`](framework/v2/intake/http.py#L160) | UTI Fetcher — passive fingerprinting | Intake-authorization ledger + per-intake request budget |

Sovereign-mode behaviour: both call sites should be constructed with
a `SovereignHttpxTransport` injected via the `httpx.Client`
constructor. The transport refuses any host outside the
engagement allowlist (charter scope ∪ LLM substrate ∪ operator
extras). See [`framework/v2/agents/egress_guard.py`](framework/v2/agents/egress_guard.py).

### 2.2 LLM substrate

| Call site | Purpose | Bound by |
|---|---|---|
| [`framework/v2/kernel/backends/ollama.py:44`](framework/v2/kernel/backends/ollama.py#L44) | Ollama probe (`/api/version`) | localhost (sovereign-permitted) |
| [`framework/v2/kernel/backends/ollama.py:49`](framework/v2/kernel/backends/ollama.py#L49) | Ollama tag list (`/api/tags`) | localhost (sovereign-permitted) |
| [`framework/v2/kernel/backends/ollama.py:91`](framework/v2/kernel/backends/ollama.py#L91) | Ollama inference (`/api/chat`) | localhost (sovereign-permitted) |
| `framework/v2/kernel/backends/anthropic.py` (via SDK) | Anthropic Messages API | **Refused under sovereign mode** by `SovereigntyPolicy.assert_permitted()` at construction |
| `framework/v2/kernel/backends/claude_code.py` (subprocess) | `claude -p` — process I/O, subprocess talks to Anthropic | **Refused under sovereign mode** |

In sovereign mode the only LLM-substrate egress that survives is to
`localhost` — the policy refuses cloud backends before they
construct, so the SDK never imports and the subprocess never
spawns.

### 2.3 Subprocess + filesystem (not network egress, but trust-relevant)

| Call site | Purpose | Concern |
|---|---|---|
| [`framework/v2/kernel/backends/claude_code.py`](framework/v2/kernel/backends/claude_code.py) | Spawns `claude -p` as a subprocess | The subprocess's network behaviour is opaque to CRUCIBLE; sovereign mode policy-refuses this backend. |
| [`framework/v2/intake/cli.py`](framework/v2/intake/cli.py) | Reads / writes engagement filesystem | Bounded by `paths.target_dir(slug)` — never escapes operator's filesystem. |

---

## 3. Documentation-only matches

Strings matching the audit greps that are NOT call sites:

| File | Line | Context | Verdict |
|---|---|---|---|
| `framework/v2/common/errors.py` | docstring of `SovereigntyViolation` | mentions "third-party telemetry endpoint" as a *threat description* | safe |
| `framework/v2/kernel/backends/claude_code.py` | docstring | mentions "cost / token telemetry we record into the CallTrace" — telemetry of CRUCIBLE's own call costs, written to local filesystem only | safe |

These are docstrings and comments. No actual telemetry endpoint is
contacted by CRUCIBLE.

---

## 4. The "anything else" bucket

After running the audit commands and excluding § 2 + § 3:

**Empty as of Session 7 review.** No CRUCIBLE production code path
egresses to a non-target / non-LLM host.

If a future change introduces a new network-I/O site, the audit
must be updated and the call site must be either justified under
§ 2 or removed. CI runs the audit greps and fails on new entries
that aren't in this document.

---

## 5. Runtime backstop

Source-level auditing is necessary but not sufficient. A malicious
or malfunctioning dependency could issue HTTP requests from inside
its own code. The runtime backstop is `SovereignHttpxTransport`
([framework/v2/agents/egress_guard.py](framework/v2/agents/egress_guard.py)):

- Wraps a real `httpx.HTTPTransport`.
- Every request's host is matched against an `EgressAllowlist` (engagement
  scope ∪ LLM substrate ∪ operator extras).
- Mismatch → `SovereigntyViolation` raised before bytes leave the host.

In sovereign mode, sovereign deployments must wire this transport
into every `httpx.Client` they construct. The framework provides
the transport; the deployment wires it. Tests in
[`framework/v2/agents/tests/test_egress_guard.py`](framework/v2/agents/tests/test_egress_guard.py) confirm the
guard fires on off-allowlist egress.

---

## 6. What this audit does NOT cover

- Network behaviour of subprocesses spawned by CRUCIBLE (specifically `claude -p`). Sovereign mode policy-refuses those backends.
- Network behaviour of the Python interpreter itself (e.g. SSL truststore updates). Trust delegated to the OS / distribution.
- Network behaviour of `pip install` during dependency installation. That is a build-time / install-time concern, addressed by hash-pinning + private mirrors. See [`SECURITY.md`](../../SECURITY.md) § 4.2.
- Network behaviour of operator-supplied tooling outside CRUCIBLE (e.g. shell scripts in `bin/`).

These are operator-deployment-environment concerns, mitigated by
firewall rules, OS profiles, and the supply-chain hardening in
SECURITY.md — not by application code.

---

## 7. Audit revision history

| Date | Sessions reviewed | Reviewer | Verdict |
|---|---|---|---|
| 2026-05-05 | Sessions 1–7 | OBSIDIAN (initial audit) | "anything else" bucket empty |

Sovereign deployments should re-run this audit on every release
candidate cut and append a row.
