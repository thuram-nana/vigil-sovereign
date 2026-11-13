# CodeQL triage — 2026-11-10 (CQ-1)

How every **critical** and every non-path **high** CodeQL result on `main` was handled. The policy is the one
`integration/vigil_integration/live/tls_breadth.py` already follows: **fix what is real; what is by design is
recorded here with a checkable rationale and is the owner's to dismiss ("won't fix") or to scope out — never
suppressed inline** (an inline `# codeql[...]` comment is not honoured by this repo's analysis anyway).

**Method.** CodeQL 2.27.4, `python-security-extended` and `javascript-security-extended`, run locally over the
whole repository and filtered with the workflow's own `paths-ignore` (the scope CI reports). Before CQ-1 the CI
scope held 235 Python results (26 critical, 196 high, 13 medium); JavaScript was not analysed in CI at all
(5 results locally).

## Fixed in CQ-1

| Rule | Where | What was wrong → fix |
|---|---|---|
| `py/insecure-temporary-file` ×6 | `sigil/perception/capture.py`, `sigil/platform/{android,macos,windows}.py` | `tempfile.mktemp` returned a guessable NAME in the shared temp dir (another local user could pre-plant it or a symlink). Each capture now writes inside its own fresh `0700` directory (`private_capture_path`). |
| `py/bad-tag-filter` ×2 | `aegis/inspect.py` (reflected-XSS oracle), `scanner/domxss.py` | `</script>` missed `</script >` / `</script\n x>`, which browsers accept — an attacker could hide a payload's script body from the AEGIS oracle, and the DOM-XSS scanner skipped such inline scripts. Now `</script\b[^>]*>`. |
| `py/insecure-protocol` ×1 | `sigil/bridge/server.py` (phone-approval channel) | TLS 1.2 floor is now explicit instead of inherited from the interpreter / OpenSSL default. |
| `py/command-line-injection` ×1 | `console/actions.py` run-tests → `vigil sandbox` | The operator / LLM-proposed command now follows `--`, so text beginning with `-` can never be read as a sandbox option (e.g. `--approve`). Not exploitable before (a lone option token leaves the required command missing and argparse refuses), now structural. |
| `js/incomplete-html-attribute-sanitization` ×2 | `sigil/bridge/webapp/app.js` (phone PWA) | `esc()` did not escape quotes but its output is placed in `data-seq="…"`. Now escapes `"` and `'`. |
| `js/unvalidated-dynamic-method-call` ×1 | `ui/customer_app/app.js` router | Fixed in CHK-2 (#1059): only a constant route name ever indexes `ROUTES`. |
| `js/remote-property-injection` ×2 | `packages/vigil-ui/app.js` `hashQuery()`, `public_site/tools/cvss-calculator/cvss.js` | User-controlled keys now only select one of the app's OWN key names; unknown / `__proto__` keys are dropped. |

After CQ-1: CI-scope Python 225 results (no new result on any changed line); whole-repo JavaScript **0**, and a
CodeQL JavaScript job now runs on every PR (advisory, like the Python one).

## By design — owner to dismiss with this rationale (or keep open)

| Rule | Where | Why it is not a vulnerability |
|---|---|---|
| `py/command-line-injection` ×10 | `console/actions.py` (learn, refresh-vulnintel, feed-daemon, codescan verify, strix run, patch, apply-fix, terminal, plan, ingest) | argv LIST, `shell=False`, fixed executable (`sys.executable` / the `vigil` entrypoint); every operator-derived token is allowlist-validated first (`_SLUG_RE`, `_VULN_ID_RE`, `_valid_finding_ref`, `_SEED_DOMAIN_RE` — all start with an alphanumeric, so none can be read as an option); the terminal action already passes `--`. CodeQL does not model custom regex validators. |
| `py/command-line-injection` | `live/executor.py:191` | The governed executor: argv list, `shell=False`, charter argv allowlist, optional egress guard. Running the operator's approved command IS its job. |
| `py/command-line-injection` | `live/sandbox_exec.py:172` | The command is ONE argv element after bwrap's `--`, run by `/bin/sh -c` INSIDE the network-isolated, workspace-confined box — it cannot reach bwrap's own options. |
| `py/command-line-injection` | `console/oob_collaborator.py:385` | Fixed interpreter + module + loopback host + a port we picked + a path under the validated slug dir. |
| `py/partial-ssrf` ×3 | `sigil/ui/ownership_fetch.py` | Fetching the customer's OWN host is the feature (domain-ownership proof). Every resolved address must be global (loopback / link-local / RFC1918 / CGNAT / ULA refused), the socket is pinned to the validated IP, https only, no redirects, bounded read, absolute deadline. |
| `py/partial-ssrf` | `integration/uiproxy.py:2255` | Reverse proxy: only the PATH is forwarded, to a pinned loopback / configured backend; the TCP peer is fixed by the connection, `http.client` rejects CR/LF. |
| `py/partial-ssrf` | `aegis/gateway.py:569` | The AEGIS gateway forwards to the OPERATOR-configured upstream only; `follow_redirects=False`, `trust_env=False`, bounded response. |
| `py/weak-sensitive-data-hashing` ×4 | `ui/sessions.py:51`, `ui/settings.py:650`, `vigil_core/escrow.py:318,384` | SHA-256 of a random 256-bit session id (a filename), of a high-entropy API key for a display fingerprint (domain-separated), and of an already-SEALED blob for integrity. None is a password; a slow KDF would add per-request latency for no security gain. (The one real case — NH-1's body binding keyed by a hop secret — was fixed with PBKDF2 in #1056.) |
| `py/insecure-protocol` ×5 | `live/egress_floor.py:698`, `scanner/quantum_era.py`, `verify/tls.py`, `scanner/websocket.py`, `ui/ownership_fetch.py:259` | The first four are TLS POSTURE PROBES of a target — offering old versions is the measurement (same rationale as `tls_breadth.py`). `ownership_fetch` already pins TLS ≥ 1.2 explicitly; CodeQL does not see the pin. |
| `py/clear-text-logging-sensitive-data` ×16 | CLI status / backup / restore / knowledge, livefire tools | All 16 read line by line: a redacted settings status and key fingerprints, secret NAMES and paths, file / key COUNTS and booleans (`owner_key=True`), warnings, a refusal reason, and the passphrase only under the explicit `--print-passphrase` flag. The livefire capture's `secret` field is the literal `"[REDACTED]"` and its identifier a non-secret prefix. None prints a secret value implicitly. |
| `py/tarslip` | `sigil/spine/upgrade.py:144` | `_safe_extract` resolves every member and refuses one outside the target, AND uses the stdlib `data` filter. |
| `py/overly-permissive-file` | `posture/bundle.py:104` | `0o644` on the PUBLIC, secret-free offline verifier inside a bundle made to be shared. |
| `py/incomplete-url-substring-sanitization` | `live/github_client.py:64` | The host is never used (the REST base is pinned); the remainder must match the exact `owner/repo` regex or it is refused. |
| `py/xml-bomb` | `scanner/sso.py:131` | A DOCTYPE pre-scan refuses the document AND the expat DOCTYPE handler raises — entity expansion never starts. |

## Deliberately vulnerable fixtures — owner decision: scope them out?

These files exist to BE vulnerable: they are the ground truth the SAST / DAST benchmarks score against, so
"fixing" them would destroy the benchmark. The workflow already excludes `**/eval/corpus/**` and
`**/corpus_apps/**` for exactly this reason; these were not covered.

- `engine/crucible/framework/v2/analysis/benchmark/python/{vulnerable,sanitized,interprocedural}.py` — critical:
  command-line-injection ×3, full-ssrf, code-injection, template-injection (`sanitized.py` being flagged is
  itself a CodeQL false positive — the benchmark measures exactly that);
- `engine/crucible/framework/v2/eval/benchmark_app.py` — critical full-ssrf; high sql-injection;
- `engine/crucible/framework/v2/scanner/benchmark.py` — high sql-injection (the soundness fixture for boolean
  inference).

Proposed (not applied — it changes what CodeQL reports): add `'**/analysis/benchmark/**'`,
`'**/eval/benchmark_app.py'` and `'**/scanner/benchmark.py'` to the Python job's `paths-ignore`.

## Not yet triaged in depth

- `py/path-injection` ×139 — the bulk; most are paths built from validated slugs / run ids under a fixed root.
  Needs a per-site pass (a follow-up), not a blanket call. **Done for the internet-facing sovereign plane** (the
  12 sites in `ui/custui.py`, `ui/server.py`, `bridge/server.py`, `ui/durability.py`, `ui/hostcmd.py`): every
  one is guarded — `resolve()` + containment in the content root (custui SPA, bridge PWA, durability backups),
  an exact allowlist (`_STATIC_OK`), or a strict id format (`hostcmd.run_status` requires `isalnum()` of a
  `token_hex` run id). By far the rest sit in the operator console / engine (`console/actions.py` 36,
  `sessions.py` 13, `oob_collaborator.py` 12, `vigil_core/highwater.py` 11, …): loopback, operator-authenticated
  surfaces — the next pass.
- `py/redos` ×3 / `py/polynomial-redos` ×7 — mostly oracle regexes evaluated on TARGET responses (a slow regex
  is a robustness risk to the scanner, not a vulnerability in the target); changing an oracle regex must keep
  the committed eval baselines byte-identical, so this is its own slice.
- `py/log-injection` ×7, `py/http-response-splitting` ×6 (medium).
