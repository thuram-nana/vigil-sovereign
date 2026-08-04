# VIGIL benchmark — a real, signed, reproducible scorecard

Every number below came from an actual run on this host. Nothing is hardcoded,
aspirational, or copied from a marketing deck. Each accuracy core is committed as a
**signed, tamper-evident, offline-verifiable** artifact you can re-derive and diff. A
tier that could not run in this sandbox is marked **operator-run**, not invented.

- Host: `Linux 7.0.12+kali-amd64`, run `2026-08-04`, offense venv `.venv-offense`.
- Methodology (the full, runnable spec): [`engine/crucible/framework/v2/docs/BENCHMARK.md`](engine/crucible/framework/v2/docs/BENCHMARK.md).

---

## 1. The thesis — *soundness*, not omniscience

> **VIGIL reports only oracle-confirmed findings, so its false-positive rate is
> ~zero — and every reported finding is *provable*: oracle-confirmed AND offline
> re-verifiable from a retained proof context.**

Two properties, stated precisely so they can't be over-read:

1. **Sound (near-zero FP).** A claim becomes a *finding* only when a deterministic
   oracle fires over data a real target produced. On a corpus with complete ground
   truth, anything reported off-manifest is a false positive **by construction** —
   that is what makes the FP column honest. VIGIL's FP column is **0**.
2. **Provable.** Each finding carries a retained `oracle_context` that **re-fires**
   offline (`framework.v2 verify`), and each published scorecard is **signed** so a
   flipped digit breaks the signature. No incumbent scanner in this comparison ships
   either property.

**This is NOT a completeness claim.** Soundness (no false alarms) is orthogonal to
recall (no missed bugs). We measure recall separately (§4, M1) and report a miss as a
true recall `< 1.0` — never hide it. "Zero FP" never means "found everything".

---

## 2. Comparative head-to-head (this host, real tools)

The self-contained labelled app plants **11 bugs** (reflected XSS, boolean-blind SQLi,
error-based SQLi, open redirect, path traversal, SSTI, host-header injection,
CORS-with-credentials, and three exposures: `.git/config`, `.env`, Spring
`/actuator/env`) and ships **5 safe controls** (`/profile`, `/api/health`,
`/download`, `/greeting`, `/support`) that must never be flagged.

Signed source: [`engine/crucible/framework/v2/docs/benchmark-comparative.json`](engine/crucible/framework/v2/docs/benchmark-comparative.json)
(+`.sig.json` +`.fingerprint.txt`).

| tool | tp | fp | fn | precision | recall | f1 | time_s | peak_rss_mb | findings |
|------|---:|---:|---:|----------:|-------:|---:|-------:|------------:|---------:|
| **crucible** | **11** | **0** | **0** | **1.000** | **1.000** | **1.000** | 11.1 | 38.9 | 11 |
| sqlmap | 0 | 0 | 11 | 0.000 | 0.000 | 0.000 | 1.1 | 100.4 | 0 |
| wapiti | 2 | 7 | 9 | 0.222 | 0.182 | 0.200 | 12.4 | 49.0 | 10 |
| nikto | 0 | 8 | 11 | 0.000 | 0.000 | 0.000 | 8.3 | – | 14 |

**Incumbent versions + exact invocations on this host** (probed into the JSON at
generation time):

| tool | version | invocation |
|------|---------|------------|
| sqlmap | `1.10.6#stable` | `sqlmap -u <url> --batch` |
| wapiti | `3.2.10` | `wapiti -u <url> -f json -o <file>` |
| nikto | `2.6.0 (LW 2.5)` | `nikto -h <url> -Format json -output <file>` |
| nuclei | `v3.10.0` (installed; **not** one of the three scored) | `nuclei -u <url> -jsonl -silent` |

### Reading the table — fairness caveats (do not skip)

- **The FP column is not a "noise" scoreboard.** It counts every finding that did
  **not** match a planted bug under the strict matcher below — which conflates two very
  different things: genuine false alarms (a detection on one of the five *clean-control*
  surfaces) **and** real detections an incumbent actually made but under a different
  label or a coarser location. Concretely, some of nikto's and wapiti's counted "FP"
  are real hits on planted bugs (e.g. an `exposure` at `/.env` / `/actuator/env`, or a
  generic `sql_injection` on the injectable route) that the strict `(class, path+param)`
  key rejected. So do **not** read the incumbent FP counts as "noise a human must
  triage" — read them beside the raw per-tool finding lists. The one thing the column
  *does* state cleanly: CRUCIBLE, reporting only oracle-confirmed findings, flagged
  **none** of the five clean controls.
- **This is a soundness / FP demonstration, not a cross-tool superiority claim.** The
  manifest uses CRUCIBLE's own class vocabulary and location granularity, so CRUCIBLE's
  perfect 11/11 (P=R=F1=1.000) is partly a **home-field artifact** — the same strict
  matching that gives CRUCIBLE a clean sweep penalizes incumbents in *both* the tp and
  fp columns. The honest, portable claim is the narrow one this whole page stakes:
  every finding CRUCIBLE reports is oracle-confirmed and offline-re-verifiable, so its
  false-positive rate on the clean controls is zero.
- **sqlmap is a SQLi-specific tool scored on a multi-class corpus.** Nine of the
  eleven planted bugs are outside its remit; a 0 here is not "sqlmap is broken", it is
  "a single-class tool on a multi-class board". It is included because practitioners
  reach for it, not to dunk on it.
- **Matching is strict** — normalized `(bug-class family, path+parameter)`, greedy
  1-to-1. An incumbent that detects a bug under a **different label vocabulary**
  (generic `SQL Injection` vs the manifest's `error_based_sqli`) or a **coarser
  location** (a host-level banner vs a `request:<check>` token) scores **below what it
  actually found**. The raw per-tool finding lists tell the fuller story. This is
  **not** a claim that "incumbents find nothing".
- **Performance is a cost axis, not accuracy.** `–` = the tool does not report that
  number; it is left blank, never faked to 0.

Reproduce: `make benchmark` (see §5).

---

## 3. CRUCIBLE accuracy core (signed)

The CRUCIBLE-only run — no external tools, the always-runnable CI spine.

Signed source: [`engine/crucible/framework/v2/docs/benchmark-results.json`](engine/crucible/framework/v2/docs/benchmark-results.json)
(+`.sig.json` +`.fingerprint.txt`), rendered scoreboard
[`benchmark-scoreboard.md`](engine/crucible/framework/v2/docs/benchmark-scoreboard.md).

| tool | tp | fp | fn | precision | recall | f1 |
|------|---:|---:|---:|----------:|-------:|---:|
| crucible | 11 | **0** | 0 | **1.000** | 1.000 | 1.000 |

- Precision target ≥ 0.98 (zero FP on the safe controls is the hard requirement) — **MET**.
- **Benchmark trust-root fingerprint** (pin this out of band):
  `sha256:edb7acf448add777faef7946e351865933d6497d081d1724a37659df3bedfdaf`
  (key id `benchmark-owner`). The comparative scorecard (§2) and the coverage
  certificate (§4, M2) sign under the **same** root.

---

## 4. The two signed cores that make it *provable*

### M1 — recall accuracy core (deterministic, signed, byte-reproducible)

The comparative scorecard bundles non-deterministic fields (wall-clock, RSS, host
versions), so it can't be re-derived byte-identically. M1 carves out the part that
**is** deterministic — the accuracy facts alone — into a committed baseline that a
fresh scan reproduces **byte-for-byte**.

Signed source: [`engine/crucible/framework/v2/eval/baselines/recall-accuracy-core.json`](engine/crucible/framework/v2/eval/baselines/recall-accuracy-core.json)
(+`.sig.json` +`.fingerprint.txt`).

| metric | value |
|--------|------:|
| tp / fp / fn | 11 / **0** / 0 |
| precision / recall / f1 | 1.000 / 1.000 / 1.000 |
| ground-truth bugs | 11 |
| distinct planted classes | 9 |

- **Scope (baked into the signed bytes):** recall of the **deterministic scanner**
  (no LLM, no out-of-band collaborator) on the planted loopback corpus, for the
  on-path classes the response-visible oracles confirm. NOT LLM-`engage` recall, NOT
  a find-everything claim.
- **M1 trust-root fingerprint:**
  `sha256:6cd32e143135d03cd8bdad8037ebd7c63ca668f1531cc52d8de13415a0875747`
  (key id `recall-baseline-owner`).
- Verified this run: `pytest framework/v2/eval/tests/test_recall_baseline.py` → **9/9
  pass** (byte-identical reproduction, offline signature verify against the *pinned*
  root, a flipped number breaks it, a fresh-key re-sign is rejected by the pin, the
  private key is not committed).

### M2 — coverage / completeness certificate (signed, per-scan)

The oracle layer proves what CRUCIBLE **found**; M2 proves what it **exercised**. For
each `(surface, param, class)` the audit reached, it records whether an applicable
oracle actually **ran** and rendered a verdict — turning a silent surface from
*merely-untested* into *provably-tested-clean*. A surface is `clean` **only** when an
applicable oracle really ran; a payload sent with no adjudicating oracle is
`inconclusive`, never clean.

Signed source: [`engine/crucible/framework/v2/docs/coverage-certificate.json`](engine/crucible/framework/v2/docs/coverage-certificate.json)
(+`.sig.json` +`.fingerprint.txt`), over the default `QUERY_VALUE` param-audit scan
(`max_pages=25`, `max_depth=4`).

| dimension | value |
|-----------|------:|
| findings (oracle fired) | 8 |
| exercised-clean (oracle ran, did not fire) | 12 |
| inconclusive (payload sent, no oracle adjudicated) | 53 |
| surfaces reached | 11 |
| insertion points probed | 14 |
| distinct classes probed | 10 |
| frontier truncated / budget exhausted | 0 / no |

- **Scope (baked into the signed bytes):** coverage of the surfaces the scanner
  **reached and probed** — NOT a proof of surface completeness. Undiscovered
  endpoints are a discovery/recall question, not a coverage one; the denominator is
  the reached surface, bounded by the caps cited above.
- The **8 findings** here count param-level oracle firings on this `QUERY_VALUE` scan;
  the §2/§3 scoreboard's **11** additionally counts the exposure and host-level checks
  the benchmark adapter enables. Different scan, honestly different denominator.
- Verified this run: `pytest framework/v2/verify/tests/test_coverage_oracle.py` →
  **9/9 pass** (byte-determinism, the honesty rule, sign/verify roundtrip, tamper +
  fresh-key-resign rejection under the out-of-band pin). Signs under the same
  benchmark trust root as §2/§3.

---

## 5. Reproduce it

All commands from the repo root, in the offense venv.

```bash
source .venv-offense/bin/activate

# (a) CRUCIBLE-only signed accuracy scorecard → the canonical committed docs
make bench
#   == python -m framework.v2 benchmark --no-incumbents \
#        --report engine/crucible/framework/v2/docs/benchmark-scoreboard.md \
#        --json   engine/crucible/framework/v2/docs/benchmark-results.json --sign [--signing-key <pinned>]

# (b) comparative head-to-head vs the installed incumbents (sqlmap/wapiti/nikto)
make benchmark

# (c) the CRUCIBLE regression gate — exit 1 on ANY new FP / newly-missed / precision drop
PYTHONPATH=engine/crucible python -m framework.v2 benchmark --gate --no-incumbents
```

**Verify a signed scorecard offline against the pinned fingerprint** (no private key
needed — verification is offense-free):

```bash
PYTHONPATH=engine/crucible python - <<'PY'
import json
from pathlib import Path
from framework.v2.eval.benchmark_run import verify_scorecard
D = Path("engine/crucible/framework/v2/docs")
for base in ("benchmark-results", "benchmark-comparative"):
    jp  = D / f"{base}.json"
    sig = json.loads((D / f"{base}.sig.json").read_text())
    fp  = (D / f"{base}.fingerprint.txt").read_text().strip()   # the pin, published out of band
    print(base, "verify:", verify_scorecard(jp, sig, trust_root_fingerprint=fp))
PY
```

**Diff / re-derive the M1 accuracy core** (proves the committed numbers are current):

```bash
cd engine/crucible
PYTHONPATH=. python -m pytest framework/v2/eval/tests/test_recall_baseline.py -q   # 9/9
PYTHONPATH=. python -m pytest framework/v2/verify/tests/test_coverage_oracle.py -q # 9/9 (M2)
```

The signing key is a repo-local, **gitignored** convenience key that pins a stable,
reproducible fingerprint. On a fresh clone without it, `--sign` mints a fresh key per
run and prints its fingerprint to pin out of band; the committed `.sig.json` /
`.fingerprint.txt` stay independently verifiable regardless. Verification never needs
the private key.

---

## 6. Honest scope — what ran here, what is operator-run

**Ran here (real numbers above):** the single **in-process labelled loopback app**
(11 planted bugs, 5 safe controls). Because its ground truth is complete, the FP
column is honest by construction, and the head-to-head, M1 and M2 numbers are all from
actual runs on this host.

**Operator-run (NOT run in this sandbox — no numbers claimed):** the dockerized
multi-app corpus in the methodology doc requires Docker Hub image pulls this sandbox
cannot perform. Each ships as a JSON descriptor for an operator to stand up; a skipped
app is reported with a reason, never counted as passed.

| tier | apps | why operator-run |
|------|------|------------------|
| Neutral labelled | OWASP Benchmark 1.2 | heavy build; run via `make bench-corpus --apps owasp-benchmark` |
| Deliberately-vulnerable | Juice Shop, DVWA, VAmPI, DVGA, Mutillidae, WebGoat | need Docker Hub pulls (blocked here) |
| Real-enterprise (FP thesis) | WordPress, Drupal, Keycloak, GitLab CE, Mattermost | need Docker Hub pulls (blocked here) |
| Real historical CVE | `_cve/cve-st-2014-3744` (`st@0.2.4`, CVE-2014-3744) | needs `bash .../\_cve/build.sh` (host npm build); not run this session |

Run them with `make bench-corpus` (see the methodology doc). Whatever an operator's
host produces is written to the same committed, diffable, signable artifacts — the
point of the whole exercise is that our claim is checkable, not taken on faith.
