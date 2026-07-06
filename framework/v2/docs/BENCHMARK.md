# CRUCIBLE public benchmark scoreboard

**Target corpus:** `crucible-benchmark-app` — a single self-contained, labelled
vulnerable web app with a known ground truth of eight planted bugs
(reflected XSS, boolean-blind SQLi, error-based SQLi, open redirect,
CORS-with-credentials, and three exposures: `.git/config`, `.env`, and
Spring `/actuator/env`) plus three SAFE endpoints (`/profile`,
`/api/health`, `/download`) that must never be flagged. Because the
ground truth is complete, anything a tool reports off-manifest is a
false positive **by construction** — that is what makes the FP column honest.

**Tools scored on this host:** crucible, sqlmap, wapiti, nikto. Incumbents that are not
installed are skipped, not failed. CRUCIBLE runs in-process against the
loopback target and reports only oracle-confirmed findings.

**CRUCIBLE precision target:** ≥ 0.98 (zero false
positives on the safe endpoints is the hard requirement).

**CRUCIBLE result:** precision 1.000 (MEETS target), recall 1.000, f1 1.000 (tp=9, fp=0, fn=0).

## Scoreboard

| tool | tp | fp | fn | precision | recall | f1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| crucible | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| sqlmap | 0 | 0 | 9 | 0.000 | 0.000 | 0.000 |
| wapiti | 2 | 7 | 7 | 0.222 | 0.222 | 0.222 |
| nikto | 0 | 7 | 9 | 0.000 | 0.000 | 0.000 |

### Reading the table

Scores compare a tool's output against CRUCIBLE's ground-truth manifest,
matched on `(normalized bug class, path+parameter)`. Incumbents that
detect a bug under a different label vocabulary (e.g. generic
`SQL Injection` vs the manifest's `error_based_sqli`) or a different
location granularity (a host-level message vs a `request:<check>` token)
will score below what they *found* — the raw finding lists tell the fuller
story. The FP column, by contrast, is unambiguous: it counts detections on
surfaces the corpus proves are clean.

