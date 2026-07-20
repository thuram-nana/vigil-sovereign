# Real-CVE corpus — known historical vulnerabilities in real packages

An in-process benchmark you designed yourself is inherently less persuasive than the
same methodology run against **known historical vulnerabilities**. This tier closes
that gap in a way that runs even where a prebuilt vulnerable-app image cannot be
pulled: each app pins a **real npm package at a version with a published CVE** and
exposes that package's documented flaw over HTTP. The vulnerability is not invented —
it is a cited, historical CVE in a widely-used dependency.

The vulnerable dependency comes from the npm registry (reachable in more environments
than Docker Hub), so the app is built on the host and copied into the cached `node`
base — no registry pull of a prebuilt image required.

## Apps

| dir | package @ version | CVE | class | how CRUCIBLE confirms |
|-----|-------------------|-----|-------|-----------------------|
| `st-2014-3744` | `st@0.2.4` | CVE-2014-3744 | path traversal | injects an encoded `../` into a path segment; `st` serves `/etc/passwd`; the side-effect oracle confirms on the `root:x:0:0:` file-content signature (a real file read, not a reflected path) |

## Build + run

```bash
bash framework/v2/eval/corpus_apps/_cve/build.sh          # build every app -> crucible-cve-<dir>:local
python3 -m framework.v2 benchmark --corpus --apps cve-st-2014-3744 --no-incumbents
```

Each app has a matching `eval/corpus_apps/cve-*.json` descriptor referencing its
`crucible-cve-<dir>:local` image. `node_modules/` is intentionally not committed —
`build.sh` installs the pinned vulnerable version from the registry so the CVE
provenance is explicit and reproducible.

## Verified result (this environment)

`cve-st-2014-3744`: CRUCIBLE **tp=1, fp=0, precision 1.000, recall 1.000** — it
confirms the real CVE-2014-3744 traversal via the file-content oracle with zero false
positives. This is a real, documented npm CVE, detected end-to-end through the same
harness and reporting as the in-process benchmark.
