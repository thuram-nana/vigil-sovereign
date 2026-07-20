{
  "summary": "Audit SIGIL for production/enterprise readiness across 6 dimensions; return a grounded, prioritized backlog",
  "agentCount": 6,
  "logs": [
    "audit complete: 46 findings — 4 critical, 15 high, 20 medium, 7 low"
  ],
  "result": {
    "dimensions": [
      "packaging, distribution & dependency hygiene",
      "performance & scale",
      "robustness & error handling",
      "observability, operability & configuration",
      "CI/CD, testing, type-safety & linting",
      "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
    ],
    "total": 46,
    "counts": {
      "critical": 4,
      "high": 15,
      "medium": 20,
      "low": 7
    },
    "findings": [
      {
        "severity": "critical",
        "title": "No build system or package metadata — the project is not installable at all",
        "files": [
          "/home/kali/sigil/requirements.txt",
          "/home/kali/sigil/README.md",
          "/home/kali/sigil/sigil/__init__.py"
        ],
        "detail": "The repo root contains only requirements.txt, README.md and .gitignore — there is no pyproject.toml, setup.py, or setup.cfg anywhere in the tree. Consequences: (1) the package cannot be `pip install`ed (editable or otherwise); every documented invocation is `python3 -m sigil.cli` run from a working copy against a manually-created venv (README lines 176-189). (2) There is zero distributable metadata — no name, version, description, license, authors, classifiers, or requires-python. (3) The MCP server registration hardcodes an absolute interpreter path `/home/<you>/.sigil/venv/bin/python -m sigil.mcp.server` (README:196) because there is no installed console tool to point at. For an enterprise/production standard this is the root gap in the whole dimension — nothing downstream (versioning, extras, reproducible installs, CI wheels) can exist without it.",
        "fix": "Add a PEP 621 pyproject.toml at repo root. `[build-system]` with `requires=[\"setuptools>=61\"]`, `build-backend=\"setuptools.build_meta\"` (classic table form — do NOT require bleeding-edge setuptools). `[project]`: name=\"sigil\", dynamic=[\"version\"] sourced from sigil/__init__.py:__version__, description, readme=\"README.md\", license, authors, `requires-python=\">=3.11\"`, and `dependencies` populated from requirements.txt. `[tool.setuptools.packages.find]` include=[\"sigil*\"]. Then `pip install -e .` becomes the install path and the venv/`-m sigil.cli` prose in the README collapses to one line.",
        "effort": "medium",
        "dimension": "packaging, distribution & dependency hygiene"
      },
      {
        "severity": "high",
        "title": "numpy is a hard runtime dependency but undeclared; entire voice/vision/gesture ML stack undeclared with no extras",
        "files": [
          "/home/kali/sigil/requirements.txt",
          "/home/kali/sigil/sigil/voice/backends.py",
          "/home/kali/sigil/sigil/platform/secrets.py",
          "/home/kali/sigil/sigil/platform/windows.py"
        ],
        "detail": "requirements.txt declares only 7 packages (cryptography, fastembed, kuzu, mcp, onnxruntime, pydantic, qdrant-client). But sigil/voice/backends.py:14 does a TOP-LEVEL `import numpy as np`, so importing the voice module — including the pure-metadata paths `sigil voice --find-voice` / `--set-voice` — hard-requires numpy, which is undeclared. It only happens to be present today because fastembed/onnxruntime pull it transitively; that is fragile and will break the moment a resolver picks a numpy-free wheel or those deps drop the transitive edge. Separately, the whole optional ML/hardware stack is lazy-imported and declared nowhere, so users discover each one from a traceback: faster_whisper (backends.py:151), torch/Silero (backends.py:164), openwakeword (backends.py:175), piper (backends.py:192), sounddevice (backends.py:320,329), mss (platform/windows.py:15,24), keyring (platform/secrets.py:20). The codebase is explicitly tiered (backends.py docstring: 'OPTIONAL ML (lazy-imported, graceful if absent)') yet has no [project.optional-dependencies] to match, so there is no `pip install sigil[voice]`.",
        "fix": "Add numpy (pinned) to core `dependencies` — it is a genuine top-level import. Then define `[project.optional-dependencies]` extras that mirror the code tiers: voice=[sounddevice, faster-whisper, torch, openwakeword, piper-tts], vision/perception=[...], gesture=[onnxruntime already core], secrets=[keyring], and an `all`/`dev` aggregate. Document `pip install sigil[voice]`. Keep the lazy-import graceful-degradation as-is; the extras just make the install intentional instead of trial-and-error.",
        "effort": "medium",
        "dimension": "packaging, distribution & dependency hygiene"
      },
      {
        "severity": "high",
        "title": "Rust kernel binary located via a hardcoded /home/kali/sigil path with no build/packaging integration",
        "files": [
          "/home/kali/sigil/sigil/voice/dispatch.py",
          "/home/kali/sigil/kernel/Cargo.toml",
          "/home/kali/sigil/sigil/agents/kernel_classify.py"
        ],
        "detail": "_default_bin() in sigil/voice/dispatch.py (lines 11-25) resolves the kernel by: env SIGIL_KERNEL_BIN → package-relative parents[2]/kernel/target/{release,debug} → a HARDCODED `Path(\"/home/kali/sigil\")` fallback (line 21) → bare `sigil-kernel` on PATH. The hardcoded operator-machine path ships inside the distributed package and is meaningless on any other host. Worse, once the package is pip-installed into site-packages, `parents[2]/kernel/...` no longer points at the repo either, and there is NO mechanism to build or bundle the Rust binary — no setuptools-rust/maturin, no cargo invocation in any install hook, and kernel/target is .gitignored so nothing is shipped. The kernel is not optional cosmetics: voice dispatch (KernelDispatch.send) and agents/kernel_classify.py:25 both shell out to it, so an installed copy silently falls back to a non-existent binary. This resolver is also duplicated-by-import (kernel_classify reuses _default_bin), so the bug has one source but two call sites.",
        "fix": "Remove the `/home/kali/sigil` literal from the fallback tuple (line 21) — never embed an operator-specific absolute path in shipped code. Then commit to a distribution story: (a) build the kernel with setuptools-rust or maturin and ship it as package data, resolving via importlib.resources.files('sigil')/..., OR (b) treat it as an external prerequisite — default to PATH lookup + document SIGIL_KERNEL_BIN and the `cargo build --release` step as an install requirement, and fail loudly (clear message) when absent instead of returning a bare name that ENOENTs. Reconcile the crate version (Cargo.toml=0.1.0) with the Python package version too.",
        "effort": "large",
        "dimension": "packaging, distribution & dependency hygiene"
      },
      {
        "severity": "high",
        "title": "No console entry point — `python -m sigil` does not even work",
        "files": [
          "/home/kali/sigil/sigil/cli.py"
        ],
        "detail": "main(argv=None) is defined at sigil/cli.py:472 and guarded by `if __name__=='__main__'` (line 599), but there is no [project.scripts] declaration (no pyproject) and no sigil/__main__.py. So the only invocation is the verbose `python3 -m sigil.cli` used throughout the README/usage; even `python -m sigil` fails because the package has no __main__.py. There is no `sigil` command on PATH after any install, which is what every downstream integration (systemd unit, MCP registration, docs) would want to reference.",
        "fix": "In pyproject add `[project.scripts]` -> `sigil = \"sigil.cli:main\"` so an installed environment exposes a `sigil` binary. Also add sigil/__main__.py containing `from .cli import main; main()` so `python -m sigil` works as a fallback. Then rewrite README usage from `$V -m sigil.cli ...` to `sigil ...`.",
        "effort": "small",
        "dimension": "packaging, distribution & dependency hygiene"
      },
      {
        "severity": "medium",
        "title": "Version single-sourcing, license, and metadata absent; Python vs Rust versions diverge",
        "files": [
          "/home/kali/sigil/sigil/__init__.py",
          "/home/kali/sigil/kernel/Cargo.toml"
        ],
        "detail": "The Python version lives only in sigil/__init__.py:6 (__version__ = \"0.0.1\") while the Rust crate kernel/Cargo.toml is at version 0.1.0 — two unrelated schemes for one product, with no reconciliation. There is no LICENSE file referenced, no authors/description/classifiers, and no readme binding. Nothing surfaces the version to `pip show`/wheel metadata because there is no packaging. This blocks release discipline (changelogs, pinned upgrades, provenance) expected at enterprise standard.",
        "fix": "Use `[project] dynamic=[\"version\"]` with `[tool.setuptools.dynamic] version={attr=\"sigil.__version__\"}` so the __init__ value is the single source. Add an explicit license (SPDX string in the classic license table form to stay compatible with stock LTS setuptools), authors, description, and readme=\"README.md\". Agree one versioning policy across the Python package and the Rust crate (e.g. keep them in lockstep or document why they differ).",
        "effort": "small",
        "dimension": "packaging, distribution & dependency hygiene"
      },
      {
        "severity": "medium",
        "title": "No reproducible-install artifact: exact pins but no hash lock and no enforced Python floor",
        "files": [
          "/home/kali/sigil/requirements.txt",
          "/home/kali/sigil/README.md"
        ],
        "detail": "requirements.txt uses exact == pins (good) but there is no hash-pinned lockfile (pip-compile/uv.lock/requirements.lock) for reproducible, tamper-evident installs, and no requires-python floor is enforced anywhere — the README claims Python 3.13 (line 170) but nothing machine-checks it, and the code's `str | None` runtime unions in signatures actually require >=3.10. The non-Python prerequisites (Docker/Qdrant, Ollama, scrot, ydotool/xdotool) are prose-only in the README, not encoded in any manifest. By contrast the Rust side already ships kernel/Cargo.lock, so the Python side is the weaker half.",
        "fix": "Generate a hashed lock (`pip-compile --generate-hashes` or `uv lock`) checked into the repo for CI/production installs; keep requirements.txt (or pyproject dependencies) as the human-edited source. Set an accurate `requires-python` in pyproject (>=3.11 given the union syntax and 3.13 target). Optionally capture system prerequisites in a Dockerfile or a documented `extras`/`constraints` file so the environment is reproducible rather than prose.",
        "effort": "medium",
        "dimension": "packaging, distribution & dependency hygiene"
      },
      {
        "severity": "low",
        "title": "Test suite and CI not wired into packaging — tests run as ad-hoc scripts",
        "files": [
          "/home/kali/sigil/tests",
          "/home/kali/sigil/README.md"
        ],
        "detail": "The 25 test files under tests/ are executed by a shell loop `for t in tests/test_*.py; do ~/.sigil/venv/bin/python \"$t\"; done` (README:307) and each file carries its own hand-rolled pass/fail printer under `if __name__` (e.g. tests/test_integrity.py tail prints 'X/Y integrity guarantees hold') rather than being collected by a standard runner. There is no [tool.pytest.ini_options], no dev/test extra pulling in pytest, and no CI workflow. This means no standard `pytest`, no exit-code-based gating, and no automated wheel/build verification — a gap for production release gating.",
        "fix": "Add a `dev` optional-dependency extra with pytest; add `[tool.pytest.ini_options]` with `testpaths=[\"tests\"]`. The files already define `test_`-prefixed functions so pytest can collect them — keep the __main__ blocks as a fallback but make `pytest` the canonical entrypoint. Add a minimal CI workflow that installs the package + dev extra, builds the kernel, and runs pytest so builds are gated.",
        "effort": "medium",
        "dimension": "packaging, distribution & dependency hygiene"
      },
      {
        "severity": "critical",
        "title": "No seq→byte-offset index: iter_records(since_seq) re-reads and JSON-parses the entire 92MB/43k spine on every call",
        "files": [
          "/home/kali/sigil/sigil/spine/store.py"
        ],
        "detail": "iter_records (store.py:103-114) opens the file and json.loads() EVERY line from byte 0, then merely FILTERS `if d[\"seq\"] > since_seq`. `since_seq` does not seek — it only discards lines after parsing them. The on-disk spine is already 97,059,527 bytes / 43,404 records (I measured it; the brief's 22MB is stale). So every one of the ~38 call sites pays a full 92MB read + 43,404 JSON parses regardless of how few records it wants. get(seq) (store.py:115-121) inherits this: it starts iter_records at byte 0 and only `break`s once r.seq>seq, so fetching a near-tail seq parses essentially the whole file — get() is O(seq-position), not O(1), yet it's called per-record in notifier/operator/actor/ui/server/bridge/server/egress/actor_gate. This is the single root cause behind every other perf finding. Note the cost is IO+CPU (JSON parse), not memory — iter_records is a generator, so streaming is already fine; the fix is indexing, not chunking.",
        "fix": "Add a persistent sidecar offset index `spine.idx` — a packed int64 array where entry i is the byte offset of the line whose seq==i (seqs are contiguous from 0). Build it with one scan if missing/stale (compare its length to the on-disk head seq via _last_nonempty_line). append() already runs under the lock and knows the offset: capture `off=f.tell()` before writing and append `off` to the index in the same critical section (O(1)). Then get(seq)=seek(idx[seq]);readline;parse (O(1)); iter_records(since_seq=s)=seek(idx[s+1]) and read forward (O(k) in the number of NEW records). mmap the index for zero-copy random access. This one change makes get/since_seq/tail all O(1)/O(k) and unblocks findings 2-8.",
        "effort": "large",
        "dimension": "performance & scale"
      },
      {
        "severity": "critical",
        "title": "KillSwitch.is_engaged() full-scans the spine on EVERY governor decision — batch proposal dispatch is O(proposals × 92MB)",
        "files": [
          "/home/kali/sigil/sigil/governor/killswitch.py",
          "/home/kali/sigil/sigil/governor/core.py",
          "/home/kali/sigil/sigil/agents/base.py"
        ],
        "detail": "Governor.decide (core.py:75) calls self.kill.is_engaged() for every non-A0 proposal, and is_engaged() (killswitch.py:40) does a full `for r in self.store.iter_records()` over all 43,404 records to find the latest kill/release. Agent._dispatch (base.py:74-100) calls governor.decide once PER proposal in a batch, and the kill state cannot change within a synchronous batch — yet it is re-scanned every iteration. A run that emits M proposals (STEWARD, consolidation promote_all, SENTINEL) does M full 92MB scans = O(M × file). For A2 proposals is_promoted() (promotion.py:48) adds a second full scan, and if budgets.json is configured budget.spent() (budget.py:30) adds a third. This is the hottest path in the system (every agent action) and it is quadratic in spine size when proposals scale with history.",
        "fix": "(a) The kill signal is a tiny latch — read it via store.tail(N) or the offset index (only the newest engage/release matters after the last release), not a full scan. (b) Memoize the verdict on (st_size, st_mtime_ns) exactly like SessionGate._killswitch_engaged already does (session.py:112-129) — that stat-guard pattern is correct and should be generalized into KillSwitch/Governor. (c) At minimum, scan kill/promotion ONCE per _dispatch batch (state is immutable across a synchronous batch) instead of once per proposal.",
        "effort": "medium",
        "dimension": "performance & scale"
      },
      {
        "severity": "high",
        "title": "PushNotifier.poll() re-fetches each event with store.get() the tailer already read — O(K × 92MB) per poll",
        "files": [
          "/home/kali/sigil/sigil/bridge/notifier.py",
          "/home/kali/sigil/sigil/spine/tail.py"
        ],
        "detail": "PushNotifier.poll (notifier.py:23-28) calls self.tailer.poll() — one full-file read — then for EACH returned event calls self.store.get(ev[\"seq\"]) to read the payload. Because the new events are near the tail, each get() re-parses almost the whole 92MB file (finding 1). The tailer ALREADY read and parsed every one of those records; it just dropped the payload in _shape() (tail.py:36-43), which only keeps seq/kind/source/actor/ts/hash/text. So K new queued items cost 1 + K near-full scans of a 92MB file for data already in hand. This runs on the live mobile push path.",
        "fix": "Carry the fields the consumer needs in the tailer atom instead of re-fetching: add `decision`, `status`, `tier` (or the whole payload) to _shape() in tail.py, and delete the store.get() loop in notifier.py — filter directly on ev. Zero extra reads.",
        "effort": "small",
        "dimension": "performance & scale"
      },
      {
        "severity": "high",
        "title": "SpineTailer.poll() reads the whole file every tick and check_anchor() rebuilds all 43k entries each anchor check — live UI SSE + mobile push both poll continuously",
        "files": [
          "/home/kali/sigil/sigil/spine/tail.py"
        ],
        "detail": "poll() (tail.py:64-80) calls store.iter_records(since_seq=self.cursor) every tick; per finding 1 that is a full 92MB read + 43,404 parses even when zero new records arrived, and both consumers named in the module docstring (UI SSE feed and mobile PushNotifier) drive poll() on a timer. check_anchor() (tail.py:82-108) calls store.entries() (store.py:157-161), a full scan that additionally materializes 43,404 ChainEntry objects (O(n) allocation) on every anchor check. On a machine polling once per second this is ~92 MB/s of steady reads that grows without bound as the spine grows.",
        "fix": "Drive poll() off the offset index (finding 1): seek to idx[cursor+1] and read only appended bytes — O(new records), and O(0)+one stat when nothing changed (short-circuit on unchanged st_size). For check_anchor, cache entries() on (st_size, st_mtime_ns) and only extend the entry list for records appended since the last call rather than rebuilding it; anchoring only needs the tail beyond the last check plus the signed head.",
        "effort": "medium",
        "dimension": "performance & scale"
      },
      {
        "severity": "high",
        "title": "BridgeDaemon.pending() does 2 full spine scans per phone poll; submit_device_approval does 2 more — each with per-record Ed25519 verification",
        "files": [
          "/home/kali/sigil/sigil/bridge/daemon.py",
          "/home/kali/sigil/sigil/mesh/registry.py",
          "/home/kali/sigil/sigil/agents/approvals.py"
        ],
        "detail": "BridgeDaemon.pending() (daemon.py:46-50) calls _authorized()→authorized_devices() (registry.py:66-76, full scan + verify_signed/Ed25519 per device record) AND approvals.pending() (approvals.py:53-68, full scan + verify_approval/Ed25519 per approval record). That is two full 92MB scans plus O(n) signature verifications on every phone poll of the queue. submit_device_approval (daemon.py:87-90) calls _authorized() (full scan) then a second full-scan dedup loop — the code comment even acknowledges 'a FULL-SPINE scan' and rationalizes it as 'human-paced', but at 92MB and growing it is a multi-hundred-ms remote round-trip that degrades forever. capability_map() (registry.py:46) has the identical full-scan-per-call shape.",
        "fix": "These are all 'fold the append-only log into latest-verified-state-per-key' projections. Cache authorized_devices()/capability_map()/pending() results keyed on (st_size, st_mtime_ns) so repeated reads within a poll burst don't re-scan or re-verify. Better: maintain a small materialized projection (device pubkey→state, approval target_seq→resolved) updated incrementally via the offset index, so a poll is O(new records since last poll), not O(file). Replace the full-scan dedup in submit_device_approval with a tail()/index lookup.",
        "effort": "medium",
        "dimension": "performance & scale"
      },
      {
        "severity": "high",
        "title": "Append-only spine has no snapshot / compaction / rotation — unbounded growth makes every rebuild and every hot path degrade linearly forever",
        "files": [
          "/home/kali/sigil/sigil/spine/store.py",
          "/home/kali/sigil/sigil/graph/rebuild.py",
          "/home/kali/sigil/sigil/vectors/index.py"
        ],
        "detail": "The spine only ever grows (append(), store.py:71-100); there is no rotation, segmenting, or compaction anywhere. It is already 92.5MB/43,404 records after a prototype's lifetime; perception OCR captured_text, subagent transcripts, and per-action gesture/approval events accrete with no ceiling. Graph rebuild (rebuild.py:_accumulate:49-97) does a FULL replay of the entire spine into a fresh Kùzu DB on every rebuild — there is no incremental path — and vectors/index.py:98 reads the whole file (since_seq) each incremental run just to reach the new tail. So both derived views' costs, and all ~38 scan sites, rise monotonically with total history and never plateau. This is the production scaling blocker.",
        "fix": "Introduce segment rotation (e.g. spine-000001.jsonl, 8-16MB each) with the offset index spanning segments, so scans/tails touch only relevant segments. Add a signed snapshot/compaction: periodically write an owner-signed materialized state (latest kill/promotion/device/caps/latest-fact-per-subject) + a checkpoint seq, and let latched-signal readers (killswitch, promotion, mesh) start from the snapshot and scan only the tail beyond it. Make graph rebuild incremental keyed on manifest.rebuilt_seq (already recorded, rebuild.py:171) instead of full replay.",
        "effort": "large",
        "dimension": "performance & scale"
      },
      {
        "severity": "medium",
        "title": "Callers use iter_records(since_seq=head−N) as a 'recent-N window' but it reads the whole 92MB file — tail() (seek-from-end) already exists and is not used",
        "files": [
          "/home/kali/sigil/sigil/agents/steward.py",
          "/home/kali/sigil/sigil/agents/sentinel.py"
        ],
        "detail": "steward.py builds the morning brief with three separate iter_records(since_seq=head−60), (since_seq=head−400), and another window (steward.py:50, 62, plus the recent-activity read) — each a full 92MB scan to obtain only the last 60-400 records. sentinel.py:27 does `sum(1 for r in iter_records(since_seq=self.since_seq) if r.kind=='commit')`, again a full read to count a recent slice. store.tail(n) (store.py:123-147) already implements exactly this as a bounded seek-from-end read (O(n bytes), not O(file)) and is used nowhere except the bridge dedup. These callers are paying O(file) for an O(window) need that the store already supports.",
        "fix": "Replace iter_records(since_seq=head−N) 'recent window' reads with store.tail(N) (or the offset-indexed since_seq once finding 1 lands). For sentinel's commit count, tail a bounded window or maintain a running count in a projection.",
        "effort": "small",
        "dimension": "performance & scale"
      },
      {
        "severity": "medium",
        "title": "Graph rebuild issues two individual Kùzu queries per entity (CREATE + MATCH-CREATE edge) — O(entities) network/DB round-trips, no batching",
        "files": [
          "/home/kali/sigil/sigil/graph/rebuild.py"
        ],
        "detail": "rebuild() (rebuild.py:132-166) loops over every project/session/document/commit and executes a separate conn.execute CREATE, then for sessions/documents/commits a SECOND conn.execute doing a MATCH (x),(p) WHERE ... CREATE (x)-[:IN_PROJECT]->(p) per entity. Each MATCH must locate both nodes. On a spine with thousands of sessions this is thousands of individual round-trips plus per-edge MATCH scans, on top of the full-spine _accumulate pass. Combined with finding 6 (always a full replay), a rebuild's cost is O(records) to read + O(entities) individual writes and grows every session.",
        "fix": "Batch the inserts — build node rows in memory (already done in _accumulate) and use Kùzu COPY FROM / parameterized multi-row inserts, and create edges by keying on the just-inserted primary keys rather than a per-row MATCH. Combine with incremental rebuild (finding 6) so only new records since manifest.rebuilt_seq are applied.",
        "effort": "medium",
        "dimension": "performance & scale"
      },
      {
        "severity": "medium",
        "title": "recall() full-scans every perception record and re-tokenizes captured_text on every remote request, only to return the LATEST match",
        "files": [
          "/home/kali/sigil/sigil/perception/recall.py"
        ],
        "detail": "recall() (recall.py:27-47) iterates the ENTIRE spine forward, and for every perception event runs _grounded_line() → salient() tokenization over the full captured_text OCR blob, keeping only the last match. It wants the most-recent sighting but reads oldest-first through all 43,404 records (and re-tokenizes potentially large OCR payloads each time) rather than stopping at the first hit from the tail. This is on the phone-facing BridgeDaemon.recall() path (daemon.py:52-63), so it is a remote request handler doing a full 92MB scan + heavy tokenization per call.",
        "fix": "Iterate newest-first (reverse via the offset index / tail segments) and return on the first grounded match — recall wants the most recent, so tail-first short-circuits after O(matches-from-end) work instead of O(all perception records). Optionally maintain a subject-token→latest-seq projection for O(1) recall on hot subjects.",
        "effort": "small",
        "dimension": "performance & scale"
      },
      {
        "severity": "high",
        "title": "A single malformed/torn spine line crashes every read path (and blocks restart after an interrupted append)",
        "files": [
          "/home/kali/sigil/sigil/spine/store.py",
          "/home/kali/sigil/sigil/spine/models.py",
          "/home/kali/sigil/sigil/spine/tail.py"
        ],
        "detail": "SpineStore.iter_records (store.py:103-113) does `d = json.loads(line)` and SpineRecord.from_dict(d) with NO error handling, and _read_last_entry (store.py:184-189) + SpineStore.__init__ (store.py:68) parse the last line the same way. append() also re-reads the tip via _read_last_entry() under the lock (store.py:91). from_dict (models.py:42-50) indexes required keys with `d[\"seq\"]`, `d[\"scope\"]`, `d[\"cert_digest\"]` etc., so a JSON-valid-but-wrong-shape line raises KeyError too. Because append() writes `f.write(json.dumps(record)+\"\\n\"); f.flush()` with no fsync and no atomic temp-swap, a crash / kill -9 / power-loss mid-append leaves a truncated final line with no trailing newline. On the next start, _last_nonempty_line returns that partial line and _read_last_entry raises json.JSONDecodeError -> SpineStore() construction throws -> the entire `sigil` CLI, the bridge daemon, and the MCP server all fail to start and cannot append. Worse, this is the source of truth for authorization: authorized_devices() and capability_map() (mesh/registry.py:66-76, 42-50) and device_nonce_highwater (bridge/envelope.py:88-101) all iterate iter_records(), and the bridge recomputes authorized_devices PER REQUEST (server.py:121-123). One bad line therefore makes every bridge request, the SSE feed, the dashboard, and the governor throw an uncaught JSONDecodeError that escapes do_GET/do_POST/SpineTailer.poll -> ThreadingHTTPServer.handle_error dumps a full traceback to stderr and drops the connection with no response. This directly contradicts the design claims in tail.py (\"the feed never re-emits or stalls\", integrity failures are \"emitted flagged (not dropped)\") and store.py's own verify() (which is supposed to be the authority on corruption but never gets to run). Note the inconsistency: tail() at store.py:142-146 ALREADY wraps json.loads/from_dict in `except (ValueError, KeyError, TypeError): continue` — the robust path exists, it just wasn't applied to the primary iterator.",
        "fix": "Make the read path crash-consistent and corruption-aware rather than fatally brittle. (1) In _read_last_entry / _last_nonempty_line, tolerate a torn FINAL line: if the file does not end in a newline, treat the trailing partial as an uncommitted write — ignore it (and optionally truncate it back to the last newline under the append lock) so the daemon always restarts. (2) In iter_records, catch json.JSONDecodeError/KeyError/TypeError per line and raise a typed SpineCorruptionError carrying the seq and byte offset (or, for read-only consumers like the tail feed, emit the record flagged integrity_ok=False and continue as tail() does) instead of letting a raw exception escape into HTTP handlers. (3) Route mid-chain corruption detection to verify(), which already exists for exactly this. This turns a total, un-restartable outage into a clean, localized, recoverable failure.",
        "effort": "medium",
        "dimension": "robustness & error handling"
      },
      {
        "severity": "high",
        "title": "No fsync on spine appends and non-atomic signed-HEAD write — a crash loses ack'd safety records and can destroy the tamper-evidence anchor",
        "files": [
          "/home/kali/sigil/sigil/spine/store.py",
          "/home/kali/sigil/sigil/spine/checkpoint.py"
        ],
        "detail": "There is no os.fsync anywhere in the codebase. SpineStore.append (store.py:97-98) does `f.write(...); f.flush()` — flush only pushes to the OS page cache; a kernel panic/power loss within the dirty-writeback window silently loses the last records. This matters because effectful records are ack'd as durable before they are: BridgeDaemon.panic_engage (bridge/daemon.py:143-149) appends the kill-switch 'engaged' event and returns `{\"ok\": True, \"seq\": ...}` to the phone; if the box loses power before writeback, the phone was told the mesh halted but on restart the kill-switch is NOT engaged — a fail-OPEN outcome on a safety control. The nonce receipt (envelope.py:79-85) can likewise be lost, re-opening a replay window. Separately, checkpoint.py:51 writes the owner-SIGNED head with `HEAD_PATH.write_text(head.model_dump_json())` — a truncate-in-place, non-atomic write. A crash mid-write leaves a truncated/empty head.json; SpineTailer._resolve_head (tail.py:113-119) then catches the parse error and returns (None, None), i.e. the whole spine silently downgrades to 'un-notarized' and the tamper-evidence anchor is gone until the owner notices and re-runs `sigil sign`. The codebase already knows the correct idiom — operator.py:311-315 uses tempfile.mkstemp + os.replace for atomic file writes — it just wasn't applied to the spine/HEAD/cursor writes.",
        "fix": "Add durability to the critical writes. (1) In append(), call os.fsync(f.fileno()) after flush (at minimum for effectful/safety kinds — kill-switch, receipts, approvals); appends are human-paced so an unconditional fsync is affordable. (2) Write HEAD_PATH via temp-file + os.replace (mkstemp in the same dir, write, fsync the fd, os.replace) so a crash can never truncate/destroy an existing valid anchor. (3) Apply the same atomic-replace to the other truncate-in-place state writes (ingest/cursor.py:24, consolidate/pipeline.py:57, governor/identity.py and spine/checkpoint.py key writes) so a crash leaves the previous valid file intact.",
        "effort": "medium",
        "dimension": "robustness & error handling"
      },
      {
        "severity": "medium",
        "title": "bridge/server.py do_POST parses Content-Length outside any try — non-numeric header escapes the handler, negative length blocks to timeout",
        "files": [
          "/home/kali/sigil/sigil/bridge/server.py"
        ],
        "detail": "In do_POST (server.py:348) `length = int(self.headers.get(\"Content-Length\", \"0\") or \"0\")` runs with no guard. A request with `Content-Length: abc` raises ValueError that escapes do_POST -> ThreadingHTTPServer.handle_error prints a full traceback to stderr and drops the connection with no HTTP response — a log-spam / info-noise vector and a divergence from this module's stated 'never leak internals as a 500' posture. A negative value (`Content-Length: -1`) passes the `length > self._MAX_BODY` check (line 349) and then `self.rfile.read(-1)` (line 351) blocks reading until EOF or the 30s socket timeout, tying up a handler thread. Notably the WS-C server this file was forked from does NOT have this bug: ui/server.py:222-225 parses Content-Length INSIDE the `try/except (ValueError, KeyError)` block that returns a clean 400. The fork dropped that protection.",
        "fix": "Parse Content-Length defensively: wrap the int() in try/except ValueError and return _deny(400, 'bad content-length'); reject negative lengths (treat <0 as 0 or 400). Mirror the ui/server.py pattern so the two forks stay consistent.",
        "effort": "small",
        "dimension": "robustness & error handling"
      },
      {
        "severity": "medium",
        "title": "KernelClassifier.classify raises AttributeError on non-object JSON, violating its documented 'fail-closed to A3 on ANY error' contract",
        "files": [
          "/home/kali/sigil/sigil/agents/kernel_classify.py"
        ],
        "detail": "classify() (kernel_classify.py:39-43) does `data = json.loads(...)` then `data.get(\"tier\")`, catching only `(ValueError, IndexError, KeyError, TypeError)`. If the kernel subprocess emits a JSON scalar or array on its last stdout line (e.g. `42`, `\"foo\"`, or `[]` — a corrupted/odd-version binary, a debug line, a wrapper that prints a bare value), json.loads succeeds and returns a non-dict, so `.get` raises AttributeError, which is NOT in the except tuple. That propagates out of classify() and crashes the caller instead of resolving to A3. This is a WARDEN danger-tier gate whose entire contract (module docstring + method docstring) is 'Any failure ... resolves to A3 (fail-closed to the most-gated tier)' and 'Fail-closed to A3 on ANY error/ambiguity' — an uncaught exception here breaks that promise on the security-critical path (Operator step tiering, Vision egress hop tiering).",
        "fix": "Guard the shape: either add AttributeError to the except tuple, or (cleaner) check `isinstance(data, dict)` before `.get`, returning Tier.A3 otherwise. Belt-and-suspenders: broaden to `except Exception: return Tier.A3` here since the whole method's spec is fail-closed-on-anything.",
        "effort": "small",
        "dimension": "robustness & error handling"
      },
      {
        "severity": "medium",
        "title": "parse_candidates coerces untrusted LLM 'confidence' with a bare float() — a non-numeric value crashes the whole extraction batch; 'inf' poisons the score",
        "files": [
          "/home/kali/sigil/sigil/consolidate/extract.py"
        ],
        "detail": "parse_candidates (extract.py:97-111) iterates model-produced JSON items with no per-item try/except. Line 108 does `model_confidence=float(it.get(\"confidence\", 0.5) or 0.5)`. The confidence field is fully attacker/model-controlled untrusted output: `\"confidence\": \"high\"` -> float('high') raises ValueError; `\"confidence\": {}` or `[]` -> TypeError; both escape parse_candidates and abort the ENTIRE window's extraction (the AgentProvider/ApiProvider call returns it directly), not just the one bad item — one malformed field discards a whole batch of otherwise-valid candidate facts and can crash the consolidation run. `\"confidence\": \"1e999\"` -> float() returns inf, silently poisoning model_confidence with a non-finite value that flows downstream into promotion math. Note the neighboring source_seqs coercion IS guarded (line 102 uses an isdigit() filter) — confidence was missed.",
        "fix": "Coerce confidence defensively per item: wrap the float() in try/except (default to 0.5 on failure), reject/clamp non-finite (math.isfinite) and clamp to [0.0, 1.0]. Better, wrap the whole per-item body (lines 99-110) in try/except Exception: continue, so a single malformed candidate is skipped rather than aborting the batch — matching the 'unreadable source is empty evidence, never a crash' doctrine used elsewhere.",
        "effort": "small",
        "dimension": "robustness & error handling"
      },
      {
        "severity": "medium",
        "title": "vectors last_indexed_seq swallows all exceptions and returns -1, silently turning a Qdrant outage into a full re-index from genesis",
        "files": [
          "/home/kali/sigil/sigil/vectors/index.py"
        ],
        "detail": "last_indexed_seq (index.py:70-76) wraps the scroll/order_by in `except Exception: return -1`. The intent (per the comment) is only to handle a missing payload index, but the broad catch also swallows a Qdrant server connection error / timeout / auth failure and reports it as 'nothing indexed'. The durable cursor is then -1, so index_spine(since_seq=-1) re-embeds and re-upserts the ENTIRE spine from genesis on every transient backend blip — expensive (re-runs the embedding model over the whole history) and needless load on the vector store, with the real failure (server unreachable) hidden. This is exactly the 'broad except that hides an operational failure and does the wrong thing' class the audit targets.",
        "fix": "Catch only the specific 'no payload index / order_by unsupported' condition and return -1 for that; let connection/timeout errors propagate (or surface them as a distinct raised error) so index_spine does not mistake an outage for an empty index and thrash a full re-index.",
        "effort": "small",
        "dimension": "robustness & error handling"
      },
      {
        "severity": "low",
        "title": "config._load_env_file reads sigil.env at import with strict UTF-8 — a non-UTF-8 byte crashes `import sigil` for the whole system",
        "files": [
          "/home/kali/sigil/sigil/config.py"
        ],
        "detail": "_load_env_file (config.py:11-23) is invoked unconditionally at module import (line 26) and does `f.read_text(encoding=\"utf-8\")` with no errors= handling. If ~/.sigil/sigil.env contains any invalid UTF-8 byte (a truncated write, an editor artifact, a copy-paste of a binary secret), read_text raises UnicodeDecodeError at import time, which aborts `import sigil` — every entrypoint (CLI, MCP server, bridge, tests) fails to load, not just the feature that needed the env var. Unvalidated external file content taking down the whole package import is a production-fragility gap.",
        "fix": "Read with `errors=\"replace\"` (or wrap the read + parse loop in try/except and log-and-continue) so a corrupt env file degrades to 'no persisted settings' rather than crashing package import.",
        "effort": "small",
        "dimension": "robustness & error handling"
      },
      {
        "severity": "high",
        "title": "11 hardcoded /home/kali absolute paths make the code undeployable on any other host",
        "files": [
          "sigil/agents/artificer.py:45",
          "sigil/agents/scholar.py:43",
          "sigil/consolidate/extract.py:119",
          "sigil/ingest/hooks.py:14",
          "sigil/agents/runner.py:77",
          "sigil/ingest/git.py:22",
          "sigil/agents/sentinel.py:40",
          "sigil/voice/dispatch.py:21"
        ],
        "detail": "Runtime paths are baked as absolute literals with no env override and no route through config.py. Concretely: (a) the frontier cognition binary `claude_bin=\"/home/kali/.local/bin/claude\"` is hardcoded in THREE places — Artificer (artificer.py:45), Scholar (scholar.py:43), ClaudeExtract (extract.py:119) — and every CLI call site constructs these with no override (cmd_agents/cmd_consolidate in cli.py), so `consolidate --provider claude`, `agents research`, `agents artifice` all invoke a path that exists only on this machine; (b) runner.py:77 defaults the ENVOY inbox to `\"/home/kali/.sigil/inbox.json\"` even though cli.py's help text advertises `~/.sigil/inbox.json` — on any other user the two disagree and the hardcoded one wins; (c) git.py:22 hardcodes the two repos to ingest; (d) sentinel.py:40 `SystemHealthWatcher(path=\"/home/kali\")` — on a host without that dir `shutil.disk_usage` raises OSError, the except returns [], and the low-disk alert SILENTLY never fires (an observability regression, not just a portability one); (e) voice/dispatch.py:21 falls back to `/home/kali/sigil` for the kernel binary. None of these read config or an env var, so a second machine is broken with no diagnostic.",
        "fix": "Add typed settings to config.py resolved env → sigil.env → default, e.g. `CLAUDE_BIN = os.environ.get('SIGIL_CLAUDE_BIN') or shutil.which('claude') or str(Path.home()/'.local/bin/claude')`, `INBOX_PATH = SIGIL_HOME/'inbox.json'`, `INGEST_REPOS = os.environ.get('SIGIL_INGEST_REPOS','').split(':') or [...]`, `DISK_WATCH_PATH = str(Path.home())`. Make the three agent constructors default `claude_bin=None` and resolve to `config.CLAUDE_BIN` when None; change runner.py to `config.INBOX_PATH`; change sentinel default to `str(Path.home())`. No caller API changes needed since these are already constructor defaults.",
        "effort": "medium",
        "dimension": "observability, operability & configuration"
      },
      {
        "severity": "high",
        "title": "Network-facing daemons emit no operational logs and suppress all request/denial logging",
        "files": [
          "sigil/bridge/server.py:114",
          "sigil/ui/server.py:63",
          "sigil/mcp/server.py",
          "sigil/bridge/server.py:192"
        ],
        "detail": "The codebase has ZERO use of the `logging` module (0 imports across sigil/) and both HTTP servers deliberately null out access logging: `def log_message(self, fmt, *args): pass` (bridge/server.py:114, ui/server.py:63). The stated intent is 'never log the auth token/envelope', but the implementation throws away the ENTIRE request log — so the WireGuard-bound bridge (a security-sensitive network service that authenticates phone device signatures and accepts effectful panic/relay actions) produces no record of who connected, which endpoint, or that a request was DENIED. Auth denials (401/403 in `_authed`, `_authed_effectful`, `_rebind_ok`) and swallowed exceptions (`_authed_effectful` bridge/server.py:192 catches `Exception` and returns `_deny(400, type(e).__name__)`; ui/server.py:231 catches `Exception` → `_deny`; mcp/server.py graph tools return `{\"error\": str(e)}`) are invisible server-side. The spine only receipts effectful `consume`, never the flood of failed/denied attempts, so there is no transport-layer audit trail and a failing daemon cannot be diagnosed in production — under systemd its stdout prints (startup banners at server.py:507-515) are the only signal, with no levels, timestamps, or error context.",
        "fix": "Add a single `sigil/logutil.py` with `configure_logging(level=os.environ.get('SIGIL_LOG_LEVEL','INFO'))` using `logging.basicConfig` with a timestamped formatter (or JSON for prod), called once from each daemon entrypoint (serve(), mcp.run wrapper, run_mic, run_gesture). Replace the no-op `log_message` with a real structured line that logs method+path+status+client but is REDACTION-SAFE by construction — it already never sees the token/envelope (those ride in headers/query the override can skip), so log `self.command`, `urlparse(self.path).path`, and the response code via a small wrapper around `_send`/`_deny`. Log every 401/403 at WARNING and every caught `Exception` at ERROR with `exc_info=True` BEFORE calling `_deny`. Keep the CLI prints in cli.py as-is (intentional user output).",
        "effort": "large",
        "dimension": "observability, operability & configuration"
      },
      {
        "severity": "medium",
        "title": "No SIGTERM/graceful-shutdown handling; daemons only catch Ctrl-C, so systemd stop is an abrupt kill",
        "files": [
          "sigil/bridge/server.py:516",
          "sigil/ui/server.py:244",
          "sigil/voice/run.py:63",
          "sigil/gesture/run.py:80"
        ],
        "detail": "There is no signal handling anywhere in the package (grep for signal/SIGTERM/atexit returns nothing). Every long-running loop guards only `except KeyboardInterrupt` (bridge/server.py:518, ui/server.py:246, voice/run.py:77). When these run as services, `systemctl stop` / `kill` sends SIGTERM, whose default action is to terminate the process immediately — the `try/except KeyboardInterrupt` never fires, `srv.shutdown()` is skipped, and in-flight handler threads (daemon_threads=True) are cut mid-request. For the bridge, an effectful request that is mid-`consume`/`panic_engage` spine append can be interrupted with no clean close. run_gesture has a `finally: g.disarm()` (good — the gesture-armed indicator is cleared even on crash) and voice closes its sink in `finally`, but neither installs a SIGTERM handler, so a systemd stop bypasses those `finally` blocks entirely. There is also no PID file and no readiness signal for `Type=notify`.",
        "fix": "In each daemon entrypoint install `signal.signal(signal.SIGTERM, lambda *_: srv.shutdown())` (and SIGINT) before `serve_forever()`, so SIGTERM routes into the same graceful `shutdown()` path; convert `serve_forever()`/`shutdown()` pairs to run the server in a thread or wrap so shutdown joins in-flight requests. For voice/gesture loops, translate SIGTERM into a flag the frame loop checks so the `finally` disarm/close runs. Ship systemd units with `TimeoutStopSec` and, where used, `Type=notify` + sd_notify READY.",
        "effort": "medium",
        "dimension": "observability, operability & configuration"
      },
      {
        "severity": "medium",
        "title": "config.py is import-frozen with no validation, no effective-config view, and no self-check/doctor",
        "files": [
          "sigil/config.py",
          "sigil/cli.py:462"
        ],
        "detail": "config.py resolves every value as a module-level constant at import time via `os.environ.get(...)`, with no schema, no type coercion, and no validation (e.g. EMBED_DIM/EMBED_MODEL can drift apart; QDRANT_URL is a raw string never checked). Layering is only partly honest: `_load_env_file()` runs at line 26, but SIGIL_HOME is already resolved at line 8 BEFORE the env file loads, so SIGIL_HOME can never be set via sigil.env (a subtle ordering trap). Crucially there is no way for an operator to see the EFFECTIVE resolved configuration (which paths, which Qdrant mode, which claude_bin, is it env or file or default) and no whole-install self-check — `sigil status` (cli.py:462) reports only spine/vector/chain state, not whether the Rust kernel binary exists, whether Qdrant is reachable, whether the owner key is present, or whether ELEVENLABS/claude bins resolve. So a misconfigured deploy fails opaquely at first use.",
        "fix": "Introduce a single resolved settings object (a frozen dataclass built once in config.py from env→file→default, with validation and clear error messages) and route the hardcoded paths from finding 1 through it. Add `sigil config` to print the effective config with each value's source (env/file/default), redacting secret-shaped keys. Add `sigil doctor` that checks: kernel binary exists+executable, Qdrant reachable (if server mode), owner keypair present under KEYS_DIR, spine chain verifies, claude_bin resolves, and scratch dirs are 0700 — exit non-zero on failure so it is CI/deploy-gateable.",
        "effort": "medium",
        "dimension": "observability, operability & configuration"
      },
      {
        "severity": "medium",
        "title": "No packaging or console entry point; git hooks bake an absolute venv interpreter into every repo",
        "files": [
          "sigil/ingest/hooks.py:14",
          "README.md"
        ],
        "detail": "There is no pyproject.toml/setup.py (only requirements.txt), so there is no `sigil` console script — yet the README's entire Usage section documents a `sigil ...` command (`$S=\"$V -m sigil.cli\"` is the real invocation). More operationally damaging: hooks.py:14 hardcodes `_PY = \"/home/kali/.sigil/venv/bin/python\"` and writes it verbatim into `post-commit`/`post-merge` hooks in every repo `install()` touches (hooks.py:15 `_BODY`). Installing SIGIL's git hooks on any machine whose venv is not exactly `/home/kali/.sigil/venv` produces silently-broken hooks (`... || true` swallows the failure), so live git ingestion just stops working with no error. This is the single most portability-hostile line because it persists a bad absolute path into files OUTSIDE the repo.",
        "fix": "Add a pyproject.toml with `[project.scripts] sigil = \"sigil.cli:main\"` and `sigil-mcp = \"sigil.mcp.server:run\"` so the documented commands exist and the interpreter is discoverable. In hooks.py resolve the interpreter at install time from `sys.executable` (the interpreter running the install), or write the hook to `exec \"$(command -v sigil)\" ingest --git-only` when the console script is installed, with `SIGIL_HOME` passed through explicitly. Fix the README to match reality.",
        "effort": "medium",
        "dimension": "observability, operability & configuration"
      },
      {
        "severity": "medium",
        "title": "No liveness/health surface for any daemon and no whole-install self-check",
        "files": [
          "sigil/bridge/server.py:233",
          "sigil/ui/server.py:109",
          "sigil/cli.py:462"
        ],
        "detail": "Neither HTTP server exposes an unauthenticated liveness endpoint — every `/api/*` route requires a valid token (ui) or device envelope (bridge), so an external supervisor/uptime probe (or the SENTINEL uptime watcher the code anticipates) cannot answer 'is the daemon up?' without holding a credential, and there is no `/healthz`. The MCP server (mcp/server.py) has a good `ingest_status` TOOL but nothing an OS-level health check can hit. There is no command that answers 'is the whole install healthy?' — `sigil status` (cli.py:462) covers spine/vector integrity only. In production you cannot wire a systemd `WatchdogSec`, a load-balancer health check, or a monitoring probe to any of these services.",
        "fix": "Add a credential-free `GET /healthz` to both `do_GET` handlers that returns only `{\"status\":\"ok\"}` plus non-sensitive liveness (uptime, bound port) and NEVER touches the spine payloads — it precedes the token/envelope gate and leaks nothing. Have the MCP wrapper log a ready line. Fold the finding-4 `sigil doctor` in as the install-level self-check. Optionally emit a periodic heartbeat record so `sigil status` can show last-seen time per daemon.",
        "effort": "medium",
        "dimension": "observability, operability & configuration"
      },
      {
        "severity": "medium",
        "title": "Voice/gesture degrade to stub/silent modes with only a print that is routinely discarded",
        "files": [
          "sigil/voice/run.py:22",
          "sigil/voice/run.py:29",
          "sigil/voice/run.py:39"
        ],
        "detail": "When faster-whisper or the ElevenLabs key is missing, `_make_asr`/`_make_tts` fall back to `_StubAsr` (transcript is a placeholder string) and `SilenceTts` (produces silence) after emitting a single `print(...)` (run.py:22/29/39). In `run_mic` this print goes to the daemon's stdout — and the project's own live-ingestion pattern runs SIGIL processes as `... >/dev/null 2>&1` (hooks.py:15), so under any similar service wrapper the operator gets NO signal that voice is running fully degraded (hears nothing / transcribes nothing) while the process reports healthy. There is no reflection of degraded mode in any status/health surface either.",
        "fix": "Route these through `logging.warning(...)` (finding 2) so they land in the daemon log regardless of stdout redirection, and record a `signal: voice.degraded` (or gesture equivalent) event on the spine / expose it via `/healthz` and `sigil status`, so 'ASR=stub, TTS=silence' is observable rather than only audible-by-absence.",
        "effort": "small",
        "dimension": "observability, operability & configuration"
      },
      {
        "severity": "low",
        "title": "No operational runbook, systemd units, log rotation, or backup procedure for the irreplaceable spine",
        "files": [
          "README.md"
        ],
        "detail": "The repo ships setup steps but nothing for RUNNING it as a service: there are no systemd unit files for the five daemons (bridge, ui/cockpit, mcp, voice, gesture), no restart policy, no documented log locations (compounded by findings 2/7), no logrotate, and — most consequentially — no backup/restore procedure for `~/.sigil/spine/` even though the whole product thesis is an append-only, irreplaceable, Ed25519-signed record (README law ②). There is also no documented key-rotation runbook despite OWNER_KEY_ID/KEYS_DIR being trust anchors. For an enterprise bar, 'how do I restart it, where are the logs, how do I back up the one file I can never regenerate, how do I rotate the owner key' are all unanswered.",
        "fix": "Add an infra/ directory with hardened systemd unit templates (Restart=on-failure, TimeoutStopSec, dedicated user, ReadWritePaths=~/.sigil, the SIGTERM handling from finding 3) and an OPERATIONS.md runbook covering: service start/stop/status, log locations + rotation, a spine backup/verify-restore procedure (copy spine.jsonl+head.json, then `sigil verify` on the copy), and the owner/warden key-rotation steps. Reference these from the README.",
        "effort": "medium",
        "dimension": "observability, operability & configuration"
      },
      {
        "severity": "critical",
        "title": "There is no CI, and the documented test runner is structurally incapable of failing (exit 0 on red)",
        "files": [
          "README.md",
          "tests/test_actor.py",
          "tests/test_bridge_server.py",
          "tests/test_operator.py",
          "tests/test_hardening.py"
        ],
        "detail": "No .github/workflows exists (git ls-files shows zero workflow/CI files tracked), so nothing runs the suite on push/PR. Worse, the canonical runner the README documents at README.md:307 — `for t in tests/test_*.py; do ~/.sigil/venv/bin/python \"$t\"; done` — cannot report failure. Every one of the 25 hand-rolled `__main__` blocks (identical across test_actor.py, test_bridge_server.py, test_hardening.py, test_operator.py, test_mobile.py, ...) catches AssertionError and bare Exception, prints `FAIL`/`ERROR`, and then falls off the end of the script with NO sys.exit. I proved this: a synthetic test using the repo's exact runner idiom with one failing assertion exits 0 ('  FAIL  test_broken ... EXIT CODE = 0'). Consequence: if this loop were ever wired into CI, a red test would ship green — the '319 tests all green' claim is unverifiable in automation. This is the keystone gap: the gate that would catch every other regression is both absent and, as written, incapable of catching anything. Note the tests are ALREADY pytest-compatible: running `python -m pytest tests/` unmodified yields '319 passed in 22.96s' with zero code changes, and pytest natively exits non-zero on failure.",
        "fix": "Adopt pytest as the runner (no test rewrites needed — collection+pass is already proven) and add a GitHub Actions workflow. Concrete plan: (1) commit `.github/workflows/ci.yml` with two jobs. python job: actions/setup-python (pinned 3.13), `pip install -e .[dev]` (see packaging finding) or `pip install -r requirements.txt -r requirements-dev.txt`, build the Rust kernel FIRST (`cargo build --release`) so the real-oracle tests actually run, then `pytest tests/ -q --maxfail=1`. rust job: actions/checkout, cache ~/.cargo + kernel/target, `cargo test --release`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`. (2) Delete the 25 `__main__` runner blocks (they are dead once pytest drives the suite and are the source of ~154 of the lint errors). If you keep a script runner for local use, make it `pytest tests/` or add `sys.exit(0 if passed==len(fns) else 1)` to each block. Gate merges on the workflow.",
        "effort": "medium",
        "dimension": "CI/CD, testing, type-safety & linting"
      },
      {
        "severity": "high",
        "title": "The Python↔Rust oracle integration tests silently skip and are counted as PASS on any host that isn't /home/kali with a prebuilt kernel",
        "files": [
          "tests/test_shared_primitives.py",
          "tests/test_scrape.py",
          "tests/test_actor.py",
          "tests/test_gesture.py"
        ],
        "detail": "The single most important cross-language contract — Python KernelClassifier calling the real Rust oracle to assign authorization tiers (A0–A3, fail-closed) — is exercised only when a binary exists at a HARDCODED absolute path `/home/kali/sigil/kernel/target/release/sigil-kernel` (test_shared_primitives.py:16, test_scrape.py:225, test_actor.py:24, test_gesture.py:189 and :242). When that path is absent — i.e. every CI runner (checkout lives at /home/runner/work/...), every other developer's machine, and even this repo before `cargo build` — the test prints `(skip real oracle — kernel not built)` and `return`s. Because the runner counts any non-raising function as PASS, a skip is indistinguishable from a pass. So the security-critical fail-closed tier mapping (`shell.exec.rm`→A3, `fs.read`→A0, unknown→A3) is, in practice, never validated in automation and the green count is inflated by silent skips.",
        "fix": "Resolve the kernel path relative to the repo root, not a user home: `_KERNEL = Path(__file__).resolve().parents[1] / 'kernel/target/release/sigil-kernel'`, overridable via `os.environ.get('SIGIL_KERNEL_BIN')`. Convert the silent `print(...); return` skips to `pytest.skip('kernel not built')` so skips are visible and counted separately from passes. In CI, build the kernel before the Python job and set the env var so the real-oracle tests are REQUIRED (not skippable) there — e.g. a `SIGIL_REQUIRE_KERNEL=1` guard that turns the skip into a hard failure on CI.",
        "effort": "small",
        "dimension": "CI/CD, testing, type-safety & linting"
      },
      {
        "severity": "high",
        "title": "No lint/format gate (ruff) and no type gate (mypy) — no config for either, and the surface to get clean is small and measured",
        "files": [
          "sigil/perception/camera_stream.py",
          "sigil/ingest/git.py",
          "sigil/agents/sources.py",
          "sigil/bridge/envelope.py",
          "kernel/src/actionlog.rs"
        ],
        "detail": "No ruff/mypy/flake8 config and no Rust fmt/clippy gate exist, yet the `# noqa: BLE001` / `# noqa: E731` comments littered through the tests show the codebase already assumes a linter that never actually runs. Measured surface (ran the tools): ruff default ruleset on production `sigil/` = 42 issues (25 semicolon E702, 12 auto-fixable unused imports F401, 4 import-order E402, 1 unused var) — roughly a day to zero. ruff on `tests/` = 160, but 154 are the E702 semicolons inside the dead `__main__` runners that pytest migration deletes outright. mypy (lenient: --ignore-missing-imports, no strict) on `sigil/` = 62 errors across 21 of 120 files. Most are annotation hygiene (a `(ok, core)` tuple-union pattern that doesn't narrow — bridge/envelope.py:111,130), but several are genuine latent-NoneType smells worth fixing: camera_stream.py:40 (`IO|None`.read), ingest/git.py:65 (`...|None`.get), sources.py:65 (return type wider than declared). Rust side: `cargo fmt --check` FAILS today (src is unformatted, e.g. kernel/src/actionlog.rs:84) and `cargo clippy` emits ~5 trivial warnings (io::Error::other suggestions).",
        "fix": "Add a `[tool.ruff]` block (target-version py313, select E/F/I plus a curated set; line-length to match), run `ruff check --fix` for the 12+3 auto-fixables, and delete the semicolon runners via the pytest migration. Add a `[tool.mypy]` block starting lenient (ignore_missing_imports=true, check_untyped_defs) as a passing gate now, and ratchet per-module toward strict via `[[tool.mypy.overrides]]` on the security-critical packages (governor, bridge, mesh, gesture) first — fix the ~5 real union-attr/return-type smells while there. Add `cargo fmt --check` and `cargo clippy -- -D warnings` to the rust CI job; run `cargo fmt` once and apply the 3 clippy suggestions to make them pass. All four gates are achievable in 2–3 focused days.",
        "effort": "medium",
        "dimension": "CI/CD, testing, type-safety & linting"
      },
      {
        "severity": "medium",
        "title": "No pinned dev toolchain or dev-dependency manifest — CI would be non-reproducible and the 'test venv' can't even run pytest",
        "files": [
          "requirements.txt",
          "kernel/Cargo.toml"
        ],
        "detail": "requirements.txt pins the seven runtime deps exactly (good) but declares NO development tooling — pytest, ruff, and mypy are absent. This bites reality: the very interpreter the README tells you to run the suite with (`~/.sigil/venv/bin/python`) has no pytest module (`No module named pytest`), so the documented harness depends on tools nothing installs. On the Rust side there is no `rust-toolchain.toml` at repo root or in kernel/ (confirmed absent), so the Rust version floats (I built with 1.95.0, but nothing pins it); Cargo.lock IS committed, which is the one thing done right. There is also no Python version pin/matrix, so 'works on my 3.13' is the only guarantee.",
        "fix": "Add a dev-dependency set — either `requirements-dev.txt` (pytest, pytest-cov, ruff, mypy, type stubs) or, better, a `[project.optional-dependencies].dev` in pyproject (see packaging finding). Add `kernel/rust-toolchain.toml` pinning the channel (e.g. `[toolchain] channel = \"1.95.0\"`, components = rustfmt, clippy) so contributors and CI use the same compiler and lints. Pin the Python version in the workflow (setup-python 3.13) and optionally add a 3.12/3.13 matrix. Keep Cargo.lock committed and add `cargo build --locked` in CI to enforce it.",
        "effort": "small",
        "dimension": "CI/CD, testing, type-safety & linting"
      },
      {
        "severity": "medium",
        "title": "No packaging metadata (no pyproject.toml/setup.py) — the package isn't installable, blocking a clean reproducible CI install and a real entry point",
        "files": [
          "sigil/__init__.py",
          "sigil/cli.py",
          "requirements.txt"
        ],
        "detail": "There is no pyproject.toml or setup.py (git ls-files confirms none tracked). `import sigil` only resolves because CWD happens to be the repo root; the CLI is invoked as `python3 -m sigil.cli` (README:189) with no console_scripts entry point, and there is no declared package version or dependency metadata. For CI this means every job must hand-manage PYTHONPATH and there's no single `pip install -e .[dev]` that pulls runtime + dev deps and wires the tools together. It also blocks reproducible builds, versioned releases, and shipping SIGIL as anything other than a git checkout — a real prototype→product gap.",
        "fix": "Add a pyproject.toml (build-backend hatchling or setuptools) declaring: project name/version, `dependencies` mirroring requirements.txt (keep exact pins), `[project.optional-dependencies].dev` (pytest, pytest-cov, ruff, mypy), a `[project.scripts] sigil = \"sigil.cli:main\"` console entry, and the `[tool.ruff]`/`[tool.mypy]`/`[tool.pytest.ini_options]` config in one file. Then CI (and users) do `pip install -e .[dev]`. Avoid PEP 639 SPDX license fields that need setuptools>=77 (use the classic license table) so stock LTS toolchains still build.",
        "effort": "small",
        "dimension": "CI/CD, testing, type-safety & linting"
      },
      {
        "severity": "medium",
        "title": "No coverage measurement, and the long-running daemons have no lifecycle/failure-injection tests",
        "files": [
          "sigil/bridge/daemon.py",
          "sigil/gesture/run.py",
          "sigil/voice/pipeline.py",
          "sigil/mcp/server.py"
        ],
        "detail": "Credit where due: concurrency IS tested at the two hot spots — tests/test_bridge_envelope.py:225 spawns 8 racing threads against the effectful-nonce replay gate, and tests/test_integrity.py:35 races 8 threads on spine append integrity, so the TOCTOU-sensitive paths have real contention coverage. The gaps are (1) no coverage is ever measured, so nobody knows which of the 120 source files the 319 tests actually exercise, and (2) the long-running daemons — bridge/daemon.py, gesture/run.py, voice/pipeline.py, mcp/server.py — are validated only by one-shot request/response tests, never by lifecycle or failure injection: what happens when the spine file is corrupted or truncated mid-run, when a worker thread dies, when the daemon is restarted (nonce-highwater/receipt idempotency across restart), or when a bound socket is already taken. These are exactly the production-reliability questions a prototype hasn't had to answer.",
        "fix": "Add pytest-cov to the dev deps and emit `--cov=sigil --cov-report=term-missing --cov-report=xml` in CI (report only at first, no hard threshold, so you can see the map before ratcheting). Add a `tests/test_daemons.py` doing lifecycle + fault injection: start each daemon on port 0 in a thread, drive it, then inject failures — truncate/corrupt the backing spine and assert fail-closed behavior, kill/restart and assert nonce-highwater replay protection survives a restart, and assert a second bind fails cleanly. Once coverage is visible, set a floor (e.g. 80% on the security packages) as a gate.",
        "effort": "medium",
        "dimension": "CI/CD, testing, type-safety & linting"
      },
      {
        "severity": "low",
        "title": "No build/release check for the Rust kernel in CI, and kernel/tests/ is an empty integration surface",
        "files": [
          "kernel/Cargo.toml",
          "kernel/tests",
          "kernel/src/main.rs"
        ],
        "detail": "The Rust kernel is a hard dependency of the Python authorization path (the oracle that assigns A0–A3 tiers), yet nothing builds or release-checks it in an automated way — there is no workflow, and the 26 inline `#[cfg(test)]` unit tests (`cargo test --release` → 26 passed) only run if someone remembers to. kernel/tests/ exists but is EMPTY, so there is no black-box integration test of the actual CLI contract the Python side depends on — the `sigil-kernel classify <tool>` stdin/stdout/exit-code behavior that KernelClassifier parses. A regression in the CLI's output format would pass all 26 in-crate tests and break Python silently.",
        "fix": "Add a rust CI job: `cargo build --release --locked`, `cargo test --release`, `cargo fmt --check`, `cargo clippy -- -D warnings`, with ~/.cargo and kernel/target cached; optionally upload the release binary as a build artifact for the Python job to consume (so the real-oracle tests don't rebuild). Add at least one file in kernel/tests/ that shells out to the built `sigil-kernel` binary and asserts the exact classify contract (input tool → tier string → exit code) that sigil/agents/kernel_classify.py relies on — this is the black-box test that protects the cross-language boundary.",
        "effort": "small",
        "dimension": "CI/CD, testing, type-safety & linting"
      },
      {
        "severity": "high",
        "title": "Local camera gesture control is an inert stub advertised as a shipped, tested capability (not flagged as a seam)",
        "files": [
          "/home/kali/sigil/sigil/gesture/landmark.py",
          "/home/kali/sigil/sigil/gesture/run.py",
          "/home/kali/sigil/README.md"
        ],
        "detail": "`OnnxHandLandmarker.detect()` (landmark.py:37-49) is the ONLY on-box hand-landmark provider, and it can never return a landmark. It loads the ONNX session and imports numpy, then unconditionally `return []` — the resize/normalize → palm-ROI → 21-keypoint decode is entirely absent (the comment says 'Kept deliberately minimal here … with no bundled .onnx this path returns [] (honest gap)'). Crucially this is NOT merely 'no model bundled': even with a valid checksum-pinned .onnx present at ~/.sigil/models/hand_landmark.onnx and a working onnxruntime, `_sess()` succeeds and detect() still returns []. Consequence: in `run_gesture` (run.py:73) `classifier.classify(landmarker.detect(frame))` always receives [], so `RuleClassifier` returns 'neutral' and `GesturePipeline` fires NOTHING — the entire local 'control the cursor with your hand through a camera' path is dead. No .onnx ships anywhere in the repo (confirmed by find). Yet README §Perception/gesture states 'Everything below is built and tested' and describes 'a warm camera stream → landmark model → invariant-feature classifier → … owner-armed session' with no seam caveat — the README explicitly flags only macOS/Windows/Android backends and the browser web engine as seams, NOT gesture. The only functional gesture path is the phone-inference `RemoteLandmarker` (gesture/remote.py), where the phone does the inference off-box. Compounding this: there is NO `sigil gesture` CLI subcommand at all (cli.py has no gesture subparser; `run_gesture` is imported only by tests and demo), so even the working remote path has no documented launcher and the local path is unreachable from the CLI. This is category (c) demo-only code masquerading as a complete feature.",
        "fix": "Pick one and align the README to it: (a) implement the real ONNX preprocessing + palm-ROI + 21-kp postprocessing in detect(), bundle/checksum a model, and add a `sigil gesture` CLI command; OR (b) make the seam honest — have `detect()` degrade explicitly (raise NotImplementedError or log a one-time 'local landmarker not wired — use the phone RemoteLandmarker' and return []), have `run_gesture` REFUSE to arm when the landmarker is the inert OnnxHandLandmarker (mirror the existing fail-closed egress-gate refusal at run.py:43), and rewrite the README to list local camera gesture as a documented seam whose only working form is the phone-streamed RemoteLandmarker.",
        "effort": "medium",
        "dimension": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
      },
      {
        "severity": "high",
        "title": "SessionGate records a signed 'gesture … injected' spine event when the input backend is an inert seam, fabricating an audit record",
        "files": [
          "/home/kali/sigil/sigil/gesture/session.py",
          "/home/kali/sigil/sigil/platform/input.py"
        ],
        "detail": "On macOS and Windows `input_backend()` returns `_SeamInputBackend` (input.py:59-79): `available()` is False and every method (`move`/`click`/`scroll`/`type`/`combo`) is a no-op `pass`. `SessionGate.arm()` and `handle()` (session.py:138-291) never consult `backend.available()`. So when a session is armed on such a host (reachable in production via the phone-trackpad remote-arm path: `arm_by_device` is cross-platform and `run_gesture` selects the seam backend on mac/win while the phone supplies landmarks through `RemoteLandmarker`), a discrete A1 gesture calls `_inject()` (which no-ops on the seam backend) and then appends a spine event `{signal: gesture.action, decision: auto, tool: 'hid.pointer.click', summary: 'gesture hid.pointer.click injected'}` and returns `{'injected': True}`. The tamper-evident, owner-signed log therefore asserts an injection that never physically occurred — a direct violation of the product's core 'prove, don't guess / every served fact is grounded' invariant, in the exact subsystem (WARDEN-audited HID injection) where the audit trail is the safety story.",
        "fix": "Gate on backend capability: refuse to arm (or record `injected: False, reason: 'no input backend on this host'`) when `backend.available()` is False, and only append the `gesture … injected` event after a backend that actually acted. At minimum, thread the real inject outcome into the spine record instead of assuming success.",
        "effort": "small",
        "dimension": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
      },
      {
        "severity": "medium",
        "title": "Token/cost budget metering is a documented seam — budgets cannot cap frontier-model spend",
        "files": [
          "/home/kali/sigil/sigil/governor/budget.py"
        ],
        "detail": "`BudgetLedger` enforces only `daily_actions` and `daily_interrupts` (record counts), and the module docstring (budget.py:6-8) explicitly states 'Token/cost caps are a documented seam: the mesh does not yet meter provider tokens per action.' An agent that makes expensive frontier calls (ClaudeVision image uploads, `claude -p` in ARTIFICER) is bounded only by a per-day action COUNT, not by tokens or dollars — yet the README disclaimer warns about 'frontier-model API spend' and the owner wants enterprise standard, where cost governance is expected. This is an honestly-documented (b) should-be-implemented-for-production gap, not a hidden one, but it is a real production blocker for cost control.",
        "fix": "Add a cost dimension the spine already has the hooks for: record per-action token/estimated-cost on the event payload (providers already return usage), sum it in `spent()`, and add a `daily_cost` cap to `BudgetCaps` enforced fail-closed alongside the existing count caps.",
        "effort": "medium",
        "dimension": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
      },
      {
        "severity": "medium",
        "title": "Scraper `HeadlessRenderer` is described in detail in the docstring but does not exist — only NullRenderer ships",
        "files": [
          "/home/kali/sigil/sigil/scrape/render.py"
        ],
        "detail": "render.py's module docstring describes a `HeadlessRenderer` that is 'a DATA-EGRESS + ATTACK surface … OFF BY DEFAULT, owner-opt-in, re-vets the host with is_public_host, runs cookieless … blocks private-IP subresource loads' — as though the opt-in JS-render capability exists behind a flag. It does not: grep finds `HeadlessRenderer` only in that docstring; the sole implementation is `NullRenderer` which always returns '' (render.py:23-28). The default-off degrade is itself honest and acceptable (category a): JS-heavy pages simply don't render. The seam-inventory problem is that the docstring reads as if a designed, gated capability is present, which misleads a reader auditing what is shipped vs stubbed.",
        "fix": "Either implement `HeadlessRenderer` behind the opt-in it describes (with the private-IP subresource enforcement, else stay disabled), or rewrite the docstring to state plainly that only NullRenderer exists today and the headless renderer is an unbuilt, deliberately-deferred seam.",
        "effort": "small",
        "dimension": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
      },
      {
        "severity": "medium",
        "title": "BASTION 'dependency-CVE' scanning has no feed source — findings only exist against an operator-supplied cve_feed",
        "files": [
          "/home/kali/sigil/sigil/agents/bastion.py"
        ],
        "detail": "`Bastion.__init__` takes `cve_feed` as an injected list (bastion.py:135-144) and `_deps()` matches installed versions against it; there is no NVD/OSV/GHSA fetch anywhere. So the advertised 'dependency-CVE' capability (README §Agents/BASTION and the intro claim 'Everything below is built and tested') only produces findings if the operator hand-supplies a CVE feed — with an empty feed BASTION silently reports zero dependency findings, which reads as 'clean' rather than 'not assessed.' The cert-expiry (SocketCertSource) and uptime (UrllibUptimeSource) scanners are genuinely real; only the CVE dimension is a BYO-data seam.",
        "fix": "Ship an offline-refreshable OSV/GHSA feed loader (or document that the CVE feed is operator-supplied and have an empty feed emit an honest 'dependency-CVE not assessed — no feed configured' refusal record rather than silently producing no findings).",
        "effort": "medium",
        "dimension": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
      },
      {
        "severity": "low",
        "title": "Stale 'not shipped here' / 'PWA not built yet' seam comments understate what is actually built",
        "files": [
          "/home/kali/sigil/sigil/bridge/daemon.py",
          "/home/kali/sigil/sigil/bridge/server.py"
        ],
        "detail": "These seam markers are now false and mislead a seam auditor in the opposite direction (they hide shipped code). daemon.py:6-9 says the WireGuard HTTP transport 'is a documented NEXT slice, not shipped here' — but bridge/server.py fully implements that transport (BridgeServer + TLS + envelope auth). server.py:51 and :270 say 'the PWA is a later slice — served if present, else 404' / 'bridge PWA not built yet' — but sigil/bridge/webapp/ exists with index.html, app.js, service-worker.js, manifest.json, style.css. The code is real; only the comments are stale.",
        "fix": "Update the daemon.py docstring to reference server.py as the shipped transport, and drop the 'PWA not built yet / later slice' comments in server.py now that sigil/bridge/webapp/ is present.",
        "effort": "small",
        "dimension": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
      },
      {
        "severity": "low",
        "title": "Voice: a placeholder ASR transcript is dispatched to the KERNEL, and the default wake/ASR are stand-ins not flagged in the README",
        "files": [
          "/home/kali/sigil/sigil/voice/run.py",
          "/home/kali/sigil/sigil/voice/backends.py",
          "/home/kali/sigil/README.md"
        ],
        "detail": "When no ASR is available, `_make_asr` falls back to `_StubAsr` whose `transcribe()` returns the literal string '(no ASR model installed — run: pip install faster-whisper)', and `run_mic`/`run_file` then hand that placeholder to `KernelDispatch().send(...)` as if it were a user command — an honest-but-odd demo path where a stub string is routed as a command. Separately, the default wake detector is `EnergyWake`, explicitly documented in backends.py:34-37 as 'a trivial wake … a stand-in for the real custom-SIGIL openWakeWord model (which needs training data)', and WhisperAsr transcribes a completed utterance buffer rather than incrementally. The README (§Perception/voice) advertises 'a full-duplex wake → VAD → streaming ASR → KERNEL → TTS pipeline' without noting the default wake word is an energy stand-in and ASR is utterance-buffered, not incrementally streaming. These are honestly labeled in code (category a) but the README slightly overclaims.",
        "fix": "Have the stub-ASR path short-circuit rather than dispatch a placeholder string as a command, and add a one-line README note that the default wake word is an energy-onset stand-in (openWakeWord 'hey_jarvis'/custom model is the upgrade) and that ASR is utterance-level.",
        "effort": "small",
        "dimension": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
      },
      {
        "severity": "low",
        "title": "README's blanket 'macOS/Windows/Android honest-degrading' is imprecise — screen capture works on mac/win; only camera/input are true seams",
        "files": [
          "/home/kali/sigil/sigil/platform/macos.py",
          "/home/kali/sigil/sigil/platform/windows.py",
          "/home/kali/sigil/sigil/platform/android.py",
          "/home/kali/sigil/README.md"
        ],
        "detail": "These backends are the model of an ACCEPTABLE, honest seam and are correctly self-describing via CapabilityDescriptor — but the README's summary is coarser than the code. macOS `capture_screen` is implemented (screencapture) and Windows `capture_screen` is implemented (optional mss); only `capture_camera` is a hard `None` on both (macos.py:28-29 'imagesnap' gap, windows.py:34-35), and input injection is a no-op seam (input.py). Android honestly reports os='android' and gates camera/screen on termux-api/screencap presence. The gaps are genuinely-unsupported-and-honest (category a) and each returns None consistently with `has_camera=False`, so callers that consult capabilities degrade correctly. The only refinement: the README lumps all three as uniformly 'honest-degrading' when in fact mac/win screen capture is real and functional.",
        "fix": "No code change needed for honesty; optionally tighten the README status line to say screen capture is real on macOS/Windows and only camera + HID-injection are the degrading seams there. Ensure any future caller that ignores CapabilityDescriptor and calls capture_camera() directly treats None as 'unsupported', not 'no capture'.",
        "effort": "small",
        "dimension": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated"
      }
    ]
  },
  "workflowProgress": [
    {
      "type": "workflow_phase",
      "index": 1,
      "title": "Audit"
    },
    {
      "type": "workflow_agent",
      "index": 1,
      "label": "audit:packaging",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "ae860bed74b59c3f2",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784451020561,
      "queuedAt": 1784450995798,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "packaging, distribution & dependency hygiene",
      "promptPreview": "Repo: /home/kali/sigil (SIGIL — a local-first, offense-free personal AI orchestrator; Python package `sigil/` ~10.9k LOC across 120 files, a Rust kernel in `kernel/`, 25 test suites in `tests/`, a `demo/`). It is a working, well-reviewed prototype with documented seams; the owner wants it brought to PRODUCTION / ENTERPRISE standard. You are a READ-ONLY auditor for ONE dimension. Be concrete and gr…",
      "lastProgressAt": 1784451306656,
      "tokens": 63560,
      "toolCalls": 21,
      "durationMs": 286095,
      "resultPreview": "{\"dimension\":\"packaging, distribution & dependency hygiene\",\"findings\":[{\"severity\":\"critical\",\"title\":\"No build system or package metadata — the project is not installable at all\",\"files\":[\"/home/kali/sigil/requirements.txt\",\"/home/kali/sigil/README.md\",\"/home/kali/sigil/sigil/__init__.py\"],\"detail\":\"The repo root contains only requirements.txt, README.md and .gitignore — there is no pyproject.to…"
    },
    {
      "type": "workflow_agent",
      "index": 2,
      "label": "audit:performance",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "a87483e45347b8d15",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784451009984,
      "queuedAt": 1784450995799,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "performance & scale",
      "promptPreview": "Repo: /home/kali/sigil (SIGIL — a local-first, offense-free personal AI orchestrator; Python package `sigil/` ~10.9k LOC across 120 files, a Rust kernel in `kernel/`, 25 test suites in `tests/`, a `demo/`). It is a working, well-reviewed prototype with documented seams; the owner wants it brought to PRODUCTION / ENTERPRISE standard. You are a READ-ONLY auditor for ONE dimension. Be concrete and gr…",
      "lastProgressAt": 1784451354469,
      "tokens": 86866,
      "toolCalls": 23,
      "durationMs": 344484,
      "resultPreview": "{\"dimension\":\"performance & scale\",\"findings\":[{\"severity\":\"critical\",\"title\":\"No seq→byte-offset index: iter_records(since_seq) re-reads and JSON-parses the entire 92MB/43k spine on every call\",\"files\":[\"/home/kali/sigil/sigil/spine/store.py\"],\"detail\":\"iter_records (store.py:103-114) opens the file and json.loads() EVERY line from byte 0, then merely FILTERS `if d[\\\"seq\\\"] > since_seq`. `since_s…"
    },
    {
      "type": "workflow_agent",
      "index": 3,
      "label": "audit:robustness",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "a3a0c4a7287c0adc1",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784451012477,
      "queuedAt": 1784450995799,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "robustness & error handling",
      "promptPreview": "Repo: /home/kali/sigil (SIGIL — a local-first, offense-free personal AI orchestrator; Python package `sigil/` ~10.9k LOC across 120 files, a Rust kernel in `kernel/`, 25 test suites in `tests/`, a `demo/`). It is a working, well-reviewed prototype with documented seams; the owner wants it brought to PRODUCTION / ENTERPRISE standard. You are a READ-ONLY auditor for ONE dimension. Be concrete and gr…",
      "lastProgressAt": 1784451475295,
      "tokens": 113406,
      "toolCalls": 32,
      "durationMs": 462817,
      "resultPreview": "{\"dimension\":\"robustness & error handling\",\"findings\":[{\"severity\":\"high\",\"title\":\"A single malformed/torn spine line crashes every read path (and blocks restart after an interrupted append)\",\"files\":[\"/home/kali/sigil/sigil/spine/store.py\",\"/home/kali/sigil/sigil/spine/models.py\",\"/home/kali/sigil/sigil/spine/tail.py\"],\"detail\":\"SpineStore.iter_records (store.py:103-113) does `d = json.loads(line…"
    },
    {
      "type": "workflow_agent",
      "index": 4,
      "label": "audit:observability",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "a05fcd30a255c8783",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784451023779,
      "queuedAt": 1784450995799,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "observability, operability & configuration",
      "promptPreview": "Repo: /home/kali/sigil (SIGIL — a local-first, offense-free personal AI orchestrator; Python package `sigil/` ~10.9k LOC across 120 files, a Rust kernel in `kernel/`, 25 test suites in `tests/`, a `demo/`). It is a working, well-reviewed prototype with documented seams; the owner wants it brought to PRODUCTION / ENTERPRISE standard. You are a READ-ONLY auditor for ONE dimension. Be concrete and gr…",
      "lastProgressAt": 1784451326779,
      "tokens": 90556,
      "toolCalls": 21,
      "durationMs": 303000,
      "resultPreview": "{\"dimension\":\"observability, operability & configuration\",\"findings\":[{\"severity\":\"high\",\"title\":\"11 hardcoded /home/kali absolute paths make the code undeployable on any other host\",\"files\":[\"sigil/agents/artificer.py:45\",\"sigil/agents/scholar.py:43\",\"sigil/consolidate/extract.py:119\",\"sigil/ingest/hooks.py:14\",\"sigil/agents/runner.py:77\",\"sigil/ingest/git.py:22\",\"sigil/agents/sentinel.py:40\",\"si…"
    },
    {
      "type": "workflow_agent",
      "index": 5,
      "label": "audit:ci_quality",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "afe4d77552efaa224",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784451017759,
      "queuedAt": 1784450995799,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "CI/CD, testing, type-safety & linting",
      "promptPreview": "Repo: /home/kali/sigil (SIGIL — a local-first, offense-free personal AI orchestrator; Python package `sigil/` ~10.9k LOC across 120 files, a Rust kernel in `kernel/`, 25 test suites in `tests/`, a `demo/`). It is a working, well-reviewed prototype with documented seams; the owner wants it brought to PRODUCTION / ENTERPRISE standard. You are a READ-ONLY auditor for ONE dimension. Be concrete and gr…",
      "lastProgressAt": 1784451704159,
      "tokens": 69310,
      "toolCalls": 33,
      "durationMs": 686400,
      "resultPreview": "{\"dimension\":\"CI/CD, testing, type-safety & linting\",\"findings\":[{\"severity\":\"critical\",\"title\":\"There is no CI, and the documented test runner is structurally incapable of failing (exit 0 on red)\",\"files\":[\"README.md\",\"tests/test_actor.py\",\"tests/test_bridge_server.py\",\"tests/test_operator.py\",\"tests/test_hardening.py\"],\"detail\":\"No .github/workflows exists (git ls-files shows zero workflow/CI fi…"
    },
    {
      "type": "workflow_agent",
      "index": 6,
      "label": "audit:seams",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "a0841a48491128e41",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784451015371,
      "queuedAt": 1784450995799,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "Honest seam/stub inventory — what is DEMO/SEAM/off-by-defau…",
      "promptPreview": "Repo: /home/kali/sigil (SIGIL — a local-first, offense-free personal AI orchestrator; Python package `sigil/` ~10.9k LOC across 120 files, a Rust kernel in `kernel/`, 25 test suites in `tests/`, a `demo/`). It is a working, well-reviewed prototype with documented seams; the owner wants it brought to PRODUCTION / ENTERPRISE standard. You are a READ-ONLY auditor for ONE dimension. Be concrete and gr…",
      "lastProgressAt": 1784451531129,
      "tokens": 343177,
      "toolCalls": 40,
      "durationMs": 515758,
      "resultPreview": "{\"dimension\":\"Honest seam/stub inventory — what is DEMO/SEAM/off-by-default masquerading as complete, and what should be implemented vs explicitly gated\",\"findings\":[{\"severity\":\"high\",\"title\":\"Local camera gesture control is an inert stub advertised as a shipped, tested capability (not flagged as a seam)\",\"files\":[\"/home/kali/sigil/sigil/gesture/landmark.py\",\"/home/kali/sigil/sigil/gesture/run.py…"
    }
  ],
  "totalTokens": 766875,
  "totalToolCalls": 170
}