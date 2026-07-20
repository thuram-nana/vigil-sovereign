# Verification coverage — the live-gated paths and their mock coverage

Some code in CRUCIBLE only runs when a live external tool, environment variable, or
headless browser is present, so a stock CI run (`pytest framework/v2`) `SKIP`s the
tests that would exercise it — the sensor subprocess parsers (nmap / tshark / nuclei /
zap), the CDP/browser DOM-XSS result handling, and the external SAST result handling
(semgrep / joern). The **live subprocess / browser stays gated** (CRUCIBLE never
installs these tools; a deployment provisions them). But their **output-handling** —
the `parse → normalize → oracle` logic that turns a tool's bytes into world-model
observations or a re-verifiable finding — is pure and can be covered offline by feeding
it **canned / recorded output**.

This document maps each live-gated path to the additive mock test that now covers it in
stock CI, and states what still genuinely requires a live run. The mock tests never
touch a real binary or browser: they monkeypatch `shutil.which` / `subprocess.run` (or
supply a fake WS connection / stub browser) and feed fixtures. They are **additive** —
they do not change the primary gate corpus (`benchmark --gate` stays byte-identical).

## The map

| Live-gated path | Gated by (skip condition) | Live test (still skipped) | New mock coverage | What still needs a live run |
|---|---|---|---|---|
| `sensors/nmap.py :: NmapServiceSensor.run()` — fixed-argv build, subprocess invocation, `-oX` stdout / exit-code → `ToolResult`, then `parse_nmap_xml` → `normalize` → observations | `CRUCIBLE_LIVE_NMAP` + `nmap` on PATH | `test_nmap_sensor.py::test_nmap_live_scan_of_localhost` | `sensors/tests/test_nmap_run_mocked.py` — mocked `subprocess.run`+`which` feed a canned `nmap -oX` XML through the real `run()`→`normalize()` into the world-model; argv shape; empty-stdout, timeout, OSError, zero-exit-empty branches | that a real `nmap` emits the assumed `-oX` schema and that probe packets reach the host |
| `sensors/tshark.py :: TsharkFlowSensor.run()` — `-T fields` argv (every `-e`), subprocess, returncode/stdout → `ToolResult`, then `parse_tshark_fields` → `_observations_from_records` | `CRUCIBLE_LIVE_PCAP` + `tshark` on PATH | `test_tshark_sensor.py::test_tshark_reads_a_real_pcap_end_to_end` (+ the `skipif(not which)` synack test) | `sensors/tests/test_tshark_run_mocked.py` — mocked `subprocess.run`+`which` over a real-but-never-read temp pcap feed a canned `tshark -T fields` dump through `run()`→`normalize()` into the world-model; argv/`-e` fields; nonzero-exit-with/without-stdout, timeout, OSError branches | that a real `tshark` renders the assumed field columns/flags for a given pcap |
| `sensors/web_scanner.py :: NucleiWebSensor.run()` / `NucleiTemplateSensor.run()` — `-u`/`-t` argv, subprocess, stdout JSONL → `ToolResult`, then `parse_nuclei` → `web_lead_observations` | `CRUCIBLE_LIVE_NUCLEI` + `nuclei` on PATH | `test_web_scanner_sensors.py::test_nuclei_live_scan_of_localhost` | `sensors/tests/test_web_scanner_run_mocked.py` — mocked `subprocess.run`+`which` feed a recorded `nuclei -jsonl` dump through `run()`→`normalize()` into leads; argv shape; clean-run-empty, timeout, OSError branches; template-corpus `-t` path | that a real `nuclei` emits the assumed JSONL schema and that probe requests reach the target |
| `sensors/web_scanner.py :: ZapWebSensor.run()` — the distinct **read-the-JSON-report-file** output-handling (`-quickout` temp file) | `zap.sh`/`zaproxy` on PATH (implicitly; no dedicated live test) | (none dedicated — only the absent-binary path was tested) | same file — a mocked `subprocess.run` **writes the report the real ZAP would** to the `-quickout` path, so `run()`'s report-read → `parse_zap` → leads is exercised; missing-report failure branch | that a real ZAP scan produces the assumed report JSON |
| `scanner/cdp.py :: CdpSession` — command-result return + interleaved-event buffering, `binding_calls` (the DOM-XSS execution signal), non-JSON-frame skipping, `wait_event` | `cdp_available()` (no Chromium) | `test_cdp.py`, `test_browser_xss.py`, `test_spa_crawler.py` (all `skipif(not cdp_available())`) | `scanner/tests/test_domxss_cdp_result_mocked.py` (part 1) — a fake WS connection hands back canned CDP frames; drives `send`/`evaluate` result + error, interleaved-event buffering, `binding_calls`, `wait_event`, garbled-frame skip | that a real Chromium actually executes the payload and emits `Runtime.bindingCalled` |
| `scanner/browser_xss.py :: confirm_dom_xss` — payload injection, `executed` decision, `FindingContext.from_dom_execution` oracle-context handling | requires a `CdpBrowser` (Chromium) | `test_browser_xss.py::test_dom_xss_confirmed_by_execution` / `..._safe_sink` | `scanner/tests/test_domxss_cdp_result_mocked.py` (part 2) — a **stub browser** that "executes" by echoing the injected binding canary; asserts `executed`, then the DOM-execution **oracle confirms** over the resulting context (and its serialized round-trip); safe-page and driver-error (no-guess) cases | that a real browser confirms in a real DOM (the end-to-end execution proof) |
| `analysis/analyzers/external.py :: SemgrepAnalyzer._normalize` (+ `analyze` subprocess seam) — `--json` result → severity map, path relativization, CWE extraction, deterministic sort | `shutil.which("semgrep") is None` | `test_semgrep_taint.py` (`requires_semgrep`), `eval/tests/test_vulnpy_corpus.py`, `test_vulnjs_corpus.py` | `analysis/tests/test_sast_result_handling.py` (semgrep half) — canned `semgrep --json` fed directly to `_normalize` and through `analyze()` over a mocked `subprocess`; garbage-tolerance; empty-stdout(0/nonzero), invalid-JSON, absent-binary branches | that a real semgrep's taint engine actually detects/relativizes the flows (the detection-quality measurement) |
| `analysis/analyzers/joern.py :: JoernAnalyzer._parse` + `_classify` (+ `analyze` subprocess seam) — CPGQL JSON-lines → sink→bug-class/CWE, normalization | `_joern_binary() is None` (no `CRUCIBLE_JOERN_HOME`/PATH) | `test_joern_dataflow.py` (`requires_joern`) | `analysis/tests/test_sast_result_handling.py` (joern half) — canned joern JSON-lines fed directly to `_parse`/`_classify` and through `analyze()` over a mocked `subprocess` (the mock **writes the `joern-flows.jsonl` the real tool would**); malformed-line skip; no-output and absent-binary branches | that a real joern CPG produces the inter-procedural flows (the deep-analysis measurement) |

## What the mocks deliberately do NOT cover

The mocks verify **output-handling**, not the tools themselves. Still requiring a live
run (kept as the `skipif`-gated tests above, run by provisioning the tool and setting
the env var):

- that the external tool's **real output actually matches the assumed schema** (the
  fixtures encode our understanding of `nmap -oX`, `tshark -T fields`, `nuclei -jsonl`,
  ZAP report JSON, `semgrep --json`, joern flows — a tool version bump could drift these);
- the **live network/DOM behavior** — that probe packets/requests reach an in-scope host,
  that a real Chromium executes an injected payload and fires the CDP binding, that a real
  taint engine finds (and a sanitized file does not trigger) the flows;
- the **gate chain end-to-end** under a signed charter + granted entitlement
  (`run_sensor` with a real subprocess), which the live sensor tests drive.

## Determinism / additivity notes

- Every mock test is deterministic: fixtures are literal, no wallclock/RNG in the asserted
  paths (the one random value — `confirm_dom_xss`'s per-payload canary — is matched by
  regex, not by equality).
- These tests are additive. They add no library/corpus entries and change no existing test,
  so `python3 -m framework.v2 benchmark --gate --no-incumbents` stays byte-identical
  (`9/0/0`, precision/recall/f1 `1.000`, PASS).
