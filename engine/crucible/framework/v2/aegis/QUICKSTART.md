# AEGIS Quickstart — see the provable firewall work in five minutes

AEGIS is the **defensive dual**: an inline runtime layer that blocks a request **only when a
deterministic oracle proves it is an attack** (attaching a re-runnable certificate), and otherwise
forwards it. It is **fail-open** and **observe-by-default** — it never takes your app down. The deep
reference is [`../docs/aegis/DEPLOYMENT.md`](../docs/aegis/DEPLOYMENT.md); this page just gets you
running.

Everything below runs **locally on loopback**. No cloud, no telemetry, no external calls.

---

## Install

**pip (any environment):**

```bash
pip install .            # from the repo root (delivers `aegis` + `crucible` + framework.v2)
aegis --help
```

The `aegis` command equals `python3 -m framework.v2 aegis`; if you prefer not to install, that longer
form works from a source checkout with no install at all.

**Docker sidecar** (build from the **repo root** — the build context must see `pyproject.toml` +
`framework/`):

```bash
docker build -f framework/v2/aegis/Dockerfile -t aegis-gateway .
```

---

## a. `aegis demo` — prove the engine end-to-end, offline

No target, no network. It plants a canary, feeds a prompt-injection turn that leaks it, and prints a
**confirmed** verdict plus a certificate you can re-verify offline:

```bash
aegis demo
# ... {"decision": "confirmed", "finding": {"bug_class": "system_prompt_disclosure", ...}}
# stderr: certificate re-verifies offline: True
```

`decision: confirmed` + `certificate re-verifies offline: True` means the proof stands on its own — a
verdict you can hand an auditor.

Inside Docker:

```bash
docker run --rm --entrypoint python3 aegis-gateway -m framework.v2 aegis demo
```

## b. Run the gateway in **observe** in front of an app

Observe mode is read-only: it inspects and forwards, blocking **nothing**, and logs a JSON verdict
(to stderr) for every proven attack it *would* block. This is how you build confidence before
enforcing.

**Against a bundled demo target.** The package ships a deliberately-vulnerable app so you have an
`--upstream` to point at immediately. In one terminal:

```bash
python3 -m framework.v2.aegis.demo_app --port 3000     # bundled vulnerable app on :3000
```

In another, put the gateway in front of it:

```bash
aegis gateway --upstream http://127.0.0.1:3000 --host 127.0.0.1 --port 8080 --mode observe
```

Now drive traffic through `:8080` and watch the gateway's stderr:

```bash
curl 'http://127.0.0.1:8080/users?name=guest'              # benign  -> forwarded, no verdict
curl "http://127.0.0.1:8080/users?name=x'%20OR%20'1'='1"   # SQLi    -> forwarded (observe), verdict logged
```

The benign request produces no verdict; the SQLi tautology logs `"decision":"confirmed"` (a proven
attack) but is still forwarded — because you are in observe.

**Against your own app.** Just point `--upstream` at it and send it your real traffic:

```bash
aegis gateway --upstream http://127.0.0.1:YOURPORT --host 0.0.0.0 --port 8080 --mode observe
```

**As the Docker sidecar** (bind `0.0.0.0` so clients outside the container can reach it; on Linux add
`--add-host=host.docker.internal:host-gateway` to reach an app on the host):

```bash
docker run --rm -p 8080:8080 aegis-gateway \
    --upstream http://host.docker.internal:3000 --host 0.0.0.0 --mode observe
```

The default `CMD` is `--mode observe`, so a bare `docker run ... aegis-gateway --upstream <url> --host 0.0.0.0`
stays read-only.

## c. Flip to **enforce** — only after zero false positives

Watch observe against your real traffic until you are satisfied it logs **no** verdicts on legitimate
requests (benign apostrophes, `AT&T`, HTML-encoded reflections, pasted SQL, etc. never trip a proof).
Then switch `--mode enforce`:

```bash
aegis gateway --upstream http://127.0.0.1:YOURPORT --host 0.0.0.0 --port 8080 --mode enforce
```

In enforce, a **proven** attack gets a `403` with its certificate; everything unproven still forwards.
Safety rails:

- **Fail-open always.** Any inspection error, an upstream that is down (honest `502`), or an unproven
  request forwards. The firewall never blocks a request it cannot *prove* is an attack.
- **Kill-switch = instant off-ramp.** Tripping the kill-switch for the gateway's `--slug` drops it to
  pass-through without downtime. In Docker, mount a volume at `/var/lib/aegis` to persist it across
  restarts.
- **Enforcement is entitlement-gated in a governed deployment.** Blocking needs the `AEGIS_RESPOND`
  capability; without it the gateway runs observe-only and logs why (detection is always available).
- **Code-accepting apps** (paste bins, dev Q&A, bug trackers) legitimately carry attack syntax in user
  content — keep those in `observe` and review before enforcing.

---

Defensive only. AEGIS protects **your own** app; it never attacks anyone and is not a stealth tool. It
blocks on proof or it forwards — there is no third, guess-based behavior. For the full oracle list,
the sidecar/middleware integration modes, and the honest coverage roadmap, read
[`../docs/aegis/DEPLOYMENT.md`](../docs/aegis/DEPLOYMENT.md).
