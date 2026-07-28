# Engagement Charter — `testphp`

> The binding authorization document (OBSIDIAN constitution §II). This charter authorizes VIGIL to test
> **Acunetix's deliberately-vulnerable, publicly-published test site** `testphp.vulnweb.com` — a target the
> vendor explicitly stands up for exactly this purpose (see `targets/_practice/README.md`). It is a LEGAL,
> owner-published practice target; VIGIL never touches any other host.

## Target hosts (in scope)

| Host | Port | What it is |
|---|---|---|
| `testphp.vulnweb.com` | 80 (http) | Acunetix's published deliberately-vulnerable PHP/MySQL test app |

**Nothing else is in scope.** Only `testphp.vulnweb.com` may be touched by any tool. No pivoting to any
other Acunetix host, no scanning of neighbouring IPs, no third-party service.

## Operator attestation

- The operator explicitly authorized live testing of **`testphp.vulnweb.com`** in this session (the
  clarification answer selecting "+ External testphp.vulnweb.com"). This is a vendor-published test site,
  legal to test by anyone.
- The operator understands offense traffic will reach an external host and accepts responsibility for
  running it only from an environment they are authorized to originate traffic from.
- Authorization is current for VIGIL live-fire validation against this single published target.

Signed: Junior Thuram Nana

## Hard limits (inviolable)

- **Single host only.** Every tool invocation MUST resolve its target to `testphp.vulnweb.com`; the live
  executor's signed-scope floor + the never-liftable egress floor refuse any other host BEFORE a packet
  leaves (`vigil_gateway.denylist` + the conjunctive gate + WARDEN tier).
- **No destructive tools without the m-of-n gate.** sqlmap/hydra/metasploit require the threshold gate even
  here (the target is shared public infrastructure — be a good citizen).
- **Throttle.** It is shared public infrastructure; keep concurrency low and rates sane. Use a recognizable
  User-Agent (`OBSIDIAN/1.0 (authorized owner-test <date>)`).
- **No real user data.** The app holds only Acunetix's fake catalogue rows; take nothing beyond the minimum
  needed to prove a finding.

## Stop conditions

- Any sign of degradation of the shared test site → stop and back off.
- The operator says stop, or the kill-switch is tripped.

## How to run it (the deliberate off-console ceremony)

A remote target needs a signed authority the console cannot mint. Provision it, then engage:

```
# 1) mint + sign the authority for this scope (a deliberate, off-console act)
vigil provision --slug testphp --scope testphp.vulnweb.com

# 2) run the gated engagement (the error-based SQLi lives at listproducts.php?cat=1' )
vigil engage http://testphp.vulnweb.com/listproducts.php?cat=1 --slug testphp --spine

# 3) the same oracle machinery L1 used mints an error_signature (error_based_sqli) FACT over the captured
#    MySQL error ("You have an error in your SQL syntax"); re-verify it OFFLINE:
python3 -m framework.v2 verify <the run's reverifiable.json>
```

> **Environment note (L2):** the loopback validation (`targets/loopback`, L1) already proved this pipeline
> end-to-end — a real `error_signature` SQLi FACT minted and re-verified 3/3 offline — with ZERO external
> dependency. This external run is byte-for-byte the same oracle path against the published site; it requires
> outbound network egress to `testphp.vulnweb.com`, which the sandbox this charter was authored in does not
> have. Run the three commands above from a network-connected host you are authorized to originate from.
