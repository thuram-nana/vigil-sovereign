# intake/ — UTI, the Universal Target Intake

Drop a URL, get a fully scaffolded engagement directory under
`targets/<slug>/` with a charter draft, threat model, attack tree,
and structured fingerprint JSON.

## Pipeline

```
URL
 │
 ├─► ethics.require_authorized_intake (refuse if no operator attestation)
 │
 ├─► Fetcher (50 req cap, polite UA, no auth, no fuzz)
 │       /
 │       /robots.txt
 │       /sitemap.xml
 │       /.well-known/security.txt
 │       /.well-known/openid-configuration
 │       /login, /api/, /wp-login.php, /admin
 │
 ├─► 7 detectors  ─►  Fingerprint (categories + confidences)
 │       server, framework, cms, auth, api, payment, cdn_waf
 │
 ├─► stack_classifier  ─►  Archetype + score + runners-up
 │       9 archetypes shipped (PHP-Smarty SMM, WordPress,
 │       Laravel marketplace, Next.js SaaS, Django REST, Rails,
 │       Spring microservices, WooCommerce, generic-web fallback)
 │
 ├─► drafters
 │       charter.draft.md     (NEVER overwrites charter.md)
 │       threat-model.md      (URK threat_model() output)
 │       attack-tree.md       (archetype seeds × common-vuln list)
 │
 ├─► scaffolder
 │       cp -r targets/_template targets/<slug>
 │       write the three drafts + recon/fingerprint.json + notes/endpoints.md
 │
 └─► MLS recorder.record_engagement_start
```

## Use

First-time authorization (one line per host):

```bash
python3 -m framework.v2 intake authorize https://example.com --operator yourname
```

This appends to `framework/v2/.intake-authorizations.txt`. UTI
refuses to operate against any host not listed there.

Then run:

```bash
python3 -m framework.v2 intake https://example.com
```

Or fingerprint only (no scaffold, no DB write):

```bash
python3 -m framework.v2 intake fingerprint https://example.com
```

## Offline / replay mode

Tests use captured fixtures. Set
`CRUCIBLE_INTAKE_FIXTURE_DIR=/path/to/fixtures` and Fetcher will
serve responses from disk instead of issuing requests.

To capture during a live run:

```bash
CRUCIBLE_INTAKE_CAPTURE_TO=intake/tests/fixtures/example \
  python3 -m framework.v2 intake https://example.com
```

## What UTI does *not* do

Per FORGE PROTOCOL § 3.1:

- Never logs in.
- Never submits forms.
- Never fuzzes.
- Never scans.
- Never makes more than 50 requests per intake.
- Fails closed: missing authorization, ambiguous ownership, suspected
  unauthorized target → halts and surfaces to the operator.

## Fail closed

The ethics gate at the top of `intake.run()` raises
`AuthorizationMissing` when the host has no entry in the ledger.
Charter draft is written to `charter.draft.md`, not `charter.md` —
the operator must move and sign before the planner (when ACP ships)
will issue any active request.
