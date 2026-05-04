"""
intake.drafters — generate the four pre-engagement documents.

Each drafter takes the Fingerprint + Classification + operator
context and returns the markdown body of one document. The bodies
are written to the engagement directory by `scaffolder.py`.

The charter drafter never auto-signs — the Signed line keeps the
literal `<name>` placeholder and the `charter.draft.md` filename
(distinct from `charter.md`). The operator is required to move and
sign before any further activity, per FORGE PROTOCOL § 8.1.
"""

from __future__ import annotations

import json
from datetime import date
from typing import Any

from ..common import logging as v2log
from ..kernel import threat_model as urk_threat_model
from ..kernel.models import ThreatModel as TMModel
from .models import Classification, Fingerprint


_log = v2log.get_logger(__name__)


# ---------------------------------------------------------------------------
# Charter drafter
# ---------------------------------------------------------------------------


def draft_charter(
    *,
    slug: str,
    target_host: str,
    target_url: str,
    classification: Classification,
    fingerprint: Fingerprint,
    operator_name: str = "<name>",
    business_context: str = "",
) -> str:
    today = date.today().isoformat()
    archetype = classification.primary.archetype
    arch_name = archetype.name
    arch_slug = archetype.slug

    return f"""# Engagement charter — `{target_host}`

**Version:** 1.0-DRAFT
**Status:** UNSIGNED — operator must move and sign this file as `charter.md`.
**Date:** {today}

> This file was drafted by UTI from a passive fingerprint of
> `{target_url}`. It is **not** authoritative. The operator MUST
> review every section and replace the `<...>` placeholders before
> any further activity. Until then v2's ethics gate refuses active
> testing against this target.

---

## 1. Operator attestation

I, **`{operator_name}`**, attest:

- I am the legal owner / authorized representative for the systems
  listed in § 2 below.
- I have the authority to authorize a security assessment of those
  systems.
- I have read and understood the OBSIDIAN constitution (`CLAUDE.md`)
  and the OPSEC discipline
  (`framework/cognitive/opsec-discipline.md`).
- I authorize OBSIDIAN to perform the activities described in this
  charter, within the limits stated.

Signed: `<name>`     Date: `__________`

---

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `{target_host}` | Primary host — fingerprinted as **{arch_name}** ({arch_slug}) | Yes (test accounts at § 5) |
| `*.{target_host}` | All subdomains discovered during recon | Yes |

Edit this table to add API hostnames, staging environments, or
sister hosts the operator owns. Subdomains discovered during recon
are conditionally in scope: agent surfaces them and waits for
operator confirmation before testing.

## 3. Out of scope (explicit)

These systems are not authorized for testing regardless of how the
agent reaches them:

- The hosting provider's control plane and shared infrastructure.
- Any CDN / WAF / payment / IdP / mail provider — third parties.
- Any system owned by a different legal entity.

Findings that *reach* these systems via in-scope flaws (SSRF,
webhook forgery, OAuth token leak) are valuable and should be
reported, but the third-party system itself is not to be exploited
beyond minimum proof.

## 4. Hard limits — never violated

- No DoS testing.
- No real-money payment movement beyond `$<X>` total cap.
- No real-user contact (no password resets / SMS / notifications to
  real customer addresses).
- No data exfiltration of real user PII beyond minimum needed to
  demonstrate impact (max `<N>` records, redacted in evidence).
- No persistence on production beyond proof (and removed within
  the same session).
- No third-party attack.
- No proxy chains, Tor, or rotating residential IPs.
- No bulk data deletion.
- No modification of admin settings on production without explicit
  confirmation per change.

## 5. Test accounts

The operator must create test accounts before active testing begins.
Tag each with the prefix `OBSIDIAN-TEST-` (or operator-chosen prefix)
so the operator can grep their DB for test artefacts.

| Role | Username/handle | Purpose |
|------|----------------|---------|
| Anonymous | (none) | Baseline external |
| User A (low-priv) | `OBSIDIAN-TEST-userA` | Standard authenticated tests |
| User B (low-priv) | `OBSIDIAN-TEST-userB` | Horizontal IDOR / tenant isolation |

## 6. Soft limits

- Off-peak window for heavy scans: `<HH:MM–HH:MM TZ>`.
- Default scan concurrency: 5–10 threads. Higher requires per-action approval.
- Rate-limit posture: respect 429 responses; back off exponentially.
- Single-IP source: `<operator-confirmed source IP>`.
- User-Agent: `OBSIDIAN/2.0 (authorized owner-test {today})`.

## 7. Posture

- [ ] **TEST** (default)
- [ ] **AUDIT**
- [ ] **EMULATE**

Selected: `<TEST | AUDIT | EMULATE>`.

## 8. Objectives

{business_context.strip() or "<operator fills in: the outcomes a successful engagement would produce>"}

## 9. Stop conditions

OBSIDIAN halts and surfaces immediately if:

- A test causes 5xx storms, sustained latency, or production degradation.
- Evidence of prior compromise is found (artifacts in webroot, unknown
  admin accounts, modified core files, suspicious cron/services).
- A test allows reading real user PII, real payment data, or real
  credentials. Do not bulk-collect; surface and ask.
- Authorization becomes unclear (in-scope / out-of-scope ambiguity).
- Operator says stop.

## 10. Communication plan

| Channel | Use | Response time expected |
|---------|-----|------------------------|
| `<channel>` | Day-to-day questions | `<within 4 hours>` |
| `<channel>` | Critical findings | `<within 1 hour>` |
| `<channel>` | Emergency stop | `<immediate, ack required>` |

## 11. Source code delivery

- [ ] Source code will be delivered at start of stage 7. Method: `<repo access | tarball | other>`.
- [ ] Source code will not be delivered (black-box only).

## 12. Continuous testing intent

- [ ] One-shot engagement.
- [ ] Quarterly self-driven re-engagement.
- [ ] Continuous monitoring of public-facing surface.

## 13. Reporting

Deliverables (per playbook 24):
- [ ] Executive summary (`reports/executive.md`).
- [ ] Technical report (`reports/technical.md`).
- [ ] Remediation roadmap (`reports/remediation-roadmap.md`).

## 14. Re-scope and amendments

Any expansion of scope, added systems, modified limits, or posture
shift requires operator update + version increment + engagement-log
entry + operator's confirmation in chat.

---

## Appendix — UTI fingerprint snapshot

This is what UTI saw on intake. It is not an exhaustive recon report;
it is the minimum signal needed to draft this charter. Refresh after
real recon.

```json
{json.dumps(_fingerprint_summary(fingerprint, classification), indent=2)}
```
"""


def _fingerprint_summary(fp: Fingerprint, cl: Classification) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "target_url": fp.target_url,
        "request_count": fp.request_count,
        "primary_archetype": {
            "slug": cl.primary.archetype.slug,
            "name": cl.primary.archetype.name,
            "score": cl.primary.score,
        },
        "best_per_category": {
            cat: {"label": d.label, "confidence": d.confidence}
            for cat, d in fp.best_per_category().items()
        },
        "security_headers_present": list(fp.security_headers.keys()),
    }
    if cl.runners_up:
        summary["runners_up"] = [
            {"slug": m.archetype.slug, "score": m.score} for m in cl.runners_up
        ]
    return summary


# ---------------------------------------------------------------------------
# Threat-model drafter
# ---------------------------------------------------------------------------


def draft_threat_model(
    *,
    slug: str,
    target_host: str,
    classification: Classification,
    fingerprint: Fingerprint,
    business_context: str = "",
    known_concerns: list[str] | None = None,
) -> str:
    """Call URK threat_model() and render to markdown.

    Falls back to an archetype-derived skeleton if URK errors.
    """
    arch = classification.primary.archetype

    try:
        tm, trace = urk_threat_model.threat_model(
            target_name=slug,
            business_context=business_context or (
                f"Target {target_host}; archetype {arch.name}"
            ),
            archetype=arch.name,
            fingerprint={"summary": fingerprint.to_text()},
            known_concerns=known_concerns or [],
        )
        body = _render_threat_model_markdown(slug, target_host, arch, tm, trace.is_dryrun)
    except Exception as e:
        _log.warning("intake.drafters.threat_model_fallback", error=str(e))
        body = _render_threat_model_skeleton(slug, target_host, arch, fingerprint)
    return body


def _render_threat_model_markdown(
    slug: str, host: str, arch: Any, tm: TMModel, is_dryrun: bool,
) -> str:
    src_note = (
        "Drafted by URK in dry-run mode (deterministic stub). "
        "Refresh after real recon."
        if is_dryrun else
        "Drafted by URK from a live LLM call. Refresh after recon as you "
        "discover new components and refute assumptions."
    )
    parts: list[str] = [
        f"# Threat model — `{host}`",
        "",
        f"**Status:** DRAFT (UTI-generated). Archetype: **{arch.name}** (`{arch.slug}`).",
        "",
        "> " + src_note,
        "",
        "## 1. Business context",
        "",
        tm.business_context.strip() or "<refine>",
        "",
        "## 2. Assets",
        "",
        "| ID | Asset | Conf | Integ | Avail | Priority | Rationale |",
        "|----|-------|------|-------|-------|----------|-----------|",
    ]
    for a in tm.assets:
        parts.append(
            f"| {a.id} | {a.name} | {a.confidentiality} | {a.integrity} "
            f"| {a.availability} | {a.priority} | {a.rationale} |"
        )

    parts += ["", "## 3. Actors", ""]
    for actor in tm.actors:
        parts.append(
            f"- **{actor.id} {actor.name}** — {actor.goal} "
            f"(skill: {actor.skill}; motivation: {actor.motivation})"
        )

    parts += ["", "## 4. Trust boundaries", ""]
    for b in tm.trust_boundaries:
        parts.append(
            f"- **{b.name}** — data: {b.data_crossing}; "
            f"auth: {b.auth_check}; failure: {b.failure_mode}"
        )

    if tm.stride_threats:
        parts += ["", "## 5. STRIDE", ""]
        for s in tm.stride_threats:
            parts.append(
                f"- **[{s.stride_class}] {s.boundary}**: {s.threat}"
                f" {'(realistic)' if s.realistic else '(theoretical)'}"
            )

    parts += [
        "", "## 6. Attack tree (root)",
        "", "```",
        _render_attack_tree(tm.attack_tree, indent=0),
        "```",
    ]

    if tm.catastrophic_outcomes:
        parts += ["", "## 7. Catastrophic outcomes (worst first)", ""]
        for i, o in enumerate(tm.catastrophic_outcomes, start=1):
            parts.append(f"{i}. {o}")

    if tm.not_in_model:
        parts += ["", "## 8. Not in model", ""]
        for x in tm.not_in_model:
            parts.append(f"- {x}")

    parts += [
        "",
        "## 9. Refresh",
        "",
        "Update this document at every phase boundary. Mark refuted "
        "assumptions explicitly; treat surprises as model errors.",
        "",
    ]
    return "\n".join(parts)


def _render_attack_tree(node: Any, indent: int) -> str:
    pad = "  " * indent
    line = f"{pad}{'└─ ' if indent else ''}{node.label}"
    if node.is_leaf:
        line += f"  [{node.status}]"
    out = [line]
    for child in node.children or []:
        out.append(_render_attack_tree(child, indent + 1))
    return "\n".join(out)


def _render_threat_model_skeleton(
    slug: str, host: str, arch: Any, fp: Fingerprint,
) -> str:
    parts = [
        f"# Threat model — `{host}`",
        "",
        f"**Status:** DRAFT (URK fallback). Archetype: **{arch.name}** (`{arch.slug}`).",
        "",
        "URK was unavailable; this skeleton was synthesized from the archetype "
        "and the intake fingerprint. Refresh by hand or re-run with a live LLM.",
        "",
        "## Archetype-derived top concerns",
        "",
    ]
    for v in arch.common_vulnerabilities:
        parts.append(f"- {v}")
    parts += ["", "## Fingerprint signals", "", "```", fp.to_text(), "```", ""]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Attack-tree drafter
# ---------------------------------------------------------------------------


def draft_attack_tree(
    *,
    slug: str,
    target_host: str,
    classification: Classification,
) -> str:
    arch = classification.primary.archetype
    today = date.today().isoformat()

    parts = [
        f"# Attack tree — `{target_host}`",
        "",
        f"**Version:** 1.0 (UTI draft)",
        f"**Date:** {today}",
        f"**Archetype:** `{arch.slug}`",
        "",
        "Initial decomposition seeded from the archetype's `attack_tree_seeds`",
        "and `common_vulnerabilities` list. Mark each leaf as you progress:",
        "",
        "- `[?]` not yet tested",
        "- `[~]` partially tested",
        "- `[X]` ruled out",
        "- `[√]` confirmed exploitable",
        "",
        "---",
        "",
    ]
    if not arch.attack_tree_seeds:
        arch_seeds = ["Take over a user account", "Reach data the user shouldn't access",
                      "Reach RCE on the host", "Manipulate state without authorisation"]
    else:
        arch_seeds = list(arch.attack_tree_seeds)

    for i, seed in enumerate(arch_seeds, start=1):
        parts += [
            f"## G{i} — {seed}",
            "",
            "```",
            f"G{i}. {seed}",
        ]
        # Hang each common vulnerability under the goal as a leaf seed.
        for j, v in enumerate(arch.common_vulnerabilities, start=1):
            parts.append(f"├── [?] L{i}.{j} {v}")
        parts.append("```")
        parts.append("")

    parts += [
        "## Update log",
        "",
        "| Date | Version | Change |",
        "|------|---------|--------|",
        f"| {today} | 1.0 | UTI draft from archetype `{arch.slug}`. |",
        "",
    ]
    return "\n".join(parts)
