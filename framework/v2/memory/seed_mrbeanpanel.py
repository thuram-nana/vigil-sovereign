"""
memory.seed_mrbeanpanel — seed MLS with the existing mrbeanpanel data.

Per FORGE PROTOCOL § 3.2 acceptance:

    "seed the store with the existing targets/mrbeanpanel/ data
     (threat model scenarios, attack tree leaves, all imagined as
     past engagement artefacts).  Run UTI on a structurally similar
     second target. Confirm the planner's first hypotheses are
     biased — measurably — toward what worked on mrbeanpanel."

This module reads the mrbeanpanel files that exist on disk, treats
them as a completed engagement, and writes the implied facts into
MLS.  Concrete actions:

  - record_engagement_start with archetype + fingerprint + context
  - record the eight top-level hypotheses from README.md as 'open'
  - record the attack-tree leaves as 'open' hypotheses
  - record three plausible "confirmed" findings reflecting the most
    common outcomes against this archetype (so recall has *something*
    to retrieve)
  - record_engagement_end + run postmortem so priors update

The "imagined past engagement" framing is honest: there are no real
findings on this target yet. The seed is for testing the substrate
and giving UTI a bias-target to query.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..common import paths
from . import postmortem, recorder
from .store import Store


_SLUG = "mrbeanpanel"
_ARCHETYPE = "PHP-Smarty SMM-panel fork"
_TARGET_URL = "https://mrbeanpanel.com"


def _read_top_hypotheses() -> list[tuple[str, str]]:
    """Pull the eight hypotheses from targets/mrbeanpanel/README.md."""
    p = paths.target_dir(_SLUG) / "README.md"
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")

    m = re.search(r"##\s*Top Hypotheses.*?\n(.*?)(?=\n##\s)", text, re.DOTALL)
    if m is None:
        return []
    block = m.group(1)
    out: list[tuple[str, str]] = []
    for line in block.splitlines():
        ml = re.match(r"\d+\.\s+\*\*(.*?)\*\*\s*(.*)", line)
        if ml:
            heading = ml.group(1).rstrip(":").strip()
            body = ml.group(2).strip()
            out.append((heading, body))
    return out


def _read_attack_tree_leaves() -> list[tuple[str, str]]:
    """Extract attack-tree leaves of form `[?] L1.2.3 description`."""
    p = paths.attack_tree_path(_SLUG)
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        m = re.search(r"\[\?\]\s+(L[0-9.]+)\s+(.*)", line)
        if m:
            handle = m.group(1)
            desc = m.group(2).strip().rstrip("\\").strip()
            out.append((handle, desc))
    return out


# Three plausible "confirmed" findings — the recurring high-impact
# patterns this archetype produces in the wild.  Marked clearly as
# seeded fixtures, not real findings, in the summary text.
_SEED_FINDINGS = [
    {
        "finding_slug": "S001-webhook-callback-no-signature",
        "title": "Payment-provider webhook accepts forged deposits without signature",
        "severity": "Critical",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_base": 9.8,
        "bug_class": "webhook-forgery",
        "surface": "POST /payment/<provider>/callback",
        "summary": (
            "[seed] Unauthenticated POST to the provider callback with "
            "an arbitrary user_id field credits balance. Recurring pattern "
            "across SMM panel forks based on Perfect Panel codebase."
        ),
        "impact": "[seed] direct balance crediting, potentially unbounded loss",
    },
    {
        "finding_slug": "S002-idor-on-orders",
        "title": "IDOR on /api/v2/orders/{id} reveals other users' order data",
        "severity": "High",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cvss_base": 6.5,
        "bug_class": "IDOR",
        "surface": "/api/v2/orders/{id}",
        "summary": (
            "[seed] Authenticated requests to /api/v2/orders/{id} return "
            "other users' order bodies when the id is incremented. "
            "Common in panel CMSes that authenticate the session but "
            "don't check resource ownership."
        ),
        "impact": "[seed] horizontal data exposure across all customers",
    },
    {
        "finding_slug": "S003-mass-assignment-on-profile",
        "title": "Mass assignment of role on PUT /profile",
        "severity": "Critical",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss_base": 8.8,
        "bug_class": "mass-assignment",
        "surface": "PUT /api/profile",
        "summary": (
            "[seed] Profile-update endpoint binds request fields without "
            "an allowlist; setting role=admin in the body promotes the "
            "user. Vertical privilege escalation."
        ),
        "impact": "[seed] vertical privilege escalation to admin",
    },
]


def seed(store: Store) -> dict[str, int | str]:
    """Idempotent: re-running yields the same row counts.

    Returns a stats dict for the CLI to print.
    """
    started_at = datetime(2026, 5, 4, tzinfo=timezone.utc).isoformat(timespec="seconds")

    fingerprint = {
        "server": "nginx",
        "framework": "PHP",
        "templating": "Smarty",
        "cms_family": "Perfect Panel fork",
        "cdn_signals": ["cdn.glycon.net", "storage.perfectcdn.com"],
        "payment_processors": [
            "Cryptomus", "Coinbase Commerce", "Payeer",
            "Perfect Money", "card-processor",
        ],
        "vertical": "SMM reseller",
    }

    eid = recorder.record_engagement_start(
        store,
        slug=_SLUG,
        target_url=_TARGET_URL,
        archetype=_ARCHETYPE,
        fingerprint=fingerprint,
        business_context=(
            "SMM (Social Media Marketing) reseller panel. ~44k users, "
            "~967k orders. Multi-PSP balance topup. Operator reports "
            "active account-takeover incidents."
        ),
        posture="TEST",
        started_at=started_at,
    )

    # Top hypotheses from README.md → recorded as 'open'.
    n_top = 0
    for i, (heading, body) in enumerate(_read_top_hypotheses(), start=1):
        recorder.record_hypothesis(
            store, _SLUG,
            handle=f"H-{i:03d}",
            bug_class=_classify_bug_class(heading),
            surface="(top-level hypothesis)",
            given="from threat model + operator priors",
            if_text=heading,
            then_text="bug confirms one of the ATO / fraud paths",
            because=body[:240] if body else "operator's prior reasoning",
            refute_on="negative-control variant of the test does not trigger",
            cheap_test="see attack-tree leaves under the corresponding goal",
            status="open",
            confidence=0.5,
            created_at=started_at,
        )
        n_top += 1

    # Attack-tree leaves → recorded as 'open' hypotheses.
    n_leaves = 0
    for handle, desc in _read_attack_tree_leaves():
        recorder.record_hypothesis(
            store, _SLUG,
            handle=handle,
            bug_class=_classify_bug_class(desc),
            surface="(attack-tree leaf)",
            given=f"attack-tree path {handle}",
            if_text=desc,
            then_text="branch confirms a leaf of the attack tree",
            because="modelled as part of the engagement attack tree",
            refute_on="branch tested and behaviour matches expected hardening",
            cheap_test="see playbook for the corresponding bug class",
            status="open",
            confidence=0.4,
            created_at=started_at,
        )
        n_leaves += 1

    # Three seeded "confirmed" findings + matching confirmed hypotheses.
    n_findings = 0
    for f in _SEED_FINDINGS:
        bug_class = str(f["bug_class"])
        surface = str(f["surface"])
        recorder.record_finding(
            store, _SLUG,
            finding_slug=str(f["finding_slug"]),
            title=str(f["title"]),
            severity=str(f["severity"]),
            cvss_vector=str(f["cvss_vector"]),
            cvss_base=float(f["cvss_base"]),  # type: ignore[arg-type]
            bug_class=bug_class,
            surface=surface,
            summary=str(f["summary"]),
            impact=str(f["impact"]),
            discovered_at=started_at,
        )
        recorder.record_hypothesis(
            store, _SLUG,
            handle=f"S-{str(f['finding_slug'])[:4]}",
            bug_class=bug_class,
            surface=surface,
            given="standard low-priv session",
            if_text=str(f["title"]),
            then_text="exploit reproduces with a single curl",
            because=str(f["summary"]),
            refute_on="response identical to baseline",
            cheap_test="single curl + diff",
            status="confirmed",
            confidence=0.95,
            created_at=started_at,
        )
        # And a successful payload to make prior diversity meaningful.
        recorder.record_payload(
            store, _SLUG,
            bug_class=bug_class,
            payload_text=_seed_payload_for(bug_class),
            target_surface=surface,
            archetype=_ARCHETYPE,
            outcome="success",
            notes="seeded — illustrates the high-yield payload for this class",
            used_at=started_at,
        )
        n_findings += 1

    # Some refuted attempts to make priors meaningful.
    for kls, surf in (
        ("SQLi", "/search?q="),
        ("XXE", "/upload"),
        ("XSS", "/profile/about"),
    ):
        recorder.record_payload(
            store, _SLUG,
            bug_class=kls, payload_text=f"[seed] standard {kls} payload",
            target_surface=surf, archetype=_ARCHETYPE, outcome="failure",
            notes="seeded refutation",
            used_at=started_at,
        )
        recorder.record_dead_end(
            store, _SLUG, technique=kls, archetype=_ARCHETYPE,
            surface=surf, reason="parameterised query / output-encoded — no signal",
            recorded_at=started_at,
        )

    # Playbook outcomes — yield numbers that produce non-trivial priors.
    for pb_id, yld in (
        ("05-api-security", 1),
        ("07-authorization", 2),
        ("11-cryptography", 0),
    ):
        recorder.record_playbook_outcome(
            store, _SLUG, playbook_id=pb_id, section="seed",
            findings_yielded=yld, time_spent_minutes=60,
            notes="seeded engagement; yield reflects the seeded findings list",
        )

    recorder.record_engagement_end(store, _SLUG)

    # Compute postmortem (this also bumps priors).
    pm_path = postmortem.run(store, _SLUG)

    return {
        "engagement_id": eid,
        "top_hypotheses": n_top,
        "attack_tree_leaves": n_leaves,
        "seed_findings": n_findings,
        "postmortem_path": str(pm_path),
    }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


_BUG_CLASS_HINTS = (
    ("password reset",        "reset-token"),
    ("session",               "session-fixation"),
    ("oauth",                 "oauth-misconfig"),
    ("2fa",                   "mfa-bypass"),
    ("idor",                  "IDOR"),
    ("mass-assignment",       "mass-assignment"),
    ("mass assignment",       "mass-assignment"),
    ("webhook",               "webhook-forgery"),
    ("race",                  "race"),
    ("sql",                   "SQLi"),
    ("xss",                   "XSS"),
    ("csrf",                  "CSRF"),
    ("ssrf",                  "SSRF"),
    ("rce",                   "RCE"),
    ("file upload",           "file-upload"),
    ("template injection",    "SSTI"),
    ("path traversal",        "path-traversal"),
    ("auth bypass",           "auth-bypass"),
    ("privilege escalation",  "privesc"),
    ("admin",                 "vertical-privesc"),
    ("subdomain takeover",    "subdomain-takeover"),
    ("source",                "source-disclosure"),
    ("env",                   "config-disclosure"),
    ("backup",                "backup-exposure"),
    ("git",                   "source-disclosure"),
    ("coupon",                "coupon-fraud"),
    ("refund",                "refund-fraud"),
    ("refer",                 "referral-fraud"),
    ("balance",               "balance-manipulation"),
    ("currency",              "currency-confusion"),
)


def _classify_bug_class(text: str) -> str:
    s = text.lower()
    for needle, label in _BUG_CLASS_HINTS:
        if needle in s:
            return label
    return "unclassified"


def _seed_payload_for(bug_class: str) -> str:
    if bug_class == "IDOR":
        return "GET /api/v2/orders/<other_user_order_id> with own session cookie"
    if bug_class == "mass-assignment":
        return 'PUT /api/profile body={"name":"x","role":"admin","is_admin":true}'
    if bug_class == "webhook-forgery":
        return ('POST /payment/<provider>/callback body={"order_id":"x",'
                '"status":"paid","amount":"100","currency":"USD","user_id":"<target>"}')
    return f"(seed payload illustrating {bug_class})"
