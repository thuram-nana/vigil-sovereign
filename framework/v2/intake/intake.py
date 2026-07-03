"""
intake.intake — UTI orchestrator. Single entry point: `run(url, ...)`.

Pipeline:

  1. Validate operator authorization for this URL (ethics gate).
  2. Build a Fetcher with a 50-request budget.
  3. Probe a small set of polite paths (/, /robots.txt, /.well-known/...).
  4. Run all seven detectors against the captured exchanges.
  5. Aggregate into a Fingerprint.
  6. Classify the stack archetype.
  7. Scaffold targets/<slug>/ from targets/_template/ + drafters.
  8. Record the engagement to MLS so future intakes have priors.

Per § 3.1, UTI never logs in, submits forms, fuzzes, or scans. The
output is `IntakeOutcome` which the CLI prints as JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..common import ethics
from ..common import logging as v2log
from ..common.errors import IntakeBudgetExceeded
from ..memory import recorder
from ..memory.store import open_store
from . import fingerprint as fp_pkg
from . import scaffolder, stack_classifier
from .http import DEFAULT_BUDGET, Fetcher, assert_public_target, make_fetcher
from .models import Fingerprint, IntakeOutcome


_log = v2log.get_logger(__name__)


_SECURITY_HEADER_NAMES = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
)


def _normalise_url(url: str) -> tuple[str, str]:
    """Return (full_url_with_scheme, hostname). Default to https://."""
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"could not parse hostname from {url!r}")
    return url, host


def run(
    target_url: str,
    *,
    slug: str | None = None,
    operator_name: str = "<name>",
    business_context: str = "",
    known_concerns: list[str] | None = None,
    budget: int = DEFAULT_BUDGET,
    fetcher: Fetcher | None = None,
    record_to_memory: bool = True,
) -> IntakeOutcome:
    full_url, host = _normalise_url(target_url)

    # 1. ethics gate
    ethics.require_authorized_intake(full_url)

    # 1b. SSRF entry-point guard (defence-in-depth). Reject a non-http(s)
    # scheme or a literal private / loopback / link-local / metadata IP at
    # the front door. DNS resolution is deferred to the fetcher's per-
    # request guard (resolve=False here) so a merely-unresolvable hostname
    # does not fail intake before scaffolding.
    assert_public_target(full_url, resolve=False)

    # 2. determine slug
    if slug is None:
        slug = scaffolder.slugify(host)
    v2log.bind_engagement(slug)
    _log.info("intake.start", slug=slug, target_url=full_url)

    # 3. fetcher — caller can pre-populate one (e.g. from a fixture
    # corpus); in that case we skip the default probe.
    if fetcher is None:
        fetcher = make_fetcher(full_url, budget=budget)
    if fetcher.used == 0:
        try:
            fetcher.probe_default_paths()
        except IntakeBudgetExceeded as e:
            _log.warning("intake.budget_exhausted_during_probe", error=str(e))

    exchanges = fetcher.exchanges

    # 4. detectors
    detector_results: dict[str, Any] = {}
    for name, detect in fp_pkg.ALL_DETECTORS:
        result = detect(exchanges)
        detector_results[name] = result

    # 5. aggregate fingerprint
    security_headers: dict[str, str] = {}
    for ex in exchanges:
        for h in _SECURITY_HEADER_NAMES:
            v = ex.header(h)
            if v and h not in security_headers:
                security_headers[h] = v
    cookies_seen: list[str] = []
    for ex in exchanges:
        for c in ex.cookies:
            if c not in cookies_seen:
                cookies_seen.append(c)
    paths_probed = list({urlparse(ex.url).path for ex in exchanges if ex.url})

    fingerprint = Fingerprint(
        target_url=full_url,
        detectors=detector_results,
        security_headers=security_headers,
        cookies_seen=cookies_seen,
        paths_probed=sorted(paths_probed),
        request_count=fetcher.used,
    )

    # 6. classify
    classification = stack_classifier.classify(fingerprint)
    _log.info(
        "intake.classified",
        slug=slug,
        archetype=classification.primary.archetype.slug,
        score=classification.primary.score,
        runners_up=[m.archetype.slug for m in classification.runners_up],
    )

    # 7. scaffold
    paths_written = scaffolder.scaffold(
        slug=slug, target_url=full_url, target_host=host,
        fingerprint=fingerprint, classification=classification,
        operator_name=operator_name,
        business_context=business_context,
        known_concerns=known_concerns,
    )

    # 8. record to memory
    if record_to_memory:
        try:
            with open_store() as store:
                recorder.record_engagement_start(
                    store, slug=slug,
                    target_url=full_url,
                    archetype=classification.primary.archetype.name,
                    fingerprint=fingerprint.model_dump(mode="json"),
                    business_context=business_context,
                    posture="TEST",
                )
        except Exception as e:
            _log.warning("intake.memory.record_failed", error=str(e))

    return IntakeOutcome(
        target_url=full_url,
        slug=slug,
        fingerprint=fingerprint,
        classification=classification,
        scaffold_dir=paths_written["scaffold_dir"],
        charter_draft_path=paths_written["charter_draft"],
        threat_model_path=paths_written["threat_model"],
        attack_tree_path=paths_written["attack_tree"],
        fingerprint_json_path=paths_written["fingerprint_json"],
        request_count=fetcher.used,
        notes=[
            f"Drafted under budget {budget}; used {fetcher.used} requests.",
            "charter.draft.md is unsigned. Move and sign as charter.md to "
            "unlock active testing.",
        ],
    )
