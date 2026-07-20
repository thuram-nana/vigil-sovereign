"""
intake.scaffolder — copy targets/_template/ to targets/<slug>/ and
populate the four root documents from the drafters.

Idempotent: re-running on an existing slug refreshes the draft files
but never touches charter.md (the operator-signed authoritative
file). It does overwrite charter.draft.md.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..common import logging as v2log
from ..common import paths
from . import drafters
from .models import Classification, Fingerprint


_log = v2log.get_logger(__name__)


def slugify(text: str) -> str:
    """Conservative slug from a hostname or URL."""
    import re
    from urllib.parse import urlparse

    if "://" in text:
        text = urlparse(text).hostname or text
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "target"


def scaffold(
    *,
    slug: str,
    target_url: str,
    target_host: str,
    fingerprint: Fingerprint,
    classification: Classification,
    operator_name: str = "<name>",
    business_context: str = "",
    known_concerns: list[str] | None = None,
) -> dict[str, str]:
    """Build the engagement directory. Returns paths of artefacts written."""
    template_dir = paths.target_template_dir()
    target_dir = paths.target_dir(slug)
    if not template_dir.is_dir():
        raise FileNotFoundError(f"target template missing at {template_dir}")

    if target_dir.exists():
        _log.info("intake.scaffold.refresh", slug=slug, dir=str(target_dir))
    else:
        shutil.copytree(template_dir, target_dir)
        _log.info("intake.scaffold.created", slug=slug, dir=str(target_dir))

    # Charter draft (NEVER overwrites charter.md)
    charter_md = drafters.draft_charter(
        slug=slug, target_host=target_host, target_url=target_url,
        classification=classification, fingerprint=fingerprint,
        operator_name=operator_name, business_context=business_context,
    )
    charter_draft = paths.charter_draft_path(slug)
    charter_draft.write_text(charter_md, encoding="utf-8")

    # Threat model
    tm_md = drafters.draft_threat_model(
        slug=slug, target_host=target_host,
        classification=classification, fingerprint=fingerprint,
        business_context=business_context,
        known_concerns=known_concerns,
    )
    threat_model_p = paths.threat_model_path(slug)
    threat_model_p.write_text(tm_md, encoding="utf-8")

    # Attack tree
    tree_md = drafters.draft_attack_tree(
        slug=slug, target_host=target_host, classification=classification,
    )
    attack_tree_p = paths.attack_tree_path(slug)
    attack_tree_p.write_text(tree_md, encoding="utf-8")

    # Fingerprint JSON
    fp_path = paths.fingerprint_path(slug)
    fp_path.parent.mkdir(parents=True, exist_ok=True)
    fp_path.write_text(
        json.dumps({
            "fingerprint": fingerprint.model_dump(),
            "classification": classification.model_dump(),
        }, indent=2, default=str),
        encoding="utf-8",
    )

    # Endpoints inventory — placeholder, not yet populated by recon.
    ep_path = paths.endpoints_path(slug)
    if not ep_path.exists():
        ep_path.parent.mkdir(parents=True, exist_ok=True)
        ep_path.write_text(
            f"# Endpoints — `{target_host}`\n\n"
            "Populate during Stage 3 (attack-surface mapping). "
            "UTI does not enumerate endpoints; intake is passive.\n",
            encoding="utf-8",
        )

    return {
        "scaffold_dir":           str(target_dir),
        "charter_draft":          str(charter_draft),
        "threat_model":           str(threat_model_p),
        "attack_tree":            str(attack_tree_p),
        "fingerprint_json":       str(fp_path),
    }
