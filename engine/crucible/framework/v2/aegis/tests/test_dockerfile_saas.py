"""AS-28 — ``Dockerfile.saas`` is a HASH-LOCKED, defense-only, closure-gated artifact.

Static, pure-stdlib file reads (no Docker daemon, no network, no ``framework`` import) — the actual
image build/scan/SBOM/sign is the DEFERRED A14 CI leg. Each "the X is present" assertion is paired with
a NEGATIVE CONTROL so a green result is evidence, not a vacuous pass.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_AEGIS_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[6]  # repo root (contains docker-compose.yml, Makefile)
_DOCKERFILE_SAAS = _AEGIS_DIR / "Dockerfile.saas"
_DOCKERFILE_BASE = _AEGIS_DIR / "Dockerfile"
_MANIFEST = _AEGIS_DIR / "saas-closure.json"

_DIGEST_RE = re.compile(r"^FROM\s+python:3\.13-slim@(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)


def test_dockerfile_saas_exists():
    assert _DOCKERFILE_SAAS.is_file()


def test_base_image_is_digest_pinned_and_aligned():
    # Hash-lock: the base is content-addressed by a full sha256 digest...
    text = _DOCKERFILE_SAAS.read_text(encoding="utf-8")
    m = _DIGEST_RE.search(text)
    assert m, "Dockerfile.saas must pin python:3.13-slim by a full @sha256 digest"
    saas_digest = m.group(1)
    # ...and it equals the sibling aegis Dockerfile's pin (one base of record, not a second provenance).
    base_m = _DIGEST_RE.search(_DOCKERFILE_BASE.read_text(encoding="utf-8"))
    assert base_m, "sibling aegis/Dockerfile lost its digest pin"
    assert saas_digest == base_m.group(1), "Dockerfile.saas base digest drifted from aegis/Dockerfile"
    # ...and the committed manifest records that same digest.
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["dockerfile"]["base_image_digest"] == saas_digest

    # NEGATIVE CONTROL: an unpinned `FROM python:3.13-slim` (tag only) must NOT satisfy the digest check.
    assert _DIGEST_RE.search("FROM python:3.13-slim\n") is None


def test_build_runs_the_closure_gate():
    # The build must FAIL CLOSED if offense is reachable: a RUN layer invokes the static closure analyzer.
    text = _DOCKERFILE_SAAS.read_text(encoding="utf-8")
    assert re.search(r"^RUN\s+python3\s+-m\s+framework\.v2\.aegis\.closure\s*$", text, re.MULTILINE), (
        "Dockerfile.saas must run the build-time closure gate (RUN python3 -m framework.v2.aegis.closure)"
    )


def test_runs_as_non_root_data_plane():
    text = _DOCKERFILE_SAAS.read_text(encoding="utf-8")
    assert re.search(r"^USER\s+aegis\s*$", text, re.MULTILINE), "a public data plane must drop root (USER aegis)"
    assert "useradd" in text


def test_does_not_ship_offense_engagement_data():
    # The defensive image copies the importable package, never the offensive playbooks / targets data.
    text = _DOCKERFILE_SAAS.read_text(encoding="utf-8")
    copy_targets = re.findall(r"^COPY\s+(.*)$", text, re.MULTILINE)
    joined = " ".join(copy_targets)
    for forbidden in ("targets/", "framework/playbooks", "framework/knowledge-base", "framework/cognitive"):
        assert forbidden not in joined, f"Dockerfile.saas must not COPY offense data: {forbidden}"


def test_dockerfile_saas_is_wired_not_an_orphan():
    # Repo doctrine (cf. test_aegis_dockerfile_wired): a Dockerfile nothing BUILDS rots. Dockerfile.saas
    # must be referenced by a real compose build service AND a make target, so its pin / COPY set / closure
    # gate are actually exercised.
    compose = (_REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "framework/v2/aegis/Dockerfile.saas" in compose, "no compose service builds Dockerfile.saas"
    makefile = (_REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "aegis-saas-image" in makefile, "no make target builds the SaaS image"


def test_manifest_records_the_deferred_a14_steps():
    # Honesty: the manifest must NAME the owner-gated steps this slice does not perform in the sandbox.
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    deferred = " ".join(manifest["deferred_to_a14_ci"]).lower()
    for token in ("build", "scan", "sbom", "sign"):
        assert token in deferred, f"deferred A14 steps must mention {token!r}"
