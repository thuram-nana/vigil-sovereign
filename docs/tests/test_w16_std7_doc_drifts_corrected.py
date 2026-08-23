"""W16-STD-7 (#533) — the §16 doc-vs-code drifts must not drift back to their false claims.

WHY THIS TEST EXISTS. The limitations inventory (§16) re-verified a batch of documentation claims that
had fallen behind the code at this HEAD. Each was corrected against the actual source; this test pins the
correction four ways, exactly as the W0-4 batch (``test_w04_stale_docs_corrected.py``) does:

  * a FORBIDDEN false phrase must be GONE from the doc;
  * a corrected ANCHOR phrase must be PRESENT (a silent revert turns it red);
  * the code FACT the correction now cites must be TRUE in-tree (a NEW overclaim turns it red);
  * negative controls prove the checker is not a no-op.

The drifts pinned here (all re-verified against the code at the fixed HEAD):

  16.2 / 16.16  DEVELOPER-HANDOFF.md and docs/AS-BUILT.md said CI runs "six / 6 jobs"; ci.yml has 12.
  16.3          docs/FEATURES.md said `k8s_workload_posture_oracle` "is NOT wired into `verifier._run`";
                it IS (verifier.py fires it on the `k8s_workload_control` ctx key).
  16.4          docs/FEATURES.md said `crucible-blackboard-chain` is
                "owner_rooted=False AND file_backed=False — NOT wired into the live engine"; the registered
                segment is owner_rooted=True, file_backed=True and is wired + offline-verified.
  16.5 / 16.8   AS-BUILT.md / AS-BUILT-LIVE.md / FEATURES.md called `Neo4jGraphStore` a `[SCAFFOLD]`
                where "every method raises"; it is a real client body issuing Cypher — only construction
                without a driver raises.
  16.6          AS-BUILT-LIVE.md said the signed per-action approval token was "genuinely not built"; it is
                built (`live/approval_token.py`).
  16.7          docs/FEATURES.md said DEFERRED-INFRA.md "contains only G1/X1/X2/X3"; it has H3/H4/R4/E too.
  16.14         scanner/campaign.py said the remote-engage browser path "is deferred until a CDP
                request-allowlist gates that egress"; that allowlist ships (`cdp.py`) and is wired.
  16.15         improve/patcher.py referenced a non-existent playbook `03-surface-mapping.md`; the file is
                `03-attack-surface-mapping.md`.
  (bonus)       a stale "13 required status checks" comment in ci.yml (canonical is 14).

Files only — reads text, parses no trust domain, runs no tool, sends no packet — so it belongs in the
docs-only ``the briefing explains every agent and capability`` required CI job.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

HANDOFF = REPO / "DEVELOPER-HANDOFF.md"
AS_BUILT = REPO / "docs" / "AS-BUILT.md"
AS_BUILT_LIVE = REPO / "docs" / "AS-BUILT-LIVE.md"
FEATURES = REPO / "docs" / "FEATURES.md"
DEFERRED = REPO / "docs" / "DEFERRED-INFRA.md"
CI_YAML = REPO / ".github" / "workflows" / "ci.yml"

CAMPAIGN = REPO / "engine" / "crucible" / "framework" / "v2" / "scanner" / "campaign.py"
PATCHER = REPO / "engine" / "crucible" / "framework" / "v2" / "improve" / "patcher.py"
VERIFIER = REPO / "engine" / "crucible" / "framework" / "v2" / "verify" / "verifier.py"
SPINE_DOMAINS = REPO / "packages" / "core" / "vigil_core" / "vigil_core" / "spine_domains.py"
STORE = REPO / "engine" / "crucible" / "framework" / "v2" / "graph" / "store.py"
APPROVAL_TOKEN = REPO / "integration" / "vigil_integration" / "live" / "approval_token.py"
CDP = REPO / "engine" / "crucible" / "framework" / "v2" / "scanner" / "cdp.py"
PLAYBOOK_OK = REPO / "engine" / "crucible" / "framework" / "playbooks" / "03-attack-surface-mapping.md"
PLAYBOOK_BAD = REPO / "engine" / "crucible" / "framework" / "playbooks" / "03-surface-mapping.md"


def _collapsed(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _has(path: Path, phrase: str) -> bool:
    assert path.is_file(), f"file missing: {path}"
    return _collapsed(phrase) in _collapsed(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The three ledgers. Kept module-level so the negative controls can perturb them.
# ---------------------------------------------------------------------------
FORBIDDEN: list[tuple[Path, str]] = [
    (HANDOFF, "runs **six jobs on Python 3.13**"),
    (HANDOFF, "the 6 CI jobs"),
    (AS_BUILT, "CI = 6 jobs:"),
    (FEATURES, "is NOT wired into `verifier._run`** — it is reachable only on the live-RBAC sensor path"),
    (FEATURES, "owner_rooted=False AND file_backed=False — NOT wired into the live engine"),
    (FEATURES, "`Neo4jGraphStore` — SCAFFOLD (infra-gated) STUB, every method raises"),
    (FEATURES, "which contains only G1/X1/X2/X3"),
    (AS_BUILT, "sits behind the same interface as a `[SCAFFOLD]` (every method raises)"),
    (AS_BUILT_LIVE, "sits behind the same interface as a `[SCAFFOLD]` (every method raises)"),
    (AS_BUILT_LIVE, "operator approval token**: genuinely not built"),
    (CAMPAIGN, "browser path is deferred until a CDP request-allowlist gates that egress"),
    (PATCHER, "framework/playbooks/03-surface-mapping.md"),
    (CI_YAML, "branch-protected with 13 required status"),
]

ANCHORS: list[tuple[Path, str]] = [
    (HANDOFF, "the 13 CI jobs"),
    (AS_BUILT, "CI = 13 jobs in `ci.yml`"),
    (FEATURES, "is wired into `verifier._run`** (`verifier.py:854-858`)"),
    (FEATURES, "owner_rooted=True AND file_backed=True**"),
    (FEATURES, "a real client body behind a deploy gate, NOT an every-method-raises stub"),
    (FEATURES, "which contains G1, X1, X2, X3, H3, H4, R4, E"),
    (AS_BUILT, "sits behind the same interface as a **real client body**"),
    (AS_BUILT_LIVE, "sits behind the same interface as a **real client body**"),
    (AS_BUILT_LIVE, "Signed per-action operator approval token**: **built**"),
    (CAMPAIGN, "that egress is now GATED at the resolver layer rather than deferred"),
    (PATCHER, "framework/playbooks/03-attack-surface-mapping.md"),
    (CI_YAML, "branch-protected with 14 required status"),
]


def present_forbidden(pairs: list[tuple[Path, str]]) -> list[str]:
    return [f"{p.name}: forbidden phrase returned: {ph!r}" for p, ph in pairs if _has(p, ph)]


def missing_anchors(pairs: list[tuple[Path, str]]) -> list[str]:
    return [f"{p.name}: corrected anchor gone: {ph!r}" for p, ph in pairs if not _has(p, ph)]


def code_fact_violations() -> list[str]:
    """Every code fact the corrections now cite must be TRUE in the tree."""
    errs: list[str] = []

    # 16.2/16.16 — ci.yml really has 13 jobs (count the top-level job keys).
    ci = CI_YAML.read_text(encoding="utf-8")
    # Job keys sit at exactly two-space indent under `jobs:`; the `on:` triggers are deeper/other.
    in_jobs = ci.split("\njobs:", 1)[-1]
    job_keys = re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", in_jobs, re.MULTILINE)
    if len(job_keys) != 13:
        errs.append(f"16.2: expected 13 ci.yml jobs, found {len(job_keys)}: {job_keys}")

    # 16.3 — verifier._run really fires k8s_workload_posture_oracle on the workload ctx key.
    if "k8s_workload_posture_oracle(ctx[" not in VERIFIER.read_text(encoding="utf-8"):
        errs.append("16.3: verifier.py does not call k8s_workload_posture_oracle(ctx[...])")

    # 16.4 — the registered crucible-blackboard-chain segment is owner_rooted=True, file_backed=True.
    sd = SPINE_DOMAINS.read_text(encoding="utf-8").splitlines()
    idx = next((i for i, ln in enumerate(sd) if 'name="crucible-blackboard-chain"' in ln), None)
    if idx is None:
        errs.append("16.4: crucible-blackboard-chain segment not found in spine_domains.py")
    else:
        window = " ".join(sd[idx:idx + 6])
        if "owner_rooted=True" not in window or "file_backed=True" not in window:
            errs.append("16.4: crucible-blackboard-chain is not owner_rooted=True/file_backed=True")

    # 16.5/16.8 — Neo4jGraphStore is a real client body (issues Cypher via a driver session).
    store = STORE.read_text(encoding="utf-8")
    if "session.execute_write(_tx_rebuild" not in store or "MERGE" not in store:
        errs.append("16.5/16.8: Neo4jGraphStore does not issue MERGE Cypher via a driver session")

    # 16.6 — the per-action approval token is really built.
    if not APPROVAL_TOKEN.is_file():
        errs.append("16.6: live/approval_token.py missing")
    else:
        at = APPROVAL_TOKEN.read_text(encoding="utf-8")
        if "def consume_token" not in at or "def verify_token" not in at:
            errs.append("16.6: approval_token.py does not define verify_token/consume_token")

    # 16.7 — DEFERRED-INFRA.md really has the H3/H4/R4/E sections.
    deferred = DEFERRED.read_text(encoding="utf-8")
    for header in ("## H3", "## H4", "## R4", "## E "):
        if header not in deferred:
            errs.append(f"16.7: DEFERRED-INFRA.md missing section {header!r}")

    # 16.14 — the CDP request-allowlist really exists.
    if "def enable_request_allowlist" not in CDP.read_text(encoding="utf-8"):
        errs.append("16.14: cdp.py does not define enable_request_allowlist")

    # 16.15 — the corrected playbook exists and the broken name does not.
    if not PLAYBOOK_OK.is_file():
        errs.append("16.15: framework/playbooks/03-attack-surface-mapping.md missing")
    if PLAYBOOK_BAD.exists():
        errs.append("16.15: framework/playbooks/03-surface-mapping.md unexpectedly exists")

    return errs


def drift_violations() -> list[str]:
    """The single enforcing checker: every drift correction still holds (forbidden gone, anchors present,
    cited code facts true). An empty list means no §16 drift has re-opened."""
    return present_forbidden(FORBIDDEN) + missing_anchors(ANCHORS) + code_fact_violations()


# ---------------------------------------------------------------------------
# The real checks.
# ---------------------------------------------------------------------------
def test_no_forbidden_false_phrase_returned():
    violations = present_forbidden(FORBIDDEN)
    assert not violations, "a §16 drift re-opened:\n" + "\n".join(violations)


def test_every_corrected_anchor_is_present():
    violations = missing_anchors(ANCHORS)
    assert not violations, "a §16 correction was silently reverted:\n" + "\n".join(violations)


def test_every_cited_code_fact_is_true_in_tree():
    violations = code_fact_violations()
    assert not violations, "a §16 correction cites a code fact that is not true:\n" + "\n".join(violations)


def test_all_drift_corrections_hold():
    violations = drift_violations()
    assert not violations, "\n".join(violations)


# ---------------------------------------------------------------------------
# Negative controls — the checker must reject a deliberately bad state.
# ---------------------------------------------------------------------------
def test_negative_control_a_returned_forbidden_phrase_is_flagged():
    # A phrase that IS still present in the tree (an anchor) stands in for a re-introduced false claim.
    bogus = [(HANDOFF, "the 13 CI jobs")]
    assert present_forbidden(bogus), "present_forbidden failed to flag a phrase that is in the file — no-op"


def test_negative_control_a_missing_anchor_is_flagged():
    assert missing_anchors([(HANDOFF, "this exact string is deliberately absent zzz")]), (
        "missing_anchors failed to flag an absent anchor — no-op"
    )
