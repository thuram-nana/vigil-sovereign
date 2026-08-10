"""cloud_benchmark — a signed, reproducible head-to-head of VIGIL cloud posture detection vs incumbents.

The CLOUD analogue of ``framework.v2.eval.benchmark_run`` (which benchmarks the WEB scanner). It scores
VIGIL's :func:`cloud_live_posture.cloud_live_verify` — the ``cloud_misconfiguration`` (CLOUD_POSTURE) and
``privilege_path`` (POLICY_PATH) oracles over a scoped capture — and each AVAILABLE incumbent CSPM
(prowler / scout-suite / checkov) against a labelled cloud ground-truth manifest, matched on
``(bug_class, resource_id)``, and emits a TAMPER-EVIDENT signed scorecard.

Design mirrors the web benchmark's honest confusion-matrix math (``scanner.benchmark._score``) and its signed
scorecard spine (``eval.benchmark_run.sign_scorecard``), but the match key is ``(bug_class, resource_id)``
instead of ``(bug_class, param)``. The signing here uses ``vigil_core`` directly (SHARED, no framework
dependency) so the scorecard signs + re-verifies OFFLINE with an out-of-band trust-root pin, exactly like the
web scorecard.

HONESTY (inherited from the web benchmark, non-negotiable). The ground truth uses VIGIL's own class
vocabulary and resource-id granularity, so a perfect VIGIL score is partly a HOME-FIELD artifact — this is a
soundness / false-positive demonstration, NOT a cross-tool superiority claim. An off-manifest incumbent
detection counts as a false positive *by construction of the strict match key*, which conflates a genuine
false alarm with a real detection reported under a different label/granularity; read the FP column next to the
raw finding sets, never alone. Incumbents not installed (or not run) are SKIPPED, never scored as zero.

Resource-id matching is CASE-SENSITIVE (a cloud resource id is case-sensitive — ``…:Acme`` and ``…:acme``
are distinct resources; the D5 scope gate matches the same way); the bug_class is lowercased. Both the
manifest and every adapter must name a resource by the SAME id form.

FATAL-2: every framework import is FUNCTION-LOCAL (only the VIGIL adapter needs the offense engine, via
``cloud_live_verify``); scoring, incumbent normalization, and signing are pure stdlib + ``vigil_core``, so
importing this module co-loads no offense engine. Live-fire (invoking a real incumbent against the authorized
cloud) needs operator-provisioned read-only creds; these fixtures are the offline, credential-free half.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Ground truth (the labelled manifest the scorecard is scored against)
# ---------------------------------------------------------------------------


def _mkey(bug_class: str, resource_id: str) -> "tuple[str, str]":
    """The canonical match identity: (lowercased bug_class, case-EXACT stripped resource id). Resource ids are
    case-sensitive (distinct resources); only surrounding whitespace is trimmed."""
    return (str(bug_class).strip().lower(), str(resource_id).strip())


@dataclass(frozen=True)
class CloudGroundTruth:
    """The labelled cloud manifest. ``vulns`` = the (resource_id, bug_class) a correct tool must confirm;
    ``safe`` = resource ids that must NEVER be flagged (a flag on one is a false positive by construction)."""

    vulns: "list[tuple[str, str]]"          # (resource_id, bug_class)
    safe: "list[str]" = field(default_factory=list)  # resource_ids that must not be flagged

    def expected_pairs(self) -> "set[tuple[str, str]]":
        return {_mkey(bc, rid) for rid, bc in self.vulns}

    def safe_ids(self) -> "set[str]":
        return {str(r).strip() for r in self.safe}


@dataclass
class ToolScore:
    """One tool's confusion counts on the cloud manifest, with derived precision/recall/f1 (rounded to 6,
    divide-by-zero → 0.0), mirroring ``eval.validation.Scoreboard``."""

    tool: str
    true_positives: int
    false_positives: int
    false_negatives: int
    safe_hits: int = 0                       # confirmed findings landing on a manifest-SAFE resource

    @property
    def precision(self) -> float:
        d = self.true_positives + self.false_positives
        return round(self.true_positives / d, 6) if d else 0.0

    @property
    def recall(self) -> float:
        d = self.true_positives + self.false_negatives
        return round(self.true_positives / d, 6) if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 6) if (p + r) else 0.0

    def to_row(self) -> dict:
        return {"tool": self.tool, "tp": self.true_positives, "fp": self.false_positives,
                "fn": self.false_negatives, "safe_hits": self.safe_hits,
                "precision": self.precision, "recall": self.recall, "f1": self.f1}


def score_pairs(tool: str, pairs: "set[tuple[str, str]]", truth: CloudGroundTruth) -> ToolScore:
    """Confusion matrix of a tool's confirmed ``(bug_class, resource_id)`` pairs vs the manifest — identical
    set-logic to ``scanner.benchmark._score``. Off-manifest pairs are false positives by construction."""
    expected = truth.expected_pairs()
    confirmed = {_mkey(bc, rid) for bc, rid in pairs}
    tp = len(confirmed & expected)
    fp = len(confirmed - expected)
    fn = len(expected - confirmed)
    safe = truth.safe_ids()
    safe_hits = len({rid for _bc, rid in confirmed if rid in safe})
    return ToolScore(tool=tool, true_positives=tp, false_positives=fp, false_negatives=fn, safe_hits=safe_hits)


# ---------------------------------------------------------------------------
# VIGIL adapter — run cloud_live_verify over the capture, extract confirmed pairs
# ---------------------------------------------------------------------------


def vigil_pairs(
    capture: "dict | bytes | str",
    *,
    provider: str,
    account: str,
    signers: "list[tuple[str, str]]",
    engagement_slug: str = "cloud-benchmark",
    region: str = "",
) -> "set[tuple[str, str]]":
    """Run VIGIL's :func:`cloud_live_verify` over ``capture`` with an ACCOUNT-scoped gate (so every captured
    resource is in scope — the benchmark measures detection over the whole captured inventory) and return the
    set of confirmed ``(bug_class, resource_id)`` pairs. Each pair's resource id is the FACT's bound subject
    (``bound_identity.resource_scope.resource``) — the case-exact captured id. Framework imports are
    function-local (FATAL-2)."""
    from .cloud_live_posture import cloud_live_verify  # noqa: PLC0415
    from .cloud_scope import CloudScopeEntry, CloudScopeGate, StaticCloudScopeSource  # noqa: PLC0415

    gate = CloudScopeGate(scope=StaticCloudScopeSource([CloudScopeEntry(provider=provider, account=account)]),
                          engagement_slug=engagement_slug)
    res = cloud_live_verify(capture, provider=provider, account=account, region=region, scope_gate=gate,
                            engagement_slug=engagement_slug, signers=signers)
    out: "set[tuple[str, str]]" = set()
    for f in res.facts:
        rid = f.signed.certificate.bound_identity.get("resource_scope", {}).get("resource", "")
        if rid:
            out.add((f.bug_class, rid))
    return out


# ---------------------------------------------------------------------------
# Incumbent adapters — normalize a CSPM's report to (bug_class, resource_id)
# ---------------------------------------------------------------------------

# Map an incumbent's native check identity to VIGIL's two cloud bug classes. Only the classes cloud_live_verify
# can itself confirm (cloud_misconfiguration = public/unencrypted-sensitive/wildcard-principal; privilege_path
# = an anonymous/over-privileged IAM grant path) are comparable; anything else the incumbent reports is left
# unmapped (dropped from the comparable set, not silently counted).
_PROWLER_CLASS = {
    "s3_bucket_public_access": "cloud_misconfiguration",
    "s3_account_level_public_access_blocks": "cloud_misconfiguration",
    "s3_bucket_policy_public_write_access": "cloud_misconfiguration",
    "rds_instance_storage_encrypted": "cloud_misconfiguration",
    "ec2_ebs_volume_encryption": "cloud_misconfiguration",
    "iam_policy_allows_privilege_escalation": "privilege_path",
    "iam_role_cross_account_readonlyaccess_policy": "privilege_path",
    "s3_bucket_policy_public_write_access_principal_wildcard": "privilege_path",
}
_CHECKOV_CLASS = {
    "CKV_AWS_20": "cloud_misconfiguration",   # S3 not public-read
    "CKV_AWS_53": "cloud_misconfiguration",   # S3 block public ACLs
    "CKV_AWS_57": "cloud_misconfiguration",   # S3 not public-write
    "CKV_AWS_16": "cloud_misconfiguration",   # RDS encryption
    "CKV_AWS_3": "cloud_misconfiguration",    # EBS encryption
    "CKV_AWS_1": "privilege_path",            # IAM policy allows * on *
    "CKV_AWS_49": "privilege_path",           # no wildcard principal in IAM
}
_SCOUT_CLASS = {
    "s3-bucket-world-listing": "cloud_misconfiguration",
    "s3-bucket-world-acl": "cloud_misconfiguration",
    "rds-instance-storage-not-encrypted": "cloud_misconfiguration",
    "iam-assume-role-lacks-external-id-and-mfa": "privilege_path",
    "iam-role-with-privilege-escalation": "privilege_path",
}


def _norm_incumbent(report: Any, class_map: "dict[str, str]", *, id_keys: "tuple[str, ...]",
                    check_keys: "tuple[str, ...]") -> "set[tuple[str, str]]":
    """Best-effort, TOTAL normalizer: walk a tool's finding list, map each check id (via ``class_map``) to a
    comparable bug_class, and pair it with the resource id. Unmapped checks are dropped (not counted). Never
    raises on a malformed entry (skips it) — a partial report degrades to fewer pairs, never a crash."""
    findings: list = []
    if isinstance(report, dict):
        for k in ("findings", "results", "Findings", "checks"):
            if isinstance(report.get(k), list):
                findings = report[k]
                break
    elif isinstance(report, list):
        findings = report
    out: "set[tuple[str, str]]" = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        check = next((str(item[k]) for k in check_keys if item.get(k)), "")
        bug_class = class_map.get(check)
        if not bug_class:
            continue
        rid = next((str(item[k]) for k in id_keys if item.get(k)), "")
        if rid:
            out.add((bug_class, rid))
    return out


def normalize_prowler(report: Any) -> "set[tuple[str, str]]":
    return _norm_incumbent(report, _PROWLER_CLASS,
                           id_keys=("resource_arn", "resource_id", "ResourceId", "resource"),
                           check_keys=("check_id", "CheckID", "check"))


def normalize_checkov(report: Any) -> "set[tuple[str, str]]":
    rep = report
    if isinstance(report, dict) and isinstance(report.get("results"), dict):
        rep = {"findings": report["results"].get("failed_checks", [])}
    return _norm_incumbent(rep, _CHECKOV_CLASS,
                           id_keys=("resource", "resource_address", "resource_id"),
                           check_keys=("check_id", "id"))


def normalize_scout_suite(report: Any) -> "set[tuple[str, str]]":
    return _norm_incumbent(report, _SCOUT_CLASS,
                           id_keys=("resource_id", "id", "arn"),
                           check_keys=("finding_id", "check", "id"))


_INCUMBENT_NORMALIZERS = {
    "prowler": normalize_prowler,
    "checkov": normalize_checkov,
    "scout-suite": normalize_scout_suite,
}


# ---------------------------------------------------------------------------
# The run: score VIGIL + each supplied incumbent report, emit + sign a scorecard
# ---------------------------------------------------------------------------


def run_cloud_benchmark(
    capture: "dict | bytes | str",
    truth: CloudGroundTruth,
    *,
    provider: str,
    account: str,
    signers: "list[tuple[str, str]]",
    incumbent_reports: "dict[str, Any] | None" = None,
    corpus_name: str = "cloud-inventory",
) -> "dict[str, Any]":
    """Score VIGIL (via ``cloud_live_verify``) and every supplied incumbent report against ``truth`` and
    return a machine-readable scorecard dict (not yet signed — see :func:`sign_cloud_scorecard`). Incumbents
    absent from ``incumbent_reports`` are listed as skipped, never scored zero (honest)."""
    reports = incumbent_reports or {}
    scores: "list[ToolScore]" = []
    scores.append(score_pairs("vigil", vigil_pairs(capture, provider=provider, account=account,
                                                   signers=signers), truth))
    skipped: "list[str]" = []
    for tool, norm in sorted(_INCUMBENT_NORMALIZERS.items()):
        if tool in reports:
            scores.append(score_pairs(tool, norm(reports[tool]), truth))
        else:
            skipped.append(tool)
    return {
        "schema": "vigil-cloud-benchmark/1",
        "corpus": corpus_name,
        "provider": provider,
        "account": account,
        "matcher": "(lowercased bug_class, case-exact resource_id); off-manifest = FP by construction",
        "ground_truth": {"vulns": [{"resource_id": r, "bug_class": b} for r, b in truth.vulns],
                         "safe": sorted(truth.safe_ids())},
        "tools_scored": [s.tool for s in scores],
        "incumbents_skipped": sorted(skipped),
        "results": [s.to_row() for s in scores],
        "honesty": ("VIGIL uses its own class vocabulary and resource-id granularity here, so a perfect VIGIL "
                    "score is partly a home-field artifact — a soundness/FP demonstration, not a cross-tool "
                    "superiority claim. Skipped incumbents were not run on this host; they are not scored 0."),
    }


def sign_cloud_scorecard(scorecard: "dict[str, Any]", out_path: "str | Path", *,
                         signers: "list[tuple[str, str]]", authorizers: "list[dict]",
                         threshold: int) -> dict:
    """Write ``scorecard`` as canonical JSON and sign it (Ed25519 m-of-n over ``vigil_core.canonical_json``)
    → a tamper-evident, independently-verifiable artifact + an out-of-band trust-root fingerprint pin.
    Mirrors ``eval.benchmark_run.sign_scorecard`` but is self-contained on ``vigil_core`` (SHARED — FATAL-2:
    no framework import). Writes ``<path>``, ``<path>.sig.json`` and ``<path>.fingerprint.txt``."""
    from vigil_core import canonical_json, sign  # noqa: PLC0415 (shared substrate, importable in both envs)

    p = Path(out_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    body = canonical_json(scorecard)
    p.write_bytes(body + b"\n")
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    fp = _trust_root_fingerprint(authorizers)
    sig_env = {
        "schema": "vigil-cloud-benchmark-sig/1",
        "scorecard": p.name,
        "scorecard_digest": digest,
        "threshold": int(threshold),
        "trust_root": {"threshold": int(threshold),
                       "authorizers": sorted(authorizers, key=lambda a: a["key_id"])},
        "signatures": sorted(({"key_id": kid, "signature_b64": sign(priv, body)} for kid, priv in signers),
                             key=lambda s: s["key_id"]),
    }
    p.with_suffix(p.suffix + ".sig.json").write_text(json.dumps(sig_env, indent=2, sort_keys=True) + "\n",
                                                     encoding="utf-8")
    p.with_suffix(p.suffix + ".fingerprint.txt").write_text(fp + "\n", encoding="utf-8")
    return sig_env


def verify_cloud_scorecard(scorecard_path: "str | Path", sig_env: dict, *,
                           trust_root_fingerprint: "str | None" = None) -> bool:
    """Re-verify a signed cloud scorecard OFFLINE: re-derive the canonical digest from the JSON on disk and
    check an m-of-n threshold of DISTINCT authorizer signatures over those bytes. Fail-closed on any mismatch.
    Pass ``trust_root_fingerprint`` (held out-of-band) to reject a forged/attacker-substituted trust root
    before any signature is checked (same pinning contract as the web scorecard verifier)."""
    from vigil_core import canonical_json, verify_one  # noqa: PLC0415

    try:
        doc = json.loads(Path(scorecard_path).read_text(encoding="utf-8"))
        body = canonical_json(doc)
        if ("sha256:" + hashlib.sha256(body).hexdigest()) != sig_env.get("scorecard_digest"):
            return False
        tr = sig_env.get("trust_root", {})
        authorizers = tr.get("authorizers", [])
        if trust_root_fingerprint is not None and _trust_root_fingerprint(authorizers) != trust_root_fingerprint:
            return False
        pub = {a["key_id"]: a["public_key_b64"] for a in authorizers}
        good: set = set()
        for s in sig_env.get("signatures", []):
            kid = s.get("key_id")
            if kid in pub and kid not in good and verify_one(pub[kid], body, s.get("signature_b64", "")):
                good.add(kid)
        return len(good) >= int(tr.get("threshold", 1))
    except Exception:  # noqa: BLE001 — any error is fail-closed (not verified)
        return False


def _trust_root_fingerprint(authorizers: "list[dict]") -> str:
    """A stable out-of-band pin for the signing trust root: sha256 over the canonical authorizer set."""
    from vigil_core import canonical_json  # noqa: PLC0415

    body = canonical_json(sorted(authorizers, key=lambda a: a["key_id"]))
    return "sha256:" + hashlib.sha256(body).hexdigest()


def render_cloud_scoreboard(scorecard: "dict[str, Any]") -> str:
    """A clean markdown scoreboard (tool | tp | fp | fn | safe_hits | precision | recall | f1) with the honest
    preamble, for a human-facing report."""
    lines = ["# VIGIL cloud benchmark scoreboard", "",
             f"**Corpus:** `{scorecard.get('corpus','')}` — provider `{scorecard.get('provider','')}` "
             f"account `{scorecard.get('account','')}`.",
             f"**Matcher:** {scorecard.get('matcher','')}", "",
             "| tool | tp | fp | fn | safe_hits | precision | recall | f1 |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for r in scorecard.get("results", []):
        lines.append(f"| {r['tool']} | {r['tp']} | {r['fp']} | {r['fn']} | {r['safe_hits']} | "
                     f"{r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} |")
    skipped = scorecard.get("incumbents_skipped", [])
    if skipped:
        lines += ["", f"**Incumbents skipped (not installed/run on this host):** {', '.join(skipped)}."]
    lines += ["", "### Reading the table", "", scorecard.get("honesty", "")]
    return "\n".join(lines) + "\n"
