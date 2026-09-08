"""remediation.campaign — a batch remediation CAMPAIGN over many findings, with a signed ledger (PCR / W3).

One finding at a time is not enterprise remediation. A campaign takes EVERY confirmed fact on a codebase's
signed spine, ranks + dedupes them, runs the gated deep-fix ladder per finding (each on its own disposable
clone — the operator's source is never touched), optionally mints a Remediation Attestation per verified
fix (W5b), and folds the outcomes into a SIGNED, HASH-CHAINED LEDGER: one entry per finding
(attested / verified / degraded / failed), linked by the vigil_core chain and anchored by a signed head, so
any entry that is altered, dropped, reordered, or inserted breaks verification.

Pure + injected: ``run_campaign`` takes ``fix_one`` / ``attest_one`` callables, so the loop, ranking, and the
ledger are testable without a model, a sandbox, or git. Module scope imports only ``vigil_core`` (+ stdlib).
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from vigil_core import digest_payload
from vigil_core.chain import build_chain, sign_head, verify_chain, verify_head
from vigil_core.models import AuthorizerKey, ChainEntry, SignedChainHead, TrustRoot

LEDGER_SCHEMA = "vigil-remediation-ledger-v1"

# ranking: highest severity first; ties by ref for determinism
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# per-entry outcome vocabulary (a ledger never says "fixed" unless the oracle + suite said so)
STATUS_ATTESTED = "attested"        # verified-no-pr AND a signed attestation was minted
STATUS_VERIFIED = "verified"        # verified-no-pr (oracle cleared) — no attestation requested/minted
STATUS_DEGRADED = "degraded"        # the ladder ended honestly short (no proposal / unverified / skipped)
STATUS_FAILED = "failed"            # build-failed / verify-still-vulnerable / a refusal
STATUS_DEDUPED = "deduped"          # a confirmed fact covered by another entry (same rule+file) — accounted, not dropped
STATUS_SKIPPED = "skipped"          # a confirmed fact not run because of the --max-findings cap (explicit bound)


def _sev(f: Any) -> int:
    return _SEVERITY_RANK.get(str(getattr(f, "severity", "") or "").strip().lower(), 0)


def _dedupe_key(f: Any) -> tuple[str, str]:
    """Findings that share the confirming rule AND the target file are one root cause; keep the first
    (highest-severity, by ranking order)."""
    src = str(getattr(f, "source", "") or "")
    tgt = str(getattr(f, "target", "") or "").split(":", 1)[0]
    return (src, tgt)


def rank_findings(findings: "list[Any]", *, dedupe: bool = True) -> "list[Any]":
    """Deterministic campaign order: severity DESC, then ref ASC; optionally dedupe by (rule, file)."""
    ordered = sorted(findings, key=lambda f: (-_sev(f), str(getattr(f, "ref", ""))))
    if not dedupe:
        return ordered
    seen: set[tuple[str, str]] = set()
    out: list[Any] = []
    for f in ordered:
        k = _dedupe_key(f)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def _entry_for(f: Any, result: Any, attestation_note: Optional[str]) -> dict:
    status_raw = str(getattr(result, "status", "") or "")
    verified = status_raw == "verified-no-pr"
    attested = bool(verified and attestation_note and str(attestation_note).startswith("attestation MINTED"))
    if attested:
        status = STATUS_ATTESTED
    elif verified:
        status = STATUS_VERIFIED
    elif status_raw in ("build-failed", "verify-still-vulnerable", "verify-cheat-suspected", "failed") \
            or status_raw.startswith("refused") \
            or status_raw.endswith("-denied") or status_raw == "pr-quorum-denied":
        status = STATUS_FAILED
    else:
        status = STATUS_DEGRADED
    att_path = ""
    if attested:
        # the minter's note is "attestation MINTED [tier] -> <path> (verify offline: ...)"
        try:
            att_path = str(attestation_note).split("-> ", 1)[1].split(" (", 1)[0].strip()
        except Exception:  # noqa: BLE001
            att_path = ""
    return {
        "ref": str(getattr(f, "ref", "")),
        "bug_class": str(getattr(f, "bug_class", "") or ""),
        "severity": str(getattr(f, "severity", "") or ""),
        "target": str(getattr(f, "target", "") or ""),
        "ladder_status": status_raw,
        "status": status,
        "verified_no_pr": verified,
        "suite_ran": bool(getattr(result, "suite_ran", False)),
        "tests_passed": getattr(result, "tests_passed", None),
        "attestation": att_path,
        "patched_paths": list(getattr(result, "patched_paths", []) or []),
        "reason": str(getattr(result, "reason", "") or "")[:400],
    }


def _cover_entry(f: Any, status: str, note: str, *, covered_by: str = "") -> dict:
    """A ledger entry for a confirmed fact that was NOT individually fixed — deduped into another entry, or
    skipped by the cap. It is RECORDED (in the signed ledger), never silently dropped."""
    return {
        "ref": str(getattr(f, "ref", "")),
        "bug_class": str(getattr(f, "bug_class", "") or ""),
        "severity": str(getattr(f, "severity", "") or ""),
        "target": str(getattr(f, "target", "") or ""),
        "ladder_status": "",
        "status": status,
        "verified_no_pr": False,
        "suite_ran": False,
        "tests_passed": None,
        "attestation": "",
        "covered_by": covered_by,
        "patched_paths": [],
        "reason": note,
    }


def run_campaign(findings: "list[Any]", *, fix_one: Callable[[Any], Any],
                 attest_one: Optional[Callable[[Any, Any], Optional[str]]] = None,
                 max_findings: int = 0, dedupe: bool = True) -> dict:
    """Run the gated fix per ranked finding (each in its own disposable clone), attest each verified one when
    ``attest_one`` is given, and return ``{entries, counts, total_findings, total_run}``. EVERY confirmed
    fact appears in ``entries`` — a deduped fact as a ``deduped`` entry (``covered_by`` the primary ref) and a
    cap-dropped fact as a ``skipped`` entry — so the signed ledger accounts for the whole surface (no fact is
    silently dropped). A per-finding exception is an honest FAILED entry, never a campaign crash."""
    ranked = rank_findings(findings, dedupe=dedupe)            # deduped + severity-ordered
    ranked_ids = {id(f) for f in ranked}
    primary_by_key: dict[tuple[str, str], str] = {}
    for f in ranked:
        primary_by_key.setdefault(_dedupe_key(f), str(getattr(f, "ref", "")))
    to_run = ranked[:max_findings] if (max_findings and max_findings > 0) else list(ranked)
    run_ids = {id(f) for f in to_run}

    entries: list[dict] = []
    for f in to_run:
        try:
            result = fix_one(f)
        except Exception as exc:  # noqa: BLE001 — one finding's failure must not kill the campaign
            result = type("R", (), {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"})()
        note = None
        if attest_one is not None and str(getattr(result, "status", "")) == "verified-no-pr":
            try:
                note = attest_one(f, result)
            except Exception as exc:  # noqa: BLE001
                note = f"attestation SKIPPED: {type(exc).__name__}: {exc}"
        entries.append(_entry_for(f, result, note))
    # RECORD (don't drop) the deduped facts — each covered by the primary with the same (rule, file)
    for f in findings:
        if id(f) in ranked_ids:
            continue
        cover = primary_by_key.get(_dedupe_key(f), "")
        entries.append(_cover_entry(f, STATUS_DEDUPED, f"covered by {cover} (same rule+file)", covered_by=cover))
    # RECORD the cap-skipped facts (ranked but beyond --max-findings)
    for f in ranked:
        if id(f) in run_ids:
            continue
        entries.append(_cover_entry(f, STATUS_SKIPPED, "not run: --max-findings cap"))

    counts = {k: sum(1 for e in entries if e["status"] == k)
              for k in (STATUS_ATTESTED, STATUS_VERIFIED, STATUS_DEGRADED, STATUS_FAILED,
                        STATUS_DEDUPED, STATUS_SKIPPED)}
    return {"entries": entries, "counts": counts,
            "total_findings": len(findings), "total_run": len(to_run)}


def build_ledger(entries: "list[dict]", *, slug: str, signers: "list[tuple[str, str]]") -> dict:
    """The SIGNED, HASH-CHAINED remediation ledger: each entry's canonical digest is a chain link
    (``vigil_core.chain.build_chain``) and the tail is anchored by an Ed25519-signed head (m-of-n capable).
    Any altered/dropped/reordered/inserted entry breaks ``verify_ledger``."""
    if not signers:
        raise ValueError("refusing to build an UNSIGNED ledger: at least one signer is required")
    digests = [digest_payload(e) for e in entries]
    chain = build_chain(digests)
    # DOMAIN-SEPARATE the ledger head from the offense SPINE head: both use vigil_core.chain.sign_head (shared
    # crucible-evidence domain), so we bind the ledger TYPE into the signed engagement_slug. A spine head
    # (plain slug) then can never satisfy verify_ledger's slug check below — no cross-protocol head replay.
    head = sign_head(chain, engagement_slug=f"{LEDGER_SCHEMA}:{slug or ''}", signers=list(signers))
    return {
        "schema": LEDGER_SCHEMA,
        "slug": str(slug or ""),
        "entries": list(entries),
        "chain": [c.model_dump() for c in chain],
        "head": head.model_dump(),
    }


def trust_root_from_pubkeys(pubkeys: "dict[str, str]", *, threshold: int = 1) -> TrustRoot:
    """A vigil_core TrustRoot from an out-of-band {key_id: public_key_b64} map."""
    auths = [AuthorizerKey(key_id=str(k), name=str(k), public_key_b64=str(v)) for k, v in pubkeys.items()]
    return TrustRoot(threshold=max(1, int(threshold)), authorizers=auths)


def verify_ledger(ledger: dict, *, trust_root: TrustRoot) -> tuple[bool, str]:
    """DEMOTE-ONLY verification: (1) schema, (2) every entry's recomputed digest equals its chain link
    (binding), (3) the chain links unbroken (``verify_chain``), (4) the signed head anchors the tail under the
    OUT-OF-BAND trust root (``verify_head``). Total — malformed input is a False, never a crash."""
    try:
        if not isinstance(ledger, dict) or ledger.get("schema") != LEDGER_SCHEMA:
            return False, "not a vigil-remediation-ledger-v1"
        entries = ledger.get("entries")
        chain_raw = ledger.get("chain")
        if not isinstance(entries, list) or not isinstance(chain_raw, list) or len(entries) != len(chain_raw):
            return False, "entries/chain shape mismatch"
        chain = [ChainEntry.model_validate(c) for c in chain_raw]
        for i, (e, c) in enumerate(zip(entries, chain)):
            if digest_payload(e) != c.cert_digest:
                return False, f"entry {i} does not match its chain link (entry altered)"
        ok, why = verify_chain(chain)
        if not ok:
            return False, why
        head = SignedChainHead.model_validate(ledger.get("head") or {})
        expect_slug = f"{LEDGER_SCHEMA}:{ledger.get('slug', '')}"
        if head.engagement_slug != expect_slug:
            return False, f"head is not a remediation-ledger head (engagement_slug {head.engagement_slug!r} != {expect_slug!r})"
        ok, why = verify_head(head, chain, trust_root)
        return (True, "ledger verified") if ok else (False, why)
    except Exception as exc:  # noqa: BLE001 — malformed material is unverified, never a crash
        return False, f"malformed ledger: {type(exc).__name__}: {exc}"
