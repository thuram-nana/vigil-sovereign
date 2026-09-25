"""
proof.run — the run-integration seam: a Strix report + its executor capture → a persisted proof record.

``build_report_mint`` returns the ``mint(report)`` callback ``proof.sink`` invokes on an allowed report that
carries an executor capture. It reads the report's attached ``_vigil_capture`` (executor-captured exchanges +
raw blobs — NEVER the LLM's free text), builds :class:`evidence.poc.CapturedExchange` objects, mints via
:func:`proof.engine.mint_proof`, and PERSISTS a small proof record under ``<run_dir>/proofs/`` for the Proof
Studio screen to read (as plain JSON — the console reads it with no import of this package, so no
framework→integration dependency).

The capture is attached ONLY by the trusted capture path (never the model), so its mere presence is what makes
a report mint-eligible. ``_vigil_capture`` shape::

    {"exchanges": [{"channel": "request_payload", "role": "q", "request_bytes_ref": "req"}, ...],
     "blobs": {"req": b"' OR '1'='1"}}          # ref -> raw bytes (the non-LLM channel a FACT rests on)

FATAL-2: ``framework`` (``CapturedExchange``) is imported LAZILY inside the callback; the module scope pulls
only ``proof.engine``/``proof.sink`` (import-clean). Determinism: the proof-record id is a content address
(no wallclock/rng).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Optional

from .degradation import CAPTURE_FAILED, DEGRADED_NAME, MINT_FAILED, REDRIVE_FAILED, record_degradation
from .engine import mint_proof
from .sink import CAPTURE_KEY

PROOFS_SUBDIR = "proofs"
REVERIFIABLE_NAME = "reverifiable.json"


def _proofs_dir(run_dir: str | os.PathLike) -> Path:
    d = Path(run_dir) / PROOFS_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _record_degraded(run_dir: "str | os.PathLike", kind: str, where: str, exc: BaseException) -> None:
    """Record a TYPED proof-degradation cause (inv 12 / S9) for an EXECUTION failure swallowed inside the
    mint callback — best-effort, NEVER raises into Strix. Only a RAISED failure reaches here; a legitimate
    non-confirmation (missing endpoint / gate refusal / oracle non-fire) returns without calling this, so it
    stays a plain LEAD and remains clean-eligible."""
    try:
        record_degradation(run_dir, kind, where=where, detail=type(exc).__name__)
    except Exception:  # noqa: BLE001 — a degradation recorder must never raise into the scan path
        pass


def read_proofs(run_dir: str | os.PathLike) -> list[dict]:
    """Every persisted proof record for a run (plain JSON). Total on a missing dir / bad file."""
    d = Path(run_dir) / PROOFS_SUBDIR
    if not d.is_dir():
        return []
    out: list[dict] = []
    for f in sorted(d.glob("*.json")):
        if f.name in (REVERIFIABLE_NAME, DEGRADED_NAME):  # siblings, not proof records (C1 report / inv-12 manifest)
            continue
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


# A minimal, honest map from a Strix finding's own taxonomy (title / CWE / class) onto the oracle's bug_class
# vocabulary. It only picks WHICH oracle to TRY — the oracle still judges the captured bytes, so a wrong hint
# simply fails to fire (→ an honest LEAD), never fabricates a FACT. The auto-capture channel is response-side
# error-signature (proof_capture), whose oracle is error-based injection, so those are the classes worth
# hinting; an unrecognised finding keeps its raw class and stays a LEAD.
# The error-signature oracle's matched datastore/parser ENGINE -> the certificate's KNOWN bug_class. The
# oracle (framework.v2.verify.oracles.error_signature_oracle) is the SOLE authority on the class: a signed
# certificate must name the vulnerability the EVIDENCE proves, never the producer's claimed CWE/title. Every
# value is a KNOWN class (verify.verifier.is_known_bug_class) served by the ERROR_SIGNATURE oracle. A test
# (test_release_gate_false_fact) pins that this map covers EVERY engine label the oracle can emit, so a new
# datastore signature can never silently fall through to the producer's (launderable) self-report.
_ERRSIG_ENGINE_TO_CLASS = {
    "mysql": "error_based_sqli", "mariadb": "error_based_sqli", "postgresql": "error_based_sqli",
    "mssql": "error_based_sqli", "oracle": "error_based_sqli", "sqlite": "error_based_sqli",
    "sql-generic": "error_based_sqli", "mongodb": "nosqli",
    "ldap": "ldap_injection", "xpath": "xpath_injection",
}


def _errsig_engine(observed_body: "bytes | None", control_body: "bytes | None") -> str:
    """The datastore/parser ENGINE the error-signature oracle matched over these bytes (e.g. "postgresql",
    "ldap", "xpath"), or ``""`` if it does not fire. Deterministic and side-effect-free, run over the SAME
    observed/control bytes the mint adjudicates, so the engine the certificate label is derived from is
    exactly the one the oracle proves. The caller maps engine -> KNOWN class via ``_ERRSIG_ENGINE_TO_CLASS``
    and FAILS CLOSED (refuses the mint) on a fired-but-unmapped engine — never the producer's claim."""
    if not observed_body:
        return ""
    from framework.v2.verify.oracles import error_signature_oracle   # lazy — FATAL-2 (offense plane)
    sig = error_signature_oracle(observed_body, control_body)
    if not getattr(sig, "fired", False):
        return ""
    return str((getattr(sig, "observed", None) or {}).get("engine", ""))


def _oracle_bug_class(report: dict) -> str:
    explicit = str(report.get("bug_class") or "").strip()
    if explicit:
        return explicit
    hay = " ".join(str(report.get(k) or "") for k in ("cwe", "title", "finding_class", "description")).lower()
    # The SPECIFIC datastore CWE wins over a generic "sql" mention, so a CWE-90/91 finding whose prose merely
    # mentions SQL is not string-laundered onto SQLi. This is only the fallback LABEL a NON-firing finding
    # keeps (→ a LEAD): for an error-signature capture that reaches a FACT, the class is OVERRIDDEN at mint
    # time by the datastore/parser ENGINE the oracle actually matched (see ``_errsig_engine_class``), so the
    # certificate always names the vulnerability the EVIDENCE proves, never the producer's self-report.
    if "cwe-90" in hay or "ldap injection" in hay:
        return "ldap_injection"
    if "cwe-91" in hay or "xpath injection" in hay:
        return "xpath_injection"
    if "cwe-89" in hay or "sql injection" in hay or "sqli" in hay:
        return "error_based_sqli"
    return str(report.get("finding_class") or "").strip()


def _finding_from_report(report: dict) -> dict:
    return {
        "check_id": report.get("id") or report.get("check_id") or report.get("finding_slug") or "finding",
        "bug_class": _oracle_bug_class(report),
        "insertion_point": report.get("insertion_point") or report.get("param") or report.get("endpoint") or "",
        "poc_script_code": report.get("poc_script_code"),
        "evidence": report.get("evidence"),
        "poc_description": report.get("poc_description"),
    }


def _persist_record(run_dir: str | os.PathLike, res: Any, finding: dict, capture: dict) -> dict:
    """Write a small, deterministic proof record for the Proof Studio screen. The id is a content address of
    the finding identity (no wallclock), so re-minting the same finding overwrites the same record."""
    pid = hashlib.sha256(
        f"{res.finding_ref}:{res.bug_class}:{res.confirmed_by}".encode("utf-8")
    ).hexdigest()[:24]
    rec = {
        "proof_id": pid,
        "finding_ref": res.finding_ref,
        "bug_class": res.bug_class or finding.get("bug_class", ""),
        "status": res.status,                       # "fact" | "lead" | "denied"
        "reason": res.reason,
        "confirmed_by": res.confirmed_by,
        "confidence": res.confidence,
        "reproduced": res.reproduced,
        "gate_category": res.gate_category,
        "spooled": bool(res.envelope_path),
        "exchanges": [{"channel": str(e.get("channel", "")), "role": str(e.get("role", ""))}
                      for e in (capture.get("exchanges") or [])],
        "poc_present": bool(finding.get("poc_script_code")),
    }
    (_proofs_dir(run_dir) / f"{pid}.json").write_text(json.dumps(rec, sort_keys=True), encoding="utf-8")
    return rec


def read_reverifiable(run_dir: str | os.PathLike) -> dict:
    """The run's re-verifiable proof report ({"active_findings": [...]}) — each entry a proven FACT with its
    ``oracle_context`` (and, for a studio proof, its ``action_id``), the material ``vigil proof-export``
    builds a client bundle from. An empty ``active_findings`` doc on missing/unreadable files (never raises).

    BOTH storage conventions are read, because the platform writes two and they never met:

      * ``proofs/reverifiable.json`` — appended by the proof studio (:func:`_persist_reverifiable`).
      * ``reverifiable.json`` at the run root — written by a scan's ``--reverifiable-out``, which is
        what every console/UI scan uses (``console/actions.py``).

    Reading only the first meant a plain scan run exported ZERO certificates: its proofs were on disk,
    re-firing, and simply never looked at, so every scan dossier shipped without the offline-verifiable
    bundle that is the point of the exercise. Entries are merged, studio proofs first (so existing
    bundles keep their certificate order), and de-duplicated by canonical content so a finding recorded
    under both conventions is certified once."""
    out: list[dict] = []
    seen: set[str] = set()
    for path in (Path(run_dir) / PROOFS_SUBDIR / REVERIFIABLE_NAME, Path(run_dir) / REVERIFIABLE_NAME):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        findings = doc.get("active_findings") if isinstance(doc, dict) else None
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            try:
                key = json.dumps(f, sort_keys=True, default=str)
            except (TypeError, ValueError):
                key = repr(f)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    return {"active_findings": out}


def _persist_reverifiable(run_dir: str | os.PathLike, finding: dict, action_id: str,
                          exchanges: Any, resolve: Any, res: Any) -> None:
    """Append (dedup by check_id) a re-verifiable finding — the SAME plain-dict oracle_context shape a
    scan's reverifiable.json carries, so ``framework.v2 evidence verify`` re-fires it byte-identically. The
    finding's top-level ``bug_class`` mirrors the class embedded in the context (reverify refuses a flip)."""
    from framework.v2.verify.poc_translate import context_from_exchanges     # lazy — FATAL-2

    ctx = context_from_exchanges(exchanges, bug_class=str(finding.get("bug_class") or ""), resolve=resolve)
    if ctx is None:
        return
    embedded_class = str(getattr(ctx, "bug_class", "") or finding.get("bug_class") or "")
    exs = list(exchanges or [])
    channel = str(getattr(exs[0], "channel", "") or "") if exs else ""
    entry = {
        "check_id": finding["check_id"],
        "bug_class": embedded_class,
        # the ORACLE FAMILY this FACT was confirmed on — A6a's remediation oracle pins the patched-build
        # re-drive to this exact channel, so a mismatched re-drive can't mint a vacuous "silence".
        "channel": channel,
        "insertion_point": finding.get("insertion_point", ""),
        "confirmed_by": res.confirmed_by,
        "confidence": res.confidence,
        "action_id": action_id,
        "oracle_context": ctx.model_dump(mode="json"),
    }
    # W16-7 (AC5): STORE the signed certificate minted here, so `export_bundle` returns it BYTE-IDENTICAL
    # instead of re-minting a fresh one at download time (which drops `res.signed` and re-signs). The stored
    # certificate was signed over THIS finding's oracle_context (the `ctx` above), so the bundle's shipped
    # reverifiable.json (which carries that same oracle_context) re-verifies against it. Best-effort: a
    # serialization hiccup simply omits the stored cert and export falls back to a deterministic re-mint —
    # it never un-mints the FACT. The blob is stripped from the bundle's own reverifiable.json (it is
    # redundant with evidence-bundle.json) so the shipped report stays lean.
    signed = getattr(res, "signed", None)
    if signed is not None:
        try:
            entry["signed_certificate"] = signed.model_dump(mode="json")
        except Exception:  # noqa: BLE001 — a non-serializable cert is dropped; export re-mints deterministically
            pass
    doc = read_reverifiable(run_dir)
    findings = [f for f in doc["active_findings"] if f.get("check_id") != entry["check_id"]]
    findings.append(entry)
    findings.sort(key=lambda f: str(f.get("check_id")))
    path = _proofs_dir(run_dir) / REVERIFIABLE_NAME
    path.write_text(json.dumps({"active_findings": findings}, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ======================================================================================================
# S7 — the web-column VIGIL-owned live re-drive.
#
# A Strix finding is a PROPOSAL. For the web classes VIGIL can re-drive with its OWN crafted, gated probes
# (open_redirect / cors / host_header_injection), we do not adjudicate the bytes Strix recorded — we RE-SEND
# our own canary against the finding's endpoint through ``live.web_redrive`` and mint a signed FACT only
# over that fresh, VIGIL-produced capture (operator decision 2: LEAD until VIGIL re-drives into an already
# fact-capable branch; those web branches are already registered + fact-capable). This needs NO producer
# request bytes — web_redrive injects its own canary — so it is independent of the request-byte capture
# (invariant 8). The dominant auto-capture class (error_based_sqli) is NOT web-re-drivable and stays a LEAD
# on this path; its live re-drive is a separate slice.
# ======================================================================================================

# A TIGHT CWE allow-list — never a fuzzy "web" hint. Over-matching would re-drive an endpoint the finding
# did not implicate (worst case a wasted gated GET, since the oracle must still fire — but keep it precise).
_WEB_CWE_TO_CLASS = {
    "cwe-601": "open_redirect",       # URL redirection to untrusted site
    "cwe-942": "cors",                # permissive cross-domain policy
    "cwe-1385": "cors",               # missing origin validation in cross-origin resource sharing
    "cwe-644": "host_header_injection",  # improper neutralization of HTTP headers (Host)
}


def _web_redrive_class(report: dict) -> "str | None":
    """The ``web_redrive.WEB_FACT_CLASSES`` class this report maps to, or ``None``.

    Conservative by design: an EXACT ``bug_class`` / ``finding_class`` match, else a tight CWE allow-list.
    ``None`` ⇒ this report is not web-re-drivable — it falls through to the captured-bytes mint, or stays a
    LEAD. This is the SINGLE source of truth for "is this report web-re-drivable" (``sink._web_redrivable``
    calls it), so the sink gate and the mint path can never disagree about which reports take the web path."""
    if not hasattr(report, "get"):
        return None
    from ..live.web_redrive import WEB_FACT_CLASSES  # noqa: PLC0415 — import-clean tuple (FATAL-2 posture)
    for key in ("bug_class", "finding_class"):
        v = str(report.get(key) or "").strip().lower()
        if v in WEB_FACT_CLASSES:
            return v
    m = re.search(r"cwe-\d+", str(report.get("cwe") or "").strip().lower())
    if m and m.group(0) in _WEB_CWE_TO_CLASS:
        return _WEB_CWE_TO_CLASS[m.group(0)]
    return None


class _WebMintResult:
    """The mint callback's return for a web re-drive. The sink reads ONLY ``.is_fact``; the rest is retained
    for the persisted record. ``is_fact`` is True IFF VIGIL independently confirmed the CLAIMED class."""

    __slots__ = ("is_fact", "facts", "family_verdict")

    def __init__(self, *, is_fact: bool, facts: list, family_verdict: str) -> None:
        self.is_fact = is_fact
        self.facts = facts
        self.family_verdict = family_verdict


def _persist_web_redrive(run_dir: "str | os.PathLike", report: dict, wclass: str, wr: Any) -> None:
    """Best-effort record of a web re-drive for the Proof-Studio screen. Mirrors the proofs/ location of
    ``_persist_record``; a hiccup here must NEVER un-mint (the signed cert already exists in ``wr.facts``).
    Uniform C1/reverifiable export for web facts is a named residual, not this slice."""
    d = Path(run_dir) / "proofs"
    d.mkdir(parents=True, exist_ok=True)
    ref = str(_finding_from_report(report)["check_id"])
    rec = {
        "kind": "web_redrive",
        "finding_ref": ref,
        "claimed_class": wclass,
        "url": getattr(wr, "url", ""),
        "claimed_family_verdict": wr.family_verdict(wclass),
        "family_verdicts": wr.family_verdicts(),
        # The insertion surfaces each family was ACTUALLY examined on, so a persisted CLEAN names WHERE it
        # looked (query/path/cookie/urlencoded-body/JSON-body) rather than reading as an unbounded absence.
        "insertion_coverage": wr.family_coverage() if hasattr(wr, "family_coverage") else {},
        "coverage_statement": wr.coverage_statement(wclass) if hasattr(wr, "coverage_statement") else "",
        # The candidate redirect-parameter names probed on the synthesised cookie/body/JSON carriers — the
        # bound an open_redirect CLEAN over those surfaces is scoped to, machine-readable rather than prose.
        "probed_redirect_param_names": list(getattr(wr, "probed_redirect_param_names", []) or []),
        "n_facts": len(wr.facts),
        "fact_refs": [getattr(f, "finding_ref", "") for f in wr.facts],
        "refused": bool(getattr(wr, "refused", False)),
        "notes": list(getattr(wr, "notes", []) or []),
    }
    (d / f"webredrive-{hashlib.sha256(ref.encode('utf-8')).hexdigest()[:16]}.json").write_text(
        json.dumps(rec, indent=2, sort_keys=True), encoding="utf-8")


def _web_redrive_mint(report: dict, wclass: str, *, run_dir: "str | os.PathLike",
                      signers: "list[tuple[str, str]]", engagement_slug: str) -> "Any | None":
    """Re-drive the finding's ``endpoint`` with VIGIL's OWN gated web probes; return a result whose
    ``.is_fact`` is True ONLY when VIGIL independently confirmed the CLAIMED class over its own live capture.

    A missing endpoint, a gate refusal (out-of-scope / kill-switch / no ACTIVE_RECON), no established
    channel, or an oracle non-fire all yield ``is_fact=False`` → the finding stays a LEAD. web_redrive
    re-injects its OWN canary rather than the producer's exact value, so a vuln that only fires on a
    specific producer-supplied parameter value not present in ``endpoint`` reproduces as an honest
    LEAD/INCONCLUSIVE, never a CLEAN claim of safety. Never raises: any failure drops the mint to a LEAD."""
    url = str(report.get("endpoint") or "").strip()
    if not url:
        return None  # nothing to re-drive → LEAD
    try:
        from ..live.web_redrive import web_redrive  # noqa: PLC0415 — pulls framework at CALL time (offense)
        # ``engagement_slug`` is BOTH the gate-authorization slug and the certificate-binding slug: the
        # bootstrap provisions the run's authority under ``engagement_slug``, so the two scopes are identical
        # by construction (a future deployment needing distinct slugs is deferred).
        # Thread the CLAIMED class through: the oidc_redirect_uri branch is class-gated in web_redrive (its
        # predicate is identical to open_redirect, so it fires ONLY for a report that actually claims oidc —
        # never as a severity-upgrade of a plain open_redirect that merely has a redirect_uri param).
        wr = web_redrive(url, slug=engagement_slug, engagement_slug=engagement_slug, signers=signers,
                         claimed_class=wclass)
    except Exception as exc:  # noqa: BLE001 — a re-drive failure drops the mint (LEAD), never raises into Strix
        # inv 12 (S9): the VIGIL-owned re-drive EXECUTION raised (gateway down / network crash / framework
        # import error) — a re-drive we could not RUN, not a target we confirmed clean. Record the typed
        # cause so the console distinguishes it from a genuine non-confirmation (which returns None WITHOUT
        # raising below). Without this the swallow renders as disposition=nothing_found / clean=True.
        _record_degraded(run_dir, REDRIVE_FAILED, "proof.run._web_redrive_mint", exc)
        return None
    # Tie the mint to the CLAIM: FACT only if the class Strix claimed was independently confirmed. Sibling
    # web classes web_redrive also probes stay in ``wr.facts`` (signed, persisted) but do NOT relabel THIS
    # finding — that would attribute a certificate for class Y to a finding claiming class X.
    claimed = wr.family_verdict(wclass)
    try:
        _persist_web_redrive(run_dir, report, wclass, wr)
    except Exception:  # noqa: BLE001 — persistence is best-effort; a signed FACT is never un-minted
        pass
    return _WebMintResult(is_fact=(claimed == "FACT"), facts=list(wr.facts), family_verdict=claimed)


# ======================================================================================================
# W1a — the error-signature RE-DRIVE rail (the SOUND primary for a Strix injection finding).
#
# Today a Strix finding in an injection class persists only as a LEAD: Route A (``web_redrive``) covers the
# web classes, and the error-signature CAPTURE path below (``_vigil_capture``) is dormant because nothing
# attaches a capture. This rail is the runner-owned primary: given a Strix finding carrying {endpoint, param,
# claimed injection class}, VIGIL re-sends its OWN gated injection probe (the RUNNER crafts the probe — never
# the Strix/LLM value), fetches a benign CONTROL twin, and mints a signed FACT ONLY when the deterministic
# ``error_signature_oracle`` FIRES over VIGIL's FRESH bytes WITH the control present. The Strix report is
# never proof; the wire bytes are. The oracle OVERRIDES the Strix-claimed class with the datastore/parser
# ENGINE it actually matched (``_ERRSIG_ENGINE_TO_CLASS``), so the certificate names the vulnerability the
# EVIDENCE proves. Everything else -> LEAD (fail-closed).
#
# This is the GENERIC Strix->re-drive DISPATCH RAIL (``_REDRIVE_ARMS`` / ``_dispatch_redrive`` below): later
# waves plug xss/ssti/timing/OOB arms into the same rail — each a runner-owned re-drive that mints only over
# VIGIL's own gated capture + its oracle.
# ======================================================================================================

# The evidence branch this rail admits through (docs/capability-matrix/evidence-branches.json). fact_capable,
# clean_capable:false (POSITIVE-only — a missing error is uninformative). admit() applies its declared
# capability; certify_admitted re-fires the oracle over the reproduced context and mints only a FACT.
_ERRSIG_STRIX_BRANCH = "error_signature.strix_redrive"

# The four injection classes this rail re-drives. The certificate's FINAL class is decided by the oracle's
# matched engine (``_ERRSIG_ENGINE_TO_CLASS``), NOT by the value here — this only selects a class-appropriate
# runner probe and gates which findings the rail claims. A wrong claim simply fails to fire -> an honest LEAD.
_ERRSIG_REDRIVE_CLASSES = ("error_based_sqli", "nosqli", "ldap_injection", "xpath_injection")

# A TIGHT CWE allow-list (never a fuzzy hint) for a report that carries no explicit bug_class/finding_class.
_ERRSIG_CWE_TO_CLASS = {
    "cwe-89": "error_based_sqli",   # SQL injection
    "cwe-943": "nosqli",            # improper neutralization of special elements in data query logic (NoSQL)
    "cwe-90": "ldap_injection",     # LDAP injection
    "cwe-91": "xpath_injection",    # XML/XPath injection (XPath)
}

# Per-class RUNNER-crafted error-provoking probe payloads. The RUNNER owns these — never the Strix/LLM value —
# so a FACT rests on VIGIL's OWN injected metacharacters. Each is a minimal syntax-breaking token for the
# datastore/parser the class names; the ``error_signature_oracle`` (not the payload) decides whether an engine
# error was provoked, and the engine it matches OVERRIDES the claimed class. urlencode carries the metachars.
_ERRSIG_PROBE_PAYLOADS = {
    "error_based_sqli": "'\"",       # unbalanced quotes break a SQL string literal
    "nosqli": "'\"{[",               # break a JSON/BSON query document / operator parse
    "ldap_injection": "*)(|&",       # unbalanced LDAP filter parens/operators
    "xpath_injection": "']|//*[",    # break an XPath string/predicate
}


def _errsig_redrive_class(report: Any) -> "str | None":
    """The injection class this report maps to for the error-signature re-drive rail, or ``None``.

    Conservative by design: an EXACT ``bug_class`` / ``finding_class`` match (plus a few common aliases), else
    a tight CWE allow-list. ``None`` ⇒ this report is not errsig-re-drivable. This is the SINGLE source of
    truth (``sink._errsig_redrivable`` delegates here), so the sink gate and the dispatch rail can never
    disagree. Pure/stdlib (no framework import) so it is safe on the import-clean sink path (FATAL-2)."""
    if not hasattr(report, "get"):
        return None
    _aliases = {
        "sqli": "error_based_sqli", "sql_injection": "error_based_sqli", "sqli_error": "error_based_sqli",
        "nosql_injection": "nosqli", "nosql": "nosqli", "mongo_injection": "nosqli",
        "ldap": "ldap_injection", "ldap_inj": "ldap_injection",
        "xpath": "xpath_injection", "xpath_inj": "xpath_injection", "xpathi": "xpath_injection",
    }
    for key in ("bug_class", "finding_class"):
        v = str(report.get(key) or "").strip().lower()
        if v in _ERRSIG_REDRIVE_CLASSES:
            return v
        if v in _aliases:
            return _aliases[v]
    m = re.search(r"cwe-\d+", str(report.get("cwe") or "").strip().lower())
    if m and m.group(0) in _ERRSIG_CWE_TO_CLASS:
        return _ERRSIG_CWE_TO_CLASS[m.group(0)]
    return None


class _ErrsigMintResult:
    """The rail's return. The sink reads ONLY ``.is_fact``; the rest is retained for the persisted record and
    for tests (the signed cert + oracle_context that re-verify OFFLINE). ``is_fact`` is True IFF VIGIL's own
    gated re-drive + the oracle firing over a control twin minted a signed certificate."""

    __slots__ = ("is_fact", "result", "oracle_context", "engine", "engine_class", "claimed_class")

    def __init__(self, *, is_fact: bool, result: Any, oracle_context: "dict | None",
                 engine: str, engine_class: str, claimed_class: str) -> None:
        self.is_fact = is_fact
        self.result = result                 # the AdapterResult (carries .signed on a FACT)
        self.oracle_context = oracle_context  # the reproduced context the FACT re-verifies over
        self.engine = engine
        self.engine_class = engine_class
        self.claimed_class = claimed_class


def _persist_errsig_redrive(run_dir: "str | os.PathLike", report: dict, claimed_class: str,
                            engine: str, engine_class: str, res: Any) -> None:
    """Best-effort record of an error-signature re-drive for the Proof-Studio screen. Mirrors the proofs/
    location of the web record; a hiccup here must NEVER un-mint (the signed cert already exists on ``res``)."""
    d = Path(run_dir) / PROOFS_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    ref = str(_finding_from_report(report)["check_id"])
    rec = {
        "kind": "strix_errsig_redrive",
        "finding_ref": ref,
        "claimed_class": claimed_class,          # the Strix-proposed class (NOT what the FACT is minted under)
        "matched_engine": engine,                # the datastore/parser engine the oracle matched
        "engine_class": engine_class,            # the ORACLE-AUTHORITATIVE class the certificate names
        "status": str(getattr(res, "status", "")),
        "is_fact": bool(getattr(res, "is_fact", False)),
        "reason": str(getattr(res, "reason", "")),
        "confirmed_by": str(getattr(res, "confirmed_by", "")),
        "confidence": float(getattr(res, "confidence", 0.0) or 0.0),
    }
    (d / f"strixerrsig-{hashlib.sha256(ref.encode('utf-8')).hexdigest()[:16]}.json").write_text(
        json.dumps(rec, indent=2, sort_keys=True), encoding="utf-8")


def _strix_errsig_redrive(report: dict, eclass: str, *, run_dir: "str | os.PathLike",
                          signers: "list[tuple[str, str]]", engagement_slug: str,
                          control_fetch: "Optional[Callable[[dict], bytes | None]]") -> "Any | None":
    """Re-drive a Strix injection finding with VIGIL's OWN gated probe and mint a signed FACT ONLY when the
    deterministic ``error_signature_oracle`` fires over VIGIL's fresh bytes WITH a benign control twin present.

    Soundness (the invariants this slice rests on):
      * The Strix report is NEVER proof. The RUNNER crafts the probe (``_ERRSIG_PROBE_PAYLOADS``); the
        Strix/LLM ``payload`` is never trusted. Only VIGIL's own gated re-drive + the oracle mint.
      * The probe goes through the SAME charter-gated, DNS-pinned, proxy-free, bounded transport the web
        re-drive uses (``web_redrive._gated_web_send``) — no new egress, the never-liftable floor unchanged.
      * A benign CONTROL twin is REQUIRED (via the ``control_fetch`` seam). Without it the oracle's
        control-comparison guard is dead code (an always-erroring page would mint), so a control that cannot
        be captured REFUSES to a LEAD (fail-closed).
      * The oracle OVERRIDES the Strix-claimed class with the ENGINE it matched (``_ERRSIG_ENGINE_TO_CLASS``);
        a fired-but-unmapped engine REFUSES (never the producer's claim).

    A missing endpoint/param, a gate refusal / no channel, no control, an oracle non-fire, or an unmapped
    engine all yield a non-FACT ⇒ the finding stays a LEAD. NEVER raises: any failure drops the mint to a
    LEAD. FATAL-2: every framework-touching import is function-local (offense-side re-drive path)."""
    url = str((report or {}).get("endpoint") or "").strip()
    param = str((report or {}).get("param") or (report or {}).get("insertion_point") or "").strip()
    payload = _ERRSIG_PROBE_PAYLOADS.get(eclass)
    if not (url and param and payload):
        return None    # nothing to re-drive / no runner probe for this class → LEAD

    try:
        from urllib.parse import urlencode, urlsplit               # stdlib
        from framework.v2.evidence.poc import CapturedExchange     # lazy — FATAL-2 (offense plane)
        from framework.v2.scanner.insertion import HttpRequest     # lazy — FATAL-2
        from framework.v2.verify.oracles import error_signature_oracle  # lazy — FATAL-2
        from framework.v2.verify.poc_translate import context_from_exchanges  # lazy — FATAL-2

        from ..live.verdict import admit                           # stdlib-only admission (registry-governed)
        from ..live.web_redrive import _gated_web_send             # pulls framework only at CALL time
        from ..oracle_adapter import certify_admitted              # lazy framework at call (offense)
    except Exception as exc:  # noqa: BLE001 — cannot even import the re-drive machinery → LEAD (fail-closed)
        _record_degraded(run_dir, REDRIVE_FAILED, "proof.run._strix_errsig_redrive.import", exc)
        return None

    # RUNNER-crafted, DETERMINISTIC probe (a content-address nonce — no wallclock/rng). The injectable param
    # carries the runner's error-provoking payload; a separate benign nonce param rides alongside (parity with
    # the LiveHttpAdapter sqli spec live/engine.py builds). The control twin is the SAME endpoint+param with a
    # benign, metacharacter-free value — so any datastore error is attributable to the payload, not the param.
    sp = urlsplit(url if "://" in url else "http://" + url)
    if not sp.hostname:
        return None
    base_url = f"{(sp.scheme or 'http')}://{sp.netloc}"
    endpoint_path = "/" + (sp.path or "/").lstrip("/")
    nonce = hashlib.sha256(f"{base_url}{endpoint_path}:{param}:{eclass}".encode("utf-8")).hexdigest()[:16]
    benign = "vfctl" + nonce
    nonce_param = "rc" if param != "rc" else "rcx"   # never collide with the injectable param

    def _q(value: str) -> str:
        return urlencode(sorted({param: value, nonce_param: nonce}.items()))

    exploit_url = f"{base_url}{endpoint_path}?{_q(payload)}"
    control_url = f"{base_url}{endpoint_path}?{_q(benign)}"

    # (1) VIGIL's OWN gated injection probe (charter gate → DNS-pin → empty ProxyHandler → bounded read).
    try:
        send, state = _gated_web_send(engagement_slug)
        resp = send(HttpRequest(method="GET", url=exploit_url))
    except Exception as exc:  # noqa: BLE001 — a transport/import crash is a re-drive we could not RUN → LEAD
        _record_degraded(run_dir, REDRIVE_FAILED, "proof.run._strix_errsig_redrive.probe", exc)
        return None
    if int(state.get("channels", 0) or 0) <= 0:
        return None    # gate refusal (out-of-scope / kill-switch) or transport error → NO channel → LEAD
    observed_body = resp.get("body")
    if not (isinstance(observed_body, str) and observed_body):
        return None    # a real channel but no readable body → the oracle cannot fire → LEAD

    # (2) VIGIL-owned benign CONTROL twin via the bootstrap seam. A control that cannot be captured REFUSES to
    #     a LEAD (fail-closed) — the oracle's control-comparison guard MUST be live.
    control_body = _fetch_control({**report, "endpoint": control_url}, control_fetch)
    if not control_body:
        if control_fetch is not None:
            record_degradation(run_dir, REDRIVE_FAILED,
                               where="proof.run._strix_errsig_redrive.control_unavailable",
                               detail="benign control twin fetch established no channel")
        return None

    # (3) the deterministic error-signature oracle over VIGIL's FRESH bytes, WITH the control twin.
    observed_bytes = observed_body.encode("utf-8", errors="replace")
    sig = error_signature_oracle(observed_bytes, control_body)
    if not getattr(sig, "fired", False):
        return None    # no engine error, or the SAME error is in the benign control → not attributable → LEAD
    engine = str((getattr(sig, "observed", None) or {}).get("engine", ""))
    engine_class = _ERRSIG_ENGINE_TO_CLASS.get(engine)
    if not engine_class:
        # FAIL-CLOSED: fired on a datastore/parser engine we cannot honestly name — REFUSE rather than fall
        # back to the producer's (launderable) claimed class. Recorded so the run can never read CLEAN over a
        # fired-but-unlabelable datastore error.
        record_degradation(run_dir, MINT_FAILED, where="proof.run._strix_errsig_redrive.unmapped_engine",
                           detail=engine)
        return None

    # (4) mint through ADMISSION over VIGIL's own capture (provenance=live_redrive). The ENGINE the oracle
    #     matched is the certificate's class — the Strix-claimed class is OVERRIDDEN at the source, so context,
    #     certify, and offline reverify are all consistent and no path can rename the class the evidence proves.
    blobs = {"errsig_obs_resp": observed_bytes, "errsig_ctrl_resp": bytes(control_body)}

    def _resolve(ref: str) -> "bytes | None":
        return blobs.get(ref)

    ex_dicts = [
        {"channel": "error_signature", "role": "mutated", "response_bytes_ref": "errsig_obs_resp",
         "status": resp.get("status")},
        {"channel": "error_signature", "role": "control", "response_bytes_ref": "errsig_ctrl_resp",
         "status": None},
    ]
    try:
        exchanges = [CapturedExchange(**d) for d in ex_dicts]
    except Exception as exc:  # noqa: BLE001 — a malformed capture drops the mint (LEAD), never raises
        _record_degraded(run_dir, CAPTURE_FAILED, "proof.run._strix_errsig_redrive.capture", exc)
        return None
    ctx = context_from_exchanges(exchanges, bug_class=engine_class, resolve=_resolve)
    if ctx is None:
        return None
    oracle_context = ctx.model_dump(mode="json")
    finding = {
        "check_id": _finding_from_report(report)["check_id"],
        "bug_class": engine_class,
        "insertion_point": param,
        "oracle_context": oracle_context,
    }
    action_id = "poc-" + hashlib.sha256(str(finding["check_id"]).encode("utf-8")).hexdigest()[:16]
    try:
        # A fire is decisive; the branch precondition (a real channel) held above. certify_admitted re-fires
        # the SAME oracle over the reproduced context and mints ONLY a FACT (provenance=live_redrive).
        admitted = admit(_ERRSIG_STRIX_BRANCH, fired=True, conclusive=True,
                         observed={"channel_established": True})
        res = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                               provenance="live_redrive")
    except Exception as exc:  # noqa: BLE001 — an admission/cert error confirms nothing (fail-closed) → LEAD
        _record_degraded(run_dir, MINT_FAILED, "proof.run._strix_errsig_redrive.mint", exc)
        return None

    try:
        _persist_errsig_redrive(run_dir, report, eclass, engine, engine_class, res)
    except Exception:  # noqa: BLE001 — persistence is best-effort; a signed FACT is never un-minted
        pass
    if getattr(res, "is_fact", False):
        # Retain the re-verifiable material (oracle_context + action_id + signed cert) so the run's dossier
        # ships the offline-verifiable bundle and `framework.v2 verify` re-fires it byte-identically.
        try:
            _persist_reverifiable(run_dir, finding, action_id, exchanges, _resolve, res)
        except Exception:  # noqa: BLE001
            pass
    return _ErrsigMintResult(is_fact=bool(getattr(res, "is_fact", False)), result=res,
                             oracle_context=oracle_context, engine=engine, engine_class=engine_class,
                             claimed_class=eclass)


def _web_redrive_arm(report: dict, wclass: str, *, run_dir: "str | os.PathLike",
                     signers: "list[tuple[str, str]]", engagement_slug: str,
                     control_fetch: "Optional[Callable[[dict], bytes | None]]" = None) -> "Any | None":
    """Rail adapter for Route A: the web re-drive needs no control_fetch (it injects its own canary), so this
    thin wrapper gives it the uniform arm signature the dispatch rail calls."""
    return _web_redrive_mint(report, wclass, run_dir=run_dir, signers=signers,
                             engagement_slug=engagement_slug)


# ======================================================================================================
# W2 — four more runner-owned re-drive arms over HTTP-response-derived oracles (no browser, no OOB):
#   reflected xss (reflection_context), ssti (evaluation), boolean_sqli (boolean_inference/SPRT),
#   time_based_sqli (timing). Each is a runner-owned gated re-drive whose FACT rests ONLY on VIGIL's OWN
#   crafted probe + its deterministic oracle (the Strix report is never proof). The three statistical/eval
#   arms live in ``live.runtime_redrive`` (siblings of ``runtime_redrive``); xss reuses the EXISTING
#   ``runtime_redrive(claimed_class="xss")`` reflection arm. All four persist an offline-re-verifiable entry.
#
# CLASS-SET DISJOINTNESS (W1a red-pen note, pinned by test_redrive_arm_class_sets_are_disjoint): each arm's
# class set + CWE map is PAIRWISE DISJOINT from every other arm's (web / errsig / xss / ssti / boolean /
# timing), so arm ORDER can never route a report to the wrong arm. The classifiers are PURE/stdlib (no
# framework import) so they are safe on the import-clean sink path (FATAL-2), mirroring ``_errsig_redrive_class``.
# ======================================================================================================

# reflected XSS (CWE-79). NOT stored/dom xss (those are DOM_EXECUTION classes, a separate arm).
_REFLECTION_REDRIVE_CLASSES = frozenset({"xss"})
_REFLECTION_ALIASES = {"reflected_xss": "xss", "cross_site_scripting": "xss",
                       "reflected_cross_site_scripting": "xss", "reflected_xss_injection": "xss"}
_REFLECTION_CWE_TO_CLASS = {"cwe-79": "xss"}

# SSTI / expression-language evaluation.
_SSTI_REDRIVE_CLASSES = frozenset({"ssti"})
_SSTI_ALIASES = {"server_side_template_injection": "ssti", "template_injection": "ssti",
                 "ssti_injection": "ssti"}
_SSTI_CWE_TO_CLASS = {"cwe-1336": "ssti"}

# Boolean-blind SQLi. Kept to boolean_sqli ALONE: nosqli/ldap/xpath belong to the errsig arm (disjointness),
# and boolean-blind SQLi shares CWE-89 with error_based_sqli, so this arm carries NO CWE map (a bare CWE-89
# routes to the errsig arm; a genuinely-boolean finding that leaks no datastore error simply re-drives there
# and stays a LEAD — the oracle, not the label, decides). Keyed on an EXPLICIT boolean class only.
_BOOLEAN_REDRIVE_CLASSES = frozenset({"boolean_sqli"})
_BOOLEAN_ALIASES = {"blind_sqli": "boolean_sqli", "boolean_based_sqli": "boolean_sqli",
                    "boolean_blind_sqli": "boolean_sqli"}
_BOOLEAN_CWE_TO_CLASS: "dict[str, str]" = {}

# Time-based blind SQLi. Same CWE-89 collision as boolean → NO CWE map; keyed on an EXPLICIT time-based class.
_TIMING_REDRIVE_CLASSES = frozenset({"time_based_sqli"})
_TIMING_ALIASES = {"time_sqli": "time_based_sqli", "time_based_blind_sqli": "time_based_sqli",
                   "blind_time_sqli": "time_based_sqli", "time_based_blind_sql_injection": "time_based_sqli"}
_TIMING_CWE_TO_CLASS: "dict[str, str]" = {}


def _classify_redrive(report: Any, classes: "frozenset[str]", aliases: "dict[str, str]",
                      cwe_map: "dict[str, str]") -> "str | None":
    """Shared PURE classifier for the W2 arms: an EXACT ``bug_class``/``finding_class`` match (or a spelling
    alias), else a tight CWE allow-list. ``None`` ⇒ this arm does not claim the report. Stdlib only (no
    framework import) so it is safe on the import-clean sink path (FATAL-2), exactly like
    ``_errsig_redrive_class``."""
    if not hasattr(report, "get"):
        return None
    for key in ("bug_class", "finding_class"):
        v = str(report.get(key) or "").strip().lower()
        if v in classes:
            return v
        if v in aliases:
            return aliases[v]
    m = re.search(r"cwe-\d+", str(report.get("cwe") or "").strip().lower())
    if m and m.group(0) in cwe_map:
        return cwe_map[m.group(0)]
    return None


def _reflection_redrive_class(report: Any) -> "str | None":
    """The reflected-xss class this report maps to (``"xss"``), or ``None``. SINGLE source of truth
    (``sink._reflection_redrivable`` delegates here)."""
    return _classify_redrive(report, _REFLECTION_REDRIVE_CLASSES, _REFLECTION_ALIASES, _REFLECTION_CWE_TO_CLASS)


def _ssti_redrive_class(report: Any) -> "str | None":
    """The SSTI class this report maps to (``"ssti"``), or ``None``. SINGLE source of truth
    (``sink._ssti_redrivable`` delegates here)."""
    return _classify_redrive(report, _SSTI_REDRIVE_CLASSES, _SSTI_ALIASES, _SSTI_CWE_TO_CLASS)


def _boolean_redrive_class(report: Any) -> "str | None":
    """The boolean-blind SQLi class this report maps to (``"boolean_sqli"``), or ``None``. SINGLE source of
    truth (``sink._boolean_redrivable`` delegates here)."""
    return _classify_redrive(report, _BOOLEAN_REDRIVE_CLASSES, _BOOLEAN_ALIASES, _BOOLEAN_CWE_TO_CLASS)


def _timing_redrive_class(report: Any) -> "str | None":
    """The time-based blind SQLi class this report maps to (``"time_based_sqli"``), or ``None``. SINGLE source
    of truth (``sink._timing_redrivable`` delegates here)."""
    return _classify_redrive(report, _TIMING_REDRIVE_CLASSES, _TIMING_ALIASES, _TIMING_CWE_TO_CLASS)


class _RuntimeMintResult:
    """The mint callback's return for a W2 runtime/statistical re-drive arm. The sink reads ONLY ``.is_fact``;
    ``.result`` (the :class:`live.runtime_redrive.RuntimeRedriveResult`) is retained for the persisted record
    and for tests (its ``.facts`` carry the signed certs + ``.contexts`` the oracle_contexts that re-verify
    OFFLINE). Deliberately has NO ``engine_class`` (errsig) / ``reproduced`` (capture) attribute, so a
    capture-bearing report still takes the executor-capture path (pinned by test)."""

    __slots__ = ("is_fact", "result")

    def __init__(self, *, is_fact: bool, result: Any) -> None:
        self.is_fact = is_fact
        self.result = result


def _persist_runtime_redrive(run_dir: "str | os.PathLike", report: dict, res: Any) -> None:
    """Best-effort Proof-Studio record of a W2 runtime re-drive (mirrors ``_persist_web_redrive``). A hiccup
    here must NEVER un-mint — the signed cert already exists in ``res.facts``."""
    d = Path(run_dir) / PROOFS_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    ref = str(_finding_from_report(report)["check_id"])
    rec = {
        "kind": "runtime_redrive",
        "finding_ref": ref,
        "bug_class": str(getattr(res, "bug_class", "") or ""),
        "url": str(getattr(res, "url", "") or ""),
        "n_facts": int(getattr(res, "n_facts", 0) or 0),
        "fact_refs": [getattr(f, "finding_ref", "") for f in getattr(res, "facts", []) or []],
        "family_verdict": res.family_verdict(str(getattr(res, "bug_class", "") or ""))
        if hasattr(res, "family_verdict") else "",
        "refused": bool(getattr(res, "refused", False)),
        "inconclusive": [list(x) for x in (getattr(res, "inconclusive", []) or [])],
        "notes": list(getattr(res, "notes", []) or []),
    }
    (d / f"runtimeredrive-{hashlib.sha256(ref.encode('utf-8')).hexdigest()[:16]}.json").write_text(
        json.dumps(rec, indent=2, sort_keys=True), encoding="utf-8")


def _persist_runtime_reverifiable(run_dir: "str | os.PathLike", res: Any) -> None:
    """Append (dedup by check_id) each of a runtime re-drive's signed FACTs to the run's re-verifiable report,
    storing the SAME JSON-safe ``oracle_context`` the FACT was minted over (from ``res.contexts``) DIRECTLY —
    the boolean/timing SPRT/latency contexts are not reconstructable via ``context_from_exchanges``, so unlike
    ``_persist_reverifiable`` this stores the retained context as-is. ``framework.v2 verify`` re-fires it
    byte-identically (``FindingContext.model_validate`` round-trips the ``to_verifier_context`` shape)."""
    facts = list(getattr(res, "facts", []) or [])
    contexts = dict(getattr(res, "contexts", {}) or {})
    if not facts:
        return
    doc = read_reverifiable(run_dir)
    by_id = {str(f.get("check_id")): f for f in doc["active_findings"] if isinstance(f, dict)}
    for fact in facts:
        ref = str(getattr(fact, "finding_ref", "") or "")
        ctx = contexts.get(ref)
        if not ref or not ctx:
            continue
        entry = {
            "check_id": ref,
            "bug_class": str(getattr(fact, "bug_class", "") or getattr(res, "bug_class", "") or ""),
            # the ORACLE FAMILY this FACT was confirmed on (the remediation re-drive pins to it).
            "channel": str(getattr(fact, "confirmed_by", "") or ""),
            "insertion_point": "",
            "confirmed_by": str(getattr(fact, "confirmed_by", "") or ""),
            "confidence": float(getattr(fact, "confidence", 0.0) or 0.0),
            "action_id": "poc-" + hashlib.sha256(ref.encode("utf-8")).hexdigest()[:16],
            "oracle_context": ctx,
        }
        signed = getattr(fact, "signed", None)
        if signed is not None:
            try:
                entry["signed_certificate"] = signed.model_dump(mode="json")
            except Exception:  # noqa: BLE001 — a non-serializable cert is dropped; reverify re-fires the ctx
                pass
        by_id[ref] = entry
    findings = sorted(by_id.values(), key=lambda f: str(f.get("check_id")))
    path = _proofs_dir(run_dir) / REVERIFIABLE_NAME
    path.write_text(json.dumps({"active_findings": findings}, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _finish_runtime_arm(report: dict, res: Any, *, run_dir: "str | os.PathLike") -> "Any | None":
    """Persist a runtime re-drive result (Proof-Studio record + offline-reverifiable FACTs) and wrap it as a
    ``_RuntimeMintResult``. Persistence is best-effort: a signed FACT is never un-minted by a persist hiccup."""
    if res is None:
        return None
    try:
        _persist_runtime_redrive(run_dir, report, res)
    except Exception:  # noqa: BLE001 — persistence is best-effort
        pass
    if int(getattr(res, "n_facts", 0) or 0) > 0:
        try:
            _persist_runtime_reverifiable(run_dir, res)
        except Exception:  # noqa: BLE001
            pass
    return _RuntimeMintResult(is_fact=int(getattr(res, "n_facts", 0) or 0) > 0, result=res)


def _reflection_redrive(report: dict, cls: str, *, run_dir: "str | os.PathLike",
                        signers: "list[tuple[str, str]]", engagement_slug: str,
                        control_fetch: "Optional[Callable[[dict], bytes | None]]" = None) -> "Any | None":
    """Rail adapter for reflected XSS: re-drive the finding's ``endpoint`` through the EXISTING
    ``runtime_redrive(claimed_class="xss")`` reflection arm; a FACT is minted ONLY when the reflection_context
    oracle reports the ``html_tag`` breakout over VIGIL's own gated capture. No control_fetch (the arm crafts
    its own canary). A missing endpoint / gate refusal / non-fire ⇒ LEAD. Never raises."""
    url = str((report or {}).get("endpoint") or "").strip()
    if not url:
        return None
    try:
        from ..live.runtime_redrive import runtime_redrive  # noqa: PLC0415 — pulls framework at CALL time
        res = runtime_redrive(url, slug=engagement_slug, engagement_slug=engagement_slug, signers=signers,
                              claimed_class="xss")
    except Exception as exc:  # noqa: BLE001 — a re-drive we could not RUN → LEAD (never a false CLEAN)
        _record_degraded(run_dir, REDRIVE_FAILED, "proof.run._reflection_redrive", exc)
        return None
    return _finish_runtime_arm(report, res, run_dir=run_dir)


def _stat_redrive_arm(report: dict, fn_name: str, where: str, *, run_dir: "str | os.PathLike",
                      signers: "list[tuple[str, str]]", engagement_slug: str) -> "Any | None":
    """Shared adapter for the three statistical/eval W2 arms (ssti / boolean / timing): extract
    {endpoint, param} from the report and drive the named ``live.runtime_redrive`` function with VIGIL's OWN
    gated probes. A missing endpoint / gate refusal / oracle non-fire ⇒ LEAD. Never raises."""
    url = str((report or {}).get("endpoint") or "").strip()
    if not url:
        return None
    param = (str((report or {}).get("param") or (report or {}).get("insertion_point") or "").strip()
             or None)
    try:
        from ..live import runtime_redrive as _rr  # noqa: PLC0415 — pulls framework at CALL time (offense)
        fn = getattr(_rr, fn_name)
        res = fn(url, slug=engagement_slug, engagement_slug=engagement_slug, signers=signers, param=param)
    except Exception as exc:  # noqa: BLE001 — a re-drive we could not RUN → LEAD (never a false CLEAN)
        _record_degraded(run_dir, REDRIVE_FAILED, where, exc)
        return None
    return _finish_runtime_arm(report, res, run_dir=run_dir)


def _ssti_redrive(report: dict, cls: str, *, run_dir: "str | os.PathLike",
                  signers: "list[tuple[str, str]]", engagement_slug: str,
                  control_fetch: "Optional[Callable[[dict], bytes | None]]" = None) -> "Any | None":
    """Rail adapter for SSTI: mint ONLY when the evaluation oracle confirms the server EVALUATED a
    runner-injected per-probe product (raw absent, control lacks it)."""
    return _stat_redrive_arm(report, "ssti_redrive", "proof.run._ssti_redrive",
                             run_dir=run_dir, signers=signers, engagement_slug=engagement_slug)


def _boolean_redrive(report: dict, cls: str, *, run_dir: "str | os.PathLike",
                     signers: "list[tuple[str, str]]", engagement_slug: str,
                     control_fetch: "Optional[Callable[[dict], bytes | None]]" = None) -> "Any | None":
    """Rail adapter for boolean-blind SQLi: mint ONLY when the boolean_inference SPRT confirms over
    runner-crafted true/false probe pairs with the within-pair dynamic-page control."""
    return _stat_redrive_arm(report, "boolean_redrive", "proof.run._boolean_redrive",
                             run_dir=run_dir, signers=signers, engagement_slug=engagement_slug)


def _timing_redrive(report: dict, cls: str, *, run_dir: "str | os.PathLike",
                    signers: "list[tuple[str, str]]", engagement_slug: str,
                    control_fetch: "Optional[Callable[[dict], bytes | None]]" = None) -> "Any | None":
    """Rail adapter for time-based blind SQLi: mint ONLY when the timing oracle confirms a delay by
    Mann-Whitney U + effect-size floor + dose-response over runner-crafted SLEEP probes."""
    return _stat_redrive_arm(report, "timing_redrive", "proof.run._timing_redrive",
                             run_dir=run_dir, signers=signers, engagement_slug=engagement_slug)


# The GENERIC Strix→re-drive dispatch rail. Each ARM is ``(classify, drive, requires_no_capture)``: the
# classifier maps a Strix report to the class it can re-drive (or None), and the driver re-sends VIGIL's OWN
# gated probe and mints ONLY over VIGIL's fresh capture + its oracle (never the Strix report). Arms are tried
# in order; the FIRST that claims the report owns it. ``requires_no_capture`` keeps a capture-bearing report
# on the executor-capture mint path below (the web arm intercepts either way — web classes are disjoint from
# injection classes). Every arm's class set is PAIRWISE DISJOINT (test_redrive_arm_class_sets_are_disjoint),
# so arm ORDER can never route a report to the wrong arm. Adding an arm = append ONE tuple here + one
# ``or _<x>_redrivable(report)`` clause in sink.py + a classifier + a driver.
_REDRIVE_ARMS = (
    (_web_redrive_class, _web_redrive_arm, False),
    (_errsig_redrive_class, _strix_errsig_redrive, True),
    (_reflection_redrive_class, _reflection_redrive, True),
    (_ssti_redrive_class, _ssti_redrive, True),
    (_boolean_redrive_class, _boolean_redrive, True),
    (_timing_redrive_class, _timing_redrive, True),
)


def _dispatch_redrive(report: dict, *, run_dir: "str | os.PathLike", signers: "list[tuple[str, str]]",
                      engagement_slug: str,
                      control_fetch: "Optional[Callable[[dict], bytes | None]]") -> "tuple[bool, Any]":
    """Try each re-drive arm in order. Returns ``(handled, result)``: ``handled=True`` means an arm owned the
    report (its result — a FACT/None — is authoritative); ``handled=False`` means fall through to the
    executor-capture mint / LEAD. A capture-bearing report is left for the capture path (``requires_no_capture``)."""
    if not hasattr(report, "get"):
        return False, None
    has_capture = report.get(CAPTURE_KEY) is not None
    for classify, drive, requires_no_capture in _REDRIVE_ARMS:
        if requires_no_capture and has_capture:
            continue
        cls = classify(report)
        if cls is not None:
            return True, drive(report, cls, run_dir=run_dir, signers=signers,
                               engagement_slug=engagement_slug, control_fetch=control_fetch)
    return False, None


# _benign_twin_url None-reasons (objection-4 honest telemetry): the two distinct causes a twin cannot be
# derived, so the caller's degradation detail states the TRUE reason rather than always "no host+path".
_TWIN_NO_HOSTPATH = "no_host_path"              # the observed request yields no derivable host+path at all
_TWIN_UNCONFIRMED_SCHEME = "unconfirmed_scheme"  # host+path derived, but the transport scheme is unconfirmed


def _benign_twin_url(request_bytes: "bytes | None",
                     observed_scheme: "str | None" = None) -> "tuple[str | None, str | None]":
    """Derive the benign CONTROL url from the OBSERVED exchange's OWN captured request — its request-target
    (host+path) with the query/payload STRIPPED, over the OBSERVED exchange's OWN transport SCHEME — so the
    control is the benign twin of the exact exchange the error-signature oracle adjudicates, fetched the same
    way (http vs https).

    Neither the twin's host+path NOR its scheme is taken from the free-text ``report['endpoint']`` on trust:
    nothing binds that field to the observed request line, so an observed always-erroring ``/api/search?q='``
    paired with ``endpoint='/'`` (host+path mismatch) — or with a wrong-scheme endpoint — would otherwise
    fetch a DIFFERENT page / a DIFFERENT transport whose error is absent and mint a FALSE FACT (BLOCK-2, and
    the scheme residual).

    Scheme resolution — the twin scheme is the transport GROUND TRUTH of how the observed response was
    obtained, and ONLY that ground truth may CONFIRM it (the in-band request-target scheme and the free-text
    endpoint scheme are NOT trusted to confirm a scheme on their own — neither is bound to the transport the
    response actually came back over):
      * if ``observed_scheme`` (the transport TLS flag recorded on the capture) is ``http`` or ``https``,
        it is AUTHORITATIVE — use it, even when an absolute-form request-target carries a DIFFERENT in-band
        scheme (objection-3: a proxied ``GET http://h/p`` observed over TLS is an https exchange);
      * else the scheme cannot be CONFIRMED for this exchange → refuse (``(None, unconfirmed_scheme)``) so the
        caller REFUSES the control (⇒ LEAD). A wrong scheme does NOT merely fail the fetch: if the target
        serves DIVERGENT content on http vs https for this path (clean http, erroring https), a defaulted- or
        guessed-http control would be clean while the observed https page errors — minting a FALSE FACT on an
        always-erroring page. In production a Caido capture always carries the TLS flag, so this only refuses
        hand-crafted captures that omit it — which is correct: an unconfirmable scheme is not a proof.

    The absolute-form request-target still supplies the twin's AUTHORITY + PATH (WHERE), just never the
    SCHEME (HOW). Returns ``(url, None)`` on success; ``(None, reason)`` when no twin can be derived, where
    ``reason`` is ``_TWIN_NO_HOSTPATH`` (the request yields no host+path) or ``_TWIN_UNCONFIRMED_SCHEME``
    (host+path derived but the transport scheme is unconfirmed) so the caller reports the true cause. NEVER
    raises."""
    from urllib.parse import urlsplit  # noqa: PLC0415 — stdlib
    try:
        if not request_bytes:
            return None, _TWIN_NO_HOSTPATH
        head = bytes(request_bytes).split(b"\r\n\r\n", 1)[0]
        lines = [ln for ln in head.split(b"\r\n") if ln.strip()]
        if not lines:
            return None, _TWIN_NO_HOSTPATH
        toks = lines[0].split()
        if len(toks) < 2:
            return None, _TWIN_NO_HOSTPATH
        target = toks[1].decode("latin-1", "replace")
        if "://" in target:                                  # absolute-form target carries its own authority + path
            sp = urlsplit(target)
            authority, path = sp.netloc, (sp.path or "/")    # scheme deliberately IGNORED — see docstring
        else:                                                # origin-form: path here, host from the Host header
            path = urlsplit(target).path or "/"
            authority = ""
            for ln in lines[1:]:
                if ln.lower().startswith(b"host:"):
                    authority = ln.split(b":", 1)[1].strip().decode("latin-1", "replace")
                    break
        if not authority:                                    # no derivable host+path ⇒ no twin (LEAD)
            return None, _TWIN_NO_HOSTPATH
        # The transport TLS flag is the SOLE authority for the scheme; absent/invalid ⇒ refuse (LEAD).
        scheme = observed_scheme if observed_scheme in ("http", "https") else None
        if scheme is None:
            return None, _TWIN_UNCONFIRMED_SCHEME
        return f"{scheme}://{authority}{path}", None         # query/payload stripped — a benign GET of the twin
    except Exception:  # noqa: BLE001 — an unparseable request ⇒ no derivable twin ⇒ LEAD; never raises
        return None, _TWIN_NO_HOSTPATH


def _fetch_control(report: dict, control_fetch: "Optional[Callable[[dict], bytes | None]]") -> "bytes | None":
    """Perform ONE VIGIL-owned benign CONTROL fetch for ``report`` — a second, benign fetch of the same
    endpoint (no payload/canary) whose response bytes are what the error-signature oracle compares the
    exploit response against. The caller pins ``report['endpoint']`` to the benign twin of the OBSERVED
    exchange (``_benign_twin_url``) BEFORE calling this, so the fetch is paired to the exchange the oracle
    adjudicates, never a free-text endpoint. Returns the control bytes, or ``None`` when no fetcher is wired
    or the fetch captured no channel. NEVER raises: a control we could not fetch degrades to a LEAD, it never
    crashes the mint (a raising fetcher must not become a false CLEAN)."""
    if control_fetch is None:
        return None
    try:
        b = control_fetch(report)
    except Exception:  # noqa: BLE001 — a control-fetch failure ⇒ no control (LEAD), never raises into the mint
        return None
    if isinstance(b, (bytes, bytearray)):
        return bytes(b) or None
    if isinstance(b, str):
        return b.encode("utf-8") or None
    return None


def build_report_mint(
    *,
    run_dir: str | os.PathLike,
    signers: "list[tuple[str, str]]",
    engagement_slug: str,
    evidence_root: Optional[str | os.PathLike] = None,
    spool_dir: Optional[str | os.PathLike] = None,
    quarantine_dir: Optional[str] = None,
    control_fetch: "Optional[Callable[[dict], bytes | None]]" = None,
) -> Callable[[dict], Any]:
    """Return the ``mint(report)`` callback for ``proof.sink``. It mints ONLY from the report's attached
    executor capture (``_vigil_capture``), persists a proof record, and returns the ``MintResult`` (or
    ``None`` if the capture is unusable — the finding then stays a plain Strix report / LEAD).

    ``control_fetch`` is the CONTROL-exchange seam (S6): a callable ``(report) -> bytes | None`` that performs
    a benign fetch of the OBSERVED exchange's own twin (host+path, payload stripped — the mint pins
    ``report['endpoint']`` to that twin via ``_benign_twin_url`` before calling, never a free-text endpoint;
    BLOCK-2) so the error-signature oracle's control-comparison guard is LIVE (see the mint body). When a
    capture already carries an executor ``role="control"`` exchange that is used directly and ``control_fetch``
    is not called. When it is ``None`` and no executor control is present, an error-signature capture cannot be
    attributed and stays a LEAD — the mint never invents a control.

    HONESTY / scope of the guarantee: the "an always-erroring page cannot mint" property holds for the
    VIGIL-FETCHED-control path (``control_fetch``), whose control VIGIL itself captures, pins to the observed
    twin, and refuses when truncated/un-decodable (``benign_control_fetch``). An executor-supplied
    ``role="control"`` exchange is trusted VERBATIM (never re-fetched here), so the property is only as sound
    as that executor's capture — it is NOT re-established by this mint for the executor-supplied control."""

    def mint(report: dict) -> Any:
        # The GENERIC Strix→re-drive dispatch rail: a finding VIGIL can re-drive is verified by traffic VIGIL
        # ITSELF sends — its own gated, crafted probes — never the producer's recorded bytes. Route A is the
        # web re-drive; W1a adds the error-signature injection re-drive (error_based_sqli / nosqli /
        # ldap_injection / xpath_injection) for a Strix finding carrying {endpoint, param, class} and NO
        # capture. A capture-bearing report is left for the executor-capture mint below. Anything an arm does
        # not claim falls through to that capture path / stays a LEAD.
        handled, redrive_result = _dispatch_redrive(
            report, run_dir=run_dir, signers=signers, engagement_slug=engagement_slug,
            control_fetch=control_fetch)
        if handled:
            return redrive_result

        from framework.v2.evidence.poc import CapturedExchange     # lazy — FATAL-2

        capture = report.get(CAPTURE_KEY) or {}
        ex_dicts = capture.get("exchanges") or []
        blobs = capture.get("blobs") or {}
        if not ex_dicts:
            return None
        try:
            exchanges = [CapturedExchange(**{k: v for k, v in ex.items() if k not in ("blob", "observed_scheme")})
                         for ex in ex_dicts]
        except Exception as exc:  # noqa: BLE001 — a malformed/hostile capture drops the mint (LEAD), never raises
            # inv 12 (S9): building the executor exchanges from the attached capture RAISED — the capture was
            # present but unusable, so this finding cannot reach a FACT and its absence must not read as clean.
            # (An empty/absent capture returns None ABOVE without raising and stays a plain, clean-eligible
            # LEAD; only this RAISED path degrades.)
            _record_degraded(run_dir, CAPTURE_FAILED, "proof.run.mint.capture", exc)
            return None

        def _resolve(ref: str) -> "bytes | None":
            b = blobs.get(ref)
            if isinstance(b, (bytes, bytearray)):
                return bytes(b)
            if isinstance(b, str):
                return b.encode("utf-8")
            return None

        # INV 6/8 gate: an error-signature FACT rests on a datastore error in the RESPONSE, but a FACT must
        # ALSO bind the exploit REQUEST that provoked it (inv 8). Without it the certificate would record a
        # response with NO record of what was sent — a claim VIGIL cannot attribute — so the finding stays a
        # LEAD (no mint). Two things this gate MUST get right (both were reproduced bypasses):
        #   1. Mirror the ORACLE's observed-exchange selection. ``context_from_exchanges`` adjudicates
        #      ``_by_role(exs,'mutated') or exs[0]`` — the FIRST error-signature exchange when none is
        #      'mutated'. ``CapturedExchange.role`` is free-form (default ""), so a role="" exchange would
        #      sail past a literal role=='mutated' filter yet still be adjudicated. Select the SAME exchange
        #      the oracle will.
        #   2. Require the request to RESOLVE to non-empty bytes, not merely be a non-empty ref STRING — a
        #      dangling ref (no blob) or a whitespace-only ref materializes nothing (``_materialize`` skips
        #      unresolvable refs) and would leave the FACT resting on the response alone.
        # Non-error-signature channels (a ``request_payload`` proof, a process-execution proof) bind their
        # own causal artifact and are unaffected.
        _errsig = [ex for ex in exchanges if getattr(ex, "channel", "") == "error_signature"]
        _ctrl_ex = None
        if _errsig:
            _observed = next((ex for ex in _errsig if getattr(ex, "role", "") == "mutated"), _errsig[0])
            _req = _resolve(getattr(_observed, "request_bytes_ref", "") or "")
            if not (_req and _req.strip()):
                return None

            # S6 scheme-pairing: the benign twin CONTROL must be fetched over the SAME transport SCHEME as the
            # observed exchange (an origin-form request line carries none; the free-text ``report['endpoint']``
            # scheme is not trusted unless it exact-matches the observed host+path). Read the transport scheme
            # recorded on the observed capture (``observed_scheme``, from the proxy TLS flag — stripped above
            # before CapturedExchange). Mirror the oracle's observed-exchange selection over the RAW dicts so
            # ``_observed_scheme`` belongs to the exchange the oracle adjudicates.
            _errsig_dicts = [d for d in ex_dicts if isinstance(d, dict) and d.get("channel") == "error_signature"]
            _observed_dict = next((d for d in _errsig_dicts if (d.get("role") or "") == "mutated"),
                                  _errsig_dicts[0] if _errsig_dicts else {})
            _observed_scheme = _observed_dict.get("observed_scheme")

            # S6 — the CONTROL exchange (this slice). An error-signature FACT is attributable ONLY when the
            # SAME datastore/parser error is ABSENT from a benign CONTROL of the same endpoint. Without a
            # control the oracle's control-comparison guard (``verify.oracles.error_signature_oracle``, the
            # ``if control and pattern.search(control)`` arm) is DEAD CODE — a page that ALWAYS returns the
            # error would mint. Make it LIVE by REQUIRING a control fed to the oracle:
            #   * prefer an executor-captured ``role="control"`` exchange (already emitted by
            #     ``report.proof_capture`` when a benign id is cited);
            #   * else perform ONE VIGIL-owned benign fetch (no payload/canary) and INJECT it as a
            #     ``role="control"`` exchange so ``context_from_exchanges`` feeds it to the oracle.
            # A control that cannot be captured REFUSES to a LEAD (never a silent skip). This can only REMOVE
            # facts (an always-erroring page now fails to mint) — it enables none.
            _ctrl_ex = next((ex for ex in _errsig if getattr(ex, "role", "") == "control"), None)
            _ctrl_body = (_resolve(getattr(_ctrl_ex, "response_bytes_ref", "") or "")
                          if _ctrl_ex is not None else None)
            if not (_ctrl_body and _ctrl_body.strip()):
                # S6 BLOCK-2: the benign control MUST be the twin of the OBSERVED exchange — derive its url
                # from the observed request we resolved above (host+path, payload/query stripped) and route
                # the fetch THERE, never a free-text ``report["endpoint"]`` that need not name the same page
                # (an observed always-erroring path with a clean ``endpoint`` would otherwise fetch a clean
                # control and mint a FALSE FACT). An observed request from which no host+path can be derived
                # yields no pairable twin ⇒ LEAD.
                _twin, _twin_reason = _benign_twin_url(_req, observed_scheme=_observed_scheme)
                if _twin is None:
                    if control_fetch is not None:
                        # Objection-4: report the TRUE cause. A twin fails to derive either because the
                        # observed request yields no host+path, or because host+path IS derivable and only the
                        # transport SCHEME was unconfirmable (no TLS flag on a hand-crafted capture) — distinct
                        # (kind, where) rows so the audit detail is honest, never a blanket "no host+path".
                        if _twin_reason == _TWIN_UNCONFIRMED_SCHEME:
                            record_degradation(
                                run_dir, REDRIVE_FAILED,
                                where="proof.run.mint.control_scheme_unconfirmed",
                                detail="observed transport scheme (TLS flag) unconfirmed for the benign control "
                                       "twin — refusing to guess http")
                        else:
                            record_degradation(
                                run_dir, REDRIVE_FAILED,
                                where="proof.run.mint.control_unpairable",
                                detail="observed request has no derivable host+path for a benign control")
                    return None
                _fetched = _fetch_control({**report, "endpoint": _twin}, control_fetch)   # benign fetch of the OBSERVED twin
                if not (_fetched and _fetched.strip()):
                    # No control could be captured ⇒ the error is NOT attributable ⇒ LEAD. Record the inv-12
                    # cause when a fetch was actually ATTEMPTED (a fetcher was wired) so an unverifiable
                    # finding never reads as CLEAN; a deployment with no control fetcher is a plain LEAD, like
                    # the request-binding gate above.
                    if control_fetch is not None:
                        record_degradation(run_dir, REDRIVE_FAILED,
                                           where="proof.run.mint.control_unavailable",
                                           detail="benign control fetch established no channel")
                    return None
                _ctrl_ref = "vigil_control_resp"
                blobs[_ctrl_ref] = _fetched
                _ctrl_dict = {"channel": "error_signature", "role": "control",
                              "response_bytes_ref": _ctrl_ref, "status": None}
                ex_dicts.append(_ctrl_dict)                # keep capture["exchanges"] consistent (persisted record)
                _ctrl_ex = CapturedExchange(**_ctrl_dict)
                exchanges.append(_ctrl_ex)                 # feed the control to the oracle via context_from_exchanges

        finding = _finding_from_report(report)
        # S6 — ORACLE-AUTHORITATIVE class. For an error-signature capture the certificate's bug_class is the
        # datastore/parser ENGINE the deterministic oracle actually matched, OVERRIDING the finding's
        # self-reported CWE/title/class. Set at the SOURCE (before the mint) so the whole chain — context,
        # confirm_and_certify, certify, and offline reverify — is consistent and NO path can rename the class
        # the evidence proves (this closes CWE/title-precedence laundering, the reverse mis-label of a
        # mis-CWE'd finding, AND an explicitly mis-declared class in one move). If the oracle does not fire,
        # the inferred class stands and the finding stays a LEAD.
        if _errsig:
            # ``_ctrl_ex`` is the control established above (executor-supplied or the injected benign fetch);
            # it is guaranteed present here (a missing control already returned a LEAD). Re-run the SAME
            # oracle over observed+control so the engine the certificate class is derived from is exactly the
            # one the oracle proves — and so a same-error control (guard suppresses the fire) yields no engine
            # and the finding falls through to the LEAD path in ``mint_proof`` below.
            _engine = _errsig_engine(
                _resolve(getattr(_observed, "response_bytes_ref", "") or ""),
                _resolve(getattr(_ctrl_ex, "response_bytes_ref", "") or "") if _ctrl_ex is not None else None,
            )
            if _engine:
                _engine_class = _ERRSIG_ENGINE_TO_CLASS.get(_engine, "")
                if not _engine_class:
                    # FAIL-CLOSED: the oracle fired on a datastore/parser engine we cannot honestly name, so
                    # REFUSE the mint rather than fall back to the producer's (launderable) claim-derived
                    # class. The CI drift guard keeps the map complete; this is the runtime backstop if that
                    # is bypassed. Recorded so the engagement can never read CLEAN over a fired-but-
                    # unlabelable datastore error.
                    record_degradation(run_dir, MINT_FAILED, where="proof.run.mint.unmapped_engine",
                                       detail=_engine)
                    return None
                finding["bug_class"] = _engine_class
        action_id = "poc-" + hashlib.sha256(str(finding["check_id"]).encode("utf-8")).hexdigest()[:16]
        # Default the evidence root to <run_dir>/evidence so every FACT MATERIALISES its executor-captured
        # raw bytes into a cert-manifestable tree — that is what makes the exported proof bundle (C1)
        # artifact-integrity-checkable offline. An explicit evidence_root still wins.
        ev_root = str(evidence_root) if evidence_root else str(Path(run_dir) / "evidence")
        res = mint_proof(
            finding=finding, exchanges=exchanges, resolve=_resolve,
            engagement_slug=engagement_slug, signers=signers,
            evidence_root=ev_root, action_id=action_id,
            spool_dir=(str(spool_dir) if spool_dir else None),
            quarantine_dir=quarantine_dir,
        )
        _persist_record(run_dir, res, finding, capture)
        if getattr(res, "is_fact", False):
            # Retain the re-verifiable material (the oracle_context + action_id) so `vigil proof-export` can
            # rebuild a client-verifiable bundle later. Best-effort: a serialization hiccup never un-mints.
            try:
                _persist_reverifiable(run_dir, finding, action_id, exchanges, _resolve, res)
            except Exception:  # noqa: BLE001
                pass
        return res

    return mint
