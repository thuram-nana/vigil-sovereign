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
        wr = web_redrive(url, slug=engagement_slug, engagement_slug=engagement_slug, signers=signers)
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


def _benign_twin_url(request_bytes: "bytes | None", endpoint_hint: "str | None" = None) -> "str | None":
    """Derive the benign CONTROL url from the OBSERVED exchange's OWN captured request — its request-target
    (host+path) with the query/payload STRIPPED — so the control is the benign twin of the exact exchange the
    error-signature oracle adjudicates.

    The free-text ``report['endpoint']`` is NOT trusted to name the twin: nothing binds it to the observed
    exchange's request line, so an observed always-erroring ``/api/search?q='`` paired with ``endpoint='/'``
    would otherwise fetch a CLEAN control (error absent) and mint a FALSE FACT on the always-erroring path
    (BLOCK-2). ``endpoint_hint`` is consulted ONLY for the URL SCHEME, and ONLY when it already names the SAME
    host+path the request does — an origin-form request-target carries no scheme, and a wrong scheme merely
    fails the fetch (⇒ no channel ⇒ LEAD), so borrowing the scheme is a convenience, never a trust of the
    hint's identity. Returns ``None`` when the request cannot be parsed into a host+path (no derivable twin ⇒
    the caller refuses to a LEAD). NEVER raises."""
    from urllib.parse import urlsplit  # noqa: PLC0415 — stdlib
    try:
        if not request_bytes:
            return None
        head = bytes(request_bytes).split(b"\r\n\r\n", 1)[0]
        lines = [ln for ln in head.split(b"\r\n") if ln.strip()]
        if not lines:
            return None
        toks = lines[0].split()
        if len(toks) < 2:
            return None
        target = toks[1].decode("latin-1", "replace")
        if "://" in target:                                  # absolute-form target carries its own authority
            sp = urlsplit(target)
            authority, scheme, path = sp.netloc, (sp.scheme or "http"), (sp.path or "/")
        else:                                                # origin-form: path here, host from the Host header
            path = urlsplit(target).path or "/"
            authority, scheme = "", "http"
            for ln in lines[1:]:
                if ln.lower().startswith(b"host:"):
                    authority = ln.split(b":", 1)[1].strip().decode("latin-1", "replace")
                    break
            if endpoint_hint:                                # borrow the SCHEME only if the hint names the same page
                hp = urlsplit(str(endpoint_hint))
                if hp.netloc.lower() == authority.lower() and (hp.path or "/") == path:
                    scheme = hp.scheme or "http"
        if not authority:
            return None
        return f"{scheme}://{authority}{path}"               # query/payload stripped — a benign GET of the twin
    except Exception:  # noqa: BLE001 — an unparseable request ⇒ no derivable twin ⇒ None (the caller LEADs)
        return None


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
        # S7: a web-re-drivable finding is verified by traffic VIGIL ITSELF sends — its own gated, crafted
        # probes against the finding's endpoint — never the producer's recorded bytes. This is the
        # VIGIL-owned re-drive that lets a Strix web finding reach a FACT. Anything else (incl. the dominant
        # error_based_sqli captured-bytes class) falls through to the error-signature mint below / stays a LEAD.
        wclass = _web_redrive_class(report)
        if wclass is not None:
            return _web_redrive_mint(report, wclass, run_dir=run_dir, signers=signers,
                                     engagement_slug=engagement_slug)

        from framework.v2.evidence.poc import CapturedExchange     # lazy — FATAL-2

        capture = report.get(CAPTURE_KEY) or {}
        ex_dicts = capture.get("exchanges") or []
        blobs = capture.get("blobs") or {}
        if not ex_dicts:
            return None
        try:
            exchanges = [CapturedExchange(**{k: v for k, v in ex.items() if k != "blob"}) for ex in ex_dicts]
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
                _twin = _benign_twin_url(_req, report.get("endpoint"))
                if _twin is None:
                    if control_fetch is not None:
                        record_degradation(run_dir, REDRIVE_FAILED,
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
