"""Consumer PR-I (Area 8) — the customer PROOF BADGE + the per-finding PCF export. SOVEREIGN; a pure projection.

A finding a customer sees was minted on the offense side by the oracle, m-of-n signed by the CRUCIBLE governance
keys, and crossed the inert seam as opaque signed DATA (``inbound/finding_receiver.py``: anchor 1 verified at
ingest, then appended under the owner-signed spine head — anchor 2). The spine record therefore already holds
everything a third party needs to check anchor 1 WITHOUT VIGIL: the certificate and its signatures. This module
SURFACES that, and nothing more:

  * ``governance_roots`` — the governance trust root(s) the badge verifies against, DERIVED from the owner-signed
    OFFENSE_GOVERNANCE delegation(s) the operator configured (``config.customer_proof_delegation_paths``) — never
    a free-floating root: each delegation must verify against the CURRENT owner key, the role, the finding's own
    engagement scope and the CURRENT clock (fail-closed: a bad / expired / foreign one contributes nothing);
  * ``build_bundle`` — the ``vigil.pcf-finding-bundle/1`` document (SPEC §8): the signed certificate + its
    signatures + that trust root, exactly as stored (deep copies; no field added to, or removed from, the signed
    certificate);
  * ``bundle_verifies`` — TWO independent verifiers must agree before anything is badged or handed out: the
    ``vigil_core`` threshold check (the receiver's own anchor-1 check) AND the SHIPPED standalone verifier's code
    (``docs/proof-carrying-finding/verify_pcf.py``, loaded from the very bytes that go into the download) run over
    the exact bundle document, pinned to the derived root's fingerprint. Either one refusing → no badge, no bundle;
  * ``overlay_proofs`` — the badge state on each row of an ALREADY tenant-scoped findings page;
  * ``export_for_org`` — the downloadable ZIP for ONE of the org's own findings (bundle + verifier + README).

Invariants. It mints NO finding / FACT (it re-states already-signed bytes; a verifier refusal only ever REMOVES a
badge), touches no target, makes no model call, and appends nothing to the spine. Tenant isolation is the
findings read's: a record is reachable only through a slug in the org's own server-derived set
(``assessments._org_slug_set`` — the one-way ``_customer_slug(org_id\\x00host)`` hash), so another tenant's finding
is structurally unreachable even by its exact digest. No private key is ever read: the bundle carries PUBLIC keys
only. FATAL-2: stdlib + ``vigil_core`` + sovereign siblings; ``assert_no_offense()`` at import; the shipped verifier
imports only the standard library and ``cryptography``.

Scope (honest). The badge and the bundle speak for the POSITIVE finding certificate only. A remediation's signed
NEGATIVE clearance certificate does not yet reach this plane: nothing carries it across the offense->sovereign seam
until the Area 10 fix-it wiring (consumer PR-K) does, and it then surfaces through this same export. Until then a
retest's "fixed" verdict is shown beside the badge as the retest's own result, never as a signed clearance.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import logging
import re
import stat
import sys
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import Signature, TrustRoot, evidence_signing_bytes, verify_threshold  # noqa: E402
from vigil_core.canonical import digest_payload  # noqa: E402

BUNDLE_FORMAT = "vigil.pcf-finding-bundle/1"
BUNDLE_NAME = "proof-bundle.json"
VERIFIER_NAME = "verify_pcf.py"
README_NAME = "README.md"
FINGERPRINT_NAME = "TRUST-ROOT-FINGERPRINT.txt"
ZIP_CONTENT_TYPE = "application/zip"

# The shipped standalone verifier, by its repo path (apps/sigil/sigil/ui/proof_export.py -> repo root is
# parents[4]). Its sha256 is pinned by the signed verifier provenance + SECURITY.md (docs/tests drift guard).
VERIFIER_PATH = Path(__file__).resolve().parents[4] / "docs" / "proof-carrying-finding" / "verify_pcf.py"

_FINDING_KIND = "finding"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_DELEGATION_BYTES = 64 * 1024        # a delegation cert is a few hundred bytes; anything larger is refused
_MAX_VERIFIER_BYTES = 1024 * 1024
# The download is a handful of small files; a bundle this large would be a bug, never a finding.
MAX_ZIP_BYTES = 2 * 1024 * 1024
# A fixed timestamp for every ZIP member: the same finding always downloads as the same bytes.
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)

_log = logging.getLogger(__name__)
_warned: "set[str]" = set()
_warned_lock = threading.Lock()


def _warn_once(key: str, msg: str, *args: Any) -> None:
    """Log one operator-facing WARNING per ``key`` per process: why badges are missing (no delegation verifies, an
    unreadable delegation file, an unavailable verifier) without repeating it on every findings read. It names
    configuration only — never a tenant, a finding or key material."""
    with _warned_lock:
        if key in _warned:
            return
        _warned.add(key)
    _log.warning(msg, *args)


class ProofUnavailable(Exception):
    """This finding's proof cannot be exported (no current owner-delegated root covers it, the bundle does not
    verify, or the shipped verifier is not available). Fail-closed: nothing is handed out."""


@dataclass(frozen=True)
class GovernanceRoot:
    """One owner-delegated governance trust root covering a scope, with its out-of-band fingerprint."""
    trust_root: TrustRoot
    fingerprint: str

    def as_json(self) -> "dict[str, Any]":
        return self.trust_root.model_dump(mode="json")


def trust_root_fingerprint(trust_root_json: "dict[str, Any]") -> str:
    """``"sha256:" + digest_payload(trust_root)`` — byte-identical to the framework's ``trust_root_fingerprint`` and
    the standalone verifier's (SPEC §6), over the trust root's PUBLIC JSON form."""
    return "sha256:" + digest_payload(trust_root_json)


# --------------------------------------------------------------------------------------------------------------
# 1. The governance root(s): DERIVED from the owner-signed delegation(s), fail-closed
# --------------------------------------------------------------------------------------------------------------
def _read_bounded(path: Path, cap: int) -> Optional[bytes]:
    """A regular file's bytes, or None (missing / not a regular file / over the cap / unreadable)."""
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return data if len(data) <= cap else None


def load_delegations(paths=None) -> list:
    """Parse every configured owner-signed delegation cert (``config.customer_proof_delegation_paths``). PARSE ONLY —
    nothing here is trusted until ``governance_roots`` verifies it. An unreadable / malformed file is skipped."""
    from vigil_core.delegation import DelegationCert
    if paths is None:
        from .. import config
        paths = config.customer_proof_delegation_paths()
    out = []
    for p in paths:
        raw = _read_bounded(Path(p), _MAX_DELEGATION_BYTES)
        if raw is None:
            _warn_once(f"deleg-unreadable:{p}", "proof badge: delegation %s is missing, not a regular file, larger "
                       "than %d bytes or unreadable; it vouches for nothing", p, _MAX_DELEGATION_BYTES)
            continue
        try:
            out.append(DelegationCert.model_validate_json(raw))
        except ValueError:
            _warn_once(f"deleg-malformed:{p}", "proof badge: delegation %s is not a delegation certificate; it "
                       "vouches for nothing", p)
            continue
    return out


def governance_roots(*, scope: str, now: float, delegations=None,
                     owner_pubkey: "Optional[str]" = None) -> "list[GovernanceRoot]":
    """Every governance trust root an owner-signed OFFENSE_GOVERNANCE delegation CURRENTLY vouches for over
    ``scope`` (a finding's own signed ``engagement_slug``), in configuration order, de-duplicated by fingerprint.
    Each delegation must verify against the CURRENT owner public key, the role, ``scope`` (``"*"`` or equal) and
    ``now`` (a trusted LOCAL clock — an expired delegation vouches for nothing, exactly as the finding drain and the
    settle drain treat it). Fail-closed: no owner key, no delegation, or none valid → ``[]``."""
    from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, DelegationError, verify_delegation
    if not isinstance(scope, str) or not scope:
        return []
    if owner_pubkey is None:
        from ..governor.identity import owner_pubkey as _owner_pubkey
        owner_pubkey = _owner_pubkey()
    if not owner_pubkey:
        return []
    if delegations is None:
        delegations = load_delegations()
    out: "list[GovernanceRoot]" = []
    seen: "set[str]" = set()
    for cert in delegations:
        try:
            root = verify_delegation(cert, trusted_owner_pubkey=owner_pubkey, now=int(now),
                                     role=OFFENSE_GOVERNANCE_ROLE, scope=scope)
        except (DelegationError, TypeError, ValueError) as e:
            # a delegation scoped to ANOTHER engagement is normal (it simply does not cover this one); any other
            # refusal (not the owner's, wrong role, expired, malformed) is configuration the operator should see
            if getattr(cert, "scope", None) in ("*", scope):
                reason = "expired" if "expired" in str(e) else str(e)
                _warn_once(f"deleg-refused:{reason}", "proof badge: a configured delegation was refused (%s); it "
                           "vouches for nothing", reason)
            continue
        fp = trust_root_fingerprint(root.model_dump(mode="json"))
        if fp in seen:
            continue
        seen.add(fp)
        out.append(GovernanceRoot(trust_root=root, fingerprint=fp))
    return out


# --------------------------------------------------------------------------------------------------------------
# 2. The bundle document (SPEC §8) and the two independent verifiers
# --------------------------------------------------------------------------------------------------------------
def _signatures(raw: Any) -> "list[dict[str, str]]":
    """The record's signatures as plain ``{key_id, signature_b64}`` dicts (string-typed only — anything else is
    dropped, which can only make verification fail, never pass)."""
    out: "list[dict[str, str]]" = []
    for s in raw if isinstance(raw, list) else []:
        if isinstance(s, dict) and isinstance(s.get("key_id"), str) and isinstance(s.get("signature_b64"), str):
            out.append({"key_id": s["key_id"], "signature_b64": s["signature_b64"]})
    return out


def build_bundle(certificate: "dict[str, Any]", signatures: Any, root: GovernanceRoot) -> "dict[str, Any]":
    """The ``vigil.pcf-finding-bundle/1`` document for one signed finding: the certificate EXACTLY as stored (a deep
    copy — nothing added, nothing dropped, so its canonical bytes are the signed bytes), its signatures, and the
    governance trust root, plus three convenience copies a verifier re-derives and refuses on any disagreement."""
    cert = copy.deepcopy(certificate)
    return {
        "format": BUNDLE_FORMAT,
        "about": ("One VIGIL proof-carrying finding: a governance-signed evidence certificate and the trust root it "
                  "verifies under. Verify it with verify_pcf.py (see README.md); pin the trust-root fingerprint "
                  "VIGIL publishes out-of-band."),
        "finding_ref": cert.get("finding_ref"),
        "cert_digest": digest_payload(cert),
        "signed_evidence": {"certificate": cert, "signatures": _signatures(signatures)},
        "trust_root": root.as_json(),
        "trust_root_fingerprint": root.fingerprint,
    }


def _vigil_core_verifies(bundle: "dict[str, Any]", root: GovernanceRoot) -> bool:
    """Verifier 1 — the receiver's own anchor-1 check (``vigil_core.verify_threshold`` over
    ``evidence_signing_bytes(certificate)``) against the derived root."""
    se = bundle.get("signed_evidence") or {}
    try:
        sigs = [Signature(key_id=s["key_id"], signature_b64=s["signature_b64"]) for s in se.get("signatures") or []]
        if not sigs:
            return False
        return bool(verify_threshold(evidence_signing_bytes(se["certificate"]), sigs, root.trust_root).satisfied)
    except Exception:  # noqa: BLE001 — malformed signature/key material is a refusal, never a crash
        return False


class _ShippedVerifier:
    """The shipped standalone verifier, loaded ONCE per process from the exact bytes the download carries (the bytes
    are read, the module is loaded, the bytes are re-read: a change in between refuses — the code that verified is
    the code that ships). Thread-safe. ``None`` from ``get`` = unavailable → every proof fails closed."""

    _lock = threading.Lock()
    _loaded: "Optional[tuple[Any, bytes]]" = None

    @classmethod
    def get(cls) -> "Optional[tuple[Any, bytes]]":
        with cls._lock:
            if cls._loaded is None:
                cls._loaded = cls._load()
            loaded = cls._loaded
        if loaded is None:
            _warn_once(f"verifier-unavailable:{VERIFIER_PATH}", "proof badge: the shipped verifier %s is unavailable "
                       "or changed while loading; no finding is badged and no proof bundle is produced",
                       VERIFIER_PATH)
        return loaded

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._loaded = None

    @staticmethod
    def _load() -> "Optional[tuple[Any, bytes]]":
        before = _read_bounded(VERIFIER_PATH, _MAX_VERIFIER_BYTES)
        if before is None:
            return None
        name = "_vigil_shipped_verify_pcf"
        try:
            spec = importlib.util.spec_from_file_location(name, VERIFIER_PATH)
            if spec is None or spec.loader is None:
                return None
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod             # registered before exec, as cli.py does for a spec-loaded module
            spec.loader.exec_module(mod)
        except (Exception, SystemExit):  # noqa: BLE001 — an unloadable verifier means NO badge anywhere, never a crash
            sys.modules.pop(name, None)
            return None
        after = _read_bounded(VERIFIER_PATH, _MAX_VERIFIER_BYTES)
        if after != before or not callable(getattr(mod, "verify_finding_bundle", None)):
            return None
        return mod, before


def verifier_source() -> "Optional[bytes]":
    """The shipped verifier's bytes (the ones loaded and run here), or None when unavailable."""
    loaded = _ShippedVerifier.get()
    return loaded[1] if loaded else None


def _shipped_verifier_verifies(bundle: "dict[str, Any]", root: GovernanceRoot) -> bool:
    """Verifier 2 — the shipped standalone verifier's ``finding`` mode over the EXACT bundle document, pinned to the
    derived root's fingerprint (what the customer's auditor runs, minus the out-of-band step)."""
    loaded = _ShippedVerifier.get()
    if loaded is None:
        return False
    try:
        ok, _log = loaded[0].verify_finding_bundle(copy.deepcopy(bundle), pin=root.fingerprint)
    except (Exception, SystemExit):  # noqa: BLE001 — a verifier fault is a refusal, never a crash
        return False
    return ok is True


def bundle_verifies(bundle: "dict[str, Any]", root: GovernanceRoot) -> bool:
    """True iff BOTH independent verifiers accept ``bundle`` under ``root`` (two refusals must both be beaten)."""
    return _vigil_core_verifies(bundle, root) and _shipped_verifier_verifies(bundle, root)


def _published_ok(fingerprint: str) -> bool:
    """When VIGIL publishes its governance fingerprint(s) (``config.proof_published_fingerprints``), a proof is
    offered only under a PUBLISHED root — so an auditor can always pin it from the public page. Unset → no
    restriction (the README then tells the auditor to obtain the pin out-of-band)."""
    from .. import config
    published = config.proof_published_fingerprints()
    return not published or fingerprint in published


def verified_bundle(certificate: Any, signatures: Any, *, now: float, roots_cache: "Optional[dict]" = None,
                    delegations=None) -> "Optional[tuple[dict[str, Any], GovernanceRoot]]":
    """The bundle for one signed finding and the root it verifies under — the FIRST current owner-delegated root
    (configuration order) under which BOTH verifiers accept it and that VIGIL publishes (when it publishes any) —
    or None (fail-closed). ``roots_cache`` memoises the derived roots per scope for one request."""
    if not isinstance(certificate, dict):
        return None
    scope = certificate.get("engagement_slug")
    if not isinstance(scope, str) or not scope:
        return None
    if roots_cache is not None and scope in roots_cache:
        roots = roots_cache[scope]
    else:
        roots = governance_roots(scope=scope, now=now, delegations=delegations)
        if roots_cache is not None:
            roots_cache[scope] = roots
    for root in roots:
        if not _published_ok(root.fingerprint):
            continue
        bundle = build_bundle(certificate, signatures, root)
        if bundle_verifies(bundle, root):
            return bundle, root
    return None


# --------------------------------------------------------------------------------------------------------------
# 3. The badge overlay on an ALREADY tenant-scoped findings page
# --------------------------------------------------------------------------------------------------------------
def _signed_records(store, slugs: "set[str]") -> "dict[tuple[str, str, str], list[tuple[int, dict, Any]]]":
    """Every signed finding record whose OWN certificate slug is in ``slugs``, grouped by the findings read's
    identity (``assessments.finding_identity`` over the SAME ``_finding_json`` projection the read used), each
    group newest-first by spine seq — the order the read lists them in."""
    from . import assessments as _assess
    groups: "dict[tuple[str, str, str], list[tuple[int, dict, Any]]]" = {}
    for r in store.iter_records():
        if getattr(r, "kind", None) != _FINDING_KIND:
            continue
        p = r.payload
        if not isinstance(p, dict):
            continue
        cert = p.get("certificate")
        if not isinstance(cert, dict):
            continue
        slug = cert.get("engagement_slug")
        if not isinstance(slug, str) or slug not in slugs:
            continue
        key = _assess.finding_identity(_assess._finding_json(p, cert))
        groups.setdefault(key, []).append((int(getattr(r, "seq", 0)), cert, p.get("signatures")))
    for recs in groups.values():
        recs.sort(key=lambda t: t[0], reverse=True)
    return groups


def overlay_proofs(store, findings: "list[dict[str, Any]]", *, now: float, delegations=None) -> None:
    """Attach ``row["proof"]`` to each row of an ALREADY tenant-scoped, newest-first findings page (the customer
    findings read): ``{"verifiable": True, "cert_digest", "trust_root_fingerprint", "threshold", "signers"}`` when
    that row's OWN signed certificate verifies under BOTH verifiers against a current owner-delegated root, else
    ``{"verifiable": False}``. Rows sharing one identity are matched to that identity's records newest-first, which
    is exactly the order and the subset the read listed (a page keeps the newest rows), so each card is badged by
    its OWN certificate. The scan is bounded to the page's own slugs, so no other tenant's record can attach. A row
    whose identity matches no signed record (a projected or legacy row) gets ``verifiable: False``."""
    from . import assessments as _assess
    rows = [f for f in findings if isinstance(f, dict)]
    slugs = {f.get("engagement_slug") for f in rows}
    want = {s for s in slugs if isinstance(s, str) and s}
    if not want:
        return
    groups = _signed_records(store, want)
    used: "dict[tuple[str, str, str], int]" = {}
    roots_cache: "dict[str, list[GovernanceRoot]]" = {}
    if delegations is None:
        delegations = load_delegations()
    for f in rows:
        key = _assess.finding_identity(f)
        i = used.get(key, 0)
        used[key] = i + 1
        recs = groups.get(key) or []
        if i >= len(recs):
            f["proof"] = {"verifiable": False}
            continue
        _seq, cert, sigs = recs[i]
        hit = verified_bundle(cert, sigs, now=now, roots_cache=roots_cache, delegations=delegations)
        if hit is None:
            f["proof"] = {"verifiable": False}
            continue
        bundle, root = hit
        f["proof"] = {"verifiable": True, "cert_digest": bundle["cert_digest"],
                      "trust_root_fingerprint": root.fingerprint, "threshold": int(root.trust_root.threshold),
                      "signers": len(bundle["signed_evidence"]["signatures"])}


# --------------------------------------------------------------------------------------------------------------
# 4. The export: ONE of the org's own findings, as a deterministic ZIP (bundle + verifier + README)
# --------------------------------------------------------------------------------------------------------------
def valid_cert_digest(value: object) -> "Optional[str]":
    """A certificate digest as the badge gave it (64 lowercase hex), else None."""
    return value if isinstance(value, str) and _HEX64.fullmatch(value) else None


def valid_slug(value: object) -> "Optional[str]":
    """An engagement slug as the findings read gave it (non-empty, bounded, no whitespace), else None."""
    if not isinstance(value, str) or not value or len(value) > 200 or any(ch.isspace() for ch in value):
        return None
    return value


def find_signed_findings(store, org_id: str, *, engagement_slug: str, cert_digest: str,
                         now: float) -> "list[tuple[dict[str, Any], Any]]":
    """Every record of the org's OWN finding whose certificate's canonical digest is ``cert_digest``, newest-first,
    as ``(certificate, signatures)`` deep copies (``[]`` when there is none). One certificate can sit on the spine
    more than once with different signature sets (re-ingested under another m-of-n subset, or a record the badge
    refused): the caller hands out the first that verifies, exactly as the overlay badged the row by whichever of
    its records verified. The slug must be in the org's CURRENT server-derived set — the set the findings read lists
    from — so another tenant's finding is structurally unreachable, even named by its exact slug and digest (the
    IDOR guard is the one-way slug hash, not a check that could be forgotten)."""
    from . import assessments as _assess
    if engagement_slug not in _assess._org_slug_set(store, org_id, now=now):
        return []
    hits: "list[tuple[int, dict, Any]]" = []
    for r in store.iter_records():
        if getattr(r, "kind", None) != _FINDING_KIND:
            continue
        p = r.payload
        if not isinstance(p, dict):
            continue
        cert = p.get("certificate")
        if not isinstance(cert, dict) or cert.get("engagement_slug") != engagement_slug:
            continue
        if digest_payload(cert) != cert_digest:
            continue
        hits.append((int(getattr(r, "seq", 0)), cert, p.get("signatures")))
    hits.sort(key=lambda t: t[0], reverse=True)
    return [(copy.deepcopy(cert), copy.deepcopy(sigs)) for _seq, cert, sigs in hits]


def _safe_name(value: object, limit: int = 40) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-.")
    return (s[:limit] or "finding")


def _readme(bundle: "dict[str, Any]", root: GovernanceRoot, verifier_sha256: str,
            published: "tuple[str, ...]") -> str:
    """The bundle's README: the exact commands, what a VERIFIED result proves, and what it does not. Deterministic
    (a pure function of the bundle, the root, the verifier bytes and the published pins)."""
    cert = bundle["signed_evidence"]["certificate"]
    ref, cls = str(cert.get("finding_ref") or ""), str(cert.get("bug_class") or "")
    surface, ocd = str(cert.get("surface") or ""), str(cert.get("oracle_context_digest") or "")
    cert_digest, threshold = str(bundle["cert_digest"]), int(root.trust_root.threshold)
    pins = ("VIGIL publishes its governance fingerprint(s) on the \"Verify a VIGIL finding\" page of its public "
            "website (/verify):\n\n" + "\n".join(f"    {p}" for p in published)) if published else (
            "Obtain VIGIL's governance fingerprint from VIGIL through a channel you trust that is independent of "
            "this download (for example the \"Verify a VIGIL finding\" page of its public website, /verify, or "
            "your VIGIL contact).")
    return f"""# VIGIL proof bundle — verify this finding yourself

Finding:                {ref}  ({cls})
Location:               {surface}
Certificate digest:     {cert_digest}
Evidence digest:        {ocd}
Trust-root fingerprint: {root.fingerprint}   (a convenience copy — pin it out-of-band, step 1)

This folder holds one finding's signed evidence certificate (`{BUNDLE_NAME}`), the standalone verifier
(`{VERIFIER_NAME}`) and this file. You do not need a VIGIL account, VIGIL's software or network access to check it.

## Step 1 — pin VIGIL's governance fingerprint out-of-band

The trust root inside `{BUNDLE_NAME}` is a convenience copy: whoever handed you this folder could have replaced
it. What anchors the proof is the fingerprint VIGIL publishes through a channel independent of this download.
{pins}

## Step 2 — check the verifier is the published one

    sha256sum {VERIFIER_NAME}

It must print `{verifier_sha256}` — the value VIGIL publishes on the same /verify page and pins in its
signed verifier provenance. The verifier imports only the Python standard library and `cryptography`.

## Step 3 — verify (offline)

    python3 -m pip install cryptography        # the verifier's only dependency
    python3 {VERIFIER_NAME} finding --bundle {BUNDLE_NAME} --trust-root-fingerprint <the fingerprint from step 1>

Exit code 0 and a last line of `finding VERIFIED` mean the check passed. Change any value of the certificate in
`{BUNDLE_NAME}` (its `bug_class` or `surface`, for example) and run it again: it prints `finding NOT VERIFIED`
and exits 2. (A file that is no longer valid JSON is an input error: exit 3.)

## What a VERIFIED result proves

* The certificate in `{BUNDLE_NAME}` was signed by at least {threshold} distinct VIGIL
  governance key(s) of the trust root you pinned (m-of-n Ed25519), and not one byte of it has changed since:
  the finding's class, its location, the digest of the evidence VIGIL's oracle judged, the signed how-to-verify
  note and every other field.
* The certificate declares a FACT provenance: it was minted from evidence VIGIL captured or re-drove itself, never
  from a model's text.

## What it does not prove on its own

* That the vulnerability still reproduces today: re-running VIGIL's deterministic oracle needs the retained
  evidence (the oracle context) and the VIGIL verifier. This bundle does not carry the raw evidence, so the
  binding and artifact checks print NOT CHECKED (`--oracle-context` / `--evidence-root` check them when you
  have those files).
* That no other finding of the same assessment was withheld: that is the engagement chain, which a single-finding
  bundle does not carry.
* VIGIL's own ledger anchor (the owner-signed spine head that chains this finding into your account's record) is
  checked by VIGIL's servers; it is not part of this download.
"""


def _zip(files: "list[tuple[str, bytes]]") -> bytes:
    """A deterministic ZIP: sorted names, one fixed timestamp, fixed permissions, DEFLATE."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, data in sorted(files):
            info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o644 & 0xFFFF) << 16
            info.create_system = 3
            zf.writestr(info, data)
    return buf.getvalue()


def export_for_org(store, org_id: str, *, engagement_slug: str, cert_digest: str, now: float) -> "dict[str, Any]":
    """The downloadable proof bundle for ONE of ``org_id``'s own findings: a deterministic ZIP of
    ``proof-bundle.json`` + the shipped ``verify_pcf.py`` + ``README.md`` + ``TRUST-ROOT-FINGERPRINT.txt``, returned
    as ``{filename, content_type, zip_b64, sha256, finding_ref, cert_digest, trust_root_fingerprint}``.

    Raises ``LookupError`` when the finding is not the org's own (never distinguishing "another tenant's" from "no
    such"), and ``ProofUnavailable`` when no current owner-delegated root under which BOTH verifiers accept it exists
    (nothing is handed out). Assumes the caller authorized ``org_id`` for ``view_assessments`` and applied the
    trial-preview lock."""
    slug = valid_slug(engagement_slug)
    digest = valid_cert_digest(cert_digest)
    if slug is None or digest is None:
        raise LookupError("no such finding for this workspace")
    found = find_signed_findings(store, org_id, engagement_slug=slug, cert_digest=digest, now=now)
    if not found:
        raise LookupError("no such finding for this workspace")
    source = verifier_source()
    hit = None
    if source is not None:
        roots_cache: "dict[str, list[GovernanceRoot]]" = {}
        delegations = load_delegations()
        for cert, sigs in found:                      # newest-first: the first record that verifies is handed out
            hit = verified_bundle(cert, sigs, now=now, roots_cache=roots_cache, delegations=delegations)
            if hit is not None:
                break
    if hit is None or source is None:
        raise ProofUnavailable("this finding's proof cannot be verified right now")
    bundle, root = hit
    cert = bundle["signed_evidence"]["certificate"]
    if bundle["cert_digest"] != digest:              # the bytes handed out are the bytes the customer asked for
        raise ProofUnavailable("this finding's proof cannot be verified right now")
    from .. import config
    published = config.proof_published_fingerprints()
    bundle_bytes = (json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    # The bytes a customer downloads must themselves verify: re-parse them and re-run both verifiers on the result.
    if not bundle_verifies(json.loads(bundle_bytes.decode("utf-8")), root):
        raise ProofUnavailable("this finding's proof cannot be verified right now")
    readme = _readme(bundle, root, hashlib.sha256(source).hexdigest(), published)
    data = _zip([(BUNDLE_NAME, bundle_bytes), (VERIFIER_NAME, source), (README_NAME, readme.encode("utf-8")),
                 (FINGERPRINT_NAME, (root.fingerprint + "\n").encode("utf-8"))])
    if len(data) > MAX_ZIP_BYTES:
        raise ProofUnavailable("this finding's proof bundle is unexpectedly large")
    return {"filename": f"vigil-proof-{_safe_name(cert.get('finding_ref'))}-{digest[:12]}.zip",
            "content_type": ZIP_CONTENT_TYPE, "zip_b64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(), "finding_ref": cert.get("finding_ref"),
            "cert_digest": digest, "trust_root_fingerprint": root.fingerprint}
