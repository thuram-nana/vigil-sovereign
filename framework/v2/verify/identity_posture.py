"""verify.identity_posture — the confirmation seam + minimal offline ingest for the identity-posture oracle.

FORGE **Domain 7** (slice 1), built on the PCF foundation: a confirmed finding here emits a real, signed,
offline-re-runnable **PCF v0.1** certificate (``evidence/pcf.py``) by construction.

An identity's posture is a PUBLISHED CONFIG ARTIFACT (its IdP-export record), so — exactly like
``verify.mesh_posture`` / ``verify.email_auth`` — this module carries a MINIMAL, OFFLINE, READ-ONLY ingest
that maps an operator-supplied identity export into the candidate controls the oracle judges, then routes
each control through ``identity_posture_oracle``, which RE-DERIVES the weakness from the export's STRICT-TYPED
literal fields (never an IdP API's or scanner's say-so — that would be string trust). NO IdP is queried and
NO authentication is attempted: it is a pure re-derivation over already-exported records.

**Deliberately out of scope (REFUSE, never assert):** anomaly/behavioral detection (probabilistic — cannot
be a near-zero-FP FACT); cloud-resource IAM (``POLICY_PATH``/``CLOUD_POSTURE`` own that); privilege
INFERENCE — the ``privileged`` attestation is required, never guessed from a role name. Slice 1 proves two
facts: ``privileged_without_mfa`` and ``stale_credential``; ``wildcard_grant`` and ``dormant_privileged`` are
a follow-up charter.

No benchmark/scan/engage finding carries ``identity_control``, so the gate stays byte-identical. Never
raises: a malformed export is a non-ingestion, not a crash.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .adapter import FindingContext
from .models import VerificationResult
from .oracles import _is_universal_grant
from .verifier import OracleVerifier


def _grant_str(g: Any) -> str:
    """Normalise one grant (a string, or an ``{"action":…, "resource":…}`` dict) to an ``action:resource``
    string so the universality check runs over one shape. Non-grant entries -> ``""``.

    A grant OBJECT is in-contract ONLY as ``{action, resource}``. Any other key — ``effect`` (a ``Deny``
    is a HARDENED control, the OPPOSITE of a weakness), a ``condition`` (a bounded break-glass grant is not
    unrestricted access), a scope/sid/etc. — can BOUND or INVERT the grant. Flattening to ``action:resource``
    and asserting universality would drop that key and assert PAST an ambiguity — the exact fault line this
    oracle refuses. So a grant object carrying any out-of-contract key REFUSES (``""`` -> no candidate), and
    such a grant stays a LEAD rather than a false FACT (both reviewers converged on this)."""
    if isinstance(g, str):
        return g.strip()
    if isinstance(g, Mapping):
        if set(g.keys()) - {"action", "resource"}:
            return ""
        action = str(g.get("action") or "").strip()
        resource = str(g.get("resource") or "").strip()
        if action or resource:
            return f"{action}:{resource}"
    return ""


def identity_posture_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained identity-posture control — routes to the identity-posture oracle.
    Total: a non-mapping yields an empty control (which the oracle refuses), never an exception."""
    src = control if isinstance(control, Mapping) else {}
    return FindingContext.from_identity_control(dict(src)).to_verifier_context()


def confirm_identity_posture(control: Mapping[str, Any], *,
                             verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge one retained identity-posture control: ``confirmed`` iff the oracle re-derives a weakness over
    the control's STRICT-TYPED literal fields (a privileged identity with MFA provably off, or a credential
    past its rotation policy). Offline; never raises."""
    return (verifier or OracleVerifier()).confirm(identity_posture_context(control))


def _mfa_flag(row: Mapping[str, Any]) -> "bool | None":
    """The identity's MFA-enrolled state as a STRICT bool, or ``None`` when unknown. Accepts the literal
    booleans only (never a truthy/falsy string) — the oracle REFUSES on unknown, so a fabricated "false"
    string must not launder into the fired condition."""
    v = row.get("mfa_enrolled")
    if v is True:
        return True
    if v is False:
        return False
    return None


def ingest_identity_export(rows: Any) -> list[dict[str, Any]]:
    """Map an exported IdP inventory into the candidate control LEADS the oracle judges. ``rows`` is a list
    of per-identity/credential dicts (or a ``{"identities": [...]}`` wrapper). Each row may carry:
    ``subject`` (the identity/credential id), ``privileged`` (bool attestation), ``mfa_enrolled`` (bool),
    and for a credential ``never_rotated`` (bool), ``age_days`` (int), ``max_age_days`` (int, the operator's
    rotation policy). Emits a candidate per applicable rule; the ORACLE decides which (if any) is a FACT.

    STRICT: the boolean attestations are passed through only as literal booleans; a truthy string never
    becomes an attestation. Pure + total — a malformed export is a non-ingestion, never a crash."""
    if isinstance(rows, Mapping):
        rows = rows.get("identities") if isinstance(rows.get("identities"), list) else None
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        subject = str(row.get("subject") or "").strip()
        # privileged_without_mfa: only a genuinely-privileged identity is a candidate (privilege is attested,
        # never inferred). MFA state (True/False/None) is passed strictly; the oracle refuses on None.
        if row.get("privileged") is True:
            c: dict[str, Any] = {"rule": "privileged_without_mfa", "subject": subject, "privileged": True}
            mfa = _mfa_flag(row)
            if mfa is not None:
                c["mfa_enrolled"] = mfa
            key = f"{subject}:privileged_without_mfa".lower()
            if key not in seen:
                seen.add(key)
                out.append(c)
        # stale_credential: a candidate when the export attests never-rotated OR supplies both age integers.
        never = row.get("never_rotated") is True
        age = row.get("age_days")
        maxa = row.get("max_age_days")
        has_ages = (isinstance(age, int) and not isinstance(age, bool)
                    and isinstance(maxa, int) and not isinstance(maxa, bool))
        if never or has_ages:
            c = {"rule": "stale_credential", "subject": subject}
            if never:
                c["never_rotated"] = True
            if has_ages:
                c["age_days"] = age
                c["max_age_days"] = maxa
            key = f"{subject}:stale_credential".lower()
            if key not in seen:
                seen.add(key)
                out.append(c)
        # wildcard_grant (slice 2): admin_all attestation, else the FIRST provably-UNIVERSAL grant. A scoped
        # or partial wildcard mints no candidate (the oracle re-derives universality regardless).
        wc: dict[str, Any] | None = None
        if row.get("admin_all") is True:
            wc = {"rule": "wildcard_grant", "subject": subject, "admin_all": True}
        else:
            grants = row.get("grants")
            if isinstance(grants, (list, tuple)):
                for g in grants:
                    gs = _grant_str(g)
                    if gs and _is_universal_grant(gs):
                        wc = {"rule": "wildcard_grant", "subject": subject, "grant": gs}
                        break
        if wc is not None:
            key = f"{subject}:wildcard_grant".lower()
            if key not in seen:
                seen.add(key)
                out.append(wc)
        # dormant_privileged (slice 2): a privileged identity with both dormancy integers retained.
        dsl = row.get("days_since_login")
        dthr = row.get("dormancy_threshold_days")
        has_dormancy = (isinstance(dsl, int) and not isinstance(dsl, bool)
                        and isinstance(dthr, int) and not isinstance(dthr, bool))
        if row.get("privileged") is True and has_dormancy:
            key = f"{subject}:dormant_privileged".lower()
            if key not in seen:
                seen.add(key)
                out.append({"rule": "dormant_privileged", "subject": subject, "privileged": True,
                            "days_since_login": dsl, "dormancy_threshold_days": dthr})
    return out


def confirm_identity_export(rows: Any, *, verifier: OracleVerifier | None = None) -> list[dict[str, Any]]:
    """Convenience end-to-end: ingest an identity export then return only the controls the oracle CONFIRMED
    as FACTs. Pure + offline — no IdP call, no authentication attempt."""
    v = verifier or OracleVerifier()
    return [c for c in ingest_identity_export(rows)
            if confirm_identity_posture(c, verifier=v).confirmed]
