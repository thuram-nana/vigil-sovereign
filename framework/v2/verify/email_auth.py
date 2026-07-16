"""verify.email_auth — the confirmation seam + minimal offline ingest for the email-auth-posture oracle.

FORGE **Domain 10**, the first stream built under the FORGE constitution (`/FORGE.md`) on the PCF foundation:
a confirmed finding here emits a real, signed, offline-re-runnable **PCF v0.1** certificate
(`evidence/pcf.py`) by construction.

A domain's email-authentication posture is a PUBLISHED CONFIG ARTIFACT (its DNS TXT records), so — exactly
like ``verify.cicd_posture`` / ``verify.mesh_posture`` — this module carries a MINIMAL, OFFLINE, READ-ONLY
ingest that maps an operator-supplied DNS policy export into the canonical control shape the oracle judges,
then routes each control through ``email_auth_posture_oracle``, which RE-DERIVES the weakness from the
record's literal text (never a receiving MTA's ``Authentication-Results`` say-so — that would be string
trust). NO DNS is queried here and NO mail is sent: it is a pure re-derivation over already-exported records.

**Deliberately out of scope (REFUSE, never assert):** message-level SPF/DKIM/DMARC *verification*. DKIM
canonicalisation and SPF include/macro chains are a semantic layer this cannot soundly re-derive offline, so
they stay LEADs (the SAML-c14n lesson: an oracle that cannot resolve a semantic layer must refuse, not assert
the negative). ``spf_missing`` alone likewise does not fire — DKIM+DMARC may still protect the domain.

No benchmark/scan/engage finding carries ``email_auth_control``, so the gate stays byte-identical. Never
raises: a malformed export is a non-ingestion, not a crash.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def email_auth_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained DNS email-auth record — routes to the email-auth-posture oracle.
    Total: a non-mapping yields an empty control (which the oracle refuses), never an exception."""
    src = control if isinstance(control, Mapping) else {}
    return FindingContext.from_email_auth_control(dict(src)).to_verifier_context()


def confirm_email_auth_posture(control: Mapping[str, Any], *,
                               verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge one retained DNS email-auth control: ``confirmed`` iff the oracle re-derives a PUBLISHED policy
    that permits spoofing (no DMARC / p=none / SPF +all). Offline; never raises."""
    return (verifier or OracleVerifier()).confirm(email_auth_context(control))


def ingest_dns_policy(domain: str, *, dmarc_record: str | None = None, spf_record: str | None = None,
                      dmarc_observed: bool = False, is_org_domain: bool = False,
                      org_domain: str | None = None, org_dmarc_record: str | None = None,
                      org_dmarc_observed: bool = False) -> list[dict[str, Any]]:
    """Map ONE domain's exported DNS policy into the candidate control LEADS the oracle judges. Pass the
    records EXACTLY as published (the TXT strings).

    The attestations are load-bearing and are only ever passed through as a LITERAL ``True``:
      * ``dmarc_observed`` — the domain's own DMARC lookup was actually performed (the oracle REFUSES to
        call a record "missing" without it: absence must be OBSERVED, never assumed).
      * ``is_org_domain`` — this IS an organizational (registrable) domain, so there is no parent policy to
        inherit. Required before an absent record can be called "no policy".
      * ``org_domain`` / ``org_dmarc_record`` / ``org_dmarc_observed`` — for a SUBDOMAIN, the organizational
        domain's retained policy. RFC 7489 §6.6.3 makes receivers fall back to it, and §6.3 applies its
        ``sp=`` (else ``p=``) to the subdomain — so WITHOUT this the inheritance chain is unresolved and the
        oracle REFUSES rather than assert (a subdomain publishing nothing may be fully protected).

    Emits a candidate per applicable rule; the ORACLE decides which (if any) is a FACT. Pure + total."""
    d = (domain or "").strip()
    dmarc = (dmarc_record or "").strip()
    spf = (spf_record or "").strip()
    out: list[dict[str, Any]] = []
    if dmarc:
        out.append({"rule": "dmarc_none", "domain": d, "dmarc_record": dmarc})
    elif dmarc_observed is True:
        c: dict[str, Any] = {"rule": "dmarc_missing", "domain": d, "dmarc_observed": True}
        if is_org_domain is True:
            c["is_org_domain"] = True
        else:
            if org_domain:
                c["org_domain"] = str(org_domain).strip()
            if org_dmarc_record:
                c["org_dmarc_record"] = str(org_dmarc_record).strip()
            if org_dmarc_observed is True:
                c["org_dmarc_observed"] = True
        out.append(c)
    if spf:
        out.append({"rule": "spf_permissive", "domain": d, "spf_record": spf})
    return out


def confirm_dns_policy(domain: str, *, verifier: OracleVerifier | None = None,
                       **policy: Any) -> list[dict[str, Any]]:
    """Convenience end-to-end: ingest a domain's exported policy then return only the controls the oracle
    CONFIRMED as FACTs. Accepts the same keywords as :func:`ingest_dns_policy`. Pure + offline — no DNS
    call, no mail."""
    v = verifier or OracleVerifier()
    return [c for c in ingest_dns_policy(domain, **policy)
            if confirm_email_auth_posture(c, verifier=v).confirmed]
