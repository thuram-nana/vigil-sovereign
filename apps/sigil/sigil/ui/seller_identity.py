"""seller_identity — the PUBLISHED seller identity of the hosted VIGIL service (legal/governance S7).

The hosted VIGIL service (``app.vigilguard.net``) is provided by one company, and consumer / distance-selling law
requires that the customer can see who that is. This module is the SINGLE owner-reviewed source of that identity — the
same trust root as ``governor/catalog.py``: a GLOBAL constant in CODE, never a per-tenant wire field and never an
invented value. Every value here is PUBLISHED verbatim on the public Terms and/or Privacy pages
(``ui/public_site/terms/index.html``, ``ui/public_site/privacy/index.html``); the Seller identity screen RENDERS these
same published facts, it does not reword or restate them.

Owner decision — PUBLISHED DETAILS ONLY: the block carries no street address, no phone number and no VAT / tax
registration number. Those are not published (and there is no tax), so they are deliberately absent here rather than
fabricated. A value is shown only because it is already public.

The block is served READ-ONLY, to an authenticated customer session, through ``Provisioner.seller_identity_get`` and the
edge's ``GET api/customer/seller-identity`` — both absent (404) unless ``VIGIL_CUSTOMER_SELLER_IDENTITY`` is on. It is a
pure display read: nothing is minted, nothing is mutated, and it never touches the signed append-only spine.
"""
from __future__ import annotations

from ..reuse import assert_no_offense

assert_no_offense()

# Each value below appears verbatim on the public Terms and/or Privacy pages (the canonical published copy). This is an
# owner-reviewed constant: it is reviewed like code, never written by a customer and never carried on the wire.
#   * legal name + expansion .......... terms/index.html §1 "Who we are", privacy/index.html "The hosted service"
#   * legal form (SARL) ............... terms/index.html §1
#   * registered city + country ....... terms/index.html §1, privacy/index.html "The hosted service"
#   * registration number (RCCM) ...... terms/index.html §1, privacy/index.html "The hosted service"
#   * contact email ................... privacy/index.html "Contact", terms/index.html §19
#   * website ......................... terms/index.html §1 "Company information"
#   * governing law ................... terms/index.html §19 "Governing law and courts"
_SELLER_IDENTITY: dict[str, str] = {
    "legal_name": "SIGIL SARL",
    "legal_name_expansion": "Sovereign Integrity Governance Infrastructure Labs",
    "legal_form": "Société à responsabilité limitée (SARL)",
    "registered_city": "Buea",
    "registered_country": "Cameroon",
    "registration_number": "RCCM RC.BUA.2026.B.0190",
    "contact_email": "info@sigilsovereign.com",
    "website": "sigilsovereign.com",
    "governing_law": "the laws of the Republic of Cameroon, including the applicable OHADA Uniform Acts",
}

#: The order the Seller identity screen shows the fields in (the screen renders exactly these, in this order).
FIELD_ORDER: tuple[str, ...] = (
    "legal_name",
    "legal_name_expansion",
    "legal_form",
    "registered_city",
    "registered_country",
    "registration_number",
    "contact_email",
    "website",
    "governing_law",
)


def published_seller_identity() -> dict[str, str]:
    """A fresh copy of the published seller-identity block — the GLOBAL, owner-reviewed identity of the hosted VIGIL
    service, exactly as published on the public Terms and Privacy pages. The caller may not mutate the module constant:
    a new dict is returned each call."""
    return dict(_SELLER_IDENTITY)
