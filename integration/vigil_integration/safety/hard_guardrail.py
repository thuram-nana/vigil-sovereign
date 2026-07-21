"""
hard_guardrail — a deterministic, non-disableable scope floor (VIGIL-FUSION F1).

Adapted from redamon's ``agentic/orchestrator_helpers/hard_guardrail.py`` (MIT; see NOTICE). This is
a categorically-never denylist for government / military / educational / intergovernmental targets,
evaluated **before the charter or any gate is consulted** and with **no LLM, no network, no settings
dependency** — it cannot be toggled off. It is defense-in-depth, not a replacement for the charter:
the charter still authorizes what IS in scope; this guard removes an entire class from consideration
so that a prompt-injection or an operator typo can never redirect an autonomous agent at, say, a
government or military host.

VIGIL note: this is a pure predicate that can only DENY — it never authorizes anything and is not an
authority. It runs first; if it does not block, the normal charter + conjunctive gate still decide.

Pure stdlib. Import-clean (no ``framework.*``/``strix.*``).
"""

from __future__ import annotations

import re

# TLD suffix patterns (case-insensitive, applied to the full normalized domain).
_TLD_PATTERNS = [
    # Government
    r"\.gov$",
    r"\.gov\.[a-z]{2,3}$",        # .gov.uk, .gov.au, .gov.br
    r"\.gob\.[a-z]{2,3}$",        # .gob.mx, .gob.es
    r"\.gouv\.[a-z]{2,3}$",       # .gouv.fr, .gouv.ci
    r"\.govt\.[a-z]{2,3}$",       # .govt.nz
    r"\.go\.[a-z]{2}$",            # .go.jp, .go.kr, .go.id (2-letter ccTLDs only)
    r"\.gv\.[a-z]{2}$",            # .gv.at (2-letter ccTLDs only)
    r"\.government\.[a-z]{2,3}$",
    # Military
    r"\.mil$",
    r"\.mil\.[a-z]{2,3}$",        # .mil.br
    # Education
    r"\.edu$",
    r"\.edu\.[a-z]{2,3}$",        # .edu.au
    r"\.ac\.[a-z]{2,3}$",         # .ac.uk, .ac.jp
    # International organizations
    r"\.int$",                     # NATO, WHO, EU agencies
]

_COMPILED_TLD_RE = re.compile("|".join(f"(?:{p})" for p in _TLD_PATTERNS), re.IGNORECASE)

# Exact-match domains for major intergovernmental organizations on generic TLDs (.org, .eu, .com)
# that the suffix rules would miss. Curated list retained from the source (MIT).
_EXACT_BLOCKED_DOMAINS: frozenset[str] = frozenset({
    # UN System: core bodies & programmes
    "un.org", "undp.org", "unep.org", "unicef.org", "unhcr.org", "unrwa.org", "unfpa.org",
    "unctad.org", "unido.org", "unwto.org", "unhabitat.org", "unodc.org", "unops.org", "unssc.org",
    "unitar.org", "uncdf.org", "unrisd.org", "unaids.org", "undrr.org", "unwater.org", "unwomen.org",
    "un-women.org", "undss.org", "unjiu.org", "unscear.org", "uncitral.org", "wfp.org", "ohchr.org",
    "unocha.org",
    # UN regional commissions
    "unece.org", "unescap.org", "uneca.org", "cepal.org", "unescwa.org",
    # UN specialized agencies (generic TLDs)
    "ilo.org", "fao.org", "unesco.org", "imf.org", "worldbank.org", "ifad.org", "iaea.org", "imo.org",
    # UN tribunals & international courts
    "icj-cij.org", "icty.org", "irmct.org", "itlos.org", "african-court.org", "corteidh.or.cr",
    # World Bank group
    "ifc.org", "miga.org",
    # EU institutions
    "europa.eu", "eib.org", "eurocontrol.eu",
    # Security & defence
    "osce.org", "csto.org", "odkb-csto.org",
    # Regional intergovernmental organizations
    "asean.org", "african-union.org", "oas.org", "caricom.org", "apec.org", "gcc-sg.org",
    "bimstec.org", "saarc-sec.org", "oic-oci.org", "comunidadandina.org", "aladi.org", "sela.org",
    "norden.org", "thecommonwealth.org", "francophonie.org", "cplp.org", "forumsec.org", "acs-aec.org",
    "eaeunion.org", "eurasiancommission.org", "ceeac-eccas.org", "sectsco.org", "turkicstates.org",
    "leagueofarabstates.net", "lasportal.org", "celacinternational.org", "s-cica.org",
    "visegradfund.org", "colombo-plan.org", "eria.org", "nepad.org", "aprm-au.org",
    # Development banks & IFIs
    "bis.org", "adb.org", "afdb.org", "aiib.org", "ebrd.com", "isdb.org", "bstdb.org", "opec.org",
    "opecfund.org", "fatf-gafi.org", "iadb.org", "caf.com", "bcie.org", "fonplata.org", "caribank.org",
    "boad.org", "eabr.org", "eadb.org", "tdbgroup.org", "coebank.org", "afreximbank.com",
    # Financial governance & regulation
    "fsb.org", "egmontgroup.org",
    # International trade & commodity organizations
    "wto.org", "intracen.org", "iccwbo.org", "ico.org", "icco.org", "isosugar.org",
    "internationaloliveoil.org", "ief.org", "ilzsg.org", "insg.org", "icsg.org",
    # International health
    "gavi.org", "theglobalfund.org", "cepi.net", "unitaid.org",
    # Arms control, non-proliferation & treaty bodies
    "ctbto.org", "opcw.org", "wassenaar.org", "nuclearsuppliersgroup.org", "australiagroup.net",
    "mtcr.info", "opanal.org", "apminebanconvention.org", "clusterconvention.org", "brsmeas.org",
    # International science & research
    "cern.ch", "home.cern", "iter.org", "esrf.eu", "embl.org", "eso.org", "cgiar.org", "irena.org",
    "ipcc.ch", "xfel.eu", "ill.eu", "euro-fusion.org", "sesame.org.jo", "icgeb.org", "isolaralliance.org",
    # Environment & climate
    "thegef.org", "greenclimate.fund", "adaptation-fund.org", "cif.org", "ramsar.org", "cites.org",
    "iucn.org",
    # Red Cross / Red Crescent (Geneva Convention status)
    "icrc.org", "ifrc.org",
    # Migration, humanitarian & cultural heritage
    "icmpd.org", "iccrom.org", "gichd.org", "dcaf.ch",
    # River basin & navigation commissions
    "mrcmekong.org", "nilebasin.org", "danubecommission.org", "icpdr.org", "ccr-zkr.org",
    # Sport governance (intergovernmental)
    "wada-ama.org", "tas-cas.org",
    # Standards, metrology & other intergovernmental bodies
    "oecd.org", "g20.org", "pca-cpa.org", "hcch.net", "unidroit.org", "wco.org", "wcoomd.org",
    "oiml.org", "bipm.org", "iso.org", "iec.ch", "iea.org", "icglr.org", "isa.org.jm", "gggi.org",
})


class HardBlockError(RuntimeError):
    """A target is on the deterministic non-disableable scope floor — it must never be touched.
    Raised fail-closed; must not be caught-and-continued (it is a categorical refusal)."""


def normalize_domain(raw: str) -> str:
    """Lowercase; strip scheme/path/port/whitespace/trailing-dot. Returns ``""`` on a non-str/empty."""
    if not isinstance(raw, str):
        return ""
    d = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0]      # strip path
    # strip an IPv6 literal's brackets before the port split, then the port
    d = d.strip("[]")
    d = d.split(":")[0]      # strip port (safe post-bracket-strip for hostnames)
    return d.rstrip(".")


def is_hard_blocked(domain: str) -> tuple[bool, str]:
    """Deterministic ``(blocked, reason)`` — is this domain a government/military/educational/
    intergovernmental target? No LLM, network, or settings. IP targets are not hard-blocked here
    (an IP has no meaningful TLD); callers gate IPs via the charter + egress denylist instead."""
    d = normalize_domain(domain or "")
    if not d:
        return False, ""
    if d in _EXACT_BLOCKED_DOMAINS:
        return True, (f"'{d}' is a protected intergovernmental organization domain — "
                      "categorically out of scope, permanently blocked.")
    for blocked in _EXACT_BLOCKED_DOMAINS:
        if d.endswith("." + blocked):
            return True, (f"'{d}' is a subdomain of the protected domain '{blocked}' — "
                          "categorically out of scope, permanently blocked.")
    if _COMPILED_TLD_RE.search(d):
        return True, (f"'{d}' belongs to a government, military, educational, or international "
                      "organization TLD — categorically out of scope, permanently blocked.")
    return False, ""


def assert_not_hard_blocked(domain: str) -> None:
    """Raise :class:`HardBlockError` fail-closed if ``domain`` is on the deterministic scope floor.
    Call this BEFORE the charter/gate for any domain target the agent proposes to touch."""
    blocked, reason = is_hard_blocked(domain)
    if blocked:
        raise HardBlockError(reason)
