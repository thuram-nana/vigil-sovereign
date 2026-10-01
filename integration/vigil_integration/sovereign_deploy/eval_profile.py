"""
vigil_integration.sovereign_deploy.eval_profile — the per-org investor-evaluation DEPLOYMENT CONFIG (INV3).

The eval-lab runs VIGIL at FULL product-path capability for each investor org, in HARD per-org isolation.
Two product-path switches are DEFAULT-OFF for safety and must be turned ON *by the deployment* (never by a
code default), and one entitlement must be PROVISIONED, before that deployment is honestly "production-on":

  1. **Family re-drive FACT-mint** — a FACT-capable discovery family (network / web / TLS / DOM) only becomes
     ELIGIBLE for VIGIL's own runner-owned re-drive when the ``VIGIL_FAMILY_REDRIVE`` flag is set AND the
     engage runs with the propose-only ``--brain hexstrike`` decision brain. The flag never mints by itself —
     it merely lets the SEPARATE, gated, admit()-crossing re-drive run (see
     :mod:`vigil_integration.live.oracle_families`). Default-off ⇒ routing emits LEADs only.
  2. **AEGIS active enforcement** — the inline Gateway blocks a PROVEN attack (403 + a re-runnable
     certificate) ONLY under ``--mode enforce`` AND only once the ``AEGIS_RESPOND`` capability is provisioned
     in the governed deployment. Without the grant the gateway HONESTLY downgrades to observe (it reports the
     downgrade; it is never silent) — so the eval deployment must provision the entitlement, or the firewall
     is read-only.

This module is the SINGLE SOURCE OF TRUTH for "what the control plane sets to turn the product path on" — the
env the per-org VM/sandbox exports, the engage flags that drive FACT-mint, and the capabilities that MUST be
provisioned. It makes NO policy of its own and verifies NOTHING: the entitlement decision stays in
``framework.v2.entitlement.policy`` (engine side) and the egress floor / isolation stay where they are. It
only declares + honestly reports configuration, so a WS3 control plane and a readiness probe read one place.

Import-clean (FATAL-2): stdlib + ``vigil_core`` + the framework-free ``live.oracle_families`` only — NOTHING
from ``framework`` / ``strix`` / ``sigil``, so it loads in the sovereign process and holds no owner key. The
AEGIS_RESPOND grant itself is an owner-key ceremony performed out of band (``framework.v2.entitlement``
provisioning on the SIGIL side); this module names the requirement, it does not sign it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

from ..live.oracle_families import FAMILY_REDRIVE_FLAG, redrive_flag_enabled

__all__ = [
    "FAMILY_REDRIVE_FLAG",
    "AEGIS_MODE_ENV",
    "ENTITLEMENT_ENFORCED_ENV",
    "EVAL_BRAIN",
    "REQUIRED_CAPABILITIES",
    "EvalReadiness",
    "production_env",
    "engage_fact_mint_flags",
    "fact_mint_enabled",
    "aegis_enforce_requested",
    "assess_readiness",
]

# The env names the eval deployment sets, mirrored from where each is READ so the config cannot drift from
# its consumer: the FACT-mint flag is read by ``live.oracle_families.redrive_flag_enabled``; the AEGIS mode
# by ``aegis.cli`` (``AEGIS_GW_MODE``); governed enforcement by ``framework.v2.entitlement.policy``
# (``CRUCIBLE_ENTITLEMENT_ENFORCED``). We reference the literal strings for the two engine-side ones (the
# engine must not be imported here); FAMILY_REDRIVE_FLAG is re-exported from its real definition.
AEGIS_MODE_ENV = "AEGIS_GW_MODE"
ENTITLEMENT_ENFORCED_ENV = "CRUCIBLE_ENTITLEMENT_ENFORCED"

# The propose-only decision brain the product-path engage uses (drives the family re-drive that is eligible to
# mint once the flag is on). Passed as ``--brain <EVAL_BRAIN>``.
EVAL_BRAIN = "hexstrike"

# Capabilities that MUST be provisioned (owner-signed, out of band) for the eval deployment to operate at the
# advertised capability. AEGIS_RESPOND is the one INV3 turns on: without it, enforce is read-only. Named as a
# plain string (the engine's ``Capability.AEGIS_RESPOND.value``) to keep this module framework-free.
REQUIRED_CAPABILITIES: tuple[str, ...] = ("aegis_respond",)

# Truthy env value for the boolean switches we SET (kept consistent with oracle_families' own truthy set).
_ON = "1"


def _env(env: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    return os.environ if env is None else env


def production_env() -> dict[str, str]:
    """The env the per-org eval control plane exports into a VM/sandbox to make the product path
    "production-on": family re-drive FACT-mint ELIGIBLE, the AEGIS Gateway in enforce mode, and governed
    entitlement enforcement ACTIVE (so AEGIS_RESPOND is a REAL gate, not a permissive ungoverned default).

    This is only half the contract — the other half is PROVISIONING :data:`REQUIRED_CAPABILITIES` via the
    owner-key entitlement ceremony; this env turns the switches on, the grant makes enforce actually block.
    Returns a fresh dict each call (never a shared mutable)."""
    return {
        FAMILY_REDRIVE_FLAG: _ON,          # FACT-mint re-drive ELIGIBLE (the gated re-drive still mints)
        AEGIS_MODE_ENV: "enforce",          # the Gateway blocks PROVEN attacks (needs AEGIS_RESPOND granted)
        ENTITLEMENT_ENFORCED_ENV: _ON,      # governed: AEGIS_RESPOND is a real, fail-closed gate
    }


def engage_fact_mint_flags() -> list[str]:
    """The engage CLI flags that drive FACT-mint on the product path: ``--brain hexstrike``. The brain
    PROPOSES the chain; the engine gates it; VIGIL's own gated re-drive (eligible only when
    :data:`FAMILY_REDRIVE_FLAG` is on) is the sole thing that can mint, crossing ``verdict.admit()``."""
    return ["--brain", EVAL_BRAIN]


def fact_mint_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """HONEST check: is family re-drive FACT-mint actually ELIGIBLE in this env? Delegates to the SAME
    predicate the routing layer reads (``redrive_flag_enabled``) so the config and the gate agree — a
    deployment that forgot to export the flag reports False here, never a false "on"."""
    return redrive_flag_enabled(_env(env))


def aegis_enforce_requested(env: Optional[Mapping[str, str]] = None) -> bool:
    """Whether the deployment env ASKS the Gateway to enforce (``AEGIS_GW_MODE=enforce``). Whether it will
    actually block additionally requires the AEGIS_RESPOND grant — that is the engine-side
    ``GatewaySettings.enforcement_status()`` call's job to report, never this module's to assume."""
    return str(_env(env).get(AEGIS_MODE_ENV, "")).strip().lower() == "enforce"


@dataclass(frozen=True)
class EvalReadiness:
    """A deployment-config readiness snapshot (configuration only — NOT an entitlement verdict). ``ready`` is
    True iff every product-path switch this module owns is on; ``missing`` names each switch that is not, so a
    control plane fails LOUD on a half-configured deployment instead of shipping a silently-degraded one. It
    deliberately does NOT assert the AEGIS_RESPOND grant is present (that is the engine's signed check) — it
    reports that the grant is still REQUIRED, so the reader knows to provision it out of band."""

    fact_mint_eligible: bool
    aegis_enforce_requested: bool
    governed_enforcement_active: bool
    required_capabilities: tuple[str, ...]
    missing: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.missing


def assess_readiness(env: Optional[Mapping[str, str]] = None) -> EvalReadiness:
    """Report, honestly and machine-readably, which product-path switches the eval deployment has turned on.
    Pure over the given env (defaults to ``os.environ``); makes no network/entitlement call. ``missing`` lists
    the switches a control plane still has to set; the AEGIS_RESPOND grant remains a separate, owner-signed
    requirement surfaced via :data:`REQUIRED_CAPABILITIES`."""
    e = _env(env)
    fm = redrive_flag_enabled(e)
    enforce = str(e.get(AEGIS_MODE_ENV, "")).strip().lower() == "enforce"
    governed = str(e.get(ENTITLEMENT_ENFORCED_ENV, "")).strip().lower() in {"1", "true", "yes", "on"}
    missing: list[str] = []
    if not fm:
        missing.append(f"{FAMILY_REDRIVE_FLAG} (family re-drive FACT-mint not eligible)")
    if not enforce:
        missing.append(f"{AEGIS_MODE_ENV}=enforce (AEGIS Gateway not in enforce mode)")
    if not governed:
        missing.append(f"{ENTITLEMENT_ENFORCED_ENV} (entitlement enforcement inactive — "
                       f"AEGIS_RESPOND would be permissively granted, not a real gate)")
    return EvalReadiness(
        fact_mint_eligible=fm,
        aegis_enforce_requested=enforce,
        governed_enforcement_active=governed,
        required_capabilities=REQUIRED_CAPABILITIES,
        missing=tuple(missing),
    )
