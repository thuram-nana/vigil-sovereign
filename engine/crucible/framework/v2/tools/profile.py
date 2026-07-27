"""
tools.profile — the unified ToolProfile + the tool-consciousness admission gate (Phase B1).

Per-tool knowledge is split across disjoint sources. This JOINS them, on the host-tool BINARY NAME (the id
that ``tools.registry`` roster keys, the Strix ``skills/tooling/<name>.md`` playbook stems, and the typed
``executor._BUILDERS`` all share), into one profile the operator/agent can reason over:

  * install + live status + binary + version + install_hint  ← :func:`tools.registry.probe_tools`
  * CLI-usage knowledge ("already knows how to use it")       ← a Strix ``tooling/<name>.md`` skill playbook
  * a machine-checkable "we can drive its CLI ourselves"      ← a typed argv builder in the live executor

THE ADMISSION GATE (the operator's rule — "only globally-recognised tools it can fully control via CLI or
background"): a tool is ADMITTED to the arsenal iff it is ``global_recognition`` AND has a ``control_surface``
in {cli, background}. A tool with a binary but no usage knowledge (no skill playbook AND no typed builder) is
REFUSED with an honest reason — the system will not claim to control a tool it has no way to drive. This is
advisory metadata only: it ADVISES what may be adopted/run; every actual execution still passes the WARDEN
gate, and a finding is a FACT only via a fired oracle. Read-only + pure (safe to call on every request).

Two-env boundary: OFFENSE-side (imports the framework roster; the Strix catalog is imported LAZILY so this
module stays import-clean when Strix is absent — then skill-doc knowledge simply reads empty, honestly).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .registry import probe_tools

# The tools the live executor can turn into a validated, gated argv itself (a STRONG "control via CLI"
# proof — VIGIL builds + gates the command). Duplicated from integration.live.executor._BUILDERS to avoid
# a backwards crucible→integration import; a drift-guard test asserts this stays equal to that source.
_TYPED_BUILDER_TOOLS = frozenset({"ffuf", "httpx", "hydra", "nmap", "nuclei", "sqlmap"})

# Globally-recognised tools NOT in the host roster and without a Strix skill doc (net-new curated metadata;
# empty today — the curated host roster + the maintained skill playbooks already are the recognition list).
_EXTRA_RECOGNISED: frozenset = frozenset()


@dataclass(frozen=True)
class ToolProfile:
    """One tool's fused, operator-facing profile. ``admitted``/``admit_reason`` are the consciousness gate's
    verdict; everything else is joined evidence. All advisory — never a fact, never an authorization."""

    name: str
    binary: str = ""
    purpose: str = ""
    # live status (from the host probe; "" / not_in_roster for a Strix-sandbox-only tool)
    status: str = "not_in_roster"
    installed: bool = False
    path: str = ""
    version: str = ""
    install_hint: str = ""
    apt: str = ""
    pip: str = ""
    in_host_roster: bool = False
    # consciousness signals
    has_skill_doc: bool = False        # a Strix tooling/<name>.md CLI playbook exists ("knows how to use it")
    has_typed_builder: bool = False    # the live executor can build a validated, gated argv for it
    control_surface: str = ""          # "cli" | "background" | "" (none → refused)
    global_recognition: bool = False
    admitted: bool = False
    admit_reason: str = ""


def _skill_tooling_names() -> set:
    """The Strix tooling skill-doc stems (the tools with a CLI playbook). Lazy + fail-open-to-empty so the
    framework never hard-depends on Strix; absent Strix ⇒ no skill knowledge (honest, not a crash)."""
    try:
        from strix.skills import get_available_skills
    except Exception:  # noqa: BLE001 — Strix not installed / import error ⇒ no skill docs, honestly
        return set()
    try:
        return {str(n).strip().lower() for n in (get_available_skills().get("tooling") or [])}
    except Exception:  # noqa: BLE001
        return set()


def _control_surface(*, has_skill_doc: bool, has_typed_builder: bool) -> str:
    """How we can drive the tool. A CLI playbook (the model knows the CLI) OR a typed argv builder (we build
    + gate the command) is a genuine CLI control surface. Neither ⇒ "" (no way to control it → refused)."""
    if has_skill_doc or has_typed_builder:
        return "cli"
    return ""


def _admit(global_recognition: bool, control_surface: str) -> tuple[bool, str]:
    """The gate: globally recognised AND a real cli|background control surface. Fail-closed + honest reason."""
    if not global_recognition:
        return False, "refused: not a globally-recognised tool (arsenal is curated, not arbitrary)"
    if control_surface not in ("cli", "background"):
        return False, ("refused: no CLI-usage knowledge — add a skill playbook or a typed argv builder "
                       "before this tool can be driven")
    return True, f"admitted ({control_surface})"


def build_profiles() -> dict:
    """Join every known tool into a ToolProfile and apply the admission gate. Deterministic (sorted by name),
    real-data-only, honest-empty. Returns {profiles:[...], summary:{...}}."""
    roster = {t["name"].strip().lower(): t for t in probe_tools().get("tools", [])}
    skill_docs = _skill_tooling_names()
    names = sorted(set(roster) | skill_docs | set(_TYPED_BUILDER_TOOLS) | set(_EXTRA_RECOGNISED))

    profiles: list[dict] = []
    for name in names:
        t = roster.get(name, {})
        in_roster = name in roster
        has_skill = name in skill_docs
        has_builder = name in _TYPED_BUILDER_TOOLS
        surface = _control_surface(has_skill_doc=has_skill, has_typed_builder=has_builder)
        recognised = in_roster or has_skill or name in _EXTRA_RECOGNISED
        admitted, reason = _admit(recognised, surface)
        profiles.append(asdict(ToolProfile(
            name=name,
            binary=str(t.get("binary", "") or name),
            purpose=str(t.get("purpose", "") or ""),
            status=str(t.get("status", "not_in_roster")) if in_roster else "not_in_roster",
            installed=bool(t.get("installed", False)),
            path=str(t.get("path", "") or ""),
            version=str(t.get("version", "") or ""),
            install_hint=str(t.get("install_hint", "") or ""),
            apt=str(t.get("apt", "") or ""),
            pip=str(t.get("pip", "") or ""),
            in_host_roster=in_roster,
            has_skill_doc=has_skill,
            has_typed_builder=has_builder,
            control_surface=surface,
            global_recognition=recognised,
            admitted=admitted,
            admit_reason=reason,
        )))

    summary = {
        "total": len(profiles),
        "admitted": sum(1 for p in profiles if p["admitted"]),
        "refused": sum(1 for p in profiles if not p["admitted"]),
        "installed": sum(1 for p in profiles if p["installed"]),
        "installable_missing": sum(1 for p in profiles
                                   if p["admitted"] and not p["installed"] and p["install_hint"]),
    }
    return {"profiles": profiles, "summary": summary}
