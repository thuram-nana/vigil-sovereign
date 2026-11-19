"""engage_surface_selectors — APEX PR-1 multi-agent SURFACE DECOMPOSITION over the goal-tree planner.

The autonomous OODA loop (:func:`engage_autonomous.run_autonomous_cycle`) picks its next action with a
SINGLE global selector (``_select`` → the path-aware / lookahead ``GoalTree`` pick). That is myopic across
attack *surfaces*: a cluster of high-prior injection leaves can monopolise the budget while the auth, access-
control and business-logic surfaces are never touched this run — the "forest for one tree" failure the
constitution warns about.

This module is the decomposition: the engagement's open leaves are classified into a fixed set of specialized
surface DOMAINS (recon / auth / injection / access-control / business-logic / ssrf-oob / exploit-chain), and a
stateful :class:`SurfaceSelector` round-robins across the domains that currently have an open leaf, delegating
the WITHIN-domain pick to the EXISTING path-aware ``GoalTree`` scorer (scoped via its ``leaf_filter`` kwarg).
Each domain is one "agent"; ``GoalTree.best_open_leaf_pathaware`` is the shared planner they all reason with.
Nothing here is rebuilt — it is an ordering layer OVER ``_select``.

INVARIANTS it keeps:
  * It only ever chooses WHICH authorized open leaf runs next. It NEVER promotes a finding, changes a verdict,
    or sends a request — every pick is still driven through the fail-closed ``invoke_tool`` gate and
    adjudicated by the oracle. Selection is advisory to the budget, authoritative to nothing.
  * DETERMINISTIC: the domain order is fixed, the round-robin cursor advances by a pure rule, and the within-
    domain pick is the deterministic path-aware scorer — same tree + world ⇒ same pick sequence.
  * Coverage, never gating: a domain with no open leaf is skipped THIS cycle, never removed; when its leaves
    appear (discovery promotes a surface) it re-enters the rotation. No surface is ever gated out.

The classifier is a pure function of ``(label, bug_class, surface)`` — the fields a ``GoalNode`` leaf already
carries — so it needs no world lookup and never raises.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # annotations only — no runtime import (kept light + import-cycle-free)
    from .planner.goal_tree import GoalNode, GoalTree
    from .worldmodel.graph import WorldModel

# The specialized surface domains, in the FIXED rotation order the round-robin visits them. Recon
# (discovery of new surfaces) leads, then the confirm/chain domains from most-common to the exploit-chain
# catch-all. The order is load-bearing ONLY for determinism + a sensible default rotation; it gates nothing.
RECON = "recon"
AUTH = "auth"
INJECTION = "injection"
ACCESS_CONTROL = "access-control"
BUSINESS_LOGIC = "business-logic"
SSRF_OOB = "ssrf-oob"
EXPLOIT_CHAIN = "exploit-chain"

DOMAINS: tuple[str, ...] = (
    RECON, AUTH, INJECTION, ACCESS_CONTROL, BUSINESS_LOGIC, SSRF_OOB, EXPLOIT_CHAIN,
)

# Ordered (domain, substring-tokens) rules; FIRST match wins, so the more specific domains are listed before
# the broad INJECTION bucket. Tokens are matched against the lower-cased bug_class (and a couple of surface
# hints). A reverify leaf that matches nothing falls back to INJECTION (the broadest active-test domain) —
# the fallback only affects rotation order + telemetry, never soundness.
_BUG_CLASS_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Out-of-band / blind-async confirmation surface (PR-2 wires the OOB receiver; here it decomposes).
    (SSRF_OOB, ("ssrf", "oob", "jndi", "log4", "deserial", "xxe", "blind_ssti", "blind-ssti")),
    # Broken access control (object / function level).
    (ACCESS_CONTROL, ("idor", "bola", "bfla", "authz", "authorization", "access_control",
                      "access-control", "privilege", "priv_esc", "privesc", "rbac",
                      "forced_brows", "missing_function", "mass_assignment", "mass-assignment")),
    # Authentication / identity / session.
    (AUTH, ("auth", "jwt", "session", "oauth", "saml", "sso", "login", "credential",
            "password", "mfa", "2fa", "otp")),
    # Business logic / workflow / abuse.
    (BUSINESS_LOGIC, ("business", "logic", "race", "workflow", "price", "quantity",
                      "coupon", "discount", "replay", "rate_limit", "rate-limit", "workflow_bypass")),
    # Explicit chaining / pivot leaves (rare as a leaf bug_class; the chaining PHASE is separate).
    (EXPLOIT_CHAIN, ("chain", "pivot", "exploit_chain", "exploit-chain", "lateral")),
    # In-band injection family (the broadest active-probe surface). Listed LAST so a more specific match wins.
    (INJECTION, ("sqli", "sql_injection", "sql-injection", "nosql", "ldap", "xpath", "ssti",
                 "template_injection", "command", "cmd_injection", "cmdi", "rce", "code_injection",
                 "xss", "redirect", "traversal", "lfi", "rfi", "crlf", "header_injection",
                 "injection", "ssrf_param")),
)

# A leaf whose label starts with this marker is a DISCOVERY probe of an unexplored endpoint (seeded by
# ``_build_goal_tree`` as ``"probe {bug_class} @ {url}"``), so it belongs to the RECON domain regardless of
# the probe's nominal bug class. A reverify leaf is ``"reverify {bug_class} @ {surface}"``.
_PROBE_LABEL_PREFIX = "probe "


def domain_for(label: Any, bug_class: Any, surface: Any) -> str:
    """Classify one goal-tree leaf into its specialized surface domain. Pure, total (never raises), and
    deterministic. A probe-leaf (label begins ``probe ``) is RECON (it discovers a new surface); every other
    leaf is a confirmed finding classified by its ``bug_class`` tokens, defaulting to INJECTION when no rule
    matches. ``surface`` is accepted for future hints and kept in the signature for a stable classifier API."""
    lbl = str(label or "").strip().lower()
    if lbl.startswith(_PROBE_LABEL_PREFIX):
        return RECON
    bc = str(bug_class or "").strip().lower()
    sf = str(surface or "").strip().lower()
    hay = f"{bc} {sf}"
    for domain, tokens in _BUG_CLASS_RULES:
        for tok in tokens:
            if tok in hay:
                return domain
    return INJECTION


def decompose(tree: "GoalTree") -> dict[str, list[int]]:
    """Partition the tree's OPEN leaves into ``{domain: [leaf_id, ...]}`` (leaf ids id-sorted within each
    domain for determinism). Only domains with at least one open leaf appear. Best-effort/total: any trouble
    yields the partition built so far."""
    groups: dict[str, list[int]] = {}
    try:
        leaves = sorted(tree.open_leaves(), key=lambda n: n.id)
    except Exception:
        return groups
    for leaf in leaves:
        try:
            d = domain_for(leaf.label, leaf.bug_class, leaf.surface)
        except Exception:
            d = INJECTION
        groups.setdefault(d, []).append(leaf.id)
    return groups


class SurfaceSelector:
    """A stateful, multi-agent SURFACE-DECOMPOSITION selector drop-in for ``engage_autonomous._select``.

    Call signature matches ``_select`` exactly:
        ``(tree, world, objectives, source, *, lookahead_depth=1, budget=None) -> GoalNode | None``

    Each call: classify the open leaves into domains, then — starting at the round-robin cursor — pick the
    first domain (in :data:`DOMAINS` order) that has an open leaf, delegate the within-domain pick to the
    path-aware ``GoalTree`` scorer scoped to that domain (via ``leaf_filter``), advance the cursor PAST the
    chosen domain, and return the leaf. So across cycles the loop sweeps surfaces round-robin instead of
    draining one high-prior cluster. Deterministic: fixed order, pure cursor rule, deterministic within-domain
    pick. Returns None only when there is no open leaf at all (the loop then stops)."""

    def __init__(self, domain_order: "tuple[str, ...] | None" = None) -> None:
        self._order: tuple[str, ...] = tuple(domain_order) if domain_order else DOMAINS
        self._cursor: int = 0

    # Exposed so ``run_autonomous_cycle`` can record per-domain telemetry for the leaf it picked.
    def domain_for(self, label: Any, bug_class: Any, surface: Any) -> str:
        return domain_for(label, bug_class, surface)

    def _pick_in_domain(
        self, tree: "GoalTree", world: "WorldModel | None", objectives: list, source: "str | None",
        ids: set, lookahead_depth: int, budget: "int | None",
    ) -> "GoalNode | None":
        """The WITHIN-domain pick: the existing path-aware scorer, scoped to this domain's leaf ids. Degrades
        exactly like ``_select`` (greedy when no world / objective / reachable crown jewel), and never raises —
        a scorer error falls back to the greedy scoped pick, then to None."""
        flt = lambda n: n.id in ids  # noqa: E731 — a tiny scoping predicate is clearer inline
        try:
            return tree.best_open_leaf_pathaware(
                world=world, objective_kinds=objectives or None, source=source, leaf_filter=flt)
        except Exception:
            try:
                return tree.best_open_leaf(leaf_filter=flt)
            except Exception:
                return None

    def __call__(
        self, tree: "GoalTree", world: "WorldModel | None", objectives: list, source: "str | None",
        *, lookahead_depth: int = 1, budget: "int | None" = None,
    ) -> "GoalNode | None":
        groups = decompose(tree)
        if not groups:
            return None   # no open leaves — the loop stops
        n = len(self._order)
        for i in range(n):
            domain = self._order[(self._cursor + i) % n]
            ids = groups.get(domain)
            if ids:
                leaf = self._pick_in_domain(
                    tree, world, objectives, source, set(ids), lookahead_depth, budget)
                # advance PAST the chosen domain so the next cycle starts at the following surface
                self._cursor = (self._cursor + i + 1) % n
                if leaf is not None:
                    return leaf
                # a domain that could not yield a concrete leaf (should not happen for a non-empty id set):
                # fall through to the next domain in this same cycle rather than stalling.
        # every present domain failed to yield a leaf (pathological) — last resort, the global greedy pick.
        try:
            return tree.best_open_leaf()
        except Exception:
            return None
