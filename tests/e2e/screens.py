"""Coverage-matrix SCAFFOLD for the 35 VIGIL UI screens.

Wave-3 agents fill `controls` per screen and write per-screen suites
(`test_<id>.py`) that drive each control and assert the real backend call with
`helpers.assert_calls`, tagging each test `real_flow` or `assert_gate`
(README §7).

Grounded in packages/vigil-ui/app.js NAV (line 107) + renderLoginGate (line 333).
Hash route = "#/<id>" under the sovereign mount, i.e.
    <base_url>/sovereign/#/<id>
`login` is the pre-auth gate (no nav id; shown when whoami is unauthenticated).

Each SCREEN carries:
  id       -- the nav id / hash route segment ("#/<id>")
  group    -- DO | MANAGE | LEARN | (login = AUTH)
  gated    -- owner/permission gated in NAV (app.js owner:/perm:); such screens
              need an owner `authed_page` and generally host `assert_gate` controls
  perm     -- the NAV `perm:` string when present (the server-enforced permission)
  flow     -- default discipline marker for this screen's controls:
              "real_flow" (reads/MERIDIAN detection/proof) or
              "assert_gate" (destructive/offense — assert the gate, never fire)
  controls -- TODO list of named controls Wave 3 must cover (button label /
              action), each paired with the backend call it must fire.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Screen:
    id: str
    group: str
    flow: str = "real_flow"            # default discipline marker
    gated: bool = False
    perm: str | None = None
    controls: tuple[str, ...] = field(default_factory=tuple)

    @property
    def hash_route(self) -> str:
        return f"#/{self.id}"


def path(screen: "Screen") -> str:
    """The hash route under the sovereign mount, e.g. '/sovereign/#/home'."""
    return f"/sovereign/{screen.hash_route}"


# ── AUTH ────────────────────────────────────────────────────────────────────
SCREENS: tuple[Screen, ...] = (
    Screen("login", "AUTH", flow="real_flow", controls=(
        "TODO: bearer sign-in submit -> POST /sovereign/api/login {token}",
        "TODO: optional TOTP code field accepted alongside token",
        "TODO: SSO button (if oidc) -> navigates /sovereign/api/oidc/login",
        "TODO: passkey sign-in (if WebAuthn) -> POST /sovereign/api/login {challenge,signature}",
    )),

    # ── DO ────────────────────────────────────────────────────────────────
    Screen("home", "DO", controls=(
        "TODO: dashboard load -> GET /sovereign/api/snapshot and/or /offense/api/status",
        "TODO: 'New Assessment' CTA -> navigates #/assess",
        "TODO: safety state chip -> navigates #/safety",
    )),
    Screen("assess", "DO", controls=(
        "TODO: start codebase scan -> POST /offense start-run",
        "TODO: start website scan (MERIDIAN :19010 target) -> POST /offense start-run",
        "TODO: live-target / external URL -> ASSERT GATE (charter/scope ceremony) [assert_gate]",
    )),
    Screen("chat", "DO", controls=(
        "TODO: send message -> POST /offense chat",
        "TODO: slash command (/findings,/report) -> navigates target screen",
        "TODO: approval-required tool call -> ASSERT GATE (approval demanded) [assert_gate]",
    )),
    Screen("terminal", "DO", controls=(
        "TODO: run command -> POST /offense terminal.run (gated)",
        "TODO: history load -> GET /offense/api/terminal/history",
        "TODO: destructive/offense command -> ASSERT GATE [assert_gate]",
    )),
    Screen("live", "DO", controls=(
        "TODO: live spine feed -> SSE /offense events (?token=)",
        "TODO: run scope ?run= -> GET /offense/api/runs",
    )),
    Screen("strix", "DO", flow="assert_gate", gated=False, controls=(
        "TODO: strix control panel load -> GET /offense strix status",
        "TODO: launch weaponized/offense action -> ASSERT GATE (gated, LEAD-only) [assert_gate]",
    )),
    Screen("findings", "DO", controls=(
        "TODO: findings list -> GET /offense/api/report/<run> or findings",
        "TODO: evidence tab -> GET /offense/api/evidence/<...>",
    )),
    Screen("proof", "DO", controls=(
        "TODO: proof list -> GET /offense/api/proof/<run>",
        "TODO: run proof/replay for real (MERIDIAN) -> POST /offense proof [real_flow]",
    )),
    Screen("report", "DO", controls=(
        "TODO: report render -> GET /offense/api/report/<run>",
        "TODO: dossier download -> GET /offense ...?token= (authUrl)",
    )),
    Screen("fixes", "DO", flow="assert_gate", controls=(
        "TODO: fix plan load -> GET /offense/api/remediate/<run>",
        "TODO: apply/autopatch (destructive PR) -> ASSERT GATE (m-of-n / approval) [assert_gate]",
    )),
    Screen("defense", "DO", controls=(
        "TODO: AEGIS status -> GET /offense/api/aegis/status",
    )),
    Screen("replay", "DO", controls=(
        "TODO: replay a signed proof bundle -> POST /offense replay [real_flow]",
    )),

    # ── MANAGE ──────────────────────────────────────────────────────────────
    Screen("library", "MANAGE", controls=(
        "TODO: engagements list -> GET /offense/api/engagements",
        "TODO: open engagement -> GET /offense/api/library/<slug>",
    )),
    Screen("sessions", "MANAGE", controls=(
        "TODO: sessions list -> GET /offense/api/sessions",
    )),
    Screen("activity", "MANAGE", controls=(
        "TODO: activity feed -> SSE/GET /offense events",
    )),
    Screen("safety", "MANAGE", flow="assert_gate", gated=True, perm="approve_a2", controls=(
        "TODO: pending approvals list -> GET /offense/api/approvals/<...>",
        "TODO: KILL-SWITCH trip -> ASSERT GATE (confirm/ceremony demanded, NOT fired) [assert_gate]",
        "TODO: panic -> ASSERT GATE [assert_gate]",
        "TODO: approve an A2 action -> ASSERT GATE (owner approval demanded) [assert_gate]",
    )),
    Screen("charter", "MANAGE", flow="assert_gate", gated=True, perm="manage_users", controls=(
        "TODO: charter status -> GET /offense/api/charter/<slug>",
        "TODO: attest/sign charter -> ASSERT GATE (owner signature ceremony) [assert_gate]",
    )),
    Screen("apikeys", "MANAGE", flow="assert_gate", gated=True, perm="secrets", controls=(
        "TODO: keys status -> GET /sovereign/api/settings (keys_failing)",
        "TODO: set/rotate key -> ASSERT GATE (secrets permission / confirm) [assert_gate]",
    )),
    Screen("tools", "MANAGE", controls=(
        "TODO: tool catalogue -> GET /offense/api/tools",
        "TODO: tool profiles -> GET /offense/api/toolprofiles",
    )),
    Screen("brain", "MANAGE", controls=(
        "TODO: brain tabs -> GET /offense/api/brain/decision?run=<...>",
    )),
    Screen("mcp", "MANAGE", controls=(
        "TODO: MCP capabilities -> GET /offense/api/mcp",
    )),
    Screen("system", "MANAGE", controls=(
        "TODO: readiness/services -> GET /offense/api/services and/or /offense/api/status",
        "TODO: start offense plane -> POST /__vigil/plane/offense/start (proxy-local, gated)",
    )),
    Screen("durability", "MANAGE", flow="assert_gate", gated=True, perm="secrets", controls=(
        "TODO: durability status -> GET /sovereign durability",
        "TODO: backup/restore/destroy -> ASSERT GATE [assert_gate]",
    )),
    Screen("ceremonies", "MANAGE", flow="assert_gate", gated=True, perm="config_nonsecret", controls=(
        "TODO: ceremony list -> GET /sovereign ceremonies",
        "TODO: run a signed ceremony -> ASSERT GATE (owner signature demanded) [assert_gate]",
        "TODO: destruction-quorum (m-of-n) -> ASSERT GATE [assert_gate]",
    )),
    Screen("budgets", "MANAGE", controls=(
        "TODO: token budgets -> GET /offense/api/token-budgets",
    )),
    Screen("compliance", "MANAGE", controls=(
        "TODO: compliance view -> GET /offense/api/compliance/<...>",
    )),
    Screen("assurance", "MANAGE", controls=(
        "TODO: telemetry/assurance -> GET /offense/api/telemetry",
    )),
    Screen("settings", "MANAGE", flow="assert_gate", gated=True, perm="config_nonsecret", controls=(
        "TODO: settings read -> GET /sovereign/api/settings",
        "TODO: change sovereignty tier / config -> ASSERT GATE (config_nonsecret, confirm) [assert_gate]",
    )),
    Screen("users", "MANAGE", flow="assert_gate", gated=True, perm="manage_users", controls=(
        "TODO: accounts list -> GET /sovereign accounts",
        "TODO: create/revoke account -> ASSERT GATE (owner-signed) [assert_gate]",
        "TODO: enroll passkey/TOTP -> ASSERT GATE [assert_gate]",
    )),
    Screen("governance", "MANAGE", controls=(
        "TODO: governance/gate audit -> GET /offense/api/governance",
    )),

    # ── LEARN ─────────────────────────────────────────────────────────────
    Screen("trust", "LEARN", controls=(
        "TODO: trust-center certs -> GET /offense/api/certs",
    )),
    Screen("posture", "LEARN", controls=(
        "TODO: proof-of-posture -> GET /offense/api/posture",
    )),
    Screen("manual", "LEARN", controls=(
        "TODO: manual renders (static, no backend call expected)",
    )),
    Screen("knowledge", "LEARN", controls=(
        "TODO: knowledge engine -> GET /offense knowledge/intel",
    )),
)

# Invariants Wave 3 (and a meta-test) can assert against.
EXPECTED_COUNT = 35
SCREEN_IDS = tuple(s.id for s in SCREENS)
BY_ID = {s.id: s for s in SCREENS}

assert len(SCREENS) == EXPECTED_COUNT, f"expected {EXPECTED_COUNT} screens, have {len(SCREENS)}"
assert len(SCREEN_IDS) == len(set(SCREEN_IDS)), "duplicate screen id"
