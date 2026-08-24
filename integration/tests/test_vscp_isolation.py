"""VSCP isolation proof — the LOAD-BEARING, CI-ENFORCED acceptance for W13-7 (#500).

This file runs in the REQUIRED ``integration two-env boundary (P5)`` job (it lives under
``integration/tests`` and is collected by that job's sovereign leg — it is framework-free
and imports nothing offense-side, so it neither ``importorskip``s ``framework`` nor is it
``--ignore``d). It puts the sibling ``vscp/`` project dir on ``sys.path`` itself (VSCP is a
SIBLING app, not an ``integration`` submodule) and proves the four-part programme bar:

  (a) VSCP is a sibling folder with its OWN runtime, deps, migrations and CI;
  (b) ISOLATION: separate DB + credentials, NO import path to assessment findings,
      isolated signing — each with a negative control proving the check is not a no-op;
  (c) a VSCP attempt to read an assessment finding is REFUSED, and a reviewer write is
      REFUSED;
  (d) reviewer roles are read-only, asserted per route.

The isolation checks reuse the SAME functions the VSCP package ships
(``vscp.isolation`` / ``vscp.config`` / ``vscp.rbac_routes`` / ``vscp.findings_boundary``),
so this proof and VSCP's own suite cannot drift.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_VSCP_PROJECT = _REPO / "vscp"
_VSCP_PKG = _VSCP_PROJECT / "vscp"

# VSCP is a sibling application; put its project dir on the path so `import vscp` resolves.
if str(_VSCP_PROJECT) not in sys.path:
    sys.path.insert(0, str(_VSCP_PROJECT))

# vigil_core is VSCP's one dependency; it is installed in P5. If (only locally) it is not
# importable, skip rather than error — the required CI job always has it.
pytest.importorskip("vigil_core", reason="vigil_core (VSCP's one dep) not importable here")

from vscp import config as vscp_config  # noqa: E402
from vscp import findings_boundary as fb  # noqa: E402
from vscp import isolation as iso  # noqa: E402
from vscp import rbac_routes as routes  # noqa: E402
from vscp.authorization import PermissionRefused, authorize_action  # noqa: E402


# ==========================================================================================
# (a) VSCP is a SIBLING FOLDER with its OWN runtime / deps / migrations / CI
# ==========================================================================================
def test_vscp_is_a_sibling_folder_with_its_own_runtime_deps_migrations_and_ci():
    assert _VSCP_PROJECT.is_dir(), "vscp/ sibling folder must exist"
    assert (_VSCP_PROJECT / "pyproject.toml").is_file(), "VSCP must have its OWN pyproject (deps/runtime)"
    assert (_VSCP_PKG / "__init__.py").is_file(), "the vscp package must exist"
    migrations = sorted((_VSCP_PKG / "migrations").glob("*.sql"))
    assert migrations, "VSCP must ship its OWN migrations"
    assert (_REPO / ".github" / "workflows" / "vscp-ci.yml").is_file(), "VSCP must have its OWN CI workflow"

    # OWN deps: the pyproject depends only on vigil-core (the shared offense-free substrate),
    # never on the offense seam / engine / agent / sovereign core.
    pyproject = (_VSCP_PROJECT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dependencies = ["vigil-core"]' in pyproject
    for forbidden in ("vigil-integration", "framework", "strix", "sigil"):
        assert f'"{forbidden}"' not in pyproject, f"VSCP must not depend on {forbidden!r}"


# ==========================================================================================
# (b) ISOLATION — separate DB + credentials, no import path to findings, isolated signing
# ==========================================================================================
def test_no_import_path_to_assessment_findings():
    """Every VSCP source file imports only stdlib / vigil_core / vscp — never framework,
    strix, sigil, or vigil_integration (whose __init__ pulls in assessment-finding code)."""
    violations = iso.scan_tree_for_import_violations(_VSCP_PKG)
    assert violations == [], f"VSCP has forbidden/off-allowlist imports: {violations}"
    # Sanity: the scan actually looked at real files.
    assert sum(1 for _ in _VSCP_PKG.rglob("*.py")) >= 8


def test_import_scanner_is_not_a_no_op_negative_control(tmp_path):
    """NEGATIVE CONTROL: the scanner catches a forbidden import. A synthetic module that
    imports `framework` (the assessment engine) is flagged by the same functions."""
    assert iso.classify_import_root("os") is None  # stdlib is fine
    assert iso.classify_import_root("vigil_core") is None  # the allowed substrate
    for forbidden in ("framework", "strix", "sigil", "vigil_integration"):
        assert iso.classify_import_root(forbidden) is not None, forbidden
    # off-allowlist external dep is also refused (fail-closed allowlist)
    assert iso.classify_import_root("requests") is not None
    assert iso.find_forbidden_import("from framework.v2 import findings") == "framework"
    # a real scan over a planted bad file flags it
    bad = tmp_path / "vscp"
    bad.mkdir()
    (bad / "leak.py").write_text("import framework.v2.blackboard as bb\n", encoding="utf-8")
    found = iso.scan_tree_for_import_violations(bad)
    assert any(v.root == "framework" for v in found), found


def test_separate_db_and_credentials(tmp_path, monkeypatch):
    """VSCP's db and signing key resolve OUTSIDE every product data root."""
    monkeypatch.setenv("VSCP_HOME", str(tmp_path / "vscp-home"))
    cfg = vscp_config.VscpConfig.resolve()
    roots = vscp_config.product_data_roots()
    assert roots, "product data roots must be enumerated"
    for path in (cfg.db_path, cfg.signing_key_path, cfg.data_dir):
        for root in roots:
            assert not path.is_relative_to(root) and path != root, f"{path} overlaps product root {root}"
    # DB and signing key are VSCP-owned, under the VSCP data dir.
    assert cfg.db_path.is_relative_to(cfg.data_dir)
    assert cfg.signing_key_path.is_relative_to(cfg.data_dir)


def test_config_refuses_overlap_with_product_data_root_negative_control(tmp_path, monkeypatch):
    """NEGATIVE CONTROL: pointing VSCP state at a product data plane is REFUSED fail-closed.

    Uses the env-driven product-root resolution so the check is hermetic: set the offense
    plane (VIGIL_BASE_DIR) to a temp dir, then a VSCP data dir INSIDE it must be refused,
    while one OUTSIDE it is accepted (proving the guard is discriminating, not blanket)."""
    product_plane = tmp_path / "product-live"
    monkeypatch.setenv("VIGIL_BASE_DIR", str(product_plane))
    with pytest.raises(vscp_config.VscpIsolationError):
        vscp_config.VscpConfig.resolve(data_dir=str(product_plane / "vscp"))
    # a signing key pointed at the product plane is likewise refused
    with pytest.raises(vscp_config.VscpIsolationError):
        vscp_config.VscpConfig.resolve(
            data_dir=str(tmp_path / "ok-home"),
            signing_key_path=str(product_plane / "keystore" / "owner.key"),
        )
    # a disjoint layout is accepted — the guard is not a blanket refusal
    ok = vscp_config.VscpConfig.resolve(data_dir=str(tmp_path / "ok-home"))
    assert ok.data_dir == (tmp_path / "ok-home").resolve()

    # And the default sovereign/host planes are refused too (independent of the env above).
    monkeypatch.delenv("VIGIL_BASE_DIR", raising=False)
    with pytest.raises(vscp_config.VscpIsolationError):
        vscp_config.VscpConfig.resolve(data_dir="~/.sigil/vscp")


# ==========================================================================================
# (c) a VSCP finding read is REFUSED; a reviewer WRITE is REFUSED
# ==========================================================================================
def test_reading_an_assessment_finding_is_refused():
    with pytest.raises(fb.FindingsAccessDenied):
        fb.read_assessment_finding("any-finding-id")
    # the boundary gate denies a request that references a finding, and allows one that does not
    assert fb.finding_boundary_gate({"finding_id": "F1"}).allow is False
    assert fb.finding_boundary_gate({"deployment_id": "d1"}).allow is True


def test_reviewer_write_is_refused_but_operator_is_allowed(tmp_path, monkeypatch):
    """(c) reviewer WRITE refused. The verdict comes from the RBAC-of-record via the facade;
    the operator positive proves the gate is not blanket-deny."""
    reviewer = authorize_action(role=routes.REVIEWER_ROLE, action="issue_authorization")
    assert reviewer.allowed is False and reviewer.denied_by == "rbac"
    operator = authorize_action(role="operator", action="issue_authorization")
    assert operator.allowed is True and operator.denied_by is None

    # And at the store level, against a REAL (isolated, temp) VSCP database: a reviewer
    # cannot register a deployment; an operator can.
    from vscp.registries import DeploymentRegistry
    from vscp.store import open_store

    monkeypatch.setenv("VSCP_HOME", str(tmp_path / "vscp-home"))
    cfg = vscp_config.VscpConfig.resolve()
    cfg.ensure_data_dir()
    with open_store(cfg) as store:
        reg = DeploymentRegistry(store)
        with pytest.raises(PermissionRefused):
            reg.register(role=routes.REVIEWER_ROLE, id="d1", name="edge", environment="production")
        made = reg.register(role="operator", id="d1", name="edge", environment="production")
        assert made.id == "d1" and [d.id for d in reg.list()] == ["d1"]


# ==========================================================================================
# (d) reviewer roles are READ-ONLY, asserted PER ROUTE
# ==========================================================================================
def test_reviewer_is_read_only_per_route():
    errors = routes.reviewer_readonly_report()
    assert errors == [], f"reviewer read-only violated on some route(s): {errors}"
    # spot-check both directions
    assert routes.reviewer_can_route("GET", "/vscp/deployments") is True
    assert routes.reviewer_can_route("POST", "/vscp/deployments") is False
    assert routes.reviewer_can_route("POST", "/vscp/authorizations") is False
    assert routes.reviewer_can_route("POST", "/vscp/authorizations/abc/revoke") is False
    # DEFAULT-DENY: an unmapped route refuses every role including owner
    assert routes.route_required_permission("POST", "/vscp/unknown") is None
    assert routes.role_can_route("owner", "POST", "/vscp/unknown") is False


def test_reviewer_readonly_report_is_not_a_no_op_negative_control(monkeypatch):
    """NEGATIVE CONTROL: the per-route reviewer-read-only check CATCHES a bad mapping.

    Inject a mutating route mapped to READ (so a reviewer could reach it); the report must
    become non-empty. Restored automatically by monkeypatch."""
    bad = dict(routes.ROUTE_PERMISSIONS)
    bad[("POST", "/vscp/oops-writable-by-reviewer")] = routes.READ
    monkeypatch.setattr(routes, "ROUTE_PERMISSIONS", bad)
    report = routes.reviewer_readonly_report()
    assert any("oops-writable-by-reviewer" in e for e in report), report
