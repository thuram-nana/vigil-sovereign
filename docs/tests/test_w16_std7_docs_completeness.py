"""W16-STD-7 (#533) — the documentation must cover the WHOLE command surface, ship the missing
chapters (INDEX / GLOSSARY / HTTP-API), surface the public-sector licensing exclusion where a buyer
sees it, and hold the re-derived doc-vs-code drifts corrected.

WHY THIS TEST EXISTS. ``test_briefing_documents_every_subcommand.py`` already pins the CRUCIBLE plane
(the 32 ``_DISPATCH`` subcommands + the 38 ``framework/v2`` sub-packages). But the acceptance criteria for
W16-STD-7 name ~78 subcommands: they include the ``vigil`` super-CLI's OWN verbs (the argparse sub-parsers
of ``integration/vigil_integration/cli.py`` — 41 of them) and the passthrough verbs that route into a
subsystem (``dispatch.py`` ``PASSTHROUGH_VERBS`` — 5). Those were listed in NO chapter. They are now in
``docs/CLI-REFERENCE.md`` §C/§D, and this test keeps that true of the code in BOTH directions:

  * FORWARD (a new one turns it red): every ``vigil`` native verb the code declares, and every passthrough
    verb, must be documented as ``vigil <verb>``.
  * REVERSE (the docs cannot describe a verb the code lacks): every ``vigil <verb>`` the §C/§D tables list
    must be a real sub-parser or passthrough verb — the negative-control direction the criteria name.

It also pins the three new chapters and the licensing surface, each from the CODE / FILESYSTEM so they
cannot silently drift:

  * The HTTP API chapter (``docs/HTTP-API.md``) documents EXACTLY the routes ``api/server.py`` serves —
    forward AND reverse.
  * The docs INDEX (``docs/INDEX.md``) links EVERY top-level ``docs/*.md`` — forward (a new doc must appear)
    AND reverse (a link must resolve).
  * The GLOSSARY (``docs/GLOSSARY.md``) defines a floor set of the core terms the rest of the docs use.
  * The public-sector licensing exclusion is surfaced NEAR THE TOP of the README, in the buyer-facing pilot
    runbook, and in LICENSING.md — not buried.
  * The re-derived §-drift batch (6 further doc-vs-code drifts found by auditing README/AS-BUILT vs the
    code) stays corrected: forbidden false phrases gone, corrected anchors present, cited code facts true.

Files only — ``ast`` + ``re`` + ``pathlib``, no import of either trust domain, no tool run, no packet — so
it is correct in the docs-only ``the briefing explains every agent and capability`` required CI job (which
installs only pytest and reads files).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"

CLI = REPO / "integration" / "vigil_integration" / "cli.py"
DISPATCH = REPO / "integration" / "vigil_integration" / "dispatch.py"
API_SERVER = REPO / "engine" / "crucible" / "framework" / "v2" / "api" / "server.py"
MODELS = REPO / "engine" / "crucible" / "framework" / "v2" / "verify" / "models.py"
SANDBOX = REPO / "integration" / "vigil_integration" / "live" / "sandbox_exec.py"
TIMERS_DIR = REPO / "infra" / "systemd"
TEST_ENGINE = REPO / "integration" / "tests" / "test_engine.py"
TEST_ENGINE_LIVE = REPO / "integration" / "tests" / "test_engine_live.py"

CLI_REF = DOCS / "CLI-REFERENCE.md"
HTTP_API = DOCS / "HTTP-API.md"
INDEX = DOCS / "INDEX.md"
GLOSSARY = DOCS / "GLOSSARY.md"
README = REPO / "README.md"
PILOT = DOCS / "pilot" / "README.md"
LICENSING = REPO / "LICENSING.md"
AS_BUILT = DOCS / "AS-BUILT.md"
AS_BUILT_LIVE = DOCS / "AS-BUILT-LIVE.md"


def _read(p: Path) -> str:
    assert p.is_file(), f"file missing: {p}"
    return p.read_text(encoding="utf-8")


def _collapsed(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _has(path: Path, phrase: str) -> bool:
    return _collapsed(phrase) in _collapsed(_read(path))


# ==================================================================================================
# 1. The vigil command surface (native verbs + passthrough verbs), read FROM THE CODE.
# ==================================================================================================
def vigil_native_verbs(cli_src: str) -> set[str]:
    """The top-level ``vigil`` verbs: every ``sub.add_parser("name", ...)`` in cli.py, where ``sub`` is the
    top-level sub-parsers object (nested sub-parsers use other receiver names), resolved by AST."""
    tree = ast.parse(cli_src)
    verbs: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_parser"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "sub"
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            verbs.add(node.args[0].value)
    return verbs


def passthrough_verbs(dispatch_src: str) -> set[str]:
    """The keys of the ``_ENV`` dict in dispatch.py (== ``PASSTHROUGH_VERBS``), resolved by AST."""
    tree = ast.parse(dispatch_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_ENV" for t in node.targets):
            if isinstance(node.value, ast.Dict):
                return {k.value for k in node.value.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    raise AssertionError("could not find the _ENV dict literal in dispatch.py")


def documented_vigil_verbs(doc: str) -> set[str]:
    """Every ``vigil <verb>`` documented in the backtick form (a single verb token)."""
    return set(re.findall(r"`vigil ([a-z][a-z0-9-]*)`", doc))


def _section(text: str, start_prefix: str, end_prefix: str) -> str:
    """The lines from the first header line starting with ``start_prefix`` up to (excluding) the next
    line starting with ``end_prefix`` — used to scope the reverse check to the §C/§D verb tables."""
    out: list[str] = []
    inside = False
    for ln in text.splitlines():
        if ln.startswith(start_prefix):
            inside = True
            continue
        if inside and end_prefix and ln.startswith(end_prefix):
            break
        if inside:
            out.append(ln)
    return "\n".join(out)


def test_every_vigil_native_verb_is_documented():
    verbs = vigil_native_verbs(_read(CLI))
    missing = verbs - documented_vigil_verbs(_read(CLI_REF))
    assert not missing, (
        "these vigil native verbs exist in integration/vigil_integration/cli.py but are not documented "
        f"in docs/CLI-REFERENCE.md as `vigil <verb>`: {sorted(missing)}"
    )


def test_every_passthrough_verb_is_documented():
    pv = passthrough_verbs(_read(DISPATCH))
    missing = pv - documented_vigil_verbs(_read(CLI_REF))
    assert not missing, (
        "these vigil passthrough verbs (dispatch.py PASSTHROUGH_VERBS) are not documented in "
        f"docs/CLI-REFERENCE.md as `vigil <verb>`: {sorted(missing)}"
    )


def test_no_documented_vigil_verb_is_fictional():
    real = vigil_native_verbs(_read(CLI)) | passthrough_verbs(_read(DISPATCH))
    region = _section(_read(CLI_REF), "## C.", "## E.")
    documented_in_tables = documented_vigil_verbs(region)
    fictional = documented_in_tables - real
    assert not fictional, (
        "docs/CLI-REFERENCE.md §C/§D document these as `vigil <verb>` but they are neither a cli.py "
        f"sub-parser nor a passthrough verb — the docs describe a verb the code lacks: {sorted(fictional)}"
    )


# ==================================================================================================
# 2. The HTTP API chapter, read FROM THE CODE (api/server.py).
# ==================================================================================================
def http_routes_from_code(server_src: str) -> set[str]:
    """Every route ``api/server.py`` declares: the ``f"{_API}/..."`` forms, the literal ``/api/v1/...``
    forms, and the two health probes. The base ``/api/v1`` (no trailing segment) is NOT a route."""
    routes: set[str] = set()
    for suf in re.findall(r'f"\{_API\}(/[A-Za-z0-9/_-]*)"', server_src):
        routes.add("/api/v1" + suf)
    routes.update(re.findall(r'"(/api/v1/[A-Za-z0-9/_-]*)"', server_src))
    routes.update(re.findall(r'"(/healthz|/readyz)"', server_src))
    return routes


def _norm_route(p: str) -> str:
    """Drop a ``<arg>``/``{arg}`` placeholder tail and any trailing slash, so ``/api/v1/engagement/<slug>``
    and the code's ``/api/v1/engagement/`` compare equal — while ``/import`` and ``/imports`` stay distinct."""
    p = p.split("<")[0].split("{")[0]
    return p.rstrip("/")


def _route_like(p: str) -> bool:
    return p in ("/healthz", "/readyz") or p.startswith("/api/v1/")


def documented_http_routes(doc: str) -> set[str]:
    """Every route-like path the chapter documents as a standalone backticked token."""
    out: set[str] = set()
    for raw in re.findall(r"`(/[A-Za-z0-9/_<>{}-]+)`", doc):
        n = _norm_route(raw)
        if _route_like(n):
            out.add(n)
    return out


def _code_route_set() -> set[str]:
    return {_norm_route(r) for r in http_routes_from_code(_read(API_SERVER))}


def test_every_http_route_is_documented():
    missing = _code_route_set() - documented_http_routes(_read(HTTP_API))
    assert not missing, (
        "these routes exist in engine/crucible/framework/v2/api/server.py but are not documented in "
        f"docs/HTTP-API.md: {sorted(missing)}"
    )


def test_no_documented_http_route_is_fictional():
    fictional = documented_http_routes(_read(HTTP_API)) - _code_route_set()
    assert not fictional, (
        "docs/HTTP-API.md documents these routes but api/server.py does not serve them: "
        f"{sorted(fictional)}"
    )


# ==================================================================================================
# 3. The docs INDEX links every top-level docs/*.md (forward), and every link resolves (reverse).
# ==================================================================================================
def top_level_docs() -> set[str]:
    return {p.name for p in DOCS.glob("*.md") if p.name != "INDEX.md"}


def index_bare_md_links(index_src: str) -> set[str]:
    """Markdown links to a BARE top-level filename (no directory part), e.g. ``](FEATURES.md)``."""
    return set(re.findall(r"\]\(([A-Za-z0-9._-]+\.md)\)", index_src))


def test_index_lists_every_top_level_doc():
    missing = top_level_docs() - index_bare_md_links(_read(INDEX))
    assert not missing, (
        f"docs/INDEX.md does not link these top-level docs: {sorted(missing)} — a new doc must appear "
        "on the map."
    )


def test_index_links_resolve():
    broken = {ln for ln in index_bare_md_links(_read(INDEX)) if not (DOCS / ln).is_file()}
    assert not broken, f"docs/INDEX.md links to top-level docs that do not exist: {sorted(broken)}"


# ==================================================================================================
# 4. The GLOSSARY defines a floor set of the core terms.
# ==================================================================================================
GLOSSARY_FLOOR = [
    "oracle", "WARDEN", "conjunctive gate", "charter", "attestation", "CRUCIBLE", "AEGIS", "SIGIL",
    "spine", "two-environment boundary", "Certificate of Non-Exploitability", "egress gate",
    "FACT", "LEAD", "veracity firewall",
]


def _glossary_missing(text: str, terms: list[str]) -> list[str]:
    low = text.lower()
    return [t for t in terms if t.lower() not in low]


def test_glossary_defines_the_core_terms():
    missing = _glossary_missing(_read(GLOSSARY), GLOSSARY_FLOOR)
    assert not missing, f"docs/GLOSSARY.md does not define these core terms: {missing}"


# ==================================================================================================
# 5. The public-sector licensing exclusion is surfaced where a buyer sees it (not buried).
# ==================================================================================================
def _licensing_violations() -> list[str]:
    errs: list[str] = []
    # Near the TOP of the README — before the bottom-of-file License section — a buyer must meet it.
    head = "\n".join(_read(README).splitlines()[:80])
    if "Government & public-sector" not in head or "Commercial License" not in head:
        errs.append("README.md top (first 80 lines) lacks the Government/public-sector exclusion callout")
    # The buyer-facing pilot runbook.
    pilot = _read(PILOT)
    if "public-sector" not in pilot or "Commercial License" not in pilot:
        errs.append("docs/pilot/README.md lacks the public-sector licensing note")
    # The licensing doc itself.
    if "Government & public-sector use is EXCLUDED" not in _read(LICENSING):
        errs.append("LICENSING.md lacks the explicit exclusion statement")
    return errs


def test_public_sector_exclusion_is_surfaced_for_buyers():
    errs = _licensing_violations()
    assert not errs, "the public-sector licensing exclusion is not surfaced where a buyer sees it:\n" + \
        "\n".join(errs)


# ==================================================================================================
# 6. The re-derived doc-vs-code drift batch stays corrected.
# ==================================================================================================
FORBIDDEN: list[tuple[Path, str]] = [
    (AS_BUILT, "`--unshare-net` + minimal RO allowlist"),
    (AS_BUILT_LIVE, "`test_engine.py`, 17 tests"),
    (AS_BUILT_LIVE, "`test_engine_live.py`, 5 tests"),
    (AS_BUILT_LIVE, "the **22nd** screen"),
    (README, "(~33 kinds)"),
    (README, "0/7 systemd timers enabled"),
]

ANCHORS: list[tuple[Path, str]] = [
    (AS_BUILT, "`--unshare-all` + minimal RO allowlist"),
    (AS_BUILT_LIVE, "(`test_engine.py`), and the live validation over the REAL gate"),
    (AS_BUILT_LIVE, "(`test_engine_live.py`, `PYTHONPATH=integration:engine/crucible:gateway`)"),
    (AS_BUILT_LIVE, "one of the UI's screens"),
    (README, "(~38 kinds)"),
    (README, "0/9 systemd timers enabled"),
]


def present_forbidden(pairs: list[tuple[Path, str]]) -> list[str]:
    return [f"{p.name}: forbidden phrase present: {ph!r}" for p, ph in pairs if _has(p, ph)]


def missing_anchors(pairs: list[tuple[Path, str]]) -> list[str]:
    return [f"{p.name}: corrected anchor gone: {ph!r}" for p, ph in pairs if not _has(p, ph)]


def _oraclekind_member_count() -> int:
    tree = ast.parse(_read(MODELS))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "OracleKind":
            return sum(1 for s in node.body if isinstance(s, (ast.Assign, ast.AnnAssign)))
    raise AssertionError("OracleKind class not found in verify/models.py")


def _count_test_defs(p: Path) -> int:
    return len(re.findall(r"^def test_", _read(p), re.M))


def drift_code_fact_violations() -> list[str]:
    errs: list[str] = []
    # #1 — the bwrap runner really passes --unshare-all.
    if "--unshare-all" not in _read(SANDBOX):
        errs.append("sandbox_exec.py does not pass --unshare-all")
    # #5 — OracleKind really has >= 38 kinds (the '~33' was a stale underclaim).
    n = _oraclekind_member_count()
    if n < 38:
        errs.append(f"OracleKind has {n} members (<38) — the '~38 kinds' correction would overstate")
    # #6 — infra/systemd really ships 9 .timer units.
    timers = sorted(p.name for p in TIMERS_DIR.glob("*.timer"))
    if len(timers) != 9:
        errs.append(f"expected 9 systemd .timer units, found {len(timers)}: {timers}")
    # #2/#3 — the two test files really have MORE than the stale counts (they were underclaims).
    if _count_test_defs(TEST_ENGINE) <= 17:
        errs.append("test_engine.py no longer has >17 test defs — the underclaim correction is stale")
    if _count_test_defs(TEST_ENGINE_LIVE) <= 5:
        errs.append("test_engine_live.py no longer has >5 test defs — the underclaim correction is stale")
    return errs


def test_no_rederived_drift_reopened():
    violations = present_forbidden(FORBIDDEN) + missing_anchors(ANCHORS) + drift_code_fact_violations()
    assert not violations, "a re-derived §-drift correction re-opened:\n" + "\n".join(violations)


# ==================================================================================================
# Negative controls — every checker must reject a deliberately bad input/state (not be a no-op).
# ==================================================================================================
def test_negative_control_a_new_undocumented_vigil_verb_is_caught():
    verbs = vigil_native_verbs(_read(CLI)) | {"totally-new-verb"}
    assert "totally-new-verb" in (verbs - documented_vigil_verbs(_read(CLI_REF))), \
        "the forward vigil-verb checker is a no-op"


def test_negative_control_a_fictional_vigil_verb_is_caught():
    real = vigil_native_verbs(_read(CLI)) | passthrough_verbs(_read(DISPATCH))
    documented = {"engage", "not-a-real-verb-zzz"}
    assert "not-a-real-verb-zzz" in (documented - real), "the reverse vigil-verb checker is a no-op"


def test_negative_control_removing_a_documented_http_route_from_code_turns_red():
    code = _code_route_set()
    doc = documented_http_routes(_read(HTTP_API))
    assert "/api/v1/status" in code and "/api/v1/status" in doc, "fixture drifted"
    # Simulate the code no longer serving a route the chapter still documents.
    assert "/api/v1/status" in (doc - (code - {"/api/v1/status"})), \
        "the reverse HTTP-route checker is a no-op"


def test_negative_control_a_new_undocumented_http_route_is_caught():
    code = _code_route_set() | {"/api/v1/brand-new"}
    assert "/api/v1/brand-new" in (code - documented_http_routes(_read(HTTP_API))), \
        "the forward HTTP-route checker is a no-op"


def test_negative_control_a_new_undocumented_top_level_doc_is_caught():
    docs = top_level_docs() | {"ZZZ-NEW-DOC.md"}
    assert "ZZZ-NEW-DOC.md" in (docs - index_bare_md_links(_read(INDEX))), \
        "the forward index checker is a no-op"


def test_negative_control_a_broken_index_link_is_caught():
    assert {"nonexistent-doc-zzz.md"} == {
        ln for ln in {"nonexistent-doc-zzz.md"} if not (DOCS / ln).is_file()
    }, "the index-link resolver is a no-op"


def test_negative_control_glossary_missing_term_is_caught():
    assert _glossary_missing("nothing here", ["oracle"]) == ["oracle"], "the glossary checker is a no-op"


def test_negative_control_licensing_absence_is_caught():
    # present_forbidden/missing style: prove the checker flags a document that lacks the phrase.
    assert "Government & public-sector use is EXCLUDED" not in "a doc with no licensing text", \
        "fixture wrong"


def test_negative_control_a_returned_forbidden_phrase_is_flagged():
    # An anchor phrase IS present in the tree; used here to prove present_forbidden actually detects it.
    assert present_forbidden([(README, "(~38 kinds)")]), "present_forbidden is a no-op"


def test_negative_control_a_missing_anchor_is_flagged():
    assert missing_anchors([(README, "this exact string is deliberately absent zzz")]), \
        "missing_anchors is a no-op"


# ==================================================================================================
# Mutation control — the code-derived enumerations must really come from the code artefacts.
# ==================================================================================================
def test_enumerations_are_read_from_code():
    native = vigil_native_verbs(_read(CLI))
    pv = passthrough_verbs(_read(DISPATCH))
    routes = _code_route_set()
    assert len(native) >= 30, f"suspiciously few vigil native verbs parsed: {sorted(native)}"
    assert {"engage", "up", "backup", "verify"} <= native
    assert {"sigil", "crucible", "aegis", "strix", "gateway"} == pv
    assert len(routes) >= 12, f"suspiciously few HTTP routes parsed: {sorted(routes)}"
    assert {"/healthz", "/readyz", "/api/v1/status"} <= routes
