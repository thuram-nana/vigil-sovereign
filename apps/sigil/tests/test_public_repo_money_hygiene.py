"""Public-repo money hygiene: no margin or markup VALUE may reach this public repository.

The guard (tools/governance/money_hygiene.py) scans every tracked text file, and in CI the commit
messages, the pull request title/body and the branch name. This suite proves it bites.

DECOYS ONLY. Every value planted below is a decoy assembled at runtime from fragments (the precedent
is the "3.5" display decoy in test_ui_margin.py), so this file never contains a real figure and never
trips the guard it tests. The setting names are assembled too, for the same reason.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
_TOOL = REPO / "tools" / "governance" / "money_hygiene.py"


def _load():
    spec = importlib.util.spec_from_file_location("money_hygiene", _TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["money_hygiene"] = mod
    spec.loader.exec_module(mod)
    return mod


mh = _load()

# Runtime-assembled decoys: no real figure, and no literal the guard would match in this file.
_D = str(3) + str(7)                       # a two-digit decoy percentage
_KD = str(7) + "." + str(3)                # a decimal decoy markup
_MK = "VIGIL_BILLING_" + "MARKUP_K"
_TM = "VIGIL_BILLING_" + "TARGET_" + "MARGIN"
_DEF = "DEFAULT_" + "MARKUP"
_PCT = "%"
_Z = str(0)


def _ids(text: str, source: str = "<t>") -> set[str]:
    return {h.pattern for h in mh.scan_text(text, source)}


# --- every pattern alternative bites (each is a mutation target) ---------------------------------

@pytest.mark.parametrize("text, pid", [
    (f"{_MK}={_KD}", "setting-value"),
    (f"export {_MK} = '{_KD}'", "setting-value"),
    (f"| `{_MK}` ({_KD}) | pricing |", "setting-value"),
    (f"{_TM}=0.{_D}", "setting-value"),
    (f"| {_MK} | {_KD} |", "setting-value"),                  # a Markdown table row
    (f"| `{_TM}` | `0.{_D}` |", "setting-value"),
    (f"{_MK}, {_KD}", "setting-value"),
    (f"{_MK} := .{_D}", "setting-value"),
    (f'{_DEF} = "{_KD}"', "default-value"),
    (f"{_DEF}: str = '{_KD}'", "default-value"),
    (f'{_DEF}_K = Fraction("{_KD}")', "default-value"),
    (f"we keep a {_D}{_PCT} gross margin", "percent-margin"),
    (f"about {_D}.5 {_PCT} margin", "percent-margin"),
    (f"a {_D} percent target margin", "percent-margin"),
    (f"{_D}{_PCT} (gross) margin", "percent-margin"),
    (f"gross margin is ~{_D}{_PCT}", "margin-then-percent"),
    (f"target margin {_D} percent", "margin-then-percent"),
    (f"price = {_D[0]}× cost", "cost-multiplier"),
    (f"priced at {_D[0]}.{_D[1]}x the direct cost", "cost-multiplier"),
    (f"a markup of {_D[0]}x", "cost-multiplier"),
    (f"os.environ.get('{_MK}', '{_KD}')", "setting-value"),
    (f"process.env.{_MK} ?? '{_KD}'", "setting-value"),
    (f"  - {_TM}=${{X:-0.{_D}}}", "setting-value"),
    (f"{_TM}=.{_D}", "setting-value"),
    (f"vigil_billing_target_margin: {_Z}.{_D}", "setting-value"),
    (f"'targetMargin': {_Z}.{_D}", "setting-value"),
    (f"markup_k = {_KD}", "setting-value"),
    (f"{_DEF} = .{_D}", "default-value"),
    (f"markup K ≤ 100; prod {_KD}", "markup-k-cell"),
    (f"margin target: {_D}", "margin-target"),
    (f"a margin of {_D} points", "margin-target"),
    (f"| Markup K | **{_KD}** |", "markup-k-cell"),
    (f"the gross margin: ~{_D}{_PCT}", "margin-then-percent"),
    (f"markup uses K = {_KD} today", "k-near-wording"),
    (f"K -> {_KD} gives the margin", "k-near-wording"),
    (f"K → {_KD} (markup)", "k-near-wording"),
])
def test_each_pattern_catches_a_decoy(text: str, pid: str) -> None:
    assert pid in _ids(text)


# --- what must pass ------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "target gross margin above that",                       # wording with no number
    f"`{_MK}` (≥ 1, ≤ 100)",                                 # a bound, not a value
    "the K4 hold and the K6 gate stay as they are",          # slice ids
    "SPLIT_K = 6",                                           # an unrelated algorithm constant
    "K" + " = " + "6" + " " * 60 + "then the margin",        # K far away from the wording
    "$5, $10, $16, $25, $50 and $100 packs; $25 per seat; 100 credits per $1",  # customer prices
    f"{_MK} is owner-set in the private deploy environment; no value is recorded here",
])
def test_public_safe_text_passes(text: str) -> None:
    assert mh.scan_text(text) == []


def test_css_margin_allowed_only_in_style_files_and_never_with_money_words() -> None:
    css = f"  margin: {_D}{_PCT}; padding: 4px;"
    assert mh.scan_text(css, "public_site/style.css") == []
    assert mh.scan_text(css, "customer_app/app.js") == []
    # The same shape in prose is not layout.
    assert mh.scan_text(css, "docs/pricing.md") != []
    # Money wording is never excused, even in a stylesheet.
    assert mh.scan_text(f"/* gross margin: {_D}{_PCT} */", "public_site/style.css") != []


def test_tolerance_allowance_is_pinned_to_the_design_doc() -> None:
    line = f"token counts must agree within a {_D[0]}{_PCT} margin (tolerance of the meter)"
    assert mh.scan_text(line, "docs/decisions/PRICING-RED-PEN-DESIGN.md") == []
    assert mh.scan_text(line, "docs/runbooks/other.md") != []
    # A price line in that same doc is still caught.
    assert mh.scan_text(f"we target a {_D}{_PCT} gross margin",
                        "docs/decisions/PRICING-RED-PEN-DESIGN.md") != []


def test_finding_never_echoes_the_value() -> None:
    hits = mh.scan_text(f"{_MK}={_KD}", "x.env")
    assert hits
    for h in hits:
        assert _KD not in h.render()


# --- the tracked tree ----------------------------------------------------------------------------

def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True,
                          text=True).stdout


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def _track(repo: Path, rel: str, data: str | bytes) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        p.write_bytes(data)
    else:
        p.write_text(data, encoding="utf-8")
    _git(repo, "add", rel)


def test_planted_fixtures_are_caught(repo: Path) -> None:
    _track(repo, "infra/systemd/x.env.example", f"{_MK}={_KD}\n")
    _track(repo, "pkg/model_metering.py", f'{_DEF} = "{_KD}"\n')
    _track(repo, "public_site/index.html", f"<p>a {_D}{_PCT} gross margin</p>\n")
    _track(repo, "docs/notes.md", f"| Markup K | **{_KD}** |\n")
    found = {(h.source, h.pattern) for h in mh.scan_tree(repo)}
    assert ("infra/systemd/x.env.example", "setting-value") in found
    assert ("pkg/model_metering.py", "default-value") in found
    assert ("public_site/index.html", "percent-margin") in found
    # A mutant that skips Markdown (or any text suffix) along with binaries fails here.
    assert ("docs/notes.md", "markup-k-cell") in found


def test_binary_skipped_by_nul_sniff_only(repo: Path) -> None:
    _track(repo, "img.bin", b"\x00\x01" + f"{_MK}={_KD}".encode())
    _track(repo, "noext", f"{_MK}={_KD}\n")             # text without a suffix is still text
    found = {h.source for h in mh.scan_tree(repo)}
    assert "img.bin" not in found
    assert "noext" in found
    assert mh.is_binary(b"a\x00b") and not mh.is_binary(b"plain text")


def test_untracked_files_are_not_scanned(repo: Path) -> None:
    (repo / "scratch.env").write_text(f"{_MK}={_KD}\n", encoding="utf-8")
    _track(repo, "ok.md", "clean\n")
    assert mh.scan_tree(repo) == []


def test_this_repository_is_clean() -> None:
    hits = mh.scan_tree(REPO)
    assert hits == [], "\n".join(h.render() for h in hits)


# --- commit, PR and branch text ------------------------------------------------------------------

def test_ci_scans_commit_messages_pr_text_and_branch(repo: Path, tmp_path_factory) -> None:
    _track(repo, "a.txt", "a\n")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD").strip()
    _track(repo, "b.txt", "b\n")
    _git(repo, "commit", "-q", "-m", f"feat: price at a {_D}{_PCT} gross margin")
    _track(repo, "c.txt", "c\n")
    _git(repo, "commit", "-q", "-m", "chore: clean message")

    ev = tmp_path_factory.mktemp("ev") / "event.json"
    ev.write_text(json.dumps({"pull_request": {
        "title": f"set {_MK}={_KD}",
        "body": f"markup K = {_KD}",
        "head": {"ref": f"claude/margin-of-{_D}"},
    }}), encoding="utf-8")

    labels: dict[str, set[str]] = {}
    for label, body in mh.ci_texts(repo, base, str(ev), None):
        for h in mh.scan_text(body, label):
            labels.setdefault(label.split(" ")[0] if label.startswith("commit") else label,
                              set()).add(h.pattern)
    assert "percent-margin" in labels["commit"]
    assert "setting-value" in labels["pull request title"]
    assert "k-near-wording" in labels["pull request body"]
    assert "margin-target" in labels["branch name"]
    # Only the two commits after base are read; base itself is not.
    commits = [lb for lb, _ in mh.ci_texts(repo, base, None, None)]
    assert len(commits) == 2


def test_ci_clean_text_passes(repo: Path, tmp_path_factory) -> None:
    _track(repo, "a.txt", "a\n")
    _git(repo, "commit", "-q", "-m", "base")
    ev = tmp_path_factory.mktemp("ev") / "event.json"
    ev.write_text(json.dumps({"pull_request": {"title": "fix: thing", "body": None,
                                               "head": {"ref": "claude/pricing-f-s0"}}}))
    assert mh.main(["ci", "--root", str(repo), "--base", "HEAD", "--event", str(ev),
                    "--head-ref", ""]) == 0


def test_cli_exit_status(repo: Path) -> None:
    _track(repo, "x.env.example", f"{_TM}=0.{_D}\n")
    assert mh.main(["tree", "--root", str(repo)]) == 1


# --- review folds ----------------------------------------------------------------------------------

def test_a_value_wrapped_onto_the_next_line_is_caught() -> None:
    text = f"we price every scan at a {_D}{_PCT}\ngross margin over direct cost\n"
    hits = mh.scan_text(text, "docs/x.md")
    assert [(h.line, h.pattern) for h in hits] == [(1, "percent-margin")]
    assert mh.scan_text(f"{_MK} =\n  {_KD}\n", "x.env") != []


def test_priced_copy_in_a_markup_file_is_not_excused_as_css() -> None:
    assert mh.scan_text(f"<p>Our margin: {_D}{_PCT} on every call</p>", "web/Pricing.tsx") != []
    assert mh.scan_text(f'const copy = "margin: {_D}{_PCT} on every scan";', "web/copy.js") != []
    # a real inline style is still layout
    assert mh.scan_text(f'<div style="margin: {_D}{_PCT}; padding: 2px">', "public_site/index.html") == []


def test_tolerance_wording_never_excuses_money_wording() -> None:
    line = f"price at a {_D}{_PCT} margin (tolerance aside)"
    assert mh.scan_text(line, "docs/decisions/PRICING-RED-PEN-DESIGN.md") != []


def test_ci_reads_only_base_to_head(repo: Path) -> None:
    _track(repo, "a.txt", "a\n")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD").strip()
    _track(repo, "b.txt", "b\n")
    _git(repo, "commit", "-q", "-m", "clean head")
    head = _git(repo, "rev-parse", "HEAD").strip()
    _track(repo, "c.txt", "c\n")
    _git(repo, "commit", "-q", "-m", f"after head: {_D}{_PCT} gross margin")
    assert [lb for lb, _ in mh.ci_texts(repo, base, None, None, head)] == [f"commit {head[:12]}"]
    assert mh.main(["ci", "--root", str(repo), "--base", base, "--head", head, "--head-ref", ""]) == 0
