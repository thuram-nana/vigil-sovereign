"""W0-4 (#399): a batch of stale docs must not drift back to their false claims.

WHY THIS TEST EXISTS. Six documentation claims had fallen behind the code, each in a way that
would mislead an operator following the docs literally:

  1. The operator-key backup path. `docs/plain-english/07-signing-and-keys.md` and the
     byte-identical `VIGIL-EXPLAINED.md` said the operator key lives at
     `~/.vigil/attestation/operator.key`. That is only the MODULE DEFAULT
     (`attestation/identity.py:42`, used by a caller that injects no path); the live wiring
     ALWAYS injects `<base_dir>/operator.key` = `.vigil-live/operator.key`
     (`live/wiring.py:312-313`, `base_dir` default `".vigil-live"` at `wiring.py:208`). An
     operator following the docs would back up the WRONG file. DATA-GROUND-TRUTH.md records
     the injected path as the real one.
  2/3. `02-the-parts.md` said "the repository ships no documented backup-and-restore procedure"
     and `12-tools-and-what-you-need.md` said the offense side has "no separate purpose-built
     command". Both FALSE: `vigil backup`/`vigil restore` ship (two planes, encrypted, signed
     manifest) and the offense plane IS covered (`.vigil-live` + the CRUCIBLE evidence tree).
  4. `packages/vigil-ui/README.md` said "21 screens" while the NAV / route() / screens.yaml
     set is 31. This count is DERIVED from the NAV block in `app.js` so it cannot drift.
  5. `manifest.json` claimed "each server derives its static filename allowlist from
     static_allowlist" — no code reads that field (sync.sh copies a hardcoded list).
  6. `docs/SUPPLY-CHAIN.md` said the hash-locks are "consumed only by supply-chain.yml" and
     "not what an operator installs" — stale: `build_envs.sh` now installs the third-party
     layer from the locks under `--require-hashes`.

An UNDERSTATED / WRONG-path doc is the dangerous kind — it sends the operator to the wrong file
or tells them a shipped control is absent. This test fails four ways, each a real drift:

  * a FORBIDDEN false phrase has returned to a doc;
  * a corrected anchor phrase is gone (a silent revert);
  * a code fact the correction now cites is not true in-tree (a NEW overclaim);
  * the README screen count / screen list no longer matches the NAV block it describes.

It reads files only — imports nothing, runs no tool, sends no packet — so it is correct to run
in the docs-only `briefing-completeness` CI job that installs only pytest.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

SIGNING = REPO / "docs" / "plain-english" / "07-signing-and-keys.md"
EXPLAINED = REPO / "docs" / "plain-english" / "VIGIL-EXPLAINED.md"
PARTS = REPO / "docs" / "plain-english" / "02-the-parts.md"
TOOLS = REPO / "docs" / "plain-english" / "12-tools-and-what-you-need.md"
README = REPO / "packages" / "vigil-ui" / "README.md"
MANIFEST = REPO / "packages" / "vigil-ui" / "manifest.json"
SUPPLY = REPO / "docs" / "SUPPLY-CHAIN.md"
APPJS = REPO / "packages" / "vigil-ui" / "app.js"


def _collapsed(path: Path) -> str:
    """File text with every whitespace run collapsed to one space, so a phrase that wraps across
    indented lines still matches as a single needle."""
    assert path.is_file(), f"doc missing: {path}"
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def _has(path: Path, phrase: str) -> bool:
    return re.sub(r"\s+", " ", phrase) in _collapsed(path)


# ---------------------------------------------------------------------------
# 1. FORBIDDEN false phrases must be GONE.
# ---------------------------------------------------------------------------
FORBIDDEN = [
    # 1. The wrong operator-key path (module default, never the injected path).
    (SIGNING, "Owner-only file under `~/.vigil/attestation/`"),
    (EXPLAINED, "Owner-only file under `~/.vigil/attestation/`"),
    # 2. "no backup ships".
    (PARTS, "The repository ships no documented backup-and-restore procedure"),
    # 3. "no offense backup command".
    (TOOLS, "There is no separate purpose-built command for those"),
    # 4. the stale screen count.
    (README, "21 screens"),
    (README, "21-screen NAV"),
    # 5. the unread-field claim.
    (MANIFEST, "each server derives its static filename allowlist from static_allowlist"),
    # 6. the supply-chain under-claim.
    (SUPPLY, "are consumed only by `.github/workflows/supply-chain.yml`"),
    (SUPPLY, "they are not what an operator installs"),
]


def test_forbidden_false_phrases_are_gone():
    for path, phrase in FORBIDDEN:
        assert not _has(path, phrase), (
            f"{path.name} still contains the stale/false phrase: {phrase!r}. "
            f"See W0-4 (#399) — do not let the doc drift back.")


# ---------------------------------------------------------------------------
# 2. Corrected anchor phrases must be PRESENT (guards a silent revert).
# ---------------------------------------------------------------------------
REQUIRED_ANCHORS = [
    (SIGNING, ".vigil-live/operator.key"),
    (EXPLAINED, ".vigil-live/operator.key"),
    (PARTS, "A documented, purpose-built backup-and-restore procedure **does** ship"),
    (TOOLS, "The offensive half is covered by the same tooling"),
    (README, "31 screens"),
    (MANIFEST, "no code reads static_allowlist"),
    (SUPPLY, "The operator's install path now installs FROM the locks"),
]


def test_corrected_anchors_present():
    for path, phrase in REQUIRED_ANCHORS:
        assert _has(path, phrase), (
            f"{path.name} lost the corrected anchor {phrase!r} — the W0-4 fix appears reverted.")


# ---------------------------------------------------------------------------
# 3. Every code fact the correction CITES must be true in-tree
#    (guards against swapping a false claim for a NEW false claim).
# ---------------------------------------------------------------------------
def test_operator_key_real_path_is_code_true():
    """The live wiring injects `<base_dir>/operator.key` with base_dir defaulting to `.vigil-live`
    — so the corrected `.vigil-live/operator.key` is the file the engine actually uses."""
    wiring = (REPO / "integration/vigil_integration/live/wiring.py").read_text(encoding="utf-8")
    assert 'str(base / "operator.key")' in wiring, (
        "wiring.py no longer injects <base_dir>/operator.key — re-derive the documented path.")
    assert 'base_dir: str = ".vigil-live"' in wiring, (
        "the LiveConfig base_dir default is no longer '.vigil-live' — the documented path may be wrong.")


def test_backup_command_actually_ships():
    """The corrected 02-the-parts / 12-tools claims cite `vigil backup`/`vigil restore` and a
    two-plane offense/sovereign backup. Those must exist."""
    cli = (REPO / "integration/vigil_integration/cli.py").read_text(encoding="utf-8")
    assert 'sub.add_parser(\n        "backup"' in cli or '"backup",' in cli, "no `vigil backup` verb in cli.py"
    assert '"restore",' in cli, "no `vigil restore` verb in cli.py"
    assert (REPO / "integration/vigil_integration/backup.py").is_file(), "offense backup module missing"
    assert (REPO / "apps/sigil/sigil/backup.py").is_file(), "sovereign backup module missing"
    off = (REPO / "integration/vigil_integration/backup.py").read_text(encoding="utf-8")
    assert "create_offense_backup" in off, "offense backup entrypoint missing"


def test_build_envs_installs_from_locks_under_require_hashes():
    """The corrected SUPPLY-CHAIN claim: the operator install path installs the third-party layer
    from the locks under --require-hashes."""
    be = (REPO / "envs/build_envs.sh").read_text(encoding="utf-8")
    assert "--require-hashes" in be, "build_envs.sh no longer uses --require-hashes — SUPPLY-CHAIN claim stale."
    assert "sovereign.lock.txt" in be and "requirements.lock.txt" in be, (
        "build_envs.sh no longer references the supply-chain locks.")


def test_static_allowlist_is_read_by_no_code():
    """The corrected manifest claim: no CODE reads `static_allowlist`. Derive it — scan the UI
    package and both plane servers' source for the identifier; the only permitted homes are the
    manifest.json itself and the README (docs)."""
    scan_dirs = [
        REPO / "packages" / "vigil-ui",
        REPO / "apps" / "sigil" / "sigil" / "ui",
        REPO / "engine" / "crucible" / "framework" / "v2" / "console",
    ]
    offenders = []
    for d in scan_dirs:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if p.suffix not in {".py", ".sh", ".js"} or not p.is_file():
                continue
            if "static_allowlist" in p.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(p.relative_to(REPO)))
    assert not offenders, (
        "code now reads `static_allowlist` (" + ", ".join(offenders) + ") — the corrected manifest "
        "description ('no code reads static_allowlist') is now false; update the manifest.")


# ---------------------------------------------------------------------------
# 4. The README screen count + screen list must match the NAV block it describes
#    (DERIVED from app.js so the doc cannot drift from the real UI).
# ---------------------------------------------------------------------------
def _nav_ids() -> list[str]:
    src = APPJS.read_text(encoding="utf-8")
    m = re.search(r"const NAV = \[(.*?)\n  \];", src, re.S)
    assert m, "could not locate the `const NAV = [ ... ];` block in app.js — its shape changed."
    return re.findall(r'id: "([a-z]+)"', m.group(1))


def _readme_table_ids() -> list[str]:
    """Backticked ids inside the DO/MANAGE/LEARN rows of the screen-map table in the README."""
    ids: list[str] = []
    for line in README.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith(("| DO |", "| MANAGE |", "| LEARN |")):
            ids += re.findall(r"`([a-z]+)`", s)
    return ids


def test_nav_block_parses():
    """MUTATION CONTROL — the assertions below are vacuous if the parse yields nothing."""
    nav = _nav_ids()
    assert len(nav) >= 20, f"NAV parse looks wrong (got {len(nav)} ids) — the block shape changed."
    assert _readme_table_ids(), "README screen-map table parsed empty — its shape changed."


def test_readme_screen_count_matches_nav():
    """The README's stated count must equal the real NAV cardinality — no magic number."""
    n = len(_nav_ids())
    body = README.read_text(encoding="utf-8")
    assert f"{n} screens" in body, (
        f"the NAV block has {n} screens but the README does not say '{n} screens' — "
        f"correct the README count (it is DERIVED from app.js).")
    assert "21 screens" not in body, "the README still says the stale '21 screens'."


def test_readme_screen_list_set_equals_nav():
    """The enumerated DO/MANAGE/LEARN table must be the exact NAV id set — no missing screens."""
    nav = set(_nav_ids())
    table = set(_readme_table_ids())
    missing = sorted(nav - table)
    extra = sorted(table - nav)
    assert not missing and not extra, (
        "the README screen-map table has drifted from the NAV block. "
        + (f"Missing from README: {missing}. " if missing else "")
        + (f"Not in NAV: {extra}." if extra else ""))
