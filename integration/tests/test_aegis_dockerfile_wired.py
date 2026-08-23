"""W17-11 (#545) — the AEGIS gateway Dockerfile must be a WIRED, buildable artifact, not an orphan.

Two honesty invariants, asserted STATICALLY (pure stdlib file reads — no Docker daemon, no network,
no `framework` import, so this runs in the sovereign integration leg alongside test_supply_chain.py):

  1. `engine/crucible/framework/v2/aegis/Dockerfile` is actually BUILT by the repo — it is referenced
     by a real compose `build:` service AND by a `make` target — rather than being presented as a
     runnable artifact in QUICKSTART/DEPLOYMENT while nothing in the tree ever builds it. An orphaned
     Dockerfile rots: its base pin, its COPY set and its install step are never exercised, so "it
     builds" is a claim no check backs. The compose service is what makes the claim true and testable.

  2. The AEGIS console setup button (`console/actions.py::aegis_setup`) fail-closes unless `httpx` is
     importable ("the gateway needs httpx to forward requests"). So `httpx` MUST be a HARD dependency
     of the offense environment, or the button is dead on first use. The offense env installs
     `-e ./engine/crucible` (envs/offense.txt), whose `pyproject.toml` therefore has to carry `httpx`
     as a non-optional dependency and the offense lock has to pin it. Both facts are DERIVED here from
     the code/lock so the assertion cannot silently drift away from what the button requires.

Every "the X is wired" assertion is paired with a NEGATIVE CONTROL proving the detector can fail, so a
green result is evidence rather than a vacuous pass.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

AEGIS_DOCKERFILE = REPO_ROOT / "engine/crucible/framework/v2/aegis/Dockerfile"
COMPOSE = REPO_ROOT / "docker-compose.yml"
MAKEFILE = REPO_ROOT / "Makefile"
CRUCIBLE_PYPROJECT = REPO_ROOT / "engine/crucible/pyproject.toml"
OFFENSE_LOCK = REPO_ROOT / "engine/crucible/framework/v2/requirements.lock.txt"
OFFENSE_ENV = REPO_ROOT / "envs/offense.txt"
CONSOLE_ACTIONS = REPO_ROOT / "engine/crucible/framework/v2/console/actions.py"


def _canon(name: str) -> str:
    """PEP 503 normalisation — `PyYAML`, `pyyaml` and `py_yaml` are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


# --------------------------------------------------------------------------------------
# Invariant 1 — the Dockerfile is a WIRED, buildable compose+make artifact.
# --------------------------------------------------------------------------------------

def _compose_build_dockerfiles(compose_text: str) -> list[Path]:
    """Resolve the Dockerfile path of every service `build:` block to an absolute path.

    A stdlib indentation walk (compose here is 2-space-indented, no tabs) so this test adds no YAML
    dependency to a suite whose sovereign leg installs none. Handles the block form
    (`build:` → `context:` / `dockerfile:`) and the inline form (`build: ./ctx`, default Dockerfile).
    Whole-line `#` comments are dropped first so a commented example command cannot satisfy the check.
    """
    lines = [ln for ln in compose_text.splitlines() if not ln.lstrip().startswith("#")]
    out: list[Path] = []
    i, n = 0, len(lines)

    def _val(s: str) -> str:
        return s.split("#", 1)[0].strip().strip('"').strip("'")

    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if stripped == "build:" or stripped.startswith("build:"):
            indent = len(raw) - len(raw.lstrip())
            inline = _val(stripped[len("build:"):])
            if inline:  # inline `build: ./ctx` → default Dockerfile in that context
                out.append((REPO_ROOT / inline / "Dockerfile").resolve())
                i += 1
                continue
            context, dockerfile = None, None
            j = i + 1
            while j < n:
                bl = lines[j]
                if not bl.strip():
                    j += 1
                    continue
                if (len(bl) - len(bl.lstrip())) <= indent:  # dedent → block ended
                    break
                bs = bl.strip()
                if bs.startswith("context:"):
                    context = _val(bs[len("context:"):])
                elif bs.startswith("dockerfile:"):
                    dockerfile = _val(bs[len("dockerfile:"):])
                j += 1
            ctx = context or "."
            out.append((REPO_ROOT / ctx / (dockerfile or "Dockerfile")).resolve())
            i = j
            continue
        i += 1
    return out


def test_aegis_dockerfile_exists() -> None:
    """Sanity: if the Dockerfile itself is gone, every assertion below would be vacuous."""
    assert AEGIS_DOCKERFILE.is_file(), f"missing {AEGIS_DOCKERFILE.relative_to(REPO_ROOT)}"


def test_aegis_dockerfile_is_built_by_a_compose_service() -> None:
    """The AEGIS Dockerfile is the build target of a real compose service (so `docker compose build`
    actually exercises it) — not merely name-dropped in a comment."""
    targets = _compose_build_dockerfiles(COMPOSE.read_text(encoding="utf-8"))
    # Anti-vacuous: the parser must see the pre-existing strix build AND the new aegis build. A parser
    # that found nothing (or everything) would make the membership check below meaningless.
    assert len(targets) >= 2, (
        f"the compose build-block parser resolved {len(targets)} target(s); the file has at least the "
        "strix-sandbox and aegis-gateway build services, so the parser is broken"
    )
    assert AEGIS_DOCKERFILE.resolve() in targets, (
        f"{AEGIS_DOCKERFILE.relative_to(REPO_ROOT)} is not the build target of any compose service — it "
        f"is orphaned. Resolved build targets were:\n  " + "\n  ".join(str(t) for t in targets)
    )


def test_compose_build_parser_can_fail_negative_control() -> None:
    """NEGATIVE CONTROL. A path the compose file does NOT build must NOT be reported as a build target,
    and an empty compose must yield no targets — otherwise the check above passes for the wrong reason."""
    bogus = (REPO_ROOT / "engine/crucible/framework/v2/aegis/NOPE.Dockerfile").resolve()
    assert bogus not in _compose_build_dockerfiles(COMPOSE.read_text(encoding="utf-8"))
    assert _compose_build_dockerfiles("services:\n  x:\n    image: alpine:3.20\n") == []


def test_aegis_image_has_a_make_target_wired_to_the_compose_service() -> None:
    """A `make aegis-image` target exists AND its recipe builds the `aegis-gateway` compose service, so
    the two cannot drift apart (a target that built some other service would be a lie)."""
    text = MAKEFILE.read_text(encoding="utf-8")
    m = re.search(r"^aegis-image:.*?(?=^\S|\Z)", text, re.MULTILINE | re.DOTALL)
    assert m, "root Makefile has no `aegis-image:` target"
    recipe = m.group(0)
    assert "aegis-gateway" in recipe, (
        "the `aegis-image` target does not build the `aegis-gateway` compose service — the make target "
        "and the compose service have drifted apart"
    )


def test_make_target_detector_can_fail_negative_control() -> None:
    """NEGATIVE CONTROL for the target regex: a target that does not exist must not be 'found'."""
    text = MAKEFILE.read_text(encoding="utf-8")
    assert re.search(r"^no-such-target-xyz:.*?(?=^\S|\Z)", text, re.MULTILINE | re.DOTALL) is None


# --------------------------------------------------------------------------------------
# Runtime completeness — the built image must actually RUN, not just build.
# framework.v2 imports the shared integrity substrate at load (common.errors →
# vigil_core.IntegrityError), which lives OUTSIDE the engine/crucible build context. An image
# that installs only `crucible` builds green but crashes on first run with
# `ModuleNotFoundError: No module named 'vigil_core'`. So the substrate must be supplied to the
# image as a named build context AND installed. These are the STATIC guards for that (a live
# `docker run` proof is in the slice's fail-before/pass-after evidence, not in this daemonless leg).
# --------------------------------------------------------------------------------------

def _aegis_build_block(compose_text: str) -> str:
    """The text of the `aegis-gateway:` service block (up to the next top-level service / `volumes:`)."""
    m = re.search(r"^  aegis-gateway:\n(?P<body>(?:  {2,}.*\n|\n)*)", compose_text, re.MULTILINE)
    assert m, "no `aegis-gateway:` service block in docker-compose.yml"
    return m.group("body")


def test_framework_actually_imports_vigil_core() -> None:
    """The requirement is real, not imaginary: some framework.v2 module imports vigil_core, so any
    packaged image of framework.v2 needs it present. Derived from the code so it cannot go stale."""
    hits = [
        p for p in (REPO_ROOT / "engine/crucible/framework/v2").rglob("*.py")
        if re.search(r"(?m)^\s*(from vigil_core\b|import vigil_core\b)", p.read_text(encoding="utf-8"))
    ]
    assert hits, "no framework.v2 module imports vigil_core — the image-substrate guard below is moot"


def test_image_installs_the_vigil_core_substrate() -> None:
    """The Dockerfile pulls the vigil_core named build context AND installs it, so the gateway starts."""
    df = AEGIS_DOCKERFILE.read_text(encoding="utf-8")
    df_nc = "\n".join(ln for ln in df.splitlines() if not ln.lstrip().startswith("#"))
    assert "--from=vigil_core" in df_nc, (
        "the AEGIS Dockerfile does not COPY the `vigil_core` named build context — the image would build "
        "green but crash at startup with ModuleNotFoundError: No module named 'vigil_core'"
    )
    assert re.search(r"pip install[^\n]*vigil_core", df_nc), "the Dockerfile never installs vigil_core"


def test_compose_supplies_the_vigil_core_build_context() -> None:
    """A Dockerfile `COPY --from=vigil_core` is inert unless the builder is handed that named context.
    The compose service must provide it, pointing at packages/core/vigil_core (which must exist)."""
    body = _aegis_build_block(COMPOSE.read_text(encoding="utf-8"))
    body_nc = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    m = re.search(r"vigil_core:\s*(?P<path>\S+)", body_nc)
    assert m, "the aegis-gateway build block does not supply a `vigil_core` additional build context"
    resolved = (REPO_ROOT / m.group("path").strip("'\"")).resolve()
    assert resolved == (REPO_ROOT / "packages/core/vigil_core").resolve(), (
        f"the vigil_core build context points at {resolved}, not packages/core/vigil_core"
    )
    assert resolved.is_dir(), f"the vigil_core build context {resolved} does not exist"


def test_vigil_core_context_detector_can_fail_negative_control() -> None:
    """NEGATIVE CONTROL: an aegis build block with no additional_contexts must not report vigil_core."""
    fake = "  aegis-gateway:\n    build:\n      context: ./engine/crucible\n\nvolumes:\n"
    body = _aegis_build_block(fake)
    body_nc = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    assert re.search(r"vigil_core:\s*(\S+)", body_nc) is None


# --------------------------------------------------------------------------------------
# Invariant 2 — httpx (required by the AEGIS setup button) resolves in the offense env.
# --------------------------------------------------------------------------------------

def _crucible_hard_deps() -> set[str]:
    """The canonicalised names of the offense engine's NON-optional runtime dependencies, parsed from
    the authoritative buildable pyproject that `envs/offense.txt` installs editable."""
    data = tomllib.loads(CRUCIBLE_PYPROJECT.read_text(encoding="utf-8"))
    names = set()
    for spec in data["project"]["dependencies"]:
        m = re.match(r"^([A-Za-z0-9._-]+)", spec)
        if m:
            names.add(_canon(m.group(1)))
    return names


def test_offense_env_installs_crucible_editable() -> None:
    """The premise of the derivation below: the offense env pulls in engine/crucible's dependencies."""
    assert "-e ./engine/crucible" in OFFENSE_ENV.read_text(encoding="utf-8")


def test_aegis_setup_button_requires_httpx() -> None:
    """The claim we are protecting is load-bearing: the console setup button fail-closes without httpx."""
    src = CONSOLE_ACTIONS.read_text(encoding="utf-8")
    assert 'find_spec("httpx")' in src, (
        "aegis_setup no longer gates on httpx — if this requirement moved, update the offense-lock "
        "assertions below to match wherever the gateway now sources its HTTP client"
    )


def test_httpx_is_a_hard_offense_dependency() -> None:
    """DERIVED from code: httpx is a hard (non-optional) crucible dependency, so the offense env that
    installs `-e ./engine/crucible` resolves it and the AEGIS setup button works on first use."""
    assert "httpx" in _crucible_hard_deps(), (
        "httpx is not a hard dependency of engine/crucible/pyproject.toml, but the AEGIS setup button "
        "requires it — the button would fail on a clean offense env"
    )


def test_httpx_is_pinned_in_the_offense_lock() -> None:
    """The hash-pinned offense lock actually carries httpx (not just the loose pyproject range)."""
    lock = OFFENSE_LOCK.read_text(encoding="utf-8")
    assert re.search(r"(?m)^httpx==", lock), "httpx is not pinned in the offense requirements lock"


def test_dependency_parser_can_fail_negative_control() -> None:
    """NEGATIVE CONTROL. A package that is NOT a crucible dependency must not be reported as one."""
    assert "definitely-not-a-real-dep-xyz" not in _crucible_hard_deps()


# --------------------------------------------------------------------------------------
# W1-7 (#416) — the AEGIS runtime is ALIGNED to the Python minor the committed locks target.
#
# `aegis/Dockerfile` used to pin `python:3.11-slim` while the locks (and every CI job, and the sibling
# `gateway/Dockerfile` data-plane image) target 3.13 — so the interpreter that SHIPS in the AEGIS image
# was the one version CI never exercised. These guards DERIVE both sides from the tree and assert they
# are equal, so the alignment cannot silently rot back. Each is paired with a NEGATIVE CONTROL proving
# the detector can fail (a green is evidence, not a vacuous pass). Pure stdlib file reads — no Docker
# daemon, no network — so this runs in the sovereign integration leg alongside the checks above.
# --------------------------------------------------------------------------------------

BUILD_ENVS = REPO_ROOT / "envs/build_envs.sh"
GATEWAY_DOCKERFILE = REPO_ROOT / "gateway/Dockerfile"


def _dockerfile_python_minor(dockerfile_text: str) -> str | None:
    """The `major.minor` of a Dockerfile's python base, read from the first non-comment `FROM`/`ARG`
    line that names `python:X.Y` — so both the direct form (`FROM python:3.13-slim@sha256:…`, the AEGIS
    image) and the build-arg form (`ARG PYTHON_BASE=python:3.13-slim@…` + `FROM ${PYTHON_BASE}`, the
    gateway image) resolve. Whole-line `#` comments are skipped first, so a commented example base can
    never be mistaken for the real pin. None when no python base is named."""
    for raw in dockerfile_text.splitlines():
        s = raw.strip()
        if s.startswith("#"):
            continue
        if re.match(r"(?i)^(FROM|ARG)\b", s):
            m = re.search(r"\bpython:(\d+\.\d+)", s)
            if m:
                return m.group(1)
    return None


def _locked_python_minor() -> str | None:
    """The Python minor the committed hash-locks target — the interpreter `envs/build_envs.sh` pins when
    it builds the two locked environments (`python3.13`). That script is the authoritative declaration of
    "the minor the locks target" (it says so in its own header and pins the interpreter accordingly), so
    it is the single source of truth these guards compare the image pins against. Parsed statically."""
    if not BUILD_ENVS.is_file():
        return None
    m = re.search(r"command -v python(\d+\.\d+)", BUILD_ENVS.read_text(encoding="utf-8"))
    return m.group(1) if m else None


def _python_pin_drift(dockerfile_text: str, locked_minor: str) -> str | None:
    """Return a human description of the drift when `dockerfile_text`'s python base does not equal
    `locked_minor`, else None. The pure predicate both the positive test and the negative control run
    through, so the negatives prove the very code the positive relies on actually rejects bad input."""
    pin = _dockerfile_python_minor(dockerfile_text)
    if pin is None:
        return "no `FROM python:X.Y` base pin found"
    if pin != locked_minor:
        return f"pins python:{pin} but the committed locks target python:{locked_minor}"
    return None


def aegis_python_pin_drift() -> str | None:
    """The ENFORCING predicate of the W1-7 claim: None IFF the AEGIS Dockerfile's python base equals the
    minor the committed locks target. A non-None result is the drift that turns the claim red."""
    locked = _locked_python_minor()
    if locked is None:
        return "could not resolve the locked Python minor from envs/build_envs.sh"
    return _python_pin_drift(AEGIS_DOCKERFILE.read_text(encoding="utf-8"), locked)


def test_locked_python_minor_resolves() -> None:
    """Anti-vacuous: the source of truth parses, so the equality below is a real comparison and not a
    `None == None` pass."""
    locked = _locked_python_minor()
    assert locked is not None and re.fullmatch(r"\d+\.\d+", locked), (
        f"could not read the locked Python minor from {BUILD_ENVS.relative_to(REPO_ROOT)}"
    )


def test_aegis_runtime_python_is_aligned_to_the_locked_target() -> None:
    """The AEGIS image's Python base equals the minor the locks target — so the runtime that ships is the
    one CI exercises. FAILS on the pre-fix tree (aegis pinned 3.11 while the locks target 3.13)."""
    drift = aegis_python_pin_drift()
    assert drift is None, (
        f"the AEGIS Dockerfile is not aligned to the locked Python target: {drift}. Align "
        f"{AEGIS_DOCKERFILE.relative_to(REPO_ROOT)}'s `FROM python:` base to the locked minor (and re-pin "
        "its digest), or the shipped runtime is a version CI never exercises (W1-7 #416)."
    )


def test_gateway_and_aegis_share_the_locked_python_base() -> None:
    """Both public-facing data-plane images (the P6 egress gateway and the AEGIS sidecar) sit on the SAME
    locked Python minor — a second, independent witness that the alignment is to the real shipped base
    and not merely to a number in a build script."""
    locked = _locked_python_minor()
    aegis = _dockerfile_python_minor(AEGIS_DOCKERFILE.read_text(encoding="utf-8"))
    gateway = _dockerfile_python_minor(GATEWAY_DOCKERFILE.read_text(encoding="utf-8"))
    assert aegis == gateway == locked, (
        f"data-plane python bases disagree: aegis={aegis}, gateway={gateway}, locked={locked}"
    )


def test_python_pin_drift_is_not_vacuous_negative_control() -> None:
    """NEGATIVE CONTROL. The drift predicate FIRES on a Dockerfile pinning a different minor than the
    locked target (the gate is not a no-op), passes one that matches (it is not always-red), and the
    extractor reads the real `FROM`/`ARG` pin — not a commented example — and returns None for a
    non-python base."""
    locked = _locked_python_minor()
    assert locked is not None
    bad = f"FROM python:2.7-slim@sha256:{'0' * 64}\n"
    assert _python_pin_drift(bad, locked) is not None, "a mismatched python pin must be flagged"
    good = f"FROM python:{locked}-slim@sha256:{'0' * 64}\n"
    assert _python_pin_drift(good, locked) is None, "a pin equal to the locked target must pass"
    assert _dockerfile_python_minor("# FROM python:3.9-slim  (an example in a comment)\n") is None
    assert _dockerfile_python_minor("FROM scratch\n") is None
    assert _dockerfile_python_minor(
        "ARG PYTHON_BASE=python:3.13-slim@sha256:" + "a" * 64 + "\nFROM ${PYTHON_BASE}\n"
    ) == "3.13"
