"""
tools.registry — the canonical catalog of the EXTERNAL host CLIs the offense engine
invokes, plus a pure, LIVE status probe (WS-TOOLS).

This is the SINGLE SOURCE OF TRUTH shared by two consumers so they can never drift:

  * ``bootstrap.sh`` (exec-only shell) reads the roster via ``python -m
    framework.v2.tools.registry --emit-shell`` (a TAB-separated dump) to know what to
    install and how; and
  * the offense console's ``GET /api/tools`` endpoint calls :func:`probe_tools` to render
    the LIVE installed / missing / failed picture for the operator.

Only the OFFENSE side ever imports this module — the tools ARE the offense engine's, and
the sovereign process must never import ``framework`` (the P5 two-env boundary). It is
import-clean (stdlib only: ``os``/``sys``/``shutil``/``subprocess``/``re``/``concurrent.futures``) so importing
it is cheap and never pulls the scan/engage hot path.

Doctrine (why every status here is REAL, never invented):

  * ``installed`` is decided by ``shutil.which`` — the shell's own PATH resolution — at the
    moment of the probe. There is no cached / hardcoded "installed" anywhere; a tool the
    box does not have reports missing, always.
  * ``version`` is a best-effort, read-only ``<binary> <version-flag>`` capture (short
    timeout, no shell, stdin closed). It is extra colour for the operator, never the source
    of the installed decision, and a hang/timeout/garbage output simply yields no version.
  * ``failed`` is NOT something a live probe can know (it is a bootstrap-time event), so it
    is layered on TOP of the live probe from an OPTIONAL hint file the installer writes
    (``$VIGIL_TOOL_STATE``). The live probe always wins: a tool the hint calls "failed" but
    that is now on PATH reports installed. Without the hint, the world is only installed /
    missing — still fully truthful; the UI never DEPENDS on the hint.
  * host security tools are Linux packages. On a non-Linux OS every tool reports
    ``unsupported`` (never a faked install) and the installer skips.

What is in the HOST roster and why (kept to what the code ACTUALLY spawns as a subprocess —
not an aspirational arsenal; every entry is traceable to a call site):

  * nmap / httpx / nuclei / ffuf / sqlmap / hydra  → ``live.executor`` argv builders
    (the offense core the live ReAct loop drives); nmap/nuclei also power the read-only
    sensors (``sensors/nmap.py``, ``sensors/web_scanner.py``).
  * semgrep / joern / bandit                       → the SAST analysis backends
    (``analysis/analyzers/external.py`` / ``joern.py``); used when present, skipped cleanly.
  * gitleaks / trufflehog                          → the secret-scanning analysis backends
    (``analysis/analyzers/external.py``); run OFFLINE (trufflehog is pinned to
    ``--no-verification``, which is what stops it phoning every provider's API with the
    operator's secrets) and the leaked value is masked out of every finding.
  * tshark                                         → the packet-flow sensor (``sensors/tshark.py``).
  * chromium (or chrome)                           → headless DOM render for DOM-XSS
    confirmation (``scanner/browser.py`` / ``scanner/cdp.py``).
  * nikto / wapiti / zaproxy                       → the eval/import adapters that spawn the
    tool and parse its report (``eval/adapters.py`` / ``adapters_ext.py``).

Deliberately EXCLUDED from the probed host roster (honesty over completeness):

  * Burp Suite — the engine's Burp adapter talks to Burp's REST API (``CRUCIBLE_BURP_URL``),
    it never spawns a ``burpsuite`` binary; probing a binary the engine does not invoke would
    be a fabricated status, so Burp is not in the roster (configure it via its env var).

The Strix tools (``SANDBOX_TOOLS``) live in the ``vigil/strix-sandbox:local`` Kali image
(``vendor/strix/containers/Dockerfile``), NOT on the host; they are surfaced as informational
context only and are never probed on the host or installed by bootstrap.
"""

from __future__ import annotations

import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "ToolSpec",
    "HOST_TOOLS",
    "SANDBOX_TOOLS",
    "binary_resolution_order",
    "SANDBOX_IMAGE",
    "platform_info",
    "install_hint",
    "probe_tool",
    "probe_tools",
    "default_state_path",
]

# A version probe must never hang the request/probe; a real ``--version`` returns instantly.
_VERSION_TIMEOUT_S: float = 2.0
_VERSION_CAP: int = 140
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SEMVER_RE = re.compile(r"\d+\.\d+")


@dataclass(frozen=True)
class ToolSpec:
    """One external CLI the offense engine may invoke.

    ``name``          stable identifier (== the roster key; also the installer hint key).
    ``binary``        the primary executable probed with ``command -v`` / ``shutil.which``.
    ``alt_binaries``  other names the SAME tool may install as (e.g. ``chromium-browser``,
                      ``google-chrome``; ``zap.sh``/``zap-cli``); the probe resolves the first
                      that is on PATH, mirroring the engine's own resolution order.
    ``purpose``       one-line operator-facing description (where the engine uses it).
    ``apt``           Debian-family package that provides the binary (Kali/Ubuntu/Debian), or
                      ``None`` if not apt-installable.
    ``pip``           PyPI application to install (via pipx / pip --user), or ``None``.
    ``manual``        the exact human-facing command/URL the operator runs to install it
                      personally — printed verbatim when an auto-install is refused or fails.
    ``optional``      ``False`` for the tools the live executor's argv builders spawn directly
                      (the offense core); ``True`` for tools the engine uses when present and
                      degrades cleanly without (analysis backends, sensors, import adapters).
    ``version_args``  argv passed to the binary for a cheap version banner; ``None`` disables
                      the version probe (heavy/GUI tools we must not launch).
    ``version_timeout_s``
                      per-tool override of ``_VERSION_TIMEOUT_S`` for the banner probe. ``None``
                      keeps the 2 s default, which is right for a native binary that prints a
                      version and exits. A JVM tool does not: Joern's banner costs a full JVM +
                      REPL start (~11 s measured), so at 2 s it timed out and the tool reported
                      installed with NO version. Raised per-spec rather than globally on purpose
                      — the default must stay tight so one slow tool cannot stall the roster.
    ``sandbox``       informational: provided by the Strix sandbox image, not the host.
    """

    name: str
    binary: str
    purpose: str
    apt: Optional[str] = None
    pip: Optional[str] = None
    manual: str = ""
    optional: bool = True
    version_args: Optional[tuple[str, ...]] = ("--version",)
    version_timeout_s: Optional[float] = None
    alt_binaries: tuple[str, ...] = ()
    sandbox: bool = False
    # ``wrong_markers`` — case-insensitive substrings that, if they appear in the version banner of the
    # binary found on PATH, mean a DIFFERENT tool sharing this name is shadowing the real one (e.g. the
    # Python ``httpx`` HTTP-client CLI shadowing ProjectDiscovery's ``httpx``). A which-hit whose banner
    # matches is reported ``shadowed`` (NOT ``installed``) so a required tool that is effectively absent
    # never shows a false green. Requires ``version_args`` (the banner is what disambiguates). If the
    # banner is EMPTY (the probe produced no output) detection cannot disambiguate and falls OPEN to
    # trust-PATH (``installed``) — an honest default: no known impostor shadows a ``wrong_markers`` tool
    # with zero output, and the real tool prints a version.
    wrong_markers: tuple[str, ...] = ()


# ---------------------------------------------------------------------------------------------------
# the canonical HOST roster — every tool here is invoked as a real subprocess by engine code.
# ---------------------------------------------------------------------------------------------------

HOST_TOOLS: tuple[ToolSpec, ...] = (
    # -- offense core: the live executor spawns these directly (optional=False) --------------------
    ToolSpec(
        name="nmap", binary="nmap", optional=False,
        purpose="Port & service discovery (live executor + nmap sensor).",
        apt="nmap", version_args=("--version",),
        manual="sudo apt-get install -y nmap",
    ),
    ToolSpec(
        name="httpx", binary="httpx", optional=False,
        purpose="Fast HTTP probing / tech fingerprint (live executor). ProjectDiscovery httpx "
                "(the CLI, NOT the same-named Python HTTP client).",
        apt="httpx-toolkit", version_args=("-version",),
        # Kali's `httpx-toolkit` package installs the REAL ProjectDiscovery binary under that name,
        # precisely because the `httpx` name is taken by the Python HTTP client. Listing it here lets
        # the shadow-aware resolver step over the impostor and find the genuine tool already present,
        # instead of declaring a required tool unusable on a correctly-provisioned machine.
        alt_binaries=("httpx-toolkit",),
        # a same-named Python `httpx` HTTP-client CLI commonly shadows ProjectDiscovery's on PATH; its
        # banner is one of these (ProjectDiscovery's `-version` prints a clean version, never these).
        wrong_markers=("command line client could not run", "options] url", "no such option",
                       "pip install"),
        manual="Kali: sudo apt-get install -y httpx-toolkit (installs as `httpx-toolkit`, which is "
               "found automatically)  |  else: "
               "go install github.com/projectdiscovery/httpx/cmd/httpx@latest  "
               "(if a Python 'httpx' shadows it, ensure the real one precedes it on PATH)",
    ),
    ToolSpec(
        name="nuclei", binary="nuclei", optional=False,
        purpose="Template-based vulnerability scanning (live executor + web sensor).",
        apt="nuclei", version_args=("-version",),
        manual="Kali/Debian: sudo apt-get install -y nuclei  |  else: "
               "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    ToolSpec(
        name="ffuf", binary="ffuf", optional=False,
        purpose="Content / parameter fuzzing & discovery (live executor).",
        apt="ffuf", version_args=("-V",),
        manual="Kali/Debian: sudo apt-get install -y ffuf  |  else: go install github.com/ffuf/ffuf/v2@latest",
    ),
    ToolSpec(
        name="sqlmap", binary="sqlmap", optional=False,
        purpose="SQL-injection confirmation (live executor + eval adapter).",
        apt="sqlmap", pip="sqlmap", version_args=("--version",),
        manual="sudo apt-get install -y sqlmap  (or: pipx install sqlmap)",
    ),
    ToolSpec(
        name="hydra", binary="hydra", optional=False,
        purpose="Credential brute-force (live executor; destructive — floors at A3 + m-of-n quorum).",
        apt="hydra", version_args=(),  # bare invocation prints the version banner
        manual="sudo apt-get install -y hydra",
    ),
    # -- analysis backends: engine uses when present, degrades cleanly (optional=True) --------------
    ToolSpec(
        name="semgrep", binary="semgrep", optional=True,
        purpose="Static analysis (SAST) over source (source-review analysis backend).",
        pip="semgrep", version_args=("--version",),
        manual="pipx install semgrep  (or: python3 -m pip install --user semgrep)",
    ),
    # Wave 2 source scanners. They are in the roster because the arsenal must be able to NAME every
    # binary the engine spawns — the drift guard states the rule as "a driven tool the arsenal cannot
    # even name is a gap", and it caught these three the moment their analyzers landed.
    ToolSpec(
        name="bandit", binary="bandit", optional=True,
        purpose="Python-specific SAST over source (analysis backend).",
        pip="bandit", version_args=("--version",),
        manual="pipx install bandit  (or: python3 -m pip install --user bandit)",
    ),
    ToolSpec(
        name="gitleaks", binary="gitleaks", optional=True,
        purpose="Secret detection across a source tree and its git history (analysis backend).",
        apt="gitleaks", version_args=("version",),   # `gitleaks version`, NOT `--version`
        manual="sudo apt-get install -y gitleaks  (or: https://github.com/gitleaks/gitleaks/releases)",
    ),
    ToolSpec(
        name="trufflehog", binary="trufflehog", optional=True,
        purpose="Secret detection with per-detector classification (analysis backend). Always driven "
                "with --no-verification: verification contacts third-party APIs, which the charter's "
                "no-egress limit forbids.",
        version_args=("--version",),   # no apt/pip on Kali — installed out of band
        manual="https://github.com/trufflesecurity/trufflehog/releases  (or: brew install trufflehog)",
    ),
    ToolSpec(
        name="joern", binary="joern", optional=True,
        purpose="Code-property-graph inter-procedural dataflow (deep source review).",
        version_args=("--version",),  # no apt/pip — installed out of band
        # Joern's banner starts a JVM and its Scala REPL: ~11 s measured cold on this host,
        # so the 2 s default timed it out and the roster showed it installed with no version.
        version_timeout_s=60.0,
        manual="Install from https://joern.io (or set CRUCIBLE_JOERN_HOME to its dir).",
    ),
    ToolSpec(
        name="bandit", binary="bandit", optional=True,
        purpose="Python-specific SAST — the AST checks semgrep's taint mode does not cover "
                "(source-review analysis backend).",
        apt="bandit", pip="bandit", version_args=("--version",),
        manual="pipx install bandit  (or: sudo apt-get install -y bandit)",
    ),
    ToolSpec(
        name="gitleaks", binary="gitleaks", optional=True,
        purpose="Secret scanning over the source tree (analysis backend). Runs offline on its "
                "embedded rules; the leaked VALUE is masked out of every finding, never recorded.",
        apt="gitleaks", version_args=("version",),  # v8's banner is a subcommand, not a flag
        manual="Kali/Debian: sudo apt-get install -y gitleaks  |  else: "
               "go install github.com/gitleaks/gitleaks/v8@latest",
    ),
    ToolSpec(
        name="trufflehog", binary="trufflehog", optional=True,
        purpose="Secret scanning over the source tree (analysis backend). Always run with "
                "--no-verification: verification calls third-party provider APIs with the "
                "operator's real secrets, and this host forbids all egress.",
        # Deliberately NO ``apt``: several distros package the abandoned python trufflehog v2 under
        # this same name, and v2 has no ``filesystem`` subcommand — an auto-install would put a
        # binary on PATH that the adapter cannot drive, which is worse than reporting it missing.
        version_args=("--version",),
        manual="Install trufflehog v3 from https://github.com/trufflesecurity/trufflehog/releases "
               "(or: go install github.com/trufflesecurity/trufflehog/v3@latest). NOT the python "
               "'trufflehog' v2 package — a different CLI with no `filesystem` subcommand.",
    ),
    # -- sensors / browser: read-only observation surfaces (optional=True) --------------------------
    ToolSpec(
        name="tshark", binary="tshark", optional=True,
        purpose="Packet-capture flow analysis (tshark sensor).",
        apt="tshark", version_args=("--version",),
        manual="sudo apt-get install -y tshark",
    ),
    ToolSpec(
        name="chromium", binary="chromium", optional=True,
        alt_binaries=("chromium-browser", "google-chrome-stable", "google-chrome", "chrome"),
        purpose="Headless DOM render for DOM-XSS confirmation (scanner browser/CDP).",
        apt="chromium", version_args=("--version",),
        manual="Kali/Debian: sudo apt-get install -y chromium  |  Ubuntu: sudo snap install chromium "
               "(or install Google Chrome).",
    ),
    # -- import/eval adapter tools: the engine spawns these and parses their report -----------------
    ToolSpec(
        name="nikto", binary="nikto", optional=True,
        purpose="Web-server misconfiguration scan (eval/import adapter parses its output).",
        apt="nikto", version_args=("-Version",),
        manual="sudo apt-get install -y nikto",
    ),
    ToolSpec(
        name="wapiti", binary="wapiti", optional=True,
        purpose="Web-application vulnerability scan (eval/import adapter parses its JSON).",
        apt="wapiti", pip="wapiti3", version_args=("--version",),
        manual="sudo apt-get install -y wapiti  (or: pipx install wapiti3)",
    ),
    ToolSpec(
        name="zaproxy", binary="zaproxy", optional=True,
        alt_binaries=("zap.sh", "zap-cli"),
        purpose="OWASP ZAP DAST (eval/import adapter parses its JSON report).",
        apt="zaproxy", version_args=None,  # GUI/daemon wrapper — do not launch it to read a version
        manual="sudo apt-get install -y zaproxy",
    ),
)


# ---------------------------------------------------------------------------------------------------
# the Strix sandbox roster — provided by the vigil/strix-sandbox:local Kali image, NOT the host.
# Informational only: never probed on the host, never installed by bootstrap. Drawn from the real
# image definition (vendor/strix/containers/Dockerfile) so this stays honest, not aspirational.
# ---------------------------------------------------------------------------------------------------

SANDBOX_IMAGE = "vigil/strix-sandbox:local"

SANDBOX_TOOLS: tuple[ToolSpec, ...] = tuple(
    ToolSpec(name=n, binary=n, purpose=p, sandbox=True, version_args=None, optional=True)
    for n, p in (
        ("nmap", "Port & service discovery."),
        ("ncat", "Netcat networking / listeners."),
        ("sqlmap", "SQL-injection confirmation."),
        ("nuclei", "Template-based vulnerability scanning."),
        ("httpx", "HTTP probing / fingerprint (ProjectDiscovery)."),
        ("subfinder", "Passive subdomain enumeration."),
        ("naabu", "Fast port scanning."),
        ("ffuf", "Content / parameter fuzzing."),
        ("katana", "Crawling / endpoint discovery."),
        ("gospider", "Web spidering."),
        ("arjun", "HTTP parameter discovery."),
        ("dirsearch", "Path brute-forcing."),
        ("wafw00f", "WAF fingerprinting."),
        ("interactsh-client", "Out-of-band interaction capture."),
        ("wapiti", "Web-application vulnerability scan."),
        ("zaproxy", "OWASP ZAP DAST."),
        ("semgrep", "Static analysis (SAST)."),
        ("bandit", "Python security linter."),
        ("trufflehog", "Secret discovery."),
        ("gitleaks", "Secret discovery in git history."),
        ("trivy", "SCA / container / IaC scanning."),
        ("chromium", "Headless browser for the agent-browser."),
        ("caido-cli", "Intercepting proxy (Caido)."),
        ("jwt_tool", "JWT analysis / attack."),
    )
)


def binary_resolution_order(tool_name: str) -> tuple[str, ...]:
    """The canonical order in which a tool's binary is looked up on PATH: its declared
    ``binary`` first, then each ``alt_binaries`` name — the same order the shadow-aware
    resolver walks (see ``_resolve`` below, ``for name in (spec.binary, *spec.alt_binaries)``).

    This exists so a tool that installs under several names (ZAP as ``zaproxy`` / ``zap.sh`` /
    ``zap-cli``; ProjectDiscovery httpx as ``httpx-toolkit``) has ONE source of truth for that
    order. A consumer that hardcodes its own tuple silently drifts — the eval ZAP adapter did
    exactly that, resolving ``zap.sh`` before ``zaproxy`` while the production sensor resolved
    ``zaproxy`` first, so on a host with both they picked different binaries. Returns ``()`` for
    an unknown tool, so a caller can fall back rather than crash."""
    spec = next((s for s in (*HOST_TOOLS, *SANDBOX_TOOLS) if s.name == tool_name), None)
    if spec is None:
        return ()
    return (spec.binary, *spec.alt_binaries)


# ---------------------------------------------------------------------------------------------------
# platform detection — host security tools are Linux packages
# ---------------------------------------------------------------------------------------------------


def _os_release() -> dict[str, str]:
    """Parse ``/etc/os-release`` into a dict, total (missing file / unreadable → ``{}``)."""
    out: dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return {}
    return out


def platform_info() -> dict[str, object]:
    """Describe the host OS and whether the host tool roster is supported here.

    ``supported`` is True only on Linux (where these packages live). ``debian_family`` is
    True on Kali/Ubuntu/Debian and any ``ID_LIKE=debian`` derivative — the apt path the
    installer drives. Total: any probe failure degrades to "unknown, unsupported"."""
    system = sys.platform
    is_linux = system.startswith("linux")
    rel = _os_release() if is_linux else {}
    osid = (rel.get("ID") or "").lower()
    id_like = (rel.get("ID_LIKE") or "").lower()
    debian_family = is_linux and (
        osid in {"debian", "ubuntu", "kali"} or "debian" in id_like or "ubuntu" in id_like
    )
    return {
        "system": "Linux" if is_linux else system,
        "id": osid or None,
        "id_like": id_like or None,
        "pretty_name": rel.get("PRETTY_NAME") or None,
        "supported": bool(is_linux),
        "debian_family": bool(debian_family),
    }


# ---------------------------------------------------------------------------------------------------
# install hints + the optional installer state hint file
# ---------------------------------------------------------------------------------------------------


def install_hint(spec: ToolSpec) -> str:
    """The exact command the operator can run to install ``spec`` personally. Prefers the tool's
    curated ``manual`` string (which already spells out the apt/pip/fallback), then apt, then pip."""
    if spec.manual:
        return spec.manual
    if spec.apt:
        return f"sudo apt-get install -y {spec.apt}"
    if spec.pip:
        return f"pipx install {spec.pip}"
    return f"(install {spec.binary} manually)"


def default_state_path() -> str:
    """Where the installer records per-tool outcomes (the FAILED hint the live probe layers on).

    ``$VIGIL_TOOL_STATE`` wins; else ``$SIGIL_HOME/vigil-tool-state.tsv``; else
    ``~/.sigil/vigil-tool-state.tsv``. bootstrap.sh reads this identical value via ``--state-path``."""
    env = os.environ.get("VIGIL_TOOL_STATE")
    if env:
        return env
    home = os.environ.get("SIGIL_HOME") or os.path.join(os.path.expanduser("~"), ".sigil")
    return os.path.join(home, "vigil-tool-state.tsv")


def _read_install_state(path: Optional[str]) -> dict[str, str]:
    """Read the installer's ``name<TAB>outcome`` hint file, total. Unknown/absent → ``{}``.

    Outcomes: ``installed`` / ``failed`` / ``missing`` / ``skipped`` / ``unsupported``. Only
    ``failed`` is load-bearing here (it upgrades a not-on-PATH tool from MISSING to FAILED);
    everything else defers to the live probe, so a stale hint never fabricates an installed status."""
    p = path or default_state_path()
    state: dict[str, str] = {}
    try:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                name, _, outcome = line.partition("\t")
                name = name.strip()
                outcome = outcome.strip().lower()
                if name and outcome:
                    state[name] = outcome
    except OSError:
        return {}
    return state


# ---------------------------------------------------------------------------------------------------
# the live probe — pure, no side effects, no install
# ---------------------------------------------------------------------------------------------------


def _resolve(spec: ToolSpec) -> Optional[str]:
    """Resolve the tool on PATH: the primary binary first, then each alternate name (the engine's
    own resolution order). Returns the absolute path of the first USABLE hit, or ``None``.

    Shadow-aware. This used to return the first PATH hit and stop, which made ``alt_binaries``
    useless for exactly the case it was needed: on Kali the real ProjectDiscovery ``httpx`` installs
    as ``httpx-toolkit`` while a same-named Python HTTP-client CLI occupies ``httpx``. The resolver
    stopped at the impostor and reported the tool shadowed and unusable — on a machine where the real
    one was installed the whole time. A tool that is present must not be reported absent.

    So when ``wrong_markers`` is set, each candidate's banner is checked and a candidate identified
    as a DIFFERENT tool is skipped in favour of the next name. If every candidate is an impostor the
    first one is still returned, so the status stays the honest ``shadowed`` rather than ``missing``:
    the operator needs to know a decoy is sitting on the name, not merely that nothing was found.
    """
    return _resolve_with_banner(spec)[0]


def _resolve_with_banner(spec: ToolSpec) -> tuple[Optional[str], str]:
    """:func:`_resolve`, also returning the version banner it read while disambiguating (``""`` when
    it did not need to read one). The caller reuses that banner instead of re-running the probe — the
    roster is resolved inside an HTTP request, so a second subprocess per collision tool is a cost
    paid on every page load, and it was enough to time the tools endpoint out."""
    impostor: tuple[Optional[str], str] = (None, "")
    for name in (spec.binary, *spec.alt_binaries):
        path = shutil.which(name)
        if not path:
            continue
        if spec.wrong_markers:
            raw = _probe_raw(path, spec.version_args, spec.version_timeout_s)
            if raw and any(m in raw.lower() for m in spec.wrong_markers):
                if impostor[0] is None:
                    impostor = (path, raw)
                continue
            return path, raw
        return path, ""
    return impostor


def _clean_version(raw: str) -> str:
    """Extract a compact version line from a tool's banner, total. Strips ANSI colour, prefers
    the first line that carries a ``N.N`` version token, else the first non-empty line, capped."""
    if not raw:
        return ""
    text = _ANSI_RE.sub("", raw)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    chosen = next((ln for ln in lines if _SEMVER_RE.search(ln)), lines[0])
    return chosen[:_VERSION_CAP]


def _probe_raw(binary_path: str, version_args: Optional[tuple[str, ...]],
               timeout_s: Optional[float] = None) -> str:
    """Best-effort, read-only capture of the FULL version banner (stdout+stderr), ANSI-stripped.
    ``version_args is None`` → skip (heavy/GUI tool). ``timeout_s`` overrides the default budget
    for the tools whose banner is genuinely slow (see ``ToolSpec.version_timeout_s``). Never
    raises: a timeout / spawn error yields ``""``. No shell; stdin is closed so a tool that would
    prompt can never hang the probe."""
    if version_args is None:
        return ""
    try:
        # Probe from a throwaway cwd. "Read-only" has to mean it: Joern's launcher
        # creates a `workspace/` directory in whatever cwd it starts in, so reading
        # its version from the engine's cwd littered the operator's repo (empty, and
        # gitignored, but still a write from a probe documented as read-only). Every
        # version probe uses an absolute binary path and a version flag, so none of
        # them depends on cwd and a neutral one is always safe.
        with tempfile.TemporaryDirectory(prefix="crucible-verprobe-") as td:
            proc = subprocess.run(  # noqa: S603 - fixed argv (resolved path + our flags), shell=False
                [binary_path, *version_args],
                capture_output=True, text=True,
                timeout=_VERSION_TIMEOUT_S if timeout_s is None else timeout_s,
                stdin=subprocess.DEVNULL, check=False, cwd=td,
            )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return ""
    return _ANSI_RE.sub("", (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""))


def _probe_version(binary_path: str, version_args: Optional[tuple[str, ...]],
                   timeout_s: Optional[float] = None) -> str:
    """The compact one-line version banner for display (wraps :func:`_probe_raw`)."""
    return _clean_version(_probe_raw(binary_path, version_args, timeout_s))


def probe_tool(spec: ToolSpec, *, with_version: bool = True,
               supported: bool = True, install_state: Optional[dict[str, str]] = None) -> dict[str, object]:
    """Live status for one tool. Pure: it resolves PATH (and optionally reads a version banner) but
    installs nothing and mutates nothing.

    ``status`` is derived, live-first:
      * ``unsupported`` — the host OS is not Linux (these are Linux packages);
      * ``shadowed``    — a binary of this name is on PATH but its version banner matches a
                          ``wrong_markers`` pattern, i.e. a DIFFERENT same-named tool shadows the real
                          one (e.g. Python ``httpx`` shadowing ProjectDiscovery ``httpx``). Reported as
                          effectively-missing (NEVER a false green for a required tool);
      * ``installed``   — the binary (or an alternate) is on PATH (the live truth always wins);
      * ``failed``      — not usable AND the installer's hint says it failed to install;
      * ``missing``     — not usable and no failed hint.
    """
    # `_resolve` already had to read a banner for a name-collision tool, in order to step over an
    # impostor and find the real binary under an alternate name. Take that banner back rather than
    # spawning the same probe a second time: this runs inside an HTTP request that probes the whole
    # roster, and a duplicated subprocess per collision tool was enough to time the endpoint out.
    path, resolved_raw = _resolve_with_banner(spec)
    on_path = path is not None
    # For a name-collision tool we MUST read the banner (even when with_version=False) to tell the real
    # tool from a same-named impostor on PATH — the banner is the disambiguator.
    if resolved_raw:
        raw = resolved_raw
    else:
        raw = (_probe_raw(path, spec.version_args, spec.version_timeout_s)
               if (on_path and (with_version or spec.wrong_markers)) else "")
    shadowed = bool(on_path and spec.wrong_markers and raw
                    and any(m in raw.lower() for m in spec.wrong_markers))
    installed = on_path and not shadowed
    version = _clean_version(raw) if (on_path and with_version) else ""

    if not supported:
        status = "unsupported"
    elif shadowed:
        status = "shadowed"
    elif installed:
        status = "installed"
    elif (install_state or {}).get(spec.name) == "failed":
        status = "failed"
    else:
        status = "missing"

    return {
        "name": spec.name,
        "binary": spec.binary,
        "purpose": spec.purpose,
        "optional": spec.optional,
        "installed": installed,
        "shadowed": shadowed,
        "path": path,
        "version": version or None,
        "status": status,
        "install_hint": install_hint(spec),
        "apt": spec.apt,
        "pip": spec.pip,
    }


def probe_tools(*, with_version: bool = True,
                install_state: Optional[dict[str, str]] = None,
                state_path: Optional[str] = None) -> dict[str, object]:
    """The full LIVE tool-status report: platform, every host tool's status, the informational
    Strix-sandbox roster, and a summary count. Pure/total — safe to call on every request.

    ``install_state`` may be supplied directly (tests); otherwise it is read fail-soft from the
    installer's hint file (``state_path`` or :func:`default_state_path`)."""
    plat = platform_info()
    supported = bool(plat["supported"])
    state = install_state if install_state is not None else _read_install_state(state_path)

    # Probed CONCURRENTLY. Each tool's probe spawns a subprocess and waits on it, so a serial sweep
    # costs the SUM of every tool's start-up time — and that grows as the operator installs more.
    # Measured here: 5.3s across the roster, of which semgrep alone was 1.9s, and the per-probe
    # ceiling is 2s, so a fully-populated host could sit near half a minute. This report is rendered
    # on a screen and re-probed on every refresh; a page that gets slower each time you install a
    # tool is a page nobody refreshes. The probes are independent and read-only, so the wall time
    # becomes the SLOWEST tool rather than the sum.
    #
    # Order is preserved (`executor.map`), because the report's ordering is part of its contract.
    # A worker that raises would poison `map`, so each probe is wrapped: an unexpected failure
    # degrades that ONE row to "missing" rather than taking down the whole report.
    def _one(spec: ToolSpec) -> dict[str, object]:
        try:
            return probe_tool(spec, with_version=with_version, supported=supported, install_state=state)
        except Exception:  # noqa: BLE001 — a probe is best-effort; never fail the whole report
            pass
        try:
            return probe_tool(spec, with_version=False, supported=supported, install_state=state)
        except Exception:  # noqa: BLE001
            pass
        # Both attempts failed, so this row is SYNTHESISED rather than dropped. `map` yields one result
        # per spec and the summary counts them, so returning nothing here would silently shorten the
        # roster — a tool that vanishes from the list reads as "not part of this build", which is a
        # different and wrong claim from "we could not probe it". Fail toward NOT-READY, never toward a
        # green row: an unprobeable tool is reported as missing.
        return {
            "name": spec.name, "binary": spec.binary, "purpose": spec.purpose,
            "optional": spec.optional, "installed": False, "shadowed": False, "path": None,
            "version": None, "status": "unsupported" if not supported else "missing",
            "install_hint": install_hint(spec), "apt": spec.apt, "pip": spec.pip,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(HOST_TOOLS) or 1)) as pool:
        tools = list(pool.map(_one, HOST_TOOLS))

    def _count(status: str) -> int:
        return sum(1 for t in tools if t["status"] == status)

    summary = {
        "total": len(tools),
        "installed": _count("installed"),
        "missing": _count("missing"),
        "failed": _count("failed"),
        "shadowed": _count("shadowed"),
        "unsupported": _count("unsupported"),
        # a required tool that is missing, failed, OR shadowed by a same-named impostor is NOT ready.
        "required_missing": sum(
            1 for t in tools if not t["optional"] and t["status"] in ("missing", "failed", "shadowed")
        ),
    }

    sandbox = [
        {"name": s.name, "purpose": s.purpose, "sandbox": True} for s in SANDBOX_TOOLS
    ]

    return {
        "platform": plat,
        "tools": tools,
        "summary": summary,
        "sandbox": {"image": SANDBOX_IMAGE, "tools": sandbox,
                    "note": "Strix runs each engagement in the Kali sandbox image; these tools come "
                            "from that image, not the host, and are neither probed nor installed here."},
        "doctrine": "Status is probed LIVE (command -v + a cheap version) at request time — never "
                    "cached or invented. 'failed' comes from the installer's hint and the live probe "
                    "always overrides it. Host security tools are Linux packages.",
    }


# ---------------------------------------------------------------------------------------------------
# the shell bridge — bootstrap.sh reads the roster from here so the two never drift
# ---------------------------------------------------------------------------------------------------

# The field separator for the shell roster is the ASCII unit separator (0x1F), NOT a tab: a tab is
# an IFS-whitespace char, so ``IFS=$'\t' read`` COLLAPSES consecutive tabs and drops EMPTY middle
# fields (e.g. a tool with no ``apt`` pkg would shift every later column left). 0x1F is non-whitespace,
# so ``IFS=$'\x1f' read`` preserves every field — empty ones included — which the installer relies on.
_SHELL_SEP = "\x1f"
_SHELL_COLUMNS = ("name", "binary", "optional", "apt", "pip", "manual", "purpose", "alt")


def _emit_shell() -> str:
    """A 0x1F-separated dump of the HOST roster for ``bootstrap.sh`` (one tool per line, columns:
    name, binary, optional(1/0), apt, pip, manual, purpose, alt). ``alt`` is the comma-joined
    alternate binary names (so the installer can detect a tool already present under an alternate,
    e.g. ``chromium-browser``/``zap.sh``). Empty cells are ``""`` and are PRESERVED by the 0x1F
    (non-whitespace) separator; no field contains the separator or a newline (purposes are
    single-line), so a bash ``while IFS=$'\\x1f' read`` parses every row unambiguously."""
    def cell(v: object) -> str:
        if v is None:
            return ""
        return str(v).replace(_SHELL_SEP, " ").replace("\t", " ").replace("\r", " ").replace("\n", " ")

    lines = []
    for s in HOST_TOOLS:
        lines.append(_SHELL_SEP.join((
            cell(s.name), cell(s.binary), "1" if s.optional else "0",
            cell(s.apt), cell(s.pip), cell(s.manual), cell(s.purpose),
            cell(",".join(s.alt_binaries)),
        )))
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI shim: ``--emit-shell`` prints the roster (for bootstrap); ``--state-path`` prints the
    default installer-state path; ``--check NAME`` exits 0 iff that tool is REALLY installed (status
    ``installed`` — a shadowed/missing/failed tool exits 1), so bootstrap shares the registry's one
    definition of "present" (incl. the name-collision banner check) rather than duplicating it in bash;
    default prints the live report as JSON (a quick self-check)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if "--emit-shell" in args:
        print(_emit_shell())
        return 0
    if "--state-path" in args:
        print(default_state_path())
        return 0
    if "--check" in args:
        i = args.index("--check")
        name = args[i + 1] if i + 1 < len(args) else ""
        spec = next((s for s in HOST_TOOLS if s.name == name), None)
        if spec is None:
            return 2
        plat = platform_info()
        st = probe_tool(spec, with_version=True, supported=bool(plat["supported"]))
        return 0 if st["status"] == "installed" else 1
    import json
    print(json.dumps(probe_tools(with_version="--no-version" not in args), indent=2, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
