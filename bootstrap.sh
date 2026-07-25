#!/usr/bin/env bash
# =============================================================================
# VIGIL bootstrap — stand up the ENTIRE system on a fresh machine, one command.
# =============================================================================
# Put this codebase on a new PC and run:  ./bootstrap.sh
#
# It is IDEMPOTENT (re-runnable; every step guards on existing state) and
# FAIL-CLOSED (a hard-requirement failure stops with a clear remedy; an optional
# piece missing prints a warning and continues). It NEVER exposes a public
# listener and NEVER silently weakens a security boundary.
#
# What it does:
#   1. preflight   — Python 3.12/3.13, Rust (for the WARDEN kernel), Docker, git, TPM probe
#   2. build       — the TWO isolated venvs + the Rust kernel (envs/build_envs.sh) + boundary check
#   3. services    — start docker-compose services (Qdrant by default), bind 127.0.0.1 only
#   4. config      — write ~/.sigil/sigil.env + repo .env, launchers, VIGIL_ROOT/CRUCIBLE_ROOT
#   5. vault       — TPM-seal the keys at rest if a TPM is present; else a loud plaintext warning
#   6. smoke       — prove the boundary holds, Qdrant is up, and vigil/sigil run
#
# Flags / env:
#   --no-rust            do NOT auto-install rustup; print instructions and stop if Rust is missing
#   --no-services        skip docker-compose (native-only install; Qdrant runs embedded)
#   --with-strix         also build the Kali strix sandbox image (needs Docker; large)
#   --no-tools           skip the offense host-tool install/probe step (nmap/nuclei/httpx/...)
#   --with-tools         force the host-tool step on (it is on by default)
#   --systemd            install the user systemd units (cockpit + consolidate)
#   --yes                non-interactive: assume "yes" to auto-installs (rustup + apt/pipx host tools)
#   PYTHON=python3.13    pin the interpreter used to build the venvs
# -----------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"                       # repo root
REPO="$(pwd)"
export VIGIL_ROOT="$REPO"
export CRUCIBLE_ROOT="$REPO/engine/crucible"

# --- flags ---
NO_RUST=0; NO_SERVICES=0; WITH_STRIX=0; DO_SYSTEMD=0; ASSUME_YES=0; WITH_TOOLS=1
for arg in "$@"; do
  case "$arg" in
    --no-rust) NO_RUST=1 ;;
    --no-services) NO_SERVICES=1 ;;
    --with-strix) WITH_STRIX=1 ;;
    --no-tools) WITH_TOOLS=0 ;;
    --with-tools) WITH_TOOLS=1 ;;
    --systemd) DO_SYSTEMD=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) grep '^#' "$0" | grep -v '^#!' | sed 's/^#\s\{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $arg (try --help)"; exit 2 ;;
  esac
done

# --- pretty output ---
c_g="\033[32m"; c_y="\033[33m"; c_r="\033[31m"; c_b="\033[1m"; c_0="\033[0m"
step() { printf "\n${c_b}==> %s${c_0}\n" "$*"; }
ok()   { printf "  ${c_g}ok${c_0}   %s\n" "$*"; }
warn() { printf "  ${c_y}warn${c_0} %s\n" "$*"; }
die()  { printf "  ${c_r}FAIL${c_0} %s\n" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
ask()  { # ask "prompt" -> 0 (yes) / 1 (no). --yes => yes; NON-interactive without --yes => NO (fail-closed,
         # so a headless run never fetch-and-executes a third-party installer without explicit consent).
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || return 1
  read -r -p "  $1 [Y/n] " a; [ -z "$a" ] || [ "$a" = y ] || [ "$a" = Y ]
}

# --- offense host-tool provisioning (WS-TOOLS) -------------------------------------------------
# The external CLIs the OFFENSE engine SPAWNS (nmap/nuclei/httpx/ffuf/sqlmap/hydra + analysis/
# sensor/adapter tools). The single source of truth for the roster is the offense engine itself
# (framework.v2.tools.registry, offense-side only — the sovereign process never imports it), read
# here via `--emit-shell`. This step DETECTS the OS, PROBES each tool (command -v), INSTALLS the
# missing ones WITH CONSENT (apt for system packages, pipx/pip --user for Python apps), and RECORDS
# a per-tool outcome the console's Tools screen reads live. It is FAIL-SOFT + IDEMPOTENT: an
# already-present tool is a no-op; a tool that will not install is recorded FAILED with its exact
# manual command and the step CONTINUES — a tool never aborts bootstrap.

_tool_present() {  # binary  "alt1,alt2"  -> 0 if the tool (or an alternate name) is on PATH
  command -v "$1" >/dev/null 2>&1 && return 0
  local b oldifs="$IFS"; IFS=', '
  for b in $2; do
    IFS="$oldifs"
    [ -n "$b" ] && command -v "$b" >/dev/null 2>&1 && return 0
    IFS=', '
  done
  IFS="$oldifs"; return 1
}

_install_one() {  # binary apt pip apt_ok sudo  -> 0 installed / 1 failed (never raises)
  local bin="$1" aptp="$2" pipp="$3" apt_ok="$4" sudo="$5"
  if [ -n "$aptp" ] && [ "$apt_ok" = 1 ]; then
    $sudo apt-get install -y "$aptp" >/dev/null 2>&1 || true
    command -v "$bin" >/dev/null 2>&1 && return 0
  fi
  if [ -n "$pipp" ]; then
    if have pipx; then pipx install "$pipp" >/dev/null 2>&1 || true; fi
    command -v "$bin" >/dev/null 2>&1 && return 0
    "$PY" -m pip install --user "$pipp" >/dev/null 2>&1 || true
    command -v "$bin" >/dev/null 2>&1 && return 0
  fi
  return 1
}

provision_host_tools() {
  local SH="${SIGIL_HOME:-$HOME/.sigil}"; export SIGIL_HOME="$SH"; mkdir -p "$SH"
  # pipx / pip --user land in ~/.local/bin — put it on PATH so a post-install probe sees them.
  export PATH="$HOME/.local/bin:$PATH"

  local PYX="$REPO/.venv-offense/bin/python"; [ -x "$PYX" ] || PYX="$PY"
  emit() { PYTHONPATH="$CRUCIBLE_ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYX" -m framework.v2.tools.registry "$@" 2>/dev/null; }

  local STATE_FILE; STATE_FILE="$(emit --state-path)"; [ -n "$STATE_FILE" ] || STATE_FILE="$SH/vigil-tool-state.tsv"
  mkdir -p "$(dirname "$STATE_FILE")"
  local ROSTER; ROSTER="$(emit --emit-shell)"
  if [ -z "$ROSTER" ]; then warn "could not read the tool roster from the offense engine — skipping tool provisioning."; return 0; fi

  # OS detect via /etc/os-release (ubuntu/debian/kali/other-linux; non-Linux → unsupported).
  local OS_KERNEL OS_ID="" OS_LIKE="" OS_PRETTY="" DEBIAN=0
  OS_KERNEL="$(uname -s 2>/dev/null || echo unknown)"
  if [ -r /etc/os-release ]; then . /etc/os-release; OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_PRETTY="${PRETTY_NAME:-}"; fi
  case " $OS_ID $OS_LIKE " in *" debian "*|*" ubuntu "*|*" kali "*) DEBIAN=1 ;; esac

  : > "$STATE_FILE"
  printf '# vigil host-tool install state — bootstrap.sh %s (os=%s)\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${OS_PRETTY:-${OS_ID:-$OS_KERNEL}}" >> "$STATE_FILE"

  # Non-Linux: these are Linux packages. Report unsupported (never a faked install), install nothing.
  if [ "$OS_KERNEL" != "Linux" ]; then
    warn "offense host tools are Linux packages; this host is '$OS_KERNEL' — UNSUPPORTED. Skipping install."
    warn "run the offense engine on Linux (Kali/Ubuntu/Debian) for nmap/nuclei/httpx/ffuf/sqlmap/…"
    while IFS=$'\x1f' read -r nm _bin _opt _apt _pip _man _pur _alt; do
      [ -n "$nm" ] && printf '%s\tunsupported\n' "$nm" >> "$STATE_FILE"
    done <<< "$ROSTER"
    return 0
  fi
  [ "$DEBIAN" = 1 ] || warn "OS '${OS_ID:-$OS_KERNEL}' is not Debian-family — apt is unavailable; tools will be reported for manual install."

  # sudo / apt availability. Root needs no sudo; non-root uses sudo if present, else apt is off.
  local UID_NOW SUDO="" APT_OK=0
  UID_NOW="$(id -u 2>/dev/null || echo 1000)"
  if [ "$UID_NOW" != "0" ] && have sudo; then SUDO="sudo"; fi
  if [ "$DEBIAN" = 1 ] && have apt-get && { [ "$UID_NOW" = "0" ] || [ -n "$SUDO" ]; }; then APT_OK=1; fi

  # One consent gate for the whole step: --yes ⇒ install; interactive ⇒ ask; non-tty w/o --yes ⇒ NO.
  local CONSENT=0
  if [ "$ASSUME_YES" = 1 ]; then CONSENT=1
  elif ask "install missing offense host tools now? (apt needs sudo; pipx/pip are user-level)"; then CONSENT=1; fi
  if [ "$CONSENT" != 1 ]; then warn "no consent (or non-interactive) — probing only; missing tools are reported with their exact install command."; fi
  if [ "$CONSENT" = 1 ] && [ "$APT_OK" = 1 ]; then
    $SUDO apt-get update >/dev/null 2>&1 || warn "apt-get update failed — continuing; individual installs may still work."
  fi

  local n_ok=0 n_missing=0 n_failed=0 n_total=0 n_req_missing=0
  while IFS=$'\x1f' read -r nm bin opt aptp pipp man pur alt; do
    [ -n "$nm" ] || continue
    n_total=$((n_total+1))
    if _tool_present "$bin" "$alt"; then
      ok "$nm present ($(command -v "$bin" 2>/dev/null || echo "$bin"))"
      printf '%s\tinstalled\n' "$nm" >> "$STATE_FILE"; n_ok=$((n_ok+1)); continue
    fi
    if [ "$CONSENT" = 1 ] && _install_one "$bin" "$aptp" "$pipp" "$APT_OK" "$SUDO"; then
      ok "$nm installed"
      printf '%s\tinstalled\n' "$nm" >> "$STATE_FILE"; n_ok=$((n_ok+1)); continue
    fi
    if [ "$CONSENT" = 1 ]; then
      warn "$nm FAILED to install — install it yourself:  ${man:-see docs/DEPLOY.md}"
      printf '%s\tfailed\n' "$nm" >> "$STATE_FILE"; n_failed=$((n_failed+1))
    else
      warn "$nm missing — install it yourself:  ${man:-see docs/DEPLOY.md}"
      printf '%s\tmissing\n' "$nm" >> "$STATE_FILE"; n_missing=$((n_missing+1))
    fi
    [ "$opt" = "0" ] && n_req_missing=$((n_req_missing+1))
  done <<< "$ROSTER"

  printf "  ${c_b}tools:${c_0} %d installed / %d missing / %d failed (of %d)\n" "$n_ok" "$n_missing" "$n_failed" "$n_total"
  if [ "$n_req_missing" -gt 0 ]; then
    warn "$n_req_missing REQUIRED offense-core tool(s) not installed — live engagements needing them will refuse until you install them."
  fi
  ok "recorded per-tool status → $STATE_FILE (the console Tools screen reads this live)"
  return 0
}

# =============================================================================
step "1/6 preflight"
# =============================================================================

# Python 3.12/3.13 — a hard requirement (the venvs + kernel build need it).
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for cand in python3.13 python3.12 python3; do have "$cand" && { PY="$cand"; break; }; done
fi
[ -n "$PY" ] || die "no Python found. Install Python 3.12 or 3.13 and re-run (or set PYTHON=...)."
PYVER="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
case "$PYVER" in
  3.12|3.13) ok "Python $PYVER ($PY)" ;;
  *) die "Python $PYVER is unsupported — need 3.12 or 3.13 (set PYTHON=python3.13)." ;;
esac

# Rust — needed by setuptools-rust to build the WARDEN kernel (part of the sovereign venv).
if have cargo && have rustc; then
  ok "Rust $(rustc --version 2>/dev/null | awk '{print $2}')"
elif [ "$NO_RUST" = 1 ]; then
  die "Rust is missing and --no-rust was given. Install it: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
else
  warn "Rust toolchain not found — it is required to build the WARDEN kernel."
  if ask "install rustup into ~/.cargo now (user-level, no root)?"; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
    have cargo || die "rustup installed but cargo is not on PATH — open a new shell and re-run."
    ok "Rust $(rustc --version 2>/dev/null | awk '{print $2}') (freshly installed)"
  else
    die "Rust is required. Install it (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh) and re-run — or re-run with --yes to auto-install it non-interactively."
  fi
fi

have git || warn "git not found — fine for a build, but you'll need it for updates."

# Docker (optional: Qdrant runs embedded without it; strix + server-mode Qdrant need it).
DOCKER_OK=0
if have docker && docker info >/dev/null 2>&1; then
  DOCKER_OK=1
  if docker compose version >/dev/null 2>&1; then ok "Docker + compose ready"; else warn "Docker present but 'docker compose' plugin missing — services will be skipped."; DOCKER_OK=0; fi
elif have docker; then
  warn "Docker installed but the daemon is unreachable (start it / add yourself to the docker group)."
else
  warn "Docker not found — Qdrant will run EMBEDDED (fine for the sovereign core; strix needs Docker)."
fi

# TPM probe (for at-rest key sealing).
TPM_OK=0
if [ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ]; then
  if have tpm2_createprimary; then TPM_OK=1; ok "TPM present + tpm2-tools installed (keys will seal at rest)";
  else warn "TPM device present but tpm2-tools missing — keys stay PLAINTEXT at rest. Remedy: sudo apt install tpm2-tools && sudo usermod -aG tss \$USER"; fi
else
  warn "no TPM device — keys will be PLAINTEXT at rest (acceptable on a trusted single-user box)."
fi

# =============================================================================
step "2/6 build the two isolated environments + the Rust kernel"
# =============================================================================
# envs/build_envs.sh is the SOLE source of the two-venv + kernel + boundary check. Re-runnable.
PYTHON="$PY" bash envs/build_envs.sh
[ -x ".venv-sovereign/bin/python" ] || die "the sovereign venv did not build."
[ -x ".venv-offense/bin/python" ]   || die "the offense venv did not build."
# The console scripts must be installed (offense.txt/sovereign.txt install `-e ./integration` + the
# subsystems). Their absence means a PARTIAL build — catch it here, not at a confusing later step.
[ -x ".venv-offense/bin/vigil" ]    || die "the offense 'vigil' console script is missing — offense env build incomplete (re-run envs/build_envs.sh)."
[ -x ".venv-sovereign/bin/sigil" ]  || die "the sovereign 'sigil' console script is missing — sovereign env build incomplete (re-run envs/build_envs.sh)."
.venv-offense/bin/python -c "import framework.v2.authority.gate" 2>/dev/null || die "framework is not importable in the offense venv — engine/crucible did not install (re-run envs/build_envs.sh)."
ok "both venvs built (with console scripts + framework); the offense-free boundary held"

# =============================================================================
step "2b offense host tools (nmap/nuclei/httpx/ffuf/sqlmap/hydra + analysis/sensors)"
# =============================================================================
# Install every external CLI the offense engine spawns. Detects the OS, probes each (command -v),
# installs the missing ones with consent (apt / pipx), records a per-tool outcome the Tools screen
# reads, and prints an installed/missing/failed summary. FAIL-SOFT — a tool never aborts bootstrap.
if [ "$WITH_TOOLS" = 1 ]; then
  provision_host_tools || warn "tool provisioning hit an unexpected error — continuing (core install unaffected)."
else
  warn "--no-tools: skipping offense host-tool install/probe. Install later with: ./bootstrap.sh --with-tools"
fi

# =============================================================================
step "3/6 services (docker-compose; 127.0.0.1-bound only)"
# =============================================================================
if [ "$NO_SERVICES" = 1 ]; then
  warn "--no-services: skipping compose (Qdrant will run embedded)."
elif [ "$DOCKER_OK" = 1 ]; then
  [ -f .env ] || { cp .env.example .env; chmod 600 .env; ok "wrote .env from .env.example (0600)"; }
  # Qdrant is OPTIONAL (SIGIL has an embedded fallback), so a compose failure (port already bound, offline
  # image pull) must NOT abort the whole bootstrap — warn and continue to config/launchers/vault.
  if docker compose --env-file .env up -d qdrant; then
    printf "  waiting for Qdrant on 127.0.0.1:6333 "
    for _ in $(seq 1 30); do
      if curl -fsS http://127.0.0.1:6333/readyz >/dev/null 2>&1; then printf "\n"; ok "Qdrant is ready"; break; fi
      printf "."; sleep 1
    done
    curl -fsS http://127.0.0.1:6333/readyz >/dev/null 2>&1 || warn "Qdrant did not report ready in 30s — check 'docker compose logs qdrant'. Embedded mode still works."
  else
    warn "docker compose could not start Qdrant (port in use / image pull) — continuing; SIGIL will use its embedded vector store."
  fi
  if [ "$WITH_STRIX" = 1 ]; then
    step "3b build the Kali strix sandbox image (this is large)"
    docker compose --profile strix build strix-sandbox && ok "built vigil/strix-sandbox:local"
  fi
else
  warn "Docker unavailable — skipping services. Qdrant runs embedded; strix will not work until Docker is up."
fi

# =============================================================================
step "4/6 config + launchers"
# =============================================================================
SIGIL_HOME="${SIGIL_HOME:-$HOME/.sigil}"
mkdir -p "$SIGIL_HOME"
# sigil.env — SIGIL's own KEY=VALUE config (only written if absent; never clobbered).
if [ ! -f "$SIGIL_HOME/sigil.env" ]; then
  {
    echo "# SIGIL config — written by bootstrap.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "SIGIL_HOME=$SIGIL_HOME"
    [ "$DOCKER_OK" = 1 ] && [ "$NO_SERVICES" != 1 ] && echo "SIGIL_QDRANT_URL=http://127.0.0.1:6333"
  } > "$SIGIL_HOME/sigil.env"
  chmod 600 "$SIGIL_HOME/sigil.env"
  ok "wrote $SIGIL_HOME/sigil.env"
else
  ok "$SIGIL_HOME/sigil.env exists (left as-is)"
fi

# repo .env (compose + wrapper vars) — only if absent.
[ -f .env ] || { cp .env.example .env; chmod 600 .env; ok "wrote .env (0600)"; }

# the live offense working dir.
mkdir -p .vigil-live && ok ".vigil-live/ ready"

# systemd canonical layout: ~/.sigil/venv -> the sovereign venv (units reference ~/.sigil/venv/bin/*).
ln -sfn "$REPO/.venv-sovereign" "$SIGIL_HOME/venv" && ok "symlink $SIGIL_HOME/venv -> .venv-sovereign"

# ~/.local/bin launchers. CRITICAL trust-domain wiring (see docs/architecture/S8-control-plane.md):
#   • `vigil` MUST come from .venv-OFFENSE: its native verbs (engage/provision/verify/identity/detect) run
#     IN-PROCESS and import framework.*, which lives ONLY in the offense venv; passthrough verbs (sigil/…)
#     re-exec into their own venv regardless, so the offense `vigil` reaches BOTH domains correctly.
#   • `sigil` MUST come from .venv-SOVEREIGN (the owner-key core).
# A symlink into a venv keeps sys.prefix = that venv, so the dispatcher resolves the repo root itself.
mkdir -p "$HOME/.local/bin"
install_launcher() {  # name  target
  local name="$1" target="$2" dest="$HOME/.local/bin/$1"
  [ -e "$dest" ] && [ ! -L "$dest" ] && warn "replacing an existing non-symlink $dest"
  ln -sfn "$target" "$dest" && ok "launcher ~/.local/bin/$name -> ${target##*/.venv-}"
}
install_launcher vigil "$REPO/.venv-offense/bin/vigil"
install_launcher sigil "$REPO/.venv-sovereign/bin/sigil"
case ":$PATH:" in *":$HOME/.local/bin:"*) : ;; *) warn "add ~/.local/bin to your PATH to use 'vigil'/'sigil' directly.";; esac

if [ "$DO_SYSTEMD" = 1 ]; then
  step "4b install user systemd units"
  mkdir -p "$HOME/.config/systemd/user"
  cp apps/sigil/deploy/systemd/*.service apps/sigil/deploy/systemd/*.timer "$HOME/.config/systemd/user/" 2>/dev/null || true
  [ -f "$SIGIL_HOME/cockpit.env" ] || cp apps/sigil/deploy/cockpit.env.example "$SIGIL_HOME/cockpit.env"
  [ -f "$SIGIL_HOME/bridge.env" ]  || cp apps/sigil/deploy/bridge.env.example  "$SIGIL_HOME/bridge.env"
  systemctl --user daemon-reload 2>/dev/null && ok "installed user units (enable with: systemctl --user enable --now sigil-cockpit)" || warn "systemctl --user unavailable here."
fi

# =============================================================================
step "5/6 vault (at-rest key sealing)"
# =============================================================================
if [ "$TPM_OK" = 1 ]; then
  if SIGIL_HOME="$SIGIL_HOME" .venv-sovereign/bin/sigil vault provision; then ok "keys seal to this machine's TPM at rest"; else warn "vault provision failed — see the message above; keys stay plaintext."; fi
else
  warn "no usable TPM — keys are PLAINTEXT at rest. On a shared/cloud host, install tpm2-tools then run: sigil vault provision"
fi

# =============================================================================
step "6/6 smoke test"
# =============================================================================
SMOKE_FAIL=0
run_smoke() { printf "  %-42s" "$1"; shift; if "$@" >/dev/null 2>&1; then printf "${c_g}ok${c_0}\n"; else printf "${c_r}FAIL${c_0}\n"; SMOKE_FAIL=1; fi; }

# Dependency-free boundary re-check (no pytest needed), mirroring test_two_env_boundary: loading the
# sovereign surfaces (sigil + vigil_integration) must pull NO offense module, AND framework/strix must not
# even be resolvable from the sovereign venv's own path. The strong invariant envs/build_envs.sh also proves.
BOUNDARY_CHECK='import importlib.util as u, sys
import sigil, vigil_integration  # noqa: F401 — loading these must not pull framework/strix
from sigil.reuse import assert_no_offense
assert_no_offense()
for m in ("framework", "strix"):
    if u.find_spec(m) is not None:
        sys.exit("VIOLATION: " + m + " resolvable in the sovereign env")'
# HARD checks — a failure here means the core install is broken (bootstrap exits non-zero).
run_smoke "two-env boundary (offense-free sovereign)" .venv-sovereign/bin/python -c "$BOUNDARY_CHECK"
# Exercise a NATIVE offense verb THROUGH THE INSTALLED LAUNCHER: `provision` mints+signs a CRUCIBLE authority,
# which imports framework.* — so this fails loudly if ~/.local/bin/vigil is wired to the wrong (sovereign)
# venv (`verify`/`--help` would NOT — they need no framework). CRUCIBLE_ROOT + base-dir point at a throwaway
# dir (with a CLAUDE.md sentinel) so BOTH the governance key and the signed authority land there and are
# removed — the smoke leaves no residue.
SMOKE_TMP="$(mktemp -d)"; : > "$SMOKE_TMP/CLAUDE.md"
run_smoke "vigil native offense verb (via launcher)" \
  env CRUCIBLE_ROOT="$SMOKE_TMP" "$HOME/.local/bin/vigil" provision --slug bootstrap-smoke --scope 127.0.0.1 --base-dir "$SMOKE_TMP"
rm -rf "$SMOKE_TMP"
run_smoke "sigil sovereign core runs (via launcher)" env SIGIL_HOME="$SIGIL_HOME" "$HOME/.local/bin/sigil" --help

# INFORMATIONAL — the full self-check. Missing Claude CLI / Qdrant server / TPM / keyring are OPTIONAL on a
# fresh box, so `sigil doctor` may report `!!`/`**` rows and exit non-zero; that does NOT fail the bootstrap.
echo
echo "  self-check (informational — missing Claude/TPM/Qdrant-server/keyring are optional):"
env SIGIL_HOME="$SIGIL_HOME" .venv-sovereign/bin/sigil doctor 2>&1 | sed 's/^/    /' || true
if [ "$DOCKER_OK" = 1 ] && [ "$NO_SERVICES" != 1 ]; then
  if curl -fsS http://127.0.0.1:6333/readyz >/dev/null 2>&1; then echo "    [ok] Qdrant readyz"; else echo "    [warn] Qdrant not ready (embedded fallback still works)"; fi
fi

echo
if [ "$SMOKE_FAIL" = 0 ]; then
  printf "${c_g}${c_b}VIGIL is ready.${c_0}\n"
  echo "  • unified CLI:   vigil --help        (offense: engage/verify; sovereign: 'vigil sigil ...')"
  echo "  • sovereign:     sigil doctor        (self-check)"
  echo "  • cockpit UI:    sigil serve         (loopback; see apps/sigil/deploy/REMOTE-HOSTING.md for a domain)"
  echo "  • engage a target you OWN + authorized:  vigil engage <url> --scope <host>"
  echo "  • docs:          docs/DEPLOY.md"
  exit 0
else
  printf "${c_y}${c_b}Bootstrap finished with smoke-test failures above.${c_0} Review them before use.\n"
  exit 1
fi
