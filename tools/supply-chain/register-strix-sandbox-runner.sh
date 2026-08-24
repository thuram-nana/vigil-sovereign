#!/usr/bin/env bash
# =============================================================================================
# register-strix-sandbox-runner.sh — provision the self-hosted runner that arms issue #653
# (W3-7 residual: live `trivy image` build+scan of the ~7GB Kali Strix sandbox image).
#
# WHAT THIS AUTOMATES
#   `.github/workflows/strix-sandbox-image-scan.yml` is a committed, DORMANT-by-design scaffold.
#   It only ever runs when BOTH of these are true:
#     (a) a GitHub Actions SELF-HOSTED runner carrying the labels
#         [self-hosted, linux, x64, large] is registered on the repo, AND
#     (b) the opt-in repository variable STRIX_SANDBOX_SCAN is set to the exact value the
#         workflow's `if:` compares against ('enabled').
#   This script is the "human/infra action" that residual calls for. It:
#     * preflights the host (gh admin auth, docker/curl/tar, disk, RAM),
#     * registers the self-hosted runner with the workflow's EXACT labels (register-runner),
#     * flips the opt-in repository variable that un-gates the scheduled run (enable-scan),
#     * reproduces the workflow's build+scan locally so you can validate first (local-scan),
#     * cleanly tears the runner back down (deregister).
#
# SECURITY — READ THIS BEFORE RUNNING.
#   Registering a self-hosted runner GRANTS THE REPOSITORY'S WORKFLOWS CODE EXECUTION ON THIS
#   HOST. Anyone who can push a workflow (or a change to this one) can run code as this runner's
#   user. Only ever register a runner on a machine you own, control, and are comfortable
#   dedicating to this — never a shared or production box, and never for a repo you do not
#   trust. The Strix sandbox image scan itself stays ADVISORY: the workflow REPORTS findings, it
#   never blocks a build (a Kali distro carries findings the author cannot fix). This script
#   never disables that advisory posture.
#
# NO SECRETS ARE BAKED IN. Every runner registration/removal token is minted at runtime from the
# GitHub API (you must be a repo admin); nothing is hardcoded. The repo slug, runner directory,
# labels, and variable name are all variables at the top of this file.
#
# DEPENDENCIES: bash, gh (authenticated, repo admin), docker (with the compose plugin), curl,
# tar. `trivy` is only needed for the `local-scan` subcommand.
#
# USAGE: see `--help`.
# =============================================================================================
set -euo pipefail

# ---------------------------------------------------------------------------------------------
# Configuration — every external value lives here. Override via the environment where noted.
# ---------------------------------------------------------------------------------------------

# Repo slug. Defaults to the canonical repo; override with VIGIL_REPO for a fork/mirror.
VIGIL_REPO="${VIGIL_REPO:-thuram-nana/vigil-sovereign}"

# Where the actions/runner install lives. Override with RUNNER_DIR or `--runner-dir <path>`.
RUNNER_DIR="${RUNNER_DIR:-$HOME/actions-runner-vigil}"

# Runner name shown in the repo's runner list.
RUNNER_NAME="${RUNNER_NAME:-$(hostname)-strix}"

# The runner labels the workflow's `runs-on` REQUIRES. These MUST equal
# `.github/workflows/strix-sandbox-image-scan.yml` -> runs-on: [self-hosted, linux, x64, large].
# GitHub only dispatches the job to a runner that carries ALL of these. A cross-check guard
# (docs/tests/test_strix_sandbox_runner_script.py) fails if this drifts from the workflow.
RUNNER_LABELS="self-hosted,linux,x64,large"

# The opt-in repository variable the workflow gates on, and the EXACT value its `if:` compares
# against: `.github/workflows/strix-sandbox-image-scan.yml` ->
#   if: ${{ vars.STRIX_SANDBOX_SCAN == 'enabled' }}
# NOTE: the workflow compares against the literal string 'enabled'. Any other value (1, true, …)
# leaves the scheduled run cleanly SKIPPED — so this is the only value that actually arms it.
SCAN_VAR_NAME="STRIX_SANDBOX_SCAN"
SCAN_VAR_ARMED_VALUE="enabled"

# The image the workflow builds+scans, and the build command the compose file declares
# (docker-compose.yml service `strix-sandbox`, profile `strix`).
STRIX_IMAGE="vigil/strix-sandbox:local"

# The trivy blocking threshold is IDENTICAL to the gateway image gate and to the workflow's gate
# step: `--severity HIGH,CRITICAL --ignore-unfixed`. These flags are written as LITERALS in the
# `local-scan` trivy invocation below (not indirected through a variable) precisely so the guard
# test docs/tests/test_strix_sandbox_runner_script.py can cross-check them, byte for byte, against
# `.github/workflows/strix-sandbox-image-scan.yml` — the two cannot drift.

# Rough host sizing floors (the image is ~7GB, plus build layers and the temp SBOM/scan work).
MIN_FREE_GB=40
MIN_RAM_GB=8

# The GitHub API host used for the runner-release tarball and API calls (leave as-is for
# github.com; only relevant if you ever point this at GHES).
GH_HOST="${GH_HOST:-github.com}"

# Resolve the repo root so `local-scan` runs `docker compose` from the right directory,
# regardless of where the operator invokes this script from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------------------------
# Small logging / failure helpers. Fail CLOSED: any unmet precondition exits non-zero.
# ---------------------------------------------------------------------------------------------
log()  { printf '[strix-runner] %s\n' "$*"; }
warn() { printf '[strix-runner] WARNING: %s\n' "$*" >&2; }
die()  { printf '[strix-runner] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
# usage / --help
# ---------------------------------------------------------------------------------------------
usage() {
  cat <<EOF
register-strix-sandbox-runner.sh — provision/arm the self-hosted runner for issue #653.

Registering a self-hosted runner grants this repo's workflows CODE EXECUTION on this host.
Only run this on a machine you own and are comfortable dedicating. The image scan stays ADVISORY.

USAGE:
  $(basename "$0") [--runner-dir <path>] <subcommand>

SUBCOMMANDS:
  preflight        Check gh admin auth, docker/curl/tar, disk and RAM. Run by the others.
  register-runner  Register a self-hosted Actions runner with labels [${RUNNER_LABELS}]
                   for ${VIGIL_REPO}. Idempotent (--replace); installs+starts the svc.
  enable-scan      Set the opt-in repo variable ${SCAN_VAR_NAME}='${SCAN_VAR_ARMED_VALUE}'
                   (the value the workflow's if: compares against). This un-gates the run.
  local-scan       Reproduce the workflow locally: build ${STRIX_IMAGE} and trivy-scan it at
                   --severity HIGH,CRITICAL --ignore-unfixed (ADVISORY: never aborts).
  deregister       Stop+uninstall the runner service and remove the runner from the repo.
  -h | --help      This message.

ENVIRONMENT OVERRIDES:
  VIGIL_REPO   (default ${VIGIL_REPO})
  RUNNER_DIR   (default ${RUNNER_DIR})
  RUNNER_NAME  (default $(hostname)-strix)

TYPICAL FLOW:
  $(basename "$0") preflight
  $(basename "$0") local-scan        # optional: validate build+scan before arming CI
  $(basename "$0") register-runner
  $(basename "$0") enable-scan        # now the weekly scheduled scan will actually run
  # …later…
  $(basename "$0") deregister
EOF
}

# ---------------------------------------------------------------------------------------------
# Preflight — all checks that must hold before we touch GitHub or docker. Fails closed.
# ---------------------------------------------------------------------------------------------
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found on PATH: $1"
}

check_gh_auth() {
  require_cmd gh
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated — run 'gh auth login' first."
}

check_gh_admin() {
  # The registration/removal-token endpoints require repo admin. Verify it up front so we fail
  # with a clear message instead of a raw 403 later.
  local is_admin
  is_admin="$(gh api "repos/${VIGIL_REPO}" --jq '.permissions.admin' 2>/dev/null || echo "false")"
  [ "${is_admin}" = "true" ] \
    || die "the authenticated gh account lacks admin on ${VIGIL_REPO} (permissions.admin=${is_admin}). Runner registration needs admin."
}

check_disk() {
  # The Strix image is ~7GB plus build layers. Warn (do not hard-fail) if the docker data root
  # has under ~${MIN_FREE_GB}GB free — the build will otherwise die halfway with ENOSPC.
  local docker_root avail_gb
  docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"
  [ -d "${docker_root}" ] || docker_root="/"
  avail_gb="$(df -BG --output=avail "${docker_root}" 2>/dev/null | tail -n1 | tr -dc '0-9')"
  if [ -n "${avail_gb}" ] && [ "${avail_gb}" -lt "${MIN_FREE_GB}" ]; then
    warn "only ${avail_gb}GB free on docker root ${docker_root} (< ${MIN_FREE_GB}GB). The ~7GB image + build layers may not fit."
  else
    log "disk OK: ${avail_gb:-?}GB free on ${docker_root} (want >= ${MIN_FREE_GB}GB)."
  fi
}

check_ram() {
  local ram_gb
  ram_gb="$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  if [ -n "${ram_gb}" ] && [ "${ram_gb}" -lt "${MIN_RAM_GB}" ]; then
    warn "only ${ram_gb}GB RAM (< ${MIN_RAM_GB}GB). Building a large Kali image may be slow or OOM."
  else
    log "RAM OK: ${ram_gb:-?}GB (want >= ${MIN_RAM_GB}GB)."
  fi
}

preflight() {
  log "preflight against ${VIGIL_REPO}…"
  check_gh_auth
  check_gh_admin
  require_cmd docker
  require_cmd curl
  require_cmd tar
  docker info >/dev/null 2>&1 || die "docker is installed but not usable (is the daemon running / do you have permission?)."
  check_disk
  check_ram
  log "preflight OK."
}

# ---------------------------------------------------------------------------------------------
# register-runner — download actions/runner, configure it with the workflow's labels, run as svc.
# Idempotent: an already-configured dir is reconfigured with --replace.
# ---------------------------------------------------------------------------------------------
download_runner() {
  # Resolve the latest actions/runner release and download the linux-x64 tarball, verifying the
  # release-published SHA-256 when one is available. Skipped entirely if the runner is already
  # extracted (idempotent re-runs do not re-download).
  if [ -x "${RUNNER_DIR}/config.sh" ]; then
    log "runner already extracted in ${RUNNER_DIR} — skipping download."
    return 0
  fi
  mkdir -p "${RUNNER_DIR}"

  local ver tarball url body sha
  ver="$(gh api repos/actions/runner/releases/latest --jq '.tag_name' | sed 's/^v//')"
  [ -n "${ver}" ] || die "could not resolve the latest actions/runner release version."
  tarball="actions-runner-linux-x64-${ver}.tar.gz"
  url="https://${GH_HOST}/actions/runner/releases/download/v${ver}/${tarball}"

  log "downloading actions/runner v${ver} for linux-x64…"
  curl -fsSL --retry 3 -o "${RUNNER_DIR}/${tarball}" "${url}" \
    || die "failed to download the runner tarball from ${url}"

  # The runner release body embeds the per-arch SHA-256 between HTML markers; verify if present.
  body="$(gh api repos/actions/runner/releases/latest --jq '.body' 2>/dev/null || echo "")"
  sha="$(printf '%s' "${body}" | sed -n 's/.*<!-- BEGIN SHA linux-x64 -->\([0-9a-f]\{64\}\).*/\1/p' | head -n1)"
  if [ -n "${sha}" ]; then
    log "verifying runner tarball SHA-256…"
    echo "${sha}  ${RUNNER_DIR}/${tarball}" | sha256sum -c - \
      || die "runner tarball SHA-256 mismatch — refusing to install a tampered runner."
  else
    warn "the release did not publish a linux-x64 SHA-256; installing the downloaded tarball unverified."
  fi

  tar -xzf "${RUNNER_DIR}/${tarball}" -C "${RUNNER_DIR}" \
    || die "failed to extract the runner tarball."
  [ -x "${RUNNER_DIR}/config.sh" ] || die "runner did not extract cleanly (no config.sh in ${RUNNER_DIR})."
}

cmd_register_runner() {
  preflight
  download_runner

  # Mint a short-lived registration token at runtime (admin-gated). NEVER hardcode a token.
  local reg_token
  reg_token="$(gh api -X POST "repos/${VIGIL_REPO}/actions/runners/registration-token" --jq '.token')"
  [ -n "${reg_token}" ] || die "failed to obtain a runner registration token (need repo admin)."

  log "configuring runner '${RUNNER_NAME}' with labels [${RUNNER_LABELS}]…"
  # --replace makes re-registration idempotent (reuses/overwrites the same runner name).
  ( cd "${RUNNER_DIR}" && ./config.sh \
      --url "https://${GH_HOST}/${VIGIL_REPO}" \
      --token "${reg_token}" \
      --labels "${RUNNER_LABELS}" \
      --name "${RUNNER_NAME}" \
      --unattended \
      --replace ) \
    || die "runner configuration failed."

  # Install + start as a service so the runner survives reboots. svc.sh needs root.
  if command -v systemctl >/dev/null 2>&1; then
    log "installing + starting the runner service (needs sudo)…"
    ( cd "${RUNNER_DIR}" && sudo ./svc.sh install && sudo ./svc.sh start ) \
      || die "runner service install/start failed — you can run it in the foreground instead: (cd ${RUNNER_DIR} && ./run.sh)"
    log "runner service is up. It carries labels [${RUNNER_LABELS}] on ${VIGIL_REPO}."
  else
    warn "systemd not detected — the runner is configured but not installed as a service."
    warn "start it in the foreground with:  (cd ${RUNNER_DIR} && ./run.sh)"
  fi

  log "next: run '$(basename "$0") enable-scan' to set ${SCAN_VAR_NAME}='${SCAN_VAR_ARMED_VALUE}' and arm the scheduled scan."
}

# ---------------------------------------------------------------------------------------------
# enable-scan — set the opt-in repository variable that un-gates the scheduled workflow run.
# ---------------------------------------------------------------------------------------------
cmd_enable_scan() {
  check_gh_auth
  check_gh_admin
  log "setting repository variable ${SCAN_VAR_NAME}='${SCAN_VAR_ARMED_VALUE}' on ${VIGIL_REPO}…"
  # `gh variable set` creates or updates the repo variable. The workflow's `if:` compares this
  # against the literal '${SCAN_VAR_ARMED_VALUE}', so this is exactly what un-gates the run.
  gh variable set "${SCAN_VAR_NAME}" --repo "${VIGIL_REPO}" --body "${SCAN_VAR_ARMED_VALUE}" \
    || die "failed to set ${SCAN_VAR_NAME} (need repo admin)."
  log "done. The weekly scheduled scan (and workflow_dispatch) will now run on the self-hosted runner."
  log "to disarm later:  gh variable set ${SCAN_VAR_NAME} --repo ${VIGIL_REPO} --body disabled   (or delete it)."
}

# ---------------------------------------------------------------------------------------------
# local-scan — reproduce the workflow's build+scan locally. ADVISORY: never aborts this script.
# ---------------------------------------------------------------------------------------------
cmd_local_scan() {
  require_cmd docker
  if ! command -v trivy >/dev/null 2>&1; then
    echo "[strix-runner] trivy is not installed. Install it, e.g.:  curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin" >&2
    exit 1
  fi

  # Build EXACTLY as the compose file / workflow declares: profile 'strix', service 'strix-sandbox'.
  log "building ${STRIX_IMAGE} (docker compose --profile strix build strix-sandbox)…"
  ( cd "${REPO_ROOT}" && docker compose --profile strix build strix-sandbox ) \
    || die "the strix sandbox image build failed."
  docker image inspect "${STRIX_IMAGE}" --format 'built {{.RepoTags}} id={{.Id}}' \
    || die "expected image ${STRIX_IMAGE} was not produced by the build."

  # Scan at the workflow's gate threshold. ADVISORY: capture the result but NEVER let a non-zero
  # trivy exit code abort this script (a Kali distro carries findings the author cannot fix).
  local ignore_args=()
  [ -f "${REPO_ROOT}/.trivyignore" ] && ignore_args=(--ignorefile "${REPO_ROOT}/.trivyignore")

  # The flags below are LITERAL and identical to the workflow's gate step (and to the gateway
  # image gate): --severity HIGH,CRITICAL --ignore-unfixed. Do not indirect them through a
  # variable — the guard test pins these exact literals against the workflow.
  log "trivy image scan (ADVISORY) at --severity HIGH,CRITICAL --ignore-unfixed…"
  local rc
  set +e
  trivy image --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    "${ignore_args[@]}" \
    --exit-code 1 \
    --no-progress \
    "${STRIX_IMAGE}"
  rc=$?
  set -e

  if [ "${rc}" -eq 0 ]; then
    log "advisory scan: no fixable HIGH,CRITICAL findings at the gate threshold (trivy exit 0)."
  else
    log "advisory scan: trivy reported fixable HIGH,CRITICAL findings (exit ${rc}). ADVISORY — not blocking."
  fi
  log "local-scan complete."
}

# ---------------------------------------------------------------------------------------------
# deregister — stop+uninstall the service and remove the runner from the repo.
# ---------------------------------------------------------------------------------------------
cmd_deregister() {
  check_gh_auth
  check_gh_admin
  [ -x "${RUNNER_DIR}/config.sh" ] || die "no configured runner found in ${RUNNER_DIR} (nothing to deregister)."

  if command -v systemctl >/dev/null 2>&1 && [ -x "${RUNNER_DIR}/svc.sh" ]; then
    log "stopping + uninstalling the runner service (needs sudo)…"
    ( cd "${RUNNER_DIR}" && sudo ./svc.sh stop || true; sudo ./svc.sh uninstall || true )
  fi

  # Mint a short-lived removal token at runtime (admin-gated). NEVER hardcode a token.
  local removal_token
  removal_token="$(gh api -X POST "repos/${VIGIL_REPO}/actions/runners/remove-token" --jq '.token')"
  [ -n "${removal_token}" ] || die "failed to obtain a runner removal token (need repo admin)."

  log "removing the runner registration from ${VIGIL_REPO}…"
  ( cd "${RUNNER_DIR}" && ./config.sh remove --token "${removal_token}" ) \
    || die "runner removal failed."
  log "runner deregistered. (The ${SCAN_VAR_NAME} variable is left as-is; unset it separately if desired.)"
}

# ---------------------------------------------------------------------------------------------
# Dispatch. A global --runner-dir may precede the subcommand.
# ---------------------------------------------------------------------------------------------
main() {
  # Parse an optional global --runner-dir before the subcommand.
  while [ $# -gt 0 ]; do
    case "$1" in
      --runner-dir) RUNNER_DIR="${2:?--runner-dir needs a path}"; shift 2 ;;
      --runner-dir=*) RUNNER_DIR="${1#*=}"; shift ;;
      *) break ;;
    esac
  done

  local subcmd="${1:-}"
  [ $# -gt 0 ] && shift || true

  case "${subcmd}" in
    preflight)       preflight ;;
    register-runner) cmd_register_runner "$@" ;;
    enable-scan)     cmd_enable_scan "$@" ;;
    local-scan)      cmd_local_scan "$@" ;;
    deregister)      cmd_deregister "$@" ;;
    -h|--help|help|"") usage ;;
    *) die "unknown subcommand: ${subcmd} (see --help)" ;;
  esac
}

main "$@"
