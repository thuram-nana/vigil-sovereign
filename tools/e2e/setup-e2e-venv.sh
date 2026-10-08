#!/usr/bin/env bash
#
# setup-e2e-venv.sh — provision the ISOLATED browser E2E venv (.venv-e2e).
#
# The PARENT/CI runs this, not the harness itself and not a live engagement.
# It is the ONLY step that touches the network (the `playwright install chromium`
# download). Everything else is offline.
#
# ISOLATION (FATAL-2): .venv-e2e is a THIRD venv, separate from the sovereign and
# offense venvs. It installs ONLY a browser/HTTP client (playwright + pytest) and
# MUST NEVER contain `framework`, `strix`, or any sovereign package. It talks to
# the stack only over the loopback network (http://127.0.0.1:8770), like a
# browser — it never imports VIGIL Python in-process.
#
# AIR-GAP: to vendor Chromium for an offline host, set PLAYWRIGHT_BROWSERS_PATH to
# a directory you will copy to that host, run the install step there once on a
# connected machine, copy the directory over, then export the SAME
# PLAYWRIGHT_BROWSERS_PATH on the air-gapped host before running pytest. A given
# pinned playwright release pins a specific Chromium revision, so the vendored
# build is reproducible.
#
set -euo pipefail

# Resolve the repo root (…/tools/e2e/ -> repo root) so the script works from anywhere.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

VENV_DIR="${VIGIL_E2E_VENV:-${REPO_ROOT}/.venv-e2e}"
REQ_FILE="${REPO_ROOT}/tests/e2e/requirements-e2e.txt"
PY="${PYTHON:-python3}"

echo "[e2e] repo root      : ${REPO_ROOT}"
echo "[e2e] venv           : ${VENV_DIR}  (isolated; NOT a FATAL-2 venv)"
echo "[e2e] requirements   : ${REQ_FILE}"

if [ ! -f "${REQ_FILE}" ]; then
  echo "[e2e] FATAL: ${REQ_FILE} not found" >&2
  exit 1
fi

# 1. Create the isolated venv (offline).
"${PY}" -m venv "${VENV_DIR}"
VENV_PY="${VENV_DIR}/bin/python"

# 2. Install the PINNED browser/HTTP client stack (offline except for the index
#    fetch; use a local wheelhouse via PIP_FIND_LINKS / --no-index for full air-gap).
"${VENV_PY}" -m pip install --upgrade pip
"${VENV_PY}" -m pip install -r "${REQ_FILE}"

# 3. THE ONE NETWORK / VENDOR STEP: download the pinned Chromium build.
#    For air-gap, export PLAYWRIGHT_BROWSERS_PATH to a vendored directory FIRST
#    (see the header) so this resolves/populates that directory instead of the
#    default per-user cache.
if [ "${VIGIL_E2E_SKIP_BROWSER_INSTALL:-0}" = "1" ]; then
  echo "[e2e] VIGIL_E2E_SKIP_BROWSER_INSTALL=1 — skipping 'playwright install chromium'"
  echo "[e2e] (ensure PLAYWRIGHT_BROWSERS_PATH points at a vendored Chromium build)"
else
  echo "[e2e] installing pinned Chromium (THE one network step) ..."
  "${VENV_PY}" -m playwright install chromium
fi

echo "[e2e] done. Run:   ${VENV_PY} -m pytest tests/e2e -v"
echo "[e2e] authed runs: VIGIL_E2E_TOKEN=<bearer> ${VENV_PY} -m pytest tests/e2e -v"
