#!/usr/bin/env bash
# =============================================================================
# VIGIL uninstall — the inverse of bootstrap.sh (W16-STD-6(e)).
# =============================================================================
# Removes ONLY the machine-level WIRING that `bootstrap.sh` created outside the
# repository — the ~/.local/bin launchers, the ~/.sigil/venv symlink, and the
# user systemd units — and PRINTS exactly what it deliberately LEAVES behind
# (the repo, the venvs, your secrets, and your engagement data). It never
# deletes data, keys, or secrets unless you pass --purge-config, and even then
# it never touches .vigil-live engagement history or docker volumes.
#
# It is IDEMPOTENT (re-runnable) and CONSERVATIVE: a launcher or venv symlink is
# removed ONLY when it actually points back into THIS repo, so an unrelated
# ~/.local/bin/vigil from another checkout is never clobbered.
#
# Usage:   ./uninstall.sh [--yes] [--purge-config]
#   --yes | -y       non-interactive (assume "yes" to the confirmation prompt)
#   --purge-config   ALSO remove ~/.config/vigil/*.env and ~/.sigil/{cockpit,bridge}.env
#                    (these are copied from examples at install; they may carry a
#                    backup passphrase — off by default so an uninstall/reinstall
#                    keeps your configuration)
#   -h | --help      show this header
#
# Honors $HOME and $SIGIL_HOME (so it can be exercised against a scratch HOME).
# -----------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"
REPO="$(pwd)"
SIGIL_HOME="${SIGIL_HOME:-$HOME/.sigil}"
BIN="$HOME/.local/bin"
UNIT_DIR="$HOME/.config/systemd/user"
VIGIL_CFG="$HOME/.config/vigil"

ASSUME_YES=0
PURGE_CONFIG=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y) ASSUME_YES=1 ;;
    --purge-config) PURGE_CONFIG=1 ;;
    -h|--help) grep '^#' "$0" | grep -v '^#!' | sed 's/^#\s\{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $arg (try --help)"; exit 2 ;;
  esac
done

c_g=""; c_y=""; c_b=""; c_0=""
if [ -t 1 ]; then c_g=$'\033[32m'; c_y=$'\033[33m'; c_b=$'\033[1m'; c_0=$'\033[0m'; fi
ok()   { printf "  ${c_g}[removed]${c_0} %s\n" "$1"; }
skip() { printf "  [absent]  %s\n" "$1"; }
keep() { printf "  ${c_y}[left]${c_0}    %s\n" "$1"; }

if [ "$ASSUME_YES" != 1 ]; then
  printf "This removes the VIGIL launchers, the ~/.sigil/venv symlink and the user systemd units\n"
  printf "installed by bootstrap.sh. Your repo, venvs, secrets and .vigil-live data are KEPT.\n"
  printf "Proceed? [y/N] "
  read -r reply || reply=""
  case "$reply" in y|Y|yes|YES) : ;; *) echo "aborted."; exit 0 ;; esac
fi

# --- collect the unit names bootstrap installs, straight from the repo -------
UNITS=()
for d in apps/sigil/deploy/systemd infra/systemd; do
  [ -d "$d" ] || continue
  for f in "$d"/*.service "$d"/*.timer; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    # bootstrap copies sigil's *.service/*.timer and infra's vigil-* units only
    case "$d/$b" in
      infra/systemd/vigil-*) UNITS+=("$b") ;;
      apps/sigil/deploy/systemd/*) UNITS+=("$b") ;;
    esac
  done
done

echo
echo "${c_b}Removing machine wiring:${c_0}"

# --- systemd user units -----------------------------------------------------
HAVE_SYSTEMCTL=0
command -v systemctl >/dev/null 2>&1 && HAVE_SYSTEMCTL=1
for u in "${UNITS[@]:-}"; do
  [ -n "$u" ] || continue
  unit_path="$UNIT_DIR/$u"
  if [ -e "$unit_path" ]; then
    if [ "$HAVE_SYSTEMCTL" = 1 ]; then
      systemctl --user disable --now "$u" >/dev/null 2>&1 || true
    fi
    rm -f "$unit_path" && ok "systemd unit $u"
  fi
done
if [ "$HAVE_SYSTEMCTL" = 1 ]; then
  systemctl --user daemon-reload >/dev/null 2>&1 || true
fi

# --- ~/.local/bin launchers (only if they point into THIS repo) -------------
remove_launcher() {  # name
  local dest="$BIN/$1"
  if [ -L "$dest" ]; then
    local tgt; tgt="$(readlink "$dest" 2>/dev/null || true)"
    case "$tgt" in
      "$REPO"/*) rm -f "$dest" && ok "launcher $dest -> $tgt" ;;
      *) keep "launcher $dest (points outside this repo: $tgt) — not ours, left" ;;
    esac
  elif [ -e "$dest" ]; then
    keep "launcher $dest (not a symlink) — left untouched"
  else
    skip "launcher $dest"
  fi
}
remove_launcher vigil
remove_launcher sigil

# --- ~/.sigil/venv symlink (only if it points at this repo's sovereign venv) -
venv_link="$SIGIL_HOME/venv"
if [ -L "$venv_link" ]; then
  tgt="$(readlink "$venv_link" 2>/dev/null || true)"
  case "$tgt" in
    "$REPO"/.venv-sovereign|"$REPO"/.venv-sovereign/) rm -f "$venv_link" && ok "symlink $venv_link -> $tgt" ;;
    *) keep "symlink $venv_link (points elsewhere: $tgt) — left" ;;
  esac
else
  skip "symlink $venv_link"
fi

# --- optional: purge the copied config env files ----------------------------
if [ "$PURGE_CONFIG" = 1 ]; then
  for envf in "$VIGIL_CFG"/*.env; do
    [ -e "$envf" ] && rm -f "$envf" && ok "config $envf"
  done
  [ -d "$VIGIL_CFG" ] && rmdir "$VIGIL_CFG" 2>/dev/null && ok "dir $VIGIL_CFG" || true
  for e in cockpit.env bridge.env; do
    [ -e "$SIGIL_HOME/$e" ] && rm -f "$SIGIL_HOME/$e" && ok "config $SIGIL_HOME/$e"
  done
fi

# --- say plainly what we deliberately leave ---------------------------------
echo
echo "${c_b}Left in place (remove by hand if you really want them gone):${c_0}"
keep "the repository itself: $REPO"
keep "the two venvs + Rust kernel: $REPO/.venv-offense, $REPO/.venv-sovereign"
keep "engagement data + session store: $REPO/.vigil-live (findings, evidence, sessions)"
keep "repo config: $REPO/.env"
keep "secrets/config: $SIGIL_HOME/sigil.env (and .sigil itself)"
if [ "$PURGE_CONFIG" != 1 ]; then
  keep "cadence config: $VIGIL_CFG/*.env, $SIGIL_HOME/{cockpit,bridge}.env  (use --purge-config to remove)"
fi
keep "docker volumes / Qdrant data (run: docker compose down -v  to drop them)"

echo
printf "${c_g}${c_b}VIGIL wiring removed.${c_0} The repo and your data are untouched.\n"
