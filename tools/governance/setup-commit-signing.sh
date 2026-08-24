#!/usr/bin/env bash
# setup-commit-signing.sh — configure this repository clone to SIGN commits ([W12-4] #493).
#
# This is the developer-side companion to the "Require signed commits" branch-protection rule. It
# configures git so every commit you make in this clone is signed, and prints how to register your
# public key with GitHub so those signatures show as "Verified".
#
# It configures LOCAL (per-repo) git config by default, so it never silently changes your global git.
# The server-side "Require signed commits" rule on `main` is a separate branch-protection admin flip
# (see docs/decisions/W12-4-enforce-signed-commits.md) — this script does not and cannot set that.
#
# Usage:
#   tools/governance/setup-commit-signing.sh ssh [~/.ssh/id_ed25519.pub]   # SSH signing (simplest)
#   tools/governance/setup-commit-signing.sh gpg <KEYID>                   # GPG/OpenPGP signing
#   tools/governance/setup-commit-signing.sh                              # print guidance only
set -euo pipefail

mode="${1:-}"

configure_ssh() {
  local key="${1:-}"
  if [ -z "${key}" ]; then
    # Pick a sensible default public key if the caller did not name one.
    for cand in "${HOME}/.ssh/id_ed25519.pub" "${HOME}/.ssh/id_rsa.pub"; do
      [ -f "${cand}" ] && key="${cand}" && break
    done
  fi
  if [ -z "${key}" ] || [ ! -f "${key}" ]; then
    echo "error: no SSH public key found. Generate one with:  ssh-keygen -t ed25519" >&2
    echo "then re-run:  $0 ssh ~/.ssh/id_ed25519.pub" >&2
    exit 2
  fi
  git config gpg.format ssh
  git config user.signingkey "${key}"
  git config commit.gpgsign true
  git config tag.gpgsign true
  echo "configured SSH commit signing with public key: ${key}"
  echo "Register it on GitHub as a SIGNING key (Settings -> SSH and GPG keys -> New SSH key -> type 'Signing Key')"
  echo "so your signatures show as Verified."
}

configure_gpg() {
  local keyid="${1:-}"
  if [ -z "${keyid}" ]; then
    echo "error: pass your GPG key id:  $0 gpg <KEYID>   (list with: gpg --list-secret-keys --keyid-format=long)" >&2
    exit 2
  fi
  git config gpg.format openpgp
  git config user.signingkey "${keyid}"
  git config commit.gpgsign true
  git config tag.gpgsign true
  echo "configured GPG commit signing with key id: ${keyid}"
  echo "Export the PUBLIC key (gpg --armor --export ${keyid}) and add it on GitHub (Settings -> SSH and GPG keys)."
}

case "${mode}" in
  ssh) configure_ssh "${2:-}";;
  gpg) configure_gpg "${2:-}";;
  "" )
    cat <<'EOF'
Configure signed commits for this clone:

  SSH signing (simplest, no GPG needed):
    tools/governance/setup-commit-signing.sh ssh [~/.ssh/id_ed25519.pub]

  GPG / OpenPGP signing:
    tools/governance/setup-commit-signing.sh gpg <KEYID>

Then verify with:
    tools/governance/verify-commit-signing.sh

The server-side "Require signed commits" rule on main is a branch-protection ADMIN action, not this
script — see docs/decisions/W12-4-enforce-signed-commits.md.
EOF
    ;;
  *)
    echo "unknown mode '${mode}'. Use: ssh | gpg | (empty for guidance)" >&2
    exit 2
    ;;
esac

echo
echo "Now verifying the resulting configuration:"
exec "$(dirname "$0")/verify-commit-signing.sh"
