#!/usr/bin/env bash
# =============================================================================
# Install the optional host tools that have no distribution package we can use
# =============================================================================
#
# WHAT AND WHY. The tool registry lists thirteen host tools. Most arrive through the system package
# manager. Three do not, for different reasons, and this script handles the two that can be installed
# without administrator rights:
#
#   semgrep   — a Python program. Install it with `pipx install semgrep`; nothing here is needed.
#   joern     — ships only as a release archive. Installed here, into the user's own directory.
#   zaproxy   — packaged for Kali as `zaproxy`, which needs administrator rights. When you do not
#               have them, the project's own portable archive gives the same program in userland.
#               The registry already accepts the archive's launcher name, so no configuration is
#               needed once it is on the path.
#
# NO ADMINISTRATOR RIGHTS ARE USED OR REQUIRED. Everything lands under the user's home directory and
# is linked into ~/.local/bin, which the tool probe and the running service both already search. The
# probe resolves the path at the moment it is asked, so a tool installed while the interface is open
# appears the next time the screen is refreshed. Nothing needs restarting.
#
# INTEGRITY. Downloads are verified against the publisher's own checksum where one is published, and
# the script REFUSES to install anything that fails. These are security tools being placed on a
# security practitioner's machine; an unverified binary here is worse than a missing one. Where a
# publisher does not ship a checksum the script says so out loud rather than pretending.
#
# SAFE TO RE-RUN. Each tool is skipped if it is already present and working. Nothing is removed and
# nothing already installed is overwritten.
#
# USAGE:
#   tools/provision/install-optional-tools.sh              # install whatever is missing
#   tools/provision/install-optional-tools.sh --check      # report only, change nothing
#   FORCE=1 tools/provision/install-optional-tools.sh      # reinstall even if present
# =============================================================================
set -euo pipefail

SHARE="${SHARE:-$HOME/.local/share}"
BIN="${BIN:-$HOME/.local/bin}"
# Downloads land on DISK, not in /tmp. On this class of machine /tmp is a tmpfs — a 1.7 GB archive
# would be pulled into RAM, and everything there is lost on reboot. They are also kept between runs
# so an interrupted download RESUMES instead of starting again: these archives are large enough that
# a failure two thirds of the way through is otherwise an hour thrown away.
CACHE="${CACHE:-$SHARE/vigil-tool-downloads}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '   \033[33m%s\033[0m\n' "$*"; }
die()  { printf '   \033[31m%s\033[0m\n' "$*"; exit 1; }

mkdir -p "$SHARE" "$BIN"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) warn "$BIN is not on your PATH — installed tools will not be found until it is." ;;
esac

# `command -v` alone is not enough: a tool can be on the path and still be unusable (a broken
# package-manager venv left a `semgrep` link pointing at a binary that did not exist). Actually run it.
have() { command -v "$1" >/dev/null 2>&1 && "$1" ${2:---version} >/dev/null 2>&1; }

# Some tools answer to more than one name, and the packaged name is often NOT the one upstream uses.
# The registry already knows this — its zaproxy entry lists `zaproxy` with `zap.sh` and `zap-cli` as
# alternates — so this script must ask the same question. Probing only one name reported a tool as
# missing that the distribution package had just installed under another, and would have downloaded
# a quarter-gigabyte archive on top of a working install.
have_any() {
  local probe="$1"; shift
  local n
  for n in "$@"; do
    if have "$n" "$probe"; then return 0; fi
  done
  return 1
}

report() {
  local name="$1" probe="$2"
  if have "$name" "$probe"; then
    info "$(printf '%-10s installed  %s' "$name" "$(command -v "$name")")"
    return 0
  fi
  info "$(printf '%-10s MISSING' "$name")"
  return 1
}

report_any() {
  local probe="$1"; shift
  local n
  for n in "$@"; do
    if have "$n" "$probe"; then
      info "$(printf '%-10s installed  %s' "$1" "$(command -v "$n")")"; return 0
    fi
  done
  info "$(printf '%-10s MISSING' "$1")"; return 1
}

# -----------------------------------------------------------------------------
say "Current state"
report semgrep --version  || true
report joern    --version || true
report_any -version zaproxy zap.sh zap-cli || true

if [ "$CHECK_ONLY" = "1" ]; then
  say "--check given; nothing installed."
  exit 0
fi

# -----------------------------------------------------------------------------
# joern — a code-analysis engine. Ships as a release archive; needs a Java runtime.
# -----------------------------------------------------------------------------
if have joern --version && [ "${FORCE:-0}" != "1" ]; then
  say "joern — already installed, skipping"
else
  say "joern — installing (a large download; it carries a whole analysis toolchain)"
  command -v java >/dev/null 2>&1 || die "joern needs a Java runtime and none was found on the path."

  JOERN_TAG="$(curl -fsSL https://api.github.com/repos/joernio/joern/releases/latest \
                | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
  info "release $JOERN_TAG"
  base="https://github.com/joernio/joern/releases/download/$JOERN_TAG"
  zip="joern-cli-linux-x86_64.zip"
  tmp="$CACHE/joern-$JOERN_TAG"
  mkdir -p "$tmp"

  # `-C -` resumes a partial file; `--retry` rides out a dropped connection rather than discarding
  # the gigabyte already fetched. The partial stays in the cache on failure, deliberately, so the
  # next run continues from where this one stopped.
  info "downloading $zip (resumable; kept in $CACHE)"
  curl -fSL --progress-bar -C - --retry 5 --retry-delay 5 --retry-all-errors \
       -o "$tmp/$zip" "$base/$zip"
  curl -fsSL -o "$tmp/$zip.sha512" "$base/$zip.sha512"

  info "verifying the publisher's checksum"
  # Pull the digest out by SHAPE — a 128-character hex run — rather than by parsing a format.
  # Publishers ship at least two: coreutils' "<hex>  <filename>" and openssl's "SHA512(f)= <hex>".
  # The previous version cut on "=", which is right for openssl and silently wrong for coreutils:
  # `cut` returns the WHOLE line when its delimiter is absent, so after whitespace-stripping, `want`
  # became the digest with the filename glued to the end. It then never equalled `got`, and a
  # correctly-downloaded 1.7 GB archive was refused with a "CHECKSUM MISMATCH" whose two values were
  # visibly identical for their first sixteen characters. Failing closed was right; the reason was
  # not. Matching the digest itself works for both formats and cannot pick up a filename.
  want="$(grep -oiE '[0-9a-f]{128}' "$tmp/$zip.sha512" | head -1 | tr 'A-Z' 'a-z')"
  got="$(sha512sum "$tmp/$zip" | cut -d' ' -f1)"
  [ -n "$want" ] || die "no checksum was published for $zip — refusing to install unverified."
  [ "$want" = "$got" ] || die "CHECKSUM MISMATCH for $zip. Refusing to install. (want ${want:0:16}…, got ${got:0:16}…)"
  info "checksum OK"

  rm -rf "$SHARE/joern"
  mkdir -p "$SHARE/joern"
  unzip -q "$tmp/$zip" -d "$SHARE/joern"
  target="$(find "$SHARE/joern" -maxdepth 3 -name joern -type f -perm -u+x | head -1)"
  [ -n "$target" ] || die "unpacked joern but found no launcher inside $SHARE/joern"
  ln -sf "$target" "$BIN/joern"
  info "linked $BIN/joern -> $target"
fi

# -----------------------------------------------------------------------------
# zaproxy — the OWASP web application scanner. Packaged for Kali, but that route needs
# administrator rights; the project's portable archive does not.
# -----------------------------------------------------------------------------
if have_any -version zaproxy zap.sh zap-cli && [ "${FORCE:-0}" != "1" ]; then
  say "zaproxy — already installed, skipping"
else
  say "zaproxy — installing the portable archive (no administrator rights needed)"
  read -r ZAP_TAG ZAP_URL <<<"$(curl -fsSL https://api.github.com/repos/zaproxy/zaproxy/releases/latest \
    | python3 -c '
import json,sys
d=json.load(sys.stdin)
a=[x for x in d["assets"] if x["name"].startswith("ZAP_") and x["name"].endswith("_Linux.tar.gz")]
print(d["tag_name"], a[0]["browser_download_url"] if a else "")')"
  [ -n "$ZAP_URL" ] || die "could not find a Linux archive in the latest zaproxy release."
  info "release $ZAP_TAG"

  tmp2="$CACHE/zap-$ZAP_TAG"
  mkdir -p "$tmp2"
  info "downloading $(basename "$ZAP_URL") (resumable; kept in $CACHE)"
  curl -fSL --progress-bar -C - --retry 5 --retry-delay 5 --retry-all-errors \
       -o "$tmp2/zap.tar.gz" "$ZAP_URL"

  # This project publishes no per-asset checksum file. Say so rather than implying verification that
  # did not happen — the download is over TLS from the project's own release host, and that is the
  # whole of the assurance.
  warn "no checksum is published for this archive; integrity rests on the TLS connection alone."

  rm -rf "$SHARE/zaproxy"
  mkdir -p "$SHARE/zaproxy"
  tar -xzf "$tmp2/zap.tar.gz" -C "$SHARE/zaproxy" --strip-components=1
  [ -f "$SHARE/zaproxy/zap.sh" ] || die "unpacked zaproxy but found no zap.sh inside $SHARE/zaproxy"
  chmod +x "$SHARE/zaproxy/zap.sh"
  ln -sf "$SHARE/zaproxy/zap.sh" "$BIN/zap.sh"
  info "linked $BIN/zap.sh -> $SHARE/zaproxy/zap.sh"
fi

# -----------------------------------------------------------------------------
say "Final state"
report semgrep --version  || true
report joern    --version || true
report_any -version zaproxy zap.sh zap-cli || true
say "Done. Refresh the System screen in the interface — it re-probes the path every time it is asked."
