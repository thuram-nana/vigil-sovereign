#!/usr/bin/env bash
# CRUCIBLE / OBSIDIAN — tool installer
#
# Installs the toolchain expected by the framework. Idempotent: safe to re-run.
# Designed for Debian/Ubuntu. Run with sudo or as root.
#
# Strategy:
#   1. apt packages first (system-wide, fast).
#   2. Go-based tools (most ProjectDiscovery + community tools).
#   3. Python pip tools.
#   4. Git-clone tools dropped under /opt/crucible-tools/.
#   5. Wordlists into /usr/share/seclists, /usr/share/payloadsallthethings.
#
# Tools are installed even if you'll only ever use a few — the cost of unused
# binaries is dwarfed by the cost of being stuck mid-engagement without one.

set -euo pipefail

# ----- helpers ---------------------------------------------------------------

GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; CYAN=$'\e[36m'; RESET=$'\e[0m'
log()   { printf '%s[+]%s %s\n' "$GREEN"  "$RESET" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }
err()   { printf '%s[x]%s %s\n' "$RED"    "$RESET" "$*" >&2; }
info()  { printf '%s[i]%s %s\n' "$CYAN"   "$RESET" "$*"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Run as root (use sudo)."
    exit 1
  fi
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

INSTALL_LOG="/var/log/crucible-install.log"
mkdir -p "$(dirname "$INSTALL_LOG")"
exec > >(tee -a "$INSTALL_LOG") 2>&1

require_root

log "CRUCIBLE installer starting at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Log: $INSTALL_LOG"

# ----- stage 0: base system --------------------------------------------------

log "Stage 0: base system packages"

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends \
  build-essential ca-certificates curl wget git unzip zip jq \
  python3 python3-pip python3-venv python3-dev \
  libpcap-dev libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev \
  ruby ruby-dev nodejs npm \
  golang-go \
  pandoc texlive-xetex texlive-fonts-recommended \
  whois dnsutils netcat-openbsd nmap masscan \
  hashcat john hydra \
  sqlmap commix \
  ffuf gobuster feroxbuster \
  zaproxy \
  apktool jadx \
  trivy \
  asciinema httpie

# pipx for Python application installs (avoids "externally-managed" errors)
apt-get install -y --no-install-recommends pipx || pip3 install --break-system-packages pipx
pipx ensurepath || true

log "Stage 0 complete"

# ----- stage 1: Go env -------------------------------------------------------

log "Stage 1: Go environment"

GO_VERSION="1.22.5"
GOPATH_DIR="/opt/go"
GOBIN_DIR="$GOPATH_DIR/bin"

export GOPATH="$GOPATH_DIR"
export GOBIN="$GOBIN_DIR"
export PATH="$GOBIN_DIR:/usr/local/go/bin:$PATH"

mkdir -p "$GOPATH_DIR" "$GOBIN_DIR"

# Prefer system Go if recent enough, else install upstream.
NEED_UPSTREAM_GO=1
if cmd_exists go; then
  GO_INSTALLED=$(go version | awk '{print $3}' | sed 's/go//')
  # crude semver compare
  if [[ "$(printf '%s\n' "$GO_VERSION" "$GO_INSTALLED" | sort -V | head -1)" == "$GO_VERSION" ]]; then
    NEED_UPSTREAM_GO=0
    info "System go $GO_INSTALLED is recent enough"
  fi
fi

if [[ $NEED_UPSTREAM_GO -eq 1 ]]; then
  info "Installing Go $GO_VERSION upstream"
  cd /tmp
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
  rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
fi

# Persist env
cat > /etc/profile.d/crucible.sh <<'EOF'
export GOPATH=/opt/go
export GOBIN=/opt/go/bin
export PATH=$GOBIN:/usr/local/go/bin:/opt/crucible-tools/bin:$PATH
EOF
chmod +x /etc/profile.d/crucible.sh

log "Stage 1 complete"

# ----- stage 2: Go tools -----------------------------------------------------

log "Stage 2: Go-based tools (ProjectDiscovery + community)"

GO_TOOLS=(
  # ProjectDiscovery
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "github.com/projectdiscovery/notify/cmd/notify@latest"
  # community
  "github.com/owasp-amass/amass/v4/...@master"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/tomnomnom/qsreplace@latest"
  "github.com/tomnomnom/anew@latest"
  "github.com/tomnomnom/unfurl@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  "github.com/zricethezav/gitleaks/v8@latest"
  "github.com/trufflesecurity/trufflehog/v3@latest"
  "github.com/securego/gosec/v2/cmd/gosec@latest"
  "github.com/aquasecurity/tfsec/cmd/tfsec@latest"
  "github.com/Shopify/kubeaudit@latest"
  "github.com/controlplaneio/kubesec/v2@latest"
  "github.com/assetnote/kiterunner/cmd/kr@latest"
  "github.com/ffuf/ffuf/v2@latest"
)

for pkg in "${GO_TOOLS[@]}"; do
  tool_name="$(basename "${pkg%@*}")"
  if cmd_exists "$tool_name"; then
    info "$tool_name already installed, refreshing"
  fi
  info "go install $pkg"
  if ! GOFLAGS=-buildvcs=false go install -v "$pkg" 2>&1 | tail -5; then
    warn "Failed to install $pkg — continuing"
  fi
done

# update nuclei templates
if cmd_exists nuclei; then
  info "Updating nuclei templates"
  nuclei -update-templates -silent || warn "nuclei template update failed"
fi

log "Stage 2 complete"

# ----- stage 3: Python tools -------------------------------------------------

log "Stage 3: Python tools"

# pipx-installed (CLI applications)
PIPX_TOOLS=(
  "scoutsuite"
  "prowler"
  "pacu"
  "kube-hunter"
  "checkov"
  "cloudsplaining"
  "bandit"
  "semgrep"
  "mitmproxy"
  "ghauri"
  "pip-audit"
  "safety"
  "detect-secrets"
  "arjun"
  "graphql-cop"
  "clairvoyance"
  "objection"
  "frida-tools"
  "impacket"
  "netexec"
)

for pkg in "${PIPX_TOOLS[@]}"; do
  if pipx list 2>/dev/null | grep -q "package $pkg "; then
    info "$pkg already installed via pipx"
    continue
  fi
  info "pipx install $pkg"
  pipx install "$pkg" 2>&1 | tail -3 || warn "pipx install $pkg failed"
done

# pip-installed (libraries imported by scripts)
info "pip libraries (for scripts)"
pip3 install --break-system-packages \
  requests urllib3 beautifulsoup4 lxml pyjwt cryptography \
  python-magic tabulate rich click \
  2>&1 | tail -5 || warn "some pip libs failed"

# jwt_tool (single-script install)
if [[ ! -d /opt/crucible-tools/jwt_tool ]]; then
  info "Installing jwt_tool"
  mkdir -p /opt/crucible-tools
  git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/crucible-tools/jwt_tool || warn "jwt_tool clone failed"
  pip3 install --break-system-packages -r /opt/crucible-tools/jwt_tool/requirements.txt 2>&1 | tail -3 || true
  ln -sf /opt/crucible-tools/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool
  chmod +x /opt/crucible-tools/jwt_tool/jwt_tool.py || true
fi

log "Stage 3 complete"

# ----- stage 4: NPM tools ----------------------------------------------------

log "Stage 4: NPM tools"

NPM_TOOLS=(
  "retire"
  "snyk"
)

for pkg in "${NPM_TOOLS[@]}"; do
  if npm list -g --depth=0 2>/dev/null | grep -q "$pkg@"; then
    info "$pkg already installed"
    continue
  fi
  info "npm install -g $pkg"
  npm install -g "$pkg" 2>&1 | tail -3 || warn "$pkg failed"
done

log "Stage 4 complete"

# ----- stage 5: Ruby tools ---------------------------------------------------

log "Stage 5: Ruby tools"

if cmd_exists gem; then
  for g in brakeman bundler-audit; do
    if gem list -i "$g" >/dev/null 2>&1; then
      info "$g already installed"
    else
      info "gem install $g"
      gem install "$g" --no-document 2>&1 | tail -3 || warn "$g failed"
    fi
  done
fi

log "Stage 5 complete"

# ----- stage 6: git-clone tools ---------------------------------------------

log "Stage 6: git-clone tools"

mkdir -p /opt/crucible-tools

clone_or_update() {
  local repo="$1" dest="$2"
  if [[ -d "$dest/.git" ]]; then
    info "Updating $dest"
    git -C "$dest" pull --ff-only --quiet || warn "Pull failed for $dest"
  else
    info "Cloning $repo"
    git clone --depth 1 "$repo" "$dest" || warn "Clone failed for $repo"
  fi
}

clone_or_update https://github.com/swisskyrepo/SSRFmap.git              /opt/crucible-tools/SSRFmap
clone_or_update https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/crucible-tools/PayloadsAllTheThings
clone_or_update https://github.com/danielmiessler/SecLists.git          /usr/share/seclists
clone_or_update https://github.com/fuzzdb-project/fuzzdb.git            /opt/crucible-tools/fuzzdb
clone_or_update https://github.com/codingo/NoSQLMap.git                 /opt/crucible-tools/NoSQLMap
clone_or_update https://github.com/enjoiz/XXEinjector.git               /opt/crucible-tools/XXEinjector
clone_or_update https://github.com/s0md3v/XSStrike.git                  /opt/crucible-tools/XSStrike
clone_or_update https://github.com/epinna/tplmap.git                    /opt/crucible-tools/tplmap
clone_or_update https://github.com/inguardians/peirates.git             /opt/crucible-tools/peirates

# install SSRFmap deps
if [[ -f /opt/crucible-tools/SSRFmap/requirements.txt ]]; then
  pip3 install --break-system-packages -r /opt/crucible-tools/SSRFmap/requirements.txt 2>&1 | tail -3 || true
fi

# common symlinks
ln -sf /opt/crucible-tools/SSRFmap/ssrfmap.py /usr/local/bin/ssrfmap || true
ln -sf /opt/crucible-tools/XSStrike/xsstrike.py /usr/local/bin/xsstrike || true
ln -sf /opt/crucible-tools/tplmap/tplmap.py /usr/local/bin/tplmap || true

log "Stage 6 complete"

# ----- stage 7: Burp / ZAP / Cloud CLIs note --------------------------------

log "Stage 7: Manual installs (notes only)"

cat <<'NOTE'
The following tools must be installed manually (license, GUI, or vendor-specific):

  Burp Suite Community/Pro      → https://portswigger.net/burp/releases
  AWS CLI v2                    → curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
                                  unzip awscliv2.zip && sudo ./aws/install
  gcloud CLI                    → https://cloud.google.com/sdk/docs/install
  Azure CLI                     → curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
  kubectl                       → curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  helm                          → curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
  MobSF                         → docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf
  Burp BApp extensions          → install from BApp Store (requires Burp Pro for some)
  OWASP Dependency-Check        → https://owasp.org/www-project-dependency-check/

You will likely want at least one of these for any real engagement.
NOTE

log "Stage 7 complete"

# ----- stage 8: directory layout ---------------------------------------------

log "Stage 8: workspace directories"

# Create a wordlists symlink farm for convenience
mkdir -p /opt/crucible-tools/bin
mkdir -p /opt/crucible-tools/wordlists
[[ -d /usr/share/seclists ]] && ln -sf /usr/share/seclists /opt/crucible-tools/wordlists/seclists
[[ -d /opt/crucible-tools/PayloadsAllTheThings ]] && \
  ln -sf /opt/crucible-tools/PayloadsAllTheThings /opt/crucible-tools/wordlists/payloads
[[ -d /opt/crucible-tools/fuzzdb ]] && \
  ln -sf /opt/crucible-tools/fuzzdb /opt/crucible-tools/wordlists/fuzzdb

log "Stage 8 complete"

# ----- final summary ---------------------------------------------------------

log "============================================================"
log "CRUCIBLE installer finished at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Run framework/tools/verify.sh to confirm tool availability."
log ""
log "Source /etc/profile.d/crucible.sh in your shell or re-login"
log "to pick up PATH changes:"
log ""
log "    source /etc/profile.d/crucible.sh"
log ""
log "Useful paths:"
log "  Go binaries        : $GOBIN_DIR"
log "  Cloned tools       : /opt/crucible-tools"
log "  Wordlists          : /usr/share/seclists, /opt/crucible-tools/wordlists"
log "  Install log        : $INSTALL_LOG"
log "============================================================"
