#!/usr/bin/env bash
# CRUCIBLE / OBSIDIAN — tool verification
#
# Confirms the tools the framework expects are callable. Does NOT install.
# Exit code:
#   0 → all critical tools present
#   1 → some critical tool missing (framework usable but degraded)
#   2 → many critical tools missing (run install.sh)

set -u

GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; CYAN=$'\e[36m'; BOLD=$'\e[1m'; RESET=$'\e[0m'

ok()    { printf '  %s✓%s %-25s %s\n' "$GREEN"  "$RESET" "$1" "$2"; }
miss()  { printf '  %s✗%s %-25s %s\n' "$RED"    "$RESET" "$1" "$2"; }
warn_() { printf '  %s!%s %-25s %s\n' "$YELLOW" "$RESET" "$1" "$2"; }
hdr()   { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$RESET"; }

CRITICAL_PRESENT=0; CRITICAL_MISSING=0
OPTIONAL_PRESENT=0; OPTIONAL_MISSING=0

check() {
  local tool="$1" tier="$2" version_cmd="${3:-}"
  if command -v "$tool" >/dev/null 2>&1; then
    local v=""
    if [[ -n "$version_cmd" ]]; then
      v="$(eval "$version_cmd" 2>&1 | head -1 | tr -d '\r' | cut -c1-60)"
    fi
    ok "$tool" "${v:-installed}"
    if [[ "$tier" == "critical" ]]; then ((CRITICAL_PRESENT++)); else ((OPTIONAL_PRESENT++)); fi
  else
    if [[ "$tier" == "critical" ]]; then
      miss "$tool" "MISSING (critical)"
      ((CRITICAL_MISSING++))
    else
      warn_ "$tool" "missing (optional)"
      ((OPTIONAL_MISSING++))
    fi
  fi
}

check_path() {
  local path="$1" label="$2" tier="$3"
  if [[ -e "$path" ]]; then
    ok "$label" "$path"
    if [[ "$tier" == "critical" ]]; then ((CRITICAL_PRESENT++)); else ((OPTIONAL_PRESENT++)); fi
  else
    if [[ "$tier" == "critical" ]]; then
      miss "$label" "MISSING ($path)"
      ((CRITICAL_MISSING++))
    else
      warn_ "$label" "missing ($path)"
      ((OPTIONAL_MISSING++))
    fi
  fi
}

# Source PATH additions if the install script created them
[[ -f /etc/profile.d/crucible.sh ]] && source /etc/profile.d/crucible.sh

printf '%s%sCRUCIBLE tool verification%s\n' "$BOLD" "$CYAN" "$RESET"
printf 'Run at: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

hdr "Core utilities"
check curl     critical "curl --version"
check wget     critical "wget --version"
check git      critical "git --version"
check jq       critical "jq --version"
check python3  critical "python3 --version"
check go       critical "go version"
check node     critical "node --version"
check npm      critical "npm --version"

hdr "Reconnaissance"
check subfinder    critical "subfinder -version 2>&1"
check amass        optional "amass version 2>&1"
check assetfinder  optional ""
check dnsx         critical "dnsx -version 2>&1"
check naabu        optional "naabu -version 2>&1"
check nmap         critical "nmap --version"
check masscan      optional "masscan --version"
check httpx        critical "httpx -version 2>&1"
check katana       optional "katana -version 2>&1"
check gau          optional ""
check waybackurls  optional ""
check ffuf         critical "ffuf -V 2>&1"
check feroxbuster  optional ""
check gobuster     optional "gobuster version"
check nuclei       critical "nuclei -version 2>&1"
check asnmap       optional ""
check tlsx         optional ""
check shuffledns   optional ""
check anew         optional ""
check qsreplace    optional ""
check unfurl       optional ""
check gf           optional ""

hdr "Web Application & API"
check sqlmap            critical "sqlmap --version"
check ghauri            optional ""
check commix            optional "commix --version"
check dalfox            optional "dalfox version"
check xsstrike          optional ""
check tplmap            optional ""
check ssrfmap           optional ""
check zaproxy           optional ""
check mitmproxy         optional "mitmproxy --version"
check mitmdump          optional ""
check jwt_tool          critical ""
check arjun             optional "arjun --help"
check graphql-cop       optional ""
check clairvoyance      optional ""
check kr                optional ""
check crlfuzz           optional ""
check interactsh-client critical ""

hdr "Source Code & Supply Chain"
check semgrep          critical "semgrep --version"
check bandit           optional "bandit --version"
check gosec            optional "gosec --version"
check brakeman         optional "brakeman --version"
check trufflehog       critical "trufflehog --version"
check gitleaks         optional "gitleaks version"
check detect-secrets   optional ""
check pip-audit        optional "pip-audit --version"
check safety           optional "safety --version"
check retire           optional "retire --version"
check snyk             optional "snyk --version"

hdr "Cloud / Container / K8s"
check scout            optional ""
check prowler          optional "prowler --version"
check pacu             optional ""
check kube-hunter      optional "kube-hunter --help 2>&1 | head -2"
check kubeaudit        optional "kubeaudit version"
check kubesec          optional "kubesec version"
check trivy            optional "trivy --version"
check checkov          optional "checkov --version"
check tfsec            optional "tfsec --version"
check cloudsplaining   optional ""
check aws              optional "aws --version 2>&1"
check gcloud           optional "gcloud --version 2>&1 | head -1"
check az               optional "az --version 2>&1 | head -1"
check kubectl          optional "kubectl version --client --output=yaml 2>&1 | head -3"
check helm             optional "helm version --short"

hdr "Mobile"
check apktool          optional "apktool --version"
check jadx             optional "jadx --version"
check frida            optional "frida --version"
check objection        optional ""

hdr "Cracking / Auth"
check hashcat          optional "hashcat --version"
check john             optional "john --version 2>&1 | head -1"
check hydra            optional "hydra -h 2>&1 | head -1"

hdr "Reporting"
check pandoc           critical "pandoc --version | head -1"
check asciinema        optional "asciinema --version"
check httpie           optional "http --version"

hdr "Wordlists & Payload Corpora"
check_path /usr/share/seclists                       "SecLists"           critical
check_path /opt/crucible-tools/PayloadsAllTheThings  "PayloadsAllTheThings" optional
check_path /opt/crucible-tools/fuzzdb                "fuzzdb"             optional
check_path /opt/crucible-tools/SSRFmap               "SSRFmap repo"       optional
check_path /opt/crucible-tools/jwt_tool              "jwt_tool repo"      optional

# ---- summary ----------------------------------------------------------------

printf '\n%s%s== SUMMARY ==%s\n' "$BOLD" "$CYAN" "$RESET"
printf '  Critical present: %s%d%s\n' "$GREEN" "$CRITICAL_PRESENT" "$RESET"
printf '  Critical missing: %s%d%s\n' "$RED"   "$CRITICAL_MISSING" "$RESET"
printf '  Optional present: %s%d%s\n' "$GREEN" "$OPTIONAL_PRESENT" "$RESET"
printf '  Optional missing: %s%d%s\n' "$YELLOW" "$OPTIONAL_MISSING" "$RESET"

if (( CRITICAL_MISSING == 0 )); then
  printf '\n%s✓ All critical tools present. Framework ready.%s\n' "$GREEN" "$RESET"
  exit 0
elif (( CRITICAL_MISSING <= 3 )); then
  printf '\n%s! %d critical tools missing. Framework usable but degraded.%s\n' \
    "$YELLOW" "$CRITICAL_MISSING" "$RESET"
  printf '  Suggested: sudo bash framework/tools/install.sh\n'
  exit 1
else
  printf '\n%sx %d critical tools missing. Run installer:%s\n' \
    "$RED" "$CRITICAL_MISSING" "$RESET"
  printf '  sudo bash framework/tools/install.sh\n'
  exit 2
fi
