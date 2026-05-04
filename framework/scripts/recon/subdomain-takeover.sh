#!/usr/bin/env bash
#
# subdomain-takeover.sh — find takeover candidates from a subdomain list.
#
# Used in playbook 12 §12.6.
#
# Reads a file with one subdomain per line, resolves each, and
# checks for the response patterns that indicate a dangling
# DNS pointer (CNAME or A) to a service where takeover is possible.
#
# Usage:
#   ./subdomain-takeover.sh subdomains.txt
#
# Better tools exist (subjack, subzy, nuclei takeover templates).
# This script is a pure-bash spotcheck that doesn't require Go
# tooling — useful for triage.

set -euo pipefail

if [ -z "${1-}" ]; then
  echo "usage: $0 subdomains.txt" >&2
  exit 1
fi

INPUT="$1"

# Pattern: CNAME contains, response 404 / NoSuchBucket / etc → vulnerable
# Quick check for common services.
declare -A FINGERPRINTS=(
  ["s3.amazonaws.com"]="NoSuchBucket"
  ["github.io"]="There isn't a GitHub Pages site here"
  ["herokuapp.com"]="No such app"
  ["zendesk.com"]="Help Center Closed"
  ["readme.io"]="Project doesnt exist"
  ["statuspage.io"]="StatusPage.io is the best way"
  ["bitbucket.io"]="Repository not found"
  ["fastly.net"]="Fastly error: unknown domain"
  ["pantheonsite.io"]="The gods are wise"
  ["surge.sh"]="project not found"
  ["tumblr.com"]="There's nothing here"
  ["unbouncepages.com"]="The requested URL was not found"
  ["wordpress.com"]="Do you want to register"
  ["ghost.io"]="The thing you were looking for is no longer here"
)

printf "%-50s %-30s %s\n" "SUBDOMAIN" "CNAME" "STATUS"
printf "%-50s %-30s %s\n" "---------" "-----" "------"

while IFS= read -r sub; do
  sub=$(echo "$sub" | tr -d '\r' | sed 's/^ *//;s/ *$//')
  [ -z "$sub" ] && continue
  [[ "$sub" =~ ^# ]] && continue

  # Resolve CNAME
  cname=$(dig +short CNAME "$sub" | tail -n1 | sed 's/\.$//')

  if [ -n "$cname" ]; then
    # Check against fingerprints
    suspect=""
    for service in "${!FINGERPRINTS[@]}"; do
      if [[ "$cname" == *"$service"* ]]; then
        # Probe it
        body=$(curl -sk -L --max-time 8 \
                    -H "User-Agent: OBSIDIAN/1.0" \
                    "http://$sub/" || echo "")
        pattern="${FINGERPRINTS[$service]}"
        if echo "$body" | grep -qi "$pattern"; then
          suspect="VULNERABLE ($service)"
        else
          suspect="probe-cname-${service%.*}"
        fi
        break
      fi
    done
    if [ -z "$suspect" ]; then
      suspect="cname-OK"
    fi
    printf "%-50s %-30s %s\n" "$sub" "$cname" "$suspect"
  else
    # No CNAME; check A
    a=$(dig +short A "$sub" | head -n1)
    if [ -z "$a" ]; then
      printf "%-50s %-30s %s\n" "$sub" "—" "NO-DNS"
    else
      printf "%-50s %-30s %s\n" "$sub" "A:$a" "ok"
    fi
  fi
done < "$INPUT"

echo
echo "VULNERABLE entries are direct candidates. Each must be"
echo "verified manually (claim the third-party tenant; or remove DNS)."
echo "probe-cname-* entries need follow-up — fingerprint not matched"
echo "but pointed at a known service."
