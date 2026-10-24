#!/usr/bin/env bash
# =============================================================================
# vigil-onboard.sh — ONE command to add + test a live, AUTHORIZED web target.
#
# Chains the whole first-time flow: scaffold+attest charter -> provision a signed
# CRUCIBLE authority (scope signed in) -> engage (attack + find bugs) -> optional
# recurring schedule. After this, re-running this same command is idempotent.
#
# AUTHORIZATION IS CAPTURED, NOT BYPASSED. --owner and --authorization are YOUR
# attestation that you own / are authorized to test the target; supplying them IS
# attesting (the charter's Signed: line is filled from --owner, which is what
# ethics.is_charter_signed checks). Without them this refuses. Protected domains
# (gov/mil/edu/IGO) are refused outright. GET-only non-destructive is the engine
# default; any destructive/mutating probe still needs the owner-signed per-action
# approval at engage time — this wrapper changes none of the gates, it orchestrates.
#
# usage:
#   tools/onboard/vigil-onboard.sh <slug> <https://host/> \
#       --owner "Name" --authorization "basis, e.g. system owner / contract #123" \
#       [--scope host1,host2] [--rate 5] [--window 00:00-06:00] \
#       [--env production|twin] [--budget 600] [--schedule nightly|weekly] \
#       [--no-engage] [--dry-run]
# =============================================================================
set -euo pipefail

SLUG="${1:-}"; URL="${2:-}"
case "$SLUG" in ""|-*) SLUG="";; esac
if [ -z "$SLUG" ] || [ -z "$URL" ]; then
  echo "usage: $0 <slug> <https://host/> --owner NAME --authorization BASIS [--scope hosts] [--rate N] [--window HH:MM-HH:MM] [--env production|twin] [--budget N] [--schedule nightly|weekly] [--no-engage] [--dry-run]" >&2
  exit 2
fi
shift 2

OWNER=""; AUTHZ=""; SCOPE=""; RATE="5"; WINDOW="any"; ENV="production"; BUDGET="600"; SCHEDULE=""; DRYRUN=0; ENGAGE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --owner) OWNER="${2:-}"; shift 2;;
    --authorization) AUTHZ="${2:-}"; shift 2;;
    --scope) SCOPE="${2:-}"; shift 2;;
    --rate) RATE="${2:-}"; shift 2;;
    --window) WINDOW="${2:-}"; shift 2;;
    --env) ENV="${2:-}"; shift 2;;
    --budget) BUDGET="${2:-}"; shift 2;;
    --schedule) SCHEDULE="${2:-}"; shift 2;;
    --no-engage) ENGAGE=0; shift;;
    --dry-run) DRYRUN=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

# ---- derive host + default scope from the URL ----
HOST="$(printf '%s' "$URL" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:[0-9]+$##')"
[ -n "$SCOPE" ] || SCOPE="$HOST"

# ---- authorization gate: refuse without the operator's attestation ----
if [ -z "$OWNER" ] || [ -z "$AUTHZ" ]; then
  echo "REFUSED: --owner and --authorization are REQUIRED — they are your attestation that you own / are" >&2
  echo "         authorized to test ${HOST}. Nothing is onboarded or engaged without it." >&2
  exit 3
fi
# ---- protected-domain guardrail (never testable) ----
case ".$HOST." in
  *.gov.*|*.mil.*|*.edu.*|*.int.*) echo "REFUSED: ${HOST} is a protected-domain class (gov/mil/edu/IGO) — never a valid target." >&2; exit 3;;
esac

# ---- locate the vigil repo + venv (run from the repo, or set VIGIL_HOME) ----
ROOT="${VIGIL_HOME:-$(pwd)}"
if [ ! -x "$ROOT/.venv-offense/bin/vigil" ]; then
  echo "ERROR: run this from the vigil repo root (or set VIGIL_HOME=/path/to/vigil). Not found: $ROOT/.venv-offense/bin/vigil" >&2
  exit 1
fi
export PATH="$ROOT/.venv-offense/bin:$PATH"
export PYTHONPATH="$ROOT/engine/crucible:$ROOT/packages/core/vigil_core:$ROOT/integration:$ROOT/range${PYTHONPATH:+:$PYTHONPATH}"
export CRUCIBLE_ROOT="$ROOT/engine/crucible"
TODAY="$(date -u +%Y-%m-%d)"
# The engine reads charters from $CRUCIBLE_ROOT/targets/<slug>/ (engine/crucible/targets/...),
# NOT the repo-root targets/. The signed authority + charter share that CRUCIBLE_ROOT tree.
TDIR="$CRUCIBLE_ROOT/targets/$SLUG"
RELDIR="engine/crucible/targets/$SLUG"
PY="$ROOT/.venv-offense/bin/python"

echo "== vigil onboard: $SLUG =="
echo "   target=$URL  host=$HOST  scope=$SCOPE  env=$ENV  rate=${RATE}rps  window=$WINDOW  budget=$BUDGET  schedule=${SCHEDULE:-none}"
echo "   owner=$OWNER  authorization=$AUTHZ"
[ "$DRYRUN" = 1 ] && echo "   (DRY RUN — scaffold the charter only; do NOT provision or engage)"

# ---- 1) scaffold + attest the charter (never overwrite an existing authorization) ----
mkdir -p "$TDIR"
if [ -f "$TDIR/charter.md" ]; then
  echo "-- charter exists at $RELDIR/charter.md — keeping YOUR authorization, not overwriting"
else
  # The engine's scope parser reads the numbered "## 2. In-scope systems" table (host backtick-wrapped
  # in column 1), NOT a free-form "Target hosts" heading (that parses to EMPTY and refuses every seed).
  ROWS=""
  OLDIFS="$IFS"; IFS=','
  for h in $SCOPE; do
    h="$(printf '%s' "$h" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [ -n "$h" ] && ROWS="${ROWS}| \`$h\` | live web application ($URL) | Owner-authorized |"$'\n'
  done
  IFS="$OLDIFS"
  cat > "$TDIR/charter.md" <<EOF
# Engagement charter — \`$SLUG\`

**Version:** 1.0
**Status:** Final (operator-confirmed)
**Date:** $TODAY

Binding authorization document (OBSIDIAN constitution §II). Generated by vigil-onboard
from operator-supplied attestation.

## 1. Operator attestation

I, **$OWNER**, attest:

- I own or am explicitly authorized to test the in-scope host(s) listed in §2 below.
- Authorization basis: $AUTHZ. Current as of $TODAY.
- No external system, third-party service, or non-owned host is authorized or to be touched.

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
$ROWS
**Nothing else is in scope.** Only the host(s) above may be touched by any tool — no pivoting to
any other host, neighbouring IP, upstream, or third party (payment/IdP/CDN/email/SMS/hosting).

## 3. Out of scope (explicit)

Every host not listed in §2; all third-party services; any destructive/mutating action taken
without the owner-signed per-action approval.

## 4. Rules of engagement

- Posture: owner-test. Throttle: ${RATE} req/s. Allowed window: ${WINDOW}.
- GET-only, non-destructive by default; destructive/mutating probes require the owner-signed
  per-action approval (default-deny otherwise).
- Stop conditions: 5xx storms / sustained latency / signs of prior compromise / readable real
  user PII or payment data → pause and surface to the operator.

## 5. Sign-off

Signed: $OWNER     Date: $TODAY
EOF
  echo "-- charter scaffolded + attested -> $RELDIR/charter.md"
fi

if [ "$DRYRUN" = 1 ]; then
  echo "== DRY RUN complete. Review $RELDIR/charter.md, then re-run without --dry-run. =="
  exit 0
fi

# ---- 2) provision the signed authority (scope signed in + enforced end-to-end) ----
echo "-- provisioning signed authority (scope=$SCOPE, env=$ENV)"
vigil provision --slug "$SLUG" --scope "$SCOPE" --environment "$ENV"

# ---- 3) engage: attack + find bugs (gated; GET-only non-destructive default) ----
if [ "$ENGAGE" = 1 ]; then
  echo "-- engaging $URL (recon + library + targeted, budget $BUDGET)"
  # framework.v2 engage takes NO --scope — scope is read from the signed authority provisioned above.
  "$PY" -m framework.v2 engage "$SLUG" "$URL" --library --targeted --recon --spine --request-budget "$BUDGET"
else
  echo "-- --no-engage: authority provisioned; skipping the live run"
fi

# ---- 4) optional recurring schedule (rootless cron) ----
if [ -n "$SCHEDULE" ]; then
  case "$SCHEDULE" in
    nightly) CRON="0 2 * * *";;
    weekly)  CRON="0 2 * * 0";;
    *) echo "WARN: unknown --schedule '$SCHEDULE' (use nightly|weekly) — skipping schedule"; CRON="";;
  esac
  if [ -n "$CRON" ]; then
    LINE="$CRON cd $ROOT && PATH=$ROOT/.venv-offense/bin:\$PATH PYTHONPATH=$ROOT/engine/crucible:$ROOT/packages/core/vigil_core:$ROOT/integration:$ROOT/range CRUCIBLE_ROOT=$ROOT/engine/crucible $PY -m framework.v2 engage $SLUG $URL --library --targeted --recon --spine --request-budget $BUDGET >> $TDIR/engage.cron.log 2>&1 # vigil-onboard:$SLUG"
    ( crontab -l 2>/dev/null | grep -v "# vigil-onboard:$SLUG" ; echo "$LINE" ) | crontab -
    echo "-- scheduled $SCHEDULE recurring engage (crontab; log: $RELDIR/engage.cron.log)"
  fi
fi

echo
echo "== DONE: $SLUG onboarded =="
echo "   re-run anytime (idempotent — keeps the charter, re-provisions, re-engages):"
echo "     cd $ROOT && VIGIL_HOME=$ROOT bash tools/onboard/vigil-onboard.sh $SLUG $URL --owner \"$OWNER\" --authorization \"$AUTHZ\" --scope $SCOPE"
echo "   findings/report: $RELDIR/   ·   verify a report offline: vigil verify <report.json>"
echo "   NOTE: blind classes (SSRF/XXE/blind-cmdi) also need an OOB collector pinned in the authority"
echo "         (not exposed by the provision CLI yet) — in-band classes (SQLi/XSS/SSTI/traversal/exposure) are covered."
