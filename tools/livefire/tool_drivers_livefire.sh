#!/usr/bin/env bash
# =============================================================================
# VIGIL LIVE-FIRE — the engine's TYPED TOOL DRIVERS, against the live loopback range
# =============================================================================
#
# WHAT THIS IS. The engine is gaining typed argv builders so it can drive its whole toolset. A builder
# that produces a plausible-looking command line proves nothing: the tool has to actually run, actually
# find the planted weakness, and its output has to actually parse into observations. Unit-testing the
# argv string alone is how you ship a driver that has never worked.
#
# This script stands up what is needed, runs every driver in the table through the ENGINE'S OWN
# executor — twice, once against a target with the weakness and once against a control where it is
# absent — and tears it all down. It exits non-zero the moment an expectation stops holding, and says
# which one. A live-fire script that only prints and never fails is a demo, not a proof.
#
# WHY IT IS AUTHORIZED. targets/loopback/charter.md authorizes a self-hosted, deliberately-vulnerable
# loopback target that VIGIL stands up and owns, and binds every tool to 127.0.0.0/8. The vulnerable
# target here is the repository's own app, started by tools/livefire/range.sh (which asserts its
# loopback binding four ways); the clean controls are HTTP servers the harness itself runs on 127.0.0.1
# and destroys with the process. There is no third party and no external host, and no public test site
# is contacted.
#
# AND THE NEGATIVE CONTROLS ARE THE PRODUCT. A detector that only ever says "found something" is
# worthless. Every driver proven here must fire on the planted weakness AND stay silent on a clean
# control — while that control is demonstrably still being tested, so its silence is evidence rather
# than an absence of evidence.
#
# ONE RUN AT A TIME, AND IT ENFORCES THAT ITSELF. Three copies of this harness were observed running
# concurrently, with two nikto processes writing the same report file. The runs share machine-global
# state none of them owns exclusively — the range target that one run's teardown DESTROYS while
# another is still scanning it, the executor's report artifacts (whose path is derived from the tool
# and the target, both identical across runs), and the single port the executor pins for ZAP's main
# proxy listener. Evidence corrupted by a second run is worse than no evidence: it still looks like a
# result. So the lock is IN the harness, taken below before anything shared is touched, and a second
# invocation fails fast naming the run that holds it.
#
# USAGE
#   tools/livefire/tool_drivers_livefire.sh              # bring up what is needed, prove, tear down
#   KEEP_RANGE=1 tools/livefire/tool_drivers_livefire.sh # leave the range target running afterwards
#   VIGIL_LIVEFIRE_RANGE_TARGET=juice  …                 # drive the web rows against another target
#   VIGIL_LIVEFIRE_ALLOW_MISSING=httpx …                 # acknowledge a known-absent tool as a SKIP
#   VIGIL_LIVEFIRE_STRICT_BUILDERS=1   …                 # fail if any executor builder has no row
#
# EXIT CODES: 0 proven · 1 an expectation did not hold · 3 another run holds the run lock.
#
# REQUIRES: the offense virtualenv at .venv-offense, python3, flock(1), and the tools themselves
# (nmap, nuclei, ffuf, sqlmap, hydra, httpx). A tool that is missing is REPORTED as unproven, never
# silently skipped.
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/tools/livefire"
RANGE_TARGET="${VIGIL_LIVEFIRE_RANGE_TARGET:-vulnapp}"
VENV="${VIGIL_OFFENSE_VENV:-$REPO/.venv-offense}"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# =============================================================================
# THE RUN LOCK — taken HERE, before anything shared is touched
# =============================================================================
#
# Deliberately the first thing this script does that can fail: before the range is brought up, before
# the virtualenv is checked, and before the teardown trap is installed, so a REFUSED second run can
# neither start a target nor destroy one. Its exit code is 3, distinct from the 1 an expectation
# failure returns, because "somebody else is running" is not a live-fire result.
#
# WHY flock AND NOT A PID FILE. The lock is an advisory lock on a descriptor this shell holds for its
# entire life, so the kernel releases it however the script ends — including SIGKILL and a power cut.
# There is no stale lock to clean up and no "is that pid still alive" guess to get wrong. The JSON
# written INTO that same file is a HOLDER RECORD and not the lock: it exists only so that a refused run
# can name who has it, and a refused run is told when it looks stale rather than quoting it as fact.
#
# The path comes from tool_drivers_livefire.py rather than being spelled here, so the shell and the
# Python harness cannot drift onto two different locks — which would leave both of them "locked" and
# neither of them exclusive.
LOCK_FILE="$(python3 "$HERE/tool_drivers_livefire.py" --lock-path)" ||
  die "cannot establish the live-fire run lock (the reason is printed above).
        Running unlocked is not an option: a second run corrupts this one's evidence."
LOCK_DIR="$(dirname "$LOCK_FILE")"
command -v flock >/dev/null 2>&1 ||
  die "flock(1) is required to serialise live-fire runs and is not installed (apt install util-linux).
        Running unlocked is not an option: a second run corrupts this one's evidence."

# `<>` and NOT `>`: opening for write TRUNCATES, and it happens BEFORE the lock is taken — so a run
# that is about to be refused would first erase the holder record it is supposed to quote back to the
# operator. Read-write leaves the record intact for the refusal message.
exec 9<>"$LOCK_FILE" || die "cannot open the run lock at $LOCK_FILE"
if ! flock -n 9; then
  python3 "$HERE/tool_drivers_livefire.py" --lock-holder >&2 || true
  exit 3
fi

LOCK_NONCE="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[ -n "$LOCK_NONCE" ] || die "could not generate a run-lock nonce from /dev/urandom"
# Sanitised, because these end up inside a JSON document a refused run parses: RANGE_TARGET is
# operator-supplied through the environment, and a quote in it would produce a record nobody can read.
sanitise() { printf '%s' "$1" | tr -cd '[:alnum:]._@-' | cut -c1-64; }
SAFE_TARGET="$(sanitise "$RANGE_TARGET")"
# An empty name would make every target share one ownership claim, which is the opposite of the point.
[ -n "$SAFE_TARGET" ] ||
  die "VIGIL_LIVEFIRE_RANGE_TARGET='$RANGE_TARGET' has no usable characters; the range has no such target"
RANGE_STAMP="$LOCK_DIR/range-$SAFE_TARGET.owner"

# The holder record, written only NOW — after the lock is held, so two runs can never interleave
# their records. A separate descriptor is used deliberately: it truncates, which fd 9 must not do,
# and truncating through another descriptor does not disturb fd 9's lock (flock binds to the inode).
printf '{"pid":%s,"nonce":"%s","user":"%s","host":"%s","started":"%s","purpose":"%s","target":"%s"}\n' \
  "$$" "$LOCK_NONCE" \
  "$(sanitise "$(id -un 2>/dev/null || echo unknown)")" \
  "$(sanitise "$(hostname 2>/dev/null || echo unknown)")" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "tool_drivers_livefire.sh" "$SAFE_TARGET" > "$LOCK_FILE"

# What lets the Python harness recognise THIS shell as its own launcher instead of refusing to run
# under a lock it cannot take. The nonce is the proof: nothing but the process that generated it and
# wrote it into the holder record could have put it in our environment.
export VIGIL_LIVEFIRE_LOCK="$LOCK_FILE"
export VIGIL_LIVEFIRE_LOCK_NONCE="$LOCK_NONCE"
export VIGIL_LIVEFIRE_LOCK_PID="$$"

# Wait until a port can actually be BOUND, not merely until nothing is listening on it.
#
# This exists because of the previous run. The tools here open hundreds of short-lived connections to
# the target, so when it stops, its side of each one sits in TIME-WAIT for a minute. range.sh decides
# whether a port is free by binding it WITHOUT SO_REUSEADDR, which those TIME-WAIT sockets defeat — so
# a re-run inside that window is refused with "already in use by something that is not part of this
# range", naming a culprit that does not exist. The condition is real and temporary, so the harness
# waits it out rather than failing a proof run over a socket timer.
wait_for_bindable() {
  local port="$1" waited=0
  while ! python3 - "$port" <<'PY'
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))       # no SO_REUSEADDR: the same test range.sh applies
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
  do
    if [ "$waited" = "0" ]; then
      info "port $port is not yet bindable (TIME-WAIT from the previous run) — waiting"
    fi
    waited=$((waited + 2))
    # Written as `if`, not `[ … ] && …`: under `set -e` a guard that evaluates FALSE makes the
    # and-list the function's status, and this one runs a teardown trap on its way out.
    if [ "$waited" -gt 90 ]; then
      die "port $port did not become bindable after ${waited}s.
        Something else is holding it:   ss -ltnp | grep $port"
    fi
    sleep 2
  done
  if [ "$waited" -gt 0 ]; then
    info "port $port is bindable again after ${waited}s"
  fi
  return 0
}

# Whether WE started the range target decides whether we may stop it: a target the operator already had
# running is not ours to tear down.
STARTED_RANGE=0

cleanup() {
  local code=$?
  if [ "$STARTED_RANGE" = "1" ]; then
    if [ "${KEEP_RANGE:-0}" = "1" ]; then
      echo
      info "KEEP_RANGE=1 — leaving '$RANGE_TARGET' up. Stop it with: tools/livefire/range.sh down $RANGE_TARGET"
      # We are deliberately handing the target on, so we are no longer the run that owns it. Dropping
      # the claim keeps a later run from reading an ownership we have given up.
      rm -f "$RANGE_STAMP"
    else
      # A RUN MUST NOT DESTROY SHARED STATE ANOTHER RUN IS USING. An agent watched its own teardown
      # pull the range out from under a sibling that was still scanning it; the sibling's tools then
      # reported nothing, which is precisely what a driver that found nothing reports.
      #
      # The run lock already makes a sibling copy of THIS script impossible. This is the second
      # check, and it is the one that holds against anything that never took the lock: the claim was
      # written to disk when our `range.sh up` succeeded, and we destroy the target only if the claim
      # on disk is still ours. A claim that has changed hands means the target is not ours to
      # destroy, and the run says so instead of destroying it.
      local stamped=""
      # `if`, not `[ … ] && …`: under `set -e` a false guard makes the and-list the function's
      # status, and this function is the EXIT trap.
      if [ -f "$RANGE_STAMP" ]; then
        stamped="$(cat "$RANGE_STAMP" 2>/dev/null || true)"
      fi
      if [ "$stamped" = "$LOCK_NONCE" ]; then
        bold "Tearing down what this script started"
        "$HERE/range.sh" down "$RANGE_TARGET" >/dev/null 2>&1 || true
        rm -f "$RANGE_STAMP"
        info "range target '$RANGE_TARGET' destroyed"
      else
        bold "NOT tearing down '$RANGE_TARGET' — it is no longer this run's to destroy"
        info "this run started it, but the ownership claim at $RANGE_STAMP now reads"
        info "'${stamped:-<no claim on disk>}' rather than this run's '$LOCK_NONCE'."
        info "Something else has taken it over, and destroying a target another run is scanning turns"
        info "its results into silence that looks exactly like a clean scan. Stop it by hand once you"
        info "are sure nothing is using it:   tools/livefire/range.sh down $RANGE_TARGET"
      fi
    fi
  fi
  # The control servers and their ports live and die inside the harness process; nothing to clean up
  # for them, which is the point of running them in-process. The run lock needs no cleanup either —
  # the kernel drops fd 9's flock however this process ends.
  exit $code
}
trap cleanup EXIT

bold "VIGIL live-fire — proving the engine's typed tool drivers"
info "range target : $RANGE_TARGET   (the vulnerable side)"
info "controls     : started in-process on loopback by the harness"
info "charter      : targets/loopback/charter.md — 127.0.0.0/8 only, nothing external"
info "run lock     : $LOCK_FILE (held by pid $$; a second run is refused, not queued)"

# The offense virtualenv is how an operator machine carries the framework + integration packages this
# harness drives. CI has no such venv (it pip-installs into the job's own interpreter and never builds
# the Rust kernel), so fall back to the interpreter on PATH when the venv is absent AND the packages
# import from there. Falling back only on a WORKING import keeps the original error for the real
# failure this check was written for — an operator whose venv is broken or half-built.
if [ -x "$VENV/bin/python" ]; then
  PY="$VENV/bin/python"
elif PYTHONPATH="integration:engine/crucible:gateway" \
     "${VIGIL_LIVEFIRE_PYTHON:-python3}" -c "import vigil_integration.live.executor" 2>/dev/null; then
  PY="${VIGIL_LIVEFIRE_PYTHON:-python3}"
  info "venv         : absent — using ${PY} (the packages import from it)"
else
  die "the offense virtualenv is missing at $VENV
        (it carries the framework + integration packages this harness drives)
        No fallback interpreter could import vigil_integration either. Set VIGIL_LIVEFIRE_PYTHON
        to an interpreter that can, or build the venv with ./bootstrap.sh"
fi
[ -f "$HERE/range_targets.py" ] || die "the range is missing at $HERE/range_targets.py
        This harness reads the range manifest rather than hardcoding a port."

bold "Bringing up the vulnerable target"
# Idempotent by design: range.sh up is a no-op on an already-running target, but we only take
# responsibility for tearing down a target that was NOT already up when we arrived.
# The status is captured BEFORE it is matched, deliberately. Piping it straight into `grep -q` under
# `set -o pipefail` reports the pipeline as FAILED whenever grep matches: grep exits at the first hit,
# range.sh takes SIGPIPE, and its 141 becomes the pipeline's status. The symptom is a script that only
# ever takes the "not running" branch — and then fights the running target for its port.
RANGE_STATUS="$("$HERE/range.sh" status 2>/dev/null || true)"
if printf '%s\n' "$RANGE_STATUS" | grep -qE "^ +$RANGE_TARGET +running"; then
  info "'$RANGE_TARGET' is already up — leaving it to whoever started it"
else
  # `range.sh list` names each target twice — once in the manifest check (where field 2 is its KIND)
  # and once in the port table — so the numeric filter is what makes this the port and not the word
  # "process". A multi-port target (webgoat) yields several; all of them have to be bindable.
  for p in $("$HERE/range.sh" list 2>/dev/null |
             awk -v t="$RANGE_TARGET" '$1 == t && $2 ~ /^[0-9]+$/ {print $2}'); do
    wait_for_bindable "$p"
  done
  # Ownership is claimed only AFTER the bring-up succeeds. Claiming it first means a FAILED start —
  # including the "that port is held by something that is not part of this range" case — would send
  # the teardown after a process this script never started.
  "$HERE/range.sh" up "$RANGE_TARGET" >/dev/null || die "could not bring up range target '$RANGE_TARGET'.
        Run it directly to see why:   tools/livefire/range.sh up $RANGE_TARGET"
  # The claim, on disk, BEFORE the in-memory flag — so the teardown has something to re-check. If the
  # write were to fail, `set -e` stops here with the flag still 0 and the target is left running: a
  # leaked target is recoverable by hand, a target destroyed under another run's scan is not.
  printf '%s\n' "$LOCK_NONCE" > "$RANGE_STAMP"
  STARTED_RANGE=1
  info "'$RANGE_TARGET' started (and will be destroyed on exit; claim recorded at $RANGE_STAMP)"
fi

# The harness re-reads the manifest, re-asserts the loopback binding, and confirms the planted weakness
# with the range's OWN differential probe before it draws a conclusion from any tool.
#
# NOT `exec`: this shell owns the teardown trap, so it has to outlive the harness. `set -e` would also
# skip the exit-code line, hence the explicit capture — the harness's non-zero verdict is the whole
# point of running it, and must survive back to the caller unchanged.
cd "$REPO"
rc=0
PYTHONPATH="integration:engine/crucible:gateway" \
  "$PY" "$HERE/tool_drivers_livefire.py" || rc=$?
exit $rc
