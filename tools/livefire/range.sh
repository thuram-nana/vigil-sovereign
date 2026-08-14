#!/usr/bin/env bash
# =============================================================================
# VIGIL RANGE — the local, deliberately-vulnerable targets the tool drivers are
# proven against, brought up and torn down on loopback
# =============================================================================
#
# WHAT THIS IS. The engine is gaining typed argv builders so it can drive its whole toolset. A
# builder that produces a plausible-looking command line proves nothing. The tool has to actually
# run, actually find the planted weakness, and its output has to actually parse into observations.
# Unit-testing the argv string alone is how you ship a driver that has never worked.
#
# This is the place those drivers get to be wrong out loud: a set of purpose-built, open-source,
# deliberately-vulnerable applications with KNOWN answers, on fixed loopback ports, plus a generated
# source tree for the tools that read code rather than traffic.
#
# WHY IT IS AUTHORIZED. Every target runs LOCALLY, in a container this script starts and destroys,
# bound to 127.0.0.1. There is no third party and no external host in scope, and no public test site
# is contacted. See targets/loopback/charter.md, which names these applications and their ports.
#
# THE LOOPBACK RULE IS ENFORCED, NOT REMEMBERED. The manifest cannot express a host address — ports
# are integers, and one function in range_targets.py turns them into a docker flag with 127.0.0.1
# written into the format string. After start, the binding is re-read from docker, then from the
# host's listening sockets, and then MEASURED: the script connects from this host's own routable
# address and requires the connection to be refused. Any of those failing tears the target down.
#
# EVERY EXPECTATION IS ASSERTED. This script exits non-zero the moment reality stops matching the
# claim — a failed pull, a target that never answers, a seed that did not take, a binding that is
# not loopback. A live-fire script that only prints and never fails is a demo, not a proof.
#
# AND THE CONTROLS ARE THE PRODUCT. `range.sh verify` does not ask each target whether it feels
# vulnerable. It runs a differential with its own negative control: the benign request that must NOT
# produce the signal, next to the attack that must. The source range works the same way — a
# deliberately-weak tree AND a clean twin, because a detector that only ever says "found something"
# is worthless.
#
# USAGE
#   tools/livefire/range.sh list                  what targets exist, and on which ports
#   tools/livefire/range.sh up juice dvwa         start only those two
#   tools/livefire/range.sh up all                start everything (pulls ~2.5 GB the first time)
#   tools/livefire/range.sh up src                generate the source range only (no docker, no pull)
#   tools/livefire/range.sh status                what is up right now
#   tools/livefire/range.sh verify [names...]     prove each planted weakness is genuinely present
#   tools/livefire/range.sh down [names...]       destroy; with no names, destroy everything
#
# REQUIRES: docker (for the container targets), python3, git. Nothing else.
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/tools/livefire"
TARGETS_PY="$HERE/range_targets.py"
SOURCE_PY="$HERE/range_source.py"

# State lives outside the source tree. `.vigil-data/` is gitignored, which matters: the source range
# plants credential-shaped fixtures, and they must never be committable by accident.
RANGE_DIR="${VIGIL_RANGE_DIR:-$REPO/.vigil-data/range}"
SRC_DIR="$RANGE_DIR/src"
RUN_DIR="$RANGE_DIR/run"

# Docker's credential helper can want an interactive GPG unlock, which fails silently and
# confusingly on a public pull. A clean config pre-empts it. (Same reason as k8s_rbac_livefire.sh.)
export DOCKER_CONFIG="${DOCKER_CONFIG:-$RANGE_DIR/dockercfg}"

NETWORK="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["network"])' "$HERE/range_targets.json")"
LABEL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["container_label"])' "$HERE/range_targets.json")"

bold()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
info()  { printf '   %s\n' "$*"; }
ok()    { printf '   \033[32mok\033[0m   %s\n' "$*"; }
fail()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; }
die()   { fail "$*"; exit 1; }

rt() { python3 "$TARGETS_PY" "$@"; }

ALL_TARGETS="$(rt names)"

usage() {
  sed -n '/^# USAGE/,/^# REQUIRES/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  echo
  echo "Targets: $ALL_TARGETS  src"
}

# Expand the argument list. `all` means every container/process target; `src` is the source range.
# Nothing is started implicitly: an operator testing one tool should not be made to pull five images.
expand() {
  local want=() a
  for a in "$@"; do
    case "$a" in
      all) for t in $ALL_TARGETS; do want+=("$t"); done; want+=("src") ;;
      src) want+=("src") ;;
      *)
        # shellcheck disable=SC2076
        [[ " $ALL_TARGETS " == *" $a "* ]] || die "unknown target '$a'. Known: $ALL_TARGETS src"
        want+=("$a")
        ;;
    esac
  done
  printf '%s\n' "${want[@]}" | awk '!seen[$0]++'
}

# ---------------------------------------------------------------------------------------
# The source range
# ---------------------------------------------------------------------------------------

src_up() {
  bold "source range — a deliberately-weak tree and its clean twin"
  mkdir -p "$SRC_DIR"
  local out
  out="$(python3 "$SOURCE_PY" --root "$SRC_DIR" --generate)" || die "source range generation failed"

  # The recorded content id is a lock, not a decoration: it is what makes two runs comparable. If
  # the generator has been edited, results measured against the old corpus and the new one are not
  # the same measurement, and that must be a loud failure rather than a quiet drift.
  local tree fp want
  for tree in vulnerable clean; do
    fp="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]]["fingerprint"])' "$tree")"
    want="$(rt source-fingerprint "$tree")"
    [ "$fp" = "$want" ] || die "source range '$tree' has content id $fp, but range_targets.json records $want.
        If the change was intended, re-record it there:  python3 $SOURCE_PY --fingerprint"
    ok "$(printf '%-11s %s  (%s)' "$tree" "$SRC_DIR/$tree" "${fp:0:16}…")"
  done
  info "vulnerable/ carries real weakness patterns and fabricated credentials; clean/ is the control."
  info "Run secret scanners with verification disabled — the planted credentials are not real."
}

src_down() {
  [ -d "$SRC_DIR" ] || return 0
  python3 "$SOURCE_PY" --root "$SRC_DIR" --remove || true
  rmdir "$SRC_DIR" 2>/dev/null || true
  ok "source range removed"
}

# ---------------------------------------------------------------------------------------
# Container and process targets
# ---------------------------------------------------------------------------------------

port_free_or_ours() {
  local name="$1" port="$2" holder
  # Refuse to fight for a port some other process owns; say who has it instead of failing inside
  # docker with a message that does not name the culprit.
  if ! python3 - "$port" <<'PY'
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
  then
    holder="$(docker ps --filter "label=$LABEL" --filter "publish=$port" --format '{{.Names}}' 2>/dev/null | head -1 || true)"
    if [ -n "$holder" ]; then
      return 0   # already ours; up is idempotent
    fi
    # The same question for a PROCESS target, which has no container to ask. Without this branch
    # `up` is idempotent for containers and fatal for processes: the range's own running vulnapp
    # holds its own port, matches no container, and gets reported as a foreign culprit — so `up all`
    # can never be run twice, and never completes at all once vulnapp is up.
    #
    # Ownership is only claimed when it is PROVEN: the pidfile's pid must be alive AND be the pid the
    # kernel names as the listener on that port. If `ss` cannot tell us who is listening, we do NOT
    # get to assume it is ours — the whole point of this check is to refuse to fight for a port.
    local pidfile pid owner
    pidfile="$RUN_DIR/$name.pid"
    if [ -f "$pidfile" ]; then
      pid="$(cat "$pidfile" 2>/dev/null || true)"
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        owner="$(ss -ltnpH "sport = :$port" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2 || true)"
        if [ "$owner" = "$pid" ]; then
          return 0   # already ours, and demonstrably so; up is idempotent
        fi
      fi
    fi
    die "port $port (for '$name') is already in use by something that is not part of this range"
  fi
  return 0
}

ensure_network() {
  docker network inspect "$NETWORK" >/dev/null 2>&1 && return 0
  # A dedicated bridge, so range targets are not on the default bridge alongside whatever else the
  # operator is running. NOT an --internal network: docker's internal networks block published
  # ports as well as egress (verified), which would make the range unreachable from the host. The
  # range therefore does NOT claim to contain a target's outbound traffic — do not point one of
  # these applications at an external URL.
  docker network create --driver bridge "$NETWORK" >/dev/null
  info "created docker network '$NETWORK'"
}

target_up() {
  local name="$1" kind image cname
  kind="$(rt kind "$name")"
  cname="$(rt container "$name")"

  bold "$name — $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["targets"][sys.argv[2]]["title"])' "$HERE/range_targets.json" "$name")"

  local p
  for p in $(rt urls "$name" | awk '{print $2}' | sed 's|.*:||'); do
    port_free_or_ours "$name" "$p"
  done

  if [ "$kind" = "container" ]; then
    image="$(rt image "$name")"
    # `docker image inspect`, NOT `docker images -q`: the latter silently returns nothing for a
    # digest-pinned reference, so every `up` re-pulled an image that was already on the machine —
    # printing "pulling" for a no-op and making an offline range impossible to start.
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      info "pulling ${image%@*} (pinned to ${image#*@})"
      docker pull "$image" >/dev/null || die "$name: pull failed for $image"
    fi
    # The digest is the point of pinning, so confirm the daemon really has THAT content, rather
    # than trusting that the pull resolved the way the manifest says it should.
    docker image inspect "$image" >/dev/null 2>&1 || die "$name: $image is not present after pull"
    ok "image pinned and present: ${image#*@}"

    ensure_network
    if docker ps -q --filter "name=^${cname}$" | grep -q .; then
      info "already running"
    else
      docker rm -f "$cname" >/dev/null 2>&1 || true
      # publish flags come from range_targets.py, the only code that binds an address.
      local pub
      # shellcheck disable=SC2046
      pub=$(rt publish-args "$name")
      # shellcheck disable=SC2086
      docker run -d --name "$cname" --label "$LABEL" --network "$NETWORK" \
        --restart no $pub "$image" >/dev/null || die "$name: docker run failed"
      ok "started as $cname"
    fi
  else
    local script logdir pidfile port
    script="$(rt script "$name")"
    logdir="$RUN_DIR/$name-logs"
    pidfile="$RUN_DIR/$name.pid"
    port="$(rt urls "$name" | awk 'NR==1{print $2}' | sed 's|.*:||')"
    mkdir -p "$logdir" "$RUN_DIR"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      info "already running (pid $(cat "$pidfile"))"
    else
      # vulnapp hard-pins 127.0.0.1 in its own source; the assertions below re-check it anyway,
      # because the range does not take a target's word for where it bound.
      nohup python3 "$script" --port "$port" --logdir "$logdir" \
        >"$RUN_DIR/$name.out" 2>&1 &
      echo $! > "$pidfile"
      ok "started as pid $(cat "$pidfile")"
    fi
  fi

  # Poll the real service. Never sleep-and-hope: a fixed sleep is either too short (a flaky range)
  # or too long (an operator waiting for nothing).
  info "waiting for it to answer"
  rt wait "$name" --any --timeout 240 || {
    [ "$kind" = "container" ] && docker logs --tail 25 "$cname" 2>&1 | sed 's/^/       /' || true
    target_down "$name"
    die "$name: never answered on loopback"
  }

  if [ -n "$(rt seed-name "$name")" ]; then
    info "seeding ($(rt seed-name "$name")) — this target is not a target until its schema exists"
    rt seed "$name" || { target_down "$name"; die "$name: seeding failed"; }
  fi

  rt wait "$name" --timeout 240 || { target_down "$name"; die "$name: never became ready"; }
  ok "ready"

  info "asserting loopback-only exposure"
  rt assert-binding "$name" || { target_down "$name"; die "$name: LOOPBACK ASSERTION FAILED"; }
  ok "loopback-only, confirmed four ways"
}

target_down() {
  local name="$1" kind cname pidfile
  kind="$(rt kind "$name" 2>/dev/null || echo container)"
  if [ "$kind" = "process" ]; then
    pidfile="$RUN_DIR/$name.pid"
    if [ -f "$pidfile" ]; then
      kill "$(cat "$pidfile")" 2>/dev/null || true
      sleep 0.3
      kill -9 "$(cat "$pidfile")" 2>/dev/null || true
      rm -f "$pidfile"
    fi
    rm -rf "$RUN_DIR/$name-logs" "$RUN_DIR/$name.out"
  else
    cname="$(rt container "$name")"
    docker rm -f "$cname" >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------------------

cmd_list() {
  bold "VIGIL range — targets"
  rt check
  printf '\n   %-11s %-7s %s\n' "TARGET" "PORT" "URL"
  local t
  for t in $ALL_TARGETS; do
    rt urls "$t" | while read -r pname purl; do
      printf '   %-11s %-7s %s  (%s)\n' "$t" "${purl##*:}" "$purl" "$pname"
    done
  done
  printf '   %-11s %-7s %s\n' "src" "-" "$SRC_DIR/{vulnerable,clean}"
}

cmd_up() {
  [ $# -gt 0 ] || { usage; die "name at least one target (or 'all')"; }
  mkdir -p "$DOCKER_CONFIG"; [ -f "$DOCKER_CONFIG/config.json" ] || echo '{}' > "$DOCKER_CONFIG/config.json"
  local wanted; wanted="$(expand "$@")"
  local t
  for t in $wanted; do
    if [ "$t" = "src" ]; then src_up; else target_up "$t"; fi
  done
  cmd_status
}

cmd_status() {
  bold "VIGIL range — status"
  printf '   %-11s %-9s %-24s %s\n' "TARGET" "STATE" "LISTENING ON" "DETAIL"
  local t kind state detail
  for t in $ALL_TARGETS; do
    kind="$(rt kind "$t")"
    if [ "$kind" = "container" ]; then
      # `docker inspect` on a missing container still emits a blank line, which would smear the
      # table; take the first non-empty line or nothing. The `|| true` is load-bearing: `status` must
      # describe a PARTLY-started range, which is the normal case (`up juice` starts one target and
      # leaves four down). Without it, `set -o pipefail` turns docker's "no such container" — the
      # expected answer for a target that is simply not running — into a fatal error, and the table
      # stops at the first absent target.
      state="$(docker inspect --format '{{.State.Status}}' "$(rt container "$t")" 2>/dev/null | head -1 || true)"
      [ -n "$state" ] || state="-"
    else
      if [ -f "$RUN_DIR/$t.pid" ] && kill -0 "$(cat "$RUN_DIR/$t.pid")" 2>/dev/null; then
        state="running"
      else
        state="-"
      fi
    fi
    if [ "$state" = "running" ]; then
      # Also `|| true`: a container that is up but not yet ready makes `rt wait` exit 1, and that is
      # a row in the table, not a reason to abandon it.
      detail="$(rt wait "$t" --timeout 5 2>&1 | tr -d '\n' | sed 's/^ *//' || true)"
    else
      detail="not started"
    fi
    printf '   %-11s %-9s %-24s %s\n' "$t" "$state" \
      "$(rt urls "$t" | awk '{printf "%s ", $2}')" "$detail"
  done
  if [ -d "$SRC_DIR/vulnerable" ]; then
    if python3 "$SOURCE_PY" --root "$SRC_DIR" --verify 2>/dev/null; then
      printf '   %-11s %-9s %-24s %s\n' "src" "present" "$SRC_DIR" "content ids match the manifest"
    else
      printf '   %-11s %-9s %-24s %s\n' "src" "DRIFTED" "$SRC_DIR" "content ids DO NOT match — regenerate"
    fi
  else
    printf '   %-11s %-9s %-24s %s\n' "src" "-" "-" "not generated"
  fi
}

cmd_verify() {
  local wanted; [ $# -gt 0 ] && wanted="$(expand "$@")" || wanted="$ALL_TARGETS"
  bold "VIGIL range — is the planted weakness genuinely there?"
  info "Each probe is a differential: the benign request that must NOT produce the signal,"
  info "next to the attack that must. Without the control, a probe proves nothing."
  local t failures=0
  for t in $wanted; do
    [ "$t" = "src" ] && continue
    printf '\n   \033[1m%s\033[0m\n' "$t"
    if ! rt weakness "$t"; then
      failures=$((failures + 1))
    fi
  done
  echo
  [ "$failures" -eq 0 ] || die "$failures target(s) did not demonstrate their planted weakness"
  ok "every probed target demonstrated its planted weakness, and every control stayed silent"
}

cmd_down() {
  bold "VIGIL range — down"
  local t
  if [ $# -eq 0 ]; then
    # Everything, by label rather than by name: a target renamed or removed from the manifest since
    # it was started would otherwise be left running forever, and "down" must leave nothing behind.
    local ids
    ids="$(docker ps -aq --filter "label=$LABEL" 2>/dev/null || true)"
    if [ -n "$ids" ]; then
      # shellcheck disable=SC2086
      docker rm -f $ids >/dev/null 2>&1 || true
      ok "removed $(printf '%s\n' "$ids" | wc -l) container(s) labelled $LABEL"
    else
      ok "no labelled containers to remove"
    fi
    for t in $ALL_TARGETS; do
      [ "$(rt kind "$t")" = "process" ] && target_down "$t"
    done
    docker network rm "$NETWORK" >/dev/null 2>&1 && ok "removed docker network '$NETWORK'" || true
    src_down
    rm -rf "$RUN_DIR" "$RANGE_DIR/dockercfg"
    rmdir "$RANGE_DIR" 2>/dev/null || true
  else
    for t in $(expand "$@"); do
      if [ "$t" = "src" ]; then src_down; else target_down "$t"; ok "$t removed"; fi
    done
  fi

  # Assert it. "down" that leaves something behind is the failure mode that quietly turns a range
  # into a permanently-exposed vulnerable application.
  local leftover=0 ids still
  if [ $# -eq 0 ]; then
    ids="$(docker ps -aq --filter "label=$LABEL" 2>/dev/null || true)"
    if [ -n "$ids" ]; then
      fail "containers still present after down: $ids"; leftover=1
    fi
    for t in $ALL_TARGETS; do
      still="$(rt listening "$t")"
      if [ -n "$still" ]; then
        fail "$t: still listening after down: $(printf '%s ' $still)"; leftover=1
      fi
    done
  fi
  [ "$leftover" -eq 0 ] || die "down did not leave a clean machine"
  ok "nothing left behind"
}

case "${1:-}" in
  up)     shift; cmd_up "$@" ;;
  down)   shift; cmd_down "$@" ;;
  status) cmd_status ;;
  list)   cmd_list ;;
  verify) shift; cmd_verify "$@" ;;
  -h|--help|help|"") usage ;;
  *)      usage; die "unknown command '${1}'" ;;
esac
