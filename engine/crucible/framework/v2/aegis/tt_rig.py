"""aegis.tt_rig — the AEGIS Test-Tenant (TT) CI rig (slice AS-1a).

A loopback acceptance harness that drives the real AEGIS gateway (``aegis.gateway``) in its
default READ-ONLY ``observe`` mode across TWO isolated test tenants and proves the three
properties the TT-CI gate demands:

  * **Observe => the attack event is visible to TT-A.** A small, deterministic attack corpus
    (parse-proof SQLi, a ``../`` traversal, and a seeded-honeypot automated-access fetch) is
    replayed through TT-A's gateway; each fires a CONFIRMED verdict that lands in TT-A's own
    monitoring feed. ``observe`` NEVER blocks — every request still forwards (200), so the rig
    also proves availability-first.
  * **A benign baseline is recorded.** A SAME-SHAPE benign corpus (the same endpoints + params
    as the attacks, with inert values) is replayed first. It forwards cleanly and produces ZERO
    confirmed events — the negative control that the detector fires on the attack, not on its
    shape.
  * **The cross-tenant control TT-B sees nothing.** TT-B receives only the benign baseline and
    never the attack; its monitoring feed stays empty. Each tenant is a wholly separate gateway
    (+ upstream + feed); under ``VIGIL_REQUIRE_TT_UIDS`` each runs in its OWN process under a
    DISTINCT OS uid, so the isolation is a real OS boundary, not just in-process separation.

DOCTRINE. This module is ADDITIVE and off the gate path: nothing under ``aegis/__init__`` or
``framework.v2.__main__`` imports it, so ``make gate`` stays byte-identical. It REUSES the
existing gateway and the existing UI-safe file-verdict sink (``aegis.cli._make_file_verdict_sink``)
rather than re-implementing either. It lives in the ENGINE plane, where the gateway it drives
lives (FATAL-2: it never imports ``sigil``). It is DETERMINISTIC — no wall-clock or global RNG
sits on the acceptance decision (that is a pure function of the feed contents); the only clock is
the telemetry timestamp the reused sink already stamps for UI ordering. Default is ``observe``
(read-only), so the rig itself has no enforcing power.

``VIGIL_REQUIRE_TT_UIDS`` (skip = FAIL). When distinct uids are REQUIRED but cannot be
provisioned (not root, or ``useradd`` unavailable), :func:`run_tt_acceptance` RAISES
:class:`TTUidsUnavailable` — a hard failure, never a silent skip (a skipped proof and a passing
proof are the same colour on a dashboard). When they are not required, the rig runs the same
acceptance in-process (same uid), which is the CI-friendly default leg.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import pwd
import select
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote

from .cli import _make_file_verdict_sink
from .gateway import serve_gateway
from .models import AegisConfig

# The directory that must be on a child process's PYTHONPATH for ``-m framework.v2.aegis.tt_rig``
# to import (engine/crucible). Derived from this file's location: aegis -> v2 -> framework -> crucible.
_ENGINE_ROOT: Path = Path(__file__).resolve().parents[3]

# A seeded honeypot path no human UI links — a fetch of it PROVES automated access (the class-1
# tripwire). Configured into each tenant gateway so the ``automated_access`` oracle can fire.
HONEYPOT_PATHS: tuple[str, ...] = ("/.git/config",)

# A stable, correlatable User-Agent for the rig's own traffic (OPSEC doctrine: be greppable, never
# evade the operator's own logs). Never a browser/crawler string, so the honeypot is not allowlisted.
_RIG_UA: str = "aegis-tt-rig/1 (authorized tenant acceptance)"

_TENANT_A: str = "tt-a"
_TENANT_B: str = "tt-b"

# The username prefix for throwaway distinct-uid tenants. Deterministic (prefix + pid + tenant), so a
# run leaves a predictable, cleanable footprint rather than random account names.
_TT_USER_PREFIX: str = "vigil-tt"


@dataclass(frozen=True)
class Probe:
    """One corpus request. ``expect_class`` is the CONFIRMED attack class the attack probe must
    fire, or ``None`` for a benign probe (which must fire nothing)."""

    name: str
    endpoint: str          # the path (no query), e.g. "/search" — the "shape" an attack/benign pair shares
    param: Optional[str]   # the query parameter the value rides in, or None (honeypot path fetch)
    value: str             # the raw (un-encoded) parameter value, or the path tail for a honeypot fetch
    expect_class: Optional[str]

    @property
    def path(self) -> str:
        """The request path+query, URL-encoded. A honeypot probe (``param is None``) fetches the
        endpoint path directly; a parameter probe appends ``?<param>=<urlencoded value>``."""
        if self.param is None:
            return self.endpoint
        return f"{self.endpoint}?{self.param}={quote(self.value, safe='')}"


# The ATTACK corpus — each entry fires exactly one CONFIRMED class in observe mode (verified in
# aegis/tests). Ordered by class name so the acceptance result is stable.
ATTACK_CORPUS: tuple[Probe, ...] = (
    Probe("automated_access", "/.git/config", None, "", "automated_access"),
    Probe("path_traversal", "/download", "file", "../../../../etc/passwd", "path_traversal_attempt"),
    Probe("sqli", "/search", "q", "' OR '1'='1", "sqli_attempt"),
)

# The SAME-SHAPE benign corpus — the SAME endpoints (and params) as the attacks, with inert values.
# Each must forward cleanly and fire NOTHING: the negative control that proves the detector keys on
# the proven attack, not on the endpoint/param shape.
BENIGN_CORPUS: tuple[Probe, ...] = (
    Probe("automated_access_twin", "/assets/app.css", None, "", None),
    Probe("path_traversal_twin", "/download", "file", "quarterly-report.pdf", None),
    Probe("sqli_twin", "/search", "q", "laptop stand", None),
)


class TTUidsUnavailable(RuntimeError):
    """Raised when distinct tenant uids are REQUIRED (``VIGIL_REQUIRE_TT_UIDS``) but cannot be
    provisioned (not root, or ``useradd`` unavailable). This is a FAILURE, never a skip."""


@dataclass
class TenantUids:
    """An allocation of distinct per-tenant uids, with best-effort cleanup of any accounts the
    allocator itself created."""

    uids: tuple[int, ...]
    created_users: tuple[str, ...] = ()

    def cleanup(self) -> None:
        userdel = shutil.which("userdel")
        for user in self.created_users:
            if userdel is not None:
                subprocess.run([userdel, user], capture_output=True)  # best-effort; never raises


def tt_uids_provisionable() -> bool:
    """True when distinct tenant uids CAN be provisioned here: we are root (so we can create
    accounts and ``setuid`` children into them) and ``useradd`` is on PATH. Used to decide whether
    the real distinct-uid path can run; when uids are REQUIRED and this is False, the rig FAILS."""
    return os.geteuid() == 0 and shutil.which("useradd") is not None


def provision_tenant_uids(n: int) -> TenantUids:
    """Provision ``n`` distinct, non-root uids by creating throwaway ``nologin`` accounts. Raises
    :class:`TTUidsUnavailable` (a FAILURE) when that is impossible — never skips."""
    if os.geteuid() != 0:
        raise TTUidsUnavailable(
            "distinct tenant uids require root (euid != 0); set up the TT-CI runner as root")
    useradd = shutil.which("useradd")
    if useradd is None:
        raise TTUidsUnavailable("useradd not found on PATH; cannot provision distinct tenant uids")
    uids: list[int] = []
    created: list[str] = []
    for i in range(n):
        user = f"{_TT_USER_PREFIX}-{os.getpid()}-{i}"
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            res = subprocess.run(
                [useradd, "-M", "-N", "-s", "/usr/sbin/nologin", user],
                capture_output=True, text=True)
            if res.returncode != 0:
                TenantUids(tuple(uids), tuple(created)).cleanup()
                raise TTUidsUnavailable(
                    f"useradd {user} failed (rc={res.returncode}): {res.stderr.strip()[-200:]}")
            uid = pwd.getpwnam(user).pw_uid
            created.append(user)
        uids.append(uid)
    if len(set(uids)) < n:
        alloc = TenantUids(tuple(uids), tuple(created))
        alloc.cleanup()
        raise TTUidsUnavailable(f"provisioned uids are not distinct: {uids}")
    return TenantUids(tuple(uids), tuple(created))


class _Upstream(http.server.BaseHTTPRequestHandler):
    """A trivial operator-app stand-in: every request answers 200 ``UPSTREAM-OK`` so the rig can
    prove the gateway forwarded (observe never blocks). Inert — it echoes nothing attacker-controlled
    into a sink and does no I/O beyond the fixed body."""

    def log_message(self, *_args: object) -> None:  # quiet
        return

    def _reply(self) -> None:
        body = b"UPSTREAM-OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_HEAD = _reply
    do_POST = _reply


def _port_of(server: socketserver.BaseServer) -> int:
    """The bound TCP port of a loopback server (``server_address`` is a ``(host, port)`` tuple for an
    AF_INET socket); narrowed from the stdlib address union for the type checker."""
    addr = server.server_address
    assert isinstance(addr, tuple), f"expected a (host, port) address, got {addr!r}"
    return int(addr[1])


def _start_upstream() -> http.server.HTTPServer:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _start_gateway(upstream_port: int, feed_path: str,
                   honeypots: tuple[str, ...]) -> socketserver.BaseServer:
    """Start one tenant gateway in READ-ONLY ``observe`` mode, fronting ``upstream_port``, streaming
    each verdict (UI-safe JSON-lines, via the reused sink) into ``feed_path`` — the tenant's
    monitoring feed."""
    config = AegisConfig(deployment_secret="k", mode="observe", honeypot_paths=list(honeypots))
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=config,
                       host="127.0.0.1", port=0, on_verdict=_make_file_verdict_sink(feed_path))
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw


class _Tenant:
    """A running test tenant: an upstream + a gateway + a monitoring feed, reachable at
    ``gateway_port``. ``uid`` is the OS uid the gateway runs under (None = in-process, same uid)."""

    def __init__(self, name: str, gateway_port: int, feed_path: str, uid: Optional[int],
                 closer: Callable[[], None]) -> None:
        self.name = name
        self.gateway_port = gateway_port
        self.feed_path = feed_path
        self.uid = uid
        self._closer = closer

    def close(self) -> None:
        self._closer()


def _start_in_process_tenant(name: str, tenant_root: Path,
                             honeypots: tuple[str, ...]) -> _Tenant:
    feed = tenant_root / "monitoring" / "feed.jsonl"
    feed.parent.mkdir(parents=True, exist_ok=True)
    upstream = _start_upstream()
    up_port = _port_of(upstream)
    gw = _start_gateway(up_port, str(feed), honeypots)
    gw_port = _port_of(gw)

    def _close() -> None:
        gw.shutdown()
        gw.server_close()
        upstream.shutdown()
        upstream.server_close()

    return _Tenant(name, gw_port, str(feed), None, _close)


def _grant_traverse(leaf: Path) -> None:
    """Add others-SEARCH (``o+x``, not read) on ``leaf`` and every ancestor, so a dropped-privilege
    tenant process can traverse to its own dir even when the (test) root lives under a root-owned
    0700 temp tree. We are root; only the search bit is added, and only where missing — the dirs stay
    unlistable. Idempotent, best-effort."""
    resolved = leaf.resolve()
    for anc in [resolved, *resolved.parents]:
        try:
            mode = anc.stat().st_mode
            if not mode & 0o001:
                os.chmod(anc, mode | 0o001)
        except OSError:
            continue


def _chown_tree(root: Path, uid: int, gid: int) -> None:
    """Recursively hand ``root`` and everything under it to ``(uid, gid)``. Best-effort per entry."""
    try:
        os.chown(root, uid, gid)
    except OSError:
        pass
    for dirpath, dirnames, filenames in os.walk(root):
        for entry in dirnames + filenames:
            try:
                os.chown(os.path.join(dirpath, entry), uid, gid)
            except OSError:
                pass


def _start_subprocess_tenant(name: str, tenant_root: Path, honeypots: tuple[str, ...],
                             uid: int) -> _Tenant:
    """Start a tenant whose upstream + gateway run in a SEPARATE process under a DISTINCT uid. The
    tenant subtree is handed to ``uid`` (0700) so the dropped-privilege child owns its monitoring
    feed AND a private CRUCIBLE_ROOT for the framework's ambient log; the (root) parent can still
    read the feed. Isolation is a real OS boundary — another tenant's uid cannot enter the dir."""
    gid = pwd.getpwuid(uid).pw_gid
    feed = tenant_root / "monitoring" / "feed.jsonl"
    feed.parent.mkdir(parents=True, exist_ok=True)
    # A per-tenant CRUCIBLE_ROOT (with the CLAUDE.md sentinel) so the child's ambient framework log
    # (``<root>/framework/v2/.crucible-v2.log``) lands somewhere the dropped uid owns, not the
    # read-only package tree.
    croot = tenant_root / "croot"
    (croot / "framework" / "v2").mkdir(parents=True, exist_ok=True)
    (croot / "CLAUDE.md").write_text("AEGIS TT-rig per-tenant sandbox root.\n", encoding="utf-8")
    # Let the dropped-privilege child traverse the ancestors of its own dir (search only), then hand
    # the whole tenant subtree to the tenant uid (0700) so another tenant's uid cannot read it.
    _grant_traverse(tenant_root.parent)
    _chown_tree(tenant_root, uid, gid)
    os.chmod(tenant_root, 0o700)

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_ENGINE_ROOT), *( [env["PYTHONPATH"]] if env.get("PYTHONPATH") else [] )])
    env["CRUCIBLE_ROOT"] = str(croot)
    argv = [sys.executable, "-m", "framework.v2.aegis.tt_rig", "_serve-tenant",
            "--feed", str(feed), "--uid", str(uid), "--gid", str(gid)]
    for hp in honeypots:
        argv += ["--honeypot", hp]
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)

    gw_port = _await_ready(proc)

    def _close() -> None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)

    return _Tenant(name, gw_port, str(feed), uid, _close)


def _await_ready(proc: "subprocess.Popen[str]", timeout: float = 20.0) -> int:
    """Read the child's single ``READY <port>`` line (or an ``ERR …`` line) from stdout, bounded by
    ``timeout``. Returns the gateway port, or raises on error/timeout (tearing the child down)."""
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout
    line = ""
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        ready, _, _ = select.select([proc.stdout], [], [], max(0.0, remaining))
        if ready:
            line = proc.stdout.readline().strip()
            break
    if line.startswith("READY "):
        return int(line.split(" ", 1)[1])
    proc.terminate()
    try:
        err = proc.stderr.read() if proc.stderr is not None else ""
    except Exception:  # noqa: BLE001 — best-effort diagnostics only
        err = ""
    raise TTUidsUnavailable(
        f"tenant child failed to come up (got {line!r}); stderr: {err.strip()[-400:]}")


def _probe(gateway_port: int, probe: Probe) -> tuple[int, bool]:
    """Send one probe through a tenant gateway. Returns ``(status, forwarded)`` where ``forwarded``
    is whether the upstream's ``UPSTREAM-OK`` body came back (observe must always forward)."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{gateway_port}{probe.path}", headers={"User-Agent": _RIG_UA})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        body = resp.read()
        return int(resp.status), (b"UPSTREAM-OK" in body)
    except urllib.error.HTTPError as exc:
        return int(exc.code), False


def _read_feed(feed_path: str) -> list[dict[str, object]]:
    path = Path(feed_path)
    if not path.exists():
        return []
    out: list[dict[str, object]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _confirmed(feed: list[dict[str, object]]) -> list[dict[str, object]]:
    return [r for r in feed if r.get("decision") == "confirmed"]


def _event_summary(feed: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{"attack_class": r.get("attack_class"), "decision": r.get("decision"),
             "action": r.get("action")} for r in _confirmed(feed)]


def _peer_isolation_child(w: int, peer_feed: str, peer_root: str, uid: int, gid: int,
                          user: str) -> int:
    """(forked child, root-only) Drop to the CONTROL tenant's identity — the SAME hardened drop
    :func:`_serve_tenant` performs (``setgid`` → ``setgroups([])`` → ``setuid``) — then ATTEMPT to
    read the ATTACK tenant's feed and list its ``0700`` root, reporting the outcome as one JSON line
    on ``w``. It also seeds the identity's real group set with ``initgroups`` BEFORE the hardening
    ``setgroups([])``, so the report proves that call actually SHEDS the shared ``users`` gid
    ``useradd -N`` hands every tenant (``residual_groups`` must come back empty). Never returns to the
    caller's flow — the parent ``os._exit``s on its return value."""
    report: dict[str, object] = {}
    try:
        os.setgid(gid)
        try:
            # Adopt the tenant's real login groups (on this provisioning: the shared `users` gid) so
            # the hardening setgroups([]) below has something real to drop — otherwise, with a root
            # parent that carries no supplementary groups, the call would be a silent no-op and could
            # not be shown to matter.
            os.initgroups(user, gid)
        except OSError:
            pass
        os.setgroups([])            # HARDENING: shed every supplementary group (incl. the shared gid).
        os.setuid(uid)
    except OSError as exc:          # fail-closed: a failed drop is reported, never silently "denied".
        report["drop_error"] = f"{type(exc).__name__}: {exc}"
        os.write(w, json.dumps(report).encode("utf-8"))
        return 0
    report["dropped_uid"] = os.getuid()
    report["residual_groups"] = sorted(os.getgroups())
    try:
        with open(peer_feed, "rb") as fh:
            fh.read(1)
        report["feed_open"] = "read"            # the OS let the dropped uid read the peer feed — BAD.
    except PermissionError:
        report["feed_open"] = "denied"          # EACCES — the 0700 boundary held.
    except FileNotFoundError:
        report["feed_open"] = "missing"         # the peer feed is gone — NOT a proof of denial.
    except OSError as exc:
        report["feed_open"] = f"error:{exc.errno}"
    try:
        os.listdir(peer_root)
        report["root_list"] = "listed"          # the dropped uid enumerated the peer root — BAD.
    except PermissionError:
        report["root_list"] = "denied"
    except OSError as exc:
        report["root_list"] = f"error:{exc.errno}"
    os.write(w, json.dumps(report).encode("utf-8"))
    return 0


def _probe_peer_feed_isolation(peer_feed: str, peer_root: str, probe_uid: int) -> dict[str, object]:
    """Root-only OS-boundary probe (the positive assertion the distinct-uid acceptance was missing).

    Fork a child, drop it to the CONTROL tenant's distinct uid/gid, and have it ATTEMPT to read the
    ATTACK tenant's ``0700`` feed and list its root. The cross-tenant OS boundary HOLDS iff BOTH
    accesses are DENIED (``EACCES``) **and** the dropped identity retains NO supplementary group (so
    the shared ``users`` gid ``useradd -N`` gives both tenants is shed by ``setgroups([])``, not
    carried across). A weakened boundary — ``tenant_root`` ``0700`` → ``0755``, or a dropped
    ``setgroups([])`` — flips one of those to a non-pass, so the acceptance can no longer ship GREEN.

    Additive and read-only: it has no enforcing power and only reads the peer's own tree. The caller
    reaches it ONLY on the distinct-uid (root) path, so non-root CI never forks here. Fail-closed:
    any drop error, a missing peer feed, or a silent child is NOT a pass.
    """
    probe_gid = int(pwd.getpwuid(probe_uid).pw_gid)
    probe_user = pwd.getpwuid(probe_uid).pw_name
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover — the child is a separate process, invisible to the parent's coverage
        try:
            os.close(r)
            rc = _peer_isolation_child(w, peer_feed, peer_root, probe_uid, probe_gid, probe_user)
        except BaseException:  # noqa: BLE001 — a child must NEVER unwind into the parent's flow
            rc = 1
        finally:
            try:
                os.close(w)
            except OSError:
                pass
        os._exit(rc)
    os.close(w)
    chunks: list[bytes] = []
    while True:
        buf = os.read(r, 65536)
        if not buf:
            break
        chunks.append(buf)
    os.close(r)
    os.waitpid(pid, 0)
    try:
        child = json.loads(b"".join(chunks).decode("utf-8") or "{}")
    except ValueError:
        child = {}
    if not isinstance(child, dict):
        child = {}
    feed_open = child.get("feed_open", "error:no-report")
    root_list = child.get("root_list", "error:no-report")
    # Sentinel: a non-empty list when the child never reported, so a silent child is NOT a group-clean pass.
    residual_groups = child.get("residual_groups", [-1])
    drop_error = child.get("drop_error")
    denied = feed_open == "denied" and root_list == "denied"
    no_group_leak = residual_groups == []
    return {
        "attempted": True,
        "peer_feed": peer_feed,
        "peer_root": peer_root,
        "probe_uid": probe_uid,
        "probe_gid": probe_gid,
        "feed_open": feed_open,
        "root_list": root_list,
        "residual_groups": residual_groups,
        "dropped_uid": child.get("dropped_uid"),
        "drop_error": drop_error,
        "denied": denied,
        "no_supplementary_group_leak": no_group_leak,
        "ok": bool(denied and no_group_leak and drop_error is None),
    }


@dataclass
class _BaselineRecord:
    probes: int = 0
    events_after_baseline: int = 0
    all_forwarded_200: bool = True
    detail: list[dict[str, object]] = field(default_factory=list)


def run_tt_acceptance(root: "str | Path", *, require_distinct_uids: bool,
                      uid_allocator: Optional[Callable[[int], TenantUids]] = None) -> dict[str, object]:
    """Run the TT-CI Observe acceptance end to end and return a JSON-native result with a top-level
    ``ok``. Two isolated tenants (TT-A under attack, TT-B the cross-tenant control) are driven over
    real loopback; the result records, for each check, whether it held.

    When ``require_distinct_uids`` is True the two gateways run in separate processes under distinct
    uids (via ``uid_allocator`` / :func:`provision_tenant_uids`); if those uids cannot be obtained
    this RAISES :class:`TTUidsUnavailable` — a failure, not a skip. When False, the tenants run
    in-process (same uid) — the default CI leg.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    mode = "distinct-uids" if require_distinct_uids else "in-process"

    alloc: Optional[TenantUids] = None
    if require_distinct_uids:
        allocator = uid_allocator if uid_allocator is not None else provision_tenant_uids
        alloc = allocator(2)  # raises TTUidsUnavailable when impossible — FAIL, never skip

    tenants: dict[str, _Tenant] = {}
    try:
        for i, name in enumerate((_TENANT_A, _TENANT_B)):
            tdir = root / name
            tdir.mkdir(parents=True, exist_ok=True)
            if alloc is not None:
                tenants[name] = _start_subprocess_tenant(name, tdir, HONEYPOT_PATHS, alloc.uids[i])
            else:
                tenants[name] = _start_in_process_tenant(name, tdir, HONEYPOT_PATHS)

        # (1) BASELINE — replay the same-shape benign corpus through BOTH tenants. It must forward
        #     cleanly and fire nothing: the negative control + the recorded benign baseline.
        baselines: dict[str, _BaselineRecord] = {}
        for name, tenant in tenants.items():
            rec = _BaselineRecord(probes=len(BENIGN_CORPUS))
            for probe in BENIGN_CORPUS:
                status, forwarded = _probe(tenant.gateway_port, probe)
                rec.detail.append({"name": probe.name, "status": status, "forwarded": forwarded})
                if not (status == 200 and forwarded):
                    rec.all_forwarded_200 = False
            rec.events_after_baseline = len(_confirmed(_read_feed(tenant.feed_path)))
            baselines[name] = rec

        # (2) ATTACK — replay the attack corpus through TT-A ONLY. Observe forwards every one (200).
        attack_detail: list[dict[str, object]] = []
        observe_never_blocked = True
        for probe in ATTACK_CORPUS:
            status, forwarded = _probe(tenants[_TENANT_A].gateway_port, probe)
            attack_detail.append({"name": probe.name, "status": status, "forwarded": forwarded,
                                  "expect_class": probe.expect_class})
            if not (status == 200 and forwarded):
                observe_never_blocked = False

        # (3) READ the per-tenant monitoring feeds and evaluate the three properties.
        feed_a = _read_feed(tenants[_TENANT_A].feed_path)
        feed_b = _read_feed(tenants[_TENANT_B].feed_path)
        events_a = _event_summary(feed_a)
        events_b = _event_summary(feed_b)
        seen_classes_a = {e["attack_class"] for e in events_a}
        expected_classes = sorted({p.expect_class for p in ATTACK_CORPUS if p.expect_class})

        attack_visible = set(expected_classes) <= seen_classes_a
        baseline_recorded = (baselines[_TENANT_A].events_after_baseline == 0
                             and all(b.all_forwarded_200 for b in baselines.values()))
        control_sees_nothing = len(events_b) == 0

        checks: dict[str, bool] = {
            "attack_event_visible_to_attack_tenant": attack_visible,
            "benign_baseline_recorded": baseline_recorded,
            "cross_tenant_control_sees_nothing": control_sees_nothing,
            "observe_never_blocked": observe_never_blocked,
        }

        # (3a) THE OS-BOUNDARY ASSERTION (distinct-uid mode only). The checks above are all computed by
        #      the ROOT parent via _read_feed, which bypasses mode bits — so an empty TT-B feed proves
        #      only that TT-B got no attack traffic, NOT that the OS would DENY TT-B's uid a read of
        #      TT-A's 0700 feed. Here we assert that boundary POSITIVELY: fork a child, drop it to
        #      TT-B's distinct identity, and require that reading TT-A's feed / listing its root is
        #      DENIED (EACCES) and that the hardened drop shed every supplementary group. Root-gated:
        #      alloc is not None only on the provisioned (root) distinct-uid path.
        peer_isolation: Optional[dict[str, object]] = None
        if alloc is not None:
            probe_uid = tenants[_TENANT_B].uid
            assert probe_uid is not None, "distinct-uid control tenant must carry an int uid"
            peer_isolation = _probe_peer_feed_isolation(
                peer_feed=tenants[_TENANT_A].feed_path,
                peer_root=str(root / _TENANT_A),
                probe_uid=probe_uid,
            )
            checks["cross_tenant_uid_cannot_read_peer_feed"] = bool(peer_isolation["ok"])

        result: dict[str, object] = {
            "ok": all(checks.values()),
            "mode": mode,
            "attack_tenant": _TENANT_A,
            "control_tenant": _TENANT_B,
            "expected_attack_classes": expected_classes,
            "checks": checks,
            "cross_tenant_fs_probe": peer_isolation,
            "tenants": {
                _TENANT_A: {
                    "uid": tenants[_TENANT_A].uid,
                    "gateway_port": tenants[_TENANT_A].gateway_port,
                    "feed": tenants[_TENANT_A].feed_path,
                    "attack_events": events_a,
                    "attack_detail": attack_detail,
                    "baseline": {
                        "benign_probes": baselines[_TENANT_A].probes,
                        "events_after_baseline": baselines[_TENANT_A].events_after_baseline,
                        "all_forwarded_200": baselines[_TENANT_A].all_forwarded_200,
                    },
                },
                _TENANT_B: {
                    "uid": tenants[_TENANT_B].uid,
                    "gateway_port": tenants[_TENANT_B].gateway_port,
                    "feed": tenants[_TENANT_B].feed_path,
                    "attack_events": events_b,
                    "baseline": {
                        "benign_probes": baselines[_TENANT_B].probes,
                        "events_after_baseline": baselines[_TENANT_B].events_after_baseline,
                        "all_forwarded_200": baselines[_TENANT_B].all_forwarded_200,
                    },
                },
            },
        }
        return result
    finally:
        for tenant in tenants.values():
            try:
                tenant.close()
            except Exception:  # noqa: BLE001 — teardown must not mask the acceptance result
                pass
        if alloc is not None:
            alloc.cleanup()


# --------------------------------------------------------------------------- distinct-uid child entry
def _serve_tenant(args: argparse.Namespace) -> int:
    """The per-tenant child entry (``python3 -m framework.v2.aegis.tt_rig _serve-tenant``). It drops
    to the tenant uid (fail-closed if it cannot), starts the upstream + observe gateway, prints
    ``READY <port>`` once listening, then serves until terminated. Any failure prints ``ERR …`` and
    exits non-zero so the parent FAILS rather than hangs."""
    if args.uid is not None:
        if os.geteuid() != 0:
            sys.stdout.write("ERR not-root: cannot drop to tenant uid\n")
            sys.stdout.flush()
            return 2
        try:
            os.setgid(int(args.gid))
            os.setgroups([])
            os.setuid(int(args.uid))
        except OSError as exc:
            sys.stdout.write(f"ERR setuid: {exc}\n")
            sys.stdout.flush()
            return 2
        if os.getuid() != int(args.uid):
            sys.stdout.write("ERR setuid: uid did not change\n")
            sys.stdout.flush()
            return 2
    try:
        upstream = _start_upstream()
        up_port = _port_of(upstream)
        gw = _start_gateway(up_port, args.feed, tuple(args.honeypot or ()))
        gw_port = _port_of(gw)
    except Exception as exc:  # noqa: BLE001 — report, never crash silently
        sys.stdout.write(f"ERR serve: {type(exc).__name__}: {exc}\n")
        sys.stdout.flush()
        return 2
    sys.stdout.write(f"READY {gw_port}\n")
    sys.stdout.flush()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:  # pragma: no cover — SIGTERM path is the normal teardown
        pass
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m framework.v2.aegis.tt_rig")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("_serve-tenant", help="(internal) serve one isolated tenant gateway")
    s.add_argument("--feed", required=True, help="path to this tenant's monitoring feed (JSON-lines)")
    s.add_argument("--uid", type=int, default=None, help="drop to this uid before serving")
    s.add_argument("--gid", type=int, default=None, help="drop to this gid before serving")
    s.add_argument("--honeypot", action="append", default=[], help="a seeded honeypot path (repeatable)")
    s.set_defaults(func=_serve_tenant)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover — exercised via subprocess in the distinct-uid path
    raise SystemExit(main())
