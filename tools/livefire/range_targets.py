#!/usr/bin/env python3
"""The VIGIL loopback range: target facts, loopback enforcement, readiness, seeding, and the
proof that each target's planted weakness is genuinely there.

WHY THIS EXISTS. The engine is gaining typed argv builders so it can drive its whole toolset. A
builder that produces a plausible-looking command line proves nothing: the tool has to actually run,
actually find the planted weakness, and its output has to actually parse into observations. That
needs targets with a known answer, and it needs them to be the SAME targets the Python harness
believes in. So this module and ``range.sh`` both read one file — ``range_targets.json`` — and
neither of them hardcodes a port, an image or a probe.

THE LOOPBACK RULE IS ENFORCED HERE, NOT OBSERVED HERE. The charter's hard limit is that every tool
resolves to 127.0.0.0/8. A range that merely *remembers* to type ``-p 127.0.0.1:...`` is one typo
from publishing a deliberately-vulnerable application to the local network. Instead:

  1. The manifest cannot express a host address. Ports are integers, and :func:`publish_args` is the
     only code that turns one into a docker flag — with ``127.0.0.1`` written into the format string.
  2. After start, :func:`assert_loopback_binding` re-reads the binding from DOCKER'S own view of the
     running container and fails unless every published HostIp is exactly ``127.0.0.1``.
  3. It then re-reads the HOST'S listening sockets from ``/proc/net/tcp`` and fails if anything
     non-loopback is listening on the port, whoever put it there.
  4. Finally it does the thing that actually settles the question: it TRIES TO CONNECT from the
     host's own routable address and requires the connection to be REFUSED. A binding you have only
     read about is a claim; a connection that is refused is a measurement.

Any of those four failing tears the target down rather than leaving it up.

WHAT THE WEAKNESS PROBES ARE FOR. Before a tool driver can be blamed for finding nothing, the range
has to show there was something to find. Each probe is a DIFFERENTIAL and carries its own negative
control: a benign request that must NOT produce the signal, next to the attack that must. "The
response contained the word error" is not evidence; "the benign request returned 46 rows and the
injected one returned those same 46 plus 10 the application deliberately hides" is.

Stdlib only, so the range never becomes a dependency of the thing it is testing.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MANIFEST = HERE / "range_targets.json"

#: The only host address this range will ever bind. Written once, used everywhere.
LOOPBACK = "127.0.0.1"

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
USER_AGENT = "VIGIL-RANGE/1.0 (authorized loopback range harness)"


# ======================================================================================
# The manifest
# ======================================================================================


@dataclass(frozen=True)
class Port:
    name: str
    host: int
    container: int


@dataclass(frozen=True)
class Target:
    name: str
    kind: str
    title: str
    ports: tuple[Port, ...]
    ready: dict
    seed: str | None
    weakness_probe: str | None
    weakness_probe_note: str
    credentials: dict | None
    notes: str
    image: str | None = None
    script: str | None = None

    @property
    def http_port(self) -> int:
        """The port the readiness probe talks to."""
        want = self.ready.get("port", "http")
        for p in self.ports:
            if p.name == want:
                return p.host
        raise KeyError(f"{self.name}: ready.port {want!r} names no port in the manifest")

    def url(self, path: str = "/", port_name: str | None = None) -> str:
        port = self.http_port
        if port_name:
            port = next(p.host for p in self.ports if p.name == port_name)
        return f"http://{LOOPBACK}:{port}{path}"


class Manifest:
    """``range_targets.json``, loaded and validated.

    Validation runs at load time rather than on demand: a manifest that has drifted into an
    unsafe or contradictory state should stop the range from starting, not surface later as a
    confusing docker error.
    """

    def __init__(self, path: Path = MANIFEST) -> None:
        raw = json.loads(path.read_text(encoding="utf-8"))
        self.path = path
        self.raw = raw
        self.container_prefix: str = raw["container_prefix"]
        self.container_label: str = raw["container_label"]
        self.network: str = raw["network"]
        self.source_range: dict = raw["source_range"]
        self.targets: dict[str, Target] = {}
        for name, t in raw["targets"].items():
            self.targets[name] = Target(
                name=name,
                kind=t["kind"],
                title=t["title"],
                image=t.get("image"),
                script=t.get("script"),
                ports=tuple(
                    Port(p["name"], p["host"], p["container"]) for p in t["ports"]
                ),
                ready=t["ready"],
                seed=t.get("seed"),
                weakness_probe=t.get("weakness_probe"),
                weakness_probe_note=t.get("weakness_probe_note", ""),
                credentials=t.get("credentials"),
                notes=t.get("notes", ""),
            )
        self.validate()

    # -- validation ---------------------------------------------------------------------
    def validate(self) -> None:
        problems: list[str] = []
        seen_ports: dict[int, str] = {}

        if self.raw.get("loopback_host") != LOOPBACK:
            problems.append(
                f"loopback_host is {self.raw.get('loopback_host')!r}; this range only binds {LOOPBACK}"
            )

        for name, t in self.targets.items():
            if t.kind not in ("container", "process"):
                problems.append(f"{name}: unknown kind {t.kind!r}")
            if t.kind == "container":
                if not t.image:
                    problems.append(f"{name}: a container target with no image")
                elif not DIGEST_RE.search(t.image):
                    # A tag is a mutable pointer. An unpinned range target can be retagged
                    # underneath the proofs, and every result it produced becomes unreproducible
                    # with no diff and no signal. Refuse to start rather than accept that.
                    problems.append(
                        f"{name}: image is not digest-pinned: {t.image}\n"
                        f"        pin it as repo:tag@sha256:<64 hex> — resolve with\n"
                        f"        docker inspect --format '{{{{index .RepoDigests 0}}}}' {t.image}"
                    )
            if t.kind == "process" and not t.script:
                problems.append(f"{name}: a process target with no script")

            if not t.ports:
                problems.append(f"{name}: no ports")
            for p in t.ports:
                # Ports must be plain integers. This is what makes a host address unrepresentable
                # in the manifest: there is nowhere to write one.
                if not isinstance(p.host, int) or not isinstance(p.container, int):
                    problems.append(f"{name}:{p.name}: ports must be integers")
                    continue
                if not (1024 <= p.host <= 65535):
                    problems.append(f"{name}:{p.name}: host port {p.host} out of range")
                if p.host in seen_ports and seen_ports[p.host] != name:
                    problems.append(
                        f"{name}:{p.name}: host port {p.host} already claimed by {seen_ports[p.host]}"
                    )
                seen_ports[p.host] = name

            try:
                t.http_port
            except KeyError as exc:
                problems.append(str(exc))

            if t.weakness_probe is None and not t.weakness_probe_note:
                # Silence about an unproven target is how a range starts overclaiming. If a target
                # has no weakness probe, the manifest has to say why in as many words.
                problems.append(
                    f"{name}: no weakness_probe and no weakness_probe_note explaining why"
                )
            if t.weakness_probe and t.weakness_probe not in WEAKNESS_PROBES:
                problems.append(f"{name}: weakness_probe {t.weakness_probe!r} is not implemented")
            if t.seed and t.seed not in SEEDS:
                problems.append(f"{name}: seed {t.seed!r} is not implemented")

        if problems:
            raise SystemExit(
                "range_targets.json is not usable:\n  - " + "\n  - ".join(problems)
            )

    def get(self, name: str) -> Target:
        if name not in self.targets:
            raise SystemExit(
                f"unknown target {name!r}. Known: {' '.join(sorted(self.targets))}"
            )
        return self.targets[name]

    def container_name(self, name: str) -> str:
        return f"{self.container_prefix}{name}"


# ======================================================================================
# Loopback enforcement
# ======================================================================================


def publish_args(target: Target) -> list[str]:
    """The docker publish flags for a target — the ONLY place a port becomes a bound address.

    ``127.0.0.1`` is written into the format string here, so there is no code path in the range
    that can produce a docker flag binding anything else, and no manifest value that can influence
    it. Getting this wrong would require editing this line.
    """
    args: list[str] = []
    for p in target.ports:
        args += ["-p", f"{LOOPBACK}:{p.host}:{p.container}"]
    return args


def _listening_on(port: int) -> list[str]:
    """Every local address currently LISTENing on ``port``, from ``/proc/net/tcp{,6}``.

    Read from procfs rather than shelled out to ``ss``/``netstat``, which are not always installed
    and whose output format varies. State ``0A`` is TCP_LISTEN.
    """
    found: list[str] = []
    for proc, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            lines = Path(proc).read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 4 or f[3] != "0A":
                continue
            addr_hex, port_hex = f[1].rsplit(":", 1)
            if int(port_hex, 16) != port:
                continue
            if v6:
                # 4 little-endian 32-bit words, each byte-reversed.
                words = [addr_hex[i : i + 8] for i in range(0, 32, 8)]
                packed = b"".join(bytes.fromhex(w)[::-1] for w in words)
                found.append(socket.inet_ntop(socket.AF_INET6, packed))
            else:
                found.append(socket.inet_ntop(socket.AF_INET, bytes.fromhex(addr_hex)[::-1]))
    return found


def _is_loopback(addr: str) -> bool:
    if addr in ("127.0.0.1", "::1"):
        return True
    if addr.startswith("127."):
        return True
    # ::ffff:127.0.0.1 — a v4-mapped loopback socket is still loopback.
    if addr.startswith("::ffff:") and addr[7:].startswith("127."):
        return True
    return False


def _routable_host_address() -> str | None:
    """This host's own routable IPv4, or None if it has none.

    Learned by opening an unconnected UDP socket toward TEST-NET-1 (192.0.2.0/24, reserved for
    documentation and routed nowhere) and reading back the source address the kernel picked. No
    packet is sent, and nothing outside this machine is contacted.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        addr = s.getsockname()[0]
        return None if _is_loopback(addr) else addr
    except OSError:
        return None
    finally:
        s.close()


def _refuses_connection(addr: str, port: int, timeout: float = 2.0) -> bool:
    """True if a TCP connection to ``addr:port`` does NOT establish."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((addr, port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def docker_port_bindings(container: str) -> dict:
    out = subprocess.run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", container],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return json.loads(out or "{}") or {}


def assert_loopback_binding(target: Target, container: str | None) -> list[str]:
    """Four independent checks that this target is reachable only over loopback.

    Returns the lines of evidence. Raises SystemExit on the first failure — the caller is expected
    to tear the target down, because a deliberately-vulnerable application published beyond
    loopback is the one outcome this range must never produce.
    """
    evidence: list[str] = []
    ports = [p.host for p in target.ports]

    # (1) Docker's own view of what it bound.
    if container:
        bindings = docker_port_bindings(container)
        published = 0
        for spec, binds in bindings.items():
            for b in binds or []:
                published += 1
                host_ip = b.get("HostIp", "")
                if host_ip != LOOPBACK:
                    raise SystemExit(
                        f"LOOPBACK VIOLATION: {container} publishes {spec} on HostIp "
                        f"{host_ip!r}, not {LOOPBACK}"
                    )
                if int(b.get("HostPort", 0)) not in ports:
                    raise SystemExit(
                        f"LOOPBACK VIOLATION: {container} publishes an unexpected host port "
                        f"{b.get('HostPort')} (manifest declares {ports})"
                    )
        if published != len(ports):
            raise SystemExit(
                f"LOOPBACK VIOLATION: {container} publishes {published} binding(s); "
                f"the manifest declares {len(ports)}"
            )
        evidence.append(f"docker: {published}/{len(ports)} binding(s), all HostIp={LOOPBACK}")

    # (2) The host's own listening sockets, whoever created them.
    for port in ports:
        addrs = _listening_on(port)
        bad = [a for a in addrs if not _is_loopback(a)]
        if bad:
            raise SystemExit(
                f"LOOPBACK VIOLATION: port {port} has non-loopback listener(s): {', '.join(bad)}"
            )
    evidence.append(f"host sockets: no non-loopback listener on {ports}")

    # (3) The measurement, not the claim: connect from this host's routable address and require a
    #     refusal. A binding you have only read about is a claim.
    routable = _routable_host_address()
    if routable is None:
        evidence.append("off-loopback reachability: SKIPPED — this host has no routable IPv4")
    else:
        for port in ports:
            if not _refuses_connection(routable, port):
                raise SystemExit(
                    f"LOOPBACK VIOLATION: {routable}:{port} accepted a connection — this target is "
                    f"reachable off loopback"
                )
        evidence.append(f"off-loopback reachability: {routable}:{ports} refused, as required")

    # (4) And it must actually be reachable ON loopback, or the checks above are vacuous.
    reachable = [p for p in ports if not _refuses_connection(LOOPBACK, p, timeout=3.0)]
    if not reachable:
        raise SystemExit(
            f"{target.name}: nothing is accepting on {LOOPBACK}:{ports} — the loopback checks above "
            f"would pass for a target that simply is not running"
        )
    evidence.append(f"loopback reachability: {LOOPBACK}:{reachable} accepted")
    return evidence


# ======================================================================================
# HTTP
# ======================================================================================


class Http:
    """A cookie-keeping HTTP client for probes and seeds. Loopback only, by construction."""

    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def set_cookie(self, name: str, value: str, host: str = LOOPBACK, path: str = "/") -> None:
        """Add a cookie to the JAR.

        Use this instead of passing a ``Cookie:`` header. ``http.cookiejar`` only attaches the jar's
        cookies when the request does not already carry a ``Cookie`` header, so setting one by hand
        silently DROPS the session cookie — and, worse, the resulting bounce to a login page hands
        back a fresh unauthenticated session that poisons the jar for every later request. That fault
        is invisible in the output: the probe still returns a page, just an unauthenticated one, and
        a differential where both sides are logged out looks exactly like "no weakness here".
        """
        self.jar.set_cookie(
            http.cookiejar.Cookie(
                version=0, name=name, value=value, port=None, port_specified=False,
                domain=host, domain_specified=False, domain_initial_dot=False,
                path=path, path_specified=True, secure=False, expires=None,
                discard=True, comment=None, comment_url=None, rest={}, rfc2109=False,
            )
        )

    def get(self, url: str, timeout: float = 15.0, headers: dict | None = None):
        return self._open(url, None, timeout, headers)

    def post(self, url: str, data: dict, timeout: float = 60.0, headers: dict | None = None):
        return self._open(url, urllib.parse.urlencode(data).encode(), timeout, headers)

    def _open(self, url: str, body, timeout: float, headers: dict | None):
        host = urllib.parse.urlsplit(url).hostname or ""
        if not _is_loopback(host):
            # Belt and braces: nothing in this file builds a non-loopback URL, and if a future edit
            # ever does, it fails here rather than sending the packet.
            raise SystemExit(f"refusing to request a non-loopback URL: {url}")
        req = urllib.request.Request(url, data=body)
        req.add_header("User-Agent", USER_AGENT)
        for k, v in (headers or {}).items():
            if k.lower() == "cookie":
                # Refused rather than documented: a hand-set Cookie header suppresses the jar, which
                # silently logs the client out mid-probe and turns a real weakness into a clean bill
                # of health. See Http.set_cookie.
                raise SystemExit(
                    "refusing a hand-set Cookie header: it suppresses the cookie jar and drops the "
                    "session. Use Http.set_cookie() so the jar sends both."
                )
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace"), resp.url
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace"), url


def wait_http(target: Target, timeout: float, ready: bool) -> tuple[bool, str]:
    """Poll the target until it answers. Never sleeps a fixed interval and hopes.

    ``ready=False`` waits for ANY HTTP response (the port is open and something is speaking HTTP),
    which is the state a seed needs. ``ready=True`` additionally requires the manifest's status and
    body marker.
    """
    http_client = Http()
    url = target.url(target.ready["path"] if ready else "/")
    want_status = target.ready.get("status", 200)
    marker = target.ready.get("marker", "")
    deadline = time.monotonic() + timeout
    last = "no response"
    while time.monotonic() < deadline:
        try:
            status, body, _ = http_client.get(url, timeout=5.0)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if not ready:
                return True, f"HTTP {status}"
            if status == want_status and marker in body:
                return True, f"HTTP {status}, marker {marker!r} present"
            last = f"HTTP {status}" + ("" if status != want_status else f", marker {marker!r} absent")
        time.sleep(0.5)
    return False, last


# ======================================================================================
# Seeds — several of these applications are not targets until their schema exists
# ======================================================================================


def _dvwa_token(body: str) -> str:
    m = re.search(r"user_token'\s*value='([0-9a-f]+)'", body)
    if not m:
        raise SystemExit("dvwa: no anti-CSRF user_token in the page — the app changed shape")
    return m.group(1)


def seed_dvwa(target: Target) -> list[str]:
    """DVWA ships with no schema: every login bounces to setup.php until it is created."""
    c = Http()
    _, body, _ = c.get(target.url("/setup.php"))
    status, _, _ = c.post(
        target.url("/setup.php"),
        {"create_db": "Create / Reset Database", "user_token": _dvwa_token(body)},
        timeout=120.0,
    )
    if status != 200:
        raise SystemExit(f"dvwa: create_db returned HTTP {status}")

    creds = target.credentials or {}
    _, body, _ = c.get(target.url("/login.php"))
    _, _, final = c.post(
        target.url("/login.php"),
        {
            "username": creds.get("username", "admin"),
            "password": creds.get("password", "password"),
            "Login": "Login",
            "user_token": _dvwa_token(body),
        },
    )
    # The assertion that matters: before seeding this lands on setup.php. Reaching index.php is
    # what distinguishes a working target from a setup page that answers 200.
    if not final.endswith("index.php"):
        raise SystemExit(f"dvwa: login after seeding landed on {final}, not index.php")
    return ["schema created", f"login as {creds.get('username')} reaches index.php"]


def seed_mutillidae(target: Target) -> list[str]:
    """Mutillidae redirects everything to database-offline.php until its schema is built."""
    c = Http()
    status, _, _ = c.get(target.url("/set-up-database.php"), timeout=180.0)
    if status != 200:
        raise SystemExit(f"mutillidae: set-up-database.php returned HTTP {status}")
    status, body, final = c.get(target.url("/index.php"))
    if "database-offline" in final or "Database Offline" in body:
        raise SystemExit("mutillidae: still reporting its database offline after seeding")
    return ["schema created", "index.php no longer redirects to database-offline.php"]


def seed_vampi(target: Target) -> list[str]:
    """VAmPI answers immediately, but with an empty user table."""
    c = Http()
    status, body, _ = c.get(target.url("/createdb"), timeout=60.0)
    if status != 200 or "populated" not in body:
        raise SystemExit(f"vampi: /createdb returned HTTP {status}: {body[:120]}")
    status, body, _ = c.get(target.url("/users/v1"))
    users = json.loads(body).get("users", []) if status == 200 else []
    if not users:
        raise SystemExit("vampi: /users/v1 is still empty after /createdb")
    return [f"database populated, {len(users)} users present"]


SEEDS = {
    "dvwa_setup": seed_dvwa,
    "mutillidae_setup": seed_mutillidae,
    "vampi_createdb": seed_vampi,
}


def run_seed(target: Target, timeout: float = 240.0) -> tuple[list[str], int]:
    """Run a target's seed, retrying until it takes or the deadline passes.

    Seeding is the one step that cannot be gated by HTTP readiness from outside, because these images
    start their WEB SERVER before their DATABASE. The port is open, ``/`` answers 200, every readiness
    signal the range can see from the network is already satisfied — and the schema call still fails.
    Measured on a cold ``citizenstig/nowasp``: ``/`` answers within a second, while
    ``set-up-database.php`` returns HTTP 500 ("Can't connect to MySQL server ... (111)") for roughly
    the next half-minute, and the application keeps redirecting to ``database-offline.php``.

    So the honest wait is to poll the real thing — the seed itself — rather than sleep a guessed
    interval before it. Retrying is safe because every seed here has RESET semantics by design
    (DVWA's "Create / Reset Database", Mutillidae's ``set-up-database.php``, VAmPI's ``/createdb``);
    running one twice rebuilds the same fixed dataset, which is also what keeps runs comparable.

    This wraps ALL seeds rather than only the one observed to race: the same web-before-database
    ordering exists in every one of these images, and a race that is currently won on a warm machine
    is not a race that has been fixed.
    """
    deadline = time.monotonic() + timeout
    last = ""
    attempts = 0
    while True:
        attempts += 1
        try:
            return SEEDS[target.seed](target), attempts
        except (SystemExit, urllib.error.URLError, OSError, ValueError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            if time.monotonic() >= deadline:
                raise SystemExit(
                    f"{target.name}: seeding never took after {attempts} attempt(s) over "
                    f"{timeout:.0f}s. Last error: {last}"
                ) from None
            time.sleep(3.0)


# ======================================================================================
# Weakness probes — each one is a differential with its own negative control
# ======================================================================================


@dataclass
class ProbeResult:
    present: bool
    control: str  # what the BENIGN request did
    attack: str  # what the ATTACK request did
    detail: str


def probe_vulnapp(target: Target) -> ProbeResult:
    c = Http()
    _, benign, _ = c.get(target.url("/search?q=apple"))
    _, inject, _ = c.get(target.url("/search?" + urllib.parse.urlencode({"q": "' OR '1'='1"})))
    n_benign = benign.count("<li>")
    n_inject = inject.count("<li>")
    return ProbeResult(
        present=n_inject > n_benign and n_benign >= 1,
        control=f"q=apple returned {n_benign} row(s)",
        attack=f"q=' OR '1'='1 returned {n_inject} row(s)",
        detail="CWE-89: the injected predicate returns rows the benign term does not match",
    )


def probe_juice(target: Target) -> ProbeResult:
    c = Http()

    def ids(q: str) -> set:
        _, body, _ = c.get(target.url("/rest/products/search?q=" + urllib.parse.quote(q, safe="")))
        try:
            return {row["id"] for row in json.loads(body).get("data", [])}
        except (ValueError, KeyError, TypeError):
            return set()

    benign = ids("")
    inject = ids("'))--")
    extra = inject - benign
    # A strict superset: the injected query returns everything the ordinary one does AND more.
    # "More rows" alone would also be produced by a different search term matching differently.
    return ProbeResult(
        present=bool(benign) and benign < inject,
        control=f"the ordinary search returns {len(benign)} products",
        attack=f"the injected search returns {len(inject)}, including {len(extra)} the app hides",
        detail="CWE-89: closing the WHERE clause exposes soft-deleted rows the query filters out",
    )


def probe_dvwa(target: Target) -> ProbeResult:
    c = Http()
    creds = target.credentials or {}
    _, body, _ = c.get(target.url("/login.php"))
    c.post(
        target.url("/login.php"),
        {
            "username": creds.get("username", "admin"),
            "password": creds.get("password", "password"),
            "Login": "Login",
            "user_token": _dvwa_token(body),
        },
    )
    # DVWA reads its difficulty from the `security` cookie, so a driver has to send it — through the
    # JAR, alongside the session cookie, never as a header (see Http.set_cookie).
    c.set_cookie("security", "low")
    _, benign, benign_url = c.get(target.url("/vulnerabilities/sqli/?id=1&Submit=Submit"))
    _, inject, _ = c.get(
        target.url(
            "/vulnerabilities/sqli/?"
            + urllib.parse.urlencode({"id": "1' OR '1'='1", "Submit": "Submit"})
        )
    )
    # An unauthenticated probe gets redirected to login.php and reads zero records from BOTH
    # requests, which is indistinguishable from "the injection did not work". Refuse to report a
    # result at all unless the probe actually reached the vulnerable page.
    if benign_url.endswith("login.php"):
        raise SystemExit(
            "dvwa: the probe was redirected to login.php, so it never reached the vulnerable page. "
            "This is a broken probe, not an absent weakness."
        )
    n_benign = benign.count("First name:")
    n_inject = inject.count("First name:")
    return ProbeResult(
        present=n_benign == 1 and n_inject > n_benign,
        control=f"id=1 returned {n_benign} record(s)",
        attack=f"id=1' OR '1'='1 returned {n_inject} record(s)",
        detail="CWE-89: a single-record lookup made to return the whole table",
    )


def probe_mutillidae(target: Target) -> ProbeResult:
    c = Http()
    err = "You have an error in your SQL syntax"
    base = "/index.php?page=user-info.php&user-info-php-submit-button=View+Account+Details&password=x&username="
    _, benign, _ = c.get(target.url(base + "alice"))
    _, inject, _ = c.get(target.url(base + urllib.parse.quote("'", safe="")))
    return ProbeResult(
        present=err not in benign and err in inject,
        control="a benign username produces no SQL error",
        attack="a single quote produces a MySQL syntax error from the server",
        detail="CWE-89: the parameter is concatenated into the statement, so it can end it",
    )


def probe_vampi(target: Target) -> ProbeResult:
    c = Http()
    _, public, _ = c.get(target.url("/users/v1"))
    _, debug, _ = c.get(target.url("/users/v1/_debug"))
    pub_has = '"password"' in public
    dbg_has = '"password"' in debug
    return ProbeResult(
        present=not pub_has and dbg_has,
        control="/users/v1 returns usernames and emails only",
        attack="/users/v1/_debug returns every user's password in cleartext",
        detail="CWE-200: a debug route left routed in production exposes the credential store",
    )


WEAKNESS_PROBES = {
    "vulnapp_sqli_differential": probe_vulnapp,
    "juice_sqli_differential": probe_juice,
    "dvwa_sqli_differential": probe_dvwa,
    "mutillidae_sqli_error": probe_mutillidae,
    "vampi_debug_exposure": probe_vampi,
}


# ======================================================================================
# CLI — the surface range.sh drives
# ======================================================================================


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="VIGIL loopback range manifest and probes")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("names", help="every target name")
    sub.add_parser("check", help="validate the manifest (pins, ports, probes)")
    for name in ("publish-args", "image", "container", "info", "urls", "kind", "script", "seed-name"):
        p = sub.add_parser(name)
        p.add_argument("target")
    p = sub.add_parser("assert-binding")
    p.add_argument("target")
    p.add_argument("--container", default=None)
    p = sub.add_parser("listening", help="addresses currently listening on this target's ports")
    p.add_argument("target")
    p = sub.add_parser("wait")
    p.add_argument("target")
    p.add_argument("--timeout", type=float, default=180.0)
    p.add_argument("--any", action="store_true", help="wait for any HTTP response, not readiness")
    p = sub.add_parser("seed")
    p.add_argument("target")
    p.add_argument("--timeout", type=float, default=240.0)
    p = sub.add_parser("weakness")
    p.add_argument("target")
    p = sub.add_parser("source-fingerprint")
    p.add_argument("tree")

    args = ap.parse_args(argv)
    m = Manifest()

    if args.cmd == "names":
        print(" ".join(sorted(m.targets)))
        return 0

    if args.cmd == "check":
        print(f"manifest OK: {len(m.targets)} target(s), every image digest-pinned")
        for name, t in sorted(m.targets.items()):
            ref = t.image or t.script
            print(f"  {name:<11} {t.kind:<9} {ref}")
        return 0

    if args.cmd == "source-fingerprint":
        print(m.source_range["trees"][args.tree]["fingerprint"])
        return 0

    t = m.get(args.target)

    if args.cmd == "publish-args":
        print(" ".join(publish_args(t)))
        return 0
    if args.cmd == "image":
        print(t.image or "")
        return 0
    if args.cmd == "script":
        print(str(REPO / t.script) if t.script else "")
        return 0
    if args.cmd == "kind":
        print(t.kind)
        return 0
    if args.cmd == "seed-name":
        print(t.seed or "")
        return 0
    if args.cmd == "container":
        print(m.container_name(t.name))
        return 0
    if args.cmd == "urls":
        for p in t.ports:
            print(f"{p.name} http://{LOOPBACK}:{p.host}")
        return 0
    if args.cmd == "info":
        print(json.dumps(m.raw["targets"][t.name], indent=2))
        return 0

    if args.cmd == "listening":
        # Used by `range.sh down` to assert the machine was actually left clean.
        for p_ in t.ports:
            for addr in _listening_on(p_.host):
                print(f"{addr}:{p_.host}")
        return 0

    if args.cmd == "assert-binding":
        container = args.container or (m.container_name(t.name) if t.kind == "container" else None)
        for line in assert_loopback_binding(t, container):
            print(f"       {line}")
        return 0

    if args.cmd == "wait":
        ok, detail = wait_http(t, args.timeout, ready=not args.any)
        print(f"       {detail}")
        return 0 if ok else 1

    if args.cmd == "seed":
        if not t.seed:
            return 0
        lines, attempts = run_seed(t, args.timeout)
        for line in lines:
            print(f"       {line}")
        if attempts > 1:
            # Say so out loud. A seed that needed five tries is a target whose database came up well
            # after its web server, and an operator debugging a slow range should not have to guess.
            print(f"       (took {attempts} attempts — the database came up after the web server)")
        return 0

    if args.cmd == "weakness":
        if not t.weakness_probe:
            print(f"       NOT PROBED — {t.weakness_probe_note}")
            return 0
        try:
            r = WEAKNESS_PROBES[t.weakness_probe](t)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            # Still a failure — a probe that could not reach its target has NOT shown the weakness is
            # absent, and must not be allowed to read as if it had. But say which of the two it is,
            # because "start the target first" and "the weakness is gone" need different actions.
            print(f"       UNREACHABLE — {type(exc).__name__}: {exc}")
            print(f"       {t.name} is not answering on {t.url()}. Start it first:")
            print(f"         tools/livefire/range.sh up {t.name}")
            return 1
        print(f"       control: {r.control}")
        print(f"       attack:  {r.attack}")
        print(f"       {'CONFIRMED' if r.present else 'NOT PRESENT'} — {r.detail}")
        return 0 if r.present else 1

    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
