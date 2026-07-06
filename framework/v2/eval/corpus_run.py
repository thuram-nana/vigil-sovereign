"""
eval.corpus_run — the dockerized multi-app benchmark lifecycle.

The in-process benchmark app proves precision on one labelled target; credibility
needs BREADTH — CRUCIBLE and the incumbents scored on many real applications:
labelled suites (neutral ground truth), deliberately-vulnerable apps, and real
production software with no planted bugs (where the metric is false-positive rate
and discovery, not recall). This module is the machinery that runs that corpus.

A :class:`CorpusApp` descriptor (one JSON file per app under ``corpus_apps/``) says
how to stand an app up in Docker, when it is healthy, where to point the scanners,
and what its ground truth is. :func:`run_corpus_app` brings the container up, runs
every available tool through the measured comparative spine
(:func:`eval.validation.comparative_report_measured`), and tears the container down
— returning per-tool accuracy+cost boards.

Design for honesty and testability:

  * Ground truth is one of three kinds — ``curated`` (we authored it; the
    co-design caveat is disclosed), ``owasp`` (neutral, loaded from OWASP
    Benchmark's own CSV via :mod:`eval.owasp_benchmark`), or ``none`` (a real app
    with no planted bugs — every confirmed finding is scrutinised as a candidate
    false positive). Nothing is scored against a manifest we quietly invented.
  * The Docker calls sit behind a :class:`Launcher` seam, so the whole
    orchestration is unit-testable against a local server with no Docker at all.
  * ``heavy`` apps (GitLab, Mattermost) are never auto-pulled here — they are
    shipped as descriptors for an operator with the RAM to run them, and skipped
    with a logged reason otherwise. No fabricated numbers for an app that did not
    actually run.
"""

from __future__ import annotations

import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from ..common.errors import EvalError
from ..scanner.campaign import WebScanCampaign
from ..scanner.cli import loopback_send
from ..scanner.insertion import InsertionKind
from ..scanner.library import load_library
from .models import _normalize_class
from .owasp_benchmark import load_owasp_expectedresults, owasp_class_key
from .validation import (
    CorpusTarget,
    CrucibleAdapter,
    ExpectedFinding,
    MeasuredBoard,
    NormalizedFinding,
    comparative_report_measured,
)


class CorpusRunError(EvalError):
    """A corpus lifecycle failure: a bad descriptor, an image that never became
    healthy, or a Docker invocation that errored. A measurement/setup error —
    never an authorization decision."""


# ---------------------------------------------------------------------------
# descriptor schema
# ---------------------------------------------------------------------------


class GroundTruth(BaseModel):
    """How a corpus app's ground truth is established. ``kind`` picks the source;
    the others are the kind-specific inputs."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["curated", "owasp", "none"]
    # curated: the manifest we authored (co-design caveat applies, disclosed).
    expected: list[ExpectedFinding] = Field(default_factory=list)
    # owasp: path to an OWASP Benchmark expectedresults CSV (neutral truth).
    owasp_csv: str | None = None
    owasp_dast_only: bool = True


class ScanTuning(BaseModel):
    """The CRUCIBLE campaign knobs for one app — kept small and explicit so a
    descriptor fully determines the run."""

    model_config = ConfigDict(extra="forbid")

    max_pages: int = 40
    max_depth: int = 4
    use_library: bool = True
    enable_oob: bool = False
    max_audit_requests: int = 0
    insertion_kinds: list[str] = Field(default_factory=lambda: ["QUERY_VALUE"])
    drop_timing: bool = True  # timing checks are slow; drop unless an app needs them

    def resolved_kinds(self) -> tuple[InsertionKind, ...]:
        try:
            return tuple(InsertionKind[k] for k in self.insertion_kinds)
        except KeyError as e:
            raise CorpusRunError(f"unknown insertion kind {e} in scan tuning") from e


class CorpusApp(BaseModel):
    """One benchmark target: how to run it, when it is up, where to scan, and what
    its ground truth is."""

    model_config = ConfigDict(extra="forbid")

    name: str
    role: Literal["labeled", "vulnerable", "real-enterprise"]
    image: str = Field(description="Docker image ref, e.g. 'bkimminich/juice-shop'.")
    container_port: int
    host_port: int = 0  # 0 -> pick a free ephemeral port
    env: dict[str, str] = Field(default_factory=dict)
    command: list[str] = Field(default_factory=list)
    health_path: str = "/"
    health_statuses: list[int] = Field(default_factory=lambda: [200])
    health_timeout_s: int = 120
    seed_path: str = "/"
    ground_truth: GroundTruth
    scan: ScanTuning = Field(default_factory=ScanTuning)
    heavy: bool = False  # RAM-heavy; operator-run, never auto-pulled here
    notes: str = ""

    @classmethod
    def from_json(cls, path: str | Path) -> "CorpusApp":
        import json

        p = Path(path).expanduser()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except OSError as e:
            raise CorpusRunError(f"cannot read corpus app {p}: {e}") from e
        except ValueError as e:
            raise CorpusRunError(f"corpus app {p} is not valid JSON: {e}") from e
        try:
            return cls.model_validate(data)
        except Exception as e:
            raise CorpusRunError(f"corpus app {p} is not a valid CorpusApp: {e}") from e


def load_corpus_apps(directory: str | Path) -> list[CorpusApp]:
    """Load every ``*.json`` app descriptor in a directory, sorted for determinism."""
    d = Path(directory).expanduser()
    if not d.is_dir():
        raise CorpusRunError(f"corpus_apps directory does not exist: {d}")
    return [CorpusApp.from_json(p) for p in sorted(d.glob("*.json"))]


# ---------------------------------------------------------------------------
# ground-truth resolution + the tuned CRUCIBLE adapter
# ---------------------------------------------------------------------------


def resolve_ground_truth(app: CorpusApp, *, base_dir: Path | None = None) -> list[ExpectedFinding]:
    """Turn a descriptor's :class:`GroundTruth` into concrete expected findings."""
    gt = app.ground_truth
    if gt.kind == "none":
        return []
    if gt.kind == "curated":
        return list(gt.expected)
    if gt.kind == "owasp":
        if not gt.owasp_csv:
            raise CorpusRunError(f"{app.name}: ground_truth.kind=owasp needs owasp_csv")
        csv_path = Path(gt.owasp_csv)
        if not csv_path.is_absolute() and base_dir is not None:
            csv_path = base_dir / csv_path
        return load_owasp_expectedresults(csv_path, dast_only=gt.owasp_dast_only)
    raise CorpusRunError(f"{app.name}: unknown ground_truth.kind {gt.kind!r}")


def class_key_for(app: CorpusApp) -> Callable[[str], str]:
    """The scorer's class-key for this app. Any app with a positive ground truth
    (owasp OR curated) scores with the neutral family-collapsing key so CRUCIBLE's
    fine-grained classes match a coarser manifest label — ``boolean_sqli`` /
    ``error_based_sqli`` / ``time_based_sqli`` all satisfy an ``sqli`` label,
    ``lfi`` satisfies ``path_traversal``, ``rce`` satisfies ``command_injection``.
    The key only ever merges same-family labels (symmetric across both sides), so it
    cannot inflate a match; a curated manifest may therefore use coarse families
    without under-counting a subclass detection. ``none`` targets have no manifest
    to match against, so the default format-only key is fine."""
    return _normalize_class if app.ground_truth.kind == "none" else owasp_class_key


class CorpusCrucibleAdapter(CrucibleAdapter):
    """A CrucibleAdapter driven by a descriptor's :class:`ScanTuning`, authorized
    for the (loopback-mapped, or operator-named) corpus host. Records the same
    per-run metrics as every CrucibleAdapter via :meth:`_record`."""

    name: str = "crucible"

    def __init__(self, tuning: ScanTuning, *, authorized_hosts: frozenset[str] = frozenset()) -> None:
        super().__init__(
            max_pages=tuning.max_pages,
            max_depth=tuning.max_depth,
            max_audit_requests=tuning.max_audit_requests,
            enable_oob=tuning.enable_oob,
            insertion_kinds=tuning.resolved_kinds(),
            authorized_hosts=authorized_hosts,
        )
        self._tuning = tuning

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        if not self._authorized(target.base_url):
            from .validation import HarnessError

            raise HarnessError(
                f"CorpusCrucibleAdapter refuses {target.base_url!r}: host not authorized."
            )
        entries = None
        if self._tuning.use_library:
            lib = load_library()
            if self._tuning.drop_timing:
                lib = [e for e in lib if e.oracle.kind != "timing"]
            entries = lib
        report = WebScanCampaign(
            loopback_send,
            max_pages=self._tuning.max_pages,
            max_depth=self._tuning.max_depth,
            max_audit_requests=self._tuning.max_audit_requests,
            enable_oob=self._tuning.enable_oob,
            use_library=self._tuning.use_library,
            library_entries=entries,
            insertion_kinds=self.insertion_kinds,
        ).run(target.base_url)
        return self._record(report)


# ---------------------------------------------------------------------------
# container lifecycle — behind a Launcher seam for docker-free testing
# ---------------------------------------------------------------------------


class Container(BaseModel):
    """A running corpus container: its id and the base URL to scan."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    container_id: str
    base_url: str
    stopper: object = None  # a zero-arg callable to tear it down (not serialized)

    def stop(self) -> None:
        if callable(self.stopper):
            self.stopper()


class Launcher(Protocol):
    """Brings an app up and returns a healthy :class:`Container`. The Docker
    implementation is the default; tests inject a fake pointing at a local server."""

    def up(self, app: CorpusApp) -> Container: ...


def _free_port() -> int:
    """Pick a free ephemeral port by binding and releasing it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def docker_available(runner: Callable[[list[str]], subprocess.CompletedProcess] | None = None) -> bool:
    """True iff a working Docker daemon is reachable (``docker version`` rc 0)."""
    run = runner or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=15))
    try:
        return run(["docker", "version"]).returncode == 0
    except Exception:
        return False


def _http_status(url: str, timeout: float = 5.0) -> int | None:
    """GET a URL and return its status code, or None on any connection error."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (loopback health check)
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code  # a 4xx/5xx still proves the server is answering
    except Exception:
        return None


def wait_healthy(
    base_url: str,
    health_path: str,
    statuses: list[int],
    timeout_s: int,
    *,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> None:
    """Poll ``base_url + health_path`` until it answers with an accepted status, or
    raise once ``timeout_s`` elapses. ``sleep``/``now`` are injectable for tests."""
    url = base_url.rstrip("/") + "/" + health_path.lstrip("/")
    deadline = now() + timeout_s
    accepted = set(statuses)
    last: int | None = None
    while now() < deadline:
        last = _http_status(url)
        if last is not None and last in accepted:
            return
        sleep(1.0)
    raise CorpusRunError(
        f"app at {url} never became healthy (last status={last}, "
        f"waited {timeout_s}s, wanted {sorted(accepted)})"
    )


class DockerLauncher:
    """Runs an app as a detached ``docker run --rm`` container mapped to a loopback
    port, waits for health, and hands back a :class:`Container` whose ``stop()``
    force-removes it."""

    def __init__(self, runner: Callable[[list[str]], subprocess.CompletedProcess] | None = None) -> None:
        self._run = runner or (
            lambda a: subprocess.run(a, capture_output=True, text=True, timeout=600)
        )

    def up(self, app: CorpusApp) -> Container:
        port = app.host_port or _free_port()
        args = ["docker", "run", "-d", "--rm", "-p", f"127.0.0.1:{port}:{app.container_port}"]
        for k, v in app.env.items():
            args += ["-e", f"{k}={v}"]
        args.append(app.image)
        args += app.command
        proc = self._run(args)
        if proc.returncode != 0:
            raise CorpusRunError(
                f"docker run failed for {app.name} ({app.image}): {proc.stderr.strip()}"
            )
        cid = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        if not cid:
            raise CorpusRunError(f"docker run for {app.name} returned no container id")
        base_url = f"http://127.0.0.1:{port}"

        def _stop() -> None:
            try:
                self._run(["docker", "rm", "-f", cid])
            except Exception:
                pass  # best-effort teardown

        try:
            wait_healthy(base_url, app.health_path, app.health_statuses, app.health_timeout_s)
        except Exception:
            _stop()
            raise
        return Container(container_id=cid, base_url=base_url, stopper=_stop)


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------


def default_corpus_dir() -> Path:
    """The shipped app-descriptor directory (``eval/corpus_apps/``)."""
    return Path(__file__).resolve().parent / "corpus_apps"


class CorpusOutcome(BaseModel):
    """The result of a whole-corpus run: per-app measured boards, and the apps that
    were skipped with an HONEST reason (docker absent, heavy/operator-run, or a
    launch failure). Skips are surfaced, never silently dropped — a corpus that ran
    3 of 13 apps must not read as '13 apps passed'."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    results: dict[str, list[MeasuredBoard]] = Field(default_factory=dict)
    skipped: dict[str, str] = Field(default_factory=dict)


def run_corpus(
    *,
    names: list[str] | None = None,
    include_heavy: bool = False,
    incumbent_adapters: list | None = None,
    apps_dir: str | Path | None = None,
    launcher: Launcher | None = None,
) -> CorpusOutcome:
    """Run the whole dockerized corpus (or a ``names`` subset), scoring every
    available tool on each app, and return per-app boards plus an honest skip map.

    Apps that cannot run here are SKIPPED WITH A REASON, not failed and not faked:
    if Docker is unreachable everything is skipped; a ``heavy`` app is skipped unless
    ``include_heavy`` (it is operator-run); an app whose image will not pull/launch is
    skipped with the launch error. ``launcher`` overrides Docker (for tests or an
    operator pointing at already-running instances)."""
    base = Path(apps_dir) if apps_dir else default_corpus_dir()
    apps = load_corpus_apps(base)
    if names:
        want = set(names)
        apps = [a for a in apps if a.name in want]
    outcome = CorpusOutcome()

    if launcher is None and not docker_available():
        for a in apps:
            outcome.skipped[a.name] = "docker daemon not available"
        return outcome

    for a in apps:
        if a.heavy and not include_heavy and launcher is None:
            outcome.skipped[a.name] = "heavy (operator-run) — pass include_heavy or a launcher"
            continue
        try:
            outcome.results[a.name] = run_corpus_app(
                a, incumbent_adapters=incumbent_adapters, launcher=launcher, base_dir=base)
        except CorpusRunError as e:
            outcome.skipped[a.name] = f"launch failed: {e}"
    return outcome


def run_corpus_app(
    app: CorpusApp,
    *,
    incumbent_adapters: list | None = None,
    launcher: Launcher | None = None,
    base_dir: Path | None = None,
) -> list[MeasuredBoard]:
    """Stand ``app`` up, score every available tool against its ground truth (with
    the app-appropriate class-key), and tear the container down. Returns the
    per-tool accuracy+cost boards.

    A ``heavy`` app is refused here — it is operator-run; the caller decides whether
    to skip or provide a launcher that can reach an already-running instance."""
    if app.heavy and launcher is None:
        raise CorpusRunError(
            f"{app.name} is marked heavy (operator-run); refusing to auto-launch. "
            "Run it yourself and pass a launcher that points at the running instance."
        )
    launcher = launcher or DockerLauncher()
    container = launcher.up(app)
    try:
        host = (urlsplit(container.base_url).hostname or "").lower()
        seed = container.base_url.rstrip("/") + "/" + app.seed_path.lstrip("/")
        target = CorpusTarget(
            name=app.name,
            base_url=seed,
            expected=resolve_ground_truth(app, base_dir=base_dir),
            notes=app.notes,
        )
        adapters: list = [CorpusCrucibleAdapter(app.scan, authorized_hosts=frozenset({host}))]
        if incumbent_adapters:
            adapters += incumbent_adapters
        return comparative_report_measured(target, adapters, class_key=class_key_for(app))
    finally:
        container.stop()
