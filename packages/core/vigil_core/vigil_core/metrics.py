"""metrics — a stdlib-only OpenMetrics / Prometheus text-format exposition (W6-3 #454).

The single shared metrics substrate for BOTH trust planes. Before this module there was NO metrics
exposition of any kind — only a business-counter JSON snapshot (``vigil_integration.telemetry``). This
adds, with ZERO new third-party dependency (so neither hash lock changes), a small OpenMetrics text
formatter plus a process-global :class:`MetricsRegistry` that a server renders on its ``/metrics`` route.

What a rendered exposition carries, per plane:

  * **RED** — Rate/Errors/Duration of the server's own requests: ``vigil_requests_total`` (a counter,
    labelled by method + HTTP status class), ``vigil_request_errors_total`` (5xx / handler crashes), and
    ``vigil_request_duration_seconds`` (a cumulative-bucket histogram + ``_sum``/``_count``).
  * **process** — ``vigil_process_resident_memory_bytes``, ``vigil_process_open_fds``,
    ``vigil_process_uptime_seconds``, ``vigil_process_start_time_seconds`` — read at render time from
    ``/proc/self`` (Linux) with total, never-raising fallbacks, so a server without ``/proc`` still renders.
  * **domain** — the four business counters the plan names: ``vigil_facts_total``, ``vigil_leads_total``,
    ``vigil_refusals_total`` (fed from the signed-spine business snapshot via
    :meth:`MetricsRegistry.update_domain_from_snapshot`) and ``vigil_gate_denials_total`` (a live counter
    the authorization edge bumps through :func:`record_gate_verdict` on a DENY).

Invariants (this module is telemetry — it NEVER authorizes):

  * **Emit-only / never gates.** No function here returns or influences an allow/deny verdict.
    :func:`record_gate_verdict` merely COUNTS a decision made elsewhere; the ``GateVerdict`` is unchanged.
  * **Total on malformed input.** Every public method degrades to a no-op / a stable string on garbage;
    a metric update or a render never raises into the caller (a broken exporter must never break a server).
  * **Deterministic text.** Series render in a stable, sorted order so a snapshot test is reproducible;
    the only non-determinism (process rss/fds/uptime) is isolated to the process-metric collector.

Import-clean: stdlib only. No ``framework.*`` / ``strix.*`` / ``sigil.*`` — a leaf both envs load, so the
two-env boundary is untouched (the offense process and the sovereign process each hold their own registry).
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

# OpenMetrics 1.0 content type — a server SHOULD set this on the /metrics response so a scraper parses
# it as OpenMetrics (a plain text/plain also works; Prometheus negotiates both).
CONTENT_TYPE = "application/openmetrics-text; version=1.0.0; charset=utf-8"

# Default cumulative histogram buckets for request latency (seconds). Standard Prometheus web latencies.
DEFAULT_LATENCY_BUCKETS: Tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)


# ---------------------------------------------------------------------------------------------------
# OpenMetrics text formatting — pure, deterministic helpers
# ---------------------------------------------------------------------------------------------------


def _fmt_float(v: Any) -> str:
    """Render a numeric sample value the way OpenMetrics wants it: integers without a decimal point,
    floats with full ``repr`` precision, and ``+Inf`` for the overflow bucket. Total."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return "0"
    if f == float("inf"):
        return "+Inf"
    if f == float("-inf"):
        return "-Inf"
    if f != f:  # NaN
        return "NaN"
    if f.is_integer():
        return str(int(f))
    return repr(f)


def _esc_label_value(v: Any) -> str:
    """Escape a label VALUE per the exposition format: backslash, double-quote, newline."""
    s = "" if v is None else str(v)
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt_labels(labels: Optional[Dict[str, Any]]) -> str:
    """Render a ``{name="value",...}`` label set (sorted by name for determinism), or ``""`` if empty."""
    if not labels:
        return ""
    parts = [f'{k}="{_esc_label_value(labels[k])}"' for k in sorted(labels)]
    return "{" + ",".join(parts) + "}"


def format_family(name: str, mtype: str, samples: Iterable[Tuple[str, Optional[Dict[str, Any]], Any]],
                  *, help_text: str = "", unit: str = "") -> str:
    """Format one metric FAMILY as OpenMetrics text: a ``# TYPE`` line (and optional ``# HELP`` / ``# UNIT``)
    followed by its samples. ``samples`` is an iterable of ``(suffix, labels, value)`` where ``suffix`` is
    appended to ``name`` (e.g. ``"_total"`` for a counter, ``"_bucket"`` for a histogram). Pure + total."""
    lines: List[str] = []
    if help_text:
        lines.append(f"# HELP {name} {help_text}")
    if unit:
        lines.append(f"# UNIT {name} {unit}")
    lines.append(f"# TYPE {name} {mtype}")
    for suffix, labels, value in samples:
        lines.append(f"{name}{suffix}{_fmt_labels(labels)} {_fmt_float(value)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------------------------------


class MetricsRegistry:
    """A thread-safe, process-local metrics registry that renders a full OpenMetrics exposition. One per
    process (one plane). Emit-only — it authorizes nothing; it only records and formats numbers."""

    def __init__(self, *, plane: str = "unknown", buckets: Iterable[float] = DEFAULT_LATENCY_BUCKETS,
                 start_time: Optional[float] = None, now_fn: Any = None) -> None:
        self._lock = threading.Lock()
        self.plane = str(plane or "unknown")
        self._now = now_fn if callable(now_fn) else time.time
        self._start = float(start_time) if start_time is not None else self._now()
        self._buckets: Tuple[float, ...] = tuple(sorted(float(b) for b in buckets))

        # RED — request counters keyed by (method, status_class); errors by method; a single latency hist.
        self._requests: Dict[Tuple[str, str], float] = {}
        self._errors: Dict[str, float] = {}
        self._hist_counts: List[float] = [0.0] * len(self._buckets)
        self._hist_inf: float = 0.0
        self._hist_sum: float = 0.0

        # domain counters (facts/leads/refusals fed from the snapshot; gate_denials a live counter).
        self._facts: float = 0.0
        self._leads: float = 0.0
        self._refusals: float = 0.0
        self._gate_denials: float = 0.0

    # -- RED instrumentation ------------------------------------------------------------------------

    def observe_request(self, *, duration_s: Any = 0.0, method: Any = "GET", status: Any = 200) -> None:
        """Record ONE served request into the RED metrics: bump the request counter for its
        (method, status-class), the latency histogram, and — for a 5xx — the error counter. Total: any
        unparseable argument degrades to a safe default; this never raises into the request path."""
        try:
            m = str(method or "GET").upper()
            try:
                code = int(status)
            except (TypeError, ValueError):
                code = 0
            cls = f"{code // 100}xx" if code >= 100 else "0xx"
            try:
                dur = max(0.0, float(duration_s))
            except (TypeError, ValueError):
                dur = 0.0
            with self._lock:
                self._requests[(m, cls)] = self._requests.get((m, cls), 0.0) + 1.0
                if code >= 500 or code == 0:
                    self._errors[m] = self._errors.get(m, 0.0) + 1.0
                for i, b in enumerate(self._buckets):
                    if dur <= b:
                        self._hist_counts[i] += 1.0
                self._hist_inf += 1.0
                self._hist_sum += dur
        except Exception:  # noqa: BLE001 — telemetry must never break the request it measures
            return

    # -- domain counters ----------------------------------------------------------------------------

    def update_domain_from_snapshot(self, snapshot: Any) -> None:
        """Fold the signed-spine business snapshot (``telemetry.collect_snapshot`` shape:
        ``{"totals": {"facts", "leads", "refusals", ...}}``) into the facts/leads/refusals domain counters.
        These are cumulative projections of an append-only spine (monotonic), so they are SET (not added).
        Total: a missing/garbage snapshot leaves the counters unchanged."""
        try:
            totals = (snapshot or {}).get("totals") if isinstance(snapshot, dict) else None
            if not isinstance(totals, dict):
                return
            with self._lock:
                self._facts = _coerce_num(totals.get("facts"), self._facts)
                self._leads = _coerce_num(totals.get("leads"), self._leads)
                self._refusals = _coerce_num(totals.get("refusals"), self._refusals)
        except Exception:  # noqa: BLE001
            return

    def inc_gate_denial(self, n: float = 1.0) -> None:
        """Bump the live gate-denial counter by ``n`` (default 1). Called by :func:`record_gate_verdict`
        from the authorization edge on a DENY. Emit-only — counting a denial changes no decision. Total."""
        try:
            step = float(n)
        except (TypeError, ValueError):
            return
        with self._lock:
            self._gate_denials += step

    # -- introspection (used by tests / the alert harness) ------------------------------------------

    def value(self, name: str, labels: Optional[Dict[str, Any]] = None) -> float:
        """The current value of a rendered series (by its full sample name incl. the ``_total`` suffix and
        its labels), parsed back out of :meth:`render`. Total — returns 0.0 for an absent series."""
        want_labels = _fmt_labels(labels)
        target = f"{name}{want_labels} "
        for line in self.render().splitlines():
            if line.startswith("#"):
                continue
            if line.startswith(target):
                try:
                    return float(line[len(target):].strip())
                except ValueError:
                    return 0.0
        return 0.0

    # -- process metrics (collected at render time; Linux /proc with total fallbacks) ---------------

    def _process_metrics(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        # resident memory
        try:
            with open("/proc/self/statm", "r", encoding="ascii") as fh:
                rss_pages = float(fh.read().split()[1])
            out["rss"] = rss_pages * float(os.sysconf("SC_PAGE_SIZE"))
        except Exception:  # noqa: BLE001 — fall back to getrusage (maxrss in KiB on Linux)
            try:
                import resource
                out["rss"] = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024.0
            except Exception:  # noqa: BLE001
                pass
        # open file descriptors
        try:
            out["fds"] = float(len(os.listdir("/proc/self/fd")))
        except Exception:  # noqa: BLE001
            pass
        # uptime + start time
        try:
            now = float(self._now())
            out["start"] = self._start
            out["uptime"] = max(0.0, now - self._start)
        except Exception:  # noqa: BLE001
            pass
        return out

    # -- render -------------------------------------------------------------------------------------

    def render(self) -> str:
        """Render the FULL OpenMetrics exposition (RED + process + domain) as text, terminated by the
        mandatory ``# EOF`` line. Deterministic ordering. Total — never raises (a collection error omits
        that family rather than failing the scrape)."""
        try:
            return self._render()
        except Exception:  # noqa: BLE001 — a render error must not 500 the /metrics route
            return "# EOF\n"

    def _render(self) -> str:
        pl = {"plane": self.plane}
        with self._lock:
            requests = dict(self._requests)
            errors = dict(self._errors)
            hist_counts = list(self._hist_counts)
            hist_inf = self._hist_inf
            hist_sum = self._hist_sum
            facts, leads, refusals, denials = self._facts, self._leads, self._refusals, self._gate_denials
        buckets = self._buckets
        blocks: List[str] = []

        # RED — requests
        req_samples = [
            ("_total", {"plane": self.plane, "method": m, "status": cls}, v)
            for (m, cls), v in sorted(requests.items())
        ]
        blocks.append(format_family(
            "vigil_requests", "counter", req_samples,
            help_text="Total HTTP requests handled by this plane's server, by method and status class."))

        err_samples = [("_total", {"plane": self.plane, "method": m}, v) for m, v in sorted(errors.items())]
        blocks.append(format_family(
            "vigil_request_errors", "counter", err_samples,
            help_text="HTTP requests that failed (5xx or handler crash) on this plane."))

        # RED — duration histogram (cumulative buckets + sum + count)
        hist_samples: List[Tuple[str, Optional[Dict[str, Any]], Any]] = []
        for i, b in enumerate(buckets):
            hist_samples.append(("_bucket", {"plane": self.plane, "le": _fmt_float(b)}, hist_counts[i]))
        hist_samples.append(("_bucket", {"plane": self.plane, "le": "+Inf"}, hist_inf))
        hist_samples.append(("_sum", pl, hist_sum))
        hist_samples.append(("_count", pl, hist_inf))
        blocks.append(format_family(
            "vigil_request_duration_seconds", "histogram", hist_samples, unit="seconds",
            help_text="Request handling latency on this plane (RED: Duration)."))

        # process metrics
        proc = self._process_metrics()
        if "rss" in proc:
            blocks.append(format_family("vigil_process_resident_memory_bytes", "gauge",
                                        [("", pl, proc["rss"])], unit="bytes",
                                        help_text="Resident memory of the server process."))
        if "fds" in proc:
            blocks.append(format_family("vigil_process_open_fds", "gauge",
                                        [("", pl, proc["fds"])],
                                        help_text="Open file descriptors held by the server process."))
        if "uptime" in proc:
            blocks.append(format_family("vigil_process_uptime_seconds", "gauge",
                                        [("", pl, proc["uptime"])], unit="seconds",
                                        help_text="Seconds since the server process started."))
        if "start" in proc:
            blocks.append(format_family("vigil_process_start_time_seconds", "gauge",
                                        [("", pl, proc["start"])], unit="seconds",
                                        help_text="Unix start time of the server process."))

        # domain counters
        blocks.append(format_family("vigil_facts", "counter", [("_total", pl, facts)],
                                    help_text="Oracle-confirmed FACTs projected from the signed spine."))
        blocks.append(format_family("vigil_leads", "counter", [("_total", pl, leads)],
                                    help_text="Unconfirmed LEADs projected from the signed spine."))
        blocks.append(format_family("vigil_refusals", "counter", [("_total", pl, refusals)],
                                    help_text="Refusals recorded on the signed spine."))
        blocks.append(format_family("vigil_gate_denials", "counter", [("_total", pl, denials)],
                                    help_text="Authorization-gate DENY verdicts observed in this process."))

        return "\n".join(blocks) + "\n# EOF\n"


def _coerce_num(v: Any, default: float) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------------------------------
# the process-global default registry + the gate-verdict recorder
# ---------------------------------------------------------------------------------------------------

_DEFAULT: Optional[MetricsRegistry] = None
_DEFAULT_LOCK = threading.Lock()


def default_registry() -> MetricsRegistry:
    """The process-global registry (created on first use). A server sets its plane once at startup via
    :func:`set_plane`; the authorization edge and the /metrics route both use THIS instance, so a gate
    denial counted anywhere in the process is reflected on that process's /metrics."""
    global _DEFAULT
    if _DEFAULT is None:
        with _DEFAULT_LOCK:
            if _DEFAULT is None:
                _DEFAULT = MetricsRegistry(plane=os.environ.get("VIGIL_PLANE", "unknown"))
    return _DEFAULT


def set_plane(plane: str) -> MetricsRegistry:
    """Set the process-global registry's plane label (idempotent; call once at server startup)."""
    reg = default_registry()
    reg.plane = str(plane or "unknown")
    return reg


def record_gate_verdict(verdict: Any, *, registry: Optional[MetricsRegistry] = None) -> Any:
    """COUNT an authorization ``GateVerdict`` (``vigil_core.gate.GateVerdict``) into the gate-denial
    counter when — and only when — it is a DENY. Duck-typed and emit-only: a DENY is ``allowed is False``
    with a ``decision``/``outcome`` of ``"deny"`` (a QUEUE, which also has ``allowed is False``, is NOT a
    denial and is not counted). The verdict is returned UNCHANGED so this can wrap a gate call inline.
    Total — a ``None``/garbage verdict is a no-op. This never affects the decision it counts."""
    try:
        allowed = getattr(verdict, "allowed", None)
        decision = getattr(verdict, "decision", None) or getattr(verdict, "outcome", None)
        if allowed is False and str(decision) == "deny":
            (registry or default_registry()).inc_gate_denial()
    except Exception:  # noqa: BLE001 — counting must never break the gate path
        pass
    return verdict
