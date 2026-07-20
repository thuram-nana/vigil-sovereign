"""
scanner.bizlogic — workflow / state-machine abuse detector (opt-in).

Business logic is doctrine's highest-yield class, yet it is the one a payload
library cannot reach: there is no canary to reflect and no datastore error to
provoke. The bug is a *sequence* the application should forbid but does not — a
required step skipped, a one-time action replayed, an out-of-order transition
accepted, a negative/overflow quantity or a tampered price taken as legitimate.
None of that is visible in a single request/response pair; it is visible only in
the **post-state** the workflow lands in after the illegitimate action.

So this module does not fuzz an insertion point. It drives an operator-declared
workflow — a small state machine of named steps with `requires` guards and
`once` limits — and, for each violation it can construct, ATTEMPTS the illegal
transition and then reads the workflow's own post-state back. The verdict is
never "the request returned 200"; it is a deterministic **predicate over the
observed post-state**, adjudicated by the achieved-state / predicate oracle
(the same authority `scanner.race` and `checks.IdorCheck` confirm through). If
the post-state proves the illegitimate state was actually reached, the finding
is promoted to a `ConfirmedFinding`; if the guard held, the predicate is false
and nothing is emitted (a LEAD at most, never a guessed finding).

Boundary, mirroring `scanner.checks`:

  * It sends NO traffic itself. Every step is performed through an injected
    ``perform`` callable — in production the scope/charter/kill-switch/egress-
    gated executor, in tests a localhost target — and the post-state is read
    through an injected ``read_state``. The detector places only the operator's
    own declared step actions (with, for tampering, an operator-declared
    override); it mints no exploit of its own.
  * It is OPT-IN and is NOT in ``scanner.checks.DEFAULT_CHECKS``: it cannot run
    without an operator-supplied ``WorkflowSpec`` describing the state machine,
    so the default scan roster and the benchmark gate never invoke it (0 extra
    requests — the gate stays byte-identical).

Everything is deterministic: the verdict rests on the observed post-state and a
pure JSON predicate AST, never on timing, and the same ``FindingContext`` is
retained so the finding re-verifies offline.

Detection / verification only, loopback / authorised targets only.
"""

from __future__ import annotations

import contextlib
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterator, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..verify.adapter import FindingContext
from ..verify.confirmation import ConfirmedFinding, confirm_finding

# The canonical bug class every finding here carries; it routes to the
# achieved-state / predicate oracle in verify.verifier.BUG_CLASS_ORACLES.
BUG_CLASS = "business_logic"

# perform one workflow step (with optional param overrides) against the target;
# the return value is not the verdict — the post-state is. Injected by the caller
# so the detector never touches the network directly.
Perform = Callable[["WorkflowStep", Mapping[str, Any]], Any]
# read the workflow's observed post-state as a JSON-safe mapping.
ReadState = Callable[[], Mapping[str, Any]]
# return the workflow to its initial state between probes (a fresh session /
# cart / draft). Optional; defaults to a no-op for a stateless target.
Reset = Callable[[], None]


# ---------------------------------------------------------------------------
# The operator-declared workflow spec
# ---------------------------------------------------------------------------


class WorkflowStep(BaseModel):
    """One node of the operator's declared state machine.

    ``effect`` and ``replay_effect`` are declarative predicate ASTs (the tiny
    all/any/not/eq/ieq/contains/icontains/in/min_len/gt/ge language the
    predicate oracle evaluates) over the observed post-state:

      * ``effect`` is TRUE iff this step actually took effect (e.g. after a
        legitimate ``ship`` the state shows ``{"shipped": true}``). It is what a
        step-skip probe checks: if it holds after calling the step WITHOUT its
        ``requires``, the guard was not enforced.
      * ``replay_effect`` (optional, meaningful only for a ``once`` step) is TRUE
        iff the action took effect MORE than the one time it is permitted (e.g.
        ``{"gt": [{"var": "redeemed_count"}, 1]}``). It is what a replay probe
        checks after applying the action twice.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    method: str = "POST"
    path: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    requires: tuple[str, ...] = ()
    once: bool = False
    effect: dict[str, Any] = Field(
        description="Predicate over post-state: TRUE iff this step took effect."
    )
    replay_effect: dict[str, Any] | None = Field(
        default=None,
        description="Predicate over post-state: TRUE iff a once-only step applied >1 time.",
    )


class TamperProbe(BaseModel):
    """A price/quantity parameter-tampering probe against one step.

    ``overrides`` replaces the step's params with tampered values (a negative or
    overflow quantity, a tampered unit price); ``danger`` is a predicate over the
    observed post-state that is TRUE iff the tampered value was accepted into a
    dangerous state (e.g. ``{"eq": [{"var": "qty"}, -5]}`` — the store persisted
    a negative quantity — or ``{"gt": [{"var": "credit"}, 0]}`` — a debit turned
    into a credit)."""

    model_config = ConfigDict(extra="forbid")

    step: str
    overrides: dict[str, Any]
    danger: dict[str, Any]
    label: str = "parameter tampering"


class WorkflowSpec(BaseModel):
    """An ordered state machine plus the tampering probes to try against it."""

    model_config = ConfigDict(extra="forbid")

    name: str
    steps: tuple[WorkflowStep, ...]
    tamper_probes: tuple[TamperProbe, ...] = ()

    def step(self, name: str) -> WorkflowStep:
        for s in self.steps:
            if s.name == name:
                return s
        raise KeyError(f"no workflow step named {name!r}")

    def _prereq_chain(self, name: str, _seen: set[str] | None = None) -> list[WorkflowStep]:
        """The transitive `requires` of ``name`` (excluding ``name`` itself),
        deduplicated and returned in dependency-first order — the legitimate
        prefix to walk before exercising or replaying a step."""
        seen = _seen if _seen is not None else set()
        chain: list[WorkflowStep] = []
        for req in self.step(name).requires:
            if req in seen:
                continue
            seen.add(req)
            for prior in self._prereq_chain(req, seen):
                if prior not in chain:
                    chain.append(prior)
            chain.append(self.step(req))
        return chain


# ---------------------------------------------------------------------------
# Confirmation helper — one place that talks to the oracle
# ---------------------------------------------------------------------------


def _confirm(
    *,
    title: str,
    summary: str,
    surface: str,
    observed_state: Mapping[str, Any],
    predicate: Mapping[str, Any],
    severity: str = "High",
) -> ConfirmedFinding | None:
    """Adjudicate ``predicate`` over the observed post-state through the
    predicate / achieved-state oracle. Returns a `ConfirmedFinding` only when the
    oracle fires — there is no assertion-only path — and `None` otherwise."""
    context = FindingContext.from_predicate(
        dict(observed_state), dict(predicate), bug_class=BUG_CLASS
    )
    finding = {
        "title": title,
        "bug_class": BUG_CLASS,
        "severity": severity,
        "surface": surface,
        "summary": summary,
    }
    return confirm_finding(finding, context)


def _noop_reset() -> None:
    return None


# ---------------------------------------------------------------------------
# The three violation probes
# ---------------------------------------------------------------------------


def probe_step_skip(
    spec: WorkflowSpec,
    step: WorkflowStep,
    perform: Perform,
    read_state: ReadState,
    reset: Reset = _noop_reset,
) -> ConfirmedFinding | None:
    """Out-of-order / skipped-prerequisite abuse.

    From a fresh workflow, perform ``step`` WITHOUT first performing any of its
    ``requires``. Read the post-state and ask the oracle whether ``step.effect``
    holds anyway — i.e. the guarded action took effect despite its precondition
    being unmet. A correctly-guarded workflow rejects the call, ``effect`` is
    false, and this returns ``None`` (no false positive on a well-behaved app)."""
    if not step.requires:
        return None  # nothing to skip — not an out-of-order candidate
    reset()
    perform(step, step.params)
    observed = read_state()
    missing = ", ".join(step.requires)
    return _confirm(
        title=f"Workflow step-skip: {step.name} reached without {missing}",
        summary=(
            f"The workflow step {step.name!r} took effect even though its required "
            f"predecessor step(s) [{missing}] were never performed. The state-machine "
            f"guard is not enforced server-side, so an attacker can jump straight to a "
            f"privileged transition (e.g. ship/fulfil without pay, or activate without "
            f"verify) by issuing the later request directly."
        ),
        surface=f"{step.method} {step.path or step.name}",
        observed_state=observed,
        predicate=step.effect,
    )


def probe_replay(
    spec: WorkflowSpec,
    step: WorkflowStep,
    perform: Perform,
    read_state: ReadState,
    reset: Reset = _noop_reset,
) -> ConfirmedFinding | None:
    """Sequential replay of a one-time action (idempotency / once-token failure).

    Distinct from ``scanner.race`` (which wins a *concurrent* check-then-act
    window): this replays a should-be-once action **sequentially** — the first
    application fully commits, then the same action is issued again. From a fresh
    workflow it legitimately walks the step's prerequisites, applies the step
    once, then applies it a second time, and asks the oracle whether
    ``replay_effect`` holds (the action took effect more than the one time it is
    permitted). Only meaningful for a ``once`` step that declares a
    ``replay_effect`` predicate; other steps return ``None``."""
    if not step.once or step.replay_effect is None:
        return None
    reset()
    for prior in spec._prereq_chain(step.name):
        perform(prior, prior.params)
    perform(step, step.params)  # first, legitimate application
    perform(step, step.params)  # the replay
    observed = read_state()
    return _confirm(
        title=f"One-time action replayed: {step.name}",
        summary=(
            f"The one-time action {step.name!r} took effect more than once when the "
            f"identical request was replayed sequentially. The action is not idempotent "
            f"and its single-use guard (once-token / server-side state) is missing, so a "
            f"coupon / credit / referral bonus can be redeemed repeatedly by resubmitting "
            f"the same request."
        ),
        surface=f"{step.method} {step.path or step.name}",
        observed_state=observed,
        predicate=step.replay_effect,
    )


def probe_tamper(
    spec: WorkflowSpec,
    tamper: TamperProbe,
    perform: Perform,
    read_state: ReadState,
    reset: Reset = _noop_reset,
) -> ConfirmedFinding | None:
    """Price / quantity parameter tampering (negative or overflow value).

    Legitimately walks the target step's prerequisites, then performs the step
    with the tampered ``overrides`` in place of its params, reads the post-state,
    and asks the oracle whether ``danger`` holds — the tampered value was accepted
    into a dangerous state. A server that clamps/validates the value fails the
    predicate and this returns ``None``."""
    step = spec.step(tamper.step)
    reset()
    for prior in spec._prereq_chain(step.name):
        perform(prior, prior.params)
    perform(step, tamper.overrides)
    observed = read_state()
    tampered = ", ".join(f"{k}={v!r}" for k, v in tamper.overrides.items())
    return _confirm(
        title=f"Parameter tampering accepted on {step.name}: {tampered}",
        summary=(
            f"The step {step.name!r} accepted a tampered parameter ({tampered}) and the "
            f"workflow landed in a dangerous state. Server-side validation of the "
            f"price/quantity is missing, so an attacker can drive a negative or overflow "
            f"value (e.g. a negative quantity that credits the account, or a tampered "
            f"unit price) straight into the persisted order/balance."
        ),
        surface=f"{step.method} {step.path or step.name}",
        observed_state=observed,
        predicate=tamper.danger,
    )


def detect_workflow_abuse(
    spec: WorkflowSpec,
    perform: Perform,
    read_state: ReadState,
    *,
    reset: Reset = _noop_reset,
) -> list[ConfirmedFinding]:
    """Run every violation probe the ``spec`` supports and return only the
    oracle-CONFIRMED findings.

    For each step with prerequisites, a step-skip probe; for each ``once`` step
    with a ``replay_effect``, a sequential-replay probe; for each declared
    ``TamperProbe``, a tampering probe. Each probe confirms strictly through the
    predicate / achieved-state oracle over the observed post-state, so a benign,
    correctly-guarded workflow yields an empty list. Findings are returned in a
    deterministic order (skips, then replays, then tampers, in spec order)."""
    findings: list[ConfirmedFinding] = []
    for step in spec.steps:
        f = probe_step_skip(spec, step, perform, read_state, reset)
        if f is not None:
            findings.append(f)
    for step in spec.steps:
        f = probe_replay(spec, step, perform, read_state, reset)
        if f is not None:
            findings.append(f)
    for tamper in spec.tamper_probes:
        f = probe_tamper(spec, tamper, perform, read_state, reset)
        if f is not None:
            findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# A local, deliberately-broken workflow — and its correctly-guarded twin
# ---------------------------------------------------------------------------
#
# These exist ONLY to prove the detector against real traffic, exactly as
# verify.confirmation stands up a vulnerable SQLi demo and a safe twin. The
# broken app models an order/coupon workflow whose server forgets three guards:
# it ships without payment (step-skip), redeems a coupon repeatedly (replay), and
# persists a negative cart quantity (tampering). The guarded twin enforces all
# three, so the same probes fire nothing against it — the negative control that
# proves the detector does not rubber-stamp.


class _WorkflowState:
    """The mutable server-side state a demo workflow request mutates and a
    ``/state`` read exposes. A fresh instance per session models the reset."""

    def __init__(self) -> None:
        self.qty = 0
        self.checked_out = False
        self.paid = False
        self.shipped = False
        self.redeemed_count = 0

    def snapshot(self) -> dict[str, Any]:
        return {
            "qty": self.qty,
            "checked_out": self.checked_out,
            "paid": self.paid,
            "shipped": self.shipped,
            "redeemed_count": self.redeemed_count,
        }


class _WorkflowHandler(BaseHTTPRequestHandler):
    """Order workflow: /add /checkout /pay /ship /redeem, and /state to read.

    Subclasses set ``enforce`` — the guarded twin (True) checks every
    precondition, the broken one (False) does not."""

    enforce: bool = False
    state: _WorkflowState = _WorkflowState()

    def log_message(self, *args: object) -> None:  # keep the demo quiet
        return

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if urllib.parse.urlsplit(self.path).path == "/state":
            self._reply(200, type(self).state.snapshot())
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        st = type(self).state
        enforce = type(self).enforce
        path = urllib.parse.urlsplit(self.path).path
        form = self._form()

        if path == "/reset":
            type(self).state = _WorkflowState()
            self._reply(200, {"ok": True})
            return

        if path == "/add":
            qty = int(form.get("qty", "1"))
            # The guarded twin rejects non-positive quantities; the broken one
            # persists whatever it is handed (negative-quantity tampering).
            if enforce and qty <= 0:
                self._reply(400, {"error": "quantity must be positive"})
                return
            st.qty = qty
            self._reply(200, {"qty": st.qty})
            return

        if path == "/checkout":
            if enforce and st.qty <= 0:
                self._reply(400, {"error": "empty cart"})
                return
            st.checked_out = True
            self._reply(200, {"checked_out": True})
            return

        if path == "/pay":
            if enforce and not st.checked_out:
                self._reply(400, {"error": "not checked out"})
                return
            st.paid = True
            self._reply(200, {"paid": True})
            return

        if path == "/ship":
            # THE step-skip bug: the broken app ships without checking payment.
            if enforce and not st.paid:
                self._reply(403, {"error": "not paid"})
                return
            st.shipped = True
            self._reply(200, {"shipped": True})
            return

        if path == "/redeem":
            # THE replay bug: the broken app re-applies the coupon every time;
            # the guarded twin redeems at most once.
            if enforce and st.redeemed_count >= 1:
                self._reply(409, {"error": "coupon already redeemed"})
                return
            st.redeemed_count += 1
            self._reply(200, {"redeemed_count": st.redeemed_count})
            return

        self._reply(404, {"error": "not found"})


class BrokenWorkflowHandler(_WorkflowHandler):
    """The deliberately-broken workflow: ships unpaid, replays coupons, takes a
    negative quantity."""

    enforce = False


class GuardedWorkflowHandler(_WorkflowHandler):
    """The correctly-guarded twin: the negative control that fires nothing."""

    enforce = True


def demo_spec() -> WorkflowSpec:
    """The `WorkflowSpec` describing the demo order/coupon workflow — the operator
    declaration the loopback proof drives."""
    return WorkflowSpec(
        name="demo-order-workflow",
        steps=(
            WorkflowStep(
                name="add", path="/add", params={"qty": 1},
                effect={"gt": [{"var": "qty"}, 0]},
            ),
            WorkflowStep(
                name="checkout", path="/checkout", requires=("add",),
                effect={"eq": [{"var": "checked_out"}, True]},
            ),
            WorkflowStep(
                name="pay", path="/pay", requires=("checkout",),
                effect={"eq": [{"var": "paid"}, True]},
            ),
            WorkflowStep(
                name="ship", path="/ship", requires=("pay",),
                effect={"eq": [{"var": "shipped"}, True]},
            ),
            WorkflowStep(
                name="redeem", path="/redeem", once=True,
                effect={"gt": [{"var": "redeemed_count"}, 0]},
                replay_effect={"gt": [{"var": "redeemed_count"}, 1]},
            ),
        ),
        tamper_probes=(
            TamperProbe(
                step="add",
                overrides={"qty": -5},
                danger={"eq": [{"var": "qty"}, -5]},
                label="negative cart quantity",
            ),
        ),
    )


@contextlib.contextmanager
def _local_workflow(handler_cls: type[_WorkflowHandler]) -> Iterator[str]:
    """Run ``handler_cls`` on 127.0.0.1:<ephemeral> for the block, yielding its
    base URL. Each entry gets a fresh state so runs are independent."""
    handler_cls.state = _WorkflowState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="bizlogic-demo", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


_USER_AGENT = "CRUCIBLE-bizlogic/1.0 (localhost workflow self-check)"


def _http_post(base_url: str, path: str, params: Mapping[str, Any]) -> dict[str, Any]:
    data = urllib.parse.urlencode({k: str(v) for k, v in params.items()}).encode("utf-8")
    req = urllib.request.Request(
        base_url + path, data=data, method="POST", headers={"User-Agent": _USER_AGENT}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (loopback only)
            return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:  # a rejected transition is a normal outcome
        return {"status": e.code, "body": e.read().decode("utf-8", "replace")}


def _http_state(base_url: str) -> dict[str, Any]:
    req = urllib.request.Request(base_url + "/state", headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (loopback only)
        return json.loads(resp.read().decode("utf-8", "replace"))


def confirm_against_local_workflow(
    app: type[_WorkflowHandler] = BrokenWorkflowHandler,
) -> list[ConfirmedFinding]:
    """Drive a REAL local workflow target through the detector.

    Stands up ``app`` on loopback, builds ``perform``/``read_state``/``reset``
    over real HTTP, and runs ``detect_workflow_abuse`` against ``demo_spec()``.
    Against ``BrokenWorkflowHandler`` it returns the oracle-confirmed step-skip,
    replay, and tampering findings; against ``GuardedWorkflowHandler`` it returns
    an empty list — the reproducible artifact proving a real target drives real
    confirmed findings via fired oracle signals, and that a guarded workflow does
    not rubber-stamp."""
    spec = demo_spec()
    with _local_workflow(app) as base_url:
        def perform(step: WorkflowStep, params: Mapping[str, Any]) -> Any:
            return _http_post(base_url, step.path, params)

        def read_state() -> Mapping[str, Any]:
            return _http_state(base_url)

        def reset() -> None:
            _http_post(base_url, "/reset", {})

        return detect_workflow_abuse(spec, perform, read_state, reset=reset)
