"""
intel.predict — AssetPredictor: attack-surface PREDICTION, as gated hypotheses.

From the assets we have observed, some others are *likely* to exist: an org that
exposes ``api`` and ``backend`` very probably has ``staging``/``dev`` too; a host
at ``10.15.4.2`` sits in a block whose neighbours are probably alive. Predicting
them lets recon look where the surface probably is instead of only where it has
already been seen.

The discipline that keeps this honest and in-scope:

  * A prediction is NEVER a graph fact. It is an `AssetHypothesis` — a labelled,
    GATED claim wrapping a `ScientificHypothesis` (prior + competing "does not
    exist" + residual, MECE) so the Scientific Confidence Engine can score it and
    say exactly how uncertain it is. Nothing is projected onto the world-model.

  * A prediction is NEVER auto-verified. `gated=True` means the operator approves
    before any collector/oracle touches it — prediction proposes WHERE to look;
    the existing oracle/verify stays the sole authority on what is real.

  * Priors are deliberately capped well below certainty (a prediction is a guess
    with a number on it, never a finding), and the roster is bounded with the cap
    logged — no silent flood.

Two inference modes, each clearly labelled: sibling-naming (strong, the primary)
and netblock-neighbour (weak, secondary, low prior).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..confidence.models import (
    AlternativeHypothesis,
    CandidateObservation,
    ScientificHypothesis,
)
from ..worldmodel.models import NodeKind
from .refs import EntityRef, canonicalize

# Common subdomain labels with a rough base rate of existing when an org is already
# exposing web infrastructure. Data, not code — tune without touching logic.
_COMMON_SUBDOMAINS: dict[str, float] = {
    "www": 0.55, "mail": 0.45, "api": 0.45, "staging": 0.40, "dev": 0.40,
    "admin": 0.38, "test": 0.35, "vpn": 0.32, "portal": 0.30, "app": 0.30,
    "beta": 0.28, "internal": 0.25, "git": 0.25, "ci": 0.22, "jenkins": 0.20,
    "grafana": 0.20, "kibana": 0.18, "backend": 0.30, "auth": 0.30, "sso": 0.28,
}
_PRIOR_CAP = 0.6                 # a prediction is never high-confidence
_MAX_PREDICTIONS_PER_APEX = 12   # bounded roster; the cap is reported, never silent


class AssetHypothesis(BaseModel):
    """A PREDICTED asset, as a gated scientific hypothesis. Never a fact, never
    auto-verified — a proposal for where to look next, with an honest number."""

    model_config = ConfigDict(extra="forbid")

    predicted: EntityRef
    apex: str = ""
    pattern: Literal["sibling-name", "netblock-neighbour"]
    rationale: str
    hypothesis: ScientificHypothesis
    status: Literal["predicted"] = "predicted"   # NEVER "confirmed" here
    gated: bool = True                            # operator approves before verification

    @property
    def prior(self) -> float:
        return self.hypothesis.prior

    @property
    def node_id(self) -> str:
        return self.predicted.node_id


def _make_hypothesis(pred: EntityRef, *, prior: float, pattern: str, refute_on: str) -> ScientificHypothesis:
    """Wrap a prediction in a MECE scientific hypothesis: exists vs does-not-exist,
    with a candidate observation (the cheap resolution test) attached for VOI."""
    prior = min(_PRIOR_CAP, max(0.01, prior))
    return ScientificHypothesis(
        id=f"PRED:{pred.node_id}",
        statement=f"{pred.node_id} exists (predicted by {pattern})",
        surface=pred.node_id, bug_class="asset-existence", prior=prior,
        alternatives=[AlternativeHypothesis(
            id=f"NX:{pred.node_id}", statement=f"{pred.node_id} does not exist",
            prior=1.0 - prior)],
        residual_prior=0.0, refute_on=refute_on)


def _resolution_candidate(pred: EntityRef) -> CandidateObservation:
    """The single decisive test for a predicted asset: does it resolve? (High TPR /
    low FPR — a name that resolves almost certainly exists.)"""
    return CandidateObservation(
        id=f"resolve:{pred.node_id}",
        statement=f"resolve {pred.node_id} (DNS / CT lookup)",
        tpr=0.95, fpr=0.03, cost=1.0)


class AssetPredictor:
    """Predicts likely assets from observed ones. Pure; emits gated hypotheses only."""

    def __init__(self, *, prior_cap: float = _PRIOR_CAP,
                 max_per_apex: int = _MAX_PREDICTIONS_PER_APEX) -> None:
        self._cap = prior_cap
        self._max = max_per_apex
        self.dropped_for_cap = 0   # how many candidates were trimmed (reported, not silent)

    # -- primary: sibling naming ---------------------------------------------

    def predict_siblings(self, observed_domains: list[str]) -> list[AssetHypothesis]:
        """Predict common sibling subdomains per apex. The prior for a sibling rises
        with how much infrastructure the org already exposes under that apex (a
        larger observed footprint ⇒ common siblings more likely)."""
        by_apex: dict[str, set[str]] = {}
        for raw in observed_domains:
            ref = canonicalize(NodeKind.DOMAIN, raw)
            name = ref.key
            apex = _apex_of(name)
            by_apex.setdefault(apex, set()).add(name)

        out: list[AssetHypothesis] = []
        for apex in sorted(by_apex):
            observed = by_apex[apex]
            observed_labels = {n[: -(len(apex) + 1)] for n in observed if n.endswith("." + apex)}
            footprint_boost = min(0.15, 0.03 * len(observed_labels))
            candidates: list[tuple[float, AssetHypothesis]] = []
            for label, base in _COMMON_SUBDOMAINS.items():
                if label in observed_labels:
                    continue
                pred = canonicalize(NodeKind.DOMAIN, f"{label}.{apex}")
                if pred.key in observed:
                    continue
                prior = min(self._cap, base + footprint_boost)
                rationale = (f"apex {apex} already exposes "
                             f"{sorted(observed_labels)[:6]} → sibling '{label}' likely")
                hyp = _make_hypothesis(pred, prior=prior, pattern="sibling-name",
                                       refute_on=f"{pred.node_id} returns NXDOMAIN")
                candidates.append((prior, AssetHypothesis(
                    predicted=pred, apex=apex, pattern="sibling-name",
                    rationale=rationale, hypothesis=hyp)))
            candidates.sort(key=lambda t: (-t[0], t[1].node_id))
            kept = candidates[: self._max]
            self.dropped_for_cap += max(0, len(candidates) - len(kept))
            out.extend(h for _, h in kept)
        return out

    # -- secondary: netblock neighbours --------------------------------------

    def predict_netblock_neighbours(self, observed_hosts: list[str],
                                    netblocks: list[str]) -> list[AssetHypothesis]:
        """Weak, low-prior prediction: given a live host inside a known netblock, the
        block's other addresses are plausibly alive. Deliberately low prior — this is
        a hint to enumerate, not a claim."""
        import ipaddress

        out: list[AssetHypothesis] = []
        nets = []
        for nb in netblocks:
            try:
                nets.append(ipaddress.ip_network(nb, strict=False))
            except ValueError:
                continue
        live = set()
        for h in observed_hosts:
            try:
                live.add(ipaddress.ip_address(canonicalize(NodeKind.HOST, h).key))
            except ValueError:
                continue
        for net in nets:
            if net.num_addresses > 1024:      # don't predict across large blocks
                continue
            for host_ip in list(net.hosts())[:6]:  # a small, bounded neighbourhood
                if host_ip in live:
                    continue
                pred = canonicalize(NodeKind.HOST, str(host_ip))
                prior = 0.15                   # weak by design
                hyp = _make_hypothesis(pred, prior=prior, pattern="netblock-neighbour",
                                       refute_on=f"{pred.node_id} does not respond")
                out.append(AssetHypothesis(
                    predicted=pred, apex="", pattern="netblock-neighbour",
                    rationale=f"{pred.node_id} is in announced block {net} with a live host",
                    hypothesis=hyp))
        return out

    def predict(self, *, observed_domains: list[str] | None = None,
                observed_hosts: list[str] | None = None,
                netblocks: list[str] | None = None) -> list[AssetHypothesis]:
        """All predictions, sibling-naming first, ordered by prior (highest first)."""
        out = self.predict_siblings(observed_domains or [])
        out += self.predict_netblock_neighbours(observed_hosts or [], netblocks or [])
        out.sort(key=lambda h: (-h.prior, h.node_id))
        return out


def _apex_of(name: str) -> str:
    """Registrable-ish apex: the last two labels (best-effort, no PSL dependency)."""
    parts = name.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name
