"""eval.corpus.vulnapp_manifest — the ground-truth manifest for the loopback benchmark app.

The A/B no-regression harness (``eval.ab``) stands up the in-process, deliberately-vulnerable loopback
target (``eval.benchmark_app.serve``) and scores each arm's findings against the planted-bug ground truth.
This module is the NAMED home of that ground truth — the ``list[ExpectedFinding]`` ab.py scores against.

SINGLE SOURCE OF TRUTH (no drift). The authoritative ground truth for this app is already
``eval.benchmark_app.benchmark_corpus`` — the exact manifest the signed public-benchmark baseline is scored
against (eleven planted bugs; eight SAFE controls that must never be flagged). Re-typing the eleven findings
here would create a SECOND list that must agree with the first by hand — a latent bug the day the app grows a
twelfth bug. So this manifest DERIVES from ``benchmark_corpus`` instead of restating it: ab.py and the public
benchmark baseline therefore score against byte-identical ground truth BY CONSTRUCTION. What this module adds
is the eval-corpus SHAPE (a stable, importable ``ExpectedFinding`` list + a ``CorpusTarget`` builder keyed on
a base_url) and a name, so the harness depends on a manifest, not on reaching into the app module.

The locations are written in CRUCIBLE's own vocabulary (param-level bugs as ``path?param``; the two
host/endpoint-level classes as the ``request:<check-id>`` token), so the comparative scorer
(``eval.validation.score``) lines a produced finding up with its label. Because the ground truth is COMPLETE,
anything an arm reports off-manifest (e.g. on a SAFE control) is a false positive by construction — which is
what makes the asymmetric no-regression gate's FP column honest.

FATAL-2 / import hygiene: this module imports only the eval-plane ``benchmark_app`` + ``validation`` (both
stdlib + pydantic, no ``engage``, no agents), so importing the manifest never pulls the heavy offense plane.

NOTE on imports. ``eval/corpus.py`` (the corpus LOADER) and ``eval/corpus/`` (this ground-truth DATA dir)
share a name, and the module shadows the directory — so ``framework.v2.eval.corpus`` is the loader, and this
file cannot be reached by a dotted ``import``. Like everything else under ``corpus/`` (``starter.json``, the
vulnpy/vulnjs samples) it is reached by FILE PATH — ``eval.ab`` loads it with ``importlib`` from
``Path(__file__)...``. So it uses ABSOLUTE imports (relative ones need a parent package that the shadow
denies it).
"""
from __future__ import annotations

from framework.v2.eval.benchmark_app import benchmark_corpus
from framework.v2.eval.validation import CorpusTarget, ExpectedFinding

# A stable identity for this corpus entry (the single app-key the A/B snapshot/gate is keyed on).
VULNAPP_NAME = "crucible-benchmark-app"

# A base_url is irrelevant to the planted-bug LABELS (it only sets where traffic goes), so a placeholder is
# enough to extract the canonical ground truth at import time. ab.py rebuilds the target with the real
# ephemeral loopback URL via :func:`vulnapp_target`.
_PLACEHOLDER_BASE = "http://127.0.0.1"


def vulnapp_expected() -> list[ExpectedFinding]:
    """The complete planted-bug ground truth for the loopback benchmark app — the eleven
    :class:`~eval.validation.ExpectedFinding` labels ab.py scores each arm against. Derived from the
    authoritative :func:`eval.benchmark_app.benchmark_corpus`, so it can never drift from the signed public
    baseline's ground truth. A fresh list each call (callers may filter/extend without mutating a shared
    constant)."""
    return list(benchmark_corpus(_PLACEHOLDER_BASE).expected)


def vulnapp_target(base_url: str) -> CorpusTarget:
    """The labelled loopback :class:`~eval.validation.CorpusTarget` for ``base_url`` (the ephemeral
    ``http://127.0.0.1:<port>`` that :func:`eval.benchmark_app.serve` yields), carrying the full ground-truth
    manifest. A thin pass-through to :func:`eval.benchmark_app.benchmark_corpus` so the A/B harness scores
    against exactly the public baseline's ground truth."""
    return benchmark_corpus(base_url)


# The canonical ground-truth list, materialised once for callers that want the labels without standing up the
# app. ``vulnapp_expected()`` returns a fresh copy of these.
VULNAPP_EXPECTED: list[ExpectedFinding] = vulnapp_expected()
