# calibration/ — calibrated exploitability scoring + the outcome ledger

This is what replaces the hardcoded `1.0`.

A finding used to be "confirmed" and carry a confidence of exactly `1.0`,
forever, no matter what happened to it afterward. Nothing measured whether
that number was honest. This layer replaces the constant with a probability
**learned from recorded outcomes**, and measures its own reliability.

## The contract

```
fit(ledger.pairs()) -> Calibrator
Calibrator.calibrate(raw_score, oracle_confirmed) -> probability in [0, 0.999]
```

The calibrated probability is fit from what findings *actually turned out to
be*. It is never `1.0` — probabilities clamp to `MAX_PROB` (0.999), the same
"a detector never claims certainty it cannot have" discipline the verify layer
uses.

## Three disciplines

1. **Learned, never hardcoded.** Isotonic regression (pure-Python
   Pool-Adjacent-Violators — no sklearn, no numpy) maps `raw_score` to the
   observed exploitable-rate. Even the boost an oracle-confirmed finding gets
   is the *empirically measured* rate among oracle-confirmed findings, not a
   constant. If confirmed findings historically turned out to be false
   positives, that learned prior shrinks and confirmation stops meaning
   certainty.

2. **Identity fallback under sparse data.** With fewer than `MIN_LABELS` (8)
   non-DISPUTED outcomes there is not enough signal to calibrate honestly, so
   the fit degrades to a passthrough (`Calibrator.method == "identity"`,
   `calibrate(s) == s`). We do not invent reliability we have not measured.

3. **Deterministic.** The ledger orders by a caller-supplied monotonic
   **sequence int**, never a wallclock — exactly like the world-model. Every
   fit and every metric is byte-stable and replayable.

## Ground truth

Each resolved finding gets one `OutcomeLabel`. Calibration needs a binary
"was it really exploitable?" target:

| label | target | meaning |
|---|---|---|
| `EXPLOITABLE` | 1.0 | confirmed real & reachable |
| `REMEDIATED` | 1.0 | was real, since fixed — the prediction was *correct* |
| `FALSE_POSITIVE` | 0.0 | the claim did not hold |
| `DISPUTED` | — | ground truth unknown; **excluded** from every fit and metric |

`DISPUTED` is the only label that never contributes. We do not guess ground
truth we do not have.

## The oracle prior

An oracle-confirmed finding (a deterministic verify/ oracle fired) is strong
evidence — but "strong" is a number the ledger teaches us, not `1.0`. We learn
`oracle_prior = P(exploitable | oracle_confirmed)` empirically (once there are
at least `MIN_ORACLE_LABELS` confirmed outcomes) and combine it with the
score via noisy-OR:

```
calibrated = 1 - (1 - isotonic(score)) * (1 - oracle_prior)
```

Two independent pieces of evidence stack, capped at `MAX_PROB`. If the ledger
has too few confirmed outcomes, no prior is learned and confirmation grants no
boost — honest silence over an invented number.

## Files

| Module | Purpose |
|---|---|
| `models.py` | `OutcomeLabel` enum; `Prediction` (raw_score, feature_hash, model_version, oracle_confirmed); `Outcome` (finding_id, label) with `label_to_target`; `Bin` and `CalibrationReport` (n, ece, brier, bins). |
| `ledger.py` | `OutcomeLedger` — append-only JSON store of `Prediction` → `Outcome` pairs, keyed by finding_id, ordered by seq int. `add_prediction` / `record_outcome` / `pairs()`; deterministic `to_json` / `from_json` / `save` / `load`. `LedgerError` on a duplicate, an unknown finding, or a corrupt document. |
| `calibrate.py` | `pav` (Pool-Adjacent-Violators); `fit` → `Calibrator` (isotonic or identity fallback, learned oracle prior); `Calibrator.calibrate`; `brier_score`, `measure_ece`, `reliability_report`. |
| `tests/` | PAV monotonicity, ECE improves after calibration on a skewed synthetic set, identity fallback under sparse data, learned (never-1.0) oracle prior, ledger round-trip. |

## Use

```python
from framework.v2.calibration import (
    OutcomeLedger, Prediction, Outcome, OutcomeLabel,
    fit, reliability_report,
)

led = OutcomeLedger()
led.add_prediction(Prediction(
    finding_id="F-001", raw_score=0.82, feature_hash="ab12",
    model_version="scorer-1", oracle_confirmed=True), seq=1)
# ... the operator later resolves it ...
led.record_outcome(Outcome(finding_id="F-001", label=OutcomeLabel.EXPLOITABLE), seq=2)

cal = fit(led.pairs())                     # isotonic, or identity if sparse
p = cal.calibrate(0.82, oracle_confirmed=True)   # a *learned* number, never 1.0

before = reliability_report(led.pairs(), None)   # raw-score reliability
after = reliability_report(led.pairs(), cal)     # calibrated reliability
print(before.ece, "->", after.ece)               # ECE should drop
```

## Status

Layer + tests only this wave. Wiring it into the scoring path — writing a
`Prediction` for every finding, recording `Outcome`s as the operator resolves
them, and reading `Calibrator.calibrate` in place of the old `1.0` — is the
next integration. It reads the verify layer's `oracle_confirmed` bit; it does
not reach back into it (no import cycle, by design).
