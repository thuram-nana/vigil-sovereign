"""Hard-prune equivalence proof for the DELEGATE account-creation cap consumer
(`ActorScope.creation_allowed`, sigil/agents/actor_scope.py).

creation_cap is a FOLD bearer with a PAIR key: `creation_created` = {(service, origin): count}, count-add.
The consumer used to full-scan the spine from genesis, counting applied `account.create` steps whose
service OR origin matches the query (relabelling the same origin cannot mint extra accounts). It now seeds
that count from `SnapshotState.load(store).creation_counter()` — summing over EITHER matching dimension —
then folds only the LIVE records `[base_seq..T]` via `iter_records(since_seq=st.base_seq - 1)`.

This is the FATAL-false-clean bearer: if the seed is dropped, or the histogram is keyed on a single flat
dimension (service only), the count silently drops below the cap and mass account creation is WRONGLY
allowed. The two proofs pin both failure modes shut:

  (A) IDENTITY — under the real (empty, Slice-C) snapshot the rewired consumer returns the known-correct
      verdict: base_seq==0 => since_seq==-1 (full genesis scan) + empty seed => byte-identical to the old
      scan. The `url=""` vs `url=set` contrast isolates the ORIGIN dimension's contribution to the verdict.
  (B) SPLIT — the associativity proof. The two creations that reach the cap for `acme` are BOTH pruned into
      the prefix [0..K); the live window carries NONE that match acme. So:
        * a SEEDLESS fold (window only) sees 0 acme creations => UNDER cap => would WRONGLY allow.
        * a FLAT service-only seed drops the same-origin/diff-service prefix row (seq 1) => seed 1 => UNDER
          cap => would WRONGLY allow.
      The correct PAIR-keyed, seeded fold returns the full-scan verdict (NOT allowed). `widgetco` spans the
      seam (seq 2 pruned into the seed, seq 3 live) to prove the count-add is associative across the split.

Record shape (actor.py execute, seq ~256): kind="event", source="agent",
  payload{signal:"web.actor.step", step_kind:"account.create", status:"applied", service, url}.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_creation_cap.py -q
"""
import tempfile

from sigil.agents.actor_scope import ActorScope, _origin
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

CAP = 2

# The query under test and its canonical origin (default port made explicit by _origin()).
ACME = "acme"
ACME_URL = "https://acme.example/signup"
ACME_ORIGIN = "https://acme.example:443"
# Same ORIGIN as acme but a DIFFERENT service label — the OR-predicate crux (relabel-the-origin attack).
ACME_EU = "acme-eu"
ACME_EU_URL = "https://acme.example/eu-signup"
# A second query whose two creations straddle the prune seam (one pruned, one live).
WIDGET = "widgetco"
WIDGET_URL = "https://widgetco.example/join"
WIDGET_ORIGIN = "https://widgetco.example:443"
# An under-cap service that exists only in the LIVE window (proves the True branch + a live-only fold).
SOLO = "solo"
SOLO_URL = "https://solo.example/register"


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _create(store, service, url, *, status="applied"):
    """Append an account.create web-actor step exactly as actor.execute() commits it (real shape)."""
    return store.append(kind="event", source="agent", actor="ACTOR",
                        payload={"signal": "web.actor.step", "step_kind": "account.create",
                                 "status": status, "service": service, "url": url})


def _seed(store):
    """Craft the record stream. Returns K = the split seq (first LIVE seq). Layout (seq):
        0 acme      applied @acme.example      -> prefix; matches the acme query by SERVICE (and origin)
        1 acme-eu   applied @acme.example      -> prefix; SAME origin, DIFFERENT service -> the OR crux
        2 widgetco  applied @widgetco.example  -> prefix; the pruned half of the seam-spanning widget count
      --- K=3 (prune point == start of the live window) ---
        3 widgetco  applied @widgetco.example  -> live;   the live half of widgetco (seam-add associativity)
        4 acme      QUEUED  @acme.example       -> live;   matches svc/origin/kind but NOT applied -> ignored
        5 solo      applied @solo.example       -> live;   a fresh under-cap service, live-only
    """
    assert _create(store, ACME, ACME_URL) == 0
    assert _create(store, ACME_EU, ACME_EU_URL) == 1        # same origin as acme, different service label
    assert _create(store, WIDGET, WIDGET_URL) == 2
    k = store.next_seq                                       # K == 3 (first live seq)
    assert _create(store, WIDGET, WIDGET_URL) == 3
    assert _create(store, ACME, ACME_URL, status="queued") == 4   # status gate -> must NOT count
    assert _create(store, SOLO, SOLO_URL) == 5
    return k


# ---- (A) IDENTITY: rewired consumer == known-correct verdict under the empty (Slice-C) snapshot ---------
def test_identity_known_correct_under_empty_snapshot():
    store = _store()
    _seed(store)
    scope = ActorScope(creation_cap=CAP)

    # acme: 2 applied creations reach the cap -> NOT allowed. Crucially, only ONE (seq0) matches by service;
    # the second (seq1) matches only by ORIGIN (different service). So the verdict depends on the OR predicate.
    assert scope.creation_allowed(store, ACME, ACME_URL) is False

    # ORIGIN isolation: query the SAME service with an EMPTY url disables the origin dimension, so only
    # service=="acme" counts (seq0) -> n=1 -> UNDER cap -> allowed. The flip vs the line above proves seq1
    # (same origin, different service) is load-bearing for the acme verdict.
    assert scope.creation_allowed(store, ACME, "") is True

    # widgetco: 2 applied creations (seq2 + seq3) reach the cap -> NOT allowed.
    assert scope.creation_allowed(store, WIDGET, WIDGET_URL) is False

    # solo: a single applied creation -> UNDER cap -> allowed.
    assert scope.creation_allowed(store, SOLO, SOLO_URL) is True

    # a service with no history at all -> empty count -> allowed.
    assert scope.creation_allowed(store, "brandnew", "https://brandnew.example/x") is True


# ---- (B) SPLIT: fold(build([0..K))) + fold([K..T]) == scan([0..T]); the SEED bears the verdict -----------
def test_split_seed_bears_the_cap_verdict(monkeypatch):
    store = _store()
    k = _seed(store)
    scope = ActorScope(creation_cap=CAP)

    # Reference verdicts from the REAL (empty) load -> a full genesis scan.
    full_acme = scope.creation_allowed(store, ACME, ACME_URL)
    full_widget = scope.creation_allowed(store, WIDGET, WIDGET_URL)
    full_solo = scope.creation_allowed(store, SOLO, SOLO_URL)
    assert full_acme is False and full_widget is False and full_solo is True

    # Fold the prefix [0..K) into a synthetic snapshot, exactly as a Slice-D/E prune would at prune time,
    # then window the consumer to the LIVE [K..T]. trusted_pubkey is irrelevant to the creation fold (it
    # verifies no signatures).
    prefix = [r for r in store.iter_records() if r.seq < k]
    synthetic = build(prefix, trusted_pubkey="", base_seq=k, snapshot_seq=k - 1)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: synthetic))

    split_acme = scope.creation_allowed(store, ACME, ACME_URL)
    split_widget = scope.creation_allowed(store, WIDGET, WIDGET_URL)
    split_solo = scope.creation_allowed(store, SOLO, SOLO_URL)

    # THE PROOF: fold(prefix seed) + fold(live) == the full genesis scan, for every query.
    assert split_acme is False and split_acme == full_acme
    assert split_widget is False and split_widget == full_widget
    assert split_solo is True and split_solo == full_solo

    # --- non-triviality guards: the prefix is non-empty, ends just below K, and is a mid-stream split ---
    assert [r.seq for r in prefix] == [0, 1, 2] and 0 < k < store.next_seq
    assert synthetic.base_seq == k and synthetic.snapshot_seq == k - 1

    # The seed histogram is PAIR-keyed. seq0 and seq1 share the SAME origin under DIFFERENT services.
    counter = synthetic.creation_counter()
    assert counter[(ACME, ACME_ORIGIN)] == 1
    assert counter[(ACME_EU, ACME_ORIGIN)] == 1        # <-- the OR crux row: different service, SAME origin
    assert counter[(WIDGET, WIDGET_ORIGIN)] == 1

    # The acme query has ZERO matching applied creations in the LIVE window -> its verdict rides ENTIRELY on
    # the seed. A fold that dropped the seed would count 0 and WRONGLY return allowed (the FATAL false-clean).
    def _live_acme_matches():
        return [r for r in store.iter_records(since_seq=k - 1)
                if r.payload.get("step_kind") == "account.create" and r.payload.get("status") == "applied"
                and (r.payload.get("service") == ACME or _origin(r.payload.get("url", "")) == ACME_ORIGIN)]
    assert _live_acme_matches() == [], "no applied acme creation lives in [K..T]"
    seedless_n = len(_live_acme_matches())
    assert seedless_n < CAP, "seedless (dropped-seed) fold is UNDER cap -> would wrongly ALLOW past the cap"

    # The PAIR/OR key is decisive too: a FLAT service-only seed would drop seq1 (different service) -> seed
    # would be 1 (only seq0) -> UNDER cap -> wrongly allowed. The real OR-summed seed is 2 -> at cap.
    or_seed = sum(cnt for (svc, org), cnt in counter.items() if svc == ACME or org == ACME_ORIGIN)
    flat_service_seed = sum(cnt for (svc, org), cnt in counter.items() if svc == ACME)
    assert or_seed == 2 and flat_service_seed == 1
    assert or_seed >= CAP and flat_service_seed < CAP, \
        "same-origin/different-service prefix row is load-bearing: a flat single-dim key under-counts"

    # Seam-add associativity: widgetco spans the split (seq2 pruned into the seed, seq3 live). The seeded
    # fold sums 1 (seed) + 1 (live) == 2 == cap -> not allowed, matching the full scan.
    live_widget = sum(1 for r in store.iter_records(since_seq=k - 1)
                      if r.payload.get("service") == WIDGET and r.payload.get("step_kind") == "account.create"
                      and r.payload.get("status") == "applied")
    assert live_widget == 1, "the live half of the seam-spanning widgetco count"
