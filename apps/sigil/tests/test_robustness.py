"""SIGIL production-hardening — robustness crash-sites + honesty seams (audit ROBUST/SEAM findings).

Covers:
  FIX 1  KernelClassifier.classify never crashes on NON-OBJECT kernel JSON → fail-closed A3.
  FIX 2  VectorIndex.last_indexed_seq distinguishes a genuinely-empty collection (→ -1) from a
         backend OUTAGE (→ raise VectorBackendUnavailable, never a silent full reindex).

Run: ~/.sigil/venv/bin/python tests/test_robustness.py
"""
import subprocess as _sp

import httpx

import sigil.agents.kernel_classify as kc_mod
from sigil.agents.base import Tier
from sigil.agents.kernel_classify import KernelClassifier
from sigil.vectors.index import VectorBackendUnavailable, VectorIndex


class _FakeProc:
    """Stand-in for subprocess.CompletedProcess (only the fields classify() reads)."""
    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode


# ---- FIX 1: kernel_classify fails closed on non-object JSON (no AttributeError crash) -------------
def test_kernel_classify_non_object_json_fails_closed_to_a3():
    kc = KernelClassifier(kernel_bin="/bin/true")   # never actually executed — subprocess.run patched
    orig = kc_mod.subprocess.run
    try:
        # A bare string / number / null / array / bool is valid JSON but not a dict; `.get("tier")`
        # would raise AttributeError. Contract: any non-object → fail-closed to the MOST-gated tier.
        for payload in ("null", "5", '"x"', "[1,2,3]", "true", "3.14"):
            kc_mod.subprocess.run = (lambda p: (lambda *a, **k: _FakeProc(p + "\n", 0)))(payload)
            t = kc.classify("hid.pointer.move")
            assert t == Tier.A3, f"non-object JSON {payload!r} must fail-closed to A3 (no crash), got {t}"
    finally:
        kc_mod.subprocess.run = orig


def test_kernel_classify_valid_object_json_still_maps_tier():
    kc = KernelClassifier(kernel_bin="/bin/true")
    orig = kc_mod.subprocess.run
    try:
        kc_mod.subprocess.run = lambda *a, **k: _FakeProc('{"tier": "A1"}\n', 0)
        assert kc.classify("hid.pointer.move") == Tier.A1, "a valid object still maps its tier"
        kc_mod.subprocess.run = lambda *a, **k: _FakeProc('{"tier": "A2"}\n', 0)
        assert kc.classify("hid.type") == Tier.A2
        kc_mod.subprocess.run = lambda *a, **k: _FakeProc("{}\n", 0)
        assert kc.classify("x") == Tier.A3, "an object missing 'tier' → A3"
        kc_mod.subprocess.run = lambda *a, **k: _FakeProc('{"tier": "WAT"}\n', 0)
        assert kc.classify("x") == Tier.A3, "an unknown tier string → A3"
    finally:
        kc_mod.subprocess.run = orig


def test_kernel_classify_preserves_existing_failclosed_paths():
    """The pre-existing fail-closed behaviour (missing binary / timeout / non-zero exit / empty) is
    unchanged — only the non-object crash is fixed."""
    kc = KernelClassifier(kernel_bin="/bin/true")
    orig = kc_mod.subprocess.run
    try:
        kc_mod.subprocess.run = lambda *a, **k: _FakeProc('{"tier": "A0"}\n', 1)   # non-zero exit
        assert kc.classify("x") == Tier.A3, "non-zero exit → A3"
        kc_mod.subprocess.run = lambda *a, **k: _FakeProc("", 0)                    # empty stdout
        assert kc.classify("x") == Tier.A3, "empty output → A3"

        def _timeout(*a, **k):
            raise _sp.TimeoutExpired(cmd="sigil-kernel", timeout=1)
        kc_mod.subprocess.run = _timeout
        assert kc.classify("x") == Tier.A3, "timeout → A3"

        def _oserr(*a, **k):
            raise OSError("no such binary")
        kc_mod.subprocess.run = _oserr
        assert kc.classify("x") == Tier.A3, "missing binary (OSError) → A3"
    finally:
        kc_mod.subprocess.run = orig
    assert kc.classify("") == Tier.A3 and kc.classify("   ") == Tier.A3, "empty/blank tool → A3"


# ---- FIX 2: vectors outage-vs-empty distinction --------------------------------------------------
class _Pt:
    def __init__(self, seq):
        self.payload = {"seq": seq}


class _FakeClient:
    """Minimal stand-in for QdrantClient — only `scroll` is exercised by last_indexed_seq."""
    def __init__(self, *, exc: BaseException | None = None, points=None):
        self._exc = exc
        self._points = points if points is not None else []

    def scroll(self, *a, **k):
        if self._exc is not None:
            raise self._exc
        return (self._points, None)


def _bare_index(client) -> VectorIndex:
    """A VectorIndex with a fake client, bypassing __init__ (which would open a real Qdrant)."""
    vi = VectorIndex.__new__(VectorIndex)
    vi.client = client
    vi.collection = "test-collection"
    return vi


def test_vectors_empty_collection_returns_minus1():
    vi = _bare_index(_FakeClient(points=[]))
    assert vi.last_indexed_seq() == -1, "a genuinely empty/uncreated collection → -1 (correct)"


def test_vectors_reads_the_durable_cursor():
    vi = _bare_index(_FakeClient(points=[_Pt(42)]))
    assert vi.last_indexed_seq() == 42, "with points present, returns the highest indexed seq"


def test_vectors_outage_does_not_masquerade_as_empty():
    """The KEY fix: a backend OUTAGE must NOT return -1 (which the caller feeds into
    index_spine(since_seq=-1) → a destructive full re-embed of the whole corpus)."""
    vi = _bare_index(_FakeClient(exc=httpx.ConnectError("connection refused")))
    raised = False
    try:
        vi.last_indexed_seq()
    except VectorBackendUnavailable:
        raised = True
    assert raised, "an outage raises VectorBackendUnavailable — it never silently returns -1"


def test_vectors_query_shape_error_is_treated_as_empty_not_outage():
    """A non-outage query error (e.g. order_by needs a payload index) is legitimately 'treat as
    empty' → -1. This is non-destructive: index_spine upserts by id=seq (idempotent), never wipes."""
    vi = _bare_index(_FakeClient(exc=ValueError("order_by requires a keyword index on 'seq'")))
    assert vi.last_indexed_seq() == -1, "a query-shape error stays -1 (idempotent re-embed, no data loss)"


def test_vectors_outage_wrapped_in_a_cause_is_still_detected():
    """qdrant wraps transport errors; the classifier walks the __cause__/__context__ chain."""
    class _Wrapped(Exception):
        pass
    try:
        raise httpx.ConnectError("refused")
    except httpx.ConnectError as inner:
        w = _Wrapped("qdrant call failed")
        w.__cause__ = inner
        vi = _bare_index(_FakeClient(exc=w))
        raised = False
        try:
            vi.last_indexed_seq()
        except VectorBackendUnavailable:
            raised = True
        assert raised, "an outage wrapped as __cause__ is still detected as unreachable (not -1)"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} robustness (crash-site + honesty) guarantees hold")
