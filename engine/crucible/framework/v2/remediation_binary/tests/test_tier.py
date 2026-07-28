"""X2 — remediation is EARNED BY ORACLE SILENCE (never asserted); the CRS engine is a gated stub."""

from __future__ import annotations

import pytest

from framework.v2.remediation_binary.tier import (
    BinaryPatchTier,
    CapturedCrash,
    SanitizerSilenceTier,
    SymbolicCrashRepairTier,
)

_ASAN = "==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010"
_UBSAN = "runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'"
_CLEAN = "all checks passed; process exited 0"


def test_confirm_crash_drives_the_sanitizer_oracle() -> None:
    sig = SanitizerSilenceTier().confirm_crash(CapturedCrash(output=_ASAN))
    assert sig.fired is True
    assert sig.observed.get("best") == "asan"


def test_confirm_clean_output_does_not_fire() -> None:
    assert SanitizerSilenceTier().confirm_crash(CapturedCrash(output=_CLEAN)).fired is False


def test_remediated_true_only_when_before_fires_and_after_is_silent() -> None:
    t = SanitizerSilenceTier()
    assert t.remediated_if_silent(_ASAN, _CLEAN) is True         # fired → silent = fixed


def test_not_remediated_when_after_still_crashes() -> None:
    t = SanitizerSilenceTier()
    assert t.remediated_if_silent(_ASAN, _UBSAN) is False        # still crashing (different bug even)
    assert t.remediated_if_silent(_ASAN, _ASAN) is False


def test_not_remediated_when_before_never_crashed() -> None:
    """You cannot earn silence you never broke — a non-reproducing 'before' proves no fix."""
    t = SanitizerSilenceTier()
    assert t.remediated_if_silent(_CLEAN, _CLEAN) is False
    assert t.remediated_if_silent(_CLEAN, _ASAN) is False


def test_remediated_accepts_captured_crash_objects_too() -> None:
    t = SanitizerSilenceTier()
    assert t.remediated_if_silent(CapturedCrash(output=_ASAN), CapturedCrash(output=_CLEAN)) is True


def test_synthesize_patch_is_research_gated_on_the_working_tier() -> None:
    with pytest.raises(NotImplementedError, match="research-gated"):
        SanitizerSilenceTier().synthesize_patch(CapturedCrash(output=_ASAN))


def test_symbolic_crs_tier_is_a_full_gated_stub() -> None:
    crs = SymbolicCrashRepairTier()
    with pytest.raises(NotImplementedError, match="research-gated"):
        crs.confirm_crash(CapturedCrash(output=_ASAN))
    with pytest.raises(NotImplementedError, match="research-gated"):
        crs.synthesize_patch(CapturedCrash(output=_ASAN))
    with pytest.raises(NotImplementedError, match="research-gated"):
        crs.remediated_if_silent(_ASAN, _CLEAN)


def test_tiers_satisfy_the_interface() -> None:
    assert isinstance(SanitizerSilenceTier(), BinaryPatchTier)
    assert isinstance(SymbolicCrashRepairTier(), BinaryPatchTier)
