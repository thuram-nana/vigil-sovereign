"""AS-26 (OPS-1) — deterministic OFFLINE tests of the Z3R relay guards (spec §9.3 AS-26 acceptance).

These prove the four relay/edge acceptance guards WITHOUT a live AWS account, a running rsync, or a network:

  * relay EACCES on the vault            -> test_vault_* + test_read_source_*
  * hostile file names harmless          -> test_hostile_* (the containment property over a hostile corpus)
  * unauthenticated transport refused    -> test_transport_*
  * CloudFront bypass refused            -> test_cloudfront_*

Each guard is tested with a POSITIVE control (the legitimate case is allowed) and NEGATIVE controls (every
hostile case is refused with the expected stable reason), so the guard is provably not a no-op. Pure stdlib
+ pytest; imported via PYTHONPATH=integration (the P5 integration job and the aegis-infra advisory job both
run it)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from vigil_integration.aegis_relay_guard import (
    DEFAULT_FORBIDDEN_ROOTS,
    MIN_RSYNC_VERSION,
    RelayRefused,
    TransportSpec,
    _main,
    assert_cloudfront_not_bypassed,
    assert_source_not_forbidden,
    contain_in_landing,
    parse_rsync_version,
    parse_transport,
    plan_pull,
    read_source_or_eacces,
    require_authenticated_transport,
    require_min_rsync_version,
    validate_rsync_flags,
)

LANDING = "/srv/aegis/landing/reports"


# ==================================================================================================
# Guard 1 — hostile file names harmless.
# ==================================================================================================
def test_hostile_plain_name_contained() -> None:
    out = contain_in_landing(LANDING, "report-2026-11-26.json")
    assert out == "/srv/aegis/landing/reports/report-2026-11-26.json"


def test_hostile_nested_name_contained() -> None:
    out = contain_in_landing(LANDING, "tenant-a/sub/report.json")
    assert out.startswith(LANDING + "/")


@pytest.mark.parametrize("name,reason", [
    ("../../etc/passwd", "escapes_landing"),
    ("../" * 20 + "etc/shadow", "escapes_landing"),
    ("a/../../../b", "escapes_landing"),
    ("/etc/passwd", "absolute_name"),
    ("\\\\server\\share\\x", "absolute_name"),
    ("C:\\windows\\system32", "absolute_name"),
    ("report\x00.json", "nul_byte"),
    ("line1\nline2", "control_char"),
    ("tab\tname", "control_char"),
    ("", "empty_name"),
    (".", "is_landing"),
])
def test_hostile_names_refused(name: str, reason: str) -> None:
    with pytest.raises(RelayRefused) as ei:
        contain_in_landing(LANDING, name)
    assert ei.value.reason == reason


def test_hostile_corpus_never_escapes() -> None:
    """The load-bearing property: for EVERY name in a hostile corpus, contain_in_landing either refuses it
    or returns a path that is strictly inside the landing dir — it never returns an escaping path."""
    corpus = [
        "ok.json", "a/b/c.json", "..", "../x", "../../x", "....//....//x", "./../../x",
        "/abs", "foo/../../../../etc/passwd", "weird\u202ename", "spaces in name.json",
        "trailing/", "dot.dot..json", "%2e%2e/evil", "a/./b/../c",
    ]
    base = Path(LANDING)
    escaped = []
    for name in corpus:
        try:
            out = Path(contain_in_landing(LANDING, name))
        except RelayRefused:
            continue
        if base != out and base not in out.parents:
            escaped.append((name, str(out)))
    assert not escaped, f"these hostile names ESCAPED the landing dir: {escaped}"


# ==================================================================================================
# Guard 2 — relay EACCES on the vault (refuses to read it).
# ==================================================================================================
@pytest.mark.parametrize("source,reason", [
    ("/var/lib/vigil/vault/owner.key", "vault_source"),
    ("/etc/vigil/vault", "vault_source"),
    ("/srv/stuff/secrets/provider.json", "vault_component"),
    ("relay/vault/sealed.bin", "vault_component"),
    ("/home/vigil/.sigil/spine", "vault_component"),
    ("", "empty_source"),
])
def test_vault_sources_refused(source: str, reason: str) -> None:
    with pytest.raises(RelayRefused) as ei:
        assert_source_not_forbidden(source)
    assert ei.value.reason == reason


def test_vault_legitimate_reports_source_allowed() -> None:
    # A plain reports/grants source carries none of the forbidden roots -> allowed (no raise).
    assert_source_not_forbidden("/srv/aegis/outbound/reports/tenant-a") is None
    assert_source_not_forbidden("tenant-b/grants") is None


def test_read_source_surfaces_eacces_via_monkeypatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """The relay never swallows a permission error into a silent empty success: read_source_or_eacces
    re-raises EACCES as a RelayRefused(eacces). Monkeypatched so it is deterministic at any uid."""
    def _boom(_path: str) -> list[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os.path, "isdir", lambda _p: True)
    monkeypatch.setattr(os, "listdir", _boom)
    with pytest.raises(RelayRefused) as ei:
        read_source_or_eacces("/var/lib/vigil/vault")
    assert ei.value.reason == "eacces"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root bypasses filesystem permissions; the monkeypatch test covers the logic")
def test_read_source_real_eacces(tmp_path: Path) -> None:
    """Live half: a chmod 000 directory raises a REAL EACCES that the relay surfaces as a refusal."""
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "owner.key").write_bytes(b"x")
    os.chmod(vault, 0o000)
    try:
        with pytest.raises(RelayRefused) as ei:
            read_source_or_eacces(str(vault))
        assert ei.value.reason == "eacces"
    finally:
        os.chmod(vault, 0o700)  # restore so tmp cleanup works


def test_read_source_missing_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RelayRefused) as ei:
        read_source_or_eacces(str(tmp_path / "does-not-exist"))
    assert ei.value.reason == "missing_source"


def test_default_forbidden_roots_cover_vault_and_sigil() -> None:
    assert "vault" in DEFAULT_FORBIDDEN_ROOTS and ".sigil" in DEFAULT_FORBIDDEN_ROOTS


# ==================================================================================================
# Guard 3 — unauthenticated transport refused.
# ==================================================================================================
@pytest.mark.parametrize("spec,reason", [
    ("rsync://relay.example/reports", "unauthenticated_daemon"),
    ("relay.example::reports", "unauthenticated_daemon"),
])
def test_transport_anonymous_daemon_refused(spec: str, reason: str) -> None:
    with pytest.raises(RelayRefused) as ei:
        require_authenticated_transport(parse_transport(spec))
    assert ei.value.reason == reason


def test_transport_ssh_without_host_key_check_refused() -> None:
    spec = TransportSpec(kind="ssh", strict_host_key_checking=False,
                         known_hosts="/etc/known_hosts", identity="/etc/id")
    with pytest.raises(RelayRefused) as ei:
        require_authenticated_transport(spec)
    assert ei.value.reason == "no_host_key_check"


def test_transport_ssh_without_known_hosts_refused() -> None:
    spec = TransportSpec(kind="ssh", strict_host_key_checking=True, known_hosts="", identity="/etc/id")
    with pytest.raises(RelayRefused) as ei:
        require_authenticated_transport(spec)
    assert ei.value.reason == "no_known_hosts"


def test_transport_ssh_without_identity_refused() -> None:
    spec = TransportSpec(kind="ssh", strict_host_key_checking=True, known_hosts="/etc/kh", identity="")
    with pytest.raises(RelayRefused) as ei:
        require_authenticated_transport(spec)
    assert ei.value.reason == "no_identity"


def test_transport_authenticated_ssh_allowed() -> None:
    spec = TransportSpec(kind="ssh", strict_host_key_checking=True,
                         known_hosts="/etc/vigil/known_hosts", identity="/etc/vigil/relay_id")
    assert require_authenticated_transport(spec) is None


# ==================================================================================================
# Guard 4 — CloudFront bypass refused.
# ==================================================================================================
SECRET = "edge-secret-abc123"


def test_cloudfront_valid_secret_allowed() -> None:
    assert assert_cloudfront_not_bypassed({"X-Vigil-Edge-Secret": SECRET}, SECRET) is None


def test_cloudfront_case_insensitive_header() -> None:
    assert assert_cloudfront_not_bypassed({"x-vigil-edge-secret": SECRET}, SECRET) is None


def test_cloudfront_missing_secret_refused() -> None:
    with pytest.raises(RelayRefused) as ei:
        assert_cloudfront_not_bypassed({"Host": "tenant-a.example"}, SECRET)
    assert ei.value.reason == "edge_secret_absent"


def test_cloudfront_wrong_secret_refused() -> None:
    with pytest.raises(RelayRefused) as ei:
        assert_cloudfront_not_bypassed({"X-Vigil-Edge-Secret": "wrong"}, SECRET)
    assert ei.value.reason == "edge_secret_mismatch"


def test_cloudfront_blank_expected_fails_closed() -> None:
    with pytest.raises(RelayRefused) as ei:
        assert_cloudfront_not_bypassed({"X-Vigil-Edge-Secret": "anything"}, "")
    assert ei.value.reason == "no_expected_secret"


def test_cloudfront_foreign_distribution_refused() -> None:
    headers = {"X-Vigil-Edge-Secret": SECRET, "X-Vigil-Distribution-Id": "EFOREIGN"}
    with pytest.raises(RelayRefused) as ei:
        assert_cloudfront_not_bypassed(headers, SECRET, allowed_distribution_ids=frozenset({"EOURS"}))
    assert ei.value.reason == "foreign_distribution"


def test_cloudfront_allowed_distribution_ok() -> None:
    headers = {"X-Vigil-Edge-Secret": SECRET, "X-Vigil-Distribution-Id": "EOURS"}
    assert assert_cloudfront_not_bypassed(headers, SECRET, allowed_distribution_ids=frozenset({"EOURS"})) is None


# ==================================================================================================
# rsync argv pinning (--no-links; regular files only).
# ==================================================================================================
def test_rsync_requires_no_links() -> None:
    with pytest.raises(RelayRefused) as ei:
        validate_rsync_flags(["--recursive", "--times"])
    assert ei.value.reason == "missing_flag"


@pytest.mark.parametrize("bad", ["--links", "-l", "--copy-links", "-a", "--archive", "-e"])
def test_rsync_rejects_forbidden_flags(bad: str) -> None:
    with pytest.raises(RelayRefused) as ei:
        validate_rsync_flags(["--no-links", bad])
    assert ei.value.reason == "forbidden_flag"


def test_rsync_pinned_flags_ok() -> None:
    assert validate_rsync_flags(["--no-links", "--recursive", "--times"]) is None


def test_plan_pull_pins_no_links_and_refuses_vault() -> None:
    plan = plan_pull("/usr/bin/rsync", "/srv/aegis/outbound/reports", LANDING)
    assert "--no-links" in plan.flags and plan.direction == "pull"
    with pytest.raises(RelayRefused):
        plan_pull("/usr/bin/rsync", "/var/lib/vigil/vault", LANDING)


# ==================================================================================================
# rsync version gate — hostile-filename containment is a receiver-side job pre-3.2.5 rsync does not do.
# ==================================================================================================
def test_rsync_version_parse() -> None:
    assert parse_rsync_version("rsync  version 3.2.7  protocol version 31") == (3, 2, 7)
    assert parse_rsync_version("no version here") is None


def test_rsync_version_too_old_refused() -> None:
    with pytest.raises(RelayRefused) as ei:
        require_min_rsync_version("rsync  version 3.1.3  protocol version 30")
    assert ei.value.reason == "rsync_too_old"


def test_rsync_version_unparseable_fails_closed() -> None:
    with pytest.raises(RelayRefused) as ei:
        require_min_rsync_version("rsync (version string munged by a hostile sender)")
    assert ei.value.reason == "rsync_version_unparsed"


def test_rsync_version_at_or_above_minimum_ok() -> None:
    assert MIN_RSYNC_VERSION == (3, 2, 5)
    assert require_min_rsync_version("rsync  version 3.2.5  protocol version 31") is None
    assert require_min_rsync_version("rsync  version 3.4.1  protocol version 32") is None


def test_cli_check_rsync_version() -> None:
    assert _main(["check-rsync-version", "--line", "rsync  version 3.2.7 protocol version 31"]) == 0
    assert _main(["check-rsync-version", "--line", "rsync  version 3.1.0 protocol version 30"]) == 1
    assert _main(["check-rsync-version", "--line", "garbage"]) == 1


# ==================================================================================================
# CLI exit codes (backs tools/z3r/z3r-relay.sh and the advisory job).
# ==================================================================================================
def test_cli_check_name_ok_and_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert _main(["check-name", "--landing-dir", LANDING, "--name", "ok.json"]) == 0
    assert _main(["check-name", "--landing-dir", LANDING, "--name", "../../etc/passwd"]) == 1


def test_cli_check_transport_and_source() -> None:
    assert _main(["check-source", "--source", "/srv/aegis/reports"]) == 0
    assert _main(["check-source", "--source", "/var/lib/vigil/vault/x"]) == 1
    assert _main(["check-transport", "--spec", "rsync://h/m"]) == 1
    assert _main(["check-transport", "--spec", "relay.host", "--strict-host-key-checking",
                  "--known-hosts", "/kh", "--identity", "/id"]) == 0


def test_cli_check_rsync_flags() -> None:
    assert _main(["check-rsync-flags", "--flags=--no-links,--recursive"]) == 0
    assert _main(["check-rsync-flags", "--flags=--recursive"]) == 1
