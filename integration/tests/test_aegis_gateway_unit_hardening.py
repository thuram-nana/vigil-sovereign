"""AS-2j — the AEGIS-SaaS gateway unit is R15-hardened, and the lint keeps it that way (fail-closed).

Deterministic + offline (framework-free: pure file reads + the stdlib lint). Three things are proven:

  1. GREEN: the SHIPPED unit ``infra/systemd/aegis-saas-gateway@.service`` passes every hardening rule.
  2. RED on the negative control: the frozen pre-AS-2j unit (the N-A defect) is flagged, and the lint
     names the specific weaknesses — this is the "N-A RED on the shipped unit" acceptance made literal.
  3. Regression-catching: flipping ANY single hardening directive on the shipped unit reds the matching
     rule — so a future edit that weakens the boundary cannot ship silently ("the shipped unit fails").

Plus the EACCES matrix (what the gateway uid can/can't touch), the no-route/DNS/IMDS invariant, the
MemoryMax formula, and the lint's own parser soundness.

Run: PYTHONPATH=integration:gateway python -m pytest integration/tests/test_aegis_gateway_unit_hardening.py -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.aegis_unit_lint import (
    DOCUMENTED_POOL,
    SHIPPED_MEMORY_MAX,
    Unit,
    lint_file,
    lint_gateway_unit,
    main,
    parse_memory_value,
    per_slot_bytes,
    pool_ceiling,
    required_memory_max_bytes,
)

_REPO = Path(__file__).resolve().parents[2]
_SHIPPED = _REPO / "infra" / "systemd" / "aegis-saas-gateway@.service"
_NEG_CONTROL = _REPO / "integration" / "tests" / "fixtures" / "aegis-saas-gateway-NA-negative-control.service.txt"


def _shipped_text() -> str:
    return _SHIPPED.read_text(encoding="utf-8")


# ============================================================ 1. the shipped unit is GREEN
def test_shipped_unit_is_fully_hardened_green():
    violations = lint_file(_SHIPPED)
    assert violations == [], "the shipped gateway unit must pass every hardening rule; got:\n" + "\n".join(
        f"  {v}" for v in violations)


def test_shipped_unit_exists_and_is_long_running():
    # Cross-check with the restart-directive guard's expectation: still a supervised long-running edge.
    u = Unit(_shipped_text())
    assert u.last("service", "Type") in (None, "simple", "notify")
    assert str(u.last("service", "Restart")).lower() == "on-failure"
    assert u.last("service", "RestartSec") is not None


# ============================================================ 2. the N-A negative control is RED
def test_na_negative_control_is_red_with_the_expected_weaknesses():
    violations = lint_file(_NEG_CONTROL)
    codes = {v.code for v in violations}
    # the N-A defect, point by point:
    expected = {
        "TCP_BIND",                    # --host/--port instead of a unix socket
        "NO_UNIX_SOCKET",              # no --listen-unix / SO_PEERCRED
        "NO_PRIVATE_NETWORK",          # route/DNS/IMDS reachable
        "NO_ADDR_FAMILY_RESTRICTION",  # IP sockets allowed
        "NO_IP_ADDRESS_DENY",
        "NO_PROTECT_PROC",             # /proc/<pid>/environ leak of AEGIS_GW_SECRET
        "NO_PROC_SUBSET",
        "NO_CREDENTIAL",               # secret via the env file, not the credential store
        "SHARED_RW_ROOT",              # ReadWritePaths=/var/lib/aegis-saas (shared spools+publish+trust root)
        "NO_READONLY_MOUNTS",
        "NO_MEMORY_MAX",               # unbounded memory (fail-open under exhaustion)
        "NO_TASKS_MAX",                # unbounded threads
        "NO_START_LIMIT",              # unbounded crash-loop
    }
    missing = expected - codes
    assert not missing, f"the lint did not catch these N-A weaknesses in the negative control: {sorted(missing)}"


# ============================================================ 3. regression-catching (flip one directive)
def _mutate(find: str, replace: str) -> "list[str]":
    text = _shipped_text()
    assert find in text, f"test fixture drift: {find!r} not in the shipped unit"
    return [v.code for v in lint_gateway_unit(text.replace(find, replace))]


@pytest.mark.parametrize("find,replace,code", [
    ("PrivateNetwork=yes\n", "", "NO_PRIVATE_NETWORK"),
    ("--listen-unix /run/aegis-saas/%i/gw.sock", "--host 0.0.0.0 --port 8080", "TCP_BIND"),
    ("--listen-unix /run/aegis-saas/%i/gw.sock", "--host 0.0.0.0 --port 8080", "NO_UNIX_SOCKET"),
    ("ProtectProc=invisible\n", "", "NO_PROTECT_PROC"),
    ("[Service]\n", "[Service]\nEnvironment=AEGIS_GW_SECRET=leakyvalue0001\n", "SECRET_IN_ENV"),
    ("StateDirectory=aegis-saas/%i\n", "StateDirectory=aegis-saas/%i\nReadWritePaths=/var/lib/aegis-saas\n",
     "SHARED_RW_ROOT"),
    ("MemoryMax=1024M\n", "", "NO_MEMORY_MAX"),
    ("MemoryMax=1024M", "MemoryMax=infinity", "NO_MEMORY_MAX"),
    ("RestrictAddressFamilies=AF_UNIX\n", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
     "IP_ADDR_FAMILY_ALLOWED"),
    ("ProtectSystem=strict\n", "ProtectSystem=full\n", "NO_PROTECT_SYSTEM_STRICT"),
    ("DynamicUser=yes\n", "User=root\n", "ROOT_OR_NO_USER"),
    ("LoadCredential=gw-secret:/etc/aegis-saas/%i.gw.secret\n", "", "NO_CREDENTIAL"),
    ("StartLimitIntervalSec=300\n", "", "NO_START_LIMIT"),
    ("TasksMax=64\n", "", "NO_TASKS_MAX"),
    ("IPAddressDeny=any\n", "", "NO_IP_ADDRESS_DENY"),
])
def test_weakening_one_directive_reds_that_rule(find, replace, code):
    assert code in _mutate(find, replace), f"weakening {find!r} should raise {code}"


# ============================================================ EACCES matrix (unit directives that enforce it)
def test_eacces_matrix_is_enforced_by_the_shipped_unit():
    u = Unit(_shipped_text())

    def last(k):
        return u.last("service", k)

    # per-instance writable surface only; nothing shared, no root
    assert str(last("DynamicUser")).lower() == "yes"           # distinct uid per instance (T-HOP)
    assert "StateDirectory" in {k for k, _ in u.sections["service"]}  # own spool, 0700
    assert str(last("StateDirectoryMode")) == "0700"
    assert u.all("service", "ReadWritePaths") == []            # no shared RW trust root (N-A fix)
    # read-only verify inputs
    assert str(last("ProtectSystem")).lower() == "strict"
    bro = " ".join(u.all("service", "BindReadOnlyPaths"))
    assert "authority-root" in bro and "monitoring_authority" in bro
    # /proc + secret isolation
    assert str(last("ProtectProc")).lower() == "invisible"
    assert str(last("ProcSubset")).lower() == "pid"
    creds = " ".join(u.all("service", "LoadCredential"))
    assert "gw-secret" in creds and "report-secret" in creds
    # no secret in the environment at all
    assert all(not kv[1].upper().startswith("AEGIS_GW_SECRET")
               for kv in u.sections["service"] if kv[0] == "Environment")
    # privilege floor
    assert str(last("NoNewPrivileges")).lower() == "yes"
    assert "" in u.all("service", "CapabilityBoundingSet")     # dropped all caps
    assert str(last("ProtectHome")).lower() == "yes"
    assert str(last("PrivateTmp")).lower() == "yes"


# ============================================================ no route / DNS / IMDS
def test_no_route_dns_or_imds_is_reachable_from_the_gateway():
    u = Unit(_shipped_text())
    assert str(u.last("service", "PrivateNetwork")).lower() == "yes"      # isolated net namespace
    raf = " ".join(u.all("service", "RestrictAddressFamilies")).upper()
    assert "AF_UNIX" in raf and "AF_INET" not in raf                      # cannot create an IP socket at all
    assert "~" not in raf                                                  # allow-list, not deny-list
    assert "any" in [x.lower() for x in u.all("service", "IPAddressDeny")] # belt-and-suspenders


# ============================================================ MemoryMax formula (spec §5.7 / §8.1)
def test_memory_formula_matches_the_documented_gateway_caps():
    assert per_slot_bytes() == 60 * 1024 * 1024                           # 10 + 2*25 MiB
    assert required_memory_max_bytes(DOCUMENTED_POOL) == (12 * 60 + 192) * 1024 * 1024   # 912 MiB


def test_shipped_memorymax_satisfies_the_formula_for_its_documented_pool():
    u = Unit(_shipped_text())
    mm = parse_memory_value(str(u.last("service", "MemoryMax")))
    assert mm is not None
    assert mm == parse_memory_value(SHIPPED_MEMORY_MAX)                   # the unit sets what the module documents
    assert mm >= required_memory_max_bytes(DOCUMENTED_POOL)              # >= the formula minimum
    assert pool_ceiling(mm) >= 1                                          # admits at least one slot above base
    # MemoryHigh (soft reclaim) sits below the hard MemoryMax cap
    mh = parse_memory_value(str(u.last("service", "MemoryHigh")))
    assert mh is not None and mh < mm


def test_pool_ceiling_and_parse_memory_value_edges():
    assert pool_ceiling(parse_memory_value("1024M")) == 10               # floor((0.8*1024-192)/60)
    assert pool_ceiling(parse_memory_value("200M")) == 0                  # below base+headroom -> no slot
    assert parse_memory_value("infinity") is None
    assert parse_memory_value("80%") is None                             # host-dependent -> rejected
    assert parse_memory_value("1G") == 1024 ** 3
    assert parse_memory_value("512K") == 512 * 1024
    assert parse_memory_value("garbage") is None


# ============================================================ lint parser soundness (fail-closed)
def test_empty_or_sectionless_input_is_red_not_silently_clean():
    assert lint_gateway_unit("") and lint_gateway_unit("")[0].code == "EMPTY"
    assert lint_gateway_unit("   \n\n") and lint_gateway_unit("   \n\n")[0].code == "EMPTY"
    assert any(v.code == "NO_SERVICE" for v in lint_gateway_unit("[Unit]\nDescription=x\n"))


def test_unreadable_file_is_a_violation_not_a_pass():
    v = lint_file(_REPO / "does" / "not" / "exist.service")
    assert v and v[0].code == "UNREADABLE"


def test_parser_folds_continuations_and_is_section_aware():
    u = Unit("[Service]\nExecStart=/x \\\n--listen-unix /s\nType=simple\n[Unit]\nPrivateNetwork=yes\n")
    # the continuation folds into one ExecStart; PrivateNetwork under [Unit] is NOT a [Service] directive
    assert "--listen-unix /s" in str(u.last("service", "ExecStart"))
    assert u.last("service", "PrivateNetwork") is None
    assert u.last("unit", "PrivateNetwork") == "yes"


def test_parser_preserves_multiplicity_for_accumulating_keys():
    u = Unit("[Service]\nLoadCredential=a:/x\nLoadCredential=b:/y\n")
    assert u.all("service", "LoadCredential") == ["a:/x", "b:/y"]        # not last-wins


def test_host_flag_is_matched_as_a_whole_token_not_a_substring():
    # a hardened unit legitimately passes --saas-host; that must NOT be read as a TCP --host bind
    toks = "python -m framework.v2 aegis gateway --listen-unix /s --saas-host app.example.com".split()
    from vigil_integration.aegis_unit_lint import _has_flag
    assert _has_flag(toks, "--listen-unix")
    assert not _has_flag(toks, "--host")


# ============================================================ CLI exit codes
def test_cli_is_green_on_shipped_and_red_on_negative_control():
    assert main([str(_SHIPPED)]) == 0
    assert main([str(_NEG_CONTROL)]) == 1
    assert main([str(_SHIPPED), str(_NEG_CONTROL)]) == 1                 # any RED -> nonzero
    assert main([]) == 2                                                 # usage -> fail-closed nonzero
