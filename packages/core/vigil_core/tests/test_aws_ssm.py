"""vigil_core.aws_ssm — reading one SSM SecureString through the injectable ``aws`` runner (no boto3).

Pinned: the exact argv (the secret is only ever on the child's stdout, never on argv), the SecureString-only rule (a
plain String parameter is refused), the name / region validation that runs BEFORE any process is spawned, the value
shape (one line of printable ASCII), and that no refusal ever quotes the CLI's output. The type probe (doctor) never
asks for decryption.
"""
from __future__ import annotations

import json

import pytest

from vigil_core.aws_ssm import (
    SECURE_STRING, SsmParameterError, check_parameter_name, check_region, get_parameter_argv, parameter_type,
    read_secure_string,
)
from vigil_core.kek import TpmResult

NAME, REGION = "/vigil/anthropic-api-key", "eu-west-1"
FAKE = "fake-provider-value-" + "x7Q2"                    # assembled at runtime; not a real key


class Runner:
    def __init__(self, rc=0, out=b""):
        self.rc, self.out, self.calls = rc, out, []

    def __call__(self, argv, stdin):
        self.calls.append((list(argv), stdin))
        return TpmResult(self.rc, self.out)


def _ok(ptype=SECURE_STRING, value=FAKE):
    return Runner(0, json.dumps([ptype, value]).encode())


def test_reads_a_secure_string_with_the_exact_argv():
    r = _ok()
    assert read_secure_string(REGION, NAME, runner=r) == FAKE
    assert r.calls == [(["aws", "--region", REGION, "ssm", "get-parameter", "--name", NAME, "--with-decryption",
                         "--query", "Parameter.[Type,Value]", "--output", "json"], None)]
    assert all(FAKE not in a for a in r.calls[0][0])


def test_surrounding_whitespace_of_the_value_is_stripped():
    assert read_secure_string(REGION, NAME, runner=_ok(value=f"  {FAKE}\n")) == FAKE


@pytest.mark.parametrize("ptype", ["String", "StringList", "securestring", ""])
def test_anything_but_a_secure_string_is_refused(ptype):
    with pytest.raises(SsmParameterError, match="not a SecureString"):
        read_secure_string(REGION, NAME, runner=_ok(ptype=ptype))


@pytest.mark.parametrize("out", [b"", b"not json", b"{}", b'["SecureString"]', b'["SecureString", 5]',
                                 b'["SecureString", "a", "b"]', b"\xff\xfe"])
def test_unexpected_output_is_refused(out):
    with pytest.raises(SsmParameterError, match="unexpected output"):
        read_secure_string(REGION, NAME, runner=Runner(0, out))


@pytest.mark.parametrize("value", ["", "   ", "two words", "line\nbreak", "tab\there", "café", "x" * 4097])
def test_a_value_that_cannot_be_a_header_is_refused(value):
    with pytest.raises(SsmParameterError, match="usable key"):
        read_secure_string(REGION, NAME, runner=_ok(value=value))


def test_a_failing_cli_is_refused_without_quoting_its_output():
    secretish = json.dumps([SECURE_STRING, FAKE]).encode()
    for runner in (Runner(255, secretish), Runner(127, b"")):
        with pytest.raises(SsmParameterError) as e:
            read_secure_string(REGION, NAME, runner=runner)
        assert FAKE not in str(e.value) and NAME in str(e.value)
    for bad in (_ok(ptype="String"), _ok(value="two words " + FAKE), Runner(0, b"[" + FAKE.encode())):
        with pytest.raises(SsmParameterError) as e:
            read_secure_string(REGION, NAME, runner=bad)
        assert FAKE not in str(e.value)


@pytest.mark.parametrize("name", ["", "vigil/key", "/", "/vigil key", "/vigil;rm", "/vigil/../key", "/vigil//key",
                                  "/vigil/./key", "/vigil/key/", "/vigil/$(id)", "--name", "/" + "a" * 1001, None, 5])
def test_a_bad_parameter_name_is_refused_before_any_spawn(name):
    r = _ok()
    with pytest.raises(SsmParameterError):
        read_secure_string(REGION, name, runner=r)        # type: ignore[arg-type]
    assert r.calls == []


@pytest.mark.parametrize("region", ["", "  ", "--endpoint-url=http://x", "eu west 1", "EU-WEST-1", "eu-west", None])
def test_a_bad_region_is_refused_before_any_spawn(region):
    r = _ok()
    with pytest.raises(SsmParameterError, match="region"):
        read_secure_string(region, NAME, runner=r)        # type: ignore[arg-type]
    assert r.calls == []


@pytest.mark.parametrize("region", ["eu-west-1", "us-east-2", "ap-southeast-2", "us-gov-west-1", " eu-west-1 "])
def test_real_region_names_are_accepted(region):
    assert check_region(region) == region.strip()


def test_real_parameter_names_are_accepted():
    for name in (NAME, "/a", "/vigil/prod/anthropic_api.key-2"):
        assert check_parameter_name(name) == name


def test_the_type_probe_never_asks_for_decryption():
    r = Runner(0, b"SecureString\n")
    assert parameter_type(REGION, NAME, runner=r) == SECURE_STRING
    argv = r.calls[0][0]
    assert "--with-decryption" not in argv and argv[-4:] == ["--query", "Parameter.Type", "--output", "text"]
    assert get_parameter_argv(REGION, NAME, decrypt=False) == argv
    assert parameter_type(REGION, NAME, runner=Runner(0, b"String\n")) == "String"
    for bad in (Runner(1, b"SecureString"), Runner(0, b"something else"), Runner(0, b"\xff")):
        with pytest.raises(SsmParameterError):
            parameter_type(REGION, NAME, runner=bad)
