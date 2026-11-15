"""The model gateway's provider key from an AWS SSM SecureString (``VIGIL_ANTHROPIC_KEY_SSM_PARAMETER``).

Default (unset): the environment key, exactly as before. Set: SSM is the ONLY source — no fallback to an environment
or sigil.env key even when one is present — and every failure keeps the gateway from starting (fail-closed). The key
never appears on an argv, in a log line, in a repr, in an error or in the effective configuration. The provisioning
policy grants exactly ``ssm:GetParameter`` on exactly that parameter.

The ``aws`` CLI is replaced by a fake runner (``vigil_core.aws_ssm._default_aws_runner``); no AWS call is made.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil import provider_key as pk
from sigil.governor.identity import ensure_owner_keypair
from vigil_core import aws_ssm
from vigil_core.kek import TpmResult

NAME, REGION = "/vigil/anthropic-api-key", "eu-west-1"
SSM_VALUE = "fake-ssm-value-" + "Zk41"                   # assembled at runtime; not a real key
ENV_VALUE = "fake-env-value-" + "Qp07"
_REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("SIGIL_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", pk.SSM_PARAMETER_ENV, pk.REGION_ENV,
              "VIGIL_MODEL_GATEWAY_ENABLED", "VIGIL_GATEWAY_DAILY_LIMIT_USD", "VIGIL_GATEWAY_TENANT_CONCURRENCY",
              "VIGIL_GATEWAY_GLOBAL_CONCURRENCY"):
        monkeypatch.delenv(k, raising=False)
    yield
    gw._RUNNING.clear()


class FakeAws:
    def __init__(self, rc=0, ptype="SecureString", value=SSM_VALUE, raw=None):
        self.rc, self.calls = rc, []
        self.out = raw if raw is not None else json.dumps([ptype, value]).encode()

    def __call__(self, argv, stdin):
        self.calls.append(list(argv))
        return TpmResult(self.rc, self.out)


def _use(monkeypatch, fake):
    monkeypatch.setattr(aws_ssm, "_default_aws_runner", fake)
    return fake


def _ssm(monkeypatch, *, region=REGION):
    monkeypatch.setenv(pk.SSM_PARAMETER_ENV, NAME)
    if region is not None:
        monkeypatch.setenv(pk.REGION_ENV, region)


# --- the default path is unchanged -----------------------------------------------------------------------------
def test_unset_parameter_reads_the_environment_as_before(monkeypatch):
    fake = _use(monkeypatch, FakeAws())
    monkeypatch.setenv("ANTHROPIC_API_KEY", f" {ENV_VALUE} ")
    assert pk.provider_key() == ENV_VALUE and pk.key_source() == "env"
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "fake-sigil-first")
    assert pk.provider_key() == "fake-sigil-first"
    monkeypatch.delenv("SIGIL_ANTHROPIC_API_KEY")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    with pytest.raises(ValueError, match=re.escape("the model gateway needs the provider key "
                                                   "(SIGIL_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY)")):
        pk.provider_key()
    assert pk.key_source() == ""
    monkeypatch.setenv(pk.SSM_PARAMETER_ENV, "   ")                   # blank reads as unset
    assert pk.key_source() == ""
    assert fake.calls == []                                            # the env path never runs the aws CLI


# --- SSM configured ------------------------------------------------------------------------------------------
def test_the_gateway_takes_its_key_from_the_secure_string(monkeypatch, caplog):
    ensure_owner_keypair()
    fake = _use(monkeypatch, FakeAws())
    _ssm(monkeypatch)
    caplog.set_level(logging.DEBUG)
    cfg = gw.config_from_env()
    assert cfg.api_key == SSM_VALUE
    assert fake.calls == [["aws", "--region", REGION, "ssm", "get-parameter", "--name", NAME, "--with-decryption",
                           "--query", "Parameter.[Type,Value]", "--output", "json"]]
    assert all(SSM_VALUE not in a for a in fake.calls[0])             # never on an argv
    assert SSM_VALUE not in repr(cfg) and SSM_VALUE not in caplog.text
    assert pk.key_source() == "ssm"


def test_ssm_wins_over_an_environment_key(monkeypatch):
    ensure_owner_keypair()
    _use(monkeypatch, FakeAws())
    _ssm(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", ENV_VALUE)
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", ENV_VALUE)
    assert gw.config_from_env().api_key == SSM_VALUE and pk.key_source() == "ssm"


@pytest.mark.parametrize("fake", [
    FakeAws(rc=255), FakeAws(rc=127, raw=b""), FakeAws(ptype="String"), FakeAws(raw=b"not json"),
    FakeAws(value=""), FakeAws(value="two words"),
], ids=["cli_error", "no_cli", "plain_string", "garbage", "empty", "not_a_header"])
def test_no_fallback_a_failing_ssm_read_keeps_the_gateway_down_even_with_an_env_key(monkeypatch, caplog, fake):
    """NEGATIVE CONTROL: a valid key in the environment never stands in for a failed SSM read."""
    ensure_owner_keypair()
    _use(monkeypatch, fake)
    _ssm(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", ENV_VALUE)
    with pytest.raises(pk.ProviderKeyError) as e:
        gw.config_from_env()
    assert ENV_VALUE not in str(e.value) and SSM_VALUE not in str(e.value) and NAME in str(e.value)
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_ENABLED", "1")
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", "1")
    caplog.set_level(logging.DEBUG)
    assert gw.start_from_env() is None and "not started" in caplog.text
    assert ENV_VALUE not in caplog.text and SSM_VALUE not in caplog.text


def test_an_error_never_quotes_the_cli_output(monkeypatch):
    _use(monkeypatch, FakeAws(rc=1, raw=json.dumps(["SecureString", SSM_VALUE]).encode()))
    _ssm(monkeypatch)
    with pytest.raises(pk.ProviderKeyError) as e:
        pk.provider_key()
    assert SSM_VALUE not in str(e.value)


@pytest.mark.parametrize("name", ["vigil/key", "/vigil key", "/vigil;id", "/vigil/../key", "/vigil/$(id)"])
def test_a_bad_parameter_name_is_refused_before_any_spawn(monkeypatch, name):
    fake = _use(monkeypatch, FakeAws())
    monkeypatch.setenv(pk.SSM_PARAMETER_ENV, name)
    monkeypatch.setenv(pk.REGION_ENV, REGION)
    with pytest.raises(pk.ProviderKeyError):
        pk.provider_key()
    assert fake.calls == []


def test_a_missing_region_is_refused_before_any_spawn(monkeypatch):
    fake = _use(monkeypatch, FakeAws())
    _ssm(monkeypatch, region=None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", ENV_VALUE)
    with pytest.raises(pk.ProviderKeyError, match="VIGIL_AWS_REGION"):
        pk.provider_key()
    assert fake.calls == []


def test_the_effective_configuration_names_the_source_never_the_key(monkeypatch):
    _use(monkeypatch, FakeAws())
    _ssm(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", ENV_VALUE)
    cfg = config.effective_config()
    assert cfg["MODEL_PROVIDER_SOURCE"] == "ssm" and cfg["MODEL_PROVIDER_SSM_PARAMETER"] == NAME
    blob = json.dumps(cfg, default=str)
    assert ENV_VALUE not in blob and SSM_VALUE not in blob
    monkeypatch.delenv(pk.SSM_PARAMETER_ENV)
    cfg = config.effective_config()
    assert (cfg["MODEL_PROVIDER_SOURCE"], cfg["MODEL_PROVIDER_SSM_PARAMETER"]) == ("env", "")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert config.effective_config()["MODEL_PROVIDER_SOURCE"] == ""


# --- provisioning grants exactly the one parameter ---------------------------------------------------------------
_PROVISION = _REPO / "apps" / "sigil" / "deploy" / "aws" / "provision.sh"


def test_provision_grants_only_ssm_get_parameter_on_the_one_parameter():
    text = _PROVISION.read_text(encoding="utf-8")
    assert 'PROVIDER_KEY_PARAMETER="${PROVIDER_KEY_PARAMETER:-/vigil/anthropic-api-key}"' in text
    assert '--arg param "arn:aws:ssm:${REGION}:${ACCT}:parameter${PROVIDER_KEY_PARAMETER}"' in text
    assert ('{Sid:"ProviderKeyParameter",Effect:"Allow",Action:["ssm:GetParameter"],Resource:$param}'
            in text)
    actions = re.findall(r'"(ssm:[A-Za-z*]+)"', text)
    assert actions == ["ssm:GetParameter"], actions                  # no ssm:*, no GetParameters(ByPath)


def test_provision_policy_renders_to_the_exact_statement():
    """Render the script's own jq policy program (the text between `--policy-document "$(jq -cn` and `')"`)."""
    jq = shutil.which("jq")
    text = _PROVISION.read_text(encoding="utf-8")
    m = re.search(r"--policy-document \"\$\(jq -cn \\\n(.*?)'(\{Version.*?\})'\)\"", text, re.S)
    assert m, "the host policy program was not found in provision.sh"
    program = m.group(2)
    assert "ProviderKeyParameter" in program
    if jq is None:                                                      # the static checks above still ran
        return
    arn = "arn:aws:ssm:eu-west-1:111122223333:parameter/vigil/anthropic-api-key"
    out = subprocess.run([jq, "-cn", "--arg", "key", "arn:aws:kms:k", "--arg", "bkt", "arn:aws:s3:::b",
                          "--arg", "param", arn, program], capture_output=True, text=True, check=True).stdout
    stmts = {s["Sid"]: s for s in json.loads(out)["Statement"]}
    assert stmts["ProviderKeyParameter"] == {"Sid": "ProviderKeyParameter", "Effect": "Allow",
                                             "Action": ["ssm:GetParameter"], "Resource": arn}
    assert [s for s in stmts.values() if any(a.startswith("ssm:") for a in s["Action"])] == [
        stmts["ProviderKeyParameter"]]
