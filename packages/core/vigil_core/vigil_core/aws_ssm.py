"""vigil_core.aws_ssm — read one AWS SSM Parameter Store SecureString through the injectable ``aws`` CLI runner.

Shared by the sovereign provider-key reader (``sigil.provider_key``: the plaintext, for the model gateway) and
``vigil doctor`` (only the parameter's TYPE, never its value), so both validate the parameter name and the region
the same way. AWS is reached exactly as the KMS KEK backend reaches it (:mod:`vigil_core.kek_backends`): a
fully-resolved argv, no shell, no boto3, the instance role's credentials, and a runner that never raises.

Secret handling: the parameter value only ever travels on the child's STDOUT into the caller's memory. It is never
on argv, never in the environment, never in an error message (every refusal names only the parameter and a fixed
reason; the CLI's own output is never quoted), and never logged here.

FATAL-2: stdlib + :mod:`vigil_core` only.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from .kek_backends import AwsRunner, _default_aws_runner

#: The only parameter type the plaintext reader accepts: a SecureString (KMS-encrypted at rest). A plain String
#: parameter holding a provider key is refused, so a key stored unencrypted never reaches the gateway.
SECURE_STRING = "SecureString"

_NAME_RE = re.compile(r"^/[A-Za-z0-9_.\-/]{1,1000}$")
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$")
_MAX_VALUE_LEN = 4096


class SsmParameterError(ValueError):
    """A parameter that could not be read (fail-closed). The message names the parameter and a fixed reason only."""


def check_parameter_name(name: object) -> str:
    """A fully-qualified parameter name (``/a/b``): a leading ``/``, then letters, digits and ``_ . - /`` only, no
    empty, ``.`` or ``..`` path segment. Refused before any process is spawned."""
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise SsmParameterError("the SSM parameter name must be a full path such as /vigil/anthropic-api-key "
                                "(letters, digits, '_', '.', '-' and '/' only)")
    if any(seg in ("", ".", "..") for seg in name[1:].split("/")):
        raise SsmParameterError("the SSM parameter name has an empty, '.' or '..' path segment")
    return name


def check_region(region: object) -> str:
    """An AWS region name such as ``eu-west-1`` (refused before any process is spawned)."""
    r = region.strip() if isinstance(region, str) else ""
    if not _REGION_RE.match(r):
        raise SsmParameterError("an AWS region such as eu-west-1 is required (VIGIL_AWS_REGION)")
    return r


def get_parameter_argv(region: str, name: str, *, decrypt: bool) -> list:
    """The ``aws ssm get-parameter`` argv. ``decrypt`` returns ``[Type, Value]`` as JSON (the plaintext of a
    SecureString); without it only the parameter's type is printed (its value is never asked for)."""
    argv = ["aws", "--region", check_region(region), "ssm", "get-parameter", "--name", check_parameter_name(name)]
    if decrypt:
        return argv + ["--with-decryption", "--query", "Parameter.[Type,Value]", "--output", "json"]
    return argv + ["--query", "Parameter.Type", "--output", "text"]


def read_secure_string(region: str, name: str, *, runner: Optional[AwsRunner] = None) -> str:
    """The decrypted value of SecureString parameter ``name``, stripped of surrounding whitespace. Raises
    :class:`SsmParameterError` — naming only the parameter — when the name or region is invalid, the CLI fails,
    its output is not ``[Type, Value]``, the type is not SecureString, or the value is empty or not a single
    printable-ASCII token (it is sent as an HTTP header)."""
    argv = get_parameter_argv(region, name, decrypt=True)
    res = (runner or _default_aws_runner)(argv, None)
    if res.rc != 0:
        raise SsmParameterError(f"SSM parameter {name} could not be read (aws exit {res.rc}: missing CLI, no "
                                f"permission, no such parameter, or AWS unreachable)")
    try:
        out = json.loads(res.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SsmParameterError(f"SSM parameter {name}: unexpected output from the aws CLI") from None
    if not (isinstance(out, list) and len(out) == 2 and all(isinstance(x, str) for x in out)):
        raise SsmParameterError(f"SSM parameter {name}: unexpected output from the aws CLI")
    ptype, value = out[0], out[1].strip()
    if ptype != SECURE_STRING:
        raise SsmParameterError(f"SSM parameter {name} is not a SecureString; store the key as a SecureString")
    if not value or len(value) > _MAX_VALUE_LEN or not all(0x21 <= ord(c) <= 0x7E for c in value):
        raise SsmParameterError(f"SSM parameter {name} does not hold a usable key (empty, or not one line of "
                                f"printable ASCII)")
    return value


def parameter_type(region: str, name: str, *, runner: Optional[AwsRunner] = None) -> str:
    """The TYPE of parameter ``name`` (``SecureString`` / ``String`` / ``StringList``), read WITHOUT decryption —
    proves the parameter exists and is readable by this identity without ever handling its value. Raises
    :class:`SsmParameterError` (naming only the parameter) on any failure."""
    res = (runner or _default_aws_runner)(get_parameter_argv(region, name, decrypt=False), None)
    if res.rc != 0:
        raise SsmParameterError(f"SSM parameter {name} could not be read (aws exit {res.rc}: missing CLI, no "
                                f"permission, no such parameter, or AWS unreachable)")
    try:
        ptype = res.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise SsmParameterError(f"SSM parameter {name}: unexpected output from the aws CLI") from None
    if ptype not in (SECURE_STRING, "String", "StringList"):
        raise SsmParameterError(f"SSM parameter {name}: unexpected output from the aws CLI")
    return ptype
