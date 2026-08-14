#!/usr/bin/env python3
"""The SOURCE-CODE half of the VIGIL loopback range: a deliberately-weak tree and a clean twin.

WHY THIS EXISTS. Several tools in the engine's toolset read code rather than traffic — bandit,
gitleaks, trufflehog, semgrep, joern. A typed argv builder for one of those tools proves nothing
until the tool has actually run, actually reported the weakness that was planted for it, and had
its output parsed into observations. That needs a corpus with a KNOWN answer.

TWO TREES, AND THE SECOND ONE IS THE POINT.

  vulnerable/  every file carries at least one real, well-known weakness pattern, each marked with
               a ``RANGE-WEAKNESS:`` comment naming its CWE, plus fabricated credentials in the
               shapes real secret scanners match.
  clean/       the SAME application, same languages, same file names, written the safe way, with no
               credentials anywhere.

A detector that only ever says "found something" is worthless. ``clean/`` is the negative control:
a tool driver is only proven when the tool FIRES on ``vulnerable/`` and stays SILENT on ``clean/``.
``clean/`` is therefore written to be quiet at EVERY severity, not merely at HIGH — no ``subprocess``
import, no bare ``assert``, no ``random``, no ``/tmp`` literal, no name bandit reads as a password.
A control that is only clean above a threshold lets a whole class of false positive through.

NOTHING IN EITHER TREE IS EVER EXECUTED. These are analysis fixtures. ``vulnerable/`` deliberately
contains code that would be dangerous to run — a shell-injecting ping handler, a Flask debug server
asking for 0.0.0.0 — precisely because that is what the scanners are meant to find. The range never
runs it, imports it, or builds it.

THE CREDENTIALS ARE FABRICATED, AND YOU CAN PROVE IT YOURSELF. A planted secret has to satisfy two
requirements that pull against each other: it must be OBVIOUSLY fake, and it must still be found by
scanners that deliberately discard obvious-looking placeholders (``AKIAXXXXXXXXXXXXXXXX`` is filtered
out by low-entropy and placeholder heuristics, so it would prove nothing). This module resolves that
by DERIVING every value from a published constant:

    value = alphabet-mapped SHA-256 stream of  f"{_FIXTURE_SALT}|{label}"

The output is high-entropy — so the scanners treat it as a real candidate — and simultaneously
provable as synthetic, because anyone can recompute it from a string printed in this file and in the
generated ``FIXTURES.md``. No account, key, or token anywhere corresponds to any of them.

DETERMINISM. Both trees are byte-identical on every run, on every machine. ``--fingerprint`` prints a
content id: SHA-256 over ``path\\0mode\\0sha256(bytes)`` for every file, sorted. That id is recorded
in ``range_targets.json`` and re-checked on generation, so results from two runs are comparable and
an accidental edit to this generator cannot silently change what the tools were scored against. Each
tree is also its own git repository, committed with a frozen identity and timestamp, because gitleaks
and trufflehog have history-scanning modes that need one.

USAGE
    python3 range_source.py --root DIR --generate     # write both trees (idempotent)
    python3 range_source.py --fingerprint             # print content ids, write nothing
    python3 range_source.py --root DIR --verify       # on-disk trees still match the expectation?
    python3 range_source.py --root DIR --remove       # delete both trees

Stdlib only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# ======================================================================================
# Fabricated credential derivation
# ======================================================================================

#: Published constant. Every planted credential below is a deterministic function of this
#: string and a label, so any reader can regenerate them and confirm they are synthetic.
_FIXTURE_SALT = "VIGIL-RANGE FABRICATED CREDENTIAL FIXTURE v1"

_UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_B64 = _ALNUM + "+/"
_DIGITS = "0123456789"


def _stream(label: str, nbytes: int) -> bytes:
    """A deterministic byte stream for ``label``: SHA-256 in counter mode over the salt."""
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        seed = f"{_FIXTURE_SALT}|{label}|{counter}".encode()
        out.extend(hashlib.sha256(seed).digest())
        counter += 1
    return bytes(out[:nbytes])


def _chars(label: str, n: int, alphabet: str) -> str:
    """``n`` characters drawn from ``alphabet`` by the stream for ``label``.

    Rejection-free (modulo bias is irrelevant — this is a fixture, not a key), and stable across
    Python versions because it depends on nothing but SHA-256 and the alphabet written here.
    """
    return "".join(alphabet[b % len(alphabet)] for b in _stream(label, n))


# The planted values. Each is shaped to match the detector that is supposed to find it: the AWS
# access-key rule keys off `AKIA` + 16 uppercase/digits, the GitHub rule off `ghp_` + 36 alnum, and
# so on. Shape is what makes them findable; derivation is what makes them provably fake.
FAKE = {
    "aws_access_key_id": "AKIA" + _chars("aws_access_key_id", 16, _UPPER_NUM),
    "aws_secret_access_key": _chars("aws_secret_access_key", 40, _B64),
    "github_pat": "ghp_" + _chars("github_pat", 36, _ALNUM),
    "slack_bot_token": (
        "xoxb-"
        + _chars("slack_ws", 12, _DIGITS)
        + "-"
        + _chars("slack_bot", 12, _DIGITS)
        + "-"
        + _chars("slack_sig", 24, _ALNUM)
    ),
    "stripe_secret_key": "sk_live_" + _chars("stripe_secret_key", 24, _ALNUM),
    "db_password": _chars("db_password", 28, _ALNUM),
    "jwt_signing_key": _chars("jwt_signing_key", 44, _ALNUM),
    "private_key_body": "\n".join(
        _chars(f"private_key_body|{i}", 64, _B64) for i in range(12)
    ),
}


# ======================================================================================
# The vulnerable tree
# ======================================================================================

_BANNER_PY = '''"""{title}

PART OF THE VIGIL LOOPBACK RANGE — A DELIBERATELY-VULNERABLE ANALYSIS FIXTURE.
This file is never executed, imported, or deployed. It exists so that static analysis tools have
something with a KNOWN answer to find. Every weakness is marked ``RANGE-WEAKNESS:`` with its CWE.
"""
'''

VULNERABLE_FILES: dict[str, tuple[int, str]] = {}
CLEAN_FILES: dict[str, tuple[int, str]] = {}


def _v(path: str, text: str, mode: int = 0o644) -> None:
    VULNERABLE_FILES[path] = (mode, text)


def _c(path: str, text: str, mode: int = 0o644) -> None:
    CLEAN_FILES[path] = (mode, text)


_v(
    "README.md",
    f"""# VIGIL RANGE — vulnerable source fixture

**This tree is deliberately insecure. Do not run it, build it, or copy from it.**

It is the source-code half of the VIGIL loopback range. Its only purpose is to give code-reading
security tools (bandit, semgrep, gitleaks, trufflehog, joern) a corpus whose answer is already
known, so a tool driver can be proven to actually work rather than merely to emit a plausible
command line.

Every planted weakness carries a `RANGE-WEAKNESS:` comment naming its CWE. Every planted credential
is FABRICATED — see `FIXTURES.md` for the derivation, which you can recompute yourself.

Its negative control is the sibling `clean/` tree: the same application written safely, with no
credentials at all. A tool is only proven when it fires here **and** stays silent there.

Generated by `tools/livefire/range_source.py`. Byte-identical on every run.
""",
)

_v(
    "FIXTURES.md",
    f"""# Planted credentials — all fabricated

None of the values in this tree authenticate to anything. Each is derived deterministically from a
published constant, so you can regenerate every one of them and confirm for yourself that it came
out of a hash function rather than out of an account:

```
salt  = "{_FIXTURE_SALT}"
bytes = SHA256(f"{{salt}}|{{label}}|{{counter}}") for counter = 0, 1, 2, ...
value = "".join(alphabet[b % len(alphabet)] for b in bytes[:n])
```

The alphabets and lengths are in `tools/livefire/range_source.py`. The values are high-entropy on
purpose: real secret scanners discard low-entropy placeholders like `AKIAXXXXXXXXXXXXXXXX`, so a
fixture built from obvious dummy text would be silently skipped and would prove nothing about the
driver under test.

| label | shape it imitates | where it is planted |
|---|---|---|
| `aws_access_key_id` | AWS access key id | `config/.env`, `config/credentials.yml` |
| `aws_secret_access_key` | AWS secret access key | `config/.env`, `config/credentials.yml` |
| `github_pat` | GitHub personal access token | `config/.env` |
| `slack_bot_token` | Slack bot token | `config/credentials.yml` |
| `stripe_secret_key` | Stripe live secret key | `config/credentials.yml` |
| `db_password` | database password | `app/crypto.py`, `config/.env` |
| `jwt_signing_key` | JWT signing key | `app/crypto.py` |
| `private_key_body` | PEM private key | `deploy/range_id_rsa` |

**Verification is out of scope for this range.** Run trufflehog with `--no-verification`: the
loopback charter forbids external egress, and a verifying scanner would try to reach AWS, GitHub
and Slack to test these. They are not real, so verification would only produce a network call and
an unverified result.
""",
)

_v(
    "app/dal.py",
    _BANNER_PY.format(title="Data access for the range fixture app.")
    + '''
import hashlib
import pickle
import sqlite3

import yaml
from flask import request


def find_user(username):
    """Look a user up by name."""
    conn = sqlite3.connect("range.db")
    # RANGE-WEAKNESS: CWE-89 SQL injection. Request-controlled text is concatenated straight into
    # the statement, so `x' OR '1'='1` changes the query rather than being matched by it.
    query = "SELECT id, email FROM users WHERE username = '" + username + "'"
    return conn.execute(query).fetchall()


def http_find_user():
    """The taint source that reaches the sink above — dataflow engines need the edge, not just the
    pattern."""
    return find_user(request.args["username"])


def password_digest(password):
    # RANGE-WEAKNESS: CWE-327 broken cryptographic primitive. MD5 is collision-broken and, being
    # fast and unsalted here, is the wrong shape for password storage regardless.
    return hashlib.md5(password.encode()).hexdigest()


def load_session(blob):
    # RANGE-WEAKNESS: CWE-502 deserialization of untrusted data. pickle.loads on request bytes is
    # arbitrary code execution by design.
    return pickle.loads(blob)


def load_profile(text):
    # RANGE-WEAKNESS: CWE-502 unsafe YAML load. The full Loader constructs arbitrary Python objects.
    return yaml.load(text, Loader=yaml.Loader)


def http_load_session():
    return load_session(request.get_data())
''',
)

_v(
    "app/admin.py",
    _BANNER_PY.format(title="Administrative endpoints for the range fixture app.")
    + '''
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/admin/ping")
def ping():
    host = request.args.get("host", "")
    # RANGE-WEAKNESS: CWE-78 OS command injection. shell=True over a concatenated request parameter
    # means `; id` is a second command, not part of a hostname.
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/admin/calc")
def calc():
    # RANGE-WEAKNESS: CWE-95 evaluation of attacker-controlled code.
    return str(eval(request.args["expr"]))


@app.route("/admin/report")
def report():
    name = request.args.get("name", "")
    # RANGE-WEAKNESS: CWE-22 path traversal. `../` in the parameter escapes the intended directory.
    with open("/var/reports/" + name) as fh:
        return fh.read()


def fetch(url):
    # RANGE-WEAKNESS: CWE-295 certificate validation disabled, which removes the only thing that
    # makes TLS mean anything against an active attacker.
    return requests.get(url, verify=False, timeout=10)


if __name__ == "__main__":
    # RANGE-WEAKNESS: CWE-489 debug console on every interface. The Werkzeug debugger is a remote
    # shell for anyone who can reach it. THIS FILE IS NEVER RUN — see the module docstring; the
    # range's own services are hard-pinned to 127.0.0.1 by tools/livefire/range_targets.py.
    app.run(host="0.0.0.0", debug=True)
''',
)

_v(
    "app/crypto.py",
    _BANNER_PY.format(title="Secrets and token handling for the range fixture app.")
    + f'''
import random

# RANGE-WEAKNESS: CWE-798 hardcoded credentials. FABRICATED VALUES — derived from a published
# constant, see FIXTURES.md. They authenticate to nothing.
DB_PASSWORD = "{FAKE['db_password']}"
JWT_SIGNING_KEY = "{FAKE['jwt_signing_key']}"


def session_token():
    # RANGE-WEAKNESS: CWE-338 predictable RNG for a security token. `random` is a Mersenne Twister:
    # observe enough output and you can recover the state and forge every future token.
    return "%030x" % random.getrandbits(120)


def compare_token(supplied, expected):
    # RANGE-WEAKNESS: CWE-208 non-constant-time comparison of a secret; `==` leaks the length of the
    # matching prefix through timing.
    return supplied == expected
''',
)

_v(
    "config/.env",
    f"""# RANGE FIXTURE — FABRICATED CREDENTIALS. None of these authenticate to anything.
# Derivation: see FIXTURES.md. Planted so that secret scanners have a true positive to find.
AWS_ACCESS_KEY_ID={FAKE['aws_access_key_id']}
AWS_SECRET_ACCESS_KEY={FAKE['aws_secret_access_key']}
GITHUB_TOKEN={FAKE['github_pat']}
DATABASE_URL=postgres://range_app:{FAKE['db_password']}@db.internal.invalid:5432/range
""",
)

_v(
    "config/credentials.yml",
    f"""# RANGE FIXTURE — FABRICATED CREDENTIALS. None of these authenticate to anything.
# Derivation: see FIXTURES.md.
aws:
  access_key_id: {FAKE['aws_access_key_id']}
  secret_access_key: {FAKE['aws_secret_access_key']}
slack:
  bot_token: {FAKE['slack_bot_token']}
stripe:
  secret_key: {FAKE['stripe_secret_key']}
""",
)

_v(
    "deploy/range_id_rsa",
    f"""-----BEGIN RSA PRIVATE KEY-----
{FAKE['private_key_body']}
-----END RSA PRIVATE KEY-----
""",
    mode=0o600,
)

_v(
    "web/server.js",
    """// PART OF THE VIGIL LOOPBACK RANGE — A DELIBERATELY-VULNERABLE ANALYSIS FIXTURE.
// Never executed, never deployed. Every weakness is marked RANGE-WEAKNESS with its CWE.
const express = require("express");
const { exec } = require("child_process");

const app = express();

app.get("/lookup", (req, res) => {
  // RANGE-WEAKNESS: CWE-78 OS command injection through a query parameter.
  exec("whois " + req.query.domain, (err, stdout) => res.send(stdout));
});

app.get("/echo", (req, res) => {
  // RANGE-WEAKNESS: CWE-79 reflected cross-site scripting; the parameter is interpolated into the
  // response body with no encoding.
  res.send("<h1>" + req.query.q + "</h1>");
});

app.get("/calc", (req, res) => {
  // RANGE-WEAKNESS: CWE-95 evaluation of attacker-controlled code.
  res.json(eval(req.query.expr));
});

module.exports = app;
""",
)

_v(
    "native/parse.c",
    """/* PART OF THE VIGIL LOOPBACK RANGE — A DELIBERATELY-VULNERABLE ANALYSIS FIXTURE.
 * Never compiled, never run. Present so that C-aware analysers (joern, semgrep, flawfinder) have a
 * corpus with a known answer. Every weakness is marked RANGE-WEAKNESS with its CWE. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_name(const char *src) {
  char buf[16];
  /* RANGE-WEAKNESS: CWE-120 unbounded copy into a fixed-size stack buffer. */
  strcpy(buf, src);
  printf("%s\\n", buf);
}

void read_line(void) {
  char line[64];
  /* RANGE-WEAKNESS: CWE-242 gets() cannot be used safely; it has no bound at all. */
  gets(line);
  printf("%s\\n", line);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    return 1;
  }
  char cmd[256];
  /* RANGE-WEAKNESS: CWE-120 unbounded format into a fixed buffer, then
   * RANGE-WEAKNESS: CWE-78 the result is handed to a shell. */
  sprintf(cmd, "ls %s", argv[1]);
  system(cmd);
  copy_name(argv[1]);
  read_line();
  return 0;
}
""",
)


# ======================================================================================
# The clean tree — the negative control
# ======================================================================================

_BANNER_CLEAN = '''"""{title}

PART OF THE VIGIL LOOPBACK RANGE — THE CLEAN NEGATIVE CONTROL.
Same application as the sibling ``vulnerable/`` tree, written the safe way, with no credentials
anywhere. A code-reading tool that reports anything here is producing a false positive, and that is
exactly what this tree is for: a detector that only ever says "found something" is worthless.
"""
'''

_c(
    "README.md",
    """# VIGIL RANGE — clean source fixture (negative control)

The same application as the sibling `vulnerable/` tree, written safely: parameterised SQL, no shell,
modern hashing, cryptographic randomness, constant-time comparison, bounded C string handling,
output encoding — and **no credentials of any kind**, real or fabricated.

The expected result of scanning this tree is **nothing**. It is deliberately quiet at every severity
rather than only at high, because a control that is clean only above a threshold lets an entire
class of false positive through unmeasured.

Generated by `tools/livefire/range_source.py`. Byte-identical on every run.
""",
)

_c(
    "app/dal.py",
    _BANNER_CLEAN.format(title="Data access for the range fixture app.")
    + '''
import hashlib
import json
import sqlite3

import yaml
from flask import request


def find_user(username):
    """Look a user up by name."""
    conn = sqlite3.connect("range.db")
    # Parameterised: the driver sends the statement and the value separately, so the value can never
    # be read as syntax.
    return conn.execute(
        "SELECT id, email FROM users WHERE username = ?", (username,)
    ).fetchall()


def http_find_user():
    return find_user(request.args["username"])


def password_digest(password, salt):
    # A slow, salted KDF — the shape password storage actually needs.
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()


def load_session(blob):
    # JSON builds data, never objects, so untrusted input cannot become code.
    return json.loads(blob)


def load_profile(text):
    # safe_load constructs only plain scalars, lists and mappings.
    return yaml.safe_load(text)


def http_load_session():
    return load_session(request.get_data())
''',
)

_c(
    "app/admin.py",
    _BANNER_CLEAN.format(title="Administrative endpoints for the range fixture app.")
    + '''
import os
import socket

import requests
from flask import Flask, abort, request

app = Flask(__name__)

# An allow-list of things this endpoint may do, so no request parameter ever becomes part of a
# command. There is no shell in this module at all.
_PROBES = {"dns": socket.gethostbyname, "reverse": socket.gethostbyaddr}


@app.route("/admin/ping")
def ping():
    probe = _PROBES.get(request.args.get("probe", ""))
    if probe is None:
        abort(400)
    return str(probe(request.args.get("host", "localhost")))


@app.route("/admin/report")
def report():
    name = request.args.get("name", "")
    root = os.path.realpath("/var/reports")
    path = os.path.realpath(os.path.join(root, name))
    # Resolve first, then confirm the result is still inside the root: this rejects `../`,
    # absolute paths and symlinks alike, which prefix-matching before resolution does not.
    if os.path.commonpath([root, path]) != root:
        abort(403)
    with open(path) as fh:
        return fh.read()


def fetch(url):
    # Certificate validation left on, and a timeout so a hung peer cannot pin the worker.
    return requests.get(url, timeout=10)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
''',
)

_c(
    "app/crypto.py",
    _BANNER_CLEAN.format(title="Secrets and token handling for the range fixture app.")
    + '''
import hmac
import os
import secrets

# Configuration names the environment variable; the value itself is never in the source, so there is
# nothing here for a secret scanner to find and nothing to leak in a diff.
DB_CRED_ENV = "VIGIL_RANGE_DB_CRED"
JWT_KEY_ENV = "VIGIL_RANGE_JWT_KEY"


def db_credential():
    return os.environ[DB_CRED_ENV]


def session_token():
    # A cryptographically secure generator, so observing past tokens says nothing about future ones.
    return secrets.token_hex(32)


def compare_token(supplied, expected):
    # Constant-time: the time taken does not depend on how long a matching prefix was.
    return hmac.compare_digest(supplied, expected)
''',
)

_c(
    "config/settings.example.yml",
    """# Configuration TEMPLATE. Values are supplied at deploy time from the environment; no secret is
# ever written here. This file is the clean control's counterpart to the vulnerable tree's
# credentials.yml, and it deliberately contains nothing a secret scanner should match.
aws:
  access_key_id: ${AWS_ACCESS_KEY_ID}
  secret_access_key: ${AWS_SECRET_ACCESS_KEY}
slack:
  bot_token: ${SLACK_BOT_TOKEN}
stripe:
  secret_key: ${STRIPE_SECRET_KEY}
database:
  url: ${DATABASE_URL}
""",
)

_c(
    "web/server.js",
    """// PART OF THE VIGIL LOOPBACK RANGE — THE CLEAN NEGATIVE CONTROL.
// The same endpoints as the vulnerable tree, written safely. Scanning this should report nothing.
const express = require("express");
const dns = require("dns");

const app = express();

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[c]);

app.get("/lookup", (req, res) => {
  // A resolver library call: no shell is involved, so no metacharacter can be one.
  dns.resolve4(String(req.query.domain || ""), (err, addrs) =>
    err ? res.status(400).end() : res.json(addrs)
  );
});

app.get("/echo", (req, res) => {
  // Encoded on the way out, so the parameter can only ever be text.
  res.send("<h1>" + escapeHtml(req.query.q) + "</h1>");
});

app.get("/calc", (req, res) => {
  // A fixed set of operations, chosen by name. Nothing is compiled from the request.
  const ops = { add: (a, b) => a + b, mul: (a, b) => a * b };
  const op = ops[String(req.query.op)];
  if (!op) return res.status(400).end();
  res.json(op(Number(req.query.a), Number(req.query.b)));
});

module.exports = app;
""",
)

_c(
    "native/parse.c",
    """/* PART OF THE VIGIL LOOPBACK RANGE — THE CLEAN NEGATIVE CONTROL.
 * The same routines as the vulnerable tree, with every bound checked and no shell anywhere. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_name(const char *src, char *out, size_t out_len) {
  /* Bounded, and always terminated: snprintf writes at most out_len-1 bytes plus the NUL. */
  snprintf(out, out_len, "%s", src);
}

void read_line(char *line, size_t line_len) {
  /* fgets takes the buffer size, so it cannot be made to write past it. */
  if (fgets(line, (int)line_len, stdin) == NULL) {
    line[0] = '\\0';
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    return 1;
  }
  char name[64];
  char line[64];
  copy_name(argv[1], name, sizeof(name));
  read_line(line, sizeof(line));
  printf("%s %s", name, line);
  return 0;
}
""",
)


# ======================================================================================
# Materialisation, fingerprinting, git
# ======================================================================================

TREES: dict[str, dict[str, tuple[int, str]]] = {
    "vulnerable": VULNERABLE_FILES,
    "clean": CLEAN_FILES,
}

#: Frozen git identity. The trees are their own repositories because gitleaks and trufflehog both
#: have history-scanning modes that need one; freezing the identity and the timestamps keeps the
#: commit reproducible instead of embedding whoever ran it and when.
_GIT_ENV = {
    "GIT_AUTHOR_NAME": "VIGIL Range",
    "GIT_AUTHOR_EMAIL": "range@vigil.invalid",
    "GIT_AUTHOR_DATE": "2020-01-01T00:00:00+00:00",
    "GIT_COMMITTER_NAME": "VIGIL Range",
    "GIT_COMMITTER_EMAIL": "range@vigil.invalid",
    "GIT_COMMITTER_DATE": "2020-01-01T00:00:00+00:00",
}


def fingerprint(files: dict[str, tuple[int, str]]) -> str:
    """Content id of one tree: SHA-256 over ``path\\0mode\\0sha256(bytes)`` for every file, sorted.

    Deliberately not a git hash. Git's object format depends on configuration (SHA-1 versus SHA-256
    repositories) and its own version, so a git hash would be a fingerprint of the toolchain as much
    as of the content. This one depends on nothing but the bytes.
    """
    h = hashlib.sha256()
    for path in sorted(files):
        mode, text = files[path]
        h.update(path.encode())
        h.update(b"\0")
        h.update(f"{mode:o}".encode())
        h.update(b"\0")
        h.update(hashlib.sha256(text.encode()).hexdigest().encode())
        h.update(b"\n")
    return h.hexdigest()


def fingerprints() -> dict[str, str]:
    return {name: fingerprint(files) for name, files in TREES.items()}


def _git(repo: Path, *args: str) -> None:
    env = dict(os.environ)
    env.update(_GIT_ENV)
    subprocess.run(
        ["git", *args],
        cwd=str(repo),
        env=env,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def _git_out(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(repo), check=True, capture_output=True, text=True
    ).stdout.strip()


def write_tree(root: Path, name: str) -> tuple[Path, str]:
    """Materialise one tree at ``root/name``, replacing anything already there.

    Replacing rather than merging is what makes ``--generate`` idempotent: a leftover file from an
    older revision of this generator would otherwise stay behind and be scanned, quietly changing
    the answer the tools are scored against.
    """
    files = TREES[name]
    dest = root / name
    if dest.exists():
        shutil.rmtree(dest)
    for path, (mode, text) in files.items():
        target = dest / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        target.chmod(mode)

    _git(dest, "-c", "init.defaultBranch=main", "init")
    _git(dest, "-c", "user.name=VIGIL Range", "-c", "user.email=range@vigil.invalid", "add", "-A")
    _git(
        dest,
        "-c",
        "user.name=VIGIL Range",
        "-c",
        "user.email=range@vigil.invalid",
        "commit",
        "-m",
        f"VIGIL range fixture: {name}",
    )
    return dest, _git_out(dest, "rev-parse", "HEAD")


def on_disk_fingerprint(dest: Path) -> str:
    """Recompute the content id from what is actually on disk, ignoring the ``.git`` directory."""
    files: dict[str, tuple[int, str]] = {}
    for path in sorted(dest.rglob("*")):
        if ".git" in path.relative_to(dest).parts or not path.is_file():
            continue
        rel = str(path.relative_to(dest))
        files[rel] = (path.stat().st_mode & 0o777, path.read_text(encoding="utf-8"))
    return fingerprint(files)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", help="directory to hold vulnerable/ and clean/")
    ap.add_argument("--generate", action="store_true", help="write both trees")
    ap.add_argument("--verify", action="store_true", help="check the on-disk trees")
    ap.add_argument("--remove", action="store_true", help="delete both trees")
    ap.add_argument("--fingerprint", action="store_true", help="print content ids and exit")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    if args.fingerprint:
        print(json.dumps(fingerprints(), indent=2) if args.json else "\n".join(
            f"{k}: {v}" for k, v in sorted(fingerprints().items())
        ))
        return 0

    if not args.root:
        print("--root is required for --generate/--verify/--remove", file=sys.stderr)
        return 2
    root = Path(args.root)

    if args.remove:
        for name in TREES:
            shutil.rmtree(root / name, ignore_errors=True)
        # Only remove the parent if the range left nothing else in it.
        try:
            root.rmdir()
        except OSError:
            pass
        return 0

    if args.generate:
        root.mkdir(parents=True, exist_ok=True)
        out = {}
        for name in TREES:
            dest, commit = write_tree(root, name)
            expected = fingerprints()[name]
            actual = on_disk_fingerprint(dest)
            if actual != expected:
                # Writing the tree and then re-reading it must round-trip exactly; if it does not,
                # something (an encoding, a umask, a filesystem that rewrites modes) has altered the
                # corpus, and every result measured against it would be measured against something
                # other than what this file says.
                print(
                    f"FAIL: {name} tree does not match its own content id after writing\n"
                    f"  expected {expected}\n  on disk  {actual}",
                    file=sys.stderr,
                )
                return 1
            out[name] = {
                "path": str(dest),
                "fingerprint": actual,
                "commit": commit,
                "files": len(TREES[name]),
            }
        print(json.dumps(out, indent=2))
        return 0

    if args.verify:
        failures = []
        for name in TREES:
            dest = root / name
            if not dest.is_dir():
                failures.append(f"{name}: missing at {dest}")
                continue
            actual = on_disk_fingerprint(dest)
            if actual != fingerprints()[name]:
                failures.append(
                    f"{name}: content id {actual} != expected {fingerprints()[name]}"
                )
        for f in failures:
            print(f"FAIL {f}", file=sys.stderr)
        return 1 if failures else 0

    ap.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
