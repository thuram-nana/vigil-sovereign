"""apt-retry.sh falls back to a signature-checked HTTPS Ubuntu mirror when the default mirrors are unreachable.

On 2026-11-11 GitHub-hosted runners could not resolve the Ubuntu mirror hostnames for hours, so every
apt-installing job failed before it ran a test, and retrying the same mirror could not help. The helper now
detects that (a DNS probe of the hosts in the runner's own apt sources) and installs from a fallback mirror.

These tests run the real script against stubs (`sudo`, `getent`, `apt-get`), so they are hermetic: no
network, no root, no real apt. They pin both halves of the contract:
  * it RECOVERS: a DNS outage, or repeated failure on the defaults, ends in an install from a fallback;
  * it NEVER WEAKENS INTEGRITY: the fallback is HTTPS only, carries `Signed-By:` the Ubuntu archive keyring,
    passes no insecure apt option, and refuses (fails closed) when it cannot meet those terms.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / ".github" / "scripts" / "apt-retry.sh"

DEFAULT_HOST = "azure.archive.ubuntu.com"
M1 = "https://mirror-one.example/ubuntu/"
M2 = "https://mirror-two.example/ubuntu/"

# apt options/terms that would let a mirror bypass signature checking. None may ever be passed.
_INSECURE = re.compile(
    r"allow-unauthenticated|allow-insecure|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories|"
    r"AllowWeakRepositories|Trusted|trusted=yes|--force-yes|allow-downgrades|allow-remove-essential|"
    r"allow-change-held-packages|Check-Valid-Until|Check-Date|Verify-Peer|Verify-Host|AllowUnauthenticated|"
    r"apt-key|gpg --import|trusted\.gpg",
    re.IGNORECASE,
)


def _exe(p: Path, body: str) -> None:
    p.write_text(body, encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# Records each call (tab-separated argv). For a fallback call (one naming Dir::Etc::SourceParts) it also
# records the source file it was given and that file's mode, then fails if that URI is in STUB_APT_FAIL_URIS
# or its host is not in STUB_RESOLVABLE (as real apt fails on a mirror it cannot resolve).
_APT_STUB = r"""#!/usr/bin/env bash
log="$STUB_APT_LOG"
parts=""
for a in "$@"; do
  case "$a" in Dir::Etc::SourceParts=*) parts="${a#Dir::Etc::SourceParts=}" ;; esac
done
{ printf 'CALL'; for a in "$@"; do printf '\t%s' "$a"; done; printf '\n'; } >> "$log"
if [ -z "$parts" ]; then
  exit "${STUB_APT_DEFAULT_RC:-0}"
fi
for f in "$parts"/*.sources; do
  printf 'MODE\t%s\n' "$(stat -c '%a' "$f")" >> "$log"
  sed 's/^/SRC\t/' "$f" >> "$log"
done
uri="$(grep -h '^URIs:' "$parts"/*.sources | head -n1 | sed 's/^URIs: //')"
for bad in ${STUB_APT_FAIL_URIS:-}; do
  if [ "$bad" = "$uri" ]; then exit 100; fi
done
host="${uri#https://}"; host="${host%%/*}"
for h in ${STUB_RESOLVABLE:-}; do
  if [ "$h" = "$host" ]; then exit 0; fi
done
exit 100
"""

# Resolves only the hosts named in STUB_RESOLVABLE.
_GETENT_STUB = r"""#!/usr/bin/env bash
[ "$1" = "hosts" ] || exit 2
for h in ${STUB_RESOLVABLE:-}; do
  if [ "$h" = "$2" ]; then echo "192.0.2.1 $2"; exit 0; fi
done
exit 2
"""


def _run(tmp_path: Path, *, resolvable: list[str], mirrors: str | None = f"{M1} {M2}",
         default_rc: int = 0, fail_uris: list[str] | None = None, keyring: bool = True,
         codename: str = "resolute", extra_env: dict[str, str] | None = None,
         pkgs: tuple[str, ...] = ("nftables",), sources_text: str | None = None,
         extra_files: dict[str, str] | None = None):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _exe(bindir / "sudo", '#!/usr/bin/env bash\nexec "$@"\n')
    _exe(bindir / "apt-get", _APT_STUB)
    _exe(bindir / "getent", _GETENT_STUB)
    for name, body in (extra_files or {}).items():
        (tmp_path / name).write_text(body.replace("{tmp}", str(tmp_path)), encoding="utf-8")
    sources = tmp_path / "ubuntu.sources"
    sources.write_text(
        sources_text.replace("{tmp}", str(tmp_path)) if sources_text is not None else
        "Types: deb\n"
        f"URIs: http://{DEFAULT_HOST}/ubuntu/\n"
        "Suites: resolute resolute-updates resolute-backports\n"
        "Components: main restricted universe multiverse\n"
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n",
        encoding="utf-8",
    )
    ring = tmp_path / "ubuntu-archive-keyring.gpg"
    if keyring:
        ring.write_bytes(b"\x99\x01\x0dnot-a-real-key-but-non-empty")
    log = tmp_path / "apt.log"
    log.write_text("", encoding="utf-8")
    env = dict(os.environ)
    env.update({
        "PATH": f"{bindir}:{env['PATH']}",
        "STUB_APT_LOG": str(log),
        "STUB_RESOLVABLE": " ".join(resolvable),
        "STUB_APT_DEFAULT_RC": str(default_rc),
        "STUB_APT_FAIL_URIS": " ".join(fail_uris or []),
        "APT_RETRY_SOURCES_FILES": str(sources),
        "APT_RETRY_UBUNTU_KEYRING": str(ring),
        "APT_RETRY_CODENAME": codename,
        "APT_RETRY_DEFAULT_ATTEMPTS": "1",   # no backoff sleeps in the tests
        "APT_RETRY_UPDATE_TIMEOUT": "20",
        "APT_RETRY_INSTALL_TIMEOUT": "20",
    })
    if mirrors is None:
        env.pop("APT_RETRY_FALLBACK_MIRRORS", None)
    else:
        env["APT_RETRY_FALLBACK_MIRRORS"] = mirrors
    env.update(extra_env or {})
    proc = subprocess.run(["bash", str(_SCRIPT), *pkgs], env=env, capture_output=True, text=True,
                          timeout=120)
    lines = log.read_text(encoding="utf-8").splitlines()
    calls = [ln.split("\t")[1:] for ln in lines if ln.startswith("CALL")]
    srcs = [ln.split("\t", 1)[1] for ln in lines if ln.startswith("SRC\t")]
    modes = [ln.split("\t", 1)[1] for ln in lines if ln.startswith("MODE\t")]
    return proc, calls, srcs, modes, ring


def _is_fallback(call: list[str]) -> bool:
    return any(a.startswith("Dir::Etc::SourceParts=") for a in call)


def _assert_no_insecure(calls: list[list[str]], srcs: list[str]) -> None:
    for call in calls:
        for a in call:
            assert not _INSECURE.search(a), f"insecure apt option passed: {a!r} in {call}"
    for line in srcs:
        assert not _INSECURE.search(line), f"insecure source-list field written: {line!r}"


def test_dns_outage_installs_from_a_signed_https_fallback_without_trying_the_defaults(tmp_path: Path):
    proc, calls, srcs, modes, ring = _run(tmp_path, resolvable=["mirror-one.example", "mirror-two.example"])
    assert proc.returncode == 0, proc.stderr
    assert "cannot resolve the default Ubuntu mirror host(s): azure.archive.ubuntu.com" in proc.stderr
    # Detected fast: the unreachable defaults are never attempted at all.
    assert calls and all(_is_fallback(c) for c in calls), calls
    # One update + one install, both against ONLY the fallback list.
    assert [c[0] for c in calls] == ["update", "install"], calls
    for c in calls:
        assert "Dir::Etc::SourceList=/dev/null" in c, c
    assert calls[1][-1] == "nftables" and "-y" in calls[1]
    # The fallback source: HTTPS, the first mirror, all three suites, pinned to the Ubuntu archive key.
    assert f"URIs: {M1}" in srcs
    assert "Suites: resolute resolute-updates" in srcs
    assert "Suites: resolute-security" in srcs
    # Both stanzas are pinned to the Ubuntu archive key, and the -security one to a maximum index age.
    assert srcs.count(f"Signed-By: {ring}") == 4   # 2 stanzas, recorded for the update and the install
    assert srcs.count("Valid-Until-Max: 1209600") == 2
    # The fallback keeps the runner's own package lists (it adds its indexes, it does not replace them).
    assert all("APT::Get::List-Cleanup=0" in c for c in calls), calls
    assert modes == ["644", "644"]   # world-readable source file, seen by both the update and the install
    _assert_no_insecure(calls, srcs)


def test_healthy_defaults_are_used_and_no_fallback_is_written(tmp_path: Path):
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=[DEFAULT_HOST, "mirror-one.example"])
    assert proc.returncode == 0, proc.stderr
    assert [c[0] for c in calls] == ["update", "install"], calls
    assert not any(_is_fallback(c) for c in calls)
    assert srcs == []
    _assert_no_insecure(calls, srcs)


def test_repeated_failure_on_resolvable_defaults_falls_back(tmp_path: Path):
    proc, calls, srcs, _, ring = _run(tmp_path, resolvable=[DEFAULT_HOST, "mirror-one.example"],
                                      default_rc=100)
    assert proc.returncode == 0, proc.stderr
    assert "trying the fallback mirrors" in proc.stderr
    assert not _is_fallback(calls[0]) and calls[0][0] == "update"   # defaults tried first
    assert _is_fallback(calls[-1]) and calls[-1][0] == "install"
    assert f"Signed-By: {ring}" in srcs
    _assert_no_insecure(calls, srcs)


def test_an_unreachable_fallback_mirror_is_attempted_then_the_next_is_used(tmp_path: Path):
    """No DNS pre-check skips a fallback mirror (a slow resolver must not skip a working one): apt decides."""
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=["mirror-two.example"])
    assert proc.returncode == 0, proc.stderr
    assert f"mirror {M1} failed; trying the next one" in proc.stderr
    assert f"URIs: {M1}" in srcs and f"URIs: {M2}" in srcs
    assert all(_is_fallback(c) for c in calls)   # the defaults were not needed


def test_a_failing_fallback_mirror_moves_on_to_the_next(tmp_path: Path):
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=["mirror-one.example", "mirror-two.example"],
                                   fail_uris=[M1])
    assert proc.returncode == 0, proc.stderr
    assert f"mirror {M1} failed; trying the next one" in proc.stderr
    # M1 is tried exactly once (its update fails): one source file, two stanzas, so two URIs lines.
    assert srcs.count(f"URIs: {M1}") == 2 and srcs.count(f"URIs: {M2}") >= 2


def test_every_fallback_and_default_failing_fails_the_step(tmp_path: Path):
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=["mirror-one.example", "mirror-two.example"],
                                   fail_uris=[M1, M2], default_rc=100)
    assert proc.returncode == 1
    assert "::error::apt-get failed installing: nftables" in proc.stderr
    assert f"URIs: {M1}" in srcs and f"URIs: {M2}" in srcs
    # The probe fired, so the fallback went first; the defaults were still tried before giving up.
    assert _is_fallback(calls[0]) and not _is_fallback(calls[-1]), calls


def test_a_probe_hit_with_a_failing_fallback_still_tries_the_defaults(tmp_path: Path):
    """A partial outage or a resolver slower than the probe timeout: the probe fires, no fallback mirror
    works, but the default mirrors do. The step must pass (it did before the fallback existed)."""
    proc, calls, _, _, _ = _run(tmp_path, resolvable=[], default_rc=0)
    assert proc.returncode == 0, proc.stderr
    assert "trying the default mirrors anyway" in proc.stderr
    assert any(_is_fallback(c) for c in calls), calls
    assert [c[0] for c in calls if not _is_fallback(c)] == ["update", "install"], calls


def test_a_plain_http_fallback_mirror_is_refused(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"],
                                mirrors="http://mirror-one.example/ubuntu/", default_rc=100)
    assert proc.returncode == 1
    assert "refusing mirror 'http://mirror-one.example/ubuntu/'" in proc.stderr
    assert calls and not any(_is_fallback(c) for c in calls)   # nothing was fetched from it


def test_a_mirror_without_a_trailing_slash_is_refused(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"],
                                mirrors="https://mirror-one.example/ubuntu", default_rc=100)
    assert proc.returncode == 1
    assert calls and not any(_is_fallback(c) for c in calls)


def test_a_missing_ubuntu_keyring_refuses_the_fallback(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"], keyring=False, default_rc=100)
    assert proc.returncode == 1
    assert "keyring" in proc.stderr and "missing" in proc.stderr
    assert calls and not any(_is_fallback(c) for c in calls)


def test_a_keyring_path_that_is_not_a_plain_absolute_path_refuses_the_fallback(tmp_path: Path):
    """The keyring path is written into Signed-By: a newline must not smuggle a field into the source. Each
    hostile path is a REAL readable keyring file, so only the path check (not the existence check) stops it."""
    for i, name in enumerate(("ring\nTrusted: yes", "ring extra", "ring;x")):
        sub = tmp_path / f"k{i}"
        sub.mkdir()
        hostile = sub / name
        hostile.write_bytes(b"\x99\x01\x0dnot-a-real-key-but-non-empty")
        bad = str(hostile)
        proc, calls, srcs, _, _ = _run(sub, resolvable=["mirror-one.example"], default_rc=100,
                                       extra_env={"APT_RETRY_UBUNTU_KEYRING": bad})
        assert proc.returncode == 1, bad
        assert "not a plain absolute path" in proc.stderr, (bad, proc.stderr)
        assert not any(_is_fallback(c) for c in calls) and srcs == [], bad


def test_an_invalid_codename_refuses_the_fallback(tmp_path: Path):
    # The first value's FIRST line is valid: a line-by-line check would pass it and write `Trusted: yes`.
    # (An empty value is not "bad": it means "read /etc/os-release", the normal runner path.)
    for bad in ("resolute\nTrusted: yes", "bad name", "Resolute", "noble;rm"):
        sub = tmp_path / f"c{abs(hash(bad))}"
        sub.mkdir()
        proc, calls, srcs, _, _ = _run(sub, resolvable=["mirror-one.example"], codename=bad, default_rc=100)
        assert proc.returncode == 1, bad
        assert "cannot determine a valid Ubuntu codename" in proc.stderr, (bad, proc.stderr)
        assert not any(_is_fallback(c) for c in calls) and srcs == [], bad


def test_an_empty_mirror_list_disables_the_fallback(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"], mirrors="", default_rc=100)
    assert proc.returncode == 1
    assert "no fallback mirror is configured" in proc.stderr
    assert calls and not any(_is_fallback(c) for c in calls)


def test_the_default_mirror_list_is_https_only(tmp_path: Path):
    """With APT_RETRY_FALLBACK_MIRRORS unset, the built-in list is used; every entry must be HTTPS."""
    src = _SCRIPT.read_text(encoding="utf-8")
    m = re.search(r'_FALLBACK_MIRRORS="\$\{APT_RETRY_FALLBACK_MIRRORS-([^}]*)\}"', src)
    assert m, "the built-in fallback mirror list moved; update this guard"
    mirrors = m.group(1).split()
    assert len(mirrors) >= 2
    assert all(u.startswith("https://") and u.endswith("/") for u in mirrors), mirrors
    # And it is really used when the variable is unset.
    hosts = [u.split("/")[2] for u in mirrors]
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=hosts[:1], mirrors=None)
    assert proc.returncode == 0, proc.stderr
    assert f"URIs: {mirrors[0]}" in srcs


def test_the_script_never_contains_an_insecure_apt_option():
    """Static guard over the script's CODE (comments excluded: they name what is forbidden)."""
    code = [ln for ln in _SCRIPT.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")]
    for ln in code:
        assert not _INSECURE.search(ln), f"insecure apt option in apt-retry.sh: {ln!r}"
    assert any("Signed-By:" in ln for ln in code)


def test_every_workflow_apt_install_goes_through_the_helper():
    """No workflow (or script a workflow runs) may call apt directly: a raw call gets neither the hang bound
    nor the fallback. Catches flags before the verb (`apt-get -qq update`, `apt-get -o X=Y install`), the
    apt front-ends, and commands split over backslash continuations."""
    raw = re.compile(r"\b(apt-get|apt|aptitude|apt-fast|nala)\b[^#\n]*?\s(update|install|upgrade|dist-upgrade)\b")
    files = sorted((_ROOT / ".github").rglob("*.y*ml")) + sorted(
        f for f in (_ROOT / ".github").rglob("*.sh") if f.name != "apt-retry.sh")
    offenders = []
    for f in files:
        text = re.sub(r"\\\n\s*", " ", f.read_text(encoding="utf-8"))   # join backslash continuations
        for n, ln in enumerate(text.splitlines(), 1):
            if ln.lstrip().startswith("#"):
                continue
            if raw.search(ln.replace("apt-retry.sh", "")):
                offenders.append(f"{f.relative_to(_ROOT)}:{n}: {ln.strip()}")
    assert not offenders, "use .github/scripts/apt-retry.sh instead of raw apt:\n" + "\n".join(offenders)


def test_the_workflow_guard_regex_catches_the_common_spellings():
    raw = re.compile(r"\b(apt-get|apt|aptitude|apt-fast|nala)\b[^#\n]*?\s(update|install|upgrade|dist-upgrade)\b")
    for bad in ("sudo apt-get install -y x", "sudo -E apt-get -y install x", "apt-get -qq update",
                "apt-get --yes install x", "apt-get -o Acquire::Retries=3 install x", "apt install x",
                "sudo nala install x", "apt-fast install x"):
        assert raw.search(bad), bad
    for ok in ('bash "${GITHUB_WORKSPACE}/.github/scripts/apt-retry.sh" nmap hydra'.replace("apt-retry.sh", ""),
               "pip install mutmut", "npm install"):
        assert not raw.search(ok), ok


# --- the probe asks about the hosts apt will REALLY contact ----------------------------------------------
# The stock Ubuntu ubuntu.sources opens with a comment that carries a URL, and the GitHub runner image points
# its Ubuntu sources at `mirror+file:/etc/apt/apt-mirrors.txt`. On the runner, #1080's first CI run probed
# only the comment's host (help.ubuntu.com) and never the mirrors apt uses.
_RUNNER_SOURCES = (
    "# See http://help.dead.example/community/UpgradeNotes for how to upgrade to\n"
    "# future releases of the distribution.\n"
    "Types: deb\n"
    "URIs: mirror+file:{tmp}/apt-mirrors.txt\n"
    "Suites: resolute resolute-updates resolute-backports\n"
    "Components: main restricted universe multiverse\n"
    "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
)
_RUNNER_MIRRORS = (
    "# the image's mirror list\n"
    "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"
    "https://archive.ubuntu.com/ubuntu/\tpriority:2\n"
)


def test_a_url_in_a_comment_is_not_probed(tmp_path: Path):
    """The comment's host does not resolve, every real mirror does: the defaults must be used."""
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=["azure.archive.ubuntu.com", "archive.ubuntu.com"],
                                   sources_text=_RUNNER_SOURCES,
                                   extra_files={"apt-mirrors.txt": _RUNNER_MIRRORS})
    assert proc.returncode == 0, proc.stderr
    assert "help.dead.example" not in proc.stderr
    assert not any(_is_fallback(c) for c in calls), calls
    assert srcs == []


def test_the_mirror_list_behind_mirror_file_is_probed(tmp_path: Path):
    """The image's real mirror does not resolve: that must be detected (and named) before any default try."""
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=["archive.ubuntu.com", "mirror-one.example"],
                                   sources_text=_RUNNER_SOURCES,
                                   extra_files={"apt-mirrors.txt": _RUNNER_MIRRORS})
    assert proc.returncode == 0, proc.stderr
    assert "cannot resolve the default Ubuntu mirror host(s): azure.archive.ubuntu.com" in proc.stderr
    assert "help.dead.example" not in proc.stderr
    assert calls and all(_is_fallback(c) for c in calls), calls


def test_a_missing_mirror_list_is_not_an_error(tmp_path: Path):
    """A `mirror+file:` that points nowhere names no host; the defaults are then simply tried."""
    proc, calls, _, _, _ = _run(tmp_path, resolvable=[], sources_text=_RUNNER_SOURCES)
    assert proc.returncode == 0, proc.stderr
    assert [c[0] for c in calls] == ["update", "install"] and not any(_is_fallback(c) for c in calls)


def test_the_security_max_age_is_configurable_and_validated(tmp_path: Path):
    proc, _, srcs, _, _ = _run(tmp_path, resolvable=["mirror-one.example"],
                               extra_env={"APT_RETRY_SECURITY_MAX_AGE": "3600"})
    assert proc.returncode == 0, proc.stderr
    assert "Valid-Until-Max: 3600" in srcs
    for bad in ("", "0", "00", "0000", "-5", "10d", "1\nTrusted: yes", "12345678901"):
        sub = tmp_path / f"bad{abs(hash(bad))}"
        sub.mkdir()
        proc, _, srcs, _, _ = _run(sub, resolvable=["mirror-one.example"],
                                   extra_env={"APT_RETRY_SECURITY_MAX_AGE": bad})
        assert proc.returncode == 0, (bad, proc.stderr)
        assert "Valid-Until-Max: 1209600" in srcs, (bad, srcs)
        _assert_no_insecure([], srcs)
