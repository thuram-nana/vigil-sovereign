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
    r"allow-change-held-packages|Check-Valid-Until|Verify-Peer|Verify-Host",
    re.IGNORECASE,
)


def _exe(p: Path, body: str) -> None:
    p.write_text(body, encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# Records each call (tab-separated argv). For a fallback call (one naming Dir::Etc::SourceParts) it also
# records the source file it was given and that file's mode, then fails if that URI is in STUB_APT_FAIL_URIS.
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
exit 0
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
         pkgs: tuple[str, ...] = ("nftables",)):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _exe(bindir / "sudo", '#!/usr/bin/env bash\nexec "$@"\n')
    _exe(bindir / "apt-get", _APT_STUB)
    _exe(bindir / "getent", _GETENT_STUB)
    sources = tmp_path / "ubuntu.sources"
    sources.write_text(
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
    assert "Suites: resolute resolute-updates resolute-security" in srcs
    assert f"Signed-By: {ring}" in srcs
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


def test_an_unresolvable_fallback_mirror_is_skipped(tmp_path: Path):
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=["mirror-two.example"])
    assert proc.returncode == 0, proc.stderr
    assert "mirror host mirror-one.example does not resolve either; skipping it" in proc.stderr
    assert f"URIs: {M2}" in srcs and f"URIs: {M1}" not in srcs


def test_a_failing_fallback_mirror_moves_on_to_the_next(tmp_path: Path):
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=["mirror-one.example", "mirror-two.example"],
                                   fail_uris=[M1])
    assert proc.returncode == 0, proc.stderr
    assert f"mirror {M1} failed; trying the next one" in proc.stderr
    assert srcs.count(f"URIs: {M1}") == 1 and srcs.count(f"URIs: {M2}") >= 1


def test_every_fallback_failing_fails_the_step(tmp_path: Path):
    proc, calls, srcs, _, _ = _run(tmp_path, resolvable=["mirror-one.example", "mirror-two.example"],
                                   fail_uris=[M1, M2])
    assert proc.returncode == 1
    assert "::error::apt-get failed installing: nftables" in proc.stderr
    assert f"URIs: {M1}" in srcs and f"URIs: {M2}" in srcs


def test_a_plain_http_fallback_mirror_is_refused(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"],
                                mirrors="http://mirror-one.example/ubuntu/")
    assert proc.returncode == 1
    assert "refusing mirror 'http://mirror-one.example/ubuntu/'" in proc.stderr
    assert calls == []   # nothing was fetched from it


def test_a_mirror_without_a_trailing_slash_is_refused(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"],
                                mirrors="https://mirror-one.example/ubuntu")
    assert proc.returncode == 1
    assert calls == []


def test_a_missing_ubuntu_keyring_refuses_the_fallback(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"], keyring=False)
    assert proc.returncode == 1
    assert "keyring" in proc.stderr and "missing" in proc.stderr
    assert calls == []


def test_an_invalid_codename_refuses_the_fallback(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"], codename="bad name\nTrusted: yes")
    assert proc.returncode == 1
    assert "cannot determine a valid Ubuntu codename" in proc.stderr
    assert calls == []


def test_an_empty_mirror_list_disables_the_fallback(tmp_path: Path):
    proc, calls, _, _, _ = _run(tmp_path, resolvable=["mirror-one.example"], mirrors="")
    assert proc.returncode == 1
    assert "no fallback mirror is configured" in proc.stderr
    assert calls == []


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
    """No workflow may call apt-get directly: a raw call gets neither the hang bound nor the fallback."""
    raw = re.compile(r"\bapt(-get)?\s+(update|install)\b")
    offenders = []
    for wf in sorted((_ROOT / ".github").rglob("*.y*ml")):
        for n, ln in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            if ln.lstrip().startswith("#"):
                continue
            if raw.search(ln):
                offenders.append(f"{wf.relative_to(_ROOT)}:{n}: {ln.strip()}")
    assert not offenders, "use .github/scripts/apt-retry.sh instead of raw apt:\n" + "\n".join(offenders)
