"""REAL sovereign homes for tests — each built and read by a CHILD process whose SIGIL_HOME is that home.

The head / floor / key / archive paths are import-time process globals, so a test that needs a second, real home
(a backup source, a restore target, a drill subject) builds and reads it in a child process. ``signed_home`` builds
a segmented spine with an owner-signed head, the floor and the owner keypair under ``home/spine/keys`` —
optionally cold-archive PRUNED at seq 10 (segments of 5 records; the snapshot lands at seq 23). ``world=True`` makes
the first two records an engaged kill switch and a 100-credit wallet grant for ``acme``, so a pruned home carries
both only in its snapshot seed.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

MAKE_HOME = """
import sys
from sigil import config
from sigil.spine import checkpoint as cp, prune
from sigil.spine.store import SpineStore
s = SpineStore(config.SPINE_PATH)
s.migrate()
seq = 0
if len(sys.argv) > 2 and sys.argv[2] == "world":
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.killswitch import KillSwitch
    from sigil.governor.wallet import WalletRegistry
    ensure_owner_keypair()
    KillSwitch(s).engage(reason="incident")
    WalletRegistry(s).grant("acme", 100, "trial", entry_id="g1", issued_at=1.0)
    seq = 2
for _seg in range(4):
    while seq < 5 * (_seg + 1):
        s.append(kind="event", source="t", actor="u", payload={"i": seq}); seq += 1
    s.rotate()
for _i in range(3):
    s.append(kind="event", source="t", actor="u", payload={"i": seq}); seq += 1
cp.checkpoint(s)
if sys.argv[1] == "prune":
    prune.commit_prune(s, 10, confirm=True)
"""

# Read a home the way its services would: prints one JSON line of what the seeded readers answer.
READ_HOME = """
import json
from sigil import config
from sigil.governor.killswitch import KillSwitch
from sigil.governor.wallet import WalletRegistry
from sigil.spine import checkpoint as cp, prune
from sigil.spine.store import SpineStore
s = SpineStore(config.SPINE_PATH)
out = {"verify_checkpoint": list(cp.verify_checkpoint(s)), "verify_archive": list(prune.verify_with_archive(s))}
try:
    out["killswitch_engaged"] = KillSwitch(s).is_engaged()
    out["wallet_acme"] = WalletRegistry(s).available("acme")
except Exception as e:
    out["read_error"] = f"{type(e).__name__}: {e}"
print(json.dumps(out))
"""


def env(home, **extra):
    """(env, python) for a child process whose SIGIL_HOME is ``home`` and that imports this checkout's sigil."""
    import sigil
    e = dict(os.environ)
    e["SIGIL_HOME"] = str(home)
    root = str(Path(sigil.__file__).resolve().parent.parent)
    e["PYTHONPATH"] = os.pathsep.join([root] + ([e["PYTHONPATH"]] if e.get("PYTHONPATH") else []))
    for k, v in extra.items():
        if v is None:
            e.pop(k, None)
        else:
            e[k] = str(v)
    return e, sys.executable


def signed_home(tmp_path, *, pruned: bool, name: str = "realhome", world: bool = False, archive_dir=None) -> Path:
    """A REAL sovereign home (its own SIGIL_HOME, built in a child process): a segmented spine with an
    owner-signed head + floor + owner keypair under ``home/spine/keys`` — optionally cold-archive PRUNED (into
    ``archive_dir`` when given, else the default ``spine/archive``)."""
    home = Path(tmp_path) / name
    home.mkdir()
    e, py = env(home, SIGIL_SPINE_ARCHIVE_DIR=str(archive_dir) if archive_dir is not None else None)
    argv = [py, "-c", MAKE_HOME, "prune" if pruned else "keep"] + (["world"] if world else [])
    subprocess.run(argv, env=e, check=True)
    assert (home / "spine" / "keys" / "owner.priv").is_file() and (home / "spine" / "head.json").is_file()
    return home


def run_in_home(home, code: str, *args: str, check: bool = True, **extra) -> "subprocess.CompletedProcess[str]":
    """Run ``python -c code args…`` with SIGIL_HOME=home (``extra`` env overrides; None removes a variable)."""
    e, py = env(home, **extra)
    return subprocess.run([py, "-c", code, *args], env=e, check=check, capture_output=True, text=True)


def read_home(home, *, fold_cache: bool = False, archive_dir=None) -> dict:
    """What the seeded readers of ``home`` answer, read in a child whose SIGIL_HOME is ``home``."""
    import json
    proc = run_in_home(home, READ_HOME, VIGIL_FOLD_CACHE_ENABLED="1" if fold_cache else None,
                       SIGIL_SPINE_ARCHIVE_DIR=str(archive_dir) if archive_dir is not None else None)
    return json.loads(proc.stdout.strip().splitlines()[-1])


# Back up the home the child runs in (its own SIGIL_HOME); prints the summary as one JSON line.
BACKUP_HOME = """
import json, sys
from sigil import config
from sigil.backup import BackupError, create_backup
from sigil.governor.identity import ensure_owner_keypair
from sigil.platform.vault import owner_vault
try:
    res = create_backup(sys.argv[1], "pw-test-only", home=config.SIGIL_HOME, vault=owner_vault(),
                        owner_key=ensure_owner_keypair())
except BackupError as e:
    res = {"error": str(e)}
print(json.dumps(res))
"""

PW = "pw-test-only"


def backup_home(home, dest, *, flag: bool = True, **extra) -> dict:
    """``sigil backup`` of ``home`` run as that home (SIGIL_PRUNED_RESTORE on unless ``flag`` is False)."""
    import json
    proc = run_in_home(home, BACKUP_HOME, str(dest), SIGIL_PRUNED_RESTORE="1" if flag else None, **extra)
    return json.loads(proc.stdout.strip().splitlines()[-1])


def open_backup(path) -> dict:
    """Decrypt a backup file (test passphrase) and return its body (manifest + file table)."""
    import json
    from sigil import backup as b
    from vigil_core.sealing import unseal
    salt, sealed = b._read_header(Path(path))
    return json.loads(unseal(b._derive_key(PW, salt), sealed, context=b._BODY_CONTEXT).decode("utf-8"))
