"""MERIDIA Permit-Lookup service — the FIXED twin of permit_lookup.py.

The remediated version: every one of the 8 planted vulnerabilities is closed with its canonical fix. This is
the diff VIGIL's `vigil patch` coder proposes (grounded in each confirmed finding) — shown here applied, so
the before/after reads directly against permit_lookup.py.
"""

import ast
import hashlib
import json
import os
import secrets
import subprocess

# FIX CWE-798 — read the secret from the environment, never hardcode it
API_KEY = os.environ["MERIDIA_API_KEY"]


def lookup_permit(db, permit_no):
    """Look up a permit by number."""
    cur = db.cursor()
    # FIX CWE-89 — parameterized query: the value can never reach the SQL text
    cur.execute("SELECT holder_name, status FROM permits WHERE permit_no = ?", (permit_no,))
    return cur.fetchall()


def hash_password(password):
    # FIX CWE-327 — a strong hash (use bcrypt/argon2 with a salt for real password storage)
    return hashlib.sha256(password.encode()).hexdigest()


def generate_report(permit_no):
    # FIX CWE-78 — no shell; the argument is passed as a separate argv element
    subprocess.run(["meridia-report", "--permit", permit_no], check=True)


def load_saved_search(blob):
    # FIX CWE-502 — a safe data format instead of pickle
    return json.loads(blob)


def read_attachment(path):
    # FIX CWE-22 — resolve and contain the path under a fixed base directory
    base = os.path.realpath("/srv/meridia/attachments")
    full = os.path.realpath(os.path.join(base, path))
    if not full.startswith(base + os.sep):
        raise ValueError("path outside the attachments directory")
    with open(full) as fh:
        return fh.read()


def evaluate_fee_rule(expression):
    # FIX CWE-95 — literal evaluation only, never arbitrary code
    return ast.literal_eval(expression)


def new_reference():
    # FIX CWE-330 — a cryptographically secure token
    return "REF-" + secrets.token_hex(4)
