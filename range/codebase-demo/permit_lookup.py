"""MERIDIA Permit-Lookup service — a DELIBERATELY VULNERABLE demo codebase (source-level).

Companion to the MERIDIAN cyber-range: a tiny microservice used to demonstrate VIGIL's *codebase* scan and
its automated fix, at the source level. Every function below plants one canonical, textbook vulnerability on
its own line, so a fix is a clean 1-3 line diff you can show directly. LAB ONLY — do not deploy, no real data.
"""

import hashlib
import os
import pickle
import random
import sqlite3  # noqa: F401  (used by the caller that passes `db`)

# CWE-798 — hardcoded secret committed in source
API_KEY = "sk-meridia-9f3a2c7b-DO-NOT-SHIP"


def lookup_permit(db, permit_no):
    """Look up a permit by number."""
    cur = db.cursor()
    # CWE-89 — SQL injection: the permit number is formatted straight into the SQL text
    cur.execute("SELECT holder_name, status FROM permits WHERE permit_no = '%s'" % permit_no)
    return cur.fetchall()


def hash_password(password):
    # CWE-327 — weak hash for a password
    return hashlib.md5(password.encode()).hexdigest()


def generate_report(permit_no):
    # CWE-78 — OS command injection: user input concatenated into a shell command
    os.system("meridia-report --permit " + permit_no)


def load_saved_search(blob):
    # CWE-502 — insecure deserialization of untrusted data
    return pickle.loads(blob)


def read_attachment(path):
    # CWE-22 — path traversal: an unchecked user path is opened
    with open(path) as fh:
        return fh.read()


def evaluate_fee_rule(expression):
    # CWE-95 — code injection via eval() of user-supplied input
    return eval(expression)  # noqa: S307


def new_reference():
    # CWE-330 — insecure randomness for a security-relevant token
    return "REF-" + str(random.randint(1000, 9999))
