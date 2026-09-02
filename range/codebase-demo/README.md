# Codebase-scan demo — MERIDIA Permit-Lookup service

> ⚠ **Deliberately vulnerable — lab only.** A tiny source-level target for demonstrating VIGIL's **codebase
> scan** and its **automated fix**. Not deployed, no real data.

[`permit_lookup.py`](permit_lookup.py) is a ~35-line Python microservice with **8 planted, canonical source
vulnerabilities** — each on its own line, so a fix is a clean 1–3 line diff shown directly in the file.

| # | Line | CWE | Bug | The fix |
|---|------|-----|-----|---------|
| 1 | `API_KEY = "sk-…"` | CWE-798 | Hardcoded secret | read from `os.environ["MERIDIA_API_KEY"]` |
| 2 | `lookup_permit` | CWE-89 | SQL injection | parameterized query: `cur.execute("… = ?", (permit_no,))` |
| 3 | `hash_password` | CWE-327 | Weak hash (md5) | `hashlib.sha256` (or bcrypt/argon2 for passwords) |
| 4 | `generate_report` | CWE-78 | OS command injection | `subprocess.run(["meridia-report", "--permit", permit_no], check=True)` (no shell) |
| 5 | `load_saved_search` | CWE-502 | Insecure deserialization | `json.loads` instead of `pickle.loads` |
| 6 | `read_attachment` | CWE-22 | Path traversal | resolve + contain the path under a fixed base dir |
| 7 | `evaluate_fee_rule` | CWE-95 | `eval()` injection | `ast.literal_eval` (no arbitrary code) |
| 8 | `new_reference` | CWE-330 | Insecure randomness | `secrets.token_hex` / `secrets.randbelow` |

**Demo flow:** VIGIL scans this file → reports the findings (CWE + file:line) → the fix feature proposes /
applies the diff for each → the patched file is shown before/after → a re-scan comes back clean.
