"""Schema + synthetic seed data for MERIDIAN. Everything here is FABRICATED — no real people or records.

All rows are tagged (national IDs `MRD-…`, permit numbers `PL-…`, the `LAB` marker on notes) so an operator
can grep them out of any capture. Passwords are deliberately weak (the planted weak-authn surface).
"""

from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE citizens (
  id INTEGER PRIMARY KEY,
  name TEXT, email TEXT, national_id TEXT, phone TEXT
);
CREATE TABLE applications (
  id INTEGER PRIMARY KEY,
  ref TEXT, citizen_id INTEGER, permit_type TEXT, status TEXT,
  notes TEXT, fee_cents INTEGER, created TEXT
);
CREATE TABLE permits (
  id INTEGER PRIMARY KEY,
  permit_no TEXT, holder_name TEXT, permit_type TEXT, status TEXT, issued_date TEXT
);
CREATE TABLE accounts (
  id INTEGER PRIMARY KEY,
  username TEXT, password TEXT, role TEXT
);
CREATE TABLE sessions (
  token TEXT PRIMARY KEY, kind TEXT, subject_id INTEGER, username TEXT, role TEXT
);
"""

# Synthetic citizens (fictional; national_id + phone are the "PII" an IDOR/BOLA finding would reach).
_CITIZENS = [
    (1, "Ada Turing", "ada.turing@example.test", "MRD-100001", "+1-555-0101"),
    (2, "Grace Lovelace", "grace.love@example.test", "MRD-100002", "+1-555-0102"),
    (3, "Alan Hopper", "alan.hopper@example.test", "MRD-100003", "+1-555-0103"),
    (4, "Katherine Noether", "kath.noether@example.test", "MRD-100004", "+1-555-0104"),
    (5, "Edsger Ritchie", "ed.ritchie@example.test", "MRD-100005", "+1-555-0105"),
]

# Applications (each belongs to a citizen; `notes` is a free-text field → the stored-XSS sink).
_APPLICATIONS = [
    (1, "APP-24-0001", 1, "Business Licence", "under_review", "Opening a bakery downtown. [LAB]", 12000, "2026-08-01"),
    (2, "APP-24-0002", 2, "Building Permit", "approved", "Rear extension, 20 sqm. [LAB]", 34000, "2026-08-03"),
    (3, "APP-24-0003", 3, "Vehicle Licence", "submitted", "Commercial van registration. [LAB]", 8000, "2026-08-06"),
    (4, "APP-24-0004", 4, "Professional Licence", "under_review", "Chartered surveyor renewal. [LAB]", 15000, "2026-08-09"),
    (5, "APP-24-0005", 5, "Business Licence", "rejected", "Missing fire certificate. [LAB]", 12000, "2026-08-11"),
]

# The PUBLIC register of issued permits — the `holder_name` column is the SQLi search target.
_PERMITS = [
    (1, "PL-2026-0001", "Ada Turing", "Business Licence", "active", "2026-05-01"),
    (2, "PL-2026-0002", "Grace Lovelace", "Building Permit", "active", "2026-05-04"),
    (3, "PL-2026-0003", "Alan Hopper", "Vehicle Licence", "active", "2026-05-09"),
    (4, "PL-2026-0004", "Katherine Noether", "Professional Licence", "suspended", "2026-05-12"),
    (5, "PL-2026-0005", "Edsger Ritchie", "Business Licence", "expired", "2026-05-15"),
    (6, "PL-2026-0006", "Meridia Freight Co", "Vehicle Licence", "active", "2026-06-01"),
    (7, "PL-2026-0007", "Northgate Builders", "Building Permit", "active", "2026-06-04"),
    (8, "PL-2026-0008", "Harbour Bakery", "Business Licence", "active", "2026-06-09"),
]

# Staff accounts across the five roles. Passwords are deliberately weak (the weak-authn surface).
_ACCOUNTS = [
    (1, "admin", "Password1!", "admin"),
    (2, "registrar", "registrar", "registrar"),
    (3, "inspector", "inspector", "inspector"),
    (4, "clerk", "clerk123", "clerk"),
    (5, "aturing", "letmein", "citizen"),
]


def seed_rows(con: sqlite3.Connection) -> None:
    con.executemany("INSERT INTO citizens VALUES (?,?,?,?,?)", _CITIZENS)
    con.executemany("INSERT INTO applications VALUES (?,?,?,?,?,?,?,?)", _APPLICATIONS)
    con.executemany("INSERT INTO permits VALUES (?,?,?,?,?,?)", _PERMITS)
    con.executemany("INSERT INTO accounts VALUES (?,?,?,?)", _ACCOUNTS)
