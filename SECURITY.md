# Security Policy

VIGIL is offensive-security tooling intended for eventual donation to governments and
national CERTs. The bar for handling a vulnerability *in VIGIL itself* is therefore
higher than for a personal or commercial tool, and this document is what a reporter or a
sovereign reviewer reads before disclosing one.

**Scope of this policy.** This policy is about vulnerabilities in **VIGIL itself** — the
first-party code in this repository and the maintainer's own infrastructure. It is **not**
about a flaw VIGIL *found* in a target you pointed it at (that is a finding for the target's
owner), nor is it authorization to test anyone else's systems. VIGIL must only ever be run
against systems you own or are explicitly authorized to test — see
[`engine/crucible/DISCLAIMER.md`](engine/crucible/DISCLAIMER.md).

The deeper, component-level report path for the offense engine (CRUCIBLE) is kept in
[`engine/crucible/SECURITY.md`](engine/crucible/SECURITY.md); this root policy is the
single front door and it takes precedence for the repository as a whole.

---

## Security contact

Report a suspected vulnerability privately, through one of these channels — **never in a
public issue, pull request, or discussion**:

- **Preferred — GitHub private vulnerability report.** On the repository's **Security** tab,
  choose **"Report a vulnerability"**. This opens a private advisory visible only to you and
  the maintainer. (If the button is not present, GitHub private vulnerability reporting has
  not yet been enabled for this repository — use email below, and it will be enabled.)
- **Email.** Send to **thuram@thuramnana.com** with a subject line beginning
  `VIGIL SECURITY:`. This is the maintainer's monitored mailbox (also used for licensing at
  [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md)). No PGP key is published yet; if you need
  an encrypted channel, say so in a first (non-sensitive) message and one will be arranged.

There is no paid bug-bounty programme. Good-faith reporters who follow this policy are
credited in the advisory and the release notes for the fix, unless they ask to remain
anonymous.

---

## Supported versions

VIGIL is pre-1.0 and ships as **one product version**, declared once in the repo-root
[`VERSION`](VERSION) file and asserted consistent across every first-party package
(see [`docs/decisions/W4-1-one-product-version.md`](docs/decisions/W4-1-one-product-version.md)).
Until a 1.x line is cut, security fixes land on `main` and in the latest tagged release only;
older checkouts are not back-patched.

| Version | Supported |
|---|---|
| `main` (current development head) | ✅ Yes — fixes land here first |
| Latest tagged release (currently `0.1.0`) | ✅ Yes |
| Any earlier commit or pre-release | ❌ No — rebase onto `main` / the latest release |

The single vendored third-party package, [`vendor/strix/`](vendor/strix/) (Apache-2.0),
keeps its **upstream** version and its own upstream security process; a vulnerability there
should be reported upstream first (see *Out of scope* below).

---

## Reporting a vulnerability — coordinated disclosure

1. **Report privately** through a channel above.
2. **Include, if you can:** the affected component and commit/version, a description of the
   flaw and its impact, and the minimal steps or proof-of-concept needed to reproduce it.
   A vulnerability class this project cares about especially: any path that bypasses a
   fail-closed gate (the WARDEN tier gate, the sovereignty tier, the scope/charter gate, the
   egress allowlist), forges or mutates a signed spine record, or crosses the two-environment
   boundary.
3. **Acknowledgement.** The maintainer aims to acknowledge a report within **3 business days**
   and to give an initial assessment within **10 business days**. These are targets for a
   single-maintainer project, not a contractual SLA.
4. **Coordinated-disclosure window.** The default window is **90 days** from the initial
   report to public disclosure, extendable by mutual agreement if a fix needs longer to land
   in deployed sovereign installations. The maintainer will keep you updated on progress and
   will coordinate the disclosure date and any credit with you.
5. **Disclosure.** A fix lands on `main` (and the patched release) and the private advisory is
   published at, or shortly after, the agreed disclosure date. Please do not disclose publicly
   before then.

### Out of scope

- A flaw in an **upstream dependency** (including vendored `strix`): report it upstream first,
  then file here once a patch is available so VIGIL can pull it.
- A bug VIGIL **found in a target**: that is a finding for the target's owner, not a
  vulnerability in VIGIL.
- **LLM reasoning quality** (an AI mis-judgement): VIGIL is designed so the AI is never
  trusted for a verdict — only a deterministic oracle mints a fact — so a reasoning slip is
  a known property, not a security vulnerability, unless it defeats a gate or an oracle.

---

## Safe harbour

The maintainer supports good-faith security research on VIGIL and will not initiate or
support legal action against you for security research that is conducted in accordance with
this policy. Specifically, if you make a good-faith effort to comply with this policy during
your research, the maintainer will:

- consider your research **authorized** with respect to any applicable anti-hacking laws
  (e.g. the U.S. Computer Fraud and Abuse Act) and anti-circumvention laws (e.g. the DMCA),
  and **will not bring or support a claim** against you for that research;
- work with you to understand and resolve the issue promptly, and will not ask a court, a
  law-enforcement agency, or a third party to pursue you for it;
- recognise your contribution publicly if you wish.

To stay within this safe harbour, your research must:

- concern **only VIGIL's own first-party code and the maintainer's own systems** — this safe
  harbour does **not** authorize you to attack third-party services, other people's systems,
  or the vendored third-party components under their own licenses/processes;
- avoid **privacy violations, data destruction, and interruption or degradation** of any
  service beyond the minimum needed to demonstrate the flaw;
- use only **your own accounts and test data**, and not access, modify, or retain data
  belonging to anyone else;
- give the maintainer a **reasonable time to fix** the issue (the coordinated-disclosure
  window above) before any public disclosure; and
- comply with all applicable laws.

If in doubt whether a specific action is authorized, ask first via the security contact above.
This safe harbour is a commitment from the maintainer of this project only; it cannot and does
not bind any third party.
