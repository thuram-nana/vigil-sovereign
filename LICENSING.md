# CRUCIBLE — Licensing

**Copyright © 2026 Junior Thuram Nana (the “Licensor”). All rights reserved.**

CRUCIBLE is **dual-licensed**. You may use it under **either**:

1. the **GNU Affero General Public License, version 3** (AGPL-3.0) — the open-source
   license in [`LICENSE`](./LICENSE); **or**
2. a **Commercial License** purchased from the Licensor.

You choose. If you have not signed a commercial agreement with the Licensor, your use is
governed by the AGPL-3.0.

> This document explains the model in plain language. It is **not legal advice**, and it is
> **not itself a license**. The binding open-source terms are the full text in [`LICENSE`](./LICENSE);
> commercial terms are the signed agreement you receive from the Licensor. Where this summary and
> those texts differ, those texts control.

---

## Option 1 — AGPL-3.0 (free and open source)

Use, run, study, modify, and redistribute CRUCIBLE for free, forever, under the AGPL-3.0.

The AGPL is a strong **copyleft** license. Its defining obligation (Section 13, *“Remote Network
Interaction”*) is what makes it the right choice for server / backend / infrastructure software:

- **You may use it for anything.** Personal, academic, commercial, internal — all fine under the AGPL.
- **If you modify it and let others interact with it over a network** (e.g. you run a modified
  CRUCIBLE, or a service built on it, that users reach over a network), **you must offer those users
  the complete corresponding source code of your modified version, under the AGPL-3.0.**
- **If you distribute it** (modified or not), the recipients get the same AGPL rights and the source.
- Derivative works and larger works that incorporate CRUCIBLE are themselves subject to the AGPL.

In short: **under the AGPL you may keep nothing proprietary that is built on CRUCIBLE and exposed
over a network — the source must travel with the service.**

Read the real terms in [`LICENSE`](./LICENSE) before relying on any summary.

---

## Option 2 — Commercial License

Buy a commercial license when you want to use CRUCIBLE **without the AGPL’s obligations**. Typical
reasons:

- **Keep your modifications private** — you extend CRUCIBLE but do not want to publish your source.
- **Embed it in a proprietary product or service** you distribute or host, without your product
  becoming subject to the AGPL.
- **Offer it (or a service built on it) over a network** without the Section-13 obligation to release
  your modified source to your users.
- **Sublicense, OEM, or redistribute** it inside a closed-source offering.
- You simply want a **warranty, indemnity, support, or SLA** the open-source license does not provide.

A commercial license grants you a private, non-copyleft right to use CRUCIBLE under negotiated terms.
It removes the AGPL copyleft obligations for your licensed use; the exact scope, support, and terms are
set out in your signed agreement.

**This dual-licensing model is standard for infrastructure/backend software** (e.g. MongoDB, Grafana,
Sentry, GitLab, and many others use AGPL-or-similar + commercial): the community gets a genuinely open,
copyleft product, and organizations that cannot meet the copyleft obligations pay for a commercial
license instead. The revenue funds continued development.

### How to obtain a commercial license

Contact the Licensor:

- **Web:** https://thuramnana.com
- **Email:** thuram@thuramnana.com
- **Subject:** `CRUCIBLE commercial license`
- Please include: your company, the product/use case, deployment model (internal / SaaS / distributed),
  and expected scale.

*(Maintainer: confirm the copyright holder line reflects your legal name/entity, and that
`thuram@thuramnana.com` is a monitored mailbox, before relying on this for commercial sales.)*

---

## Which license applies to you?

| Your situation | License |
|---|---|
| Personal use, research, evaluation, internal tools you don’t modify-and-expose | **AGPL-3.0** (free) |
| You modify CRUCIBLE and are happy to publish your source under AGPL-3.0 | **AGPL-3.0** (free) |
| You modify it and want to keep the changes private | **Commercial** |
| You embed it in a proprietary product or a hosted service and don’t want AGPL to reach that product | **Commercial** |
| You want warranty / indemnity / support / SLA | **Commercial** |

If in doubt, or if your lawyers want certainty, get a commercial license — or ask us.

---

## Contributions

To keep dual-licensing possible, the Licensor must hold sufficient rights in **all** of the code it
licenses commercially. Therefore:

- By submitting a contribution (a pull request, patch, or other change), **you license your
  contribution to the Licensor under both the AGPL-3.0 and terms that permit the Licensor to also
  distribute your contribution under the Commercial License**, and you represent that you have the
  right to do so.
- Equivalently: contributions are made under the project’s **inbound = AGPL-3.0**, plus a grant that
  lets the Licensor relicense your contribution commercially (a lightweight Contributor License
  Agreement / Developer Certificate of Origin grant).
- If you cannot grant those rights (e.g. employer-owned code), do not submit the contribution without
  the necessary permission.

A formal `CLA.md` / DCO sign-off may be introduced later; until then, opening a PR constitutes the
grant above.

---

## Trademarks

“CRUCIBLE” and any associated logos are marks of the Licensor. The AGPL and any commercial license
grant rights in the **software**, not in the Licensor’s **name or marks**. You may state that your
product “uses CRUCIBLE,” but you may not imply endorsement or use the marks as your own.

---

## SPDX

Source files are licensed under:

```
SPDX-License-Identifier: AGPL-3.0-or-later
```

with the commercial exception available under a separate signed agreement as described above.

---

## Third-party components

CRUCIBLE depends on third-party open-source packages (see `framework/v2/pyproject.toml`), each under
its own license. Those licenses are unaffected by CRUCIBLE’s dual license and continue to govern their
respective components.
