# Role / authorization matrix — `<target-name>`

Maps every role × every endpoint × every action to the
**intended** authorization outcome. This drives playbook 07
authorization testing.

For each cell, mark:
- `OK` — role intended to access.
- `403` — role intended to be denied.
- `?` — unknown intent; ask operator or read source.

Then test each cell. A cell where intent is `403` but observed is
`OK` is a finding.

---

## Roles

(Adjust per target.)

| Role | Description | Test account |
|------|-------------|--------------|
| `anon` | Unauthenticated | — |
| `user` | Standard authenticated | alice@test.example |
| `user-other` | Different account, same role | bob@test.example |
| `premium` | Paid tier | premium@test.example |
| `support` | Support staff | support@test.example |
| `admin` | Admin | admin@test.example |
| `superadmin` | Owner / root | super@test.example |
| `child-panel` | (if reseller / multi-tenant) | child1@test.example |
| `child-panel-other` | Sibling tenant | child2@test.example |

---

## Endpoints × roles

(Sample — extend per target.)

| Endpoint | anon | user | user-other (read) | user-other (write) | premium | support | admin | superadmin |
|----------|:----:|:----:|:-----------------:|:------------------:|:-------:|:-------:|:-----:|:----------:|
| `GET /` | OK | OK | OK | n/a | OK | OK | OK | OK |
| `POST /login` | OK | OK | n/a | n/a | OK | OK | OK | OK |
| `GET /account` | 403 | OK | 403 | n/a | OK | 403 | OK | OK |
| `GET /api/v2/orders/{id}` | 403 | OK (own) | 403 (other) | n/a | OK (own) | OK (any) | OK (any) | OK (any) |
| `POST /api/v2/orders` | 403 | OK | n/a | n/a | OK | OK (impersonate?) | OK | OK |
| `POST /api/v2/orders/{id}/refund` | 403 | OK (own) | 403 | 403 | OK (own) | OK | OK | OK |
| `GET /admin/users` | 403 | 403 | n/a | n/a | 403 | OK (read) | OK | OK |
| `POST /admin/users/{id}/impersonate` | 403 | 403 | n/a | n/a | 403 | OK (with audit) | 403 | OK |
| `POST /admin/settings` | 403 | 403 | n/a | n/a | 403 | 403 | OK | OK |
| `DELETE /admin/users/{id}` | 403 | 403 | n/a | n/a | 403 | 403 | 403 | OK |
| `POST /webhook/stripe` | OK (signed) | OK (signed) | n/a | n/a | OK | OK | OK | OK |
| `GET /api/v2/admin/diagnostics` | 403 | 403 | n/a | n/a | 403 | OK | OK | OK |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |

---

## Multi-tenant cells

For multi-tenant products (e.g., reseller panels with child-panels):

| Endpoint | child-panel-A on own resource | child-panel-A on child-B's resource | superadmin on any |
|----------|:------------------------------:|:------------------------------------:|:------------------:|
| `GET /api/v2/orders/{id}` | OK | 403 | OK |
| `POST /api/v2/orders` | OK | n/a | OK |
| ... | ... | ... | ... |

Cross-tenant cells are the highest-priority test surface for
multi-tenant products.

---

## Test status per cell

For each cell with an `OK` or `403` value, mark whether tested:
- `[ ]` — not tested.
- `[t]` — tested, intended outcome confirmed.
- `[!]` — tested, intended outcome violated → finding.

(Maintain in a parallel table or annotate cells.)

---

## Method-swap and bypass tests

For each row that is `403` for a role, the test isn't done after
verifying the standard request returns 403. Per playbook 07 §7.2,
also try:

- Method swap: GET / POST / PUT / DELETE / PATCH / OPTIONS / HEAD.
- Path tricks: `./`, `//`, trailing `/`, case, `%20`, `%00`.
- Header trust: `X-Original-URL`, `X-Forwarded-For: 127.0.0.1`,
  `X-Real-IP`, `X-Forwarded-Host`.
- Force-browse: directly request unlinked admin paths from source /
  JS bundles.

For each row × bypass-vector, document the test status.
