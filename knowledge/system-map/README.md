# system-map/ — the machine-readable map SIGIL reads

This is how **SIGIL knows the system**. Two files (populated by slice **S1**):

- `screens.yaml` — the **human source of truth**: one entry per UI screen with its `id`, `label`, `group`,
  `owner`, `plane`, a `description`, and the voice `synonyms` SIGIL matches against.
- `system-map.json` — **generated** from `screens.yaml` by `tools/system-map/generate.py`, and **committed**
  so the sovereign nav router and the browser both read it same-origin.

**Invariant:** CI runs a drift-check asserting `NAV ids == route() ids == manifest ids` against
`packages/vigil-ui/app.js`, so SIGIL's map can never silently diverge from the real UI. The manifest is
**immutable committed data** — a shared file both planes read, never a live handle (FATAL-2 clean).
