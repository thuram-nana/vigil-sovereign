# skills/ — learned vulnerability playbooks (advisory only)

The Knowledge Engine (slice **K3**), when the operator **accepts** a proposal to learn a vulnerability,
deep-learns it and writes durable playbooks here:

- `find/<id>.md` — how to **find** the vulnerability.
- `detect/<id>.md` — how to **detect** it. *A detector may only map onto an **existing** deterministic oracle
  kind, or become a **gated proposal** for a real oracle — never a soft/LLM oracle.*
- `prevent/<id>.md` — how to **prevent / remediate** it.

## Doctrine

A skill is **advisory**. It grants **no authority** and **confirms nothing** — `SkillLoader` parses no tier from
it, and its graph counterpart is stamped `intel`/`ungrounded`. Only a fired deterministic oracle over real
evidence mints a FACT. `SkillLoader` loads at most `MAX_SKILLS` (id-sorted) per query, so retrieval ranks to
the top-relevant; the folder may hold many more.
