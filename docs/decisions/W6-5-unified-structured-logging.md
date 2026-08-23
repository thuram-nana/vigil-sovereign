# W6-5 — Unify logging: structured JSON, redaction, rotation, one log-level variable

Issue: [#456](https://github.com/thuram-nana/vigil-sovereign/issues/456) ·
Milestone: W6 — OBSERVABILITY & HEALTH.

## The claim (registered in the claims registry — [W0-3] #398, id `W6-5`)

<!-- CLAIM:W6-5 -->
> **Registered claim (W0-3 #398):** Every VIGIL plane emits structured JSON logs through one shared redaction processor that masks secret-keyed fields and credential shapes before any line is written.

The fuller statement, and why it is TRUE of the code:

> The offense engine, the sovereign SIGIL plane and the host gateway all configure their logging through
> ONE shared setup (`vigil_core.logging_setup`) built on ONE shared redaction helper
> (`vigil_core.redact`). A secret that reaches a log — a secret-keyed structured field
> (`authorization`, `cookie`, `api_key`, …) or a credential SHAPE in the free-text message (a `Bearer`
> token, an `Authorization` / `Cookie` header line, a `secret=value` assignment) — is masked before the
> line is written, in every plane. One `VIGIL_LOG_LEVEL` governs all three planes (the previous
> `SIGIL_LOG_LEVEL` is still honoured, with a one-time deprecation warning), and every log destination —
> including the previously-unbounded `.vigil-live/ui/logs/*.log` child-capture files — is size-bounded
> with rotation and retention.

## The defect this closed

Three inconsistent logging stacks: the offense engine had structlog JSON + redaction + rotation; the
sovereign plane logged **plain text to stderr with no redaction mechanism** (only a docstring
convention); the gateway used a bare `logging.basicConfig`. The `.vigil-live/ui/logs/*.log` files had no
rotation and no size bound. Only `SIGIL_LOG_LEVEL` existed, governing one of the three planes.

## What ships

- **`vigil_core.redact`** — the ONE redaction helper. The logic previously lived only in the offense
  engine (`framework/v2/common/redact.py`); that module is now a thin re-export of this shared source, so
  offense behaviour is byte-identical while the masker is maintained once. `vigil_core` imports no
  `framework.*` / `strix.*` / `sigil.*`, so it is a member of BOTH isolated environments and reusing it
  crosses no FATAL-2 boundary. It adds `redact_log_message` for credential shapes in a free-text message.
- **`vigil_core.logging_setup`** — the ONE stdlib-only logging setup: a `RedactingJsonFormatter` (JSON
  lines; the message and every structured extra pass through the shared redactor), a single
  `VIGIL_LOG_LEVEL` resolver (with the deprecated `SIGIL_LOG_LEVEL` fallback), a secure rotating file
  handler, and a `RotatingLineWriter` for subprocess-output capture. Stdlib-only because the gateway
  declares zero third-party runtime dependencies and structlog is not in the sovereign environment.
- **Sovereign** (`apps/sigil/sigil/obs.py`) and **gateway** (`gateway/vigil_gateway/cli.py`) now install
  the shared handler; the **offense** engine keeps its structlog pipeline but resolves its level from
  `VIGIL_LOG_LEVEL` and redacts through the same shared helper.
- **`.vigil-live/ui/logs/*.log`** — the child backends' merged stdout/stderr is piped and pumped through
  a `RotatingLineWriter` (0600 file under a 0700 dir, `VIGIL_LOG_MAX_BYTES` / `VIGIL_LOG_BACKUP_COUNT`),
  so a chatty or long-running backend can no longer fill the disk.

## How it is proved

`proved_by` = `packages/core/vigil_core/tests/test_logging_unified.py`, which runs in the **required**
`vigil_core — shared integrity substrate` CI job. It asserts well-formed JSON, redaction with a POSITIVE
control (a bearer token / Authorization header / cookie are masked) and a NEGATIVE control (a non-secret
field survives — the redactor is not a blanket no-op), the single-variable precedence and the deprecation
warning, and that rotation triggers and is size-bounded. Each plane additionally carries its own
per-plane negative control: `apps/sigil/tests/test_logging_redaction.py` (sovereign),
`gateway/tests/test_logging.py` (gateway),
`engine/crucible/framework/v2/common/tests/test_logging_plane.py` (offense), and
`integration/tests/test_ui_log_rotation.py` (the UI child-log rotation). A tree without this change has
no `vigil_core.logging_setup` module, so the proving test fails at import — the "fails without the fix"
property is observed, not assumed.

## Honest scope (do not overclaim)

Redaction is by structured-log KEY name and by credential SHAPE in a message — deliberately conservative,
so it never scans a response body / captured evidence for "token-like" substrings (that would destroy the
proof a finding rests on; captured evidence bytes are protected instead by owner-only 0600 permissions,
per [W16-8] #514). A masked header VALUE in a free-text message is masked to end-of-line (cookies use `;`
internally), so trailing non-secret text after a credential header on the same line is also masked — the
safe side for a log line. `VIGIL_LOG_LEVEL` is read from each process's environment by the shared setup;
set it in the service environment (systemd / shell / compose) so the offense and gateway children inherit
it. The UI setting persists it to `sigil.env`, which the sovereign process loads.
