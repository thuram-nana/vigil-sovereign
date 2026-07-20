# kernel/ — URK, the Universal Reasoning Kernel

Wraps the v1 cognitive prose (`framework/cognitive/*.md`) as typed,
callable functions. Every binding loads the relevant section of the
cognitive doc, prompts an LLM, and parses the response into a Pydantic
schema.

## Entry points

```python
from framework.v2.kernel import (
    hypothesize,    # → HypothesisSet  ← hypothesis-driven.md
    critique,       # → CritiqueResult ← self-critique.md
    pivot,          # → PivotProposal  ← pivot-protocols.md
    decide,         # → SeverityDecision ← decision-frameworks.md
    opsec,          # → OpsecGuidance  ← opsec-discipline.md
    threat_model,   # → ThreatModel    ← threat-modeling.md
)

result, trace = hypothesize(
    observation="GET /api/v2/orders/123 returned 200 with another user's data",
    surface="/api/v2/orders/{id}",
)
for h in result.hypotheses:
    print(h.id, h.bug_class, "—", h.if_action)
```

## Backends

URK ships eight backend names spanning four sovereignty classes.

| Backend | Class | Activates when | Notes |
|---|---|---|---|
| `AnthropicBackend` (`anthropic`) | cloud_only | `ANTHROPIC_API_KEY` set + `anthropic` SDK installed | Default model `claude-sonnet-4-6` (override `CRUCIBLE_ANTHROPIC_MODEL`). |
| `AnthropicBackend` ZDR (`anthropic-zdr`) | trusted_cloud | + `CRUCIBLE_ANTHROPIC_ZDR=1` | Operator attests the API key is associated with a Zero-Data-Retention contract. |
| `BedrockBackend` (`bedrock`) | sovereign_cloud | `boto3` installed + AWS creds + `CRUCIBLE_BEDROCK_REGION` in allowlist | Claude on AWS Bedrock with regional restriction. Default region allowlist: us-gov-east-1 / us-gov-west-1 / eu-west-1 / eu-west-3 / eu-central-1 / ap-northeast-1 / us-east-1 / us-west-2. |
| `VertexBackend` (`vertex`) | sovereign_cloud | `google-auth` installed + `CRUCIBLE_VERTEX_PROJECT` + `CRUCIBLE_VERTEX_REGION` in allowlist | Claude on GCP Vertex AI with regional restriction. Default region allowlist: us-central1 / us-east5 / europe-west4 / europe-west9 / asia-northeast1. |
| `MistralBackend` (`mistral`) | sovereign_cloud | `MISTRAL_API_KEY` set | Mistral La Plateforme; httpx-direct (no SDK dep). EU-jurisdictional. |
| `ClaudeCodeBackend` (`claude-code`) | cloud_only | `claude` CLI installed + OAuth credentials (`~/.claude/.credentials.json`) | Routes via `claude -p` subprocess. |
| `OllamaBackend` (`ollama`) | local | local Ollama daemon answering at `http://localhost:11434` with the configured model pulled | Default `qwen2.5-coder:32b` (override `CRUCIBLE_OLLAMA_MODEL`). |
| `DryRunBackend` (`dryrun`) | local | always | Writes prompt to `framework/v2/.dryrun/`, returns deterministic per-schema fixture. No network. |

Selection order is *tier-aware*. The active sovereignty tier
(default PERMISSIVE; set via `CRUCIBLE_SOVEREIGNTY_TIER`) determines
which backends are reachable:

| Tier | Auto-selection preference |
|---|---|
| AIR_GAPPED | ollama → vllm → llama-cpp → tgi → dryrun |
| SOVEREIGN_CLOUD | bedrock → vertex → mistral → ollama → ... → dryrun |
| TRUSTED_CLOUD | anthropic-zdr → bedrock → vertex → mistral → ollama → ... → dryrun |
| PERMISSIVE | anthropic → claude-code → anthropic-zdr → bedrock → ... → dryrun |

Override with `CRUCIBLE_LLM_BACKEND=<name>`. Cloud-class backends
(`anthropic`, `claude-code`) attempted under sovereign tiers raise
`SovereigntyViolation` at construction. See
[`framework/v2/kernel/sovereignty.py`](sovereignty.py) for the policy
gate.

Inspect at any time:

```bash
python3 -m framework.v2 status
python3 -m framework.v2 kernel backend
```

## CLI

```bash
python3 -m framework.v2 kernel hypothesize --observation "..." --surface "..."
python3 -m framework.v2 kernel critique --claim "..." --evidence "..."
python3 -m framework.v2 kernel pivot --thread "..." --posture EMULATE
python3 -m framework.v2 kernel decide --summary "..."
python3 -m framework.v2 kernel opsec --action "..." --posture EMULATE
python3 -m framework.v2 kernel threat-model --target your-target --context "..."
```

Each prints `{"parsed": ..., "trace": ...}` — the parsed Pydantic
result plus a `CallTrace` (which backend ran, which cognitive
sections were quoted, tokens, latency).

## What URK does *not* do

- It does not paraphrase the cognitive layer. It quotes the relevant
  sections verbatim into the system prompt. v1 prose is the source of
  truth; URK is a citation layer.
- It does not enforce ethics. That is `common/ethics.py`. URK calls
  are pure reasoning operations; the gates apply at the action layer.
- It does not learn between calls. That is MLS (`memory/`). URK
  produces structured outputs that MLS records.

## Doctrine compliance

A few schema fields encode v1 doctrine:

- `HypothesisSet.doctrine_compliant()` returns True iff
  `len(hypotheses) >= 5` (hypothesis-driven.md § 2 forcing function).
- `CritiqueResult.deception_check` is required — every critique must
  name where the agent might be deceiving itself
  (self-critique.md § 1.5).
- `OpsecGuidance.allowed=False` is mandatory for the seven absolutes
  in opsec-discipline.md § 7.

The bindings ask for these in their task directives. The schemas
require them as fields. Belt and braces.
