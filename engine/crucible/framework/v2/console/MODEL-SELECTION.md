# Model choice, reasoning depth, and honest token accounting in Chat

## What already exists (and is not being used)

The engine has a full provider layer at `kernel/llm.py` — a `Prompt`, an `LLMBackend` interface, and
`complete_with_failover`. Ten backends are already written:

| Backend | Trust class | Notes |
|---|---|---|
| `ollama`, `vllm`, `llama-cpp`, `tgi`, `self-hosted` | **local** | run on this machine; **no network egress at all** |
| `bedrock`, `vertex`, `mistral` | sovereign_cloud | cloud, jurisdictionally bounded |
| `anthropic-zdr` | trusted_cloud | cloud with a data-handling agreement |
| `anthropic`, `claude-code`, `azure_openai` | cloud_only | no special data-handling agreement |

**The console uses none of them.** `actions.terminal_propose` imports the Anthropic SDK directly and
hard-codes `model="claude-opus-5"`. So the work is mostly to route the chat through the layer that is
already there, not to build a provider abstraction.

## The model picker is a sovereignty control, not a preference

`kernel/sovereignty.py` already classifies every backend and gates it by the operator's tier:

- **AIR_GAPPED** permits `local` only
- **SOVEREIGN_CLOUD** adds jurisdictionally-bounded cloud
- **TRUSTED_CLOUD** adds cloud under a data-handling agreement
- **PERMISSIVE** adds everything (this machine is currently PERMISSIVE)

So the picker must show each model's **trust class** and, when a model is unavailable, **say why** —
"your sovereignty tier is AIR_GAPPED and this is a cloud model" — rather than hiding it or failing at
send time. An unknown backend classifies as `cloud_only`, which fails closed under every sovereign
tier; that behaviour must be preserved exactly.

### The pairing that matters

Chat is gaining file and codebase upload. **Choosing a local model means an uploaded client codebase
never leaves the machine.** That is the honest answer to the egress problem the attachment audit
raised, and for reviewing sensitive third-party code it is the configuration to recommend. The picker
should make that consequence visible at the moment of choosing — "local · nothing leaves this
machine" against "cloud · your files are sent to a third party".

## Token accounting — what is honest, and what is not

**We cannot show "tokens left in your account."** No provider API exposes remaining quota, and
inventing a number in a system whose entire premise is verifiable honesty would be indefensible.

Four things *are* true and useful, and those are what to show:

1. **Used, actually measured.** Providers return input/output token counts on every response. The
   provider layer does not currently carry them — `Prompt` has `max_tokens` and the result has no
   usage field — so this needs adding to the backend interface and accumulating per chat.
2. **Context headroom.** The model's context window minus the assembled prompt. This is computable
   and is the number that actually predicts the next failure, so it is the more useful of the two.
3. **An operator-set ceiling.** A per-chat budget the operator chooses, tracked against measured use.
   Honest because the operator set it, and it is the thing they actually wanted: a limit they can see
   approaching.
4. **Not metered.** For a local model, there is no cost and no quota — say exactly that rather than
   showing a meaningless zero.

## Reasoning depth

An "effort" control exists but sets a **global** setting; it should be per-chat and sent with the
request. It also means different things per provider: adaptive thinking on current Claude models,
`max_tokens` and prompt shaping elsewhere. The control should describe the effect ("thinks longer,
costs more, slower") rather than exposing a provider-specific knob.

## Connecting a local model

`ollama` and `self-hosted` backends exist. What is missing is the operator path: point at a local
endpoint, list the models it serves, test the connection, and save the choice — with a clear failure
message when nothing is listening, rather than a silent fallback to a cloud model. **A failure to
reach the local model must never silently fall back to cloud**: that would turn a sovereignty choice
into an accidental egress.

## What is genuinely new

- A direct **OpenAI** backend. `azure_openai` covers Azure-hosted GPT models; the plain OpenAI API is
  not implemented. It classifies `cloud_only` and is gated like any other cloud backend.
- **Usage capture** on the backend interface, and its accumulation per chat.
- The **operator-facing model picker, depth control and budget display**, none of which exist.
