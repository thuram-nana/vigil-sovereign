"""
DryRunBackend — the default fallback.

When no live LLM is reachable, URK still has to produce structured
output that downstream subsystems can use. DryRun:

  - writes the fully-rendered prompt to framework/v2/.dryrun/<ts>-<schema>.txt
  - delegates to a per-schema fixture provider (see kernel.fixtures)
  - returns a Pydantic instance synthesised from the structured input

The output is *deterministic*. The fixture providers are not
"realistic LLM output" — they are plausible-baseline output derived
from the actual structured input plus the cognitive doc's own
examples. Reasoning quality is bounded; this is documented in
V2-LIMITATIONS.md.

The dryrun directory is gitignored. Operators can grep prompts there
post-engagement to audit what URK would have asked an LLM.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from ...common import logging as v2log
from ...common import paths
from ..llm import LLMBackend, LLMResult, Prompt, make_call_trace


_log = v2log.get_logger(__name__)


class DryRunBackend(LLMBackend):
    name = "dryrun"

    @property
    def is_dryrun(self) -> bool:
        return True

    def is_available(self) -> tuple[bool, str]:
        return True, "always available; no network"

    def complete(self, prompt: Prompt) -> LLMResult:
        from . import fixtures  # local import to avoid circular at module load

        t0 = time.perf_counter()

        # 1. write the prompt to disk for audit
        d = paths.dryrun_dir()
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = d / f"{ts}-{prompt.schema_name}.txt"
        with out.open("w", encoding="utf-8") as f:
            f.write(f"# DryRun prompt — schema={prompt.schema_name}\n")
            f.write(f"# cognitive_doc={prompt.cognitive_doc}\n")
            f.write(f"# sections={prompt.cognitive_sections}\n")
            f.write("# ----- system -----\n")
            f.write(prompt.system + "\n\n")
            f.write("# ----- user -----\n")
            f.write(prompt.user + "\n")

        # 2. ask the per-schema fixture provider for an instance
        provider = fixtures.get_provider(prompt.schema_name)
        instance = provider(prompt.schema, prompt.structured_input)

        latency = (time.perf_counter() - t0) * 1000.0
        trace = make_call_trace(
            backend=self.name,
            is_dryrun=True,
            cognitive_doc=prompt.cognitive_doc,
            cognitive_sections=prompt.cognitive_sections,
            tokens_in=0,
            tokens_out=0,
            latency_ms=latency,
        )
        _log.info(
            "kernel.dryrun.complete",
            schema=prompt.schema_name,
            prompt_path=str(out),
        )
        return LLMResult(parsed=instance, trace=trace, raw_response="")
