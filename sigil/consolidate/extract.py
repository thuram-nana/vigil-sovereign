"""Candidate extraction (SIGIL §6.3.1, cognition cascade T1). An ExtractionProvider turns a
window of spine records into candidate facts. Three implementations:

  * AgentProvider   — headless `claude -p` on the Max plan (D5: agent-driven, zero API cost).
  * ReplayProvider  — replays a captured golden fixture (zero cost, exercises the parse path).
  * HeuristicProvider — offline keyword extraction (no LLM; a weak fallback + deterministic
                        double for tests).

None of these is trusted: whatever a provider proposes is only a CANDIDATE. The gate
(gate.admit) re-executes every citation before anything becomes a fact. The extraction prompt
still injects the prove-don't-guess doctrine so the agent is asked to cite verbatim and refuse
to invent — belt (honest prompt) and suspenders (re-execution gate)."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

from ..spine.models import SpineRecord
from .models import CandidateFact

# the prove-don't-guess doctrine, distilled for extraction (framework/cognitive/metacognition.md).
DOCTRINE = (
    "You extract DURABLE FACTS from a person's work log. A `decision` is a CHOICE the person "
    "COMMITTED TO ('we'll use X', 'decided to Y') — NOT a status update, test result, log line, "
    "or an instruction to someone else. A `commitment` is a PROMISE the person made, ideally with a "
    "due date. An `entity` is a durable named thing (project/person/tool/component). If a record is "
    "just narration, a result, or a task assignment, extract NOTHING from it. Rules, above all else:\n"
    "1. PROVE, DON'T GUESS. Only report a fact that the provided records EXPLICITLY support. "
    "Never infer, embellish, or invent a decision, commitment, or entity that is not in the text.\n"
    "2. CITE VERBATIM. For every fact, cite the exact record seq(s) and copy a `quote` that is a "
    "VERBATIM substring of a cited record. If you cannot quote it word-for-word, do not report it. "
    "The `statement` must be a COMPRESSION of your quote — use ONLY words that appear in the quote "
    "(you may drop and reorder words, but never add a word the quote does not contain).\n"
    "3. REFUSE HONESTLY. If a record supports no durable fact, return fewer facts — an empty list "
    "is a correct answer. Do not pad.\n"
    "4. DON'T FABRICATE CONFIDENCE. `confidence` is your rough estimate only; it never makes a "
    "weakly-supported claim strong.\n"
    "5. CONTRADICTIONS. If the records show the person REVERSING an earlier decision (choosing X "
    "then later choosing not-X or a different option for the SAME subject), emit a kind='contradiction' "
    "whose source_seqs cite BOTH the earlier and later records AND provide a `quotes` array with a "
    "VERBATIM quote from EACH of those two records. Only flag genuine OPPOSITION, never a restatement "
    "or refinement of the same choice.\n"
)

_SCHEMA_HINT = (
    "Return ONLY a JSON array (no prose) of objects: "
    '{"kind": "decision"|"commitment"|"entity"|"contradiction", "subject": "<what it is about>", '
    '"statement": "<advisory summary in the person\'s terms>", "quote": "<verbatim span from a cited record>", '
    '"quotes": ["<verbatim from record A>", "<verbatim from record B>"] (contradictions ONLY, one per conflicting record), '
    '"source_seqs": [<int seq>...], "owner": "<for commitments, who>"|null, '
    '"due_iso": "<ISO date if a due date is stated>"|null, "confidence": <0..1>}.'
)


# a fast, cheap model is ideal for this mechanical extraction task.
FAST_MODEL = "claude-haiku-4-5-20251001"


@runtime_checkable
class ExtractionProvider(Protocol):
    def extract(self, records: list[SpineRecord]) -> list[CandidateFact]: ...


def render_window(records: Iterable[SpineRecord], *, max_chars: int = 1200) -> str:
    lines = []
    for r in records:
        txt = (r.text() or "").replace("\n", " ").strip()
        if not txt:
            continue
        lines.append(f"[seq {r.seq}] ({r.kind} · {r.actor}) {txt[:max_chars]}")
    return "\n".join(lines)


def build_prompt(records: list[SpineRecord]) -> str:
    """The extraction prompt every LLM provider sends (doctrine + schema + rendered window)."""
    return f"{DOCTRINE}\n{_SCHEMA_HINT}\n\nRECORDS:\n{render_window(records)}\n"


def parse_candidates(raw: str, *, extractor: str) -> list[CandidateFact]:
    """Robustly pull the JSON array out of a model response (tolerates ```json fences / prose)."""
    if not raw:
        return []
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", raw, re.S)
    body = fenced.group(1) if fenced else None
    if body is None:
        start, end = raw.find("["), raw.rfind("]")
        body = raw[start:end + 1] if 0 <= start < end else None
    if body is None:
        return []
    try:
        items = json.loads(body)
    except json.JSONDecodeError:
        return []
    out = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict) or it.get("kind") not in ("decision", "commitment", "entity", "contradiction"):
            continue
        seqs = it.get("source_seqs") or []
        seqs = [int(s) for s in seqs if isinstance(s, (int, float, str)) and str(s).lstrip("-").isdigit()]
        raw_quotes = it.get("quotes") or []
        quotes = tuple(str(q) for q in raw_quotes if isinstance(q, str) and q.strip()) if isinstance(raw_quotes, list) else ()
        out.append(CandidateFact(
            kind=it["kind"], subject=str(it.get("subject", "")).strip(),
            statement=str(it.get("statement", "")).strip(), quote=str(it.get("quote", "")),
            source_seqs=seqs, model_confidence=float(it.get("confidence", 0.5) or 0.5),
            owner=(it.get("owner") or None), due_iso=(it.get("due_iso") or None),
            extractor=extractor, quotes=quotes))
    return out


class AgentProvider:
    """`--provider claude`: headless Claude Code on the MAX plan (D5, owner's preference).
    Spawns `claude -p --model <fast> <prompt>` per window — no metered API key needed. A fast
    model (Haiku) keeps each batch quick and cheap for this mechanical extraction."""

    def __init__(self, claude_bin: str = "/home/kali/.local/bin/claude",
                 model: str = FAST_MODEL, timeout: int = 180) -> None:
        self.claude_bin = claude_bin
        self.model = model
        self.timeout = timeout

    def extract(self, records: list[SpineRecord]) -> list[CandidateFact]:
        if not records:
            return []
        cmd = [self.claude_bin, "-p", build_prompt(records)]
        if self.model:
            cmd += ["--model", self.model]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.SubprocessError, OSError):
            return []
        return parse_candidates(proc.stdout, extractor="agent")


class ApiProvider:
    """`--provider api`: the metered Anthropic Messages API (Claude API key). Reads the key
    from SIGIL_ANTHROPIC_API_KEY / ANTHROPIC_API_KEY (or ~/.sigil/sigil.env via config). Raw
    HTTP — no SDK dependency. Use when you want the API rather than the Max subscription."""

    def __init__(self, model: str = FAST_MODEL, api_key: str | None = None,
                 timeout: int = 120, max_tokens: int = 2048) -> None:
        import os
        self.model = model
        self.api_key = api_key or os.environ.get("SIGIL_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self.timeout = timeout
        self.max_tokens = max_tokens

    def extract(self, records: list[SpineRecord]) -> list[CandidateFact]:
        if not records:
            return []
        if not self.api_key:
            raise RuntimeError("ApiProvider needs an API key — set ANTHROPIC_API_KEY (or SIGIL_ANTHROPIC_API_KEY)")
        import json as _json
        import urllib.request
        body = _json.dumps({
            "model": self.model, "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": build_prompt(records)}],
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body, method="POST",
            headers={"content-type": "application/json", "x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = _json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError):
            return []
        text = "".join(b.get("text", "") for b in payload.get("content", []) if isinstance(b, dict))
        return parse_candidates(text, extractor="api")


class LocalProvider:
    """`--provider local`: a local Ollama model (fully offline, zero cost, no data leaves the
    box). Requires Ollama running at OLLAMA_HOST (default 127.0.0.1:11434) with `model` pulled."""

    def __init__(self, model: str = "llama3.1", host: str | None = None, timeout: int = 180) -> None:
        import os
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434"
        self.timeout = timeout

    def extract(self, records: list[SpineRecord]) -> list[CandidateFact]:
        if not records:
            return []
        import json as _json
        import urllib.request
        body = _json.dumps({"model": self.model, "prompt": build_prompt(records), "stream": False}).encode("utf-8")
        req = urllib.request.Request(f"{self.host.rstrip('/')}/api/generate", data=body, method="POST",
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = _json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError):
            return []
        return parse_candidates(payload.get("response", ""), extractor="local")


class ReplayProvider:
    """Replays a captured fixture (a JSON array of candidate dicts). Zero cost; proves the
    parse/gate path end-to-end without a live call."""

    def __init__(self, fixture: str | Path) -> None:
        self.fixture = Path(fixture)

    def extract(self, records: list[SpineRecord]) -> list[CandidateFact]:
        return parse_candidates(self.fixture.read_text(encoding="utf-8"), extractor="replay")


_DECISION_CUES = ("decided to", "we'll go with", "going with", "chose to", "chosen:", "decision:")
_COMMIT_CUES = ("i'll ", "i will ", "we'll ", "commit to", "todo:", "next step", "by end of", "due ")


class HeuristicProvider:
    """Offline, no-LLM keyword extractor — a weak fallback and a deterministic test double.
    Emits a candidate per cue-bearing sentence, quoting that sentence verbatim (so the gate
    grounds it). Deliberately conservative; the AgentProvider is the real extractor."""

    def extract(self, records: list[SpineRecord]) -> list[CandidateFact]:
        out = []
        for r in records:
            for sent in re.split(r"(?<=[.!?])\s+", (r.text() or "")):
                low = sent.lower().strip()
                if not low:
                    continue
                if any(c in low for c in _DECISION_CUES):
                    out.append(CandidateFact("decision", low[:60], sent.strip(), sent.strip(),
                                             [r.seq], 0.5, extractor="heuristic"))
                elif any(c in low for c in _COMMIT_CUES):
                    out.append(CandidateFact("commitment", low[:60], sent.strip(), sent.strip(),
                                             [r.seq], 0.5, owner="owner", extractor="heuristic"))
        return out
