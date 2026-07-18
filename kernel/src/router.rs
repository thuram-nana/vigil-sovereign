//! T0 cognition router (SIGIL §7). T0 classifies every input into one of four routes. This v1
//! is deterministic + rule-based (no model call, <1 ms) — a small local Ollama model is a later
//! refinement. The router policy is DATA and is versioned like code (SIGIL §7).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Answer directly from memory (a recall question). Fast path.
    AnswerLocal,
    /// Escalate to a fast frontier model (Haiku-class): short drafts/triage.
    EscalateT1,
    /// Escalate to a deep frontier model (Sonnet/Opus-class): planning, hard reasoning, code.
    EscalateT2,
    /// Dispatch to an agent (build/research/comms) — real mesh is Phase 3.
    DispatchAgent,
}

impl Route {
    pub fn as_str(&self) -> &'static str {
        match self {
            Route::AnswerLocal => "answer_local",
            Route::EscalateT1 => "escalate_t1",
            Route::EscalateT2 => "escalate_t2",
            Route::DispatchAgent => "dispatch_agent",
        }
    }
}

const MEMORY_CUES: &[&str] = &[
    "what did i", "when did i", "recall", "remember when", "what do i know", "search memory",
    "what did we", "who is", "show me", "find in memory", "history of", "what have i decided",
    "did i decide", "what's open", "what is open", "what did you do",
];
const AGENT_CUES: &[&str] = &[
    "build ", "implement ", "fix the", "open a pr", "refactor", "run the tests", "deploy",
    "research ", "compare ", "due diligence", "draft an email", "send an email", "email ",
];
const PLAN_CUES: &[&str] = &[
    "plan ", "design ", "architect", "how should i", "strategy", "reason about", "think through",
    "write code", "debug ", "why does",
];

/// Route an intent. Order: memory-recall → agent-task → deep-plan → (short ⇒ T1, else T2).
pub fn route(intent: &str) -> Route {
    let t = intent.to_ascii_lowercase();
    if MEMORY_CUES.iter().any(|c| t.contains(c)) {
        return Route::AnswerLocal;
    }
    if AGENT_CUES.iter().any(|c| t.contains(c)) {
        return Route::DispatchAgent;
    }
    if PLAN_CUES.iter().any(|c| t.contains(c)) {
        return Route::EscalateT2;
    }
    if t.split_whitespace().count() <= 12 {
        Route::EscalateT1
    } else {
        Route::EscalateT2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_match_intent_class() {
        assert_eq!(route("what did i decide about the graph database"), Route::AnswerLocal);
        assert_eq!(route("recall my reasons for choosing Qdrant"), Route::AnswerLocal);
        assert_eq!(route("build a rate limiter for the API"), Route::DispatchAgent);
        assert_eq!(route("research vector databases for on-device use"), Route::DispatchAgent);
        assert_eq!(route("design the WARDEN tier promotion policy"), Route::EscalateT2);
        assert_eq!(route("summarize this in a line"), Route::EscalateT1); // short, no cue
        assert_eq!(
            route("give me a careful multi-paragraph comparison of the tradeoffs between these three approaches in detail"),
            Route::EscalateT2 // long, no cue
        );
    }
}
