--------------------------- MODULE Boundary_broken ---------------------------
(***************************************************************************)
(* FATAL-2 two-environment boundary (VIGIL).                               *)
(*                                                                         *)
(* Faithful abstraction of the STRUCTURAL guard that keeps the offense     *)
(* engine and the sovereign core from ever co-existing in one process,     *)
(* and keeps the owner signing key out of any offense process.             *)
(*                                                                         *)
(* Model <-> code correspondence (human-argued abstraction, NOT a          *)
(* code-extraction proof):                                                 *)
(*                                                                         *)
(*  - LoadSovereign guard  ~offenseLoaded[p]                               *)
(*      == apps/sigil/sigil/reuse/__init__.py assert_no_offense (~L53-60): *)
(*         a SIGIL (env-sovereign) process refuses to proceed if ANY       *)
(*         offense module (framework or strix) is already loaded -- it     *)
(*         raises RuntimeError("SIGIL sovereignty violation ...").         *)
(*         This is THE co-load refusal.                                    *)
(*                                                                         *)
(*  - LoadOffense guard  ~sovereignLoaded[p]                               *)
(*      == integration/tests/test_two_env_boundary.py: the offense engine  *)
(*         is only reachable in env-offense; no sovereign member declares   *)
(*         a dependency on crucible/framework/strix, and a real sovereign  *)
(*         venv genuinely lacks the offense members, so offense cannot      *)
(*         load where the sovereign core lives (dependency-graph boundary).*)
(*                                                                         *)
(*  - AttachOwnerKey guard  sovereignLoaded[p] /\ ~offenseLoaded[p]        *)
(*      == integration/vigil_integration/offense_worker.py:57-61: the      *)
(*         offense worker __init__ raises ValueError if handed an          *)
(*         owner_key ("must be KEYLESS"); has_owner_key is structurally     *)
(*         False. The owner-signed spine head (anchor 2) is added only on   *)
(*         the sovereign side (inert_finding.py:16,89).                     *)
(*                                                                         *)
(*  - MintFinding / IngestFinding: the seam carries DATA, not capability.  *)
(*      == integration/vigil_integration/inert_finding.py _parse_envelope: *)
(*         the inbound blob is parsed with json.loads ONLY (never pickle    *)
(*         or eval), size-bounded and strictly shaped, then re-verified     *)
(*         m-of-n with vigil_core.verify_threshold (verify_signature,       *)
(*         L77-84). IngestFinding therefore does NOT set offenseLoaded on   *)
(*         the receiver: a finding crosses as inert signed JSON, granting   *)
(*         no code and no capability.                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANT Procs          \* a tiny finite set of processes, e.g. {p1, p2, p3}

VARIABLES
    offenseLoaded,      \* [Procs -> BOOLEAN] : framework/strix loaded in p
    sovereignLoaded,    \* [Procs -> BOOLEAN] : a sigil/vigil_core module loaded in p
    hasOwnerKey,        \* [Procs -> BOOLEAN] : p holds the owner Ed25519 signing key
    seam,               \* "empty" | "inTransit" : an inert finding datum on the wire
    ingested            \* [Procs -> BOOLEAN] : p re-verified + accepted a finding datum

vars == <<offenseLoaded, sovereignLoaded, hasOwnerKey, seam, ingested>>

TypeOK ==
    /\ offenseLoaded   \in [Procs -> BOOLEAN]
    /\ sovereignLoaded \in [Procs -> BOOLEAN]
    /\ hasOwnerKey     \in [Procs -> BOOLEAN]
    /\ seam \in {"empty", "inTransit"}
    /\ ingested \in [Procs -> BOOLEAN]

Init ==
    /\ offenseLoaded   = [p \in Procs |-> FALSE]
    /\ sovereignLoaded = [p \in Procs |-> FALSE]
    /\ hasOwnerKey     = [p \in Procs |-> FALSE]
    /\ seam = "empty"
    /\ ingested = [p \in Procs |-> FALSE]

\* Load the offense engine (framework/strix) into process p.
\* Refused if p already runs the sovereign core (dep-graph boundary) OR
\* p holds the owner key (keyless offense worker).
LoadOffense(p) ==
    /\ ~offenseLoaded[p]
    /\ ~sovereignLoaded[p]                          \* dep-graph boundary: no co-load
    /\ ~hasOwnerKey[p]                              \* keyless offense worker
    /\ offenseLoaded' = [offenseLoaded EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<sovereignLoaded, hasOwnerKey, seam, ingested>>

\* MUTANT: assert_no_offense() has been DELETED. The sovereign core now loads
\* even when the offense engine is already in-process. The co-load refusal at
\* reuse/__init__.py:56-60 is gone -- this is the single load-bearing guard removed.
LoadSovereign(p) ==
    /\ ~sovereignLoaded[p]
    \* /\ ~offenseLoaded[p]   <== REMOVED: the co-load refusal (assert_no_offense) is gone
    /\ sovereignLoaded' = [sovereignLoaded EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, hasOwnerKey, seam, ingested>>

\* Place the owner signing key into process p. Only ever into a sovereign,
\* offense-free process (anchor-2 signer); an offense worker refuses it.
AttachOwnerKey(p) ==
    /\ ~hasOwnerKey[p]
    /\ sovereignLoaded[p]
    /\ ~offenseLoaded[p]                            \* offense worker is KEYLESS by construction
    /\ hasOwnerKey' = [hasOwnerKey EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, seam, ingested>>

\* The offense side (having run the oracle) emits a CONFIRMED finding as an
\* inert signed JSON datum onto the seam. Only an offense process mints.
MintFinding(p) ==
    /\ offenseLoaded[p]
    /\ seam = "empty"
    /\ seam' = "inTransit"
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, hasOwnerKey, ingested>>

\* The sovereign side receives the datum and re-verifies it m-of-n.
\* Crucially, offenseLoaded[p] is NOT changed: json.loads of inert DATA
\* grants no code and no capability -- data crosses the seam, capability
\* does not.
IngestFinding(p) ==
    /\ sovereignLoaded[p]
    /\ seam = "inTransit"
    /\ ingested' = [ingested EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, hasOwnerKey, seam>>

Next ==
    \E p \in Procs :
        \/ LoadOffense(p)
        \/ LoadSovereign(p)
        \/ AttachOwnerKey(p)
        \/ MintFinding(p)
        \/ IngestFinding(p)

Spec == Init /\ [][Next]_vars

\* ---- The FATAL-2 boundary invariant ----
BoundaryHolds ==
    \A p \in Procs :
        /\ ~(offenseLoaded[p] /\ sovereignLoaded[p])       \* never co-load
        /\ (offenseLoaded[p] => ~hasOwnerKey[p])           \* offense never holds owner key

\* The seam is inert: a process only ever holds an ingested finding if it is
\* the sovereign side; the datum never turned it into an offense process.
\* (Given BoundaryHolds, sovereignLoaded[p] => ~offenseLoaded[p], so an
\* ingesting process is provably not offense-capable.)
InertSeam ==
    \A p \in Procs : ingested[p] => sovereignLoaded[p]

=============================================================================
