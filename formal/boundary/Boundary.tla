------------------------------ MODULE Boundary ------------------------------
(***************************************************************************)
(* FATAL-2 two-environment boundary (VIGIL).                               *)
(*                                                                         *)
(* Faithful abstraction of the STRUCTURAL guard that keeps the offense     *)
(* engine and the SIGIL sovereign core from ever co-existing in one        *)
(* process, and keeps the owner signing key out of any offense process.    *)
(*                                                                         *)
(* SHARED LIBRARY (A15): ``vigil_core`` is deliberately installed in BOTH  *)
(* environments (offense signs / the sovereign side re-verifies with       *)
(* ``vigil_core.verify_threshold``). It is therefore modelled here as a    *)
(* SHARED, boundary-ORTHOGONAL library (``coreLoaded``): ``LoadCore`` has   *)
(* NO co-load guard, so an offense process may hold ``vigil_core`` — and    *)
(* ``BoundaryHolds`` (below) still holds in every such state. The sovereign *)
(* module governed by the co-load refusal is SIGIL, NOT ``vigil_core``;     *)
(* the earlier model conflated the two and thus asserted a sovereign-only   *)
(* property the real (vigil_core-in-offense) system does not have.          *)
(*                                                                         *)
(* Model <-> code correspondence (human-argued abstraction, NOT a          *)
(* code-extraction proof):                                                 *)
(*                                                                         *)
(*  - LoadSovereign guard  ~offenseLoaded[p]                               *)
(*      == apps/sigil/sigil/reuse/__init__.py assert_no_offense (~L53-60): *)
(*         a SIGIL (env-sovereign) process refuses to proceed if ANY       *)
(*         offense module (framework or strix) is already loaded -- it     *)
(*         raises RuntimeError("SIGIL sovereignty violation ...").         *)
(*         This is THE co-load refusal. It guards SIGIL, not vigil_core.   *)
(*                                                                         *)
(*  - LoadOffense guard  ~sovereignLoaded[p]                               *)
(*      == integration/tests/test_two_env_boundary.py: the offense engine  *)
(*         is only reachable in env-offense; no sovereign member declares   *)
(*         a dependency on crucible/framework/strix, and a real sovereign  *)
(*         venv genuinely lacks the offense members, so offense cannot      *)
(*         load where the SIGIL core lives (dependency-graph boundary).    *)
(*                                                                         *)
(*  - LoadCore  (no guard)                                                 *)
(*      == vigil_core is a plain shared library on BOTH env manifests; it  *)
(*         carries no assert_no_offense and no offense members, so either   *)
(*         an offense OR a sovereign process may import it freely.          *)
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
(*         L77-84). Both sides use vigil_core (coreLoaded) for the crypto;  *)
(*         IngestFinding does NOT set offenseLoaded on the receiver: a      *)
(*         finding crosses as inert signed JSON, granting no code and no    *)
(*         capability.                                                      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANT Procs          \* a tiny finite set of processes, e.g. {p1, p2, p3}

VARIABLES
    offenseLoaded,      \* [Procs -> BOOLEAN] : framework/strix loaded in p
    sovereignLoaded,    \* [Procs -> BOOLEAN] : a SIGIL (sovereign core) module loaded in p -- NOT vigil_core
    coreLoaded,         \* [Procs -> BOOLEAN] : vigil_core (SHARED lib) loaded in p -- boundary-orthogonal
    hasOwnerKey,        \* [Procs -> BOOLEAN] : p holds the owner Ed25519 signing key
    seam,               \* "empty" | "inTransit" : an inert finding datum on the wire
    ingested            \* [Procs -> BOOLEAN] : p re-verified + accepted a finding datum

vars == <<offenseLoaded, sovereignLoaded, coreLoaded, hasOwnerKey, seam, ingested>>

TypeOK ==
    /\ offenseLoaded   \in [Procs -> BOOLEAN]
    /\ sovereignLoaded \in [Procs -> BOOLEAN]
    /\ coreLoaded      \in [Procs -> BOOLEAN]
    /\ hasOwnerKey     \in [Procs -> BOOLEAN]
    /\ seam \in {"empty", "inTransit"}
    /\ ingested \in [Procs -> BOOLEAN]

Init ==
    /\ offenseLoaded   = [p \in Procs |-> FALSE]
    /\ sovereignLoaded = [p \in Procs |-> FALSE]
    /\ coreLoaded      = [p \in Procs |-> FALSE]
    /\ hasOwnerKey     = [p \in Procs |-> FALSE]
    /\ seam = "empty"
    /\ ingested = [p \in Procs |-> FALSE]

\* Load the offense engine (framework/strix) into process p.
\* Refused if p already runs the SIGIL sovereign core (dep-graph boundary) OR
\* p holds the owner key (keyless offense worker). vigil_core (coreLoaded) is
\* NOT checked: a process may already hold the shared lib.
LoadOffense(p) ==
    /\ ~offenseLoaded[p]
    /\ ~sovereignLoaded[p]                          \* dep-graph boundary: no co-load with SIGIL
    /\ ~hasOwnerKey[p]                              \* keyless offense worker
    /\ offenseLoaded' = [offenseLoaded EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<sovereignLoaded, coreLoaded, hasOwnerKey, seam, ingested>>

\* Load a SIGIL sovereign module into process p.
\* assert_no_offense(): refused if ANY offense module is already loaded.
LoadSovereign(p) ==
    /\ ~sovereignLoaded[p]
    /\ ~offenseLoaded[p]                            \* <== assert_no_offense co-load refusal
    /\ sovereignLoaded' = [sovereignLoaded EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, coreLoaded, hasOwnerKey, seam, ingested>>

\* Load the SHARED vigil_core library into process p. NO co-load guard: vigil_core
\* is installed in both environments, so either an offense OR a sovereign process
\* may import it. This is the A15 correction -- vigil_core is orthogonal to the
\* boundary, and BoundaryHolds must (and does) hold even when coreLoaded /\ offenseLoaded.
LoadCore(p) ==
    /\ ~coreLoaded[p]
    /\ coreLoaded' = [coreLoaded EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, hasOwnerKey, seam, ingested>>

\* Place the owner signing key into process p. Only ever into a sovereign,
\* offense-free process (anchor-2 signer); an offense worker refuses it.
AttachOwnerKey(p) ==
    /\ ~hasOwnerKey[p]
    /\ sovereignLoaded[p]
    /\ ~offenseLoaded[p]                            \* offense worker is KEYLESS by construction
    /\ hasOwnerKey' = [hasOwnerKey EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, coreLoaded, seam, ingested>>

\* The offense side (having run the oracle) emits a CONFIRMED finding as an
\* inert signed JSON datum onto the seam. Only an offense process mints, and it
\* signs with the SHARED vigil_core crypto (coreLoaded) -- so an offense process
\* provably holds vigil_core, and the boundary still holds.
MintFinding(p) ==
    /\ offenseLoaded[p]
    /\ coreLoaded[p]
    /\ seam = "empty"
    /\ seam' = "inTransit"
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, coreLoaded, hasOwnerKey, ingested>>

\* The sovereign side receives the datum and re-verifies it m-of-n with vigil_core.
\* Crucially, offenseLoaded[p] is NOT changed: json.loads of inert DATA grants no
\* code and no capability -- data crosses the seam, capability does not.
IngestFinding(p) ==
    /\ sovereignLoaded[p]
    /\ coreLoaded[p]
    /\ seam = "inTransit"
    /\ ingested' = [ingested EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, coreLoaded, hasOwnerKey, seam>>

Next ==
    \E p \in Procs :
        \/ LoadOffense(p)
        \/ LoadSovereign(p)
        \/ LoadCore(p)
        \/ AttachOwnerKey(p)
        \/ MintFinding(p)
        \/ IngestFinding(p)

Spec == Init /\ [][Next]_vars

\* ---- The FATAL-2 boundary invariant ----
\* Note: it is stated over offenseLoaded vs sovereignLoaded (SIGIL) ONLY -- it does
\* NOT mention coreLoaded, so vigil_core in an offense process never breaks it.
BoundaryHolds ==
    \A p \in Procs :
        /\ ~(offenseLoaded[p] /\ sovereignLoaded[p])       \* never co-load offense + SIGIL
        /\ (offenseLoaded[p] => ~hasOwnerKey[p])           \* offense never holds owner key

\* The seam is inert: a process only ever holds an ingested finding if it is
\* the sovereign side; the datum never turned it into an offense process.
\* (Given BoundaryHolds, sovereignLoaded[p] => ~offenseLoaded[p], so an
\* ingesting process is provably not offense-capable.)
InertSeam ==
    \A p \in Procs : ingested[p] => sovereignLoaded[p]

=============================================================================
