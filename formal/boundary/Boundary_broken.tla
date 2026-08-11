--------------------------- MODULE Boundary_broken ---------------------------
(***************************************************************************)
(* MUTANT of Boundary.tla: the assert_no_offense() co-load refusal is      *)
(* DELETED from LoadSovereign. TLC MUST report BoundaryHolds VIOLATED.      *)
(* Everything else (incl. the shared vigil_core `coreLoaded` model, A15) is *)
(* identical to the faithful spec, so the only load-bearing change is the   *)
(* removed guard.                                                           *)
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

LoadOffense(p) ==
    /\ ~offenseLoaded[p]
    /\ ~sovereignLoaded[p]                          \* dep-graph boundary: no co-load with SIGIL
    /\ ~hasOwnerKey[p]                              \* keyless offense worker
    /\ offenseLoaded' = [offenseLoaded EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<sovereignLoaded, coreLoaded, hasOwnerKey, seam, ingested>>

\* MUTANT: assert_no_offense() has been DELETED. The SIGIL sovereign core now loads
\* even when the offense engine is already in-process. The co-load refusal at
\* reuse/__init__.py:56-60 is gone -- this is the single load-bearing guard removed.
LoadSovereign(p) ==
    /\ ~sovereignLoaded[p]
    \* /\ ~offenseLoaded[p]   <== REMOVED: the co-load refusal (assert_no_offense) is gone
    /\ sovereignLoaded' = [sovereignLoaded EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, coreLoaded, hasOwnerKey, seam, ingested>>

\* The SHARED vigil_core library -- no co-load guard (identical to the faithful spec).
LoadCore(p) ==
    /\ ~coreLoaded[p]
    /\ coreLoaded' = [coreLoaded EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, hasOwnerKey, seam, ingested>>

AttachOwnerKey(p) ==
    /\ ~hasOwnerKey[p]
    /\ sovereignLoaded[p]
    /\ ~offenseLoaded[p]                            \* offense worker is KEYLESS by construction
    /\ hasOwnerKey' = [hasOwnerKey EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, coreLoaded, seam, ingested>>

MintFinding(p) ==
    /\ offenseLoaded[p]
    /\ coreLoaded[p]
    /\ seam = "empty"
    /\ seam' = "inTransit"
    /\ UNCHANGED <<offenseLoaded, sovereignLoaded, coreLoaded, hasOwnerKey, ingested>>

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

BoundaryHolds ==
    \A p \in Procs :
        /\ ~(offenseLoaded[p] /\ sovereignLoaded[p])       \* never co-load offense + SIGIL
        /\ (offenseLoaded[p] => ~hasOwnerKey[p])           \* offense never holds owner key

InertSeam ==
    \A p \in Procs : ingested[p] => sovereignLoaded[p]

=============================================================================
