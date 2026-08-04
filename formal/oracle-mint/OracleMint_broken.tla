------------------------- MODULE OracleMint_broken -------------------------
(***************************************************************************)
(* MUTANT of OracleMint.  IDENTICAL to the faithful spec EXCEPT the ONE   *)
(* load-bearing guard is removed: CriticEndorse is weakened so a critic's  *)
(* endorsement mints a FACT directly, WITHOUT any oracle having fired      *)
(* (oracleFired is left untouched).                                        *)
(*                                                                        *)
(* This is exactly the hallucination the real pipeline exists to kill:    *)
(* a non-oracle actor (a critic's say-so) promoting a claim to a signed   *)
(* FACT with no deterministic oracle over real bytes — i.e. bypassing     *)
(* confirm_finding()/verifier.confirm().confirmed. TLC must report        *)
(* OracleOnlyMints VIOLATED, proving the guard in the faithful spec is    *)
(* load-bearing and the invariant is non-vacuous (it CAN fail).           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Claims

VARIABLES
    status,
    oracleFired,
    reproduces

vars == <<status, oracleFired, reproduces>>

Status == {"LEAD", "FACT"}

TypeOK ==
    /\ status      \in [Claims -> Status]
    /\ oracleFired \in [Claims -> BOOLEAN]
    /\ reproduces  \in [Claims -> BOOLEAN]

Init ==
    /\ status      = [c \in Claims |-> "LEAD"]
    /\ oracleFired = [c \in Claims |-> FALSE]
    /\ reproduces  \in [Claims -> BOOLEAN]

OracleFire(c) ==
    /\ reproduces[c] = TRUE
    /\ oracleFired' = [oracleFired EXCEPT ![c] = TRUE]
    /\ status'      = [status      EXCEPT ![c] = "FACT"]
    /\ UNCHANGED reproduces

LlmPropose(c) ==
    /\ status' = [status EXCEPT ![c] = "LEAD"]
    /\ UNCHANGED <<oracleFired, reproduces>>

(***************************************************************************)
(* MUTANT: the guard is gone. A critic endorsement mints a FACT with no   *)
(* oracle fire.  Compare the faithful spec, where this set status:="LEAD".*)
(***************************************************************************)
CriticEndorse(c) ==
    /\ status' = [status EXCEPT ![c] = "FACT"]     \* <-- injected defect
    /\ UNCHANGED <<oracleFired, reproduces>>

RlRerank(c) ==
    /\ status' = [status EXCEPT ![c] = "LEAD"]
    /\ UNCHANGED <<oracleFired, reproduces>>

FirewallReexec(c) ==
    /\ status[c] = "FACT"
    /\ status' = [status EXCEPT ![c] = "LEAD"]
    /\ UNCHANGED <<oracleFired, reproduces>>

Next ==
    \E c \in Claims :
        \/ OracleFire(c)
        \/ LlmPropose(c)
        \/ CriticEndorse(c)
        \/ RlRerank(c)
        \/ FirewallReexec(c)

Spec == Init /\ [][Next]_vars

OracleOnlyMints ==
    \A c \in Claims : status[c] = "FACT" => oracleFired[c] = TRUE

=============================================================================
