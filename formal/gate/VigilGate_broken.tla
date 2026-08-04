----------------------- MODULE VigilGate_broken -----------------------
(***************************************************************************)
(* MUTANT of VigilGate. IDENTICAL except the ONE load-bearing guard that   *)
(* enforces the destructive-action threshold conjunct is REMOVED:          *)
(*                                                                         *)
(*   conjunctive_decide (vigil_core/gate.py ~line 120):                    *)
(*       if getattr(dz, "authorized", False) is not True:                  *)
(*           return GateVerdict(False, "deny", ...)   # <-- DELETED here    *)
(*                                                                         *)
(* i.e. the  `destructive /\ ~quorum -> "deny"`  clause is dropped from     *)
(* Decide. Everything else is byte-identical to VigilGate.tla. This proves  *)
(* the guard is load-bearing: with it gone, a destructive action with       *)
(* CRUCIBLE authority + WARDEN "auto" + NO owner m-of-n quorum auto-runs,    *)
(* violating GateSound -> TLC emits a counterexample trace (non-vacuous).   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

VARIABLES
    state,
    killClear, inWindow, inScope, underBudget,
    tier,
    destructive, destructionWired, quorum,
    cruError, wardenError, destructionError,
    executed, verdict

vars == << state, killClear, inWindow, inScope, underBudget, tier,
           destructive, destructionWired, quorum,
           cruError, wardenError, destructionError, executed, verdict >>

Tiers    == {"auto", "queue", "deny"}
Verdicts == {"none", "allow", "queue", "deny"}

Authority == killClear /\ inWindow /\ inScope /\ underBudget
AnyError  == cruError \/ wardenError \/ (destructive /\ destructionError)

(*-------------------------------------------------------------------------*)
(* MUTANT Decide: the  `destructive /\ ~quorum -> "deny"`  guard is REMOVED. *)
(* All other conjuncts (errors, window/scope/budget, wiring) are preserved  *)
(* so the mutation targets EXACTLY the threshold-quorum check.              *)
(*-------------------------------------------------------------------------*)
Decide ==
    IF   cruError                             THEN "deny"
    ELSE IF ~Authority                        THEN "deny"
    ELSE IF wardenError                       THEN "deny"
    ELSE IF destructive /\ ~destructionWired  THEN "deny"
    ELSE IF destructive /\ destructionError   THEN "deny"
    \* MUTANT: the  `ELSE IF destructive /\ ~quorum THEN "deny"`  line is gone.
    ELSE IF tier = "auto"                     THEN "allow"
    ELSE IF tier = "queue"                    THEN "queue"
    ELSE                                           "deny"

TypeOK ==
    /\ state \in {"idle", "submitted", "done"}
    /\ killClear \in BOOLEAN /\ inWindow \in BOOLEAN
    /\ inScope \in BOOLEAN /\ underBudget \in BOOLEAN
    /\ tier \in Tiers
    /\ destructive \in BOOLEAN /\ destructionWired \in BOOLEAN /\ quorum \in BOOLEAN
    /\ cruError \in BOOLEAN /\ wardenError \in BOOLEAN /\ destructionError \in BOOLEAN
    /\ executed \in BOOLEAN
    /\ verdict \in Verdicts

Init ==
    /\ state = "idle"
    /\ killClear = FALSE /\ inWindow = FALSE /\ inScope = FALSE /\ underBudget = FALSE
    /\ tier = "deny"
    /\ destructive = FALSE /\ destructionWired = FALSE /\ quorum = FALSE
    /\ cruError = FALSE /\ wardenError = FALSE /\ destructionError = FALSE
    /\ executed = FALSE
    /\ verdict = "none"

Submit ==
    /\ state = "idle"
    /\ \E kc, iw, isc, ub, d, dw, q, ce, we, de \in BOOLEAN :
         \E t \in Tiers :
           /\ killClear'        = kc
           /\ inWindow'         = iw
           /\ inScope'          = isc
           /\ underBudget'      = ub
           /\ destructive'      = d
           /\ destructionWired' = dw
           /\ quorum'           = q
           /\ cruError'         = ce
           /\ wardenError'      = we
           /\ destructionError' = de
           /\ tier'             = t
    /\ state'    = "submitted"
    /\ executed' = FALSE
    /\ verdict'  = "none"

Execute ==
    /\ state = "submitted"
    /\ state'    = "done"
    /\ verdict'  = Decide
    /\ executed' = (Decide = "allow")
    /\ UNCHANGED << killClear, inWindow, inScope, underBudget, tier,
                    destructive, destructionWired, quorum,
                    cruError, wardenError, destructionError >>

Reset ==
    /\ state = "done"
    /\ state'    = "idle"
    /\ executed' = FALSE
    /\ verdict'  = "none"
    /\ UNCHANGED << killClear, inWindow, inScope, underBudget, tier,
                    destructive, destructionWired, quorum,
                    cruError, wardenError, destructionError >>

Next == Submit \/ Execute \/ Reset

Spec == Init /\ [][Next]_vars

(* SAME invariant as the faithful spec — unchanged. *)
GateSound ==
    executed =>
        /\ Authority
        /\ tier = "auto"
        /\ (destructive => quorum)
        /\ (destructive => destructionWired)
        /\ ~AnyError
=============================================================================
