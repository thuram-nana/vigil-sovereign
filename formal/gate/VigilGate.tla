-------------------------- MODULE VigilGate --------------------------
(***************************************************************************)
(* Machine-checked model of the VIGIL CONJUNCTIVE GATE (gate-of-record).  *)
(*                                                                         *)
(* Faithful abstraction of the enforcing predicate in:                     *)
(*   packages/core/vigil_core/vigil_core/gate.py :: conjunctive_decide     *)
(*   integration/vigil_integration/conjunctive_gate.py :: build_offense_gate*)
(*   engine/crucible/framework/v2/authority/gate.py :: authorize_action    *)
(*   integration/vigil_integration/warden_gate.py :: decide_tool           *)
(*                                                                         *)
(* Every target-touching offense action auto-runs ("allow") ONLY IF, over  *)
(* one signed spine, ALL of these hold, first-failure-wins, fail-closed:   *)
(*   * CRUCIBLE authority in-envelope: kill-switch clear /\ in validity     *)
(*     window /\ target in scope /\ under action budget                     *)
(*     (authorize_action, authority/gate.py:70-118, steps 1,2,3,6).         *)
(*   * WARDEN tier decision is exactly "auto"  (conjunctive_decide step 4;  *)
(*     decide_tool, warden_gate.py:118-140 — only outcome=="auto" opens).   *)
(*   * If the action is destructive/high-blast, an owner-inclusive m-of-n   *)
(*     threshold-destruction authorization is present AND its `authorized`  *)
(*     field is strictly True (conjunctive_decide step 3, gate.py ~110-125).*)
(*   * ANY exception in ANY conjunct is a DENY (never caught-and-continued).*)
(*                                                                         *)
(* SCOPE / HONESTY: TLC proves the invariant over a BOUNDED, finite model.  *)
(* The model<->code link is a human-argued abstraction, NOT a code          *)
(* extraction proof. We do NOT claim "the code is formally verified"; we    *)
(* claim the soundness invariant holds in a machine-checked model that      *)
(* faithfully abstracts the enforcing code at the file:line cited above.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

VARIABLES
    state,             \* "idle" | "submitted" | "done"
    \* --- CRUCIBLE authority sub-conditions (authorize_action) ---
    killClear,         \* kill-switch NOT tripped (step 1, absolute stop)
    inWindow,          \* now within [not_before, not_after] (step 2)
    inScope,           \* target host matches scope (step 3)
    underBudget,       \* actions_taken < max_actions (step 6)
    \* --- WARDEN tool tier (decide_tool) ---
    tier,              \* "auto" | "queue" | "deny"
    \* --- I4 threshold-destruction conjunct ---
    destructive,       \* action is destructive/high-blast
    destructionWired,  \* a threshold-destruction gate was actually wired
    quorum,            \* destruction_authorize() returned  authorized IS True
    \* --- fail-closed error injection (one try/except per conjunct) ---
    cruError,          \* crucible_authorize() raised
    wardenError,       \* warden_decide() raised
    destructionError,  \* destruction_authorize() raised
    \* --- outputs ---
    executed,          \* did the action auto-run? (verdict allowed == TRUE)
    verdict            \* "none" | "allow" | "queue" | "deny"

vars == << state, killClear, inWindow, inScope, underBudget, tier,
           destructive, destructionWired, quorum,
           cruError, wardenError, destructionError, executed, verdict >>

Tiers    == {"auto", "queue", "deny"}
Verdicts == {"none", "allow", "queue", "deny"}

(* CRUCIBLE authority = conjunction of its (non-destructive) in-envelope gates. *)
Authority == killClear /\ inWindow /\ inScope /\ underBudget

(* An exception the fail-closed try/except turns into a DENY. destructionError  *)
(* is only on the destructive path, mirroring conjunctive_decide's structure.   *)
AnyError == cruError \/ wardenError \/ (destructive /\ destructionError)

(*-------------------------------------------------------------------------*)
(* Decide: the FAITHFUL decision procedure. It mirrors conjunctive_decide   *)
(* step-for-step: first-failure-wins, fail-closed, only "auto" opens.       *)
(*-------------------------------------------------------------------------*)
Decide ==
    IF   cruError                             THEN "deny"   \* 1. crucible raised -> DENY
    ELSE IF ~Authority                        THEN "deny"   \* 1. cru.allowed == False -> DENY
    ELSE IF wardenError                       THEN "deny"   \* 2. warden raised -> DENY
    ELSE IF destructive /\ ~destructionWired  THEN "deny"   \* 3. no destruction gate wired -> DENY
    ELSE IF destructive /\ destructionError   THEN "deny"   \* 3. destruction gate raised -> DENY
    ELSE IF destructive /\ ~quorum            THEN "deny"   \* 3. authorized is NOT True -> DENY  <== load-bearing
    ELSE IF tier = "auto"                     THEN "allow"  \* 4. ONLY "auto" opens the gate
    ELSE IF tier = "queue"                    THEN "queue"  \* 5. in envelope, owner approval
    ELSE                                           "deny"   \* 6. deny / unrecognised -> DENY

(*-------------------------------------------------------------------------*)
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

(* Submit: pick a fully nondeterministic action request. *)
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

(* Execute: run the gate on the frozen request. The action auto-runs iff the *)
(* conjunctive verdict is "allow".                                            *)
Execute ==
    /\ state = "submitted"
    /\ state'    = "done"
    /\ verdict'  = Decide
    /\ executed' = (Decide = "allow")
    /\ UNCHANGED << killClear, inWindow, inScope, underBudget, tier,
                    destructive, destructionWired, quorum,
                    cruError, wardenError, destructionError >>

(* Reset: allow another request (keeps the model live; no deadlock). *)
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

(*-------------------------------------------------------------------------*)
(* THE SOUNDNESS INVARIANT.                                                 *)
(* An action was auto-executed ONLY in a state where the full conjunction   *)
(* held: CRUCIBLE authority in-envelope, WARDEN tier == "auto",             *)
(* (destructive => threshold quorum present), and NO conjunct errored.      *)
(*-------------------------------------------------------------------------*)
GateSound ==
    executed =>
        /\ Authority
        /\ tier = "auto"
        /\ (destructive => quorum)
        /\ (destructive => destructionWired)
        /\ ~AnyError
=============================================================================
