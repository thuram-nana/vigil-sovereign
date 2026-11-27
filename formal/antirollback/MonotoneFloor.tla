---------------------------- MODULE MonotoneFloor ----------------------------
(***************************************************************************)
(* Machine-checked model of VIGIL's durable anti-rollback high-water floor.*)
(*                                                                         *)
(* Faithful abstraction of the enforcing code (correspondence is human-    *)
(* argued, NOT extracted):                                                 *)
(*                                                                         *)
(*   packages/core/vigil_core/vigil_core/highwater.py                      *)
(*     check_highwater()  lines 87-100  -- the ACCEPT guard: a signed head *)
(*       is accepted only if head.entry_count >= floor.entry_count (94,    *)
(*       the PRIMARY monotone guard) AND head.last_seq >= floor.last_seq   *)
(*       (97, the secondary guard).                                        *)
(*     _advance_locked()  lines 181-189 -- on accept the durable floor is  *)
(*       overwritten with the head's values (187: new = _floor_dict(head)),*)
(*       and this only runs AFTER check_highwater passes, so the write is  *)
(*       UPWARD-ONLY.  A failing check raises HighWaterDowngrade (186) and *)
(*       writes NOTHING -- the floor is left unchanged.                    *)
(*     docstring lines 11-14 -- last_seq is 0-indexed, so it reads 0 for   *)
(*       BOTH an empty chain AND a 1-record chain; a 1->0 truncation slips *)
(*       past a last_seq-only check but is caught by entry_count.  This is *)
(*       modelled below via LS(ec) and is exactly what the mutant breaks.  *)
(*                                                                         *)
(*   packages/core/vigil_core/vigil_core/chain.py                          *)
(*     verify_head()      lines 93-94   -- the in-memory sibling guard:    *)
(*       head.last_seq < prev_highwater  =>  "rollback rejected".          *)
(*     sign_head()        lines 68-75   -- last_seq = entries[-1].seq;     *)
(*       entry_count = len(entries).  This determines LS(ec) below for a   *)
(*       window that starts at seq 0 (the v1 / base_seq=0 case we model).  *)
(*                                                                         *)
(* INVARIANT proved: MonotoneFloor -- the accepted high-water never        *)
(* decreases across any transition (equivalently, a below-floor head is    *)
(* never accepted).                                                        *)
(*                                                                         *)
(* --- AS-2c EXTENSION: the AEGIS enforcement EPOCH floor -----------------*)
(*                                                                         *)
(* The gateway v2 slice (AS-2c) adds a second monotone floor of the SAME   *)
(* anti-rollback shape, over the authority EPOCH rather than the spine     *)
(* entry_count.  Faithful abstraction (human-argued):                      *)
(*                                                                         *)
(*   packages/core/vigil_core/vigil_core/authority_v2.py                   *)
(*     evaluate_authority() line 648 -- "grant.epoch < epoch_floor =>      *)
(*       PASS_THROUGH ('stale-epoch')": a grant BELOW the floor is never   *)
(*       accepted for enforcement (it degrades to uninspected pass-through)*)
(*   engine/crucible/framework/v2/aegis/authority_v2_check.py              *)
(*     MonotoneEpochFloor.raise_to() -- "floor := max(floor, epoch)",      *)
(*       UPWARD-ONLY (a lower EpochStatement is a no-op); seeded from the   *)
(*       verified EpochStatement, so the floor is re-established keylessly  *)
(*       on boot/replacement/move and can never be rolled BACK below a     *)
(*       signed statement.                                                  *)
(*                                                                         *)
(* Two INVARIANTS proved for it below:                                      *)
(*   EnforcementFloorMonotone -- aegisFloor never decreases across any      *)
(*     transition (the floor "never regresses below a signed floor").       *)
(*   NoEnforceBelowFloor      -- no grant is ever ACCEPTED for enforcement  *)
(*     while its epoch sits below the floor (the stale-epoch guard is       *)
(*     load-bearing: drop it and a below-floor grant would enforce).        *)
(***************************************************************************)
EXTENDS Naturals

CONSTANT MaxEC                 \* bound on entry_count AND on the epoch, so TLC's state space is finite
ASSUME MaxEC \in Nat /\ MaxEC >= 1

VARIABLES
    floorEC,                   \* durable floor entry_count  (accepted high-water, primary field)
    floorLS,                   \* durable floor last_seq      (accepted high-water, secondary field)
    floorEC_prev,              \* history: floorEC immediately BEFORE the last transition
    floorLS_prev,              \* history: floorLS immediately BEFORE the last transition
    aegisFloor,                \* AS-2c: the AEGIS enforcement EPOCH floor (max over verified EpochStatements)
    aegisFloor_prev,           \* history: aegisFloor immediately BEFORE the last transition
    enforcedBelowFloor         \* AS-2c: set TRUE iff a grant was ever accepted-for-enforce below the floor

vars == << floorEC, floorLS, floorEC_prev, floorLS_prev,
           aegisFloor, aegisFloor_prev, enforcedBelowFloor >>

(***************************************************************************)
(* last_seq of a signed head as a function of its entry_count, for a       *)
(* chain window that starts at seq 0 (sign_head, chain.py:68-72):          *)
(*   empty chain      -> entry_count = 0, last_seq = 0                      *)
(*   1-record chain   -> entry_count = 1, last_seq = 0   (0-indexed!)       *)
(*   n-record chain   -> entry_count = n, last_seq = n-1                    *)
(* The 0 vs 1 degeneracy (both give last_seq = 0) is precisely why the      *)
(* entry_count guard, not last_seq, is the sound anti-rollback guard.       *)
(***************************************************************************)
LS(ec) == IF ec = 0 THEN 0 ELSE ec - 1

Candidates == 0 .. MaxEC       \* every incoming candidate head, by its entry_count
Epochs     == 0 .. MaxEC       \* every incoming epoch (an EpochStatement's, or a grant's)

Init ==
    /\ floorEC = 0
    /\ floorLS = 0
    /\ floorEC_prev = 0
    /\ floorLS_prev = 0
    /\ aegisFloor = 0
    /\ aegisFloor_prev = 0
    /\ enforcedBelowFloor = FALSE

(***************************************************************************)
(* Frames: a step on one floor leaves the OTHER floor's values unchanged,   *)
(* but still advances that floor's *_prev history to its current value, so   *)
(* the monotone invariant is checked (trivially, equal) across every step.   *)
(***************************************************************************)
AegisUnchanged ==
    /\ aegisFloor' = aegisFloor
    /\ aegisFloor_prev' = aegisFloor
    /\ enforcedBelowFloor' = enforcedBelowFloor

HWUnchanged ==
    /\ floorEC' = floorEC
    /\ floorLS' = floorLS
    /\ floorEC_prev' = floorEC
    /\ floorLS_prev' = floorLS

(***************************************************************************)
(* check_highwater (highwater.py:87-100): accept iff the head is >= the     *)
(* floor on BOTH monotone fields.  BOTH conjuncts are load-bearing; the     *)
(* first (entry_count) is the one the mutant deletes.                       *)
(***************************************************************************)
AcceptGuard(ec) ==
    /\ ec >= floorEC           \* highwater.py:94  entry_count guard (PRIMARY)
    /\ LS(ec) >= floorLS       \* highwater.py:97  last_seq guard (secondary)

(* _advance_locked (highwater.py:181-189): floor := head's values, upward-only *)
Accept(ec) ==
    /\ AcceptGuard(ec)
    /\ floorEC' = ec
    /\ floorLS' = LS(ec)
    /\ floorEC_prev' = floorEC
    /\ floorLS_prev' = floorLS
    /\ AegisUnchanged

(* Below-floor head REFUSED: HighWaterDowngrade raised (186), nothing written, *)
(* floor unchanged.  Modelled as a step that leaves the floor where it was.    *)
Refuse(ec) ==
    /\ ~AcceptGuard(ec)
    /\ UNCHANGED << floorEC, floorLS >>
    /\ floorEC_prev' = floorEC
    /\ floorLS_prev' = floorLS
    /\ AegisUnchanged

(***************************************************************************)
(* AS-2c AEGIS enforcement epoch floor transitions.                         *)
(*                                                                         *)
(* RaiseFloor(e): a verified EpochStatement sets floor := max(floor, e)     *)
(*   (authority_v2_check.MonotoneEpochFloor.raise_to) -- UPWARD-ONLY, so a   *)
(*   lower e is a no-op and the floor can never be rolled back.             *)
(* EnforceGrant(g): a grant is accepted for enforcement ONLY when its epoch *)
(*   g is at/above the floor (evaluate_authority's stale-epoch guard, 648). *)
(*   enforcedBelowFloor records whether that guard was ever violated -- in  *)
(*   the faithful model it never is, so the flag stays FALSE.               *)
(***************************************************************************)
RaiseFloor(e) ==
    /\ aegisFloor' = IF e > aegisFloor THEN e ELSE aegisFloor
    /\ aegisFloor_prev' = aegisFloor
    /\ enforcedBelowFloor' = enforcedBelowFloor
    /\ HWUnchanged

EnforceGrant(g) ==
    /\ g >= aegisFloor                         \* authority_v2.py:648 stale-epoch guard (load-bearing)
    /\ enforcedBelowFloor' = (g < aegisFloor)  \* FALSE under the guard; a mutant dropping it sets TRUE
    /\ aegisFloor' = aegisFloor
    /\ aegisFloor_prev' = aegisFloor
    /\ HWUnchanged

Next ==
    \/ \E ec \in Candidates : Accept(ec) \/ Refuse(ec)
    \/ \E e  \in Epochs     : RaiseFloor(e)
    \/ \E g  \in Epochs     : EnforceGrant(g)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ floorEC \in 0 .. MaxEC
    /\ floorLS \in 0 .. MaxEC
    /\ floorEC_prev \in 0 .. MaxEC
    /\ floorLS_prev \in 0 .. MaxEC
    /\ aegisFloor \in 0 .. MaxEC
    /\ aegisFloor_prev \in 0 .. MaxEC
    /\ enforcedBelowFloor \in BOOLEAN

(***************************************************************************)
(* MonotoneFloor: after every transition the accepted high-water is >= what *)
(* it was before that transition, on BOTH fields.  Because the floor is     *)
(* only ever written to an accepted head's values, this is equivalent to    *)
(* "a below-floor head is never accepted".                                  *)
(***************************************************************************)
MonotoneFloor ==
    /\ floorEC >= floorEC_prev
    /\ floorLS >= floorLS_prev

(***************************************************************************)
(* AS-2c: the AEGIS enforcement epoch floor never regresses, and no grant   *)
(* is ever accepted for enforcement below it.                               *)
(***************************************************************************)
EnforcementFloorMonotone ==
    aegisFloor >= aegisFloor_prev

NoEnforceBelowFloor ==
    enforcedBelowFloor = FALSE

=============================================================================
