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
(***************************************************************************)
EXTENDS Naturals

CONSTANT MaxEC                 \* bound on entry_count so TLC's state space is finite
ASSUME MaxEC \in Nat /\ MaxEC >= 1

VARIABLES
    floorEC,                   \* durable floor entry_count  (accepted high-water, primary field)
    floorLS,                   \* durable floor last_seq      (accepted high-water, secondary field)
    floorEC_prev,              \* history: floorEC immediately BEFORE the last transition
    floorLS_prev               \* history: floorLS immediately BEFORE the last transition

vars == << floorEC, floorLS, floorEC_prev, floorLS_prev >>

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

Init ==
    /\ floorEC = 0
    /\ floorLS = 0
    /\ floorEC_prev = 0
    /\ floorLS_prev = 0

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

(* Below-floor head REFUSED: HighWaterDowngrade raised (186), nothing written, *)
(* floor unchanged.  Modelled as a step that leaves the floor where it was.    *)
Refuse(ec) ==
    /\ ~AcceptGuard(ec)
    /\ UNCHANGED << floorEC, floorLS >>
    /\ floorEC_prev' = floorEC
    /\ floorLS_prev' = floorLS

Next == \E ec \in Candidates : Accept(ec) \/ Refuse(ec)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ floorEC \in 0 .. MaxEC
    /\ floorLS \in 0 .. MaxEC
    /\ floorEC_prev \in 0 .. MaxEC
    /\ floorLS_prev \in 0 .. MaxEC

(***************************************************************************)
(* MonotoneFloor: after every transition the accepted high-water is >= what *)
(* it was before that transition, on BOTH fields.  Because the floor is     *)
(* only ever written to an accepted head's values, this is equivalent to    *)
(* "a below-floor head is never accepted".                                  *)
(***************************************************************************)
MonotoneFloor ==
    /\ floorEC >= floorEC_prev
    /\ floorLS >= floorLS_prev

=============================================================================
