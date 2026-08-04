------------------------- MODULE MonotoneFloor_broken -------------------------
(***************************************************************************)
(* MUTANT of MonotoneFloor.  IDENTICAL in every line EXCEPT the one guard   *)
(* that enforces the invariant: the entry_count conjunct of AcceptGuard     *)
(* (highwater.py:94, the PRIMARY anti-rollback guard) is DELETED.  Only the *)
(* last_seq guard (highwater.py:97) remains.                                *)
(*                                                                         *)
(* This reproduces the exact defect the code's docstring (highwater.py:11- *)
(* 14) warns about: last_seq is 0-indexed, so a 1-record chain (entry_count *)
(* = 1, last_seq = 0) can be rolled back to an empty chain (entry_count =   *)
(* 0, last_seq = 0) -- last_seq does NOT decrease (0 -> 0), so a last_seq-  *)
(* only check accepts the truncation and the durable floor DROPS from 1 to  *)
(* 0.  TLC must report MonotoneFloor VIOLATED with that 2-step trace,       *)
(* proving the deleted guard is load-bearing (the check is non-vacuous).    *)
(***************************************************************************)
EXTENDS Naturals

CONSTANT MaxEC
ASSUME MaxEC \in Nat /\ MaxEC >= 1

VARIABLES floorEC, floorLS, floorEC_prev, floorLS_prev
vars == << floorEC, floorLS, floorEC_prev, floorLS_prev >>

LS(ec) == IF ec = 0 THEN 0 ELSE ec - 1

Candidates == 0 .. MaxEC

Init ==
    /\ floorEC = 0
    /\ floorLS = 0
    /\ floorEC_prev = 0
    /\ floorLS_prev = 0

(***************************************************************************)
(* MUTANT: the `ec >= floorEC` conjunct (highwater.py:94) is REMOVED.       *)
(* Only the last_seq guard survives.                                        *)
(***************************************************************************)
AcceptGuard(ec) ==
    /\ LS(ec) >= floorLS       \* highwater.py:97 only -- entry_count guard deleted

Accept(ec) ==
    /\ AcceptGuard(ec)
    /\ floorEC' = ec
    /\ floorLS' = LS(ec)
    /\ floorEC_prev' = floorEC
    /\ floorLS_prev' = floorLS

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

MonotoneFloor ==
    /\ floorEC >= floorEC_prev
    /\ floorLS >= floorLS_prev

=============================================================================
