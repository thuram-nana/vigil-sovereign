---------------------------- MODULE OracleMint ----------------------------
(***************************************************************************)
(* VIGIL — ORACLE-AS-SOLE-AUTHORITY (the no-hallucinated-findings          *)
(* invariant, the headline honesty property of the confirm_and_certify     *)
(* pipeline).                                                              *)
(*                                                                        *)
(* A claim's status is either LEAD (a labelled, retained, replayable      *)
(* hypothesis) or FACT (a signed, proof-carrying certificate). The whole  *)
(* point of the system is: a claim becomes FACT *only* because a          *)
(* deterministic ORACLE fired over the real target bytes.  LLM proposals, *)
(* critic endorsements and RL re-ranking may set or keep a claim a LEAD   *)
(* (and may demote), but they must NEVER mint a FACT.  The re-execution   *)
(* firewall is demote-only.                                               *)
(*                                                                        *)
(* INVARIANT (OracleOnlyMints): in every reachable state,                 *)
(*     status[c] = FACT  =>  oracleFired[c] = TRUE                        *)
(* i.e. a claim carries the FACT status only if an oracle actually fired  *)
(* over its bytes at some point in its history.                          *)
(*                                                                        *)
(* CODE CORRESPONDENCE (human-argued abstraction, NOT code extraction):   *)
(*  - The ONLY place status becomes "fact":                              *)
(*    integration/vigil_integration/oracle_adapter.py:157-164             *)
(*    (confirm_and_certify step 3 — build+sign the certificate), reached  *)
(*    ONLY after                                                          *)
(*  - confirm_finding(...) returned non-None                              *)
(*    oracle_adapter.py:117-118, which returns a ConfirmedFinding only    *)
(*    when                                                                *)
(*  - verifier.confirm(ctx).confirmed is True                             *)
(*    framework/v2/verify/confirmation.py:129-131, which is True only     *)
(*    when a signal s with s.fired and s.confidence >= high_confidence    *)
(*    exists                                                              *)
(*    framework/v2/verify/verifier.py:580-581.                            *)
(*    OracleFire(c) abstracts exactly this fired-oracle event; its guard  *)
(*    reproduces[c]=TRUE models "the retained context actually reproduces *)
(*    the finding" (SafeDemoHandler / non-reproducing context => confirm  *)
(*    returns None => reproduces=FALSE).                                  *)
(*  - LlmPropose / CriticEndorse / RlRerank abstract every non-oracle     *)
(*    actor; in the real pipeline NONE of them can reach the mint path —  *)
(*    they only ever produce a labelled lead.  Here they can only set     *)
(*    status := LEAD.                                                     *)
(*  - FirewallReexec abstracts the re-execution firewall which may DEMOTE *)
(*    a fact at re-verification (demote-only), never promote.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Claims          \* a tiny finite set of claim identifiers

VARIABLES
    status,               \* status[c] \in {"LEAD","FACT"}
    oracleFired,          \* oracleFired[c] \in BOOLEAN — history flag: an oracle fired over c's bytes
    reproduces            \* reproduces[c] \in BOOLEAN — do c's retained bytes actually reproduce
                          \* the finding? (i.e. would the deterministic oracle fire).  Static.

vars == <<status, oracleFired, reproduces>>

Status == {"LEAD", "FACT"}

TypeOK ==
    /\ status      \in [Claims -> Status]
    /\ oracleFired \in [Claims -> BOOLEAN]
    /\ reproduces  \in [Claims -> BOOLEAN]

Init ==
    /\ status      = [c \in Claims |-> "LEAD"]
    /\ oracleFired = [c \in Claims |-> FALSE]
    /\ reproduces  \in [Claims -> BOOLEAN]     \* nondeterministic: some claims reproduce, some don't

(***************************************************************************)
(* OracleFire(c): the deterministic oracle fires over c's REAL bytes.     *)
(* Guard reproduces[c]=TRUE == verifier.confirm(ctx).confirmed (a signal  *)
(* fired at >= high_confidence).  It records the history flag AND mints   *)
(* the FACT (confirm_and_certify step 3).  This is the ONLY transition    *)
(* that may set status := "FACT".                                         *)
(***************************************************************************)
OracleFire(c) ==
    /\ reproduces[c] = TRUE
    /\ oracleFired' = [oracleFired EXCEPT ![c] = TRUE]
    /\ status'      = [status      EXCEPT ![c] = "FACT"]
    /\ UNCHANGED reproduces

(***************************************************************************)
(* Non-oracle actors.  An LLM proposal, a critic endorsement, an RL       *)
(* re-rank may set or KEEP a claim a LEAD (and may demote a FACT back to  *)
(* a LEAD), but MUST NOT mint a FACT.  They never touch oracleFired.      *)
(***************************************************************************)
LlmPropose(c) ==
    /\ status' = [status EXCEPT ![c] = "LEAD"]
    /\ UNCHANGED <<oracleFired, reproduces>>

CriticEndorse(c) ==
    /\ status' = [status EXCEPT ![c] = "LEAD"]
    /\ UNCHANGED <<oracleFired, reproduces>>

RlRerank(c) ==
    /\ status' = [status EXCEPT ![c] = "LEAD"]
    /\ UNCHANGED <<oracleFired, reproduces>>

(***************************************************************************)
(* FirewallReexec(c): the re-execution firewall.  Demote-only — a fact    *)
(* that fails re-verification drops back to a LEAD.  Never promotes.      *)
(***************************************************************************)
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

(***************************************************************************)
(* The honesty invariant.                                                 *)
(***************************************************************************)
OracleOnlyMints ==
    \A c \in Claims : status[c] = "FACT" => oracleFired[c] = TRUE

=============================================================================
