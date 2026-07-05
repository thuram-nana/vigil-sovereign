# Graph Report - /home/kali/Pictures/PENTEST-main  (2026-07-05)

## Corpus Check
- 364 files · ~812,522 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 4300 nodes · 15759 edges · 62 communities detected
- Extraction: 41% EXTRACTED · 59% INFERRED · 0% AMBIGUOUS · INFERRED: 9293 edges (avg confidence: 0.63)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]

## God Nodes (most connected - your core abstractions)
1. `WorldModel` - 202 edges
2. `HttpRequest` - 195 edges
3. `worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` - 181 edges
4. `NodeKind` - 165 edges
5. `Edge` - 164 edges
6. `EdgeKind` - 134 edges
7. `CrucibleError` - 133 edges
8. `FindingContext` - 130 edges
9. `Node` - 126 edges
10. `Blackboard` - 108 edges

## Surprising Connections (you probably didn't know these)
- `CLI entry point for v2. Invoke with:      python3 -m framework.v2 <subcommand> [` --uses--> `CrucibleError`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/__main__.py → /home/kali/Pictures/PENTEST-main/framework/v2/common/errors.py
- `One-shot environment summary: which backends are reachable, which     paths reso` --uses--> `CrucibleError`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/__main__.py → /home/kali/Pictures/PENTEST-main/framework/v2/common/errors.py
- `FindingPayload` --uses--> `Tests for eval.produce's calibrated-confidence path.  The unit under test: a cri`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/agents/models.py → /home/kali/Pictures/PENTEST-main/framework/v2/eval/tests/test_produce_calibration.py
- `agents.egress_guard — runtime egress allowlist for sovereign-mode httpx.  Why th` --uses--> `SovereigntyViolation`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/agents/egress_guard.py → /home/kali/Pictures/PENTEST-main/framework/v2/common/errors.py
- `Hosts permitted to receive HTTP requests from this process.      Three categorie` --uses--> `SovereigntyViolation`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/agents/egress_guard.py → /home/kali/Pictures/PENTEST-main/framework/v2/common/errors.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (458): from_state(), detect_outliers(), _median(), intruder.analysis — anomaly detection over an attack's result population.  Burp, Indices of anomalous rows.      A row is flagged if ANY of: its status code is a, _Row, AttackType, intruder.attack — the four attack-type combinatorics.  Given marked insertion po (+450 more)

### Community 1 - "Community 1"
Cohesion: 0.01
Nodes (301): Fold another context's populated inputs into this one, so a single         findi, Agent, main(), request_one(), Agent, agents.base — common Agent interface.  Every specialist agent subclasses `Agent`, Base class for every agent under MAO.      Subclasses set the class-level `name`, Return True if there is work for this agent right now.          Cheap; called ev (+293 more)

### Community 2 - "Community 2"
Cohesion: 0.02
Nodes (344): AttackerState, worldmodel.attacker — the attacker's own state as first-class, persistent facts., Record that the attacker has reached ``service_id`` (a service /         endpoin, Node ids the attacker currently controls (deterministic order)., Credential/session/token ids the attacker currently holds., Service/endpoint/segment ids the attacker has reached., A thin, typed view over a :class:`WorldModel` for recording and querying     wha, Idempotently add the attacker principal node. Returns its id. (+336 more)

### Community 3 - "Community 3"
Cohesion: 0.02
Nodes (265): AnthropicBackend, AnthropicBackend — live LLM via the Anthropic Messages API.  Activates when:   -, Live Anthropic backend. The ZDR variant differs only in `name`     (which the so, BaseModel, BedrockBackend, BedrockBackend — Claude on AWS Bedrock with regional restriction.  Sovereign-clo, _region_allowlist(), build_system_prompt() (+257 more)

### Community 4 - "Community 4"
Cohesion: 0.03
Nodes (280): binding_satisfied(), current_host_identifiers(), The set of identifiers the running host can present. Compared,     case-sensitiv, Return (ok, reason). A 'none' binding is always satisfied. A     'host_attestati, _read_machine_ids(), authority_signing_bytes(), _canonical_json(), entitlement_signing_bytes() (+272 more)

### Community 5 - "Community 5"
Cohesion: 0.02
Nodes (230): _coerce_text(), FindingContext, from_http_responses(), from_oob(), from_process_output(), from_side_effect(), _hit_to_dict(), verify.adapter — translate already-collected observations into oracle inputs.  ` (+222 more)

### Community 6 - "Community 6"
Cohesion: 0.02
Nodes (189): PatternAnalyzer, _r(), analysis.analyzers.builtin — the offline pattern analyzer.  A real, dependency-f, Offline pattern-based static analyzer. Always available., _Rule, _analyzers(), _authorize(), build_parser() (+181 more)

### Community 7 - "Community 7"
Cohesion: 0.03
Nodes (175): build_engagement_allowlist(), EgressAllowlist, agents.egress_guard — runtime egress allowlist for sovereign-mode httpx.  Why th, Construct an allowlist for one engagement.      Reads the charter scope via `eth, httpx transport that refuses requests to hosts outside the     allowlist. Wraps, Hosts permitted to receive HTTP requests from this process.      Three categorie, SovereignHttpxTransport, EngagementRefused (+167 more)

### Community 8 - "Community 8"
Cohesion: 0.02
Nodes (156): detect(), api_detection — identify API patterns (REST / GraphQL / SOAP / RPC)., detect(), auth_detection — identify the authentication scheme(s)., run(), detect(), cdn_waf_detection — identify CDN, WAF, and edge-protection layers., detect() (+148 more)

### Community 9 - "Community 9"
Cohesion: 0.03
Nodes (117): Insert a new event. Validates payload against the kind's schema., Convenience: post a new event with supersedes_id=old_id,         copying engagem, _payloads(), _postmortem(), _priors(), _seed(), _similar(), _wins() (+109 more)

### Community 10 - "Community 10"
Cohesion: 0.04
Nodes (124): BlackboardEventRow, Materialised view of a row, with payload already deserialised., _bin_edges(), brier_score(), Calibrator, _clamp(), fit(), measure_ece() (+116 more)

### Community 11 - "Community 11"
Cohesion: 0.04
Nodes (121): BlackboardError, Anything wrong with a blackboard operation (validation, IO)., _load_produced(), _regress(), _score(), _show(), builtin_corpus(), _corpus_from_dir() (+113 more)

### Community 12 - "Community 12"
Cohesion: 0.03
Nodes (115): pytest_configure(), `logging.bind_engagement(slug)` sets a module-level slug that     routes subsequ, _unbind_engagement_after_test(), attack_technique(), cognitive(), Document, load(), _parse() (+107 more)

### Community 13 - "Community 13"
Cohesion: 0.02
Nodes (112): AdaptResult, _alt_case(), _crossover(), _double_url_encode(), evolve(), EvolveResult, _fullwidth(), _mutate() (+104 more)

### Community 14 - "Community 14"
Cohesion: 0.05
Nodes (105): proposal_signing_bytes(), _emit(), _horizon(), _load_snapshot(), _now(), _review(), ingest_horizon(), load_horizon_feed() (+97 more)

### Community 15 - "Community 15"
Cohesion: 0.05
Nodes (97): _add_action_args(), _annotate(), _descriptor(), _rules(), _ruleset(), ActionDescriptor, ActionKind, ActionSignal (+89 more)

### Community 16 - "Community 16"
Cohesion: 0.04
Nodes (73): _classify(), detection_cost_of_technique(), _edge_cost(), _noisy_or(), path_detection_cost(), _path_techniques(), rank_paths(), scanner.detection_cost — stealth ranking via detection ACCOUNTING.  Rank candida (+65 more)

### Community 17 - "Community 17"
Cohesion: 0.06
Nodes (44): diff_summary(), main(), make_request(), Print per-class summary., Compare valid vs invalid stats., Make one login attempt with the wrong password., summarize(), arm_key() (+36 more)

### Community 18 - "Community 18"
Cohesion: 0.12
Nodes (35): _assess(), _load_message(), Malformed message artifact., SocialDefenseError, CrucibleError, assess_message(), _band(), _domain() (+27 more)

### Community 19 - "Community 19"
Cohesion: 0.2
Nodes (11): analyze(), _is_sequential(), scanner.sequencer — session-token / nonce randomness analysis.  A session token, Interpret a token as an integer via decimal, hex, or base64-big-endian., True if the tokens decode to integers forming an arithmetic progression or     p, The randomness verdict for a set of tokens., Measure the randomness of ``tokens`` and flag the weaknesses that make a     ses, SequencerResult (+3 more)

### Community 20 - "Community 20"
Cohesion: 1.0
Nodes (0): 

### Community 21 - "Community 21"
Cohesion: 1.0
Nodes (0): 

### Community 22 - "Community 22"
Cohesion: 1.0
Nodes (0): 

### Community 23 - "Community 23"
Cohesion: 1.0
Nodes (0): 

### Community 24 - "Community 24"
Cohesion: 1.0
Nodes (1): The binary exploitability target for this outcome (None if excluded).

### Community 25 - "Community 25"
Cohesion: 1.0
Nodes (1): |mean_pred - mean_actual| — this bin's contribution to miscalibration.

### Community 26 - "Community 26"
Cohesion: 1.0
Nodes (0): 

### Community 27 - "Community 27"
Cohesion: 1.0
Nodes (1): True iff evolution beat the best seed.

### Community 28 - "Community 28"
Cohesion: 1.0
Nodes (0): 

### Community 29 - "Community 29"
Cohesion: 1.0
Nodes (0): 

### Community 30 - "Community 30"
Cohesion: 1.0
Nodes (0): 

### Community 31 - "Community 31"
Cohesion: 1.0
Nodes (0): 

### Community 32 - "Community 32"
Cohesion: 1.0
Nodes (0): 

### Community 33 - "Community 33"
Cohesion: 1.0
Nodes (0): 

### Community 34 - "Community 34"
Cohesion: 1.0
Nodes (0): 

### Community 35 - "Community 35"
Cohesion: 1.0
Nodes (0): 

### Community 36 - "Community 36"
Cohesion: 1.0
Nodes (0): 

### Community 37 - "Community 37"
Cohesion: 1.0
Nodes (0): 

### Community 38 - "Community 38"
Cohesion: 1.0
Nodes (1): recall — fraction of ground truth rediscovered.

### Community 39 - "Community 39"
Cohesion: 1.0
Nodes (0): 

### Community 40 - "Community 40"
Cohesion: 1.0
Nodes (0): 

### Community 41 - "Community 41"
Cohesion: 1.0
Nodes (0): 

### Community 42 - "Community 42"
Cohesion: 1.0
Nodes (0): 

### Community 43 - "Community 43"
Cohesion: 1.0
Nodes (0): 

### Community 44 - "Community 44"
Cohesion: 1.0
Nodes (0): 

### Community 45 - "Community 45"
Cohesion: 1.0
Nodes (0): 

### Community 46 - "Community 46"
Cohesion: 1.0
Nodes (0): 

### Community 47 - "Community 47"
Cohesion: 1.0
Nodes (1): The fired signals; the subset that carried the confirmation.

### Community 48 - "Community 48"
Cohesion: 1.0
Nodes (1): A baseline vs. mutated response pair, for the differential oracle         (boole

### Community 49 - "Community 49"
Cohesion: 1.0
Nodes (1): A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned

### Community 50 - "Community 50"
Cohesion: 1.0
Nodes (1): An expected (attacker-predicted) vs. observed state pair for the         achieve

### Community 51 - "Community 51"
Cohesion: 1.0
Nodes (1): Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort

### Community 52 - "Community 52"
Cohesion: 1.0
Nodes (1): A unique canary marker plus the sink it was observed in, for the         side-ef

### Community 53 - "Community 53"
Cohesion: 1.0
Nodes (1): The callback base a probe embeds. The operator-hosted relay URL when         one

### Community 54 - "Community 54"
Cohesion: 1.0
Nodes (0): 

### Community 55 - "Community 55"
Cohesion: 1.0
Nodes (0): 

### Community 56 - "Community 56"
Cohesion: 1.0
Nodes (1): The identity triple (src, dst, kind-value) used for upsert.

### Community 57 - "Community 57"
Cohesion: 1.0
Nodes (1): Ordered node ids along the path: src of each edge, then final dst.

### Community 58 - "Community 58"
Cohesion: 1.0
Nodes (1): The provenance id of each hop, in order.

### Community 59 - "Community 59"
Cohesion: 1.0
Nodes (0): 

### Community 60 - "Community 60"
Cohesion: 1.0
Nodes (1): Mint a fresh correlation token and return (token, callback_url).          The UR

### Community 61 - "Community 61"
Cohesion: 1.0
Nodes (1): Return all hits recorded against `token` so far (possibly empty).

## Knowledge Gaps
- **264 isolated node(s):** ``logging.bind_engagement(slug)` sets a module-level slug that     routes subsequ`, `Laplace-smoothed success rate.`, `Wilson 95% lower bound — conservative for the planner.`, `memory.embed — embeddings for similarity search.  Two backends ship in this sess`, `Feature-hashing TF vectorizer. 256-dim, L2-normalized, signed.` (+259 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 20`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 21`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 22`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 23`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 24`** (1 nodes): `The binary exploitability target for this outcome (None if excluded).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 25`** (1 nodes): `|mean_pred - mean_actual| — this bin's contribution to miscalibration.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 26`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 27`** (1 nodes): `True iff evolution beat the best seed.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 29`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 30`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 31`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 32`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 33`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 34`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 35`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 36`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 37`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 38`** (1 nodes): `recall — fraction of ground truth rediscovered.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 39`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 40`** (1 nodes): `codeinj.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 41`** (1 nodes): `ssrf.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 42`** (1 nodes): `pathtrav.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 43`** (1 nodes): `cmdi.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 44`** (1 nodes): `nosqli.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (1 nodes): `sqli.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 46`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 47`** (1 nodes): `The fired signals; the subset that carried the confirmation.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 48`** (1 nodes): `A baseline vs. mutated response pair, for the differential oracle         (boole`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 49`** (1 nodes): `A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 50`** (1 nodes): `An expected (attacker-predicted) vs. observed state pair for the         achieve`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 51`** (1 nodes): `Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 52`** (1 nodes): `A unique canary marker plus the sink it was observed in, for the         side-ef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 53`** (1 nodes): `The callback base a probe embeds. The operator-hosted relay URL when         one`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 54`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 55`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 56`** (1 nodes): `The identity triple (src, dst, kind-value) used for upsert.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 57`** (1 nodes): `Ordered node ids along the path: src of each edge, then final dst.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 58`** (1 nodes): `The provenance id of each hop, in order.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 59`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 60`** (1 nodes): `Mint a fresh correlation token and return (token, callback_url).          The UR`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 61`** (1 nodes): `Return all hits recorded against `token` so far (possibly empty).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` connect `Community 0` to `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 13`, `Community 14`, `Community 15`, `Community 16`, `Community 18`, `Community 19`?**
  _High betweenness centrality (0.222) - this node is a cross-community bridge._
- **Why does `CrucibleError` connect `Community 2` to `Community 0`, `Community 1`, `Community 3`, `Community 4`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 17`, `Community 18`?**
  _High betweenness centrality (0.073) - this node is a cross-community bridge._
- **Why does `HttpRequest` connect `Community 0` to `Community 1`, `Community 3`, `Community 6`?**
  _High betweenness centrality (0.038) - this node is a cross-community bridge._
- **Are the 186 inferred relationships involving `WorldModel` (e.g. with `ChainedConclusion` and `AttackPath`) actually correct?**
  _`WorldModel` has 186 INFERRED edges - model-reasoned connections that need verification._
- **Are the 172 inferred relationships involving `str` (e.g. with `main()` and `.__init__()`) actually correct?**
  _`str` has 172 INFERRED edges - model-reasoned connections that need verification._
- **Are the 189 inferred relationships involving `HttpRequest` (e.g. with `JwtNoneCheck` and `scanner.jwt — JSON Web Token analysis and attacks.  JWTs are their own attack su`) actually correct?**
  _`HttpRequest` has 189 INFERRED edges - model-reasoned connections that need verification._
- **Are the 157 inferred relationships involving `worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` (e.g. with `Store` and `Blackboard`) actually correct?**
  _`worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` has 157 INFERRED edges - model-reasoned connections that need verification._