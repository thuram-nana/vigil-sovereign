# Graph Report - /home/kali/Pictures/PENTEST-main  (2026-07-05)

## Corpus Check
- 375 files · ~857,046 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 4620 nodes · 16620 edges · 102 communities detected
- Extraction: 41% EXTRACTED · 59% INFERRED · 0% AMBIGUOUS · INFERRED: 9886 edges (avg confidence: 0.63)
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
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 73|Community 73]]
- [[_COMMUNITY_Community 74|Community 74]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 80|Community 80]]
- [[_COMMUNITY_Community 81|Community 81]]
- [[_COMMUNITY_Community 82|Community 82]]
- [[_COMMUNITY_Community 83|Community 83]]
- [[_COMMUNITY_Community 84|Community 84]]
- [[_COMMUNITY_Community 85|Community 85]]
- [[_COMMUNITY_Community 86|Community 86]]
- [[_COMMUNITY_Community 87|Community 87]]
- [[_COMMUNITY_Community 88|Community 88]]
- [[_COMMUNITY_Community 89|Community 89]]
- [[_COMMUNITY_Community 90|Community 90]]
- [[_COMMUNITY_Community 91|Community 91]]
- [[_COMMUNITY_Community 92|Community 92]]
- [[_COMMUNITY_Community 93|Community 93]]
- [[_COMMUNITY_Community 94|Community 94]]
- [[_COMMUNITY_Community 95|Community 95]]
- [[_COMMUNITY_Community 96|Community 96]]
- [[_COMMUNITY_Community 97|Community 97]]
- [[_COMMUNITY_Community 98|Community 98]]
- [[_COMMUNITY_Community 99|Community 99]]
- [[_COMMUNITY_Community 100|Community 100]]
- [[_COMMUNITY_Community 101|Community 101]]

## God Nodes (most connected - your core abstractions)
1. `HttpRequest` - 230 edges
2. `WorldModel` - 230 edges
3. `NodeKind` - 199 edges
4. `Edge` - 198 edges
5. `worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` - 185 edges
6. `FindingContext` - 158 edges
7. `EdgeKind` - 155 edges
8. `CrucibleError` - 144 edges
9. `Node` - 142 edges
10. `OracleKind` - 125 edges

## Surprising Connections (you probably didn't know these)
- `CLI entry point for v2. Invoke with:      python3 -m framework.v2 <subcommand> [` --uses--> `CrucibleError`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/__main__.py → /home/kali/Pictures/PENTEST-main/framework/v2/common/errors.py
- `One-shot environment summary: which backends are reachable, which     paths reso` --uses--> `CrucibleError`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/__main__.py → /home/kali/Pictures/PENTEST-main/framework/v2/common/errors.py
- `Move the cursor to the latest event id seen.` --uses--> `Blackboard`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/agents/base.py → /home/kali/Pictures/PENTEST-main/framework/v2/agents/blackboard.py
- `FindingPayload` --uses--> `Tests for eval.produce's calibrated-confidence path.  The unit under test: a cri`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/agents/models.py → /home/kali/Pictures/PENTEST-main/framework/v2/eval/tests/test_produce_calibration.py
- `CrucibleError` --uses--> `scanner.learning — a self-learning contextual bandit for check ordering.  The sc`  [INFERRED]
  /home/kali/Pictures/PENTEST-main/framework/v2/common/errors.py → /home/kali/Pictures/PENTEST-main/framework/v2/scanner/learning.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (477): FindingContext, from_predicate(), from_state(), from_timing_samples(), Typed, replayable bundle of the observations one finding is judged on.      A fi, detect_outliers(), _median(), intruder.analysis — anomaly detection over an attack's result population.  Burp (+469 more)

### Community 1 - "Community 1"
Cohesion: 0.02
Nodes (387): AttackerState, worldmodel.attacker — the attacker's own state as first-class, persistent facts., Record that the attacker has reached ``service_id`` (a service /         endpoin, Node ids the attacker currently controls (deterministic order)., Credential/session/token ids the attacker currently holds., Service/endpoint/segment ids the attacker has reached., A thin, typed view over a :class:`WorldModel` for recording and querying     wha, Idempotently add the attacker principal node. Returns its id. (+379 more)

### Community 2 - "Community 2"
Cohesion: 0.01
Nodes (297): from_http_responses(), Fold another context's populated inputs into this one, so a single         findi, Agent, main(), request_one(), Move the cursor to the latest event id seen., open_blackboard(), Read events for an engagement. Defaults exclude superseded rows. (+289 more)

### Community 3 - "Community 3"
Cohesion: 0.02
Nodes (264): AnthropicBackend, AnthropicBackend — live LLM via the Anthropic Messages API.  Activates when:   -, Live Anthropic backend. The ZDR variant differs only in `name`     (which the so, BaseModel, BedrockBackend, BedrockBackend — Claude on AWS Bedrock with regional restriction.  Sovereign-clo, _region_allowlist(), build_system_prompt() (+256 more)

### Community 4 - "Community 4"
Cohesion: 0.02
Nodes (251): The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp, _clause_true(), confirm_against_local_target(), confirm_finding(), _DemoHandler, DifferentialDemoHandler, _finding_to_dict(), _http_get() (+243 more)

### Community 5 - "Community 5"
Cohesion: 0.02
Nodes (217): Agent, agents.base — common Agent interface.  Every specialist agent subclasses `Agent`, Base class for every agent under MAO.      Subclasses set the class-level `name`, Return True if there is work for this agent right now.          Cheap; called ev, Do one unit of work; return the number of events posted.          Implementation, Events posted to this engagement since this agent's cursor., BenchmarkReport, Blackboard (+209 more)

### Community 6 - "Community 6"
Cohesion: 0.04
Nodes (208): binding_satisfied(), current_host_identifiers(), The set of identifiers the running host can present. Compared,     case-sensitiv, Return (ok, reason). A 'none' binding is always satisfied. A     'host_attestati, _read_machine_ids(), _canonical_json(), entitlement_signing_bytes(), improve.canonical — deterministic signing bytes for a proposal.  Governance appr (+200 more)

### Community 7 - "Community 7"
Cohesion: 0.03
Nodes (175): build_engagement_allowlist(), EgressAllowlist, agents.egress_guard — runtime egress allowlist for sovereign-mode httpx.  Why th, Construct an allowlist for one engagement.      Reads the charter scope via `eth, httpx transport that refuses requests to hosts outside the     allowlist. Wraps, Hosts permitted to receive HTTP requests from this process.      Three categorie, SovereignHttpxTransport, EngagementRefused (+167 more)

### Community 8 - "Community 8"
Cohesion: 0.02
Nodes (189): authority_signing_bytes(), The exact bytes a governance approver signs to approve a merge., authority_from_charter(), authority_from_scope(), authority.charter — derive an engagement authority from the charter.  The charte, Build an authority from an explicit scope list. Fail closed on an     empty scop, Build an authority from the charter's in-scope host table. Raises     OutOfScope, _authorize() (+181 more)

### Community 9 - "Community 9"
Cohesion: 0.03
Nodes (141): PatternAnalyzer, _r(), analysis.analyzers.builtin — the offline pattern analyzer.  A real, dependency-f, Offline pattern-based static analyzer. Always available., _Rule, _analyzers(), _index(), _scan() (+133 more)

### Community 10 - "Community 10"
Cohesion: 0.03
Nodes (112): _payloads(), _postmortem(), _priors(), _seed(), _similar(), _wins(), blob_to_vec(), cosine() (+104 more)

### Community 11 - "Community 11"
Cohesion: 0.03
Nodes (118): detect(), api_detection — identify API patterns (REST / GraphQL / SOAP / RPC)., detect(), auth_detection — identify the authentication scheme(s)., detect(), cdn_waf_detection — identify CDN, WAF, and edge-protection layers., detect(), cms_detection — identify the CMS / off-the-shelf application. (+110 more)

### Community 12 - "Community 12"
Cohesion: 0.04
Nodes (121): BlackboardError, Anything wrong with a blackboard operation (validation, IO)., _load_produced(), _regress(), builtin_corpus(), _corpus_from_dir(), _corpus_from_file(), load_corpus() (+113 more)

### Community 13 - "Community 13"
Cohesion: 0.04
Nodes (114): _add_action_args(), _annotate(), _assess(), build_parser(), _descriptor(), _fingerprint_only(), _is_loopback(), _load_message() (+106 more)

### Community 14 - "Community 14"
Cohesion: 0.04
Nodes (107): proposal_signing_bytes(), _emit(), _horizon(), _load_snapshot(), _now(), _review(), _show(), ingest_horizon() (+99 more)

### Community 15 - "Community 15"
Cohesion: 0.04
Nodes (81): _coerce_text(), from_boolean_probes(), from_oob(), from_process_output(), from_side_effect(), _hit_to_dict(), verify.adapter — translate already-collected observations into oracle inputs.  `, Keep mappings/lists as-is (JSON-safe, and the side-effect oracle searches     th (+73 more)

### Community 16 - "Community 16"
Cohesion: 0.04
Nodes (67): AdaptResult, _alt_case(), _crossover(), _double_url_encode(), evolve(), EvolveResult, _fullwidth(), _mutate() (+59 more)

### Community 17 - "Community 17"
Cohesion: 0.04
Nodes (73): _classify(), detection_cost_of_technique(), _edge_cost(), _noisy_or(), path_detection_cost(), _path_techniques(), rank_paths(), scanner.detection_cost — stealth ranking via detection ACCOUNTING.  Rank candida (+65 more)

### Community 18 - "Community 18"
Cohesion: 0.06
Nodes (54): What a crawl found: the fuzzable requests (ready for ``AuditEngine.audit``),, Breadth-first, scope-bounded, cycle-safe crawler. ``send(HttpRequest) ->     {st, Canonical location key: identical param *names* (not values) collapse, so     ``, analyze_html(), analyze_js(), _clip(), scanner.domxss — static DOM-XSS source→sink analysis.  DOM-based XSS lives entir, Variables assigned (directly) from a DOM source -> the source they carry. (+46 more)

### Community 19 - "Community 19"
Cohesion: 0.05
Nodes (52): diff_summary(), main(), make_request(), Print per-class summary., Compare valid vs invalid stats., Make one login attempt with the wrong password., summarize(), _check_bound() (+44 more)

### Community 20 - "Community 20"
Cohesion: 0.06
Nodes (41): pytest_configure(), `logging.bind_engagement(slug)` sets a module-level slug that     routes subsequ, _unbind_engagement_after_test(), attack_technique(), cognitive(), Document, load(), _parse() (+33 more)

### Community 21 - "Community 21"
Cohesion: 0.07
Nodes (36): arm_key(), BetaPosterior, _candidates(), context_key(), from_dict(), from_json(), LearningError, load() (+28 more)

### Community 22 - "Community 22"
Cohesion: 0.15
Nodes (14): analyze(), collect_tokens(), _is_sequential(), scanner.sequencer — session-token / nonce randomness analysis.  A session token, Interpret a token as an integer via decimal, hex, or base64-big-endian., True if the tokens decode to integers forming an arithmetic progression or     p, The randomness verdict for a set of tokens., Call ``issue`` up to ``n`` times, collecting the non-empty tokens it     returns (+6 more)

### Community 23 - "Community 23"
Cohesion: 1.0
Nodes (0): 

### Community 24 - "Community 24"
Cohesion: 1.0
Nodes (0): 

### Community 25 - "Community 25"
Cohesion: 1.0
Nodes (0): 

### Community 26 - "Community 26"
Cohesion: 1.0
Nodes (0): 

### Community 27 - "Community 27"
Cohesion: 1.0
Nodes (1): The binary exploitability target for this outcome (None if excluded).

### Community 28 - "Community 28"
Cohesion: 1.0
Nodes (1): |mean_pred - mean_actual| — this bin's contribution to miscalibration.

### Community 29 - "Community 29"
Cohesion: 1.0
Nodes (0): 

### Community 30 - "Community 30"
Cohesion: 1.0
Nodes (1): True iff evolution beat the best seed.

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
Nodes (0): 

### Community 39 - "Community 39"
Cohesion: 1.0
Nodes (0): 

### Community 40 - "Community 40"
Cohesion: 1.0
Nodes (0): 

### Community 41 - "Community 41"
Cohesion: 1.0
Nodes (1): recall — fraction of ground truth rediscovered.

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
Nodes (0): 

### Community 48 - "Community 48"
Cohesion: 1.0
Nodes (0): 

### Community 49 - "Community 49"
Cohesion: 1.0
Nodes (0): 

### Community 50 - "Community 50"
Cohesion: 1.0
Nodes (1): A baseline vs. mutated response pair, for the differential oracle         (boole

### Community 51 - "Community 51"
Cohesion: 1.0
Nodes (1): Aligned per-round responses for the SPRT boolean-inference oracle:         for e

### Community 52 - "Community 52"
Cohesion: 1.0
Nodes (1): Paired latency samples (a benign baseline vs a delay-injected probe)         for

### Community 53 - "Community 53"
Cohesion: 1.0
Nodes (1): A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned

### Community 54 - "Community 54"
Cohesion: 1.0
Nodes (1): An expected (attacker-predicted) vs. observed state pair for the         achieve

### Community 55 - "Community 55"
Cohesion: 1.0
Nodes (1): Raw observed values plus a declarative dangerous-condition predicate         for

### Community 56 - "Community 56"
Cohesion: 1.0
Nodes (1): Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort

### Community 57 - "Community 57"
Cohesion: 1.0
Nodes (1): A unique canary marker plus the sink it was observed in, for the         side-ef

### Community 58 - "Community 58"
Cohesion: 1.0
Nodes (1): The callback base a probe embeds. The operator-hosted relay URL when         one

### Community 59 - "Community 59"
Cohesion: 1.0
Nodes (0): 

### Community 60 - "Community 60"
Cohesion: 1.0
Nodes (0): 

### Community 61 - "Community 61"
Cohesion: 1.0
Nodes (1): Posterior mean of the Beta belief, alpha / (alpha + beta).

### Community 62 - "Community 62"
Cohesion: 1.0
Nodes (1): The identity triple (src, dst, kind-value) used for upsert.

### Community 63 - "Community 63"
Cohesion: 1.0
Nodes (1): Ordered node ids along the path: src of each edge, then final dst.

### Community 64 - "Community 64"
Cohesion: 1.0
Nodes (1): Confidence of the weakest edge — the path is no stronger.

### Community 65 - "Community 65"
Cohesion: 1.0
Nodes (1): The provenance id of each hop, in order.

### Community 66 - "Community 66"
Cohesion: 1.0
Nodes (1): The path's success belief: the product of its edges' belief means         (indep

### Community 67 - "Community 67"
Cohesion: 1.0
Nodes (0): 

### Community 68 - "Community 68"
Cohesion: 1.0
Nodes (1): What a node *is*. The set spans the surfaces a modern engagement     touches — w

### Community 69 - "Community 69"
Cohesion: 1.0
Nodes (1): The identity triple (src, dst, kind-value) used for upsert.

### Community 70 - "Community 70"
Cohesion: 1.0
Nodes (1): An enumerated simple path through the world-model: an ordered list     of the ed

### Community 71 - "Community 71"
Cohesion: 1.0
Nodes (1): Ordered node ids along the path: src of each edge, then final dst.

### Community 72 - "Community 72"
Cohesion: 1.0
Nodes (1): The provenance id of each hop, in order.

### Community 73 - "Community 73"
Cohesion: 1.0
Nodes (1): A baseline vs. mutated response pair, for the differential oracle         (boole

### Community 74 - "Community 74"
Cohesion: 1.0
Nodes (1): An expected (attacker-predicted) vs. observed state pair for the         achieve

### Community 75 - "Community 75"
Cohesion: 1.0
Nodes (1): Paired latency samples (a benign baseline vs a delay-injected probe)         for

### Community 76 - "Community 76"
Cohesion: 1.0
Nodes (1): A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned

### Community 77 - "Community 77"
Cohesion: 1.0
Nodes (1): An expected (attacker-predicted) vs. observed state pair for the         achieve

### Community 78 - "Community 78"
Cohesion: 1.0
Nodes (1): Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort

### Community 79 - "Community 79"
Cohesion: 1.0
Nodes (1): The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp

### Community 80 - "Community 80"
Cohesion: 1.0
Nodes (1): Fold another context's populated inputs into this one, so a single         findi

### Community 81 - "Community 81"
Cohesion: 1.0
Nodes (1): The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp

### Community 82 - "Community 82"
Cohesion: 1.0
Nodes (1): The aggregate verdict for one finding.      `confirmed` is True only when at lea

### Community 83 - "Community 83"
Cohesion: 1.0
Nodes (1): Side-effect reflection: place a unique canary (wrapped by `payload_template`)

### Community 84 - "Community 84"
Cohesion: 1.0
Nodes (1): A passive, abstract description of what an oracle must compare.      This is del

### Community 85 - "Community 85"
Cohesion: 1.0
Nodes (1): The aggregate verdict for one finding.      `confirmed` is True only when at lea

### Community 86 - "Community 86"
Cohesion: 1.0
Nodes (1): A baseline vs. mutated response pair, for the differential oracle         (boole

### Community 87 - "Community 87"
Cohesion: 1.0
Nodes (1): Paired latency samples (a benign baseline vs a delay-injected probe)         for

### Community 88 - "Community 88"
Cohesion: 1.0
Nodes (1): A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned

### Community 89 - "Community 89"
Cohesion: 1.0
Nodes (1): An expected (attacker-predicted) vs. observed state pair for the         achieve

### Community 90 - "Community 90"
Cohesion: 1.0
Nodes (1): Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort

### Community 91 - "Community 91"
Cohesion: 1.0
Nodes (1): A unique canary marker plus the sink it was observed in, for the         side-ef

### Community 92 - "Community 92"
Cohesion: 1.0
Nodes (1): Fold another context's populated inputs into this one, so a single         findi

### Community 93 - "Community 93"
Cohesion: 1.0
Nodes (1): The fired signals; the subset that carried the confirmation.

### Community 94 - "Community 94"
Cohesion: 1.0
Nodes (1): A baseline vs. mutated response pair, for the differential oracle         (boole

### Community 95 - "Community 95"
Cohesion: 1.0
Nodes (1): A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned

### Community 96 - "Community 96"
Cohesion: 1.0
Nodes (1): Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort

### Community 97 - "Community 97"
Cohesion: 1.0
Nodes (1): A unique canary marker plus the sink it was observed in, for the         side-ef

### Community 98 - "Community 98"
Cohesion: 1.0
Nodes (1): Fold another context's populated inputs into this one, so a single         findi

### Community 99 - "Community 99"
Cohesion: 1.0
Nodes (1): The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp

### Community 100 - "Community 100"
Cohesion: 1.0
Nodes (1): Mint a fresh correlation token and return (token, callback_url).          The UR

### Community 101 - "Community 101"
Cohesion: 1.0
Nodes (1): Return all hits recorded against `token` so far (possibly empty).

## Knowledge Gaps
- **321 isolated node(s):** ``logging.bind_engagement(slug)` sets a module-level slug that     routes subsequ`, `Laplace-smoothed success rate.`, `Wilson 95% lower bound — conservative for the planner.`, `memory.embed — embeddings for similarity search.  Two backends ship in this sess`, `Feature-hashing TF vectorizer. 256-dim, L2-normalized, signed.` (+316 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 23`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 24`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 25`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 26`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 27`** (1 nodes): `The binary exploitability target for this outcome (None if excluded).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (1 nodes): `|mean_pred - mean_actual| — this bin's contribution to miscalibration.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 29`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 30`** (1 nodes): `True iff evolution beat the best seed.`
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
- **Thin community `Community 38`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 39`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 40`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 41`** (1 nodes): `recall — fraction of ground truth rediscovered.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 42`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 43`** (1 nodes): `codeinj.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 44`** (1 nodes): `ssrf.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (1 nodes): `pathtrav.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 46`** (1 nodes): `cmdi.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 47`** (1 nodes): `nosqli.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 48`** (1 nodes): `sqli.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 49`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 50`** (1 nodes): `A baseline vs. mutated response pair, for the differential oracle         (boole`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 51`** (1 nodes): `Aligned per-round responses for the SPRT boolean-inference oracle:         for e`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 52`** (1 nodes): `Paired latency samples (a benign baseline vs a delay-injected probe)         for`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 53`** (1 nodes): `A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 54`** (1 nodes): `An expected (attacker-predicted) vs. observed state pair for the         achieve`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 55`** (1 nodes): `Raw observed values plus a declarative dangerous-condition predicate         for`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 56`** (1 nodes): `Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 57`** (1 nodes): `A unique canary marker plus the sink it was observed in, for the         side-ef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 58`** (1 nodes): `The callback base a probe embeds. The operator-hosted relay URL when         one`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 59`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 60`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 61`** (1 nodes): `Posterior mean of the Beta belief, alpha / (alpha + beta).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 62`** (1 nodes): `The identity triple (src, dst, kind-value) used for upsert.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 63`** (1 nodes): `Ordered node ids along the path: src of each edge, then final dst.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 64`** (1 nodes): `Confidence of the weakest edge — the path is no stronger.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 65`** (1 nodes): `The provenance id of each hop, in order.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 66`** (1 nodes): `The path's success belief: the product of its edges' belief means         (indep`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 67`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 68`** (1 nodes): `What a node *is*. The set spans the surfaces a modern engagement     touches — w`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 69`** (1 nodes): `The identity triple (src, dst, kind-value) used for upsert.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 70`** (1 nodes): `An enumerated simple path through the world-model: an ordered list     of the ed`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 71`** (1 nodes): `Ordered node ids along the path: src of each edge, then final dst.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 72`** (1 nodes): `The provenance id of each hop, in order.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 73`** (1 nodes): `A baseline vs. mutated response pair, for the differential oracle         (boole`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 74`** (1 nodes): `An expected (attacker-predicted) vs. observed state pair for the         achieve`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 75`** (1 nodes): `Paired latency samples (a benign baseline vs a delay-injected probe)         for`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 76`** (1 nodes): `A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 77`** (1 nodes): `An expected (attacker-predicted) vs. observed state pair for the         achieve`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 78`** (1 nodes): `Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 79`** (1 nodes): `The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 80`** (1 nodes): `Fold another context's populated inputs into this one, so a single         findi`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 81`** (1 nodes): `The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 82`** (1 nodes): `The aggregate verdict for one finding.      `confirmed` is True only when at lea`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 83`** (1 nodes): `Side-effect reflection: place a unique canary (wrapped by `payload_template`)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 84`** (1 nodes): `A passive, abstract description of what an oracle must compare.      This is del`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 85`** (1 nodes): `The aggregate verdict for one finding.      `confirmed` is True only when at lea`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 86`** (1 nodes): `A baseline vs. mutated response pair, for the differential oracle         (boole`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 87`** (1 nodes): `Paired latency samples (a benign baseline vs a delay-injected probe)         for`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 88`** (1 nodes): `A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 89`** (1 nodes): `An expected (attacker-predicted) vs. observed state pair for the         achieve`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 90`** (1 nodes): `Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 91`** (1 nodes): `A unique canary marker plus the sink it was observed in, for the         side-ef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 92`** (1 nodes): `Fold another context's populated inputs into this one, so a single         findi`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 93`** (1 nodes): `The fired signals; the subset that carried the confirmation.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 94`** (1 nodes): `A baseline vs. mutated response pair, for the differential oracle         (boole`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 95`** (1 nodes): `A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 96`** (1 nodes): `Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 97`** (1 nodes): `A unique canary marker plus the sink it was observed in, for the         side-ef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 98`** (1 nodes): `Fold another context's populated inputs into this one, so a single         findi`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 99`** (1 nodes): `The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 100`** (1 nodes): `Mint a fresh correlation token and return (token, callback_url).          The UR`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 101`** (1 nodes): `Return all hits recorded against `token` so far (possibly empty).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` connect `Community 0` to `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 13`, `Community 14`, `Community 15`, `Community 16`, `Community 17`, `Community 18`, `Community 20`, `Community 22`?**
  _High betweenness centrality (0.219) - this node is a cross-community bridge._
- **Why does `HttpRequest` connect `Community 0` to `Community 18`, `Community 13`, `Community 3`, `Community 5`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._
- **Why does `Store` connect `Community 10` to `Community 0`, `Community 2`, `Community 5`, `Community 14`?**
  _High betweenness centrality (0.038) - this node is a cross-community bridge._
- **Are the 224 inferred relationships involving `HttpRequest` (e.g. with `JwtNoneCheck` and `scanner.jwt — JSON Web Token analysis and attacks.  JWTs are their own attack su`) actually correct?**
  _`HttpRequest` has 224 INFERRED edges - model-reasoned connections that need verification._
- **Are the 214 inferred relationships involving `WorldModel` (e.g. with `ChainedConclusion` and `AttackPath`) actually correct?**
  _`WorldModel` has 214 INFERRED edges - model-reasoned connections that need verification._
- **Are the 178 inferred relationships involving `str` (e.g. with `main()` and `.__init__()`) actually correct?**
  _`str` has 178 INFERRED edges - model-reasoned connections that need verification._
- **Are the 196 inferred relationships involving `NodeKind` (e.g. with `ChainedConclusion` and `AttackPath`) actually correct?**
  _`NodeKind` has 196 INFERRED edges - model-reasoned connections that need verification._