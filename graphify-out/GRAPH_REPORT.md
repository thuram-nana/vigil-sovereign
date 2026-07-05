# Graph Report - /home/kali/Pictures/PENTEST-main  (2026-07-05)

## Corpus Check
- 369 files · ~835,510 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 4480 nodes · 16241 edges · 82 communities detected
- Extraction: 41% EXTRACTED · 59% INFERRED · 0% AMBIGUOUS · INFERRED: 9623 edges (avg confidence: 0.63)
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

## God Nodes (most connected - your core abstractions)
1. `HttpRequest` - 226 edges
2. `WorldModel` - 202 edges
3. `worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` - 183 edges
4. `NodeKind` - 165 edges
5. `Edge` - 164 edges
6. `FindingContext` - 153 edges
7. `EdgeKind` - 134 edges
8. `CrucibleError` - 133 edges
9. `Node` - 126 edges
10. `RequestTemplate` - 117 edges

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
Cohesion: 0.02
Nodes (444): AttackerState, worldmodel.attacker — the attacker's own state as first-class, persistent facts., Record that the attacker has reached ``service_id`` (a service /         endpoin, Node ids the attacker currently controls (deterministic order)., Credential/session/token ids the attacker currently holds., Service/endpoint/segment ids the attacker has reached., A thin, typed view over a :class:`WorldModel` for recording and querying     wha, Idempotently add the attacker principal node. Returns its id. (+436 more)

### Community 1 - "Community 1"
Cohesion: 0.01
Nodes (383): FindingContext, from_state(), Typed, replayable bundle of the observations one finding is judged on.      A fi, detect_outliers(), _median(), intruder.analysis — anomaly detection over an attack's result population.  Burp, Indices of anomalous rows.      A row is flagged if ANY of: its status code is a, _Row (+375 more)

### Community 2 - "Community 2"
Cohesion: 0.02
Nodes (319): from_http_responses(), Agent, Agent, agents.base — common Agent interface.  Every specialist agent subclasses `Agent`, Base class for every agent under MAO.      Subclasses set the class-level `name`, Return True if there is work for this agent right now.          Cheap; called ev, Do one unit of work; return the number of events posted.          Implementation, Events posted to this engagement since this agent's cursor. (+311 more)

### Community 3 - "Community 3"
Cohesion: 0.01
Nodes (302): _coerce_text(), from_boolean_probes(), from_oob(), from_process_output(), from_side_effect(), from_timing_samples(), _hit_to_dict(), verify.adapter — translate already-collected observations into oracle inputs.  ` (+294 more)

### Community 4 - "Community 4"
Cohesion: 0.02
Nodes (217): AnthropicBackend, AnthropicBackend — live LLM via the Anthropic Messages API.  Activates when:   -, Live Anthropic backend. The ZDR variant differs only in `name`     (which the so, BedrockBackend, BedrockBackend — Claude on AWS Bedrock with regional restriction.  Sovereign-clo, _region_allowlist(), build_system_prompt(), build_user_prompt() (+209 more)

### Community 5 - "Community 5"
Cohesion: 0.03
Nodes (200): build_engagement_allowlist(), EgressAllowlist, agents.egress_guard — runtime egress allowlist for sovereign-mode httpx.  Why th, Construct an allowlist for one engagement.      Reads the charter scope via `eth, httpx transport that refuses requests to hosts outside the     allowlist. Wraps, Hosts permitted to receive HTTP requests from this process.      Three categorie, SovereignHttpxTransport, EngagementRefused (+192 more)

### Community 6 - "Community 6"
Cohesion: 0.04
Nodes (201): binding_satisfied(), current_host_identifiers(), The set of identifiers the running host can present. Compared,     case-sensitiv, Return (ok, reason). A 'none' binding is always satisfied. A     'host_attestati, _read_machine_ids(), _canonical_json(), entitlement_signing_bytes(), improve.canonical — deterministic signing bytes for a proposal.  Governance appr (+193 more)

### Community 7 - "Community 7"
Cohesion: 0.02
Nodes (197): _add_action_args(), _annotate(), build_parser(), _descriptor(), _is_loopback(), _load_produced(), main(), _NoRedirect (+189 more)

### Community 8 - "Community 8"
Cohesion: 0.03
Nodes (141): PatternAnalyzer, _r(), analysis.analyzers.builtin — the offline pattern analyzer.  A real, dependency-f, Offline pattern-based static analyzer. Always available., _Rule, _analyzers(), _index(), _scan() (+133 more)

### Community 9 - "Community 9"
Cohesion: 0.03
Nodes (154): _bin_edges(), brier_score(), Calibrator, _clamp(), fit(), measure_ece(), pav(), _predicted() (+146 more)

### Community 10 - "Community 10"
Cohesion: 0.02
Nodes (151): detect(), api_detection — identify API patterns (REST / GraphQL / SOAP / RPC)., detect(), auth_detection — identify the authentication scheme(s)., BaseModel, detect(), cdn_waf_detection — identify CDN, WAF, and edge-protection layers., _fingerprint_only() (+143 more)

### Community 11 - "Community 11"
Cohesion: 0.03
Nodes (112): _payloads(), _postmortem(), _priors(), _seed(), _similar(), _wins(), blob_to_vec(), cosine() (+104 more)

### Community 12 - "Community 12"
Cohesion: 0.04
Nodes (113): authority_signing_bytes(), The exact bytes a governance approver signs to approve a merge., authority_from_charter(), authority_from_scope(), authority.charter — derive an engagement authority from the charter.  The charte, Build an authority from an explicit scope list. Fail closed on an     empty scop, Build an authority from the charter's in-scope host table. Raises     OutOfScope, _authorize() (+105 more)

### Community 13 - "Community 13"
Cohesion: 0.04
Nodes (107): proposal_signing_bytes(), _emit(), _horizon(), _load_snapshot(), _now(), _review(), _show(), ingest_horizon() (+99 more)

### Community 14 - "Community 14"
Cohesion: 0.03
Nodes (89): browser_send(), BrowserCrawler, scanner.browser_crawler — JS-aware (SPA) crawling via the headless browser.  The, A ``send`` that renders each request's URL in a headless browser and     returns, A JS-aware crawler: the same graph-based crawl, but every page is rendered     i, _add_request(), CrawlResult, _Extractor (+81 more)

### Community 15 - "Community 15"
Cohesion: 0.03
Nodes (89): pytest_configure(), `logging.bind_engagement(slug)` sets a module-level slug that     routes subsequ, _unbind_engagement_after_test(), attack_technique(), cognitive(), Document, load(), _parse() (+81 more)

### Community 16 - "Community 16"
Cohesion: 0.03
Nodes (58): Fold another context's populated inputs into this one, so a single         findi, main(), request_one(), ping(), calc(), load_state(), fetch(), main() (+50 more)

### Community 17 - "Community 17"
Cohesion: 0.04
Nodes (73): _classify(), detection_cost_of_technique(), _edge_cost(), _noisy_or(), path_detection_cost(), _path_techniques(), rank_paths(), scanner.detection_cost — stealth ranking via detection ACCOUNTING.  Rank candida (+65 more)

### Community 18 - "Community 18"
Cohesion: 0.05
Nodes (58): arm_key(), BetaPosterior, _candidates(), context_key(), ContextualBandit, from_dict(), from_json(), LearningError (+50 more)

### Community 19 - "Community 19"
Cohesion: 0.05
Nodes (50): AdaptResult, _alt_case(), _crossover(), _double_url_encode(), evolve(), EvolveResult, _fullwidth(), _mutate() (+42 more)

### Community 20 - "Community 20"
Cohesion: 0.13
Nodes (33): _assess(), _load_message(), Malformed message artifact., SocialDefenseError, assess_message(), _band(), _domain(), socialdefense.detectors — the inbound social-engineering indicator engine.  Dete (+25 more)

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
Nodes (0): 

### Community 25 - "Community 25"
Cohesion: 1.0
Nodes (1): The binary exploitability target for this outcome (None if excluded).

### Community 26 - "Community 26"
Cohesion: 1.0
Nodes (1): |mean_pred - mean_actual| — this bin's contribution to miscalibration.

### Community 27 - "Community 27"
Cohesion: 1.0
Nodes (0): 

### Community 28 - "Community 28"
Cohesion: 1.0
Nodes (1): True iff evolution beat the best seed.

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
Nodes (0): 

### Community 39 - "Community 39"
Cohesion: 1.0
Nodes (1): recall — fraction of ground truth rediscovered.

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
Nodes (0): 

### Community 48 - "Community 48"
Cohesion: 1.0
Nodes (1): A baseline vs. mutated response pair, for the differential oracle         (boole

### Community 49 - "Community 49"
Cohesion: 1.0
Nodes (1): An expected (attacker-predicted) vs. observed state pair for the         achieve

### Community 50 - "Community 50"
Cohesion: 1.0
Nodes (1): Paired latency samples (a benign baseline vs a delay-injected probe)         for

### Community 51 - "Community 51"
Cohesion: 1.0
Nodes (1): A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned

### Community 52 - "Community 52"
Cohesion: 1.0
Nodes (1): An expected (attacker-predicted) vs. observed state pair for the         achieve

### Community 53 - "Community 53"
Cohesion: 1.0
Nodes (1): Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort

### Community 54 - "Community 54"
Cohesion: 1.0
Nodes (1): The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp

### Community 55 - "Community 55"
Cohesion: 1.0
Nodes (1): The callback base a probe embeds. The operator-hosted relay URL when         one

### Community 56 - "Community 56"
Cohesion: 1.0
Nodes (0): 

### Community 57 - "Community 57"
Cohesion: 1.0
Nodes (0): 

### Community 58 - "Community 58"
Cohesion: 1.0
Nodes (1): The identity triple (src, dst, kind-value) used for upsert.

### Community 59 - "Community 59"
Cohesion: 1.0
Nodes (1): Ordered node ids along the path: src of each edge, then final dst.

### Community 60 - "Community 60"
Cohesion: 1.0
Nodes (1): The provenance id of each hop, in order.

### Community 61 - "Community 61"
Cohesion: 1.0
Nodes (0): 

### Community 62 - "Community 62"
Cohesion: 1.0
Nodes (1): The aggregate verdict for one finding.      `confirmed` is True only when at lea

### Community 63 - "Community 63"
Cohesion: 1.0
Nodes (1): Side-effect reflection: place a unique canary (wrapped by `payload_template`)

### Community 64 - "Community 64"
Cohesion: 1.0
Nodes (1): A passive, abstract description of what an oracle must compare.      This is del

### Community 65 - "Community 65"
Cohesion: 1.0
Nodes (1): The aggregate verdict for one finding.      `confirmed` is True only when at lea

### Community 66 - "Community 66"
Cohesion: 1.0
Nodes (1): A baseline vs. mutated response pair, for the differential oracle         (boole

### Community 67 - "Community 67"
Cohesion: 1.0
Nodes (1): Paired latency samples (a benign baseline vs a delay-injected probe)         for

### Community 68 - "Community 68"
Cohesion: 1.0
Nodes (1): A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned

### Community 69 - "Community 69"
Cohesion: 1.0
Nodes (1): An expected (attacker-predicted) vs. observed state pair for the         achieve

### Community 70 - "Community 70"
Cohesion: 1.0
Nodes (1): Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort

### Community 71 - "Community 71"
Cohesion: 1.0
Nodes (1): A unique canary marker plus the sink it was observed in, for the         side-ef

### Community 72 - "Community 72"
Cohesion: 1.0
Nodes (1): Fold another context's populated inputs into this one, so a single         findi

### Community 73 - "Community 73"
Cohesion: 1.0
Nodes (1): The fired signals; the subset that carried the confirmation.

### Community 74 - "Community 74"
Cohesion: 1.0
Nodes (1): A baseline vs. mutated response pair, for the differential oracle         (boole

### Community 75 - "Community 75"
Cohesion: 1.0
Nodes (1): A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned

### Community 76 - "Community 76"
Cohesion: 1.0
Nodes (1): Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort

### Community 77 - "Community 77"
Cohesion: 1.0
Nodes (1): A unique canary marker plus the sink it was observed in, for the         side-ef

### Community 78 - "Community 78"
Cohesion: 1.0
Nodes (1): Fold another context's populated inputs into this one, so a single         findi

### Community 79 - "Community 79"
Cohesion: 1.0
Nodes (1): The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp

### Community 80 - "Community 80"
Cohesion: 1.0
Nodes (1): Mint a fresh correlation token and return (token, callback_url).          The UR

### Community 81 - "Community 81"
Cohesion: 1.0
Nodes (1): Return all hits recorded against `token` so far (possibly empty).

## Knowledge Gaps
- **288 isolated node(s):** ``logging.bind_engagement(slug)` sets a module-level slug that     routes subsequ`, `Laplace-smoothed success rate.`, `Wilson 95% lower bound — conservative for the planner.`, `memory.embed — embeddings for similarity search.  Two backends ship in this sess`, `Feature-hashing TF vectorizer. 256-dim, L2-normalized, signed.` (+283 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 21`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 22`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 23`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 24`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 25`** (1 nodes): `The binary exploitability target for this outcome (None if excluded).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 26`** (1 nodes): `|mean_pred - mean_actual| — this bin's contribution to miscalibration.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 27`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (1 nodes): `True iff evolution beat the best seed.`
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
- **Thin community `Community 38`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 39`** (1 nodes): `recall — fraction of ground truth rediscovered.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 40`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 41`** (1 nodes): `codeinj.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 42`** (1 nodes): `ssrf.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 43`** (1 nodes): `pathtrav.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 44`** (1 nodes): `cmdi.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (1 nodes): `nosqli.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 46`** (1 nodes): `sqli.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 47`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 48`** (1 nodes): `A baseline vs. mutated response pair, for the differential oracle         (boole`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 49`** (1 nodes): `An expected (attacker-predicted) vs. observed state pair for the         achieve`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 50`** (1 nodes): `Paired latency samples (a benign baseline vs a delay-injected probe)         for`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 51`** (1 nodes): `A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 52`** (1 nodes): `An expected (attacker-predicted) vs. observed state pair for the         achieve`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 53`** (1 nodes): `Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 54`** (1 nodes): `The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 55`** (1 nodes): `The callback base a probe embeds. The operator-hosted relay URL when         one`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 56`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 57`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 58`** (1 nodes): `The identity triple (src, dst, kind-value) used for upsert.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 59`** (1 nodes): `Ordered node ids along the path: src of each edge, then final dst.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 60`** (1 nodes): `The provenance id of each hop, in order.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 61`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 62`** (1 nodes): `The aggregate verdict for one finding.      `confirmed` is True only when at lea`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 63`** (1 nodes): `Side-effect reflection: place a unique canary (wrapped by `payload_template`)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 64`** (1 nodes): `A passive, abstract description of what an oracle must compare.      This is del`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 65`** (1 nodes): `The aggregate verdict for one finding.      `confirmed` is True only when at lea`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 66`** (1 nodes): `A baseline vs. mutated response pair, for the differential oracle         (boole`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 67`** (1 nodes): `Paired latency samples (a benign baseline vs a delay-injected probe)         for`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 68`** (1 nodes): `A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 69`** (1 nodes): `An expected (attacker-predicted) vs. observed state pair for the         achieve`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 70`** (1 nodes): `Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 71`** (1 nodes): `A unique canary marker plus the sink it was observed in, for the         side-ef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 72`** (1 nodes): `Fold another context's populated inputs into this one, so a single         findi`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 73`** (1 nodes): `The fired signals; the subset that carried the confirmation.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 74`** (1 nodes): `A baseline vs. mutated response pair, for the differential oracle         (boole`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 75`** (1 nodes): `A list of out-of-band interactions (whatever `OOBReceiver.poll`         returned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 76`** (1 nodes): `Captured stdout/stderr for the sanitizer oracle (ASAN/UBSAN/panic/         abort`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 77`** (1 nodes): `A unique canary marker plus the sink it was observed in, for the         side-ef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 78`** (1 nodes): `Fold another context's populated inputs into this one, so a single         findi`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 79`** (1 nodes): `The exact mapping `OracleVerifier.confirm` consumes. Only keys whose         inp`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 80`** (1 nodes): `Mint a fresh correlation token and return (token, callback_url).          The UR`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 81`** (1 nodes): `Return all hits recorded against `token` so far (possibly empty).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` connect `Community 0` to `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 13`, `Community 14`, `Community 15`, `Community 16`, `Community 17`, `Community 18`, `Community 19`, `Community 20`?**
  _High betweenness centrality (0.225) - this node is a cross-community bridge._
- **Why does `HttpRequest` connect `Community 1` to `Community 0`, `Community 7`, `Community 10`, `Community 14`, `Community 18`?**
  _High betweenness centrality (0.059) - this node is a cross-community bridge._
- **Why does `CrucibleError` connect `Community 0` to `Community 2`, `Community 4`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 11`, `Community 12`, `Community 15`, `Community 18`, `Community 20`?**
  _High betweenness centrality (0.058) - this node is a cross-community bridge._
- **Are the 220 inferred relationships involving `HttpRequest` (e.g. with `JwtNoneCheck` and `scanner.jwt — JSON Web Token analysis and attacks.  JWTs are their own attack su`) actually correct?**
  _`HttpRequest` has 220 INFERRED edges - model-reasoned connections that need verification._
- **Are the 176 inferred relationships involving `str` (e.g. with `main()` and `.__init__()`) actually correct?**
  _`str` has 176 INFERRED edges - model-reasoned connections that need verification._
- **Are the 186 inferred relationships involving `WorldModel` (e.g. with `ChainedConclusion` and `AttackPath`) actually correct?**
  _`WorldModel` has 186 INFERRED edges - model-reasoned connections that need verification._
- **Are the 159 inferred relationships involving `worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` (e.g. with `Store` and `Blackboard`) actually correct?**
  _`worldmodel — the persistent, typed attack-graph substrate.  Every other reasonin` has 159 INFERRED edges - model-reasoned connections that need verification._