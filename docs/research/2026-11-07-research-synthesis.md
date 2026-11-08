# ZAAFElegia: research synthesis (2026-11-07)

Input for the design phase. Three research tracks: reverse engineering SigmaHQ/sigma, SIEM requirements for 2025–2026 (including AI-driven threats), and the open-source landscape. Figures marked UNSOURCED could not be traced to a source.

## 1. What SigmaHQ/sigma is, and is not

Sigma is **not a SIEM**. It is a vendor-neutral detection rule format ("YARA for logs") plus a rule corpus and a quality pipeline. It does not collect, store or execute anything. Rules are converted (via pySigma) into a SIEM's query language, and that SIEM runs them.

| Layer | What it is | License |
|---|---|---|
| Specification | YAML rule format: `logsource` + `detection` (selections with field modifiers) + `condition`. v2 adds correlation rules and filters. Lives in SigmaHQ/sigma-specification. | Public domain |
| Rule corpus | 3,164 core rules, 474 emerging-threat rules, 141 threat-hunting rules, 25 placeholder rules, 173 deprecated rules. | DRL 1.1 (attribution required) |
| Toolchain | pySigma: parser, processing pipelines (field mapping), backends (Splunk, Elastic, …). sigma-cli wraps it. | LGPL |
| Quality pipeline | Schema validation (sigma-rules-validator), logsource tests, regression tests against 1,427 recorded log files (evtx-sigma-checker), goodlog false-positive test against a clean Windows baseline, status promotion (experimental → test → stable). | n/a |

### Corpus statistics (shallow clone, 2026-11-07)

- **Products:** Windows 2,751 (72%) · Linux 245 · Azure 123 · macOS 73 · AWS 58 · GCP 26 · Zeek 24 · Okta 22 · M365 19 · Cisco 17.
- **Categories:** process_creation 1,383 (36%) · registry_set 207 · file_event 177 · ps_script 165 · image_load 101 · network_connection 56 · dns_query 23.
- **Status:** test 2,838 · experimental 249 · stable 77.
- **Level:** high 1,428 · medium 1,360 · low 272 · critical 71.
- **Modifiers:** endswith 2,877 · contains 2,789 · contains|all 937 · startswith 502 · re 169 · windash 105 · cidr 33 · fieldref 5.
- **Correlation and filter rules in the repo:** 0 and 0. The spec supports them; the corpus does not use them yet.

### Gaps in Sigma

1. The corpus is endpoint-centric and Windows-heavy. Cloud, SaaS and identity coverage is thin. There is no coverage of attacks on AI, LLM or agent systems.
2. Every rule detects a single event. Multi-stage attack chains are not expressed.
3. Maturity is low: about 2% of rules are `stable`.
4. Field names assume Sysmon or ECS. OCSF mapping is immature (pySigma-pipeline-ocsf).

### Patterns worth copying

- Rule metadata: UUID `id`, `status` lifecycle, `level`, `falsepositives`, ATT&CK `tags`, `references`, `author`.
- Logsource abstraction (`product` / `category` / `service`), with field mapping done in pipelines rather than in rules.
- CI that tests every rule for true positives on recorded data and for false positives on a clean baseline.
- Coverage heatmap generated from tags (ATT&CK Navigator).

## 2. Threat landscape and requirements (2025–2026)

### Threat drivers

- **Speed:**
  - Average eCrime breakout time is 29 minutes; the fastest seen was 27 s (CrowdStrike GTR 2026).
  - Hand-off between intrusion groups takes 22 s (M-Trends 2026).
  - Implication: detection needs to run in about a minute.
- **Long tail:** median dwell time is 14 days, and espionage or DPRK IT-worker cases run 122 days (M-Trends 2026). Implication: 12–24 months of searchable history.
- **Initial access:**
  - Exploits have overtaken credentials: 31% vs 13% (DBIR 2026).
  - Edge and VPN devices rose from 3% to 22% of exploitation targets (DBIR 2025).
  - Time to exploit is now negative: exploitation often starts before a patch exists.
- **Identity:**
  - 79% of intrusions involve no malware (CrowdStrike 2025).
  - Identity attacks rose 32% in H1 2025 (Microsoft DDR 2025).
  - Common techniques: AiTM, token theft, help-desk vishing.
- **SaaS and supply chain:**
  - OAuth token abuse, as in the Salesloft Drift / Salesforce breach (Aug 2025).
  - Third-party breaches rose 60% year on year (DBIR 2026).
  - Shai-Hulud npm worms, one variant of which spread through MCP packages.
- **AI-driven attacks:**
  - AI-written phishing, and deepfake fraud such as the $25.6M Arup case.
  - Malware that calls LLMs while running (PROMPTSTEAL, PROMPTFLUX).
  - Agentic attackers: GTG-1002, now MITRE campaign C0062.
  - LLMjacking: stolen cloud keys used to run Bedrock models.
- **Attacks on AI:**
  - Prompt injection, and agent goal hijack or tool misuse (OWASP LLM Top 10 2025, OWASP Agentic Top 10).
  - Malicious MCP servers such as postmark-mcp.
  - MITRE ATLAS v5 added 14 agent techniques.

### Market

- **Incumbent pain:** ingest-cost trade-offs, alert fatigue, query-language lock-in (SPL, KQL, YARA-L, AQL), and forced platform migrations (QRadar to XSIAM, Sentinel portal cutoff 2027-03-31).
- **Direction:** decoupled security data lakes and pipeline-level cost control.
  - Sentinel data lake.
  - AWS Security Lake on OCSF.
  - CrowdStrike–Onum, SentinelOne–Observo and Palo Alto–Chronosphere acquisitions.
  - Databricks agreed to buy Panther (June 2026).
- **AI SOC:** Gartner predicts that by 2028, 70% of large SOCs will pilot AI agents but only 15% will see measurable gains without structured evaluation.

### Regulatory clocks (Indonesia first)

- **Bank Indonesia** (PBI 2/2024, PADG 24/2024 amended by PADG 29/2026): first notice within **1 hour**, report within **3 days**.
- **OJK** (POJK 11/2022, SEOJK 29/2022): about **24 h**. To verify against the primary text.
- **UU PDP 27/2022:** **3×24 h**.
- **BSSN** Reg. 1/2024: mandatory reporting, no fixed deadline found.
- **Global:** NIS2 24h/72h/1mo · DORA 4h/72h/1mo · SEC 4 business days · CERT-In 6h with 180-day log retention.

### Implied requirements

**MUST**
1. Native Sigma v2 engine (all correlation types), same rule on stream and history.
2. Streaming time-to-alert ≤ 1 min.
3. OCSF internal schema with ECS and OTLP intake.
4. Hot and cold storage, 12–24 months searchable, with retro-hunt.
5. Identity-first detection content.
6. SaaS and cloud connectors.
7. Edge-device parsing plus correlation with CISA KEV.
8. Per-source ingest cost visibility and filtering.
9. ATT&CK and ATLAS coverage map.
10. Case timeline with regulatory clock templates (BI, OJK, PDP, NIS2, DORA).
11. Telemetry for attacks on AI: LLM gateway logs, MCP tool-call audit logs, agent identities.

**SHOULD**
1. Risk-based alerting per entity, including non-human and agent identities.
2. UEBA baselines, including LLM token use.
3. STIX/TAXII and MISP intake.
4. SOAR hooks with human approval.
5. Federated queries to existing SIEMs.
6. Sigma translation to SPL, KQL and ES|QL.

**LATER**
1. AI triage agent with an evaluation harness.
2. Natural-language-to-Sigma authoring.
3. Deepfake and voice-channel signals.
4. MSSP multi-tenancy.
5. Indonesian data-residency packaging.

## 3. Open-source landscape (gh api, 2026-11-07)

### Key finding

`timescale/rsigma` (MIT, Rust, created 2026-02, 184 stars) is a Sigma-native toolkit. It includes a parser, linter, evaluator, a correlation engine with sliding, tumbling and session windows, a streaming daemon (OTLP, NATS and HTTP input), risk-based alerting, OCSF Detection Finding output, MCP and LSP servers, and backtest in CI. It is the main candidate to reuse and also the main competitor. Risk: one maintainer wrote about 2,100 of its ~2,378 commits.

### Reuse map

| Layer | Decision | Candidates |
|---|---|---|
| Collection | Reuse | OTel Collector / Alloy, Vector (MPL-2.0), Fluent Bit; endpoints: osquery, Falco, Tracee, rustinel |
| Normalization | Reuse and extend | OCSF schema, mapped with Vector VRL; pySigma-pipeline-ocsf; keep ECS aliases |
| Storage | Reuse | ClickHouse (hot and warm), Parquet or Iceberg on S3 (cold); VictoriaLogs as a light option |
| Detection engine | Reuse or fork | rsigma for streaming; pySigma (LGPL, unmodified) plus a custom ClickHouse/SQL backend for history |
| Correlation | **Build (differentiator)** | Sigma v2 correlation with identical stream and history semantics, entity risk, ATT&CK chains |
| Detection-as-code CI | Build thin | rsigma lint and backtest, Atomic Red Team, Stratus Red Team; method from Splunk contentctl and Elastic detection-rules |
| Case management | Integrate | DFIR-IRIS (LGPL), TheHive 5 connector; build only a minimal alert and incident queue |
| SOAR | Integrate | Shuffle (AGPL, separate service), n8n, webhooks |
| Threat intel | Integrate | MISP, OpenCTI (STIX/TAXII) |
| UI | **Build** | No permissive Sigma-native SIEM UI exists; references: SigNoz, Security Onion, OpenSearch Dashboards |
| AI | **Build** | MCP server over our own API; evaluation harness; analyst verdicts fed back into rule tuning |

### Open-source gaps (where ZAAFElegia can differentiate)

1. One Sigma rule, correlations included, running consistently on the live stream and on cheap columnar history (detection plus retro-hunt).
2. Uneven Sigma correlation support: Hayabusa is AGPL and works on files only; rsigma is young; OpenSearch uses its own correlation format.
3. No permissive, cost-efficient security data lake: Matano is dormant, OpenObserve is AGPL, Quickwit belongs to Datadog.
4. Detection testing is tied to vendors, and the main open replay dataset (Security-Datasets) has been stale since 2024.
5. AI triage has no reproducible evaluation and no loop from analyst verdicts back to rule tuning.

### License constraints

- **Do not copy code from:**
  - Elastic License 2.0: Security Onion, elastic/detection-rules.
  - SSPL: Graylog.
  - AGPL: Hayabusa, Loki, OpenObserve, Velociraptor, MISP, Shuffle, Cortex, Wazuh engine.
  - These can still be integrated as separate network services.
- **LGPL** (pySigma, Zircolite, IRIS): use unmodified as libraries.
- **Attribution:** SigmaHQ rules under DRL 1.1 must keep author and reference visible; ATT&CK requires its copyright notice.
- **Recommended license for ZAAFElegia:** Apache-2.0.

## 4. Open questions to close before design sign-off

- OJK incident-reporting clock and log-retention period (primary text of SEOJK 29/2022).
- Whether the UU PDP agency is operational, and the status of the KKS bill.
- Verify rsigma's README claims with a hands-on test before committing to it.
