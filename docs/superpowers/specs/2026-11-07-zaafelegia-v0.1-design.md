# ZAAFElegia v0.1: Sigma-native detection engine and CLI

- **Status:** design approved section by section on 2026-11-07, pending review of this written spec.
- **Owner:** Rifqi Fitriady.
- **Background research:** [2026-11-07-research-synthesis.md](../../research/2026-11-07-research-synthesis.md).

## 1. Context

ZAAFElegia is an open-source (Apache-2.0) security detection project. Its long-term aim is a Sigma-native SIEM. Version 0.1 is deliberately narrower: a detection **engine library and CLI**, written in Rust, that runs Sigma rules over log files, streams and Parquet data.

Sigma (SigmaHQ) is a rule format and rule corpus, not an execution engine. Existing open-source engines leave several gaps:

- **Hayabusa** (AGPL) handles files only and focuses on Windows.
- **Chainsaw** (GPL) is forensic-focused.
- **Zircolite** (LGPL) works through SQLite.
- **rsigma** (MIT) is young and mostly the work of one maintainer.
- **OpenSearch Security Analytics** uses its own correlation format instead of Sigma's.

None of them proves full Sigma v2 conformance, guarantees identical results on live streams and on historical columnar data, or covers attacks on and with AI systems.

### Goals for v0.1

1. **Full Sigma v2 conformance:** every modifier, meta-filters, and every correlation type including `temporal_ordered`. Conformance is proven by a public, language-neutral conformance suite.
2. **One rule for stream and history:** the same rule gives identical results whether it is evaluated event by event on files or stdin, or compiled to Apache DataFusion over Parquet. Differential testing in CI enforces this.
3. **AI attack detection pack:** new logsources for LLM gateways and MCP tool calls, plus 20–25 rules mapped to MITRE ATT&CK, MITRE ATLAS, the OWASP LLM Top 10 and the OWASP Agentic Top 10.
4. **Built-in detection-as-code:** rule tests (true-positive and false-positive fixtures), differential tests and ATT&CK/ATLAS coverage maps from one CLI, usable in CI.
5. **Inputs:** generic JSON/NDJSON, Windows EVTX, cloud and SaaS audit logs (AWS CloudTrail including Bedrock, Azure/Entra, GCP, Okta, M365, GitHub), and Parquet/OCSF.

### Non-goals for v0.1 (deferred to v0.2+)

- A long-running daemon or server, or network ingestion beyond stdin.
- Storage management, retention or indexing. v0.1 reads Parquet; it does not write a data lake.
- A UI, case management or SOAR.
- Automatic download or update of SigmaHQ rules. Users point the CLI at a path.
- Conversion of Sigma to SPL, KQL or ES|QL.
- An AI triage agent or an MCP server.

## 2. Decisions log

| # | Decision | Alternatives rejected | Reason |
|---|---|---|---|
| D1 | Open-source community project, Apache-2.0 | Commercial/MSSP; internal lab | Owner's choice. Apache-2.0 keeps every reuse path open. |
| D2 | Own engine, written from scratch | Build on rsigma; engine abstraction | Owner's choice. The engine is the differentiator. |
| D3 | Rust | Go; Python | Owner's choice. Performance, memory safety, DataFusion/Arrow ecosystem, mature `evtx` crate. |
| D4 | v0.1 = engine + CLI | Full vertical slice; engine + daemon | Fastest path to users and contributors. Platform features follow. |
| D5 | Shared IR, two single-event evaluators (native and DataFusion), one shared correlator | Everything on DataFusion; native only | Only option that is both fast on large history and correlation-consistent. |
| D6 | Alerts as OCSF Detection Finding | Custom JSON | Standard consumed by AWS Security Lake and other tools. |
| D7 | Test fixtures in a sidecar `<rule>.test.yml` | A test section inside the rule | Rules stay 100% standard Sigma and portable. |
| D8 | AI logsource fields follow OpenTelemetry GenAI semantic conventions | Our own schema | Existing standard, so no new schema to maintain or defend. |
| D9 | Repository goes public when M1 is complete | Public now | First impression is working, tested code. |

## 3. Architecture

### 3.1 Workspace layout

```
ZAAFElegia/
├── crates/
│   ├── zaaf-sigma/        # YAML → typed AST (rules, filters, correlations), with spans
│   ├── zaaf-pipeline/     # field and logsource mapping pipelines (YAML) + presets
│   ├── zaaf-ir/           # AST + pipeline → IR (all modifiers resolved)
│   ├── zaaf-event/        # Event trait: uniform field access over JSON / EVTX / Arrow row
│   ├── zaaf-eval/         # native evaluator, the semantic reference
│   ├── zaaf-datafusion/   # IR → DataFusion expressions over Parquet
│   ├── zaaf-correlate/    # the one stateful correlator
│   ├── zaaf-input/        # readers: NDJSON, EVTX, cloud presets, Parquet
│   ├── zaaf-testkit/      # fixtures, differential tests, SigmaHQ regression runner
│   └── zaaf-cli/          # the `zaaf` binary
├── pipelines/             # preset pipeline YAMLs (sysmon, ecs, ocsf, cloudtrail, entra, okta, …)
├── rules/ai/              # AI attack detection pack (+ .test.yml fixtures)
├── conformance/           # language-neutral Sigma v2 conformance suite
├── docs/
└── fuzz/
```

### 3.2 Crate responsibilities and interfaces

**`zaaf-sigma`**
- Parses Sigma YAML, including multi-document collections, into a typed AST: `Rule`, `Filter` (meta-filter) and `CorrelationRule`.
- Each node keeps its source span, so errors read `file:line:col`.
- Does no semantic resolution and does not depend on other zaaf crates.

**`zaaf-pipeline`**
- Loads pipeline YAML files. Each pipeline has:
  - logsource conditions (which rules it applies to);
  - field-name mappings (Sigma field → event path, one-to-many allowed);
  - value transformations;
  - placeholder expansion (`%var%`).
- Several pipelines can be stacked in priority order.
- Ships presets for Sysmon, ECS, OCSF, CloudTrail, Entra ID, Okta, M365, GitHub audit, OTel GenAI and LiteLLM.

**`zaaf-ir`**
- Compiles AST + pipelines into an immutable `CompiledRule`. The detection becomes a boolean tree of `Predicate { field: FieldPath, op: Op, values, case: Sensitivity }`.
- `Op` covers equality, contains, startswith, endswith, regex, cidr, numeric comparison, exists, null and fieldref.
- Value-level modifiers (`windash`, `base64`, `base64offset`, `wide`/`utf16*`, `expand`, `all`) are expanded at compile time, so evaluators never see them.
- Meta-filters are folded into the rules they target.
- `CompiledCorrelation` references `CompiledRule` ids.

**`zaaf-event`**
- Trait `Event`:
  - `fn get(&self, path: &FieldPath) -> FieldValues<'_>`, which returns zero or more values; arrays are flattened according to Sigma semantics;
  - `fn timestamp(&self) -> Option<Timestamp>`.
- Implementations: `JsonEvent` (serde_json), `EvtxEvent` and `ArrowRowEvent`.
- Field paths support dotted nesting and keys that literally contain dots.

**`zaaf-eval`**
- `Evaluator::new(&[CompiledRule])` builds a lookup that groups rules by logsource and by the fields they use, so rules that cannot apply are skipped.
- `eval(&self, &dyn Event) -> impl Iterator<Item = Match>`.
- This crate **defines** the semantics. Every other evaluator is tested against it.

**`zaaf-datafusion`**
- Translates `CompiledRule` into a DataFusion `Expr` over a Parquet table.
- A field that does not exist in the Parquet schema is treated exactly as `zaaf-eval` treats a missing field: value predicates on it are false, `|exists: false` and `field: null` are true. The conformance suite has a case for each.
- Emits a `Match` stream ordered by timestamp.
- Any predicate that cannot be translated faithfully makes the rule fall back to row-wise native evaluation via `ArrowRowEvent`. `zaaf explain` reports the fallback.

**`zaaf-correlate`**
- Consumes a time-ordered `Match` stream and emits `CorrelationAlert`s.
- Implements `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_median` and `value_percentile`, with `timespan`, `group-by`, aliases and generated-rule suppression as the spec defines them.
- Has exactly one implementation, used by both evaluation paths.

**`zaaf-input`**
- Readers produce `Event`s and handle format auto-detection: `.evtx` magic bytes, the Parquet footer, CloudTrail `{"Records":[...]}`, and NDJSON.
- Cloud presets know each source's timestamp field and record envelope.

**`zaaf-testkit`**
- Runs `.test.yml` fixtures, the conformance suite, differential tests, and the SigmaHQ regression runner.

**`zaaf-cli`**
- The binary `zaaf`. It holds no detection logic of its own.

### 3.3 Data flow

```
input (ndjson / evtx / cloud / parquet)
  │
  ├─ stream mode ─► Event ─► zaaf-eval ───────────┐
  │                                               ├─► Match ─► reorder buffer ─► zaaf-correlate ─► Alert
  └─ hunt mode (Parquet) ─► zaaf-datafusion ──────┘   (watermark)                                (OCSF Detection Finding)
```

- **Single-event matches** become alerts directly, unless the rule is marked as generated-only by a correlation rule.
- **Time ordering:**
  - Correlation needs ordered input. A reorder buffer holds matches up to a configurable watermark (`--max-lateness`, default 5 min).
  - Matches that arrive later than the watermark are counted and reported in the summary, never dropped silently.
  - Matches only are buffered, not raw events, so memory stays proportional to the detection volume.
- **Memory cap:** the correlator caps open groups and windows (`--max-correlation-groups`). When the cap is exceeded it evicts the oldest group and records a metric.

### 3.4 Alert output

Alerts use OCSF Detection Finding (class 2004). Every alert carries:

- rule id, title, level and status;
- tags (ATT&CK, ATLAS, OWASP);
- the matched fields and the source event, or for a correlation, every contributing event id;
- the rule's `author` and `references`, as DRL 1.1 attribution requires.

Output formats: `table` (default on a TTY), `json`, `ndjson` (default when piped) and `csv`.

## 4. CLI

| Command | Purpose |
|---|---|
| `zaaf hunt [PATHS…\|-] -r RULES… [-p PIPELINE…]` | Run rules over logs |
| `zaaf check RULES… [-p PIPELINE…]` | Parse and lint |
| `zaaf test RULES… [--differential]` | Run `.test.yml` fixtures |
| `zaaf explain RULE [-p PIPELINE…]` | Print the IR, the DataFusion plan and any fallbacks |
| `zaaf coverage RULES… -o FILE` | ATT&CK + ATLAS Navigator layer, or Markdown |

### `hunt` options

- `--format auto|ndjson|evtx|cloudtrail|entra|okta|m365|github|parquet`
- `--engine auto|stream|datafusion`. With `auto`, Parquet uses DataFusion and everything else uses stream.
- `--from/--to` restrict the time range.
- `--min-level` and `--status` filter which rules run.
- `-o table|json|ndjson|csv`
- `--fail-on-match`
- `--strict`, `--max-errors N`
- `--max-lateness` and `--max-correlation-groups`
- `-` reads stdin as a live stream, for example `tail -f app.log | zaaf hunt -r rules/ -`.

### `check` lint rules

Errors:
- schema violations;
- unknown modifiers;
- duplicate ids;
- correlations that reference missing rules;
- invalid regex.

Warnings:
- fields left unmapped by the selected pipelines;
- regex that needs a backtracking engine;
- ATT&CK or ATLAS tags that do not exist. The tags are checked against bundled ATT&CK/ATLAS STIX data.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Matches found (only with `--fail-on-match`) |
| 2 | Rule errors |
| 3 | Input errors (only with `--strict`, or when `--max-errors` is exceeded) |
| 4 | Internal error |

### Test fixture format (`<rule>.test.yml`)

```yaml
rule: mcp_tool_outside_allowlist.yml
pipelines: [otel_genai]          # optional
cases:
  - name: agent calls shell exec after reading email
    expect: match                # match | no_match | {count: N}
    events: fixtures/tp_shell_exec.ndjson
  - name: allowlisted tool use
    expect: no_match
    events:
      - { "gen_ai.tool.name": "search_docs", "gen_ai.agent.id": "a1" }
```

`zaaf test --differential` runs every case through both the native and the DataFusion evaluator. To use DataFusion, the fixture events are first converted to a temporary Parquet file. Any difference between the two results counts as a failure.

## 5. Detection content

### 5.1 New logsources

| Logsource | Canonical fields (OTel GenAI) | v0.1 pipeline presets |
|---|---|---|
| `product: llm_gateway`, `category: llm_request` | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.prompt`, `gen_ai.completion`, `user.id`, `client.address` | OTel GenAI spans (JSON export), LiteLLM proxy logs |
| `product: mcp`, `category: mcp_tool_call` | `gen_ai.tool.name`, `gen_ai.tool.call.arguments`, `gen_ai.agent.id`, `session.id`, `mcp.server.name`, `mcp.content.source` (trusted/untrusted) | ZAAFElegia MCP audit-log JSON format (documented in `docs/logsources/mcp.md`) |
| `product: aws`, `service: cloudtrail` (existing) | CloudTrail fields | CloudTrail preset |

### 5.2 AI rule pack (20–25 rules, all `status: experimental`)

| Group | Example rule | Sigma technique | Mapping |
|---|---|---|---|
| LLMjacking | Bedrock model enumeration followed by `InvokeModel`/`Converse` from the same identity within 1 h | `temporal_ordered` | ATT&CK T1078.004, ATLAS |
| Unbounded consumption | Token use per identity above a threshold in a window | `value_sum` | OWASP LLM10 |
| Prompt injection | Injection phrases or Unicode tag characters (U+E0000–U+E007F) in retrieved content or tool output | single-event | OWASP LLM01, ATLAS AML.T0051 |
| Agent tool misuse | Untrusted content read, then a sensitive tool (exec, send_email, write_file) in the same session within 5 min | `temporal_ordered` | OWASP ASI01, ASI02 |
| Agent exfiltration | Secret access, then outbound call to a new domain in the same session | `temporal_ordered` | ASI02, T1567 |
| MCP supply chain | Modification of `.mcp.json`, `claude_desktop_config.json`, `~/.cursor/mcp.json` | `file_event` | T1554 |
| AI-enabled malware | Non-browser process (LOLBin, script host) resolving or connecting to LLM API domains | `dns_query`, `network_connection` | T1071, PROMPTSTEAL-style |
| Shadow AI | Proxy access to unsanctioned GenAI domains | single-event, `level: informational` | — |

- **Tags:** in addition to `attack.*`, the pack uses `atlas.<id>` and `owasp.llm<NN>` / `owasp.asi<NN>`. These namespaces are documented in `docs/tags.md`.
- **Fixtures:** they are synthetic, because no public dataset of real agent attacks exists, and each fixture is labelled `synthetic: true`.
- **Upstream contribution:** the endpoint-based rules (MCP config, AI-enabled malware) will be proposed to SigmaHQ.

### 5.3 Conformance suite (`conformance/`)

- **Format:** language-neutral. Each case is a directory with `rules/*.yml`, `events.ndjson`, `expected.yml` (matched rule ids per event index, and correlation alerts with their contributing event indexes) and a `spec_ref` naming the specification section under test.
- **Coverage:**
  - condition grammar (`1 of x*`, `all of them`, precedence of `not`/`and`/`or`, parentheses);
  - wildcards and escaping;
  - default case-insensitivity and the `cased` modifier;
  - `null` and `exists`;
  - every value modifier;
  - numeric comparisons;
  - `cidr`, `fieldref` and placeholders;
  - meta-filters;
  - every correlation type, including window boundaries (inclusive/exclusive), `group-by` with missing fields, and alias handling.
- **Run:** `zaaf test conformance/`. The README invites other engines to run it.

### 5.4 SigmaHQ regression (CI, fetched at test time, not vendored)

1. Every rule in `rules`, `rules-emerging-threats`, `rules-threat-hunting` and `rules-placeholder` parses and compiles. Exceptions are listed in `conformance/known-unsupported.yml`, each with a reason.
2. Rules are run against SigmaHQ `regression_data`, and the match/no-match result is compared with the expected results. The pass rate is published in the README.

## 6. Error handling

| Situation | Behaviour |
|---|---|
| Invalid rule | Reported with `file:line:col` and skipped. With `--strict` the run aborts with exit code 2. |
| Malformed log record | Counted; the first N examples are shown; processing continues until `--max-errors` (then exit code 3). |
| Regex | `regex` crate, which runs in linear time. Patterns that need lookaround or backreferences fall back to `fancy-regex` with a backtrack limit, and lint warns about them. |
| Hostile or odd input | The engine never panics on data. Parser, EVTX reader, NDJSON reader and evaluator are fuzzed. |
| Correlator memory cap | Oldest groups are evicted, and the eviction count appears in the run summary. |
| Late events | Counted per rule and reported in the summary. |
| DataFusion translation gap | Per-rule fallback to native row-wise evaluation, reported by `explain` and in a verbose log. |

Every run ends with a summary: events read, parse errors, rules loaded and skipped, matches, correlation alerts, late events and evictions.

## 7. Testing strategy

1. **Unit tests** in every crate.
2. **Conformance suite**, the primary semantic gate.
3. **Differential tests:** `proptest` generates events for each conformance rule, and `zaaf-eval` and `zaaf-datafusion` must agree on every generated event.
4. **SigmaHQ regression**, as described in §5.4.
5. **Fuzzing** with `cargo-fuzz` on the parser, the readers and the evaluator. A short run happens on each PR and a longer run nightly.
6. **Benchmarks** with `criterion`, plus an end-to-end comparison with Hayabusa and Chainsaw on the same public EVTX dataset. The methodology is published, whatever the result.
7. **CI (GitHub Actions):** `fmt`, `clippy -D warnings`, tests, conformance, differential tests, and `cargo-deny`. `cargo-deny` blocks AGPL, SSPL, Elastic License, GPL and unlicensed dependencies.

## 8. Milestones

Each milestone ships as a `0.0.x` pre-release.

| # | Scope | Done when |
|---|---|---|
| M1 | `zaaf-sigma`, `zaaf-pipeline` (core), `zaaf-ir`, `zaaf-event` (JSON), `zaaf-eval`, NDJSON input, `check`, single-event `hunt`, conformance suite (single-event parts) | Single-event conformance passes; 100% of the SigmaHQ corpus parses (or exceptions are documented). **Repository goes public.** |
| M2 | `zaaf-correlate` with all types, reorder buffer and watermark | Correlation conformance passes |
| M3 | EVTX reader, cloud/SaaS presets, the full set of pipeline presets | SigmaHQ `regression_data` run is automated and its pass rate published |
| M4 | `zaaf-datafusion`, Parquet input, `explain` | Differential tests pass across the whole conformance suite |
| M5 | `zaaf-testkit` `test`, `coverage`, AI logsources and rule pack, a GitHub Action | Every AI rule has passing TP and FP fixtures |
| v0.1 | Release binaries (Linux, macOS, Windows), docs site, benchmark results | Public release |

## 9. Licensing and community

- **License:** `LICENSE` is Apache-2.0.
- **NOTICE:** `NOTICE` explains:
  - DRL 1.1 attribution when SigmaHQ rules are used: author and reference are kept in alerts;
  - MITRE ATT&CK/ATLAS terms for the bundled STIX data.
- **Community files:** `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant), `SECURITY.md`, and issue/PR templates.
- **No code copied from copyleft projects:** nothing is copied from Hayabusa, Chainsaw, Velociraptor, Security Onion, elastic/detection-rules or any other AGPL, GPL, SSPL or Elastic-licensed project. They are studied as references only.

## 10. Risks

| Risk | Mitigation |
|---|---|
| Two evaluators diverge | `zaaf-eval` is the reference; differential tests and per-rule fallback |
| The Sigma spec is ambiguous in places (for example window boundaries, `group-by` with missing fields) | Each interpretation is recorded in the conformance case's `spec_ref` notes and raised upstream in sigma-specification |
| Scope of v0.1 is large for a small team | Milestones are independently releasable; M1 alone is useful |
| Synthetic fixtures for the AI pack may not reflect real attacks | `experimental` status, `synthetic: true` labels, and an open call for real-world samples |
| Competing with rsigma and Hayabusa for attention | Lead with provable conformance, stream/history equivalence and the AI pack, not raw speed |

## 11. Open questions (do not block M1)

- Exact OCSF Detection Finding field mapping for correlation alerts with many contributing events: embed them, or reference them by id.
- Final names of the OTel GenAI attributes for tool calls and agent ids, to be pinned to a specific semconv version when M5 starts.
- Whether to publish the conformance suite as its own repository later.
