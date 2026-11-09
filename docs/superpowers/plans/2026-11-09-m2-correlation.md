# ZAAFElegia M2: Correlation Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship pre-release `0.0.2` of ZAAFElegia: Sigma 2.1 correlation rules (every type, chains, aliases, `generate`) evaluated by one stateful correlator behind a reorder buffer with a watermark, wired into `zaaf check` and `zaaf hunt`, proven by correlation cases in the language-neutral conformance suite, plus the per-event evaluation work budget the M1 final review asked for.

**Architecture:**
- `zaaf-eval` gains a per-(rule, event) work budget (Task 1).
- `zaaf-sigma` parses correlation documents into a typed `Correlation` with positions (Task 2).
- `zaaf-ir` resolves references by `id` or `name`, orders chains, applies aliases and pipeline field mapping, and produces `CompiledCorrelation`s (Task 3).
- The new crate `zaaf-correlate` holds the only correlation implementation: a sliding window with incremental aggregates for every type (Task 4), groups, conditions, chaining and the memory cap (Task 5), and a reorder buffer with a watermark plus the `CorrelationEngine` facade (Task 6).
- `zaaf hunt` feeds rule matches to the engine and writes correlation alerts as OCSF Detection Findings that reference their contributors (Task 7).
- `zaaf-testkit` and the conformance suite gain correlation expectations and ten correlation cases (Tasks 8 and 9); a fuzz target covers the correlator (Task 10); docs and the 0.0.2 version close the milestone (Task 11).

**Tech Stack:** Rust (edition 2024, MSRV 1.89). No new third-party dependencies: `zaaf-correlate` uses only `std` and the workspace crates. Tests: assert_cmd/predicates/tempfile, cargo-fuzz.

**Spec:** [docs/superpowers/specs/2026-11-07-zaafelegia-v0.1-design.md](../specs/2026-11-07-zaafelegia-v0.1-design.md), milestone M2 (§3.2 `zaaf-correlate`, §3.3 data flow, reorder buffer and memory cap, §4 `hunt` options, §5.3 conformance, §6 error handling, §8). Sigma semantics: Sigma correlation rules specification 2.1.0 (2025-08-02) and its JSON schema.

**Base:** `main` at `9096ecc` (after the minor-backlog merge, PR #3). Every "replace" block below quotes that commit's text.

**Verification of this plan:** every task's code below was applied mechanically, task by task, to a fresh `git archive` export of `9096ecc`; after each task the code was already `rustfmt`-clean, `cargo clippy --workspace --all-targets -- -D warnings` was clean and `cargo test --workspace --locked` passed (counts per task in each task's Step "see them pass"). After Task 11: 316 tests; `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok` (its one `syn` duplicate warning already exists on `main`); `cargo +1.89 check --workspace --all-targets --locked` passes; the SigmaHQ corpus (commit `53b90df`, `--expect-counts 3807,3807`) gives 3807/3807 files with 0 errors and 0 warnings; the `correlate` fuzz target ran 90 s (268k runs, with its seeds and dictionary) and `parse_rule` 60 s (556k runs, with the new correlation seeds) without a crash. See "Self-review" at the end for what was not verified.

## Global Constraints

- **License:** Apache-2.0. `cargo-deny` must reject AGPL, GPL, SSPL, Elastic License and unlicensed dependencies. M2 adds no third-party dependency.
- **No copied code:** nothing is copied from Hayabusa, Chainsaw, Velociraptor, Security Onion, elastic/detection-rules, rsigma or any copyleft or source-available project.
- **Toolchain:** Rust stable, `edition = "2024"`, `rust-version = "1.89"`. Rust 1.88+ has `let` chains, so clippy's `collapsible_if` expects them; the code below uses them.
- **Names:** crates are `zaaf-*` (new: `zaaf-correlate`, with `publish = false` like every crate on `main`); the binary is `zaaf`.
- **Sigma version:** Sigma specification 2.1.0, including the correlation rules specification 2.1.0.
- **Semantic reference:** `zaaf-eval` defines single-event semantics; `zaaf-correlate` is the only correlation implementation (design D5). Every interpretation of an ambiguous point is recorded in a conformance case's `spec_ref`/`description` and in `conformance/README.md`.
- **Alerts:** OCSF Detection Finding, `class_uid: 2004`. Every alert carries the rule's `author` and `references` (DRL 1.1); a correlation alert also carries those of every contributing rule.
- **Exit codes (unchanged):** `0` OK, `1` matches found (only with `--fail-on-match`; correlation alerts count), `2` rule errors (and usage errors), `3` input errors (with `--strict`, or above `--max-errors`; unreadable inputs always), `4` internal error.
- **No panics on data:** the engine must not panic on any rule text or log input.
- **Nothing is dropped silently:** late matches, matches without a timestamp, matches without a group-by field, evicted groups, dropped window entries, early buffer releases and work-budget hits are counted and reported.
- **Every task ends with:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` (which also updates `Cargo.lock` when the task adds a dependency), `cargo test --workspace --locked`, all passing, then a commit that includes any `Cargo.lock` change. CI runs with `--locked`.
- **Commit messages** end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Third-party APIs:** versions stay pinned in the workspace `Cargo.toml`. If an API differs slightly from the code shown, adapt minimally, keep the behaviour, and say so in the commit body.

## Decisions (recorded here; each is the conservative option, flagged where the spec is silent)

| # | Decision | Why |
|---|---|---|
| M2-D1 | **Work budget** per (rule, event): 64 MiB of work units (`DEFAULT_WORK_BUDGET = 1 << 26`). Each predicate and each field lookup costs 1; each value comparison costs 1 plus the byte length of the compared text; `fieldref` pays for each normalised value and for both sides of every pair. The budget sits on top of the per-event `EventCtx` cache from `main`: the cache decides what is *computed* once per event, the budget charges what each rule *compares*, so a rule pays the same whether an earlier rule warmed the cache or not. On exhaustion the rule counts as *not matching* that event (never as a match, even under `not`), and the hit is counted per rule and warned like regex limit hits. Pattern-side cost (glob backtracking) is rule-controlled and not charged. Not configurable from the CLI in M2. | M1 final review: bounds keyword, glob-over-many-values and `fieldref` amplification without changing results on normal events. |
| M2-D2 | **Window:** for a contribution at time `t` the window is `[t - timespan, t]`, inclusive at both ends. The condition is evaluated after every contribution (sliding windows ending at each match, as the spec asks: "not restricted to boundaries"). When it holds, one alert lists every contribution in the window and the group is cleared, so no contribution counts towards two alerts of one correlation. Consequence: an upper-bound-only condition (`lt: 2`) holds at the first match. **Flagged interpretation.** | Deterministic, streaming, no end-of-window timers; matches how SIEM threshold rules behave. |
| M2-D3 | **Group-by with a missing field** (absent, null, or an empty array): the match joins no group and is counted (`missing_group_by`, reported). It is not grouped with other field-less matches. Group values compare exactly (case-sensitive); an array field groups by its full list of non-null values. **Flagged interpretation.** | Grouping unrelated events under a shared "null" key would create false correlations; counting keeps it visible. |
| M2-D4 | **`group-by` absent:** accepted with a warning; all matches form one group. | The spec says "mandatory" but describes it as optional; failing would reject rules pySigma accepts. |
| M2-D5 | **`temporal`/`temporal_ordered`:** default condition `gte: <number of rules>`. `temporal` counts distinct referenced rules in the window; `temporal_ordered` counts the longest prefix of `rules` that occurs in order; equal timestamps count as in order. | Spec: count of different event types; ties cannot be ordered reliably at second resolution. |
| M2-D6 | **`value_percentile`:** the percentage of the group's values in the window equal to the arriving match's value (so `lte: 1` finds values seen in at most 1% of the group's matches). **Flagged interpretation:** the spec example ("a process name ... than 1% of all the processes") gives no percentile rank, so a rank-based reading is impossible. **`value_median`** (in the design spec, not in the Sigma 2.1.0 schema): accepted with a warning, evaluated as the median; kept out of the conformance suite (extensions are not allowed there). | |
| M2-D7 | **Numbers** for value_sum/avg/median: JSON numbers or numeric strings, the first finite numeric value of the first mapped field that has one. A match without a number stays in the window but adds nothing; with no numbers at all the condition is not evaluated. | Mirrors M1 numeric comparison (case 011). |
| M2-D8 | **`generate`:** a rule *or correlation* alerts on its own unless it is referenced and every referencing correlation has `generate: false` (the default). Inner correlations of a chain therefore do not alert by default ("only the outermost correlation rule may define meta information"). | Never hide an alert another correlation asked to keep. |
| M2-D9 | **Chains:** an inner alert is one contribution to the outer correlation at the time it fires; its group values are the only fields it carries, so every outer group-by (and value) field must be an inner group-by name, otherwise it is a rule error. Correlations come out of `zaaf-ir` in dependency order; cycles are rule errors. | Spec allows chaining; an unreadable field would silently never match. |
| M2-D10 | **Field mapping:** group-by, alias and condition fields go through the pipelines of the *referenced rule's* logsource; of several mapped names, the first present with a non-null value is used. | Same field names as the rule's own detection. |
| M2-D11 | **Reorder buffer:** watermark = newest timestamp seen − `--max-lateness` (default `5m`; `0` allowed). Matches are released when `time <= watermark`, in time order, ties in arrival order. A match is **late** when its time is before the watermark at arrival or before an already released match: counted per rule, warned, not correlated; its single-event finding is still written. The buffer holds at most 1,000,000 matches; beyond that the oldest is released early (counted). At the end of input, and also when `--max-errors` aborts the run, everything still buffered is correlated before the output is closed. Only reduced matches (`Observation`: group values, aggregate value, a reference) are buffered, never events. | Design §3.3. |
| M2-D12 | **Matches without a timestamp** are not correlated (counted per rule, warned). The M1 `Utc::now()` fallback still applies to single-event finding times only. | Wall-clock time would corrupt the watermark. |
| M2-D13 | **Memory:** `--max-correlation-groups` (default 100,000, at least 1) caps open groups across all correlations; opening another evicts the least recently updated group; evictions of groups that still had entries inside their timespan are counted. Expired groups are freed silently. Each group keeps at most 65,536 entries (oldest dropped, counted). Per-contribution work is O(1) amortised except `temporal_ordered` (O(rules × log n)) and `value_median` (O(distinct values)), both bounded by the entry cap. | Design §3.3 "memory cap"; bounded per-event work. |
| M2-D14 | **Output (resolves design §11 open question): reference, not embed.** A correlation finding lists contributors in `finding_info.related_events` (`uid` of the match's own finding, or of the inner correlation finding; `type`, `title`, first/last seen) and `unmapped.correlation` (`type`, `timespan`, `group_by`, `condition`, `fields`, aggregate `value`, `contributor_count`, `event_count`, `events[]` with `source`, `record`, `finding_uid`, `rule_id`, `time`; lists capped at 1,000). `unmapped.sigma.contributing_rules` carries every contributing rule's `id`, `title`, `author`, `references`. A contributing match is referenced by the uid `main` already gives single-event findings, `{rule_id}:{FNV-1a 64 of the event's canonical JSON}` (computed by the same `finding_uid` helper whether or not the rule's own finding is written). The correlation finding's uid is `{correlation id}:{FNV-1a 64 of the contributing match uids, each followed by a 0xff byte}`, computed with the same `fnv1a` helper in `output.rs`, so it is stable across runs. | Bounded alert size; events stay locatable; DRL attribution for base rules. |
| M2-D15 | **`--min-level`/`--status`** select what alerts. Rules and inner correlations a selected correlation needs are still evaluated; unselected correlations are removed (not muted) so they do not use the group cap. | Filtering a base rule out must not break a selected correlation. |
| M2-D16 | **References** by `id` or `name` across all loaded files; correlation ids default to `title:{title}` like rules and are unique across rules and correlations; an ambiguous name, a rule named twice in one `rules` list, an unknown reference and an alias naming a rule outside `rules` are rule errors at the reference's position. | Spec "Related rules"; design §4 lint "correlations that reference missing rules". |
| M2-D17 | **Shape checks** in `zaaf-sigma`: `timespan` is a positive integer with `s`, `m`, `h` or `d` (at most 3650d; `w`, `M`, `y` are errors), unknown keys inside `correlation:` are errors (catches `group_by`), condition operators are `gt gte lt lte eq neq` with numeric (int or float) values AND'd, `field` only for value types and a list only for `value_count`, `condition` required except for the temporal types, `generate` must be a boolean. | Spec "Time Selection", "Condition", JSON schema. |
| M2-D18 | **Conformance format:** keep `case.yml` (M1 decision; design §5.3 says `expected.yml`). New optional keys: `correlations`, `correlation_only` (exact list; absent = none), `max_lateness` (default `5m`), `late`, `missing_group_by`. Events are fed in file order; timestamps decide correlation order. | Backward compatible with the 30 M1 cases. |
| M2-D19 | **Lateness syntax:** `0` or `N[smhd]` (zero allowed), shared by the CLI and the testkit (`zaaf_correlate::parse_lateness`). | |
| M2-D20 | **Total compile budget:** correlations add no weight. When the budget has skipped rules, every correlation is skipped too, without per-correlation errors: it counts in the budget error's "(N documents skipped)" and in `correlations_skipped`. | Otherwise each correlation would report the skipped rules as "unknown", burying the one real error. |
| M2-D21 | **Correlation metadata** uses the rule helpers on `main`: `parse_title` (missing or non-string title is an error) and a shared `parse_meta` (wrongly typed `id`, `author`, `references`, ... are ignored with a warning naming the field); a YAML merge key inside `correlation:` is rejected like everywhere else. | One behaviour for rules and correlations. |

## Scope notes for M2

- **In scope:** everything in the M2 row of design §8 plus the work budget. `zaaf check` lints correlations (the M1-deferred "correlations that reference missing rules" lint).
- **Not in scope:** DataFusion feeding the correlator (M4), EVTX timestamps (M3), CLI flags for the per-group entry cap, the reorder-buffer cap or the work budget (constants, documented in the README), tagging/pushing the 0.0.2 release (needs Rifqi, as in M1 Task 16), regenerating the README roadmap images (`assets/readme/*.svg`, generated by `assets/readme/src/build.py`; Task 11 updates only the roadmap table).
- **Determinism:** with the same inputs, alerts and their uids are identical across runs: single-event uids are content hashes (from `main`), and correlation uids hash those.

## Built on `main` 9096ecc: how the minor-backlog changes are used

The first version of this plan was verified on `c2e0212`. The minor-backlog branch has since merged (PR #3); every task below is rewritten against `9096ecc` and re-verified. Where a backlog change touches M2 code:

- **G1 #12, #10, condition messages (`zaaf-sigma`):** `Detection::condition_positions` and token-named condition errors need nothing from M2. `parse_document` already has a `warns` out-parameter, so Task 2 only routes correlations through it. Task 2 extracts the rule metadata block of `parse_rule` into `parse_meta`, which `parse_rule` and `parse_correlation` share; `assemble` is not used for correlations because they have no `logsource` or `detection`. `parse_title`, `merge_key_error`, `warn` and the YAML helpers become `pub(crate)` for `correlation.rs` (M2-D21).
- **G2 `Budget`, `attempted`, skipped-count wording, duplicate id first, logsource-mismatch and failed-filter warnings (`rule.rs`):** Task 3 adds the correlation step after the rules loop and before the budget error is written, reusing the `seen` id set, which now holds exactly the ids of compiled rules (duplicates are rejected before compiling). If `budget.exceeded()`, correlations are skipped and counted in `budget.skipped` (M2-D20), so the existing exact "(N documents skipped)" count includes them. A test pins this.
- **G2 `FieldValue::Uint`:** correlation extraction uses `as_text`/`as_f64`, which cover it; Task 1's `text_len` handles every variant.
- **G2 per-event `EventCtx` cache and per-rule regex counters (`zaaf-eval`):** Task 1 keeps both. `Evaluator::new` still collects the regex counters once and now delegates to `with_work_budget`; `matching_rules` keeps one `EventCtx` per event and gives each rule a fresh `Work` (M2-D1).
- **G3 streaming arrays, `--max-line-bytes`, `name:LINE:` fatal errors, Cf `sanitize`:** Task 7 edits only the per-event loop, the summary and the abort path of `scan`; the input handling is untouched. Every new warning goes through `sanitize`.
- **G3 content-hash finding uid and FNV helper (`output.rs`):** Task 7 splits the existing hash into `fnv1a` (bytes) + `event_hash` (canonical JSON), adds `finding_uid(info, evidence)` used by `detection_finding` and by the correlation references, and `correlation_uid` on the same `fnv1a`. A unit test pins `fnv1a` to the FNV-1a reference vectors, so existing uids do not change.
- **G3 `zaaf check` exit 2 with no rule files; `publish = false`:** no interaction; `crates/zaaf-correlate/Cargo.toml` has `publish = false` (Task 4).
- **G4 SHA-pinned actions, `--locked`, Dependabot:** Task 10 changes only the fuzz matrix line; the pinned steps already pass `seeds/<target>` and `dictionaries/<target>.dict` by name, so the new target picks up `fuzz/seeds/correlate/` and `fuzz/dictionaries/correlate.dict` without other workflow edits. Tasks that add dependencies commit the updated `Cargo.lock` so `--locked` CI passes.
- **G4 exact corpus counts:** Task 3's change to `compare_known_unsupported.py` adds compiled `correlations` to the document lower bound with `report.get`, so the required-key schema (`REPORT_KEYS`) is unchanged; `--expect-counts 3807,3807` still holds (the pinned corpus has no correlation documents).
- **G4 fuzz seeds:** Task 10 adds `fuzz/seeds/correlate/` (an NDJSON stream and an "extra rules + `%%` + events" input) and two correlation documents to `fuzz/seeds/parse_rule/`.

## File Structure

```
crates/
├── zaaf-eval/src/lib.rs            # + Work, WorkExhausted, DEFAULT_WORK_BUDGET, eval_bounded, work_limit_hits (on top of EventCtx)
├── zaaf-sigma/src/
│   ├── correlation.rs              # NEW: Correlation, CorrelationType, CondOp, Spanned, Alias, parse_timespan, shape checks
│   ├── document.rs                 # Document::Correlation(Correlation); parse_meta shared with rules; helpers pub(crate)
│   └── lib.rs                      # re-exports
├── zaaf-ir/src/
│   ├── correlation.rs              # NEW: CompiledCorrelation, InputSource, FieldSource, compile_correlations, correlation_only
│   ├── rule.rs                     # compile() also compiles correlations; CompileOutput.correlations
│   └── lib.rs                      # re-exports
├── zaaf-correlate/                 # NEW crate: the one correlator
│   ├── src/alert.rs                # FieldText, AggValue, Contributor, CorrelationAlert
│   ├── src/window.rs               # Window: sliding window + incremental aggregates for every type
│   ├── src/correlator.rs           # Correlator: extraction, groups, conditions, chaining, caps, Stats
│   ├── src/reorder.rs              # ReorderBuffer (watermark), parse_lateness
│   ├── src/engine.rs               # CorrelationEngine = ReorderBuffer + Correlator + late counters
│   ├── src/lib.rs
│   └── tests/{correlator,engine}.rs
├── zaaf-cli/
│   ├── src/select.rs               # NEW: which rules/correlations run and which alert
│   ├── src/output.rs               # + MatchRef, finding_uid, correlation_uid, correlation_finding
│   ├── src/hunt.rs                 # --max-lateness, --max-correlation-groups, engine wiring, warnings, summary
│   ├── src/check.rs                # correlation counts
│   └── tests/correlate.rs          # NEW
└── zaaf-testkit/src/lib.rs         # correlation expectations in case.yml
conformance/cases/031..040-correlation-*   # NEW cases; README interpretations 21-36
fuzz/fuzz_targets/correlate.rs              # NEW fuzz target
fuzz/seeds/correlate/, fuzz/dictionaries/correlate.dict   # NEW seeds and dictionary
fuzz/seeds/parse_rule/03[49]-correlation-*.yml            # NEW parse_rule seeds
docs/releases/0.0.2.md                      # NEW
```

---

### Task 1: zaaf-eval: per-event evaluation work budget

Bounds evaluation work per (rule, event) so that keyword searches over huge events, `fieldref` over large arrays and many-valued fields cannot amplify CPU time (decision M2-D1). This is the first M2 task, as the M1 final review recommended, because the correlator runs after the evaluator and inherits its cost. It threads a `Work` counter through the existing `EventCtx`-based evaluation on `main`; the cache and the per-rule regex counters stay as they are.

**Files:**
- Modify: `crates/zaaf-eval/src/lib.rs`
- Modify: `crates/zaaf-cli/tests/hunt.rs`
- Modify: `crates/zaaf-cli/src/hunt.rs`

**Interfaces:**
- Consumes: `zaaf_ir::{Expr, Predicate, Matcher, Target, CompiledRule}`, `zaaf_event::{Event, FieldValue}` (unchanged).
- Produces (in `zaaf_eval`):
  - `pub const DEFAULT_WORK_BUDGET: u64 = 1 << 26;`
  - `pub struct WorkExhausted;` and `pub struct Work` with `Work::new(budget: u64) -> Work`.
  - `Evaluator::with_work_budget(rules: Vec<CompiledRule>, budget: u64) -> Evaluator` (`Evaluator::new` uses the default).
  - `Evaluator::work_limit_hits(&self) -> Vec<(usize, u64)>`: `(rule index, events)` for rules that ran out of budget.
  - `pub fn eval_bounded(expr: &Expr, event: &dyn Event, work: &mut Work) -> Result<bool, WorkExhausted>` (builds its own `EventCtx`).
  - `eval_expr(expr, event) -> bool` and `Evaluator::matching_rules` keep their signatures; `matching_rules` keeps one `EventCtx` per event, gives each rule a fresh `Work`, and treats an exhausted rule as not matching.
  - Internally `eval_with`, `eval_predicate`, `value_matches` and `fieldref` return `Result<bool, WorkExhausted>`; `get(ctx, field, work)` charges a cached lookup; `text_len(&FieldValue)` sizes a comparison without allocating for strings.
  - In `zaaf-cli/src/hunt.rs`, `warn_regex_limits` becomes `warn_limits` and also prints work-budget hits.

- [ ] **Step 1: Write the failing tests**

In `crates/zaaf-eval/src/lib.rs`, replace:

```rust
        assert_eq!(reported[0].0, 1);
        assert!(reported[0].1 >= 1);
    }
}
```

with:

```rust
        assert_eq!(reported[0].0, 1);
        assert!(reported[0].1 >= 1);
    }

    fn evaluator_with_budget(src: &str, budget: u64) -> Evaluator {
        let rules = evaluator(src).rules;
        Evaluator::with_work_budget(rules, budget)
    }

    #[test]
    fn fieldref_over_large_arrays_runs_out_of_work_and_is_reported() {
        let e = evaluator_with_budget(
            &format!(
                "{}---\n{}",
                rule(
                    "ref",
                    "    s:\n        A|fieldref|contains: B\n    condition: s\n"
                ),
                rule("plain", "    s:\n        C: x\n    condition: s\n"),
            ),
            100_000,
        );
        let a: Vec<String> = (0..1000).map(|i| format!("left-{i}")).collect();
        let b: Vec<String> = (0..1000).map(|i| format!("right-{i}")).collect();
        let event = JsonEvent::new(serde_json::json!({"A": a, "B": b, "C": "x"}));
        // 1000 x 1000 pairs cost about 16M units: over budget, so "no match", counted.
        assert_eq!(e.matching_rules(&event), vec![1]);
        assert_eq!(e.work_limit_hits(), vec![(0, 1)]);
        // A matching pair found before the budget runs out still matches.
        let hit = JsonEvent::new(serde_json::json!({"A": ["xx-left-0"], "B": a, "C": "x"}));
        assert_eq!(e.matching_rules(&hit), vec![0, 1]);
        assert_eq!(e.work_limit_hits(), vec![(0, 1)]);
    }

    #[test]
    fn keyword_search_over_a_huge_event_is_bounded() {
        let e = evaluator_with_budget(
            &rule("kw", "    k:\n        - needle\n    condition: k\n"),
            10_000,
        );
        let big: Vec<String> = (0..5000).map(|i| format!("hay-{i}")).collect();
        let event = JsonEvent::new(serde_json::json!({ "a": big }));
        assert!(e.matching_rules(&event).is_empty());
        assert_eq!(e.work_limit_hits(), vec![(0, 1)]);
        // A small event under the same budget evaluates normally and is not counted.
        let small = JsonEvent::new(serde_json::json!({"a": "a needle here"}));
        assert_eq!(e.matching_rules(&small), vec![0]);
        assert_eq!(e.work_limit_hits(), vec![(0, 1)]);
    }

    #[test]
    fn budget_is_per_rule_and_per_event() {
        let e = evaluator_with_budget(
            &format!(
                "{}---\n{}",
                rule("a", "    s:\n        F|contains: zz\n    condition: s\n"),
                rule("b", "    s:\n        F|contains: zz\n    condition: s\n"),
            ),
            40,
        );
        // Each rule pays about 2 + 1 + 1 + 30 units for a 30-byte value: under 40 each.
        let event = JsonEvent::new(serde_json::json!({"F": format!("{}zz", "x".repeat(28))}));
        assert_eq!(e.matching_rules(&event), vec![0, 1]);
        assert_eq!(e.matching_rules(&event), vec![0, 1]);
        assert!(e.work_limit_hits().is_empty());
    }

    #[test]
    fn exhausted_budget_never_turns_into_a_match_under_not() {
        let e = evaluator_with_budget(
            &rule(
                "n",
                "    s:\n        F|contains: needle\n    condition: not s\n",
            ),
            50,
        );
        let event = JsonEvent::new(serde_json::json!({"F": "x".repeat(200)}));
        assert!(e.matching_rules(&event).is_empty());
        assert_eq!(e.work_limit_hits(), vec![(0, 1)]);
    }

    #[test]
    fn default_budget_is_64_mib_of_text() {
        assert_eq!(DEFAULT_WORK_BUDGET, 64 * 1024 * 1024);
        let mut w = Work::new(10);
        assert_eq!(w.charge(10), Ok(()));
        assert_eq!(w.charge(1), Err(WorkExhausted));
    }
}
```

In `crates/zaaf-cli/tests/hunt.rs`, replace:

```rust
        .code(3)
        .stderr(predicate::str::contains("b.json:3: invalid JSON array: "));
}
```

with:

```rust
        .code(3)
        .stderr(predicate::str::contains("b.json:3: invalid JSON array: "));
}

#[test]
fn work_budget_hits_are_reported_without_changing_exit_code() {
    let dir = only_rule(
        "title: Ref\nid: r-ref\nlogsource:\n    product: test\ndetection:\n    sel:\n        A|fieldref|contains: B\n    condition: sel\n",
    );
    let a: Vec<String> = (0..3000).map(|i| format!("left-{i:05}")).collect();
    let b: Vec<String> = (0..3000).map(|i| format!("right-{i:05}")).collect();
    let line = serde_json::json!({"A": a, "B": b}).to_string();
    fs::write(dir.path().join("events.ndjson"), format!("{line}\n")).unwrap();
    hunt(dir.path())
        .args(["-o", "ndjson"])
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("exceeded the per-event work budget")
                .and(predicate::str::contains("r-ref")),
        );
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-eval && cargo test -p zaaf-cli --test hunt work_budget`
Expected: FAIL to compile: `no function or associated item named with_work_budget found for struct Evaluator` (and the CLI test fails because no warning is printed).

- [ ] **Step 3: Implement**

In `crates/zaaf-eval/src/lib.rs`, replace:

```rust
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;
use zaaf_event::{Event, FieldValue, parse_timestamp, timestamp_from_epoch};
use zaaf_ir::{
    CmpOp, CompiledRule, Expr, LimitCounter, Matcher, Predicate, RefMode, Target, TimePart,
};

pub struct Evaluator {
    rules: Vec<CompiledRule>,
    /// Per rule, the distinct regex hit counters, collected once at construction.
    counters: Vec<Vec<LimitCounter>>,
}

impl Evaluator {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        let counters = rules.iter().map(|r| r.expr.regex_counters()).collect();
        Self { rules, counters }
    }

    pub fn rules(&self) -> &[CompiledRule] {
```

with:

```rust
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use zaaf_event::{Event, FieldValue, parse_timestamp, timestamp_from_epoch};
use zaaf_ir::{
    CmpOp, CompiledRule, Expr, LimitCounter, Matcher, Predicate, RefMode, Target, TimePart,
};

/// Work units one rule may spend on one event before it gives up (see [`Work`]).
/// A unit is roughly one byte of compared text, so the default allows about 64 MiB of
/// comparisons per rule and event: far above any normal event, low enough that
/// amplification (keywords over many values, `fieldref` over large arrays) stays bounded.
pub const DEFAULT_WORK_BUDGET: u64 = 1 << 26;

/// The work budget ran out; the rule is treated as not matching the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkExhausted;

/// Remaining work units for one (rule, event) evaluation. Every predicate costs 1, every
/// field lookup 1, and every value comparison 1 plus the byte length of the text compared
/// (for `fieldref`, both sides). The per-event cache decides what is computed; the budget
/// charges what each rule compares, so a rule pays the same whether a value was cached
/// by an earlier rule or not. Pattern-side costs such as glob backtracking depend on the
/// rule, not on the event, and are not charged.
#[derive(Debug, Clone, Copy)]
pub struct Work {
    left: u64,
}

impl Work {
    pub fn new(budget: u64) -> Self {
        Self { left: budget }
    }

    fn charge(&mut self, units: usize) -> Result<(), WorkExhausted> {
        let units = units as u64;
        if units > self.left {
            self.left = 0;
            return Err(WorkExhausted);
        }
        self.left -= units;
        Ok(())
    }
}

pub struct Evaluator {
    rules: Vec<CompiledRule>,
    /// Per rule, the distinct regex hit counters, collected once at construction.
    counters: Vec<Vec<LimitCounter>>,
    budget: u64,
    /// Per rule, events whose evaluation ran out of work budget.
    work_limit_hits: Vec<AtomicU64>,
}

impl Evaluator {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        Self::with_work_budget(rules, DEFAULT_WORK_BUDGET)
    }

    /// Like [`Evaluator::new`] with a custom per-(rule, event) work budget.
    pub fn with_work_budget(rules: Vec<CompiledRule>, budget: u64) -> Self {
        let counters = rules.iter().map(|r| r.expr.regex_counters()).collect();
        let work_limit_hits = rules.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            rules,
            counters,
            budget,
            work_limit_hits,
        }
    }

    pub fn rules(&self) -> &[CompiledRule] {
```

In `crates/zaaf-eval/src/lib.rs`, replace:

```rust
            .collect()
    }

    /// Indexes (into `rules()`) of every rule that matches `event`, in rule order.
    pub fn matching_rules(&self, event: &dyn Event) -> Vec<usize> {
        // One cache per event: leaf values, field lookups and lower-cased texts are
        // computed at most once however many rules and predicates read them.
        let ctx = EventCtx::new(event);
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| eval_with(&r.expr, &ctx))
            .map(|(i, _)| i)
            .collect()
    }
}

pub fn eval_expr(expr: &Expr, event: &dyn Event) -> bool {
    eval_with(expr, &EventCtx::new(event))
}

/// A scalar of the event plus its lazily computed lower-cased text.
```

with:

```rust
            .collect()
    }

    /// `(rule index, events)` for every rule that ran out of work budget on some events, in
    /// rule order. Such an evaluation counts as "no match"; this reports it so it is visible.
    pub fn work_limit_hits(&self) -> Vec<(usize, u64)> {
        self.work_limit_hits
            .iter()
            .enumerate()
            .map(|(i, n)| (i, n.load(Ordering::Relaxed)))
            .filter(|(_, n)| *n > 0)
            .collect()
    }

    /// Indexes (into `rules()`) of every rule that matches `event`, in rule order. Each
    /// rule gets a fresh work budget for the event.
    pub fn matching_rules(&self, event: &dyn Event) -> Vec<usize> {
        // One cache per event: leaf values, field lookups and lower-cased texts are
        // computed at most once however many rules and predicates read them.
        let ctx = EventCtx::new(event);
        let mut out = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            match eval_with(&r.expr, &ctx, &mut Work::new(self.budget)) {
                Ok(true) => out.push(i),
                Ok(false) => {}
                Err(WorkExhausted) => {
                    self.work_limit_hits[i].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        out
    }
}

/// Evaluates without a work limit (tests and tools that trust their input).
pub fn eval_expr(expr: &Expr, event: &dyn Event) -> bool {
    eval_bounded(expr, event, &mut Work::new(u64::MAX)).unwrap_or(false)
}

/// Evaluates `expr`, charging `work`; `Err` when the budget runs out.
pub fn eval_bounded(
    expr: &Expr,
    event: &dyn Event,
    work: &mut Work,
) -> Result<bool, WorkExhausted> {
    eval_with(expr, &EventCtx::new(event), work)
}

/// Byte length of a value's text (0 for null), without allocating for strings.
fn text_len(v: &FieldValue) -> usize {
    match v {
        FieldValue::Str(s) => s.len(),
        FieldValue::Null => 0,
        other => other.as_text().map_or(0, |t| t.len()),
    }
}

/// A scalar of the event plus its lazily computed lower-cased text.
```

In `crates/zaaf-eval/src/lib.rs`, replace:

```rust
    }
}

fn eval_with(expr: &Expr, ctx: &EventCtx) -> bool {
    match expr {
        Expr::And(items) => items.iter().all(|e| eval_with(e, ctx)),
        Expr::Or(items) => items.iter().any(|e| eval_with(e, ctx)),
        Expr::Not(inner) => !eval_with(inner, ctx),
        Expr::Pred(p) => eval_predicate(p, ctx),
    }
}

fn eval_predicate(p: &Predicate, ctx: &EventCtx) -> bool {
    match &p.target {
        Target::AnyField => ctx.leaves().iter().any(|v| value_matches(&p.matcher, v)),
        Target::Fields(fields) => match &p.matcher {
            Matcher::Exists(want) => fields.iter().any(|f| ctx.get(f).is_some()) == *want,
            // Mirrors `Exists(false)`: true only when EVERY mapped alternative is absent or
            // contains a JSON null (so `["a", null]` counts as null). A field that is
            // present with no null (even `[]` or `{}`) makes the predicate false.
            Matcher::Null => fields.iter().all(|f| match ctx.get(f) {
                None => true,
                Some(values) => values.iter().any(|v| matches!(v.value, FieldValue::Null)),
            }),
            Matcher::FieldRef {
                other,
                mode,
                case_sensitive,
            } => fields.iter().any(|f| {
                other
                    .iter()
                    .any(|o| fieldref(ctx, f, o, *mode, *case_sensitive))
            }),
            m => fields.iter().any(|f| {
                ctx.get(f)
                    .is_some_and(|values| values.iter().any(|v| value_matches(m, v)))
            }),
        },
    }
}

fn value_matches(m: &Matcher, c: &Cached) -> bool {
    let v = &c.value;
    match m {
        Matcher::Str {
            pattern,
            case_sensitive,
```

with:

```rust
    }
}

fn eval_with(expr: &Expr, ctx: &EventCtx, work: &mut Work) -> Result<bool, WorkExhausted> {
    match expr {
        Expr::And(items) => {
            for e in items {
                if !eval_with(e, ctx, work)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Expr::Or(items) => {
            for e in items {
                if eval_with(e, ctx, work)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Expr::Not(inner) => Ok(!eval_with(inner, ctx, work)?),
        Expr::Pred(p) => eval_predicate(p, ctx, work),
    }
}

/// `EventCtx::get`, charged one unit.
fn get<'e>(ctx: &EventCtx<'e>, field: &str, work: &mut Work) -> Result<Values<'e>, WorkExhausted> {
    work.charge(1)?;
    Ok(ctx.get(field))
}

fn eval_predicate(p: &Predicate, ctx: &EventCtx, work: &mut Work) -> Result<bool, WorkExhausted> {
    work.charge(1)?;
    match &p.target {
        Target::AnyField => {
            for v in ctx.leaves() {
                if value_matches(&p.matcher, v, work)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Target::Fields(fields) => match &p.matcher {
            Matcher::Exists(want) => {
                let mut any = false;
                for f in fields {
                    if get(ctx, f, work)?.is_some() {
                        any = true;
                        break;
                    }
                }
                Ok(any == *want)
            }
            // Mirrors `Exists(false)`: true only when EVERY mapped alternative is absent or
            // contains a JSON null (so `["a", null]` counts as null). A field that is
            // present with no null (even `[]` or `{}`) makes the predicate false.
            Matcher::Null => {
                for f in fields {
                    if let Some(values) = get(ctx, f, work)? {
                        work.charge(values.len())?;
                        if !values.iter().any(|v| matches!(v.value, FieldValue::Null)) {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            }
            Matcher::FieldRef {
                other,
                mode,
                case_sensitive,
            } => {
                for f in fields {
                    for o in other {
                        if fieldref(ctx, f, o, *mode, *case_sensitive, work)? {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            m => {
                for f in fields {
                    if let Some(values) = get(ctx, f, work)? {
                        for v in values.iter() {
                            if value_matches(m, v, work)? {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
        },
    }
}

fn value_matches(m: &Matcher, c: &Cached, work: &mut Work) -> Result<bool, WorkExhausted> {
    let v = &c.value;
    work.charge(1 + text_len(v))?;
    Ok(match m {
        Matcher::Str {
            pattern,
            case_sensitive,
```

In `crates/zaaf-eval/src/lib.rs`, replace:

```rust
        Matcher::TimePart { part, op, value } => timestamp_of(v)
            .is_some_and(|ts| compare(*op, time_part(ts, *part) as f64, *value as f64)),
        Matcher::Exists(_) | Matcher::Null | Matcher::FieldRef { .. } => false,
    }
}

/// Trims, drops an IPv6 `%zone` suffix (only when the text contains `:`) and parses. Leading-zero dotted quads stay rejected.
```

with:

```rust
        Matcher::TimePart { part, op, value } => timestamp_of(v)
            .is_some_and(|ts| compare(*op, time_part(ts, *part) as f64, *value as f64)),
        Matcher::Exists(_) | Matcher::Null | Matcher::FieldRef { .. } => false,
    })
}

/// Trims, drops an IPv6 `%zone` suffix (only when the text contains `:`) and parses. Leading-zero dotted quads stay rejected.
```

In `crates/zaaf-eval/src/lib.rs`, replace:

```rust
    }
}

fn fieldref(ctx: &EventCtx, field: &str, other: &str, mode: RefMode, case_sensitive: bool) -> bool {
    let (Some(left), Some(right)) = (ctx.get(field), ctx.get(other)) else {
        return false;
    };
    fn norm<'a>(c: &'a Cached<'_>, case_sensitive: bool) -> Option<Cow<'a, str>> {
        if case_sensitive {
```

with:

```rust
    }
}

fn fieldref(
    ctx: &EventCtx,
    field: &str,
    other: &str,
    mode: RefMode,
    case_sensitive: bool,
    work: &mut Work,
) -> Result<bool, WorkExhausted> {
    let (Some(left), Some(right)) = (get(ctx, field, work)?, get(ctx, other, work)?) else {
        return Ok(false);
    };
    fn norm<'a>(c: &'a Cached<'_>, case_sensitive: bool) -> Option<Cow<'a, str>> {
        if case_sensitive {
```

In `crates/zaaf-eval/src/lib.rs`, replace:

```rust
            c.lower().map(Cow::Borrowed)
        }
    }
    let rights: Vec<_> = right
        .iter()
        .filter_map(|c| norm(c, case_sensitive))
        .collect();
    left.iter()
        .filter_map(|c| norm(c, case_sensitive))
        .any(|l| {
            rights.iter().any(|r| match mode {
                RefMode::Equals => l == *r,
                RefMode::Contains => l.contains(r.as_ref()),
                RefMode::StartsWith => l.starts_with(r.as_ref()),
                RefMode::EndsWith => l.ends_with(r.as_ref()),
            })
        })
}

#[cfg(test)]
```

with:

```rust
            c.lower().map(Cow::Borrowed)
        }
    }
    let mut rights = Vec::new();
    for c in right.iter() {
        if let Some(r) = norm(c, case_sensitive) {
            work.charge(1 + r.len())?;
            rights.push(r);
        }
    }
    for c in left.iter() {
        let Some(l) = norm(c, case_sensitive) else {
            continue;
        };
        work.charge(1 + l.len())?;
        for r in &rights {
            work.charge(1 + l.len() + r.len())?;
            let hit = match mode {
                RefMode::Equals => l == *r,
                RefMode::Contains => l.contains(r.as_ref()),
                RefMode::StartsWith => l.starts_with(r.as_ref()),
                RefMode::EndsWith => l.ends_with(r.as_ref()),
            };
            if hit {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
    let rule_count = rules.len();
    let evaluator = Evaluator::new(rules);
    let code = scan(&args, &evaluator, from, to, rule_count);
    warn_regex_limits(&evaluator);
    code
}

fn warn_regex_limits(evaluator: &Evaluator) {
    for (idx, hits) in evaluator.regex_limit_hits() {
        let info = &evaluator.rules()[idx].info;
        eprintln!(
            "warning: rule `{}` ({}): {hits} regex evaluation(s) hit the backtracking limit and were treated as no match",
            sanitize(&info.title),
            sanitize(&info.id)
        );
```

with:

```rust
    let rule_count = rules.len();
    let evaluator = Evaluator::new(rules);
    let code = scan(&args, &evaluator, from, to, rule_count);
    warn_limits(&evaluator);
    code
}

fn warn_limits(evaluator: &Evaluator) {
    for (idx, hits) in evaluator.regex_limit_hits() {
        let info = &evaluator.rules()[idx].info;
        eprintln!(
            "warning: rule `{}` ({}): {hits} regex evaluation(s) hit the backtracking limit and were treated as no match",
            sanitize(&info.title),
            sanitize(&info.id)
        );
    }
    for (idx, events) in evaluator.work_limit_hits() {
        let info = &evaluator.rules()[idx].info;
        eprintln!(
            "warning: rule `{}` ({}): {events} event(s) exceeded the per-event work budget and were treated as no match",
            sanitize(&info.title),
            sanitize(&info.id)
        );
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-eval && cargo test -p zaaf-cli --test hunt`
Expected: PASS (zaaf-eval: 16 tests; hunt: 22 tests, including `work_budget_hits_are_reported_without_changing_exit_code`). Workspace total after this task: 245.

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add crates/zaaf-cli/src/hunt.rs crates/zaaf-cli/tests/hunt.rs crates/zaaf-eval/src/lib.rs
git commit -m "feat(eval): per-event evaluation work budget, reported like regex limit hits" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 2: zaaf-sigma: parse correlation documents

Replaces `CorrelationStub` with a fully parsed `Correlation` and positioned shape diagnostics (decisions M2-D4, M2-D6, M2-D17, M2-D21). Cross-document checks (do referenced rules exist) are Task 3. `zaaf-ir` still skips correlations with the M1 warning after this task; only the stub's field access changes. The metadata block of `parse_rule` moves into `parse_meta`, shared with correlations.

Step 1 writes the test module of the new `correlation.rs`, declares and re-exports the module in `lib.rs`, and updates the M1 tests that used incomplete correlation documents (an incomplete correlation is now a parse error).

**Files:**
- Create: `crates/zaaf-sigma/src/correlation.rs`
- Modify: `crates/zaaf-sigma/src/document.rs`
- Modify: `crates/zaaf-sigma/src/lib.rs`
- Modify: `crates/zaaf-ir/src/rule.rs`
- Modify: `crates/zaaf-cli/tests/check.rs`

**Interfaces:**
- Consumes: `zaaf_sigma::document` items made `pub(crate)` here: `Node`, `Map`, `Diags`, `line_col`, `err`, `warn`, `entry`, `get`, `merge_key_error`, `parse_title`; new `pub(crate) fn parse_meta(map: &Map, warns: &mut Diags) -> RuleMeta` (now also used by `parse_rule`); `parse_document`'s existing `warns` out-parameter.
- Produces (re-exported from `zaaf_sigma`):
  - `enum CorrelationType { EventCount, ValueCount, Temporal, TemporalOrdered, ValueSum, ValueAvg, ValueMedian, ValuePercentile }` with `parse(&str) -> Option<Self>`, `as_str(self) -> &'static str`, `needs_field(self) -> bool`, `is_temporal(self) -> bool`.
  - `enum CondOp { Gt, Gte, Lt, Lte, Eq, Neq }` with `parse`, `as_str`, `holds(self, value: f64, bound: f64) -> bool`.
  - `struct Spanned { value: String, line: usize, col: usize }`.
  - `struct CorrelationCondition { bounds: Vec<(CondOp, f64)>, fields: Vec<String>, line: usize, col: usize }`.
  - `struct Alias { name: Spanned, fields: Vec<(Spanned, String)> }`.
  - `struct Correlation { meta: RuleMeta, kind: CorrelationType, rules: Vec<Spanned>, group_by: Vec<Spanned>, timespan: String, timespan_ms: i64, aliases: Vec<Alias>, condition: Option<CorrelationCondition>, generate: bool, line: usize, col: usize }`.
  - `pub fn parse_timespan(s: &str) -> Option<i64>` (milliseconds) and `pub const MAX_TIMESPAN_MS: i64`.
  - `pub(crate) fn parse_correlation(doc: &Node, map: &Map, warns: &mut Diags) -> Result<Correlation, Diags>`.
  - `Document::Correlation(Correlation)`; `CorrelationStub` is removed. Correlation warnings reach `ParsedFile::diagnostics` through `warns`, like rule warnings.

- [ ] **Step 1: Write the failing tests**

Create `crates/zaaf-sigma/src/correlation.rs` containing only this test module for now (Step 3 puts the implementation above it):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{Document, parse_str};

    fn corr(src: &str) -> Correlation {
        let p = parse_str(src);
        assert!(
            p.diagnostics.iter().all(|d| !d.is_error()),
            "{:?}",
            p.diagnostics
        );
        match p.documents.into_iter().next() {
            Some(Document::Correlation(c)) => c,
            other => panic!("expected a correlation, got {other:?}"),
        }
    }

    fn errors(src: &str) -> Vec<String> {
        let p = parse_str(src);
        assert!(p.documents.is_empty(), "{:?}", p.documents);
        p.diagnostics
            .iter()
            .filter(|d| d.is_error())
            .map(|d| d.to_string())
            .collect()
    }

    const BRUTE: &str = "title: Many failed logins
id: c1
name: brute
level: high
author: Ann
references: [https://x]
correlation:
    type: event_count
    rules:
        - failed_login
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    group-by:
        - ComputerName
    timespan: 1h
    condition:
        gte: 100
";

    #[test]
    fn parses_the_spec_event_count_example() {
        let c = corr(BRUTE);
        assert_eq!(c.meta.title, "Many failed logins");
        assert_eq!(c.meta.id.as_deref(), Some("c1"));
        assert_eq!(c.meta.name.as_deref(), Some("brute"));
        assert_eq!(c.meta.level.as_deref(), Some("high"));
        assert_eq!(c.meta.author.as_deref(), Some("Ann"));
        assert_eq!(c.kind, CorrelationType::EventCount);
        let refs: Vec<&str> = c.rules.iter().map(|r| r.value.as_str()).collect();
        assert_eq!(
            refs,
            vec!["failed_login", "5638f7c0-ac70-491d-8465-2a65075e0d86"]
        );
        assert_eq!((c.rules[0].line, c.rules[0].col), (10, 11));
        assert_eq!(c.group_by[0].value, "ComputerName");
        assert_eq!(c.timespan, "1h");
        assert_eq!(c.timespan_ms, 3_600_000);
        let cond = c.condition.unwrap();
        assert_eq!(cond.bounds, vec![(CondOp::Gte, 100.0)]);
        assert!(cond.fields.is_empty());
        assert!(!c.generate);
        assert_eq!((c.line, c.col), (1, 1));
    }

    #[test]
    fn parses_value_types_ranges_aliases_and_generate() {
        let c = corr(
            "title: v\ncorrelation:\n    type: value_count\n    rules: [a, b]\n    group-by: [ip]\n    timespan: 90m\n    generate: true\n    aliases:\n        ip:\n            a: source.ip\n            b: destination.ip\n    condition:\n        field: [User, Domain]\n        gt: 100\n        lte: 200\n",
        );
        assert_eq!(c.kind, CorrelationType::ValueCount);
        assert_eq!(c.timespan_ms, 90 * 60_000);
        assert!(c.generate);
        let cond = c.condition.unwrap();
        assert_eq!(cond.fields, vec!["User", "Domain"]);
        assert_eq!(cond.bounds, vec![(CondOp::Gt, 100.0), (CondOp::Lte, 200.0)]);
        assert_eq!(c.aliases.len(), 1);
        assert_eq!(c.aliases[0].name.value, "ip");
        assert_eq!(c.aliases[0].fields[1].0.value, "b");
        assert_eq!(c.aliases[0].fields[1].1, "destination.ip");
        let avg = corr(
            "title: v\ncorrelation:\n    type: value_avg\n    rules: [a]\n    group-by: [ip]\n    timespan: 1d\n    condition:\n        field: bytes\n        gt: 2.5\n",
        );
        assert_eq!(avg.condition.unwrap().bounds, vec![(CondOp::Gt, 2.5)]);
    }

    #[test]
    fn temporal_condition_is_optional() {
        let c = corr(
            "title: t\ncorrelation:\n    type: temporal_ordered\n    rules: [a, b]\n    group-by: [User]\n    timespan: 10s\n",
        );
        assert_eq!(c.kind, CorrelationType::TemporalOrdered);
        assert!(c.condition.is_none());
    }

    #[test]
    fn missing_group_by_is_a_warning_and_value_median_warns() {
        let p = parse_str(
            "title: m\ncorrelation:\n    type: value_median\n    rules: [a]\n    timespan: 1h\n    condition:\n        field: n\n        gt: 1\n",
        );
        assert_eq!(p.documents.len(), 1);
        let msgs: Vec<String> = p.diagnostics.iter().map(|d| d.to_string()).collect();
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert!(msgs.iter().all(|m| m.starts_with("warning:")), "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("value_median")), "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("one group")), "{msgs:?}");
    }

    #[test]
    fn unused_alias_warns() {
        let p = parse_str(
            "title: u\ncorrelation:\n    type: temporal\n    rules: [a]\n    group-by: [x]\n    timespan: 1h\n    aliases:\n        y:\n            a: f\n",
        );
        assert_eq!(p.documents.len(), 1);
        assert_eq!(
            p.diagnostics[0].location,
            Location::at(8, 9, "correlation.aliases.y")
        );
        assert!(p.diagnostics[0].message.contains("not used in `group-by`"));
    }

    #[test]
    fn timespan_formats() {
        assert_eq!(parse_timespan("30s"), Some(30_000));
        assert_eq!(parse_timespan("5m"), Some(300_000));
        assert_eq!(parse_timespan("2h"), Some(7_200_000));
        assert_eq!(parse_timespan("1d"), Some(86_400_000));
        assert_eq!(parse_timespan("3650d"), Some(MAX_TIMESPAN_MS));
        for bad in [
            "",
            "m",
            "0s",
            "5",
            "5M",
            "1w",
            "-5m",
            "+5m",
            "1.5h",
            "3651d",
            "99999999999999999999d",
        ] {
            assert_eq!(parse_timespan(bad), None, "{bad}");
        }
    }

    #[test]
    fn shape_errors_have_positions() {
        let e = errors(
            "title: x\ncorrelation:\n    type: event_count\n    rules: [a, a]\n    group-by: [g]\n    timespan: 1w\n    condition:\n        gte: many\n",
        );
        assert!(
            e.iter()
                .any(|m| m.contains(":4:16: correlation.rules[1]: duplicate entry `a`")),
            "{e:?}"
        );
        assert!(
            e.iter().any(|m| m.contains(":6:15: correlation.timespan:")),
            "{e:?}"
        );
        assert!(
            e.iter()
                .any(|m| m.contains(":8:14: correlation.condition.gte: must be a number")),
            "{e:?}"
        );
    }

    #[test]
    fn missing_parts_are_errors() {
        let e = errors("correlation:\n    type: event_count\n    rules: []\n    group_by: [g]\n");
        let all = e.join("\n");
        assert!(all.contains("missing mandatory `title`"), "{all}");
        assert!(all.contains("unknown correlation key `group_by`"), "{all}");
        assert!(all.contains("must list at least one rule"), "{all}");
        assert!(all.contains("missing mandatory `timespan`"), "{all}");
        assert!(all.contains("`event_count` needs a `condition`"), "{all}");
        let e =
            errors("title: x\ncorrelation:\n    rules: [a]\n    group-by: [g]\n    timespan: 1h\n");
        assert!(e.join("\n").contains("missing mandatory `type`"), "{e:?}");
        let e = errors(
            "title: x\ncorrelation:\n    type: value_sum\n    rules: [a]\n    group-by: [g]\n    timespan: 1h\n    condition:\n        gt: 5\n",
        );
        assert!(e.join("\n").contains("`value_sum` needs `field`"), "{e:?}");
        let e = errors(
            "title: x\ncorrelation:\n    type: event_count\n    rules: [a]\n    group-by: [g]\n    timespan: 1h\n    condition:\n        field: f\n        gt: 5\n",
        );
        assert!(
            e.join("\n")
                .contains("`field` is not used by `event_count`"),
            "{e:?}"
        );
        let e = errors(
            "title: x\ncorrelation:\n    type: value_sum\n    rules: [a]\n    group-by: [g]\n    timespan: 1h\n    condition:\n        field: [a, b]\n        gt: 5\n",
        );
        assert!(
            e.join("\n")
                .contains("only `value_count` accepts several fields"),
            "{e:?}"
        );
        let e = errors(
            "title: x\ncorrelation:\n    type: temporal\n    rules: [a]\n    group-by: [g]\n    timespan: 1h\n    condition:\n        between: 5\n",
        );
        assert!(
            e.join("\n")
                .contains("unknown condition operator `between`"),
            "{e:?}"
        );
        let e = errors(
            "title: x\ncorrelation:\n    type: temporal\n    rules: [a]\n    group-by: [g]\n    timespan: 1h\n    generate: yes please\n",
        );
        assert!(e.join("\n").contains("must be true or false"), "{e:?}");
        let e =
            errors("title: x\ncorrelation:\n    type: nearby\n    rules: [a]\n    timespan: 1h\n");
        assert!(e.join("\n").contains("unknown correlation type"), "{e:?}");
        let e = errors("title: x\ncorrelation: [a]\n");
        assert!(
            e.join("\n").contains("`correlation` must be a mapping"),
            "{e:?}"
        );
        let e = errors(
            "title: x\ncorrelation:\n    type: temporal\n    rules: [a]\n    group-by: [g]\n    timespan: 1h\n    aliases:\n        g: [x]\n",
        );
        assert!(
            e.join("\n").contains("must map rule names to field names"),
            "{e:?}"
        );
    }

    #[test]
    fn metadata_type_warnings_and_merge_keys() {
        let p = parse_str(
            "title: t\nauthor: [a]\ncorrelation:\n    type: temporal\n    rules: [a]\n    group-by: [g]\n    timespan: 1m\n",
        );
        assert_eq!(p.documents.len(), 1);
        assert_eq!(p.diagnostics.len(), 1, "{:?}", p.diagnostics);
        assert!(
            p.diagnostics[0]
                .message
                .contains("`author` must be a string")
        );
        let e = errors(
            "title: [x]\ncorrelation:\n    type: temporal\n    rules: [a]\n    group-by: [g]\n    timespan: 1m\n",
        );
        assert!(e.join("\n").contains("`title` must be a string"), "{e:?}");
        let e = errors(
            "base: &b\n    type: temporal\ntitle: x\ncorrelation:\n    <<: *b\n    rules: [a]\n    timespan: 1m\n",
        );
        assert!(e.join("\n").contains("YAML merge keys"), "{e:?}");
    }

    #[test]
    fn cond_ops_compare() {
        assert!(CondOp::Gt.holds(2.0, 1.0) && !CondOp::Gt.holds(1.0, 1.0));
        assert!(CondOp::Gte.holds(1.0, 1.0));
        assert!(CondOp::Lt.holds(0.0, 1.0) && !CondOp::Lt.holds(1.0, 1.0));
        assert!(CondOp::Lte.holds(1.0, 1.0));
        assert!(CondOp::Eq.holds(3.0, 3.0) && !CondOp::Eq.holds(3.0, 4.0));
        assert!(CondOp::Neq.holds(3.0, 4.0) && !CondOp::Neq.holds(3.0, 3.0));
    }
}
```

In `crates/zaaf-sigma/src/document.rs`, replace:

```rust
    }

    #[test]
    fn multi_document_with_correlation_stub() {
        let src = format!(
            "{}---\ntitle: many\nid: c1\ncorrelation:\n    type: event_count\n    rules: [r1]\n    timespan: 1h\n",
            rule_with("    sel:\n        A: 1\n    condition: sel\n")
        );
        let parsed = parse_str(&src);
```

with:

```rust
    }

    #[test]
    fn multi_document_with_correlation() {
        let src = format!(
            "{}---\ntitle: many\nid: c1\ncorrelation:\n    type: event_count\n    rules: [r1]\n    group-by: [A]\n    timespan: 1h\n    condition:\n        gte: 2\n",
            rule_with("    sel:\n        A: 1\n    condition: sel\n")
        );
        let parsed = parse_str(&src);
```

In `crates/zaaf-sigma/src/lib.rs`, replace:

```rust
//! Sigma rule parser for ZAAFElegia.

pub mod condition;
pub mod diagnostic;
pub mod document;
pub mod modifier;
```

with:

```rust
//! Sigma rule parser for ZAAFElegia.

pub mod condition;
pub mod correlation;
pub mod diagnostic;
pub mod document;
pub mod modifier;
```

In `crates/zaaf-sigma/src/lib.rs`, replace:

```rust
pub mod value;

pub use condition::{CondExpr, Quantifier, SelTarget, parse_condition};
pub use diagnostic::{Diagnostic, Location, Severity};
pub use document::{
    CorrelationStub, Detection, Document, FieldItem, Filter, LogSource, ParsedFile, Rule, RuleMeta,
    SearchIdentifier, parse_file, parse_str,
};
pub use modifier::{FieldKey, Modifier, parse_field_key};
```

with:

```rust
pub mod value;

pub use condition::{CondExpr, Quantifier, SelTarget, parse_condition};
pub use correlation::{
    Alias, CondOp, Correlation, CorrelationCondition, CorrelationType, MAX_TIMESPAN_MS, Spanned,
    parse_timespan,
};
pub use diagnostic::{Diagnostic, Location, Severity};
pub use document::{
    Detection, Document, FieldItem, Filter, LogSource, ParsedFile, Rule, RuleMeta,
    SearchIdentifier, parse_file, parse_str,
};
pub use modifier::{FieldKey, Modifier, parse_field_key};
```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
    #[test]
    fn duplicate_ids_correlations_and_levels() {
        let src = format!(
            "{}---\ntitle: second\nid: r1\nlogsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s\n---\ntitle: corr\ncorrelation:\n    type: event_count\n",
            rule_with("    s:\n        A: 1\n    condition: s\n")
        );
        let out = compile_src(&src, &PipelineSet::default());
```

with:

```rust
    #[test]
    fn duplicate_ids_correlations_and_levels() {
        let src = format!(
            "{}---\ntitle: second\nid: r1\nlogsource:\n    product: x\ndetection:\n    s:\n        A: 1\n    condition: s\n---\ntitle: corr\ncorrelation:\n    type: event_count\n    rules: [r1]\n    group-by: [A]\n    timespan: 1h\n    condition:\n        gte: 2\n",
            rule_with("    s:\n        A: 1\n    condition: s\n")
        );
        let out = compile_src(&src, &PipelineSet::default());
```

In `crates/zaaf-cli/tests/check.rs`, replace:

```rust
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("r.yml"),
        format!("{GOOD}---\ntitle: corr\ncorrelation:\n    type: event_count\n"),
    )
    .unwrap();
    let out = zaaf()
```

with:

```rust
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("r.yml"),
        format!(
            "{GOOD}---\ntitle: corr\ncorrelation:\n    type: event_count\n    rules: [r-whoami]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        gte: 2\n"
        ),
    )
    .unwrap();
    let out = zaaf()
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-sigma`
Expected: FAIL to compile: `unresolved imports correlation::Alias, correlation::CondOp, ...` (the module holds only tests so far).

- [ ] **Step 3: Implement**

At the top of `crates/zaaf-sigma/src/correlation.rs`, above `#[cfg(test)]`, add the implementation:

```rust
//! Sigma correlation rules (Sigma correlation specification 2.1.0).
//!
//! The parser checks the shape of one correlation document. Checks that need other
//! documents (do referenced rules exist, are alias rule names referenced) happen in
//! `zaaf-ir`.

use crate::diagnostic::{Diagnostic, Location};
use crate::document::{
    Diags, Map, Node, RuleMeta, entry, err, get, line_col, merge_key_error, parse_meta,
    parse_title, warn,
};
use saphyr::{Scalar, YamlData};

/// The correlation types of Sigma 2.1.0, plus `value_median` (see [`CorrelationType::ValueMedian`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorrelationType {
    EventCount,
    ValueCount,
    Temporal,
    TemporalOrdered,
    ValueSum,
    ValueAvg,
    /// Not in the Sigma 2.1.0 schema; accepted (with a warning) as the median of `field`.
    ValueMedian,
    ValuePercentile,
}

impl CorrelationType {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "event_count" => Self::EventCount,
            "value_count" => Self::ValueCount,
            "temporal" => Self::Temporal,
            "temporal_ordered" => Self::TemporalOrdered,
            "value_sum" => Self::ValueSum,
            "value_avg" => Self::ValueAvg,
            "value_median" => Self::ValueMedian,
            "value_percentile" => Self::ValuePercentile,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EventCount => "event_count",
            Self::ValueCount => "value_count",
            Self::Temporal => "temporal",
            Self::TemporalOrdered => "temporal_ordered",
            Self::ValueSum => "value_sum",
            Self::ValueAvg => "value_avg",
            Self::ValueMedian => "value_median",
            Self::ValuePercentile => "value_percentile",
        }
    }

    /// Types whose `condition` names a `field`.
    pub fn needs_field(self) -> bool {
        matches!(
            self,
            Self::ValueCount
                | Self::ValueSum
                | Self::ValueAvg
                | Self::ValueMedian
                | Self::ValuePercentile
        )
    }

    /// `temporal` and `temporal_ordered`, whose `condition` is optional.
    pub fn is_temporal(self) -> bool {
        matches!(self, Self::Temporal | Self::TemporalOrdered)
    }
}

/// A comparison in a correlation `condition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Neq,
}

impl CondOp {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Eq => "eq",
            Self::Neq => "neq",
        }
    }

    /// `value <op> bound`.
    pub fn holds(self, value: f64, bound: f64) -> bool {
        match self {
            Self::Gt => value > bound,
            Self::Gte => value >= bound,
            Self::Lt => value < bound,
            Self::Lte => value <= bound,
            Self::Eq => value == bound,
            Self::Neq => value != bound,
        }
    }
}

/// A string from the rule with its 1-based position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned {
    pub value: String,
    pub line: usize,
    pub col: usize,
}

/// `condition:` of a correlation. Several bounds are AND'd.
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationCondition {
    pub bounds: Vec<(CondOp, f64)>,
    /// `field` (one name, or several for `value_count`); empty when not given.
    pub fields: Vec<String>,
    pub line: usize,
    pub col: usize,
}

/// One entry of `aliases:`: the alias name and, per referenced rule, the event field.
#[derive(Debug, Clone, PartialEq)]
pub struct Alias {
    pub name: Spanned,
    /// `(rule reference, field name)`; the reference is a rule `name` (or id).
    pub fields: Vec<(Spanned, String)>,
}

/// Longest accepted `timespan`: 3650 days.
pub const MAX_TIMESPAN_MS: i64 = 3650 * 86_400_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Correlation {
    pub meta: RuleMeta,
    pub kind: CorrelationType,
    /// Referenced rules or correlations, by `id` or `name`, in the order given.
    pub rules: Vec<Spanned>,
    /// Field names or alias names. Empty when `group-by` is absent (one global group).
    pub group_by: Vec<Spanned>,
    /// `timespan` as written (`5m`) and in milliseconds.
    pub timespan: String,
    pub timespan_ms: i64,
    pub aliases: Vec<Alias>,
    pub condition: Option<CorrelationCondition>,
    /// `generate: true` keeps the referenced rules' own alerts.
    pub generate: bool,
    /// 1-based position where the document starts (its first key).
    pub line: usize,
    pub col: usize,
}

const KEYS: &[&str] = &[
    "type",
    "rules",
    "aliases",
    "group-by",
    "timespan",
    "condition",
    "generate",
];

/// Parses `^[0-9]+[smhd]$` into milliseconds (at least 1 unit, at most [`MAX_TIMESPAN_MS`]).
pub fn parse_timespan(s: &str) -> Option<i64> {
    let unit = match s.chars().last()? {
        's' => 1_000i64,
        'm' => 60_000,
        'h' => 3_600_000,
        'd' => 86_400_000,
        _ => return None,
    };
    let digits = &s[..s.len() - 1];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    let ms = n.checked_mul(unit)?;
    (ms > 0 && ms <= MAX_TIMESPAN_MS).then_some(ms)
}

fn spanned(node: &Node, value: &str) -> Spanned {
    let (line, col) = line_col(node);
    Spanned {
        value: value.to_string(),
        line,
        col,
    }
}

/// A list of strings (a single string is accepted as a one-element list).
fn string_list(node: &Node, path: &str, diags: &mut Diags) -> Vec<Spanned> {
    let items: Vec<&Node> = match &node.data {
        YamlData::Sequence(seq) => seq.iter().collect(),
        YamlData::Value(Scalar::String(_)) => vec![node],
        _ => {
            diags.push(err(node, path, "must be a list of strings"));
            return Vec::new();
        }
    };
    let mut out: Vec<Spanned> = Vec::new();
    for (i, item) in items.into_iter().enumerate() {
        let item_path = format!("{path}[{i}]");
        match item.data.as_str() {
            Some("") => diags.push(err(item, &item_path, "must not be empty")),
            Some(s) if out.iter().any(|o| o.value == s) => {
                diags.push(err(item, &item_path, format!("duplicate entry `{s}`")))
            }
            Some(s) => out.push(spanned(item, s)),
            None => diags.push(err(item, &item_path, "must be a string")),
        }
    }
    out
}

fn number(node: &Node) -> Option<f64> {
    match &node.data {
        YamlData::Value(Scalar::Integer(i)) => Some(*i as f64),
        YamlData::Value(Scalar::FloatingPoint(f)) if f.into_inner().is_finite() => {
            Some(f.into_inner())
        }
        _ => None,
    }
}

fn parse_condition(
    kind: CorrelationType,
    node: &Node,
    diags: &mut Diags,
) -> Option<CorrelationCondition> {
    let YamlData::Mapping(m) = &node.data else {
        diags.push(err(
            node,
            "correlation.condition",
            "must be a mapping such as `gte: 10`",
        ));
        return None;
    };
    let before = diags.len();
    let mut bounds = Vec::new();
    let mut fields = Vec::new();
    for (k, v) in m {
        let Some(key) = k.data.as_str() else {
            diags.push(err(k, "correlation.condition", "keys must be strings"));
            continue;
        };
        let path = format!("correlation.condition.{key}");
        if key == "field" {
            if !kind.needs_field() {
                diags.push(err(
                    k,
                    &path,
                    format!("`field` is not used by `{}` correlations", kind.as_str()),
                ));
                continue;
            }
            let list = string_list(v, &path, diags);
            if list.is_empty() {
                diags.push(err(v, &path, "must name a field"));
            } else if list.len() > 1 && kind != CorrelationType::ValueCount {
                diags.push(err(v, &path, "only `value_count` accepts several fields"));
            }
            fields = list.into_iter().map(|s| s.value).collect();
            continue;
        }
        let Some(op) = CondOp::parse(key) else {
            diags.push(err(
                k,
                &path,
                format!("unknown condition operator `{key}` (expected gt, gte, lt, lte, eq, neq or field)"),
            ));
            continue;
        };
        match number(v) {
            Some(n) => bounds.push((op, n)),
            None => diags.push(err(v, &path, "must be a number")),
        }
    }
    if diags.len() == before && bounds.is_empty() {
        diags.push(err(
            node,
            "correlation.condition",
            "needs at least one of gt, gte, lt, lte, eq, neq",
        ));
    }
    if diags.len() == before && kind.needs_field() && fields.is_empty() {
        diags.push(err(
            node,
            "correlation.condition",
            format!("`{}` needs `field` in the condition", kind.as_str()),
        ));
    }
    let (line, col) = line_col(node);
    (diags.len() == before).then_some(CorrelationCondition {
        bounds,
        fields,
        line,
        col,
    })
}

fn parse_aliases(node: &Node, diags: &mut Diags) -> Vec<Alias> {
    let YamlData::Mapping(m) = &node.data else {
        diags.push(err(
            node,
            "correlation.aliases",
            "must map alias names to `rule name: field` mappings",
        ));
        return Vec::new();
    };
    let mut out = Vec::new();
    for (k, v) in m {
        let Some(name) = k.data.as_str() else {
            diags.push(err(k, "correlation.aliases", "alias names must be strings"));
            continue;
        };
        let path = format!("correlation.aliases.{name}");
        let YamlData::Mapping(entries) = &v.data else {
            diags.push(err(v, &path, "must map rule names to field names"));
            continue;
        };
        let mut fields = Vec::new();
        for (rk, fv) in entries {
            match (rk.data.as_str(), fv.data.as_str()) {
                (Some(rule), Some(field)) if !field.is_empty() => {
                    fields.push((spanned(rk, rule), field.to_string()))
                }
                _ => diags.push(err(
                    rk,
                    &path,
                    "each entry must be `rule name: field name` (strings)",
                )),
            }
        }
        if fields.is_empty() {
            diags.push(err(v, &path, "alias maps no rule to a field"));
        }
        out.push(Alias {
            name: spanned(k, name),
            fields,
        });
    }
    out
}

/// Parses one correlation document. Warnings (also those of a rejected document) go to
/// `warns`; errors are returned.
pub(crate) fn parse_correlation(
    doc: &Node,
    map: &Map,
    warns: &mut Diags,
) -> Result<Correlation, Diags> {
    let mut diags: Diags = Vec::new();
    let title = parse_title(doc, map, &mut diags);
    let mut meta = parse_meta(map, warns);
    let Some((ckey, cnode)) = entry(map, "correlation") else {
        return Err(diags);
    };
    let YamlData::Mapping(cm) = &cnode.data else {
        diags.push(err(cnode, "correlation", "`correlation` must be a mapping"));
        return Err(diags);
    };
    if let Some(d) = merge_key_error(cm, "correlation") {
        diags.push(d);
        return Err(diags);
    }
    for (k, _) in cm {
        match k.data.as_str() {
            Some(key) if KEYS.contains(&key) => {}
            Some(key) => diags.push(err(
                k,
                &format!("correlation.{key}"),
                format!("unknown correlation key `{key}`"),
            )),
            None => diags.push(err(k, "correlation", "keys must be strings")),
        }
    }

    let kind = match get(cm, "type") {
        None => {
            diags.push(err(ckey, "correlation.type", "missing mandatory `type`"));
            None
        }
        Some(t) => match t.data.as_str().and_then(CorrelationType::parse) {
            Some(k) => Some(k),
            None => {
                diags.push(err(
                    t,
                    "correlation.type",
                    "unknown correlation type (expected event_count, value_count, temporal, temporal_ordered, value_sum, value_avg or value_percentile)",
                ));
                None
            }
        },
    };
    if kind == Some(CorrelationType::ValueMedian)
        && let Some(t) = get(cm, "type")
    {
        diags.push(warn(
            t,
            "correlation.type",
            "`value_median` is not part of Sigma 2.1.0; it is evaluated as the median of `field`",
        ));
    }

    let rules = match get(cm, "rules") {
        None => {
            diags.push(err(ckey, "correlation.rules", "missing mandatory `rules`"));
            Vec::new()
        }
        Some(r) => {
            let list = string_list(r, "correlation.rules", &mut diags);
            if list.is_empty() && matches!(r.data, YamlData::Sequence(_)) {
                diags.push(err(r, "correlation.rules", "must list at least one rule"));
            }
            list
        }
    };

    let group_by = match get(cm, "group-by") {
        None => {
            diags.push(warn(
                ckey,
                "correlation.group-by",
                "no `group-by`: all matching events form one group",
            ));
            Vec::new()
        }
        Some(g) => string_list(g, "correlation.group-by", &mut diags),
    };

    let mut timespan = String::new();
    let mut timespan_ms = 0;
    match get(cm, "timespan") {
        None => diags.push(err(ckey, "correlation.timespan", "missing mandatory `timespan`")),
        Some(t) => match t.data.as_str().and_then(|s| parse_timespan(s).map(|ms| (s, ms))) {
            Some((s, ms)) => {
                timespan = s.to_string();
                timespan_ms = ms;
            }
            None => diags.push(err(
                t,
                "correlation.timespan",
                "must be a positive number followed by s, m, h or d (for example `5m`), at most 3650d",
            )),
        },
    }

    let aliases = get(cm, "aliases").map_or_else(Vec::new, |a| parse_aliases(a, &mut diags));
    for a in &aliases {
        if !group_by.iter().any(|g| g.value == a.name.value) {
            diags.push(Diagnostic::warning(
                Location::at(
                    a.name.line,
                    a.name.col,
                    format!("correlation.aliases.{}", a.name.value),
                ),
                format!("alias `{}` is not used in `group-by`", a.name.value),
            ));
        }
    }

    let condition = match (kind, get(cm, "condition")) {
        (Some(k), Some(c)) => parse_condition(k, c, &mut diags),
        (Some(k), None) if !k.is_temporal() => {
            diags.push(err(
                ckey,
                "correlation.condition",
                format!("`{}` needs a `condition`", k.as_str()),
            ));
            None
        }
        _ => None,
    };

    let generate = match get(cm, "generate") {
        None => false,
        Some(g) => match &g.data {
            YamlData::Value(Scalar::Boolean(b)) => *b,
            _ => {
                diags.push(err(g, "correlation.generate", "must be true or false"));
                false
            }
        },
    };

    let (line, col) = line_col(doc);
    let (errors, mut warnings): (Diags, Diags) = diags.into_iter().partition(|d| d.is_error());
    warns.append(&mut warnings);
    match (title, kind) {
        (Some(title), Some(kind)) if errors.is_empty() => {
            meta.title = title;
            Ok(Correlation {
                meta,
                kind,
                rules,
                group_by,
                timespan,
                timespan_ms,
                aliases,
                condition,
                generate,
                line,
                col,
            })
        }
        _ => Err(errors),
    }
}

```

In `crates/zaaf-sigma/src/document.rs`, replace:

```rust
//! Sigma YAML documents: rules, meta filters and (stubbed) correlation rules.

use crate::condition::{CondExpr, parse_condition};
use crate::diagnostic::{Diagnostic, Location};
use crate::modifier::{Modifier, parse_field_key};
use crate::value::RuleValue;
use saphyr::{AnnotatedMapping, LoadableYamlNode, MarkedYaml, Scalar, YamlData};
use std::path::Path;

type Node<'a> = MarkedYaml<'a>;
type Map<'a> = AnnotatedMapping<'a, MarkedYaml<'a>>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSource {
```

with:

```rust
//! Sigma YAML documents: rules, meta filters and correlation rules.

use crate::condition::{CondExpr, parse_condition};
use crate::correlation::{Correlation, parse_correlation};
use crate::diagnostic::{Diagnostic, Location};
use crate::modifier::{Modifier, parse_field_key};
use crate::value::RuleValue;
use saphyr::{AnnotatedMapping, LoadableYamlNode, MarkedYaml, Scalar, YamlData};
use std::path::Path;

pub(crate) type Node<'a> = MarkedYaml<'a>;
pub(crate) type Map<'a> = AnnotatedMapping<'a, MarkedYaml<'a>>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSource {
```

In `crates/zaaf-sigma/src/document.rs`, replace:

```rust
    pub col: usize,
}

/// Placeholder until correlation rules are implemented (milestone M2).
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationStub {
    pub title: String,
    pub id: Option<String>,
    /// 1-based position where the document starts (its first key).
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Document {
    Rule(Rule),
    Filter(Filter),
    Correlation(CorrelationStub),
}

#[derive(Debug, Default)]
```

with:

```rust
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Document {
    Rule(Rule),
    Filter(Filter),
    Correlation(Correlation),
}

#[derive(Debug, Default)]
```

In `crates/zaaf-sigma/src/document.rs`, replace:

```rust
    pub diagnostics: Vec<Diagnostic>,
}

type Diags = Vec<Diagnostic>;

/// 1-based line and column where `node` starts.
fn line_col(node: &Node) -> (usize, usize) {
    (node.span.start.line(), node.span.start.col() + 1)
}

fn err(node: &Node, path: &str, msg: impl Into<String>) -> Diagnostic {
    let (line, col) = line_col(node);
    Diagnostic::error(Location::at(line, col, path), msg)
}

/// The key and value nodes of `key` in a mapping.
fn entry<'n, 'a>(map: &'n Map<'a>, key: &str) -> Option<(&'n Node<'a>, &'n Node<'a>)> {
    map.iter().find(|(k, _)| k.data.as_str() == Some(key))
}

fn get<'n, 'a>(map: &'n Map<'a>, key: &str) -> Option<&'n Node<'a>> {
    entry(map, key).map(|(_, v)| v)
}

```

with:

```rust
    pub diagnostics: Vec<Diagnostic>,
}

pub(crate) type Diags = Vec<Diagnostic>;

/// 1-based line and column where `node` starts.
pub(crate) fn line_col(node: &Node) -> (usize, usize) {
    (node.span.start.line(), node.span.start.col() + 1)
}

pub(crate) fn err(node: &Node, path: &str, msg: impl Into<String>) -> Diagnostic {
    let (line, col) = line_col(node);
    Diagnostic::error(Location::at(line, col, path), msg)
}

/// The key and value nodes of `key` in a mapping.
pub(crate) fn entry<'n, 'a>(map: &'n Map<'a>, key: &str) -> Option<(&'n Node<'a>, &'n Node<'a>)> {
    map.iter().find(|(k, _)| k.data.as_str() == Some(key))
}

pub(crate) fn get<'n, 'a>(map: &'n Map<'a>, key: &str) -> Option<&'n Node<'a>> {
    entry(map, key).map(|(_, v)| v)
}

```

In `crates/zaaf-sigma/src/document.rs`, replace:

```rust
             split the collection into standalone rules",
        )]);
    }
    let (line, col) = line_col(doc);
    let has = |key: &str| entry(map, key).is_some();
    if has("correlation") {
        return Ok(Document::Correlation(CorrelationStub {
            title: get_str(map, "title").unwrap_or_default(),
            id: get_str(map, "id"),
            line,
            col,
        }));
    }
    if has("filter") && !has("detection") {
        return parse_filter(doc, map, warns).map(Document::Filter);
```

with:

```rust
             split the collection into standalone rules",
        )]);
    }
    let has = |key: &str| entry(map, key).is_some();
    if has("correlation") {
        return parse_correlation(doc, map, warns).map(Document::Correlation);
    }
    if has("filter") && !has("detection") {
        return parse_filter(doc, map, warns).map(Document::Filter);
```

In `crates/zaaf-sigma/src/document.rs`, replace:

```rust
    str_of(map, key).ok().flatten()
}

fn warn(node: &Node, path: &str, msg: impl Into<String>) -> Diagnostic {
    let (line, col) = line_col(node);
    Diagnostic::warning(Location::at(line, col, path), msg)
}
```

with:

```rust
    str_of(map, key).ok().flatten()
}

pub(crate) fn warn(node: &Node, path: &str, msg: impl Into<String>) -> Diagnostic {
    let (line, col) = line_col(node);
    Diagnostic::warning(Location::at(line, col, path), msg)
}
```

In `crates/zaaf-sigma/src/document.rs`, replace:

```rust
    }
}

/// An error when `map` uses a YAML merge key (`<<`), which Sigma documents may not use.
fn merge_key_error(map: &Map, path: &str) -> Option<Diagnostic> {
    map.iter()
        .find(|(k, _)| k.data.as_str() == Some("<<"))
        .map(|(k, _)| err(k, path, "YAML merge keys (`<<`) are not supported"))
}

/// The mandatory `title` (a missing or non-string one is an error in `diags`).
fn parse_title(doc: &Node, map: &Map, diags: &mut Diags) -> Option<String> {
    match str_of(map, "title") {
        Ok(Some(t)) => Some(t),
        Ok(None) => {
```

with:

```rust
    }
}

/// The optional metadata shared by rules and correlations; `title` is left empty for the
/// caller (it is mandatory and parsed by [`parse_title`]).
pub(crate) fn parse_meta(map: &Map, warns: &mut Diags) -> RuleMeta {
    RuleMeta {
        title: String::new(),
        id: meta_str(map, "id", warns),
        name: meta_str(map, "name", warns),
        status: meta_str(map, "status", warns),
        level: meta_str(map, "level", warns),
        description: meta_str(map, "description", warns),
        author: meta_str(map, "author", warns),
        references: get_str_list(map, "references", warns),
        tags: get_str_list(map, "tags", warns),
        falsepositives: get_str_list(map, "falsepositives", warns),
        date: meta_str(map, "date", warns),
        modified: meta_str(map, "modified", warns),
    }
}

/// An error when `map` uses a YAML merge key (`<<`), which Sigma documents may not use.
pub(crate) fn merge_key_error(map: &Map, path: &str) -> Option<Diagnostic> {
    map.iter()
        .find(|(k, _)| k.data.as_str() == Some("<<"))
        .map(|(k, _)| err(k, path, "YAML merge keys (`<<`) are not supported"))
}

/// The mandatory `title` (a missing or non-string one is an error in `diags`).
pub(crate) fn parse_title(doc: &Node, map: &Map, diags: &mut Diags) -> Option<String> {
    match str_of(map, "title") {
        Ok(Some(t)) => Some(t),
        Ok(None) => {
```

In `crates/zaaf-sigma/src/document.rs`, replace:

```rust
        }
    };
    let (line, col) = line_col(doc);
    let meta = RuleMeta {
        title: String::new(),
        id: meta_str(map, "id", warns),
        name: meta_str(map, "name", warns),
        status: meta_str(map, "status", warns),
        level: meta_str(map, "level", warns),
        description: meta_str(map, "description", warns),
        author: meta_str(map, "author", warns),
        references: get_str_list(map, "references", warns),
        tags: get_str_list(map, "tags", warns),
        falsepositives: get_str_list(map, "falsepositives", warns),
        date: meta_str(map, "date", warns),
        modified: meta_str(map, "modified", warns),
    };
    assemble(doc, map, diags, detection, |title, logsource, detection| {
        Rule {
            meta: RuleMeta { title, ..meta },
```

with:

```rust
        }
    };
    let (line, col) = line_col(doc);
    let meta = parse_meta(map, warns);
    assemble(doc, map, diags, detection, |title, logsource, detection| {
        Rule {
            meta: RuleMeta { title, ..meta },
```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
                out.diagnostics.push(warning(
                    &source,
                    document_at(c.line, c.col),
                    format!("correlation rule `{}` skipped: correlation support arrives in milestone M2", c.title),
                ));
            }
        }
```

with:

```rust
                out.diagnostics.push(warning(
                    &source,
                    document_at(c.line, c.col),
                    format!("correlation rule `{}` skipped: correlation support arrives in milestone M2", c.meta.title),
                ));
            }
        }
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-sigma && cargo test -p zaaf-ir && cargo test -p zaaf-cli --test check`
Expected: PASS (zaaf-sigma: 62 tests, including 10 in `correlation::tests`). Workspace total: 255.

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add crates/zaaf-cli/tests/check.rs crates/zaaf-ir/src/rule.rs crates/zaaf-sigma/src/correlation.rs crates/zaaf-sigma/src/document.rs crates/zaaf-sigma/src/lib.rs
git commit -m "feat(sigma): parse correlation rules with positioned shape diagnostics" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 3: zaaf-ir: compile correlations (references, chains, aliases, mapping) and lint them in `zaaf check`

Resolves every `rules` entry by `id` or `name` across all loaded documents, orders chained correlations (inner first), rejects cycles, applies aliases and pipeline field mapping, and computes which rules only feed correlations (decisions M2-D8, M2-D9, M2-D10, M2-D16). When the total compile budget has skipped rules, correlations are skipped with them (M2-D20). `zaaf check` reports correlation counts; the corpus script counts compiled correlations as documents.

Between this task and Task 7, `zaaf hunt` ignores compiled correlations (it only reads `CompileOutput::rules`).

**Files:**
- Create: `crates/zaaf-ir/src/correlation.rs`
- Modify: `crates/zaaf-ir/src/rule.rs`
- Modify: `crates/zaaf-ir/src/lib.rs`
- Modify: `crates/zaaf-cli/src/check.rs`
- Modify: `crates/zaaf-cli/tests/check.rs`
- Modify: `scripts/compare_known_unsupported.py`
- Modify: `scripts/test_compare_known_unsupported.py`

**Interfaces:**
- Consumes: Task 2's `zaaf_sigma::{Correlation, CorrelationType, CondOp, Spanned}`; `zaaf_pipeline::PipelineSet::map_field(&LogSource, &str) -> MappedField`; `rule.rs`'s `error`/`warning` helpers (made `pub(crate)` here), its `seen` rule-id set and its `Budget` (`exceeded()`, `skipped`).
- Produces (re-exported from `zaaf_ir`):
  - `enum InputSource { Rule(usize), Correlation(usize) }` (indexes into `CompileOutput::rules` / `::correlations`; a correlation input index is always lower than its consumer's).
  - `enum FieldSource { Event(Vec<String>), Group(usize) }`.
  - `struct CorrelationInput { source: InputSource, group_by: Vec<FieldSource>, value: Vec<FieldSource> }`.
  - `struct CompiledCorrelation { info: RuleInfo, kind: CorrelationType, inputs: Vec<CorrelationInput>, group_by: Vec<String>, timespan: String, timespan_ms: i64, bounds: Vec<(CondOp, f64)>, fields: Vec<String>, generate: bool }`.
  - `struct CorrelationOnly { rules: Vec<bool>, correlations: Vec<bool> }` and `pub fn correlation_only(rule_count: usize, correlations: &[CompiledCorrelation]) -> CorrelationOnly`.
  - `CompileOutput` gains `correlations: Vec<CompiledCorrelation>`; `correlations_skipped` now counts correlation documents that failed to compile or were skipped by the total budget.
  - `zaaf check`: text summary `checked N files: R rules, F filters, C correlations, S correlations skipped, E errors, W warnings`; JSON report gains `"correlations"`.

- [ ] **Step 1: Write the failing tests**

Create `crates/zaaf-ir/src/correlation.rs` containing only this test module for now (Step 3 puts the implementation above it):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{CompileOutput, SourcedDocument, compile};
    use zaaf_pipeline::parse_pipeline;

    fn compile_src(src: &str, pipelines: &PipelineSet) -> CompileOutput {
        let parsed = zaaf_sigma::parse_str(src);
        assert!(
            parsed.diagnostics.iter().all(|d| !d.is_error()),
            "{:?}",
            parsed.diagnostics
        );
        compile(
            parsed
                .documents
                .into_iter()
                .map(|document| SourcedDocument {
                    document,
                    source: None,
                })
                .collect(),
            pipelines,
        )
    }

    fn rule(id: &str, name: &str, product: &str) -> String {
        format!(
            "title: {id}\nid: {id}\nname: {name}\nlogsource:\n    product: {product}\ndetection:\n    s:\n        EventID: 1\n    condition: s\n"
        )
    }

    fn errors(out: &CompileOutput) -> Vec<String> {
        out.diagnostics
            .iter()
            .filter(|d| d.is_error())
            .map(|d| d.to_string())
            .collect()
    }

    #[test]
    fn references_by_id_and_name_with_mapping_and_aliases() {
        let pipes = PipelineSet::new(vec![
            parse_pipeline(
                "name: p\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      User: user.name\n    rule_conditions:\n      - product: windows\n",
            )
            .unwrap(),
        ]);
        let src = format!(
            "{}---\n{}---\ntitle: corr\nid: c1\nlevel: high\ncorrelation:\n    type: temporal\n    rules: [r-a, net]\n    group-by: [User, ip]\n    timespan: 5m\n    aliases:\n        ip:\n            r-a: source.ip\n            net: destination.ip\n",
            rule("r-a", "auth", "windows"),
            rule("r-b", "net", "linux"),
        );
        let out = compile_src(&src, &pipes);
        assert!(errors(&out).is_empty(), "{:?}", out.diagnostics);
        let c = &out.correlations[0];
        assert_eq!(c.info.id, "c1");
        assert_eq!(c.info.level, Level::High);
        assert_eq!(c.kind, CorrelationType::Temporal);
        assert_eq!(c.group_by, vec!["User", "ip"]);
        assert_eq!(c.timespan_ms, 300_000);
        assert_eq!(c.bounds, vec![(CondOp::Gte, 2.0)]);
        assert_eq!(c.inputs[0].source, InputSource::Rule(0));
        assert_eq!(c.inputs[1].source, InputSource::Rule(1));
        assert_eq!(
            c.inputs[0].group_by,
            vec![
                FieldSource::Event(vec!["user.name".into()]),
                FieldSource::Event(vec!["source.ip".into()])
            ]
        );
        assert_eq!(
            c.inputs[1].group_by,
            vec![
                FieldSource::Event(vec!["User".into()]),
                FieldSource::Event(vec!["destination.ip".into()])
            ]
        );
        assert_eq!(out.correlations_skipped, 0);
    }

    #[test]
    fn unknown_ambiguous_and_alias_errors_point_at_the_reference() {
        let src = format!(
            "{}---\n{}---\ntitle: corr\ncorrelation:\n    type: event_count\n    rules: [missing, dup]\n    group-by: [x]\n    timespan: 5m\n    condition:\n        gte: 2\n---\ntitle: corr2\ncorrelation:\n    type: temporal\n    rules: [r-a]\n    group-by: [x]\n    timespan: 5m\n    aliases:\n        x:\n            r-b: f\n",
            rule("r-a", "dup", "t"),
            rule("r-b", "dup", "t"),
        );
        let out = compile_src(&src, &PipelineSet::default());
        let e = errors(&out);
        assert!(out.correlations.is_empty());
        assert_eq!(out.correlations_skipped, 2);
        assert!(
            e.iter().any(|m| m.contains(":24:13: correlation.rules[0]: correlation `corr`: references unknown rule `missing`")),
            "{e:?}"
        );
        assert!(
            e.iter()
                .any(|m| m.contains("correlation.rules[1]") && m.contains("ambiguous")),
            "{e:?}"
        );
        assert!(
            e.iter()
                .any(|m| m.contains("correlation.aliases.x.r-b") && m.contains("not in `rules`")),
            "{e:?}"
        );
    }

    #[test]
    fn chains_come_out_in_dependency_order_and_cycles_are_errors() {
        // The outer correlation is written first; it must be compiled after the inner one.
        let src = format!(
            "title: outer\nid: c-outer\ncorrelation:\n    type: temporal_ordered\n    rules: [many_failed, r-ok]\n    group-by: [User]\n    timespan: 10m\n---\ntitle: inner\nid: c-inner\nname: many_failed\ncorrelation:\n    type: event_count\n    rules: [r-fail]\n    group-by: [User]\n    timespan: 10m\n    condition:\n        gte: 3\n---\n{}---\n{}---\ntitle: loop1\nid: l1\ncorrelation:\n    type: temporal\n    rules: [l2]\n    group-by: [User]\n    timespan: 1m\n---\ntitle: loop2\nid: l2\ncorrelation:\n    type: temporal\n    rules: [l1]\n    group-by: [User]\n    timespan: 1m\n",
            rule("r-fail", "failed", "t"),
            rule("r-ok", "ok", "t"),
        );
        let out = compile_src(&src, &PipelineSet::default());
        let ids: Vec<&str> = out
            .correlations
            .iter()
            .map(|c| c.info.id.as_str())
            .collect();
        assert_eq!(ids, vec!["c-inner", "c-outer"]);
        assert_eq!(
            out.correlations[1].inputs[0].source,
            InputSource::Correlation(0)
        );
        assert_eq!(
            out.correlations[1].inputs[0].group_by,
            vec![FieldSource::Group(0)]
        );
        assert_eq!(out.correlations[1].inputs[1].source, InputSource::Rule(1));
        let e = errors(&out);
        assert_eq!(e.len(), 2, "{e:?}");
        assert!(e.iter().all(|m| m.contains("reference cycle")), "{e:?}");
    }

    #[test]
    fn chained_group_by_must_exist_in_the_inner_correlation() {
        let src = format!(
            "{}---\ntitle: inner\nid: c-inner\ncorrelation:\n    type: event_count\n    rules: [r-a]\n    group-by: [Host]\n    timespan: 10m\n    condition:\n        gte: 3\n---\ntitle: outer\nid: c-outer\ncorrelation:\n    type: event_count\n    rules: [c-inner]\n    group-by: [User]\n    timespan: 10m\n    condition:\n        gte: 2\n",
            rule("r-a", "a", "t"),
        );
        let out = compile_src(&src, &PipelineSet::default());
        let e = errors(&out);
        assert_eq!(out.correlations.len(), 1);
        assert!(
            e.iter().any(|m| m.contains(
                "`User` is not a group-by field of the referenced correlation `c-inner`"
            )),
            "{e:?}"
        );
    }

    #[test]
    fn duplicate_correlation_id_and_double_reference_are_errors() {
        let src = format!(
            "{}---\ntitle: c\nid: r-a\ncorrelation:\n    type: temporal\n    rules: [r-a]\n    group-by: [x]\n    timespan: 1m\n---\ntitle: d\ncorrelation:\n    type: temporal\n    rules: [r-a, a]\n    group-by: [x]\n    timespan: 1m\n",
            rule("r-a", "a", "t"),
        );
        let out = compile_src(&src, &PipelineSet::default());
        let e = errors(&out).join("\n");
        assert!(e.contains("duplicate rule id `r-a`"), "{e}");
        assert!(e.contains("names the same rule twice"), "{e}");
        assert!(out.correlations.is_empty());
    }

    #[test]
    fn value_fields_are_mapped_and_correlation_ids_default_to_title() {
        let src = format!(
            "{}---\ntitle: big transfer\ncorrelation:\n    type: value_sum\n    rules: [r-a]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        field: bytes\n        gt: 100\n",
            rule("r-a", "a", "t"),
        );
        let out = compile_src(&src, &PipelineSet::default());
        let c = &out.correlations[0];
        assert_eq!(c.info.id, "title:big transfer");
        assert_eq!(c.fields, vec!["bytes"]);
        assert_eq!(
            c.inputs[0].value,
            vec![FieldSource::Event(vec!["bytes".into()])]
        );
        assert_eq!(c.bounds, vec![(CondOp::Gt, 100.0)]);
    }

    #[test]
    fn generate_decides_which_rules_alert_on_their_own() {
        let src = format!(
            "{}---\n{}---\n{}---\ntitle: c1\nid: c1\ncorrelation:\n    type: temporal\n    rules: [r-a, r-b]\n    group-by: [x]\n    timespan: 1m\n---\ntitle: c2\nid: c2\ncorrelation:\n    type: event_count\n    rules: [r-b, c1]\n    group-by: [x]\n    timespan: 1m\n    generate: true\n    condition:\n        gte: 1\n",
            rule("r-a", "a", "t"),
            rule("r-b", "b", "t"),
            rule("r-c", "c", "t"),
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert!(errors(&out).is_empty(), "{:?}", out.diagnostics);
        let only = correlation_only(out.rules.len(), &out.correlations);
        // r-a: only c1 (generate false). r-b: c1 and c2 (generates). r-c: unreferenced.
        assert_eq!(only.rules, vec![true, false, false]);
        // c1 is referenced by c2 with generate: true, c2 by nothing.
        assert_eq!(only.correlations, vec![false, false]);
    }
}
```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.correlations_skipped, 1);
        assert!(first_error(&out).contains("duplicate rule id `r1`"));
        assert_eq!(out.rules[0].info.level, Level::Medium);
        assert_eq!(Level::parse("Critical"), Some(Level::Critical));
```

with:

```rust
        );
        let out = compile_src(&src, &PipelineSet::default());
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.correlations.len(), 1);
        assert_eq!(out.correlations_skipped, 0);
        assert!(first_error(&out).contains("duplicate rule id `r1`"));
        assert_eq!(out.rules[0].info.level, Level::Medium);
        assert_eq!(Level::parse("Critical"), Some(Level::Critical));
```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
    }

    #[test]
    fn mid_size_regexes_hit_the_rule_budget_before_compiling_them_all() {
        // Each `\w{1,64}` weighs 4096 units; 17 exceed the 65536 per-rule budget.
        let vals: Vec<String> = (1..=2000)
```

with:

```rust
    }

    #[test]
    fn correlations_are_skipped_with_the_rules_the_total_budget_skipped() {
        let vals: Vec<String> = (0..3750).map(|i| format!("'v{i}'")).collect();
        let one = |n: usize| {
            format!(
                "title: t{n}\nid: r{n}\nlogsource:\n    product: windows\ndetection:\n    s:\n        C|re: [{}]\n    condition: s\n",
                vals.join(", ")
            )
        };
        let mut src: Vec<String> = (0..20).map(one).collect();
        src.push("title: c1\ncorrelation:\n    type: event_count\n    rules: [r0]\n    group-by: [U]\n    timespan: 1m\n    condition:\n        gte: 2\n".into());
        src.push("title: c2\ncorrelation:\n    type: temporal\n    rules: [r19]\n    group-by: [U]\n    timespan: 1m\n".into());
        let out = compile_src(&src.join("---\n"), &PipelineSet::default());
        let errs: Vec<_> = out.diagnostics.iter().filter(|d| d.is_error()).collect();
        // One budget error; no "unknown rule" error for the correlation whose rule was skipped.
        assert_eq!(errs.len(), 1, "{errs:?}");
        let kept = MAX_TOTAL_WEIGHT / (3750 * 16);
        assert!(
            errs[0]
                .message
                .contains(&format!("({} documents skipped)", 20 - kept + 2)),
            "{}",
            errs[0].message
        );
        assert!(out.correlations.is_empty());
        assert_eq!(out.correlations_skipped, 2);
    }

    #[test]
    fn mid_size_regexes_hit_the_rule_budget_before_compiling_them_all() {
        // Each `\w{1,64}` weighs 4096 units; 17 exceed the 65536 per-rule budget.
        let vals: Vec<String> = (1..=2000)
```

In `crates/zaaf-ir/src/lib.rs`, replace:

```rust
//! Compiles parsed Sigma documents into the ZAAFElegia intermediate representation.

pub mod ir;
mod item;
pub mod regex_engine;
mod rule;
mod transform;

pub use ir::{CmpOp, Expr, Matcher, Predicate, RefMode, Target, TimePart};
pub use regex_engine::{BACKTRACK_LIMIT, CompiledRegex, LimitCounter, RegexFlags};
pub use rule::{
```

with:

```rust
//! Compiles parsed Sigma documents into the ZAAFElegia intermediate representation.

mod correlation;
pub mod ir;
mod item;
pub mod regex_engine;
mod rule;
mod transform;

pub use correlation::{
    CompiledCorrelation, CorrelationInput, CorrelationOnly, FieldSource, InputSource,
    correlation_only,
};
pub use ir::{CmpOp, Expr, Matcher, Predicate, RefMode, Target, TimePart};
pub use regex_engine::{BACKTRACK_LIMIT, CompiledRegex, LimitCounter, RegexFlags};
pub use rule::{
```

In `crates/zaaf-cli/tests/check.rs`, replace:

```rust
}

#[test]
fn json_report_and_correlation_warning() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("r.yml"),
```

with:

```rust
}

#[test]
fn json_report_counts_correlations() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("r.yml"),
```

In `crates/zaaf-cli/tests/check.rs`, replace:

```rust
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["files"], 1);
    assert_eq!(report["rules"], 1);
    assert_eq!(report["correlations_skipped"], 1);
    let d = &report["diagnostics"][0];
    assert_eq!(d["severity"], "warning");
    assert_eq!(d["line"], 10);
    assert_eq!(d["col"], 1);
    assert!(d["path"].is_null());
    assert!(d["file"].as_str().unwrap().ends_with("r.yml"));
}

#[test]
```

with:

```rust
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["files"], 1);
    assert_eq!(report["rules"], 1);
    assert_eq!(report["correlations"], 1);
    assert_eq!(report["correlations_skipped"], 0);
    assert_eq!(report["errors"], 0);
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 0);
}

#[test]
fn correlation_with_missing_rule_is_an_error_at_the_reference() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("c.yml"),
        "title: corr\ncorrelation:\n    type: temporal\n    rules:\n        - nope\n    group-by: [User]\n    timespan: 5m\n",
    )
    .unwrap();
    zaaf().arg("check").arg(dir.path()).assert().code(2).stdout(
        predicate::str::contains("c.yml:5:11: correlation.rules[0]")
            .and(predicate::str::contains("references unknown rule `nope`"))
            .and(predicate::str::contains(
                "0 correlations, 1 correlations skipped",
            )),
    );
}

#[test]
```

In `scripts/test_compare_known_unsupported.py`, replace:

```python

    def test_files_without_documents(self):
        self.assertEqual(c.check(report(files=10, rules=2), {}, 0)[0], 1)

    def test_null_file_error(self):
        r = report(diags=[err(None)])
```

with:

```python

    def test_files_without_documents(self):
        self.assertEqual(c.check(report(files=10, rules=2), {}, 0)[0], 1)

    def test_correlation_documents_count(self):
        r = report(files=4, rules=3)
        r["correlations"] = 1
        self.assertEqual(c.check(r, {}, 0)[0], 0)

    def test_null_file_error(self):
        r = report(diags=[err(None)])
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-ir correlation && cargo test -p zaaf-cli --test check`
Expected: FAIL to compile: `unresolved imports correlation::CompiledCorrelation, ...` (the module holds only tests so far). `python3 -I scripts/test_compare_known_unsupported.py` fails `test_correlation_documents_count` until Step 3.

- [ ] **Step 3: Implement**

At the top of `crates/zaaf-ir/src/correlation.rs`, above `#[cfg(test)]`, add the implementation:

```rust
//! Compiles correlation documents: resolves rule references (by `id` or `name`),
//! chains, aliases and pipeline field mapping.
//!
//! Correlations come out in dependency order: a correlation that references another
//! correlation always has a higher index, so a correlator can cascade alerts forward.

use crate::rule::{CompiledRule, Level, RuleInfo, error, warning};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use zaaf_pipeline::PipelineSet;
use zaaf_sigma::{CondOp, Correlation, CorrelationType, Diagnostic, Location, LogSource, Spanned};

/// What a correlation input consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSource {
    /// Index into `CompileOutput::rules`.
    Rule(usize),
    /// Index into `CompileOutput::correlations` (always lower than the consumer's index).
    Correlation(usize),
}

/// Where one group-by or value field is read for one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldSource {
    /// Event field names after pipeline mapping; the first one present with a non-null
    /// value is used.
    Event(Vec<String>),
    /// Position in the inner correlation's group-by (chained correlations).
    Group(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationInput {
    pub source: InputSource,
    /// One entry per `group-by` name of the correlation.
    pub group_by: Vec<FieldSource>,
    /// One entry per condition `field` (value_* types only).
    pub value: Vec<FieldSource>,
}

#[derive(Debug, Clone)]
pub struct CompiledCorrelation {
    pub info: RuleInfo,
    pub kind: CorrelationType,
    /// In the order of the rule's `rules` list.
    pub inputs: Vec<CorrelationInput>,
    /// `group-by` names as written (field or alias names).
    pub group_by: Vec<String>,
    pub timespan: String,
    pub timespan_ms: i64,
    /// AND'd bounds. For `temporal`/`temporal_ordered` without a condition this is
    /// `gte: <number of rules>`.
    pub bounds: Vec<(CondOp, f64)>,
    /// Condition `field` names (value_* types), as written.
    pub fields: Vec<String>,
    pub generate: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Target {
    Rule(usize),
    Corr(usize),
}

fn at(s: &Spanned, path: String) -> Location {
    Location::at(s.line, s.col, path)
}

/// Resolves a reference by id or name; `Err` carries the message.
fn resolve(reference: &str, index: &HashMap<String, Vec<Target>>) -> Result<Target, String> {
    match index.get(reference).map(Vec::as_slice) {
        Some([t]) => Ok(*t),
        Some([_, _, ..]) => Err(format!(
            "reference `{reference}` is ambiguous: several rules or correlations have this id or name"
        )),
        _ => Err(format!(
            "references unknown rule `{reference}` (no loaded rule or correlation has this id or name)"
        )),
    }
}

/// Compiles correlations against already compiled `rules`. Returns them in dependency
/// order plus the number of correlation documents that failed.
pub(crate) fn compile_correlations(
    docs: Vec<(Correlation, Option<PathBuf>)>,
    rules: &[CompiledRule],
    pipelines: &PipelineSet,
    seen_ids: &mut HashSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<CompiledCorrelation>, usize) {
    let mut index: HashMap<String, Vec<Target>> = HashMap::new();
    let add = |key: &str, t: Target, index: &mut HashMap<String, Vec<Target>>| {
        let v = index.entry(key.to_string()).or_default();
        if !v.contains(&t) {
            v.push(t);
        }
    };
    for (i, r) in rules.iter().enumerate() {
        add(&r.info.id, Target::Rule(i), &mut index);
        if let Some(n) = &r.info.name {
            add(n, Target::Rule(i), &mut index);
        }
    }
    // Ids: unique across rules and correlations, like rule ids.
    let mut ids = Vec::with_capacity(docs.len());
    let mut valid = vec![true; docs.len()];
    for (i, (c, source)) in docs.iter().enumerate() {
        let id = c
            .meta
            .id
            .clone()
            .unwrap_or_else(|| format!("title:{}", c.meta.title));
        if !seen_ids.insert(id.clone()) {
            diagnostics.push(error(
                source,
                Location::at(c.line, c.col, ""),
                format!(
                    "duplicate rule id `{id}`; correlation `{}` skipped",
                    c.meta.title
                ),
            ));
            valid[i] = false;
        } else {
            add(&id, Target::Corr(i), &mut index);
            if let Some(n) = &c.meta.name {
                add(n, Target::Corr(i), &mut index);
            }
        }
        ids.push(id);
    }

    // Resolve references; a failure invalidates the correlation.
    let mut targets: Vec<Vec<Target>> = vec![Vec::new(); docs.len()];
    for (i, (c, source)) in docs.iter().enumerate() {
        if !valid[i] {
            continue;
        }
        for (k, r) in c.rules.iter().enumerate() {
            match resolve(&r.value, &index) {
                Ok(t) => targets[i].push(t),
                Err(msg) => {
                    diagnostics.push(error(
                        source,
                        at(r, format!("correlation.rules[{k}]")),
                        format!("correlation `{}`: {msg}", c.meta.title),
                    ));
                    valid[i] = false;
                }
            }
        }
        let ts = &targets[i];
        if valid[i] && ts.iter().enumerate().any(|(k, t)| ts[..k].contains(t)) {
            diagnostics.push(error(
                source,
                Location::at(c.line, c.col, "correlation.rules"),
                format!(
                    "correlation `{}`: `rules` names the same rule twice (by id and by name)",
                    c.meta.title
                ),
            ));
            valid[i] = false;
        }
    }

    // Dependency order; what is left over is in (or depends on) a cycle or a broken correlation.
    let mut order: Vec<usize> = Vec::new();
    let mut placed = vec![false; docs.len()];
    loop {
        let mut progress = false;
        for i in 0..docs.len() {
            if placed[i] || !valid[i] {
                continue;
            }
            let deps: Vec<usize> = targets[i]
                .iter()
                .filter_map(|t| match t {
                    Target::Corr(j) => Some(*j),
                    Target::Rule(_) => None,
                })
                .collect();
            if deps.iter().any(|&j| !valid[j]) {
                let (c, source) = &docs[i];
                diagnostics.push(error(
                    source,
                    Location::at(c.line, c.col, "correlation.rules"),
                    format!(
                        "correlation `{}` references a correlation that has errors",
                        c.meta.title
                    ),
                ));
                valid[i] = false;
                progress = true;
            } else if deps.iter().all(|&j| placed[j]) {
                placed[i] = true;
                order.push(i);
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }
    for i in 0..docs.len() {
        if valid[i] && !placed[i] {
            let (c, source) = &docs[i];
            diagnostics.push(error(
                source,
                Location::at(c.line, c.col, "correlation.rules"),
                format!(
                    "correlation `{}` is part of a reference cycle",
                    c.meta.title
                ),
            ));
            valid[i] = false;
        }
    }

    // Compile in dependency order.
    let mut position: HashMap<usize, usize> = HashMap::new();
    let mut out: Vec<CompiledCorrelation> = Vec::new();
    let mut docs: Vec<Option<(Correlation, Option<PathBuf>)>> =
        docs.into_iter().map(Some).collect();
    let mut failed = valid.iter().filter(|v| !**v).count();
    for i in order {
        let Some((c, source)) = docs[i].take() else {
            continue;
        };
        let inner_failed = targets[i].iter().any(|t| match t {
            Target::Corr(j) => !position.contains_key(j),
            Target::Rule(_) => false,
        });
        if inner_failed {
            diagnostics.push(error(
                &source,
                Location::at(c.line, c.col, "correlation.rules"),
                format!(
                    "correlation `{}` references a correlation that has errors",
                    c.meta.title
                ),
            ));
            failed += 1;
            continue;
        }
        let sources: Vec<InputSource> = targets[i]
            .iter()
            .map(|t| match t {
                Target::Rule(r) => InputSource::Rule(*r),
                Target::Corr(j) => InputSource::Correlation(position[j]),
            })
            .collect();
        match build(
            &c,
            &source,
            &ids[i],
            sources,
            &index,
            &targets[i],
            rules,
            &out,
            pipelines,
            diagnostics,
        ) {
            Some(cc) => {
                position.insert(i, out.len());
                out.push(cc);
            }
            None => failed += 1,
        }
    }
    (out, failed)
}

#[allow(clippy::too_many_arguments)]
fn build(
    c: &Correlation,
    source: &Option<PathBuf>,
    id: &str,
    sources: Vec<InputSource>,
    index: &HashMap<String, Vec<Target>>,
    targets: &[Target],
    rules: &[CompiledRule],
    done: &[CompiledCorrelation],
    pipelines: &PipelineSet,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<CompiledCorrelation> {
    let title = &c.meta.title;
    let mut ok = true;
    // alias name -> input position -> field
    let mut aliases: HashMap<&str, HashMap<usize, &str>> = HashMap::new();
    for a in &c.aliases {
        let entry = aliases.entry(a.name.value.as_str()).or_default();
        for (rref, field) in &a.fields {
            let path = format!("correlation.aliases.{}.{}", a.name.value, rref.value);
            match resolve(&rref.value, index) {
                Ok(t) => match targets.iter().position(|x| *x == t) {
                    Some(pos) => {
                        entry.insert(pos, field.as_str());
                    }
                    None => {
                        diagnostics.push(error(
                            source,
                            at(rref, path),
                            format!(
                                "correlation `{title}`: alias `{}` names `{}`, which is not in `rules`",
                                a.name.value, rref.value
                            ),
                        ));
                        ok = false;
                    }
                },
                Err(msg) => {
                    diagnostics.push(error(
                        source,
                        at(rref, path),
                        format!("correlation `{title}`: {msg}"),
                    ));
                    ok = false;
                }
            }
        }
    }

    let input_name = |pos: usize| c.rules[pos].value.as_str();
    let mut inputs = Vec::with_capacity(sources.len());
    for (pos, src) in sources.iter().enumerate() {
        let field_source = |name: &str,
                            what: &str,
                            s: &Spanned,
                            diagnostics: &mut Vec<Diagnostic>|
         -> Option<FieldSource> {
            match src {
                InputSource::Rule(r) => {
                    let ls: &LogSource = &rules[*r].info.logsource;
                    Some(FieldSource::Event(pipelines.map_field(ls, name).names))
                }
                InputSource::Correlation(j) => {
                    match done[*j].group_by.iter().position(|g| g == name) {
                        Some(p) => Some(FieldSource::Group(p)),
                        None => {
                            diagnostics.push(error(
                                source,
                                at(s, what.to_string()),
                                format!(
                                    "correlation `{title}`: `{name}` is not a group-by field of the referenced correlation `{}`, so its alerts carry no such value",
                                    input_name(pos)
                                ),
                            ));
                            None
                        }
                    }
                }
            }
        };
        let mut group_by = Vec::new();
        for (g_i, g) in c.group_by.iter().enumerate() {
            let field = match aliases.get(g.value.as_str()) {
                Some(per_input) => match per_input.get(&pos) {
                    Some(f) => *f,
                    None => {
                        diagnostics.push(warning(
                            source,
                            at(g, format!("correlation.group-by[{g_i}]")),
                            format!(
                                "correlation `{title}`: alias `{}` has no field for `{}`; the field `{}` is used",
                                g.value,
                                input_name(pos),
                                g.value
                            ),
                        ));
                        g.value.as_str()
                    }
                },
                None => g.value.as_str(),
            };
            match field_source(
                field,
                &format!("correlation.group-by[{g_i}]"),
                g,
                diagnostics,
            ) {
                Some(fs) => group_by.push(fs),
                None => ok = false,
            }
        }
        let mut value = Vec::new();
        if let Some(cond) = &c.condition {
            let s = Spanned {
                value: String::new(),
                line: cond.line,
                col: cond.col,
            };
            for f in &cond.fields {
                match field_source(f, "correlation.condition.field", &s, diagnostics) {
                    Some(fs) => value.push(fs),
                    None => ok = false,
                }
            }
        }
        inputs.push(CorrelationInput {
            source: *src,
            group_by,
            value,
        });
    }
    if !ok {
        return None;
    }

    let level = match c.meta.level.as_deref() {
        None => Level::Medium,
        Some(s) => Level::parse(s).unwrap_or_else(|| {
            diagnostics.push(warning(
                source,
                Location::at(c.line, c.col, ""),
                format!("correlation `{title}`: unknown level `{s}`, using medium"),
            ));
            Level::Medium
        }),
    };
    let bounds = match &c.condition {
        Some(cond) => cond.bounds.clone(),
        None => vec![(CondOp::Gte, inputs.len() as f64)],
    };
    Some(CompiledCorrelation {
        info: RuleInfo {
            id: id.to_string(),
            name: c.meta.name.clone(),
            title: title.clone(),
            level,
            status: c.meta.status.clone(),
            description: c.meta.description.clone(),
            author: c.meta.author.clone(),
            references: c.meta.references.clone(),
            tags: c.meta.tags.clone(),
            falsepositives: c.meta.falsepositives.clone(),
            logsource: LogSource::default(),
            source: source.clone(),
        },
        kind: c.kind,
        inputs,
        group_by: c.group_by.iter().map(|g| g.value.clone()).collect(),
        timespan: c.timespan.clone(),
        timespan_ms: c.timespan_ms,
        bounds,
        fields: c
            .condition
            .as_ref()
            .map(|cond| cond.fields.clone())
            .unwrap_or_default(),
        generate: c.generate,
    })
}

/// Which rules and correlations only feed correlations (Sigma `generate: false`, the
/// default) and so produce no alert of their own. A rule or correlation stays
/// stand-alone when nothing references it or when any referencing correlation sets
/// `generate: true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationOnly {
    pub rules: Vec<bool>,
    pub correlations: Vec<bool>,
}

pub fn correlation_only(
    rule_count: usize,
    correlations: &[CompiledCorrelation],
) -> CorrelationOnly {
    // 0 = not referenced, 1 = referenced only with generate: false, 2 = some referrer generates.
    let mut rules = vec![0u8; rule_count];
    let mut corrs = vec![0u8; correlations.len()];
    for c in correlations {
        let mark = if c.generate { 2 } else { 1 };
        for input in &c.inputs {
            let slot = match input.source {
                InputSource::Rule(r) => &mut rules[r],
                InputSource::Correlation(j) => &mut corrs[j],
            };
            *slot = (*slot).max(mark);
        }
    }
    CorrelationOnly {
        rules: rules.into_iter().map(|m| m == 1).collect(),
        correlations: corrs.into_iter().map(|m| m == 1).collect(),
    }
}

```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
//! is still applied and the compiler emits a warning on that rule. A filter that fails
//! to compile leaves its targeted rules unfiltered; each of those rules gets a warning.

use crate::ir::Expr;
use crate::item::{and, compile_item, or, weight};
use std::collections::HashSet;
```

with:

```rust
//! is still applied and the compiler emits a warning on that rule. A filter that fails
//! to compile leaves its targeted rules unfiltered; each of those rules gets a warning.

use crate::correlation::{CompiledCorrelation, compile_correlations};
use crate::ir::Expr;
use crate::item::{and, compile_item, or, weight};
use std::collections::HashSet;
```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
#[derive(Debug, Default)]
pub struct CompileOutput {
    pub rules: Vec<CompiledRule>,
    pub diagnostics: Vec<Diagnostic>,
    pub filters: usize,
    pub correlations_skipped: usize,
}

```

with:

```rust
#[derive(Debug, Default)]
pub struct CompileOutput {
    pub rules: Vec<CompiledRule>,
    /// In dependency order (see [`crate::InputSource`]).
    pub correlations: Vec<CompiledCorrelation>,
    pub diagnostics: Vec<Diagnostic>,
    pub filters: usize,
    /// Correlation documents that parsed but were not compiled: they failed, or the
    /// total compile budget skipped them.
    pub correlations_skipped: usize,
}

```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
    }
}

fn error(source: &Option<PathBuf>, location: Location, msg: String) -> Diagnostic {
    located(Diagnostic::error(location, msg), source)
}

fn warning(source: &Option<PathBuf>, location: Location, msg: String) -> Diagnostic {
    located(Diagnostic::warning(location, msg), source)
}

```

with:

```rust
    }
}

pub(crate) fn error(source: &Option<PathBuf>, location: Location, msg: String) -> Diagnostic {
    located(Diagnostic::error(location, msg), source)
}

pub(crate) fn warning(source: &Option<PathBuf>, location: Location, msg: String) -> Diagnostic {
    located(Diagnostic::warning(location, msg), source)
}

```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
    let mut out = CompileOutput::default();
    let mut rules = Vec::new();
    let mut filters = Vec::new();
    for SourcedDocument { document, source } in docs {
        match document {
            Document::Rule(r) => rules.push((r, source)),
            Document::Filter(f) => filters.push((f, source)),
            Document::Correlation(c) => {
                out.correlations_skipped += 1;
                out.diagnostics.push(warning(
                    &source,
                    document_at(c.line, c.col),
                    format!("correlation rule `{}` skipped: correlation support arrives in milestone M2", c.meta.title),
                ));
            }
        }
    }
    out.filters = filters.len();
```

with:

```rust
    let mut out = CompileOutput::default();
    let mut rules = Vec::new();
    let mut filters = Vec::new();
    let mut correlations = Vec::new();
    for SourcedDocument { document, source } in docs {
        match document {
            Document::Rule(r) => rules.push((r, source)),
            Document::Filter(f) => filters.push((f, source)),
            Document::Correlation(c) => correlations.push((c, source)),
        }
    }
    out.filters = filters.len();
```

In `crates/zaaf-ir/src/rule.rs`, replace:

```rust
            },
            expr,
        });
    }
    if let Some((source, location, is_filter, crossing_skipped)) = budget.first_skip.clone() {
        let what = match (crossing_skipped, is_filter) {
```

with:

```rust
            },
            expr,
        });
    }
    // Correlations add no weight, but once the budget skipped rules they would only
    // report the skipped rules as unknown references: they are skipped with them.
    if budget.exceeded() {
        budget.skipped += correlations.len();
        out.correlations_skipped = correlations.len();
    } else {
        let (compiled, failed) = compile_correlations(
            correlations,
            &out.rules,
            pipelines,
            &mut seen,
            &mut out.diagnostics,
        );
        out.correlations = compiled;
        out.correlations_skipped = failed;
    }
    if let Some((source, location, is_filter, crossing_skipped)) = budget.first_skip.clone() {
        let what = match (crossing_skipped, is_filter) {
```

In `crates/zaaf-cli/src/check.rs`, replace:

```rust
            }
            writeln!(
                out,
                "checked {} files: {} rules, {} filters, {} correlations skipped, {errors} errors, {warnings} warnings",
                loaded.files,
                loaded.output.rules.len(),
                loaded.output.filters,
                loaded.output.correlations_skipped
            )
        })(),
```

with:

```rust
            }
            writeln!(
                out,
                "checked {} files: {} rules, {} filters, {} correlations, {} correlations skipped, {errors} errors, {warnings} warnings",
                loaded.files,
                loaded.output.rules.len(),
                loaded.output.filters,
                loaded.output.correlations.len(),
                loaded.output.correlations_skipped
            )
        })(),
```

In `crates/zaaf-cli/src/check.rs`, replace:

```rust
                "files": loaded.files,
                "rules": loaded.output.rules.len(),
                "filters": loaded.output.filters,
                "correlations_skipped": loaded.output.correlations_skipped,
                "errors": errors,
                "warnings": warnings,
```

with:

```rust
                "files": loaded.files,
                "rules": loaded.output.rules.len(),
                "filters": loaded.output.filters,
                "correlations": loaded.output.correlations.len(),
                "correlations_skipped": loaded.output.correlations_skipped,
                "errors": errors,
                "warnings": warnings,
```

In `scripts/compare_known_unsupported.py`, replace:

```python
            problems.append(f"UNEXPECTED (no file): {d['message']}")

    files = report["files"]
    docs = report["rules"] + report["filters"] + report["correlations_skipped"]
    ok = files - len(failing)

    if files == 0 or report["rules"] == 0:
        problems.append(f"degenerate report: files={files}, rules={report['rules']}")
    # Every file that did not fail must have produced at least one document
    # (rule, filter or skipped correlation). Multi-document files only raise the
    # document count, so this lower bound cannot be gamed by them; it catches a
    # run that silently scanned nothing for most files.
    if ok > docs:
```

with:

```python
            problems.append(f"UNEXPECTED (no file): {d['message']}")

    files = report["files"]
    docs = (report["rules"] + report["filters"] + report.get("correlations", 0)
            + report["correlations_skipped"])
    ok = files - len(failing)

    if files == 0 or report["rules"] == 0:
        problems.append(f"degenerate report: files={files}, rules={report['rules']}")
    # Every file that did not fail must have produced at least one document
    # (rule, filter, correlation or skipped correlation). Multi-document files only raise the
    # document count, so this lower bound cannot be gamed by them; it catches a
    # run that silently scanned nothing for most files.
    if ok > docs:
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-ir && cargo test -p zaaf-cli --test check && python3 -I scripts/test_compare_known_unsupported.py`
Expected: PASS (zaaf-ir: 74 tests, 7 of them in `correlation::tests` and `correlations_are_skipped_with_the_rules_the_total_budget_skipped` in `rule::tests`; check: 18 tests; Python: OK). Workspace total: 264.

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add crates/zaaf-cli/src/check.rs crates/zaaf-cli/tests/check.rs crates/zaaf-ir/src/correlation.rs crates/zaaf-ir/src/lib.rs crates/zaaf-ir/src/rule.rs scripts/compare_known_unsupported.py scripts/test_compare_known_unsupported.py
git commit -m "feat(ir,cli): compile correlation rules and lint their references" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 4: zaaf-correlate: alerts and the sliding window

Creates the `zaaf-correlate` crate (`publish = false`, like every crate on `main`) with its value types and the one window implementation that serves every correlation type (decisions M2-D2, M2-D5, M2-D6, M2-D7, M2-D13). The window keeps entries in time order and updates every aggregate incrementally when an entry enters or leaves.

**Files:**
- Create: `crates/zaaf-correlate/Cargo.toml`
- Create: `crates/zaaf-correlate/src/lib.rs`
- Create: `crates/zaaf-correlate/src/alert.rs`
- Create: `crates/zaaf-correlate/src/window.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: `zaaf_sigma::CorrelationType`.
- Produces (in `zaaf_correlate`):
  - `type FieldText = Vec<String>;`
  - `enum AggValue { Num(f64), Key(Vec<FieldText>) }`.
  - `enum Contributor<R> { Match { rule: usize, time_ms: i64, reference: R }, Alert(Box<CorrelationAlert<R>>) }` with `time_ms()`, `first_ms()`, `matches() -> Vec<(usize, i64, &R)>`.
  - `struct CorrelationAlert<R> { correlation: usize, time_ms: i64, first_ms: i64, group: Vec<FieldText>, value: f64, contributors: Vec<Contributor<R>> }` with `matches()` (every single-event match below it, through chains).
  - `zaaf_correlate::window::{Entry<R>, Window<R>}`: `Window::new(inputs)`, `len`, `is_empty`, `newest_ms`, `oldest_ms`, `expire_before(cutoff_ms)`, `push(entry, max_entries) -> u64` (dropped count), `aggregate(kind, arriving: Option<&AggValue>) -> Option<f64>`, `into_contributors()`.

- [ ] **Step 1: Write the failing tests**

Step 1 creates the crate skeleton and its plain data types (`alert.rs`), then the window's test module.

In `Cargo.toml`, replace:

```toml
zaaf-eval = { path = "crates/zaaf-eval", version = "0.0.1" }
zaaf-input = { path = "crates/zaaf-input", version = "0.0.1" }
zaaf-testkit = { path = "crates/zaaf-testkit", version = "0.0.1" }

[profile.release]
# panic must stay "unwind": zaaf maps panics to exit code 4 via catch_unwind.
```

with:

```toml
zaaf-eval = { path = "crates/zaaf-eval", version = "0.0.1" }
zaaf-input = { path = "crates/zaaf-input", version = "0.0.1" }
zaaf-testkit = { path = "crates/zaaf-testkit", version = "0.0.1" }
zaaf-correlate = { path = "crates/zaaf-correlate", version = "0.0.1" }

[profile.release]
# panic must stay "unwind": zaaf maps panics to exit code 4 via catch_unwind.
```

Create `crates/zaaf-correlate/Cargo.toml`:

```toml
[package]
name = "zaaf-correlate"
description = "The stateful Sigma correlation engine of ZAAFElegia"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
zaaf-event.workspace = true
zaaf-ir.workspace = true
zaaf-sigma.workspace = true

[dev-dependencies]
serde_json.workspace = true
zaaf-pipeline.workspace = true
```

Create `crates/zaaf-correlate/src/lib.rs`:

```rust
//! The one stateful Sigma correlator of ZAAFElegia (design spec §3.2, §3.3).
//!
//! It consumes single-event rule matches in time order and emits correlation alerts.
//! Every evaluation path (the native stream evaluator now, DataFusion in M4) feeds it,
//! so correlation semantics exist exactly once.

mod alert;
pub mod window;

pub use alert::{AggValue, Contributor, CorrelationAlert, FieldText};
```

Create `crates/zaaf-correlate/src/alert.rs`:

```rust
//! Values carried through the correlator and the alerts it emits.

/// The non-null scalar values of one field, as text, in event order. An array field
/// gives several entries; a missing or all-null field gives no `FieldText` at all.
pub type FieldText = Vec<String>;

/// The value one contribution adds to a value_* aggregate.
#[derive(Debug, Clone, PartialEq)]
pub enum AggValue {
    /// `value_sum`, `value_avg`, `value_median`: a finite number.
    Num(f64),
    /// `value_count`, `value_percentile`: the texts of the condition field(s).
    Key(Vec<FieldText>),
}

/// What contributed to a correlation alert. `R` is the caller's reference to the
/// single-event match (for the CLI: the finding uid and where the event came from).
#[derive(Debug, Clone, PartialEq)]
pub enum Contributor<R> {
    Match {
        /// Index into the compiled rules.
        rule: usize,
        time_ms: i64,
        reference: R,
    },
    /// An alert of a referenced (inner) correlation.
    Alert(Box<CorrelationAlert<R>>),
}

impl<R> Contributor<R> {
    /// When this contribution entered the window (an inner alert: when it fired).
    pub fn time_ms(&self) -> i64 {
        match self {
            Self::Match { time_ms, .. } => *time_ms,
            Self::Alert(a) => a.time_ms,
        }
    }

    /// Time of the earliest single-event match below this contribution.
    pub fn first_ms(&self) -> i64 {
        match self {
            Self::Match { time_ms, .. } => *time_ms,
            Self::Alert(a) => a.first_ms,
        }
    }

    /// Every single-event match below this contributor, depth first.
    pub fn matches(&self) -> Vec<(usize, i64, &R)> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect<'a>(&'a self, out: &mut Vec<(usize, i64, &'a R)>) {
        match self {
            Self::Match {
                rule,
                time_ms,
                reference,
            } => out.push((*rule, *time_ms, reference)),
            Self::Alert(a) => a.contributors.iter().for_each(|c| c.collect(out)),
        }
    }
}

/// One correlation hit.
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationAlert<R> {
    /// Index into the compiled correlations.
    pub correlation: usize,
    /// Time of the contribution that made the condition true.
    pub time_ms: i64,
    /// Time of the earliest single-event match below this alert (through chains).
    pub first_ms: i64,
    /// One value per `group-by` name, in order (empty without `group-by`).
    pub group: Vec<FieldText>,
    /// The aggregate that satisfied the condition: a count, a sum, an average, a
    /// median or a percentage.
    pub value: f64,
    /// Every contribution in the window, oldest first.
    pub contributors: Vec<Contributor<R>>,
}

impl<R> CorrelationAlert<R> {
    /// Every single-event match below this alert (through chained alerts), oldest first.
    pub fn matches(&self) -> Vec<(usize, i64, &R)> {
        let mut out = Vec::new();
        for c in &self.contributors {
            c.collect(&mut out);
        }
        out
    }
}
```

Create `crates/zaaf-correlate/src/window.rs` containing only this test module for now (Step 3 puts the implementation above it):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn entry(time_ms: i64, input: usize, value: Option<AggValue>) -> Entry<u32> {
        Entry {
            time_ms,
            input,
            value,
            contributor: Contributor::Match {
                rule: input,
                time_ms,
                reference: time_ms as u32,
            },
        }
    }

    fn key(s: &str) -> Option<AggValue> {
        Some(AggValue::Key(vec![vec![s.to_string()]]))
    }

    fn num(x: f64) -> Option<AggValue> {
        Some(AggValue::Num(x))
    }

    #[test]
    fn ord_key_round_trips_and_orders() {
        let xs = [-1e300, -2.5, -0.0, 0.0, 1.0, 3.5, 1e300];
        for w in xs.windows(2) {
            assert!(ord_key(w[0]) <= ord_key(w[1]), "{w:?}");
        }
        for x in xs {
            assert_eq!(from_ord_key(ord_key(x)), x);
        }
    }

    #[test]
    fn event_count_and_inclusive_expiry() {
        let mut w = Window::new(1);
        for t in [0, 1000, 5000] {
            w.push(entry(t, 0, None), 100);
        }
        w.expire_before(5000 - 5000);
        assert_eq!(w.aggregate(CorrelationType::EventCount, None), Some(3.0));
        w.expire_before(5001 - 5000);
        assert_eq!(w.aggregate(CorrelationType::EventCount, None), Some(2.0));
        assert_eq!(w.oldest_ms(), Some(1000));
        assert_eq!(w.newest_ms(), Some(5000));
    }

    #[test]
    fn value_count_and_percentile_track_expiry() {
        let mut w = Window::new(1);
        w.push(entry(0, 0, key("a")), 100);
        w.push(entry(1, 0, key("b")), 100);
        w.push(entry(2, 0, key("a")), 100);
        w.push(entry(3, 0, None), 100);
        assert_eq!(w.aggregate(CorrelationType::ValueCount, None), Some(2.0));
        let a = key("a").unwrap();
        let b = key("b").unwrap();
        let pa = w
            .aggregate(CorrelationType::ValuePercentile, Some(&a))
            .unwrap();
        assert!((pa - 200.0 / 3.0).abs() < 1e-9, "{pa}");
        assert_eq!(w.aggregate(CorrelationType::ValuePercentile, None), None);
        w.expire_before(2);
        assert_eq!(w.aggregate(CorrelationType::ValueCount, None), Some(1.0));
        assert_eq!(
            w.aggregate(CorrelationType::ValuePercentile, Some(&b)),
            Some(0.0)
        );
        w.expire_before(4);
        assert_eq!(w.aggregate(CorrelationType::ValueCount, None), None);
    }

    #[test]
    fn sum_avg_median() {
        let mut w = Window::new(1);
        for (t, x) in [(0, 10.0), (1, 1.0), (2, 4.0), (3, 7.0)] {
            w.push(entry(t, 0, num(x)), 100);
        }
        w.push(entry(4, 0, None), 100);
        assert_eq!(w.aggregate(CorrelationType::ValueSum, None), Some(22.0));
        assert_eq!(w.aggregate(CorrelationType::ValueAvg, None), Some(5.5));
        assert_eq!(w.aggregate(CorrelationType::ValueMedian, None), Some(5.5));
        w.expire_before(1);
        assert_eq!(w.aggregate(CorrelationType::ValueSum, None), Some(12.0));
        assert_eq!(w.aggregate(CorrelationType::ValueAvg, None), Some(4.0));
        assert_eq!(w.aggregate(CorrelationType::ValueMedian, None), Some(4.0));
        w.expire_before(4);
        assert_eq!(w.aggregate(CorrelationType::ValueSum, None), None);
        assert_eq!(w.aggregate(CorrelationType::ValueMedian, None), None);
        assert_eq!(w.aggregate(CorrelationType::EventCount, None), Some(1.0));
    }

    #[test]
    fn median_with_duplicates() {
        let mut w = Window::new(1);
        for (t, x) in [(0, 2.0), (1, 2.0), (2, 9.0)] {
            w.push(entry(t, 0, num(x)), 100);
        }
        assert_eq!(w.aggregate(CorrelationType::ValueMedian, None), Some(2.0));
        w.push(entry(3, 0, num(9.0)), 100);
        assert_eq!(w.aggregate(CorrelationType::ValueMedian, None), Some(5.5));
    }

    #[test]
    fn temporal_counts_distinct_inputs() {
        let mut w = Window::new(3);
        w.push(entry(0, 2, None), 100);
        w.push(entry(1, 2, None), 100);
        assert_eq!(w.aggregate(CorrelationType::Temporal, None), Some(1.0));
        w.push(entry(2, 0, None), 100);
        assert_eq!(w.aggregate(CorrelationType::Temporal, None), Some(2.0));
        w.expire_before(2);
        assert_eq!(w.aggregate(CorrelationType::Temporal, None), Some(1.0));
    }

    #[test]
    fn temporal_ordered_prefix_allows_equal_times() {
        let mut w = Window::new(3);
        // c, b, a in time: only the first input is in order.
        w.push(entry(0, 2, None), 100);
        w.push(entry(1, 1, None), 100);
        w.push(entry(2, 0, None), 100);
        assert_eq!(
            w.aggregate(CorrelationType::TemporalOrdered, None),
            Some(1.0)
        );
        w.push(entry(3, 1, None), 100);
        assert_eq!(
            w.aggregate(CorrelationType::TemporalOrdered, None),
            Some(2.0)
        );
        // Same time as the input 1 entry, arriving after it: still in order.
        w.push(entry(3, 2, None), 100);
        assert_eq!(
            w.aggregate(CorrelationType::TemporalOrdered, None),
            Some(3.0)
        );
        let mut tie = Window::new(2);
        tie.push(entry(5, 1, None), 100);
        tie.push(entry(5, 0, None), 100);
        assert_eq!(
            tie.aggregate(CorrelationType::TemporalOrdered, None),
            Some(2.0)
        );
    }

    #[test]
    fn entry_cap_drops_oldest() {
        let mut w = Window::new(1);
        let mut dropped = 0;
        for t in 0..5 {
            dropped += w.push(entry(t, 0, num(1.0)), 3);
        }
        assert_eq!(dropped, 2);
        assert_eq!(w.len(), 3);
        assert_eq!(w.oldest_ms(), Some(2));
        assert_eq!(w.aggregate(CorrelationType::ValueSum, None), Some(3.0));
        let refs: Vec<i64> = w.into_contributors().iter().map(|c| c.time_ms()).collect();
        assert_eq!(refs, vec![2, 3, 4]);
    }
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-correlate`
Expected: FAIL to compile: `Window`, `Entry` and `ord_key` are not defined (`window.rs` holds only tests so far).

- [ ] **Step 3: Implement**

At the top of `crates/zaaf-correlate/src/window.rs`, above `#[cfg(test)]`, add the implementation:

```rust
//! The sliding window of one correlation group and its incremental aggregates.
//!
//! One implementation serves every correlation type: entries are kept in time order and
//! every aggregate is updated when an entry enters or leaves, so evaluating a condition
//! costs at most O(log n) per input (`temporal_ordered`) or O(distinct values)
//! (`value_median`), both bounded by the per-group entry cap.

use crate::alert::{AggValue, Contributor, FieldText};
use std::collections::{BTreeMap, HashMap, VecDeque};
use zaaf_sigma::CorrelationType;

/// One contribution in a window.
#[derive(Debug, Clone)]
pub struct Entry<R> {
    pub time_ms: i64,
    /// Position of the input in the correlation's `rules`.
    pub input: usize,
    pub value: Option<AggValue>,
    pub contributor: Contributor<R>,
}

/// Total order on finite `f64` as `u64` (negative numbers first).
fn ord_key(x: f64) -> u64 {
    let b = x.to_bits();
    if b >> 63 == 1 { !b } else { b | (1 << 63) }
}

fn from_ord_key(k: u64) -> f64 {
    f64::from_bits(if k >> 63 == 1 { k & !(1 << 63) } else { !k })
}

/// The entries of one group inside its `timespan`, with incremental aggregates.
#[derive(Debug)]
pub struct Window<R> {
    entries: VecDeque<Entry<R>>,
    /// Entry times per input, oldest first (for `temporal`/`temporal_ordered`).
    times: Vec<VecDeque<i64>>,
    /// Occurrences of each `Key` value (`value_count`, `value_percentile`).
    distinct: HashMap<Vec<FieldText>, u32>,
    /// Running sum, count and sorted multiset of `Num` values.
    sum: f64,
    numbers: u64,
    sorted: BTreeMap<u64, u32>,
    keys: u64,
}

impl<R> Window<R> {
    /// `inputs` is the number of rules the correlation references.
    pub fn new(inputs: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            times: vec![VecDeque::new(); inputs],
            distinct: HashMap::new(),
            sum: 0.0,
            numbers: 0,
            sorted: BTreeMap::new(),
            keys: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn newest_ms(&self) -> Option<i64> {
        self.entries.back().map(|e| e.time_ms)
    }

    /// Drops every entry older than `cutoff_ms` (the window is `[cutoff, now]`, inclusive).
    pub fn expire_before(&mut self, cutoff_ms: i64) {
        while self.entries.front().is_some_and(|e| e.time_ms < cutoff_ms) {
            self.pop_front();
        }
    }

    /// Adds an entry at the newest end; returns how many old entries were dropped to
    /// stay within `max_entries`.
    pub fn push(&mut self, e: Entry<R>, max_entries: usize) -> u64 {
        let mut dropped = 0;
        while self.entries.len() >= max_entries.max(1) {
            self.pop_front();
            dropped += 1;
        }
        if let Some(t) = self.times.get_mut(e.input) {
            t.push_back(e.time_ms);
        }
        match &e.value {
            Some(AggValue::Num(x)) => {
                self.sum += x;
                self.numbers += 1;
                *self.sorted.entry(ord_key(*x)).or_insert(0) += 1;
            }
            Some(AggValue::Key(k)) => {
                self.keys += 1;
                *self.distinct.entry(k.clone()).or_insert(0) += 1;
            }
            None => {}
        }
        self.entries.push_back(e);
        dropped
    }

    fn pop_front(&mut self) {
        let Some(e) = self.entries.pop_front() else {
            return;
        };
        if let Some(t) = self.times.get_mut(e.input) {
            t.pop_front();
        }
        match &e.value {
            Some(AggValue::Num(x)) => {
                self.numbers -= 1;
                // Recompute from scratch when empty so rounding errors do not linger.
                self.sum = if self.numbers == 0 { 0.0 } else { self.sum - x };
                let k = ord_key(*x);
                if let Some(n) = self.sorted.get_mut(&k) {
                    *n -= 1;
                    if *n == 0 {
                        self.sorted.remove(&k);
                    }
                }
            }
            Some(AggValue::Key(k)) => {
                self.keys -= 1;
                if let Some(n) = self.distinct.get_mut(k) {
                    *n -= 1;
                    if *n == 0 {
                        self.distinct.remove(k);
                    }
                }
            }
            None => {}
        }
    }

    /// The aggregate the condition is compared with, or `None` when it is undefined
    /// (no value in the window, or the arriving entry has no value for
    /// `value_percentile`).
    pub fn aggregate(&self, kind: CorrelationType, arriving: Option<&AggValue>) -> Option<f64> {
        match kind {
            CorrelationType::EventCount => Some(self.entries.len() as f64),
            CorrelationType::Temporal => {
                Some(self.times.iter().filter(|t| !t.is_empty()).count() as f64)
            }
            CorrelationType::TemporalOrdered => Some(self.ordered_prefix() as f64),
            CorrelationType::ValueCount => (self.keys > 0).then_some(self.distinct.len() as f64),
            CorrelationType::ValueSum => (self.numbers > 0).then_some(self.sum),
            CorrelationType::ValueAvg => (self.numbers > 0).then(|| self.sum / self.numbers as f64),
            CorrelationType::ValueMedian => self.median(),
            CorrelationType::ValuePercentile => match arriving {
                Some(AggValue::Key(k)) if self.keys > 0 => {
                    let n = self.distinct.get(k).copied().unwrap_or(0);
                    Some(100.0 * n as f64 / self.keys as f64)
                }
                _ => None,
            },
        }
    }

    /// Length of the longest prefix of the inputs that occurs in order: input 0 at t0,
    /// input 1 at t1 >= t0, and so on. Equal times count as in order.
    fn ordered_prefix(&self) -> usize {
        let mut after = i64::MIN;
        for (k, times) in self.times.iter().enumerate() {
            let i = times.partition_point(|t| *t < after);
            match times.get(i) {
                Some(t) => after = *t,
                None => return k,
            }
        }
        self.times.len()
    }

    fn median(&self) -> Option<f64> {
        if self.numbers == 0 {
            return None;
        }
        let n = self.numbers;
        let (lo, hi) = ((n - 1) / 2, n / 2);
        let (mut seen, mut lo_v, mut hi_v) = (0u64, None, None);
        for (k, c) in &self.sorted {
            let next = seen + u64::from(*c);
            if lo_v.is_none() && lo < next {
                lo_v = Some(from_ord_key(*k));
            }
            if hi < next {
                hi_v = Some(from_ord_key(*k));
                break;
            }
            seen = next;
        }
        Some((lo_v? + hi_v?) / 2.0)
    }

    /// Time of the oldest entry.
    pub fn oldest_ms(&self) -> Option<i64> {
        self.entries.front().map(|e| e.time_ms)
    }

    pub fn into_contributors(self) -> Vec<Contributor<R>> {
        self.entries.into_iter().map(|e| e.contributor).collect()
    }
}

```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-correlate`
Expected: PASS (8 tests in `window::tests`). Workspace total: 272.

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add Cargo.toml Cargo.lock crates/zaaf-correlate
git commit -m "feat(correlate): new crate with alert types and the sliding window" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 5: zaaf-correlate: the correlator (groups, conditions, chaining, memory cap)

`Correlator<R>` turns a rule match into an `Observation` (only the group values and aggregate value each consuming correlation needs) and processes observations in time order: groups, window expiry, condition, alert, group reset, chaining into outer correlations, missing group-by counting, the group cap with LRU eviction, and the per-group entry cap (decisions M2-D2, M2-D3, M2-D9, M2-D13). The integration tests compile real rules and drive them with `zaaf-eval`.

**Files:**
- Create: `crates/zaaf-correlate/tests/correlator.rs`
- Create: `crates/zaaf-correlate/src/correlator.rs`
- Modify: `crates/zaaf-correlate/Cargo.toml`
- Modify: `crates/zaaf-correlate/src/lib.rs`

**Interfaces:**
- Consumes: Task 3's `CompiledCorrelation`, `FieldSource`, `InputSource`; Task 4's `Window`, `Entry`, `AggValue`, `Contributor`, `CorrelationAlert`, `FieldText`; `zaaf_event::Event`.
- Produces (re-exported from `zaaf_correlate`):
  - `pub const DEFAULT_MAX_GROUPS: usize = 100_000; pub const DEFAULT_MAX_ENTRIES_PER_GROUP: usize = 65_536;`
  - `struct Limits { max_groups: usize, max_entries_per_group: usize }` (`Default`).
  - `struct Part { correlation: usize, input: usize, group: Option<Vec<FieldText>>, value: Option<AggValue> }`.
  - `struct Observation<R> { time_ms: i64, rule: usize, reference: R, parts: Vec<Part> }`.
  - `struct Stats { alerts: u64, evicted_groups: u64, truncated_entries: u64, missing_group_by: Vec<u64> }`.
  - `Correlator<R: Clone>`: `new(correlations, rule_count, limits)`, `correlations()`, `stats()`, `open_groups()`, `consumes(rule) -> bool`, `observe(rule, &dyn Event, time_ms, reference) -> Option<Observation<R>>`, `process(Observation<R>) -> Vec<CorrelationAlert<R>>`.

- [ ] **Step 1: Write the failing tests**

In `crates/zaaf-correlate/Cargo.toml`, replace:

```toml
[dev-dependencies]
serde_json.workspace = true
zaaf-pipeline.workspace = true
```

with:

```toml
[dev-dependencies]
serde_json.workspace = true
zaaf-pipeline.workspace = true
zaaf-eval.workspace = true
```

Create `crates/zaaf-correlate/tests/correlator.rs`:

```rust
use serde_json::{Value, json};
use zaaf_correlate::{Contributor, Correlator, Limits, Stats};
use zaaf_eval::Evaluator;
use zaaf_event::{Event, JsonEvent};
use zaaf_ir::{SourcedDocument, compile};
use zaaf_pipeline::PipelineSet;

/// Rule `id` matching events whose `EventID` equals `event_id`.
fn rule(id: &str, event_id: u32) -> String {
    format!(
        "title: {id}\nid: {id}\nname: {id}\nlogsource:\n    product: test\ndetection:\n    s:\n        EventID: {event_id}\n    condition: s\n"
    )
}

/// Compiles `src`, feeds `events` (in order, reference = event index) and returns
/// `(correlation id, contributing event indexes)` per alert, plus the statistics.
fn run_with(src: &str, events: &[Value], limits: Limits) -> (Vec<(String, Vec<usize>)>, Stats) {
    let parsed = zaaf_sigma::parse_str(src);
    assert!(
        parsed.diagnostics.iter().all(|d| !d.is_error()),
        "{:?}",
        parsed.diagnostics
    );
    let out = compile(
        parsed
            .documents
            .into_iter()
            .map(|document| SourcedDocument {
                document,
                source: None,
            })
            .collect(),
        &PipelineSet::default(),
    );
    assert!(
        out.diagnostics.iter().all(|d| !d.is_error()),
        "{:?}",
        out.diagnostics
    );
    let rule_count = out.rules.len();
    let evaluator = Evaluator::new(out.rules);
    let mut correlator: Correlator<usize> = Correlator::new(out.correlations, rule_count, limits);
    let mut alerts = Vec::new();
    for (i, v) in events.iter().enumerate() {
        let event = JsonEvent::new(v.clone());
        let ts = event.timestamp().expect("test events have timestamps");
        for rule in evaluator.matching_rules(&event) {
            if let Some(obs) = correlator.observe(rule, &event, ts.timestamp_millis(), i) {
                alerts.extend(correlator.process(obs));
            }
        }
    }
    let ids = alerts
        .iter()
        .map(|a| {
            let mut idx: Vec<usize> = a.matches().iter().map(|(_, _, r)| **r).collect();
            idx.sort();
            idx.dedup();
            (
                correlator.correlations()[a.correlation].info.id.clone(),
                idx,
            )
        })
        .collect();
    (ids, correlator.stats().clone())
}

fn run(src: &str, events: &[Value]) -> Vec<(String, Vec<usize>)> {
    run_with(src, events, Limits::default()).0
}

/// An event at `secs` seconds after 2026-11-07T00:00:00Z.
fn ev(secs: i64, event_id: u32, extra: Value) -> Value {
    let mut v = json!({
        "@timestamp": chrono_like(secs),
        "EventID": event_id,
    });
    if let (Value::Object(m), Value::Object(x)) = (&mut v, extra) {
        m.extend(x);
    }
    v
}

fn chrono_like(secs: i64) -> String {
    let (h, m, s) = (secs / 3600, (secs / 60) % 60, secs % 60);
    format!("2026-11-07T{h:02}:{m:02}:{s:02}Z")
}

fn s(v: &[(&str, &[usize])]) -> Vec<(String, Vec<usize>)> {
    v.iter()
        .map(|(id, e)| (id.to_string(), e.to_vec()))
        .collect()
}

const COUNT3: &str = "title: c\nid: c\ncorrelation:\n    type: event_count\n    rules: [r1]\n    group-by: [User]\n    timespan: 5m\n    condition:\n        gte: 3\n";

#[test]
fn event_count_per_group_with_inclusive_window_and_reset() {
    let src = format!("{}---\n{COUNT3}", rule("r1", 1));
    let a = json!({"User": "alice"});
    let b = json!({"User": "bob"});
    let events = vec![
        ev(0, 1, a.clone()),
        ev(10, 1, b.clone()),
        ev(60, 1, a.clone()),
        ev(300, 1, a.clone()), // exactly 5m after the first: inside the window
        ev(301, 1, a.clone()), // the group was cleared by the alert
        ev(302, 1, b.clone()),
        ev(311, 1, b.clone()), // bob: 10s is now 301s old, outside 5m
    ];
    assert_eq!(run(&src, &events), s(&[("c", &[0, 2, 3])]));
}

#[test]
fn just_outside_the_window_does_not_count() {
    let src = format!(
        "{}---\ntitle: c\nid: c\ncorrelation:\n    type: event_count\n    rules: [r1]\n    group-by: [User]\n    timespan: 10s\n    condition:\n        gte: 2\n",
        rule("r1", 1)
    );
    let u = json!({"User": "u"});
    assert!(run(&src, &[ev(0, 1, u.clone()), ev(11, 1, u.clone())]).is_empty());
    assert_eq!(
        run(&src, &[ev(0, 1, u.clone()), ev(10, 1, u.clone())]),
        s(&[("c", &[0, 1])])
    );
}

#[test]
fn missing_group_by_field_is_counted_not_grouped() {
    let src = format!("{}---\n{COUNT3}", rule("r1", 1));
    let events = vec![
        ev(0, 1, json!({})),
        ev(1, 1, json!({"User": null})),
        ev(2, 1, json!({"User": []})),
    ];
    let (alerts, stats) = run_with(&src, &events, Limits::default());
    assert!(alerts.is_empty());
    assert_eq!(stats.missing_group_by, vec![3]);
}

#[test]
fn no_group_by_is_one_group() {
    let src = format!(
        "{}---\ntitle: c\nid: c\ncorrelation:\n    type: event_count\n    rules: [r1]\n    timespan: 5m\n    condition:\n        gte: 2\n",
        rule("r1", 1)
    );
    let events = vec![ev(0, 1, json!({"User": "a"})), ev(1, 1, json!({}))];
    assert_eq!(run(&src, &events), s(&[("c", &[0, 1])]));
}

#[test]
fn value_count_counts_distinct_values() {
    let src = format!(
        "{}---\ntitle: c\nid: c\ncorrelation:\n    type: value_count\n    rules: [r1]\n    group-by: [Host]\n    timespan: 5m\n    condition:\n        field: User\n        gte: 3\n",
        rule("r1", 1)
    );
    let h = |u: &str| json!({"Host": "h1", "User": u});
    let events = vec![
        ev(0, 1, h("a")),
        ev(1, 1, h("a")),
        ev(2, 1, h("b")),
        ev(3, 1, json!({"Host": "h1"})), // no User: counted as an event, adds no value
        ev(4, 1, h("A")),                // values are case-sensitive
    ];
    assert_eq!(run(&src, &events), s(&[("c", &[0, 1, 2, 3, 4])]));
}

#[test]
fn value_sum_avg_and_median() {
    let corr = |kind: &str, cond: &str| {
        format!(
            "{}---\ntitle: c\nid: c\ncorrelation:\n    type: {kind}\n    rules: [r1]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        field: bytes\n        {cond}\n",
            rule("r1", 1)
        )
    };
    let b = |n: Value| json!({"User": "u", "bytes": n});
    let events = vec![
        ev(0, 1, b(json!(100))),
        ev(1, 1, b(json!("250"))),
        ev(2, 1, b(json!("n/a"))),
        ev(3, 1, b(json!(700))),
    ];
    assert_eq!(
        run(&corr("value_sum", "gt: 1000"), &events),
        s(&[("c", &[0, 1, 2, 3])])
    );
    assert!(run(&corr("value_sum", "gt: 1050"), &events).is_empty());
    // Averages over numeric values only: (100 + 250) / 2 = 175 at event 1. The alert
    // clears the group; event 2 has no number, event 3 alone averages 700.
    assert_eq!(
        run(&corr("value_avg", "gte: 175"), &events),
        s(&[("c", &[0, 1]), ("c", &[2, 3])])
    );
    // Median of 100, 250, 700 is 250, reached at event 3 (event 1 has median 175).
    assert_eq!(
        run(&corr("value_median", "eq: 250"), &events),
        s(&[("c", &[0, 1, 2, 3])])
    );
}

#[test]
fn value_percentile_is_the_share_of_the_arriving_value() {
    let src = format!(
        "{}---\ntitle: c\nid: c\ncorrelation:\n    type: value_percentile\n    rules: [r1]\n    group-by: [Host]\n    timespan: 1h\n    condition:\n        field: Image\n        lte: 25\n",
        rule("r1", 1)
    );
    let p = |i: &str| json!({"Host": "h", "Image": i});
    let events = vec![
        ev(0, 1, p("svchost.exe")),
        ev(1, 1, p("svchost.exe")),
        ev(2, 1, p("svchost.exe")),
        ev(3, 1, p("evil.exe")), // 1 of 4 = 25%
    ];
    assert_eq!(run(&src, &events), s(&[("c", &[0, 1, 2, 3])]));
}

#[test]
fn temporal_with_aliases_any_order() {
    let src = format!(
        "{}---\n{}---\ntitle: c\nid: c\ncorrelation:\n    type: temporal\n    rules: [err, conn]\n    group-by: [internal_ip]\n    timespan: 10s\n    aliases:\n        internal_ip:\n            err: destination.ip\n            conn: source.ip\n",
        rule("err", 1),
        rule("conn", 2),
    );
    let events = vec![
        ev(0, 2, json!({"source.ip": "10.0.0.1"})),
        ev(1, 1, json!({"destination.ip": "10.0.0.2"})),
        ev(5, 1, json!({"destination.ip": "10.0.0.1"})),
    ];
    assert_eq!(run(&src, &events), s(&[("c", &[0, 2])]));
}

#[test]
fn temporal_ordered_needs_the_listed_order() {
    let src = format!(
        "{}---\n{}---\ntitle: c\nid: c\ncorrelation:\n    type: temporal_ordered\n    rules: [first, second]\n    group-by: [User]\n    timespan: 1m\n",
        rule("first", 1),
        rule("second", 2),
    );
    let u = json!({"User": "u"});
    assert!(run(&src, &[ev(0, 2, u.clone()), ev(1, 1, u.clone())]).is_empty());
    assert_eq!(
        run(
            &src,
            &[
                ev(0, 2, u.clone()),
                ev(1, 1, u.clone()),
                ev(2, 2, u.clone())
            ]
        ),
        s(&[("c", &[0, 1, 2])])
    );
    // Equal timestamps count as in order, whatever the arrival order.
    assert_eq!(
        run(&src, &[ev(7, 2, u.clone()), ev(7, 1, u.clone())]),
        s(&[("c", &[0, 1])])
    );
}

#[test]
fn chained_correlations_follow_the_spec_example() {
    let src = format!(
        "title: brute then success\nid: outer\ncorrelation:\n    type: temporal_ordered\n    rules: [many_failed, ok]\n    group-by: [User]\n    timespan: 10m\n---\ntitle: many failed\nid: inner\nname: many_failed\ncorrelation:\n    type: event_count\n    rules: [failed]\n    group-by: [User]\n    timespan: 10m\n    condition:\n        gte: 3\n---\n{}---\n{}",
        rule("failed", 4625),
        rule("ok", 4624),
    );
    let u = json!({"User": "u"});
    let events = vec![
        ev(0, 4624, u.clone()),
        ev(10, 4625, u.clone()),
        ev(20, 4625, u.clone()),
        ev(30, 4625, u.clone()),
        ev(40, 4624, u.clone()),
    ];
    assert_eq!(
        run(&src, &events),
        s(&[("inner", &[1, 2, 3]), ("outer", &[0, 1, 2, 3, 4])])
    );
}

#[test]
fn chained_alert_is_a_nested_contributor() {
    let src = format!(
        "title: o\nid: o\ncorrelation:\n    type: event_count\n    rules: [i]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        gte: 1\n---\ntitle: i\nid: i\ncorrelation:\n    type: event_count\n    rules: [r1]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        gte: 2\n---\n{}",
        rule("r1", 1)
    );
    let parsed = zaaf_sigma::parse_str(&src);
    let out = compile(
        parsed
            .documents
            .into_iter()
            .map(|document| SourcedDocument {
                document,
                source: None,
            })
            .collect(),
        &PipelineSet::default(),
    );
    let mut c: Correlator<&str> = Correlator::new(out.correlations, 1, Limits::default());
    let e = JsonEvent::new(json!({"User": "u"}));
    assert!(c.process(c.observe(0, &e, 0, "a").unwrap()).is_empty());
    let alerts = c.process(c.observe(0, &e, 5, "b").unwrap());
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[1].group, vec![vec!["u".to_string()]]);
    // The outer alert's first match is the inner alert's first match, not its firing time.
    assert_eq!(alerts[1].first_ms, 0);
    assert_eq!(alerts[1].time_ms, 5);
    match &alerts[1].contributors[..] {
        [Contributor::Alert(inner)] => {
            assert_eq!(inner.correlation, 0);
            assert_eq!(inner.first_ms, 0);
            assert_eq!(inner.time_ms, 5);
            assert_eq!(inner.value, 2.0);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(c.stats().alerts, 2);
}

#[test]
fn upper_bounds_are_checked_on_every_contribution() {
    // `lt: 3` holds as soon as one event arrives: conditions are evaluated on the window
    // ending at each contribution, and an alert clears the group.
    let src = format!(
        "{}---\ntitle: c\nid: c\ncorrelation:\n    type: event_count\n    rules: [r1]\n    group-by: [User]\n    timespan: 5m\n    condition:\n        lt: 3\n",
        rule("r1", 1)
    );
    let u = json!({"User": "u"});
    assert_eq!(
        run(&src, &[ev(0, 1, u.clone()), ev(1, 1, u.clone())]),
        s(&[("c", &[0]), ("c", &[1])])
    );
}

#[test]
fn group_cap_evicts_the_least_recently_updated_group() {
    let src = format!("{}---\n{COUNT3}", rule("r1", 1));
    let u = |n: &str| json!({"User": n});
    let events = vec![
        ev(0, 1, u("a")),
        ev(1, 1, u("a")),
        ev(2, 1, u("b")),
        ev(3, 1, u("c")), // evicts a (least recently updated)
        ev(4, 1, u("a")), // a starts again from 1, evicting b
        ev(5, 1, u("c")),
        ev(6, 1, u("c")), // c reaches 3
    ];
    let limits = Limits {
        max_groups: 2,
        ..Limits::default()
    };
    let (alerts, stats) = run_with(&src, &events, limits);
    assert_eq!(alerts, s(&[("c", &[3, 5, 6])]));
    assert_eq!(stats.evicted_groups, 2);
}

#[test]
fn expired_groups_are_freed_without_counting_evictions() {
    let src = format!("{}---\n{COUNT3}", rule("r1", 1));
    let u = |n: &str| json!({"User": n});
    let events = vec![ev(0, 1, u("a")), ev(1000, 1, u("b")), ev(2000, 1, u("c"))];
    let limits = Limits {
        max_groups: 1,
        ..Limits::default()
    };
    let (_, stats) = run_with(&src, &events, limits);
    assert_eq!(stats.evicted_groups, 0);
}

#[test]
fn entry_cap_is_counted() {
    let src = format!(
        "{}---\ntitle: c\nid: c\ncorrelation:\n    type: value_count\n    rules: [r1]\n    group-by: [Host]\n    timespan: 1h\n    condition:\n        field: User\n        gte: 3\n",
        rule("r1", 1)
    );
    let h = |u: &str| json!({"Host": "h", "User": u});
    let events = vec![ev(0, 1, h("a")), ev(1, 1, h("b")), ev(2, 1, h("c"))];
    let limits = Limits {
        max_entries_per_group: 2,
        ..Limits::default()
    };
    let (alerts, stats) = run_with(&src, &events, limits);
    assert!(alerts.is_empty());
    assert_eq!(stats.truncated_entries, 1);
}

#[test]
fn observe_skips_rules_no_correlation_uses() {
    let src = format!("{}---\n{}---\n{COUNT3}", rule("r1", 1), rule("r2", 2));
    let parsed = zaaf_sigma::parse_str(&src);
    let out = compile(
        parsed
            .documents
            .into_iter()
            .map(|document| SourcedDocument {
                document,
                source: None,
            })
            .collect(),
        &PipelineSet::default(),
    );
    let c: Correlator<()> = Correlator::new(out.correlations, 2, Limits::default());
    let e = JsonEvent::new(json!({"User": "u"}));
    assert!(c.consumes(0));
    assert!(!c.consumes(1));
    assert!(c.observe(1, &e, 0, ()).is_none());
    let obs = c.observe(0, &e, 0, ()).unwrap();
    assert_eq!(obs.parts.len(), 1);
    assert_eq!(obs.parts[0].group, Some(vec![vec!["u".to_string()]]));
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-correlate --test correlator`
Expected: FAIL to compile: `unresolved imports zaaf_correlate::Correlator, zaaf_correlate::Limits, zaaf_correlate::Stats`.

- [ ] **Step 3: Implement**

Create `crates/zaaf-correlate/src/correlator.rs`:

```rust
//! Groups, windows, conditions, chaining and the memory cap.
//!
//! Semantics (recorded in the M2 plan and `conformance/README.md`):
//! - Contributions are processed in time order. For each one, the window of its group is
//!   `[t - timespan, t]` (both ends inclusive), where `t` is the contribution's time.
//! - The condition is evaluated after every contribution. When it holds, one alert is
//!   emitted with every contribution in the window, and the group is cleared, so a
//!   contribution never counts towards two alerts of the same correlation.
//! - A contribution whose group-by field is missing (or null) is not counted in any group;
//!   it is counted in [`Stats::missing_group_by`] instead.
//! - At most `max_groups` groups are open; opening another evicts the least recently
//!   updated one ([`Stats::evicted_groups`] counts evictions of groups that still had
//!   entries inside their timespan). A group keeps at most `max_entries_per_group`
//!   entries; older ones are dropped and counted in [`Stats::truncated_entries`].

use crate::alert::{AggValue, Contributor, CorrelationAlert, FieldText};
use crate::window::{Entry, Window};
use std::collections::{BTreeMap, HashMap, VecDeque};
use zaaf_event::Event;
use zaaf_ir::{CompiledCorrelation, FieldSource, InputSource};
use zaaf_sigma::CorrelationType;

/// Default for `zaaf hunt --max-correlation-groups`.
pub const DEFAULT_MAX_GROUPS: usize = 100_000;
/// Entries one group keeps at most; older entries are dropped (and counted).
pub const DEFAULT_MAX_ENTRIES_PER_GROUP: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_groups: usize,
    pub max_entries_per_group: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_groups: DEFAULT_MAX_GROUPS,
            max_entries_per_group: DEFAULT_MAX_ENTRIES_PER_GROUP,
        }
    }
}

/// What one match contributes to one correlation input.
#[derive(Debug, Clone, PartialEq)]
pub struct Part {
    pub correlation: usize,
    pub input: usize,
    /// `None` when a group-by field is missing.
    pub group: Option<Vec<FieldText>>,
    pub value: Option<AggValue>,
}

/// A single-event match reduced to what the correlations need. The event itself is not
/// kept, so buffering costs memory proportional to the detections, not the input.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation<R> {
    pub time_ms: i64,
    pub rule: usize,
    pub reference: R,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub alerts: u64,
    pub evicted_groups: u64,
    pub truncated_entries: u64,
    /// Per correlation: contributions dropped because a group-by field was missing.
    pub missing_group_by: Vec<u64>,
}

struct GroupState<R> {
    window: Window<R>,
    lru: (i64, u64),
}

type GroupKey = (usize, Vec<FieldText>);

pub struct Correlator<R> {
    correlations: Vec<CompiledCorrelation>,
    by_rule: Vec<Vec<(usize, usize)>>,
    by_correlation: Vec<Vec<(usize, usize)>>,
    groups: HashMap<GroupKey, GroupState<R>>,
    lru: BTreeMap<(i64, u64), GroupKey>,
    tick: u64,
    limits: Limits,
    stats: Stats,
}

/// The non-null values of the first of `names` that has any, as text.
fn field_text(event: &dyn Event, names: &[String]) -> Option<FieldText> {
    names.iter().find_map(|n| {
        let texts: FieldText = event
            .get(n)?
            .iter()
            .filter_map(|v| v.as_text().map(|t| t.into_owned()))
            .collect();
        (!texts.is_empty()).then_some(texts)
    })
}

fn first_number(texts: &FieldText) -> Option<f64> {
    texts
        .iter()
        .find_map(|t| t.trim().parse::<f64>().ok().filter(|x| x.is_finite()))
}

fn number_from_event(event: &dyn Event, names: &[String]) -> Option<f64> {
    names.iter().find_map(|n| {
        event
            .get(n)?
            .iter()
            .find_map(|v| v.as_f64().filter(|x| x.is_finite()))
    })
}

fn read(source: &FieldSource, event: Option<&dyn Event>, group: &[FieldText]) -> Option<FieldText> {
    match (source, event) {
        (FieldSource::Event(names), Some(e)) => field_text(e, names),
        (FieldSource::Group(p), None) => group.get(*p).cloned(),
        _ => None,
    }
}

/// Group key and aggregate value of one input, read from an event or from an inner
/// correlation's group values.
fn extract(
    kind: CorrelationType,
    group_by: &[FieldSource],
    value: &[FieldSource],
    event: Option<&dyn Event>,
    inner_group: &[FieldText],
) -> (Option<Vec<FieldText>>, Option<AggValue>) {
    let group: Option<Vec<FieldText>> = group_by
        .iter()
        .map(|s| read(s, event, inner_group))
        .collect();
    let value = match kind {
        CorrelationType::ValueSum | CorrelationType::ValueAvg | CorrelationType::ValueMedian => {
            value
                .first()
                .and_then(|s| match (s, event) {
                    (FieldSource::Event(names), Some(e)) => number_from_event(e, names),
                    _ => read(s, event, inner_group).as_ref().and_then(first_number),
                })
                .map(AggValue::Num)
        }
        CorrelationType::ValueCount | CorrelationType::ValuePercentile => value
            .iter()
            .map(|s| read(s, event, inner_group))
            .collect::<Option<Vec<FieldText>>>()
            .map(AggValue::Key),
        CorrelationType::EventCount
        | CorrelationType::Temporal
        | CorrelationType::TemporalOrdered => None,
    };
    (group, value)
}

struct Pending<R> {
    correlation: usize,
    input: usize,
    group: Option<Vec<FieldText>>,
    value: Option<AggValue>,
    contributor: Contributor<R>,
    time_ms: i64,
}

impl<R: Clone> Correlator<R> {
    pub fn new(correlations: Vec<CompiledCorrelation>, rule_count: usize, limits: Limits) -> Self {
        let mut by_rule = vec![Vec::new(); rule_count];
        let mut by_correlation = vec![Vec::new(); correlations.len()];
        for (c, corr) in correlations.iter().enumerate() {
            for (i, input) in corr.inputs.iter().enumerate() {
                let slot = match input.source {
                    InputSource::Rule(r) => by_rule.get_mut(r),
                    InputSource::Correlation(j) => by_correlation.get_mut(j),
                };
                if let Some(slot) = slot {
                    slot.push((c, i));
                }
            }
        }
        let stats = Stats {
            missing_group_by: vec![0; correlations.len()],
            ..Stats::default()
        };
        Self {
            correlations,
            by_rule,
            by_correlation,
            groups: HashMap::new(),
            lru: BTreeMap::new(),
            tick: 0,
            limits,
            stats,
        }
    }

    pub fn correlations(&self) -> &[CompiledCorrelation] {
        &self.correlations
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Number of open groups.
    pub fn open_groups(&self) -> usize {
        self.groups.len()
    }

    /// True when some correlation consumes matches of `rule`.
    pub fn consumes(&self, rule: usize) -> bool {
        self.by_rule.get(rule).is_some_and(|v| !v.is_empty())
    }

    /// Reduces a match of `rule` on `event` to an observation, or `None` when no
    /// correlation consumes the rule.
    pub fn observe(
        &self,
        rule: usize,
        event: &dyn Event,
        time_ms: i64,
        reference: R,
    ) -> Option<Observation<R>> {
        let consumers = self.by_rule.get(rule).filter(|v| !v.is_empty())?;
        let parts = consumers
            .iter()
            .map(|&(c, i)| {
                let corr = &self.correlations[c];
                let input = &corr.inputs[i];
                let (group, value) =
                    extract(corr.kind, &input.group_by, &input.value, Some(event), &[]);
                Part {
                    correlation: c,
                    input: i,
                    group,
                    value,
                }
            })
            .collect();
        Some(Observation {
            time_ms,
            rule,
            reference,
            parts,
        })
    }

    /// Processes one observation (callers feed them in time order) and returns the
    /// alerts it completes, including those of chained correlations.
    pub fn process(&mut self, obs: Observation<R>) -> Vec<CorrelationAlert<R>> {
        let mut queue: VecDeque<Pending<R>> = obs
            .parts
            .into_iter()
            .map(|p| Pending {
                correlation: p.correlation,
                input: p.input,
                group: p.group,
                value: p.value,
                contributor: Contributor::Match {
                    rule: obs.rule,
                    time_ms: obs.time_ms,
                    reference: obs.reference.clone(),
                },
                time_ms: obs.time_ms,
            })
            .collect();
        let mut out = Vec::new();
        while let Some(p) = queue.pop_front() {
            let Some(alert) = self.add(p) else {
                continue;
            };
            for &(c, i) in &self.by_correlation[alert.correlation] {
                let corr = &self.correlations[c];
                let input = &corr.inputs[i];
                let (group, value) =
                    extract(corr.kind, &input.group_by, &input.value, None, &alert.group);
                queue.push_back(Pending {
                    correlation: c,
                    input: i,
                    group,
                    value,
                    contributor: Contributor::Alert(Box::new(alert.clone())),
                    time_ms: alert.time_ms,
                });
            }
            self.stats.alerts += 1;
            out.push(alert);
        }
        out
    }

    fn add(&mut self, p: Pending<R>) -> Option<CorrelationAlert<R>> {
        self.expire_idle(p.time_ms);
        let Some(group) = p.group else {
            self.stats.missing_group_by[p.correlation] += 1;
            return None;
        };
        let key: GroupKey = (p.correlation, group);
        let (kind, timespan, inputs) = {
            let c = &self.correlations[p.correlation];
            (c.kind, c.timespan_ms, c.inputs.len())
        };
        if !self.groups.contains_key(&key) {
            self.make_room(p.time_ms);
            self.groups.insert(
                key.clone(),
                GroupState {
                    window: Window::new(inputs),
                    lru: (i64::MIN, 0),
                },
            );
        }
        self.tick += 1;
        let state = self.groups.get_mut(&key)?;
        self.lru.remove(&state.lru);
        state.lru = (p.time_ms, self.tick);
        self.lru.insert(state.lru, key.clone());
        state
            .window
            .expire_before(p.time_ms.saturating_sub(timespan));
        let arriving = p.value.clone();
        self.stats.truncated_entries += state.window.push(
            Entry {
                time_ms: p.time_ms,
                input: p.input,
                value: p.value,
                contributor: p.contributor,
            },
            self.limits.max_entries_per_group,
        );
        let value = state.window.aggregate(kind, arriving.as_ref())?;
        let bounds = &self.correlations[p.correlation].bounds;
        if !bounds.iter().all(|(op, b)| op.holds(value, *b)) {
            return None;
        }
        let state = self.groups.remove(&key)?;
        self.lru.remove(&state.lru);
        let contributors = state.window.into_contributors();
        Some(CorrelationAlert {
            correlation: key.0,
            time_ms: p.time_ms,
            first_ms: contributors
                .iter()
                .map(Contributor::first_ms)
                .min()
                .unwrap_or(p.time_ms),
            group: key.1,
            value,
            contributors,
        })
    }

    /// Drops groups whose newest entry has left their timespan (oldest updates first).
    fn expire_idle(&mut self, now_ms: i64) {
        while let Some((&(last, tick), key)) = self.lru.first_key_value() {
            let timespan = self.correlations[key.0].timespan_ms;
            if last >= now_ms.saturating_sub(timespan) {
                break;
            }
            let key = key.clone();
            self.lru.remove(&(last, tick));
            self.groups.remove(&key);
        }
    }

    /// Evicts least recently updated groups until another one fits.
    fn make_room(&mut self, now_ms: i64) {
        while self.groups.len() >= self.limits.max_groups.max(1) {
            let Some((_, key)) = self.lru.pop_first() else {
                break;
            };
            if let Some(state) = self.groups.remove(&key) {
                let timespan = self.correlations[key.0].timespan_ms;
                if state
                    .window
                    .newest_ms()
                    .is_some_and(|t| t >= now_ms.saturating_sub(timespan))
                {
                    self.stats.evicted_groups += 1;
                }
            }
        }
    }
}
```

In `crates/zaaf-correlate/src/lib.rs`, replace:

```rust
//! so correlation semantics exist exactly once.

mod alert;
pub mod window;

pub use alert::{AggValue, Contributor, CorrelationAlert, FieldText};
```

with:

```rust
//! so correlation semantics exist exactly once.

mod alert;
mod correlator;
pub mod window;

pub use alert::{AggValue, Contributor, CorrelationAlert, FieldText};
pub use correlator::{
    Correlator, DEFAULT_MAX_ENTRIES_PER_GROUP, DEFAULT_MAX_GROUPS, Limits, Observation, Part, Stats,
};
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-correlate`
Expected: PASS (8 unit tests, 16 in `tests/correlator.rs`). Workspace total: 288.

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add Cargo.lock crates/zaaf-correlate
git commit -m "feat(correlate): correlator with groups, chaining and a memory cap" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 6: zaaf-correlate: reorder buffer, watermark and the engine facade

The reorder buffer puts observations in time order behind a watermark and hands late ones back; `CorrelationEngine` combines it with the correlator and counts late matches per rule (decisions M2-D11, M2-D19). The CLI (Task 7) and the conformance runner (Task 8) both drive this one facade.

**Files:**
- Create: `crates/zaaf-correlate/tests/engine.rs`
- Create: `crates/zaaf-correlate/src/reorder.rs`
- Create: `crates/zaaf-correlate/src/engine.rs`
- Modify: `crates/zaaf-correlate/src/lib.rs`

**Interfaces:**
- Consumes: Task 5's `Correlator`, `Limits`, `Observation`, `Stats`; `zaaf_sigma::parse_timespan`.
- Produces (re-exported from `zaaf_correlate`):
  - `pub const DEFAULT_MAX_LATENESS_MS: i64 = 300_000; pub const DEFAULT_MAX_BUFFERED: usize = 1_000_000;`
  - `pub fn parse_lateness(s: &str) -> Option<i64>`.
  - `ReorderBuffer<T>`: `new(lateness_ms, max_buffered)`, `watermark()`, `len`, `is_empty`, `forced_releases()`, `push(time_ms, item) -> Result<Vec<T>, T>` (`Err` = late), `flush() -> Vec<T>`.
  - `struct EngineLimits { correlator: Limits, max_lateness_ms: i64, max_buffered: usize }` (`Default`).
  - `CorrelationEngine<R: Clone>`: `new(correlations, rule_count, limits)`, `correlations()`, `consumes(rule)`, `push(rule, &dyn Event, time_ms, reference) -> Vec<CorrelationAlert<R>>`, `finish() -> Vec<CorrelationAlert<R>>`, `late_matches() -> &[u64]` (per rule), `stats()`, `forced_releases()`.

- [ ] **Step 1: Write the failing tests**

Create `crates/zaaf-correlate/tests/engine.rs`:

```rust
use serde_json::{Value, json};
use zaaf_correlate::{CorrelationEngine, EngineLimits};
use zaaf_eval::Evaluator;
use zaaf_event::{Event, JsonEvent};
use zaaf_ir::{SourcedDocument, compile};
use zaaf_pipeline::PipelineSet;

const SRC: &str = "title: r1\nid: r1\nlogsource:\n    product: test\ndetection:\n    s:\n        EventID: 1\n    condition: s\n---\ntitle: r2\nid: r2\nlogsource:\n    product: test\ndetection:\n    s:\n        EventID: 2\n    condition: s\n---\ntitle: c\nid: c\ncorrelation:\n    type: temporal_ordered\n    rules: [r1, r2]\n    group-by: [User]\n    timespan: 1m\n";

fn ev(secs: u32, event_id: u32) -> Value {
    json!({
        "@timestamp": format!("2026-11-07T00:{:02}:{:02}Z", secs / 60, secs % 60),
        "EventID": event_id,
        "User": "u",
    })
}

/// Runs the engine over `events` in the given (arrival) order.
fn run(events: &[Value], max_lateness_ms: i64) -> (Vec<Vec<usize>>, Vec<u64>) {
    let parsed = zaaf_sigma::parse_str(SRC);
    let out = compile(
        parsed
            .documents
            .into_iter()
            .map(|document| SourcedDocument {
                document,
                source: None,
            })
            .collect(),
        &PipelineSet::default(),
    );
    let rule_count = out.rules.len();
    let evaluator = Evaluator::new(out.rules);
    let limits = EngineLimits {
        max_lateness_ms,
        ..EngineLimits::default()
    };
    let mut engine: CorrelationEngine<usize> =
        CorrelationEngine::new(out.correlations, rule_count, limits);
    let mut alerts = Vec::new();
    for (i, v) in events.iter().enumerate() {
        let event = JsonEvent::new(v.clone());
        let t = event.timestamp().unwrap().timestamp_millis();
        for r in evaluator.matching_rules(&event) {
            alerts.extend(engine.push(r, &event, t, i));
        }
    }
    alerts.extend(engine.finish());
    let idx = alerts
        .iter()
        .map(|a| a.matches().iter().map(|(_, _, r)| **r).collect())
        .collect();
    (idx, engine.late_matches().to_vec())
}

#[test]
fn out_of_order_within_lateness_is_reordered() {
    // Arrival: r2 at 0:10, then r1 at 0:05. In time order r1 precedes r2.
    let (alerts, late) = run(&[ev(10, 2), ev(5, 1)], 60_000);
    assert_eq!(alerts, vec![vec![1, 0]]);
    assert_eq!(late, vec![0, 0]);
}

#[test]
fn without_lateness_the_same_input_is_late_and_counted() {
    let (alerts, late) = run(&[ev(10, 2), ev(5, 1)], 0);
    assert!(alerts.is_empty());
    assert_eq!(late, vec![1, 0]);
}

#[test]
fn matches_beyond_the_watermark_are_late() {
    // Watermark after 3:00 with 1m lateness is 2:00; a 1:00 match is late.
    let (alerts, late) = run(&[ev(180, 2), ev(60, 1), ev(170, 1), ev(175, 2)], 60_000);
    assert_eq!(alerts, vec![vec![2, 3]]);
    assert_eq!(late, vec![1, 0]);
}

#[test]
fn finish_flushes_buffered_matches() {
    let (alerts, _) = run(&[ev(1, 1), ev(2, 2)], 3_600_000);
    assert_eq!(alerts, vec![vec![0, 1]]);
}
```

Create `crates/zaaf-correlate/src/reorder.rs` containing only this test module for now (Step 3 puts the implementation above it):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lateness_syntax() {
        assert_eq!(parse_lateness("0"), Some(0));
        assert_eq!(parse_lateness("0s"), Some(0));
        assert_eq!(parse_lateness("00m"), Some(0));
        assert_eq!(parse_lateness("30s"), Some(30_000));
        assert_eq!(parse_lateness("5m"), Some(DEFAULT_MAX_LATENESS_MS));
        for bad in ["", "s", "-1m", "5 minutes", "1w", "1.5m"] {
            assert_eq!(parse_lateness(bad), None, "{bad}");
        }
    }

    #[test]
    fn holds_until_the_watermark_then_releases_in_time_order() {
        let mut b = ReorderBuffer::new(10, 100);
        assert_eq!(b.push(100, "a"), Ok(vec![]));
        assert_eq!(b.push(95, "b"), Ok(vec![]));
        assert_eq!(b.watermark(), Some(90));
        // newest 111 -> watermark 101: 95 and 100 leave, in time order.
        assert_eq!(b.push(111, "c"), Ok(vec!["b", "a"]));
        assert_eq!(b.len(), 1);
        assert_eq!(b.flush(), vec!["c"]);
        assert!(b.is_empty());
    }

    #[test]
    fn late_items_are_handed_back() {
        let mut b = ReorderBuffer::new(10, 100);
        b.push(100, 1).unwrap();
        // Exactly at the watermark: not late, and released at once.
        assert_eq!(b.push(90, 2), Ok(vec![2]));
        assert_eq!(b.push(89, 3), Err(3));
        assert_eq!(b.push(200, 4), Ok(vec![1]));
        assert_eq!(b.push(195, 5), Ok(vec![]));
        assert_eq!(b.push(150, 6), Err(6));
    }

    #[test]
    fn zero_lateness_releases_immediately_and_keeps_ties() {
        let mut b = ReorderBuffer::new(0, 100);
        assert_eq!(b.push(5, 'a'), Ok(vec!['a']));
        assert_eq!(b.push(5, 'b'), Ok(vec!['b']));
        assert_eq!(b.push(4, 'c'), Err('c'));
    }

    #[test]
    fn full_buffer_releases_the_oldest_early() {
        let mut b = ReorderBuffer::new(1_000, 2);
        assert_eq!(b.push(10, 'a'), Ok(vec![]));
        assert_eq!(b.push(20, 'b'), Ok(vec![]));
        assert_eq!(b.push(15, 'c'), Ok(vec!['a']));
        assert_eq!(b.forced_releases(), 1);
        // 9 is inside the lateness window but older than the item released early (10).
        assert_eq!(b.push(9, 'd'), Err('d'));
        assert_eq!(b.flush(), vec!['c', 'b']);
    }
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-correlate --test engine`
Expected: FAIL to compile: `unresolved imports zaaf_correlate::CorrelationEngine, zaaf_correlate::EngineLimits`. (`reorder.rs` holds only tests and is not declared yet; Step 3 declares it.)

- [ ] **Step 3: Implement**

At the top of `crates/zaaf-correlate/src/reorder.rs`, above `#[cfg(test)]`, add the implementation:

```rust
//! Reorder buffer with a watermark (design spec §3.3).
//!
//! Items are held until the watermark (`newest time seen - max lateness`) passes them,
//! then released in time order (ties in arrival order). An item is *late* when its time
//! is before the watermark at its arrival, or before an item already released; late
//! items are handed back to the caller to count and report, never dropped silently.

use std::collections::BTreeMap;

/// Default for `zaaf hunt --max-lateness`: 5 minutes.
pub const DEFAULT_MAX_LATENESS_MS: i64 = 300_000;
/// Items held at most; beyond this the oldest is released early (and counted).
pub const DEFAULT_MAX_BUFFERED: usize = 1_000_000;

/// Parses a lateness: `0`, or a number followed by `s`, `m`, `h` or `d` (zero allowed,
/// at most 3650d), in milliseconds.
pub fn parse_lateness(s: &str) -> Option<i64> {
    let zero_digits = |d: &str| !d.is_empty() && d.bytes().all(|b| b == b'0');
    if zero_digits(s)
        || s.strip_suffix(['s', 'm', 'h', 'd'])
            .is_some_and(zero_digits)
    {
        return Some(0);
    }
    zaaf_sigma::parse_timespan(s)
}

#[derive(Debug)]
pub struct ReorderBuffer<T> {
    lateness_ms: i64,
    max_buffered: usize,
    newest: Option<i64>,
    /// Time of the last released item.
    released: i64,
    seq: u64,
    items: BTreeMap<(i64, u64), T>,
    forced: u64,
}

impl<T> ReorderBuffer<T> {
    pub fn new(lateness_ms: i64, max_buffered: usize) -> Self {
        Self {
            lateness_ms: lateness_ms.max(0),
            max_buffered: max_buffered.max(1),
            newest: None,
            released: i64::MIN,
            seq: 0,
            items: BTreeMap::new(),
            forced: 0,
        }
    }

    /// `newest time seen - max lateness`, once anything has been pushed.
    pub fn watermark(&self) -> Option<i64> {
        self.newest.map(|n| n.saturating_sub(self.lateness_ms))
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Items released early because the buffer was full.
    pub fn forced_releases(&self) -> u64 {
        self.forced
    }

    /// Adds an item. `Ok` holds the items now released, oldest first; `Err` hands a late
    /// item back.
    pub fn push(&mut self, time_ms: i64, item: T) -> Result<Vec<T>, T> {
        if self.watermark().is_some_and(|w| time_ms < w) || time_ms < self.released {
            return Err(item);
        }
        self.items.insert((time_ms, self.seq), item);
        self.seq += 1;
        self.newest = Some(self.newest.map_or(time_ms, |n| n.max(time_ms)));
        let mut out = Vec::new();
        let watermark = self.watermark().unwrap_or(i64::MIN);
        while let Some((&(t, _), _)) = self.items.first_key_value() {
            let full = self.items.len() > self.max_buffered;
            if t > watermark && !full {
                break;
            }
            if t > watermark {
                self.forced += 1;
            }
            self.released = t;
            if let Some((_, item)) = self.items.pop_first() {
                out.push(item);
            }
        }
        Ok(out)
    }

    /// Releases everything, oldest first (end of input).
    pub fn flush(&mut self) -> Vec<T> {
        if let Some((&(t, _), _)) = self.items.last_key_value() {
            self.released = self.released.max(t);
        }
        std::mem::take(&mut self.items).into_values().collect()
    }
}

```

Create `crates/zaaf-correlate/src/engine.rs`:

```rust
//! Reorder buffer + correlator: what the CLI and the conformance runner drive.

use crate::alert::CorrelationAlert;
use crate::correlator::{Correlator, Limits, Observation, Stats};
use crate::reorder::{DEFAULT_MAX_BUFFERED, DEFAULT_MAX_LATENESS_MS, ReorderBuffer};
use zaaf_event::Event;
use zaaf_ir::CompiledCorrelation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineLimits {
    pub correlator: Limits,
    pub max_lateness_ms: i64,
    pub max_buffered: usize,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            correlator: Limits::default(),
            max_lateness_ms: DEFAULT_MAX_LATENESS_MS,
            max_buffered: DEFAULT_MAX_BUFFERED,
        }
    }
}

pub struct CorrelationEngine<R> {
    correlator: Correlator<R>,
    buffer: ReorderBuffer<Observation<R>>,
    late: Vec<u64>,
}

impl<R: Clone> CorrelationEngine<R> {
    pub fn new(
        correlations: Vec<CompiledCorrelation>,
        rule_count: usize,
        limits: EngineLimits,
    ) -> Self {
        Self {
            correlator: Correlator::new(correlations, rule_count, limits.correlator),
            buffer: ReorderBuffer::new(limits.max_lateness_ms, limits.max_buffered),
            late: vec![0; rule_count],
        }
    }

    pub fn correlations(&self) -> &[CompiledCorrelation] {
        self.correlator.correlations()
    }

    /// True when some correlation consumes matches of `rule`.
    pub fn consumes(&self, rule: usize) -> bool {
        self.correlator.consumes(rule)
    }

    /// Feeds a match of `rule` on `event` at `time_ms`. Returns the alerts completed by
    /// matches that the watermark released (possibly earlier ones).
    pub fn push(
        &mut self,
        rule: usize,
        event: &dyn Event,
        time_ms: i64,
        reference: R,
    ) -> Vec<CorrelationAlert<R>> {
        let Some(obs) = self.correlator.observe(rule, event, time_ms, reference) else {
            return Vec::new();
        };
        match self.buffer.push(time_ms, obs) {
            Ok(released) => self.process(released),
            Err(late) => {
                if let Some(n) = self.late.get_mut(late.rule) {
                    *n += 1;
                }
                Vec::new()
            }
        }
    }

    /// End of input: releases and processes everything still buffered.
    pub fn finish(&mut self) -> Vec<CorrelationAlert<R>> {
        let rest = self.buffer.flush();
        self.process(rest)
    }

    fn process(&mut self, released: Vec<Observation<R>>) -> Vec<CorrelationAlert<R>> {
        released
            .into_iter()
            .flat_map(|o| self.correlator.process(o))
            .collect()
    }

    /// Per rule: matches that arrived too late to be correlated.
    pub fn late_matches(&self) -> &[u64] {
        &self.late
    }

    pub fn stats(&self) -> &Stats {
        self.correlator.stats()
    }

    /// Matches released before the watermark because the buffer was full.
    pub fn forced_releases(&self) -> u64 {
        self.buffer.forced_releases()
    }
}
```

In `crates/zaaf-correlate/src/lib.rs`, replace:

```rust
//! The one stateful Sigma correlator of ZAAFElegia (design spec §3.2, §3.3).
//!
//! It consumes single-event rule matches in time order and emits correlation alerts.
//! Every evaluation path (the native stream evaluator now, DataFusion in M4) feeds it,
//! so correlation semantics exist exactly once.

mod alert;
mod correlator;
pub mod window;

pub use alert::{AggValue, Contributor, CorrelationAlert, FieldText};
pub use correlator::{
    Correlator, DEFAULT_MAX_ENTRIES_PER_GROUP, DEFAULT_MAX_GROUPS, Limits, Observation, Part, Stats,
};
```

with:

```rust
//! The one stateful Sigma correlator of ZAAFElegia (design spec §3.2, §3.3).
//!
//! It consumes single-event rule matches and emits correlation alerts. A reorder
//! buffer puts matches in time order first; matches later than the watermark are
//! counted, never dropped silently. Every evaluation path (the native stream evaluator
//! now, DataFusion in M4) feeds the same engine, so correlation semantics exist once.

mod alert;
mod correlator;
mod engine;
mod reorder;
pub mod window;

pub use alert::{AggValue, Contributor, CorrelationAlert, FieldText};
pub use correlator::{
    Correlator, DEFAULT_MAX_ENTRIES_PER_GROUP, DEFAULT_MAX_GROUPS, Limits, Observation, Part, Stats,
};
pub use engine::{CorrelationEngine, EngineLimits};
pub use reorder::{DEFAULT_MAX_BUFFERED, DEFAULT_MAX_LATENESS_MS, ReorderBuffer, parse_lateness};
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-correlate`
Expected: PASS (13 unit tests including 5 in `reorder::tests`; 16 correlator and 4 engine integration tests). Workspace total: 297.

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add crates/zaaf-correlate
git commit -m "feat(correlate): reorder buffer with watermark and late-match counting" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 7: zaaf-cli: correlation in `zaaf hunt` and correlation findings

Wires the engine into `zaaf hunt`: `--max-lateness` and `--max-correlation-groups`, rule/correlation selection under `--min-level`/`--status`, `generate` suppression, correlation findings that reference their contributors, warnings for every counter, the extended summary line, and correlating what is buffered when `--max-errors` aborts (decisions M2-D8, M2-D11 to M2-D15). Exit codes are unchanged; `--fail-on-match` also counts correlation alerts. `output.rs` reuses `main`'s FNV-1a code for both uids.

`select.rs` keeps its unit tests in the module: Step 1 writes them, Step 3 declares the module in `main.rs` and adds the implementation above them.

**Files:**
- Create: `crates/zaaf-cli/tests/correlate.rs`
- Create: `crates/zaaf-cli/src/select.rs`
- Modify: `crates/zaaf-cli/Cargo.toml`
- Modify: `crates/zaaf-cli/src/main.rs`
- Modify: `crates/zaaf-cli/src/output.rs`
- Modify: `crates/zaaf-cli/src/hunt.rs`

**Interfaces:**
- Consumes: Task 6's `CorrelationEngine`, `EngineLimits`, `Limits`, `DEFAULT_MAX_GROUPS`, `DEFAULT_MAX_ENTRIES_PER_GROUP`, `parse_lateness`, `CorrelationAlert`, `Contributor`, `FieldText`; Task 3's `CompiledCorrelation`, `InputSource`, `correlation_only`; Task 1's `Evaluator::work_limit_hits` (via `warn_limits`).
- Produces:
  - `select::select(rules, correlations, keep: impl Fn(&RuleInfo) -> bool) -> Selection` with `Selection { rules, original, rule_infos, standalone_rules, correlations, standalone_correlations }`.
  - `output::MatchRef { uid: String, source: Arc<str>, record: u64 }`, `output::finding_uid(info: &RuleInfo, evidence: &serde_json::Value) -> String` (the uid `detection_finding` writes), `output::correlation_uid(corr, alert) -> String`, `output::correlation_finding(corr, alert, correlations, rules) -> serde_json::Value`, `output::MAX_LISTED_CONTRIBUTORS = 1000`; private `fnv1a(bytes: impl IntoIterator<Item = u8>) -> u64` behind both `event_hash` and `correlation_uid`.
  - `zaaf hunt` flags `--max-lateness <DURATION>` (default `5m`) and `--max-correlation-groups <N>` (default 100000, at least 1).
  - Summary line: `E events[ (N outside time range)], M malformed records, U unreadable inputs, R rules, K matches, C correlations, A correlation alerts, L late matches, V evicted groups`.

- [ ] **Step 1: Write the failing tests**

Create `crates/zaaf-cli/tests/correlate.rs`:

```rust
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;

fn zaaf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zaaf"))
}

/// The spec's "failed logins followed by a successful login" example, in one file.
const BRUTE: &str = "title: Brute force then success
id: c-outer
level: high
author: Corr Author
references: [https://example.com/corr]
correlation:
    type: temporal_ordered
    rules: [many_failed, successful_login]
    group-by: [User]
    timespan: 10m
---
title: Many failed logins
id: c-inner
name: many_failed
correlation:
    type: event_count
    rules: [failed_login]
    group-by: [User]
    timespan: 10m
    condition:
        gte: 3
---
title: Failed login
id: r-failed
name: failed_login
author: Base Author
references: [https://example.com/base]
level: low
logsource:
    product: test
detection:
    s:
        EventID: 4625
    condition: s
---
title: Successful login
id: r-ok
name: successful_login
level: low
logsource:
    product: test
detection:
    s:
        EventID: 4624
    condition: s
";

fn line(secs: u32, event_id: u32, user: &str) -> String {
    format!(
        "{{\"@timestamp\": \"2026-11-07T01:{:02}:{:02}Z\", \"EventID\": {event_id}, \"User\": \"{user}\"}}\n",
        secs / 60,
        secs % 60
    )
}

fn setup(rules: &str, events: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    fs::write(dir.path().join("rules/r.yml"), rules).unwrap();
    fs::write(dir.path().join("events.ndjson"), events).unwrap();
    dir
}

fn hunt(dir: &Path) -> Command {
    let mut c = zaaf();
    c.arg("hunt")
        .arg("-r")
        .arg(dir.join("rules"))
        .arg(dir.join("events.ndjson"))
        .args(["-o", "ndjson"]);
    c
}

fn findings(out: &[u8]) -> Vec<Value> {
    String::from_utf8(out.to_vec())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn brute_events() -> String {
    [
        line(0, 4625, "alice"),
        line(10, 4625, "alice"),
        line(20, 4625, "bob"),
        line(30, 4625, "alice"),
        line(40, 4624, "alice"),
    ]
    .concat()
}

#[test]
fn correlation_finding_references_its_contributors() {
    let dir = setup(BRUTE, &brute_events());
    let out = hunt(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "5 events, 0 malformed records, 0 unreadable inputs, 2 rules, 0 matches, 2 correlations, 1 correlation alerts, 0 late matches, 0 evicted groups",
        ))
        .get_output()
        .stdout
        .clone();
    let f = findings(&out);
    // generate defaults to false: neither the base rules nor the inner correlation alert alone.
    assert_eq!(f.len(), 1, "{f:?}");
    let c = &f[0];
    assert_eq!(c["class_uid"], 2004);
    assert_eq!(c["severity"], "High");
    assert_eq!(c["finding_info"]["analytic"]["uid"], "c-outer");
    assert_eq!(c["time"], 1_794_013_240_000_i64);
    assert_eq!(c["finding_info"]["first_seen_time"], 1_794_013_200_000_i64);
    let related = c["finding_info"]["related_events"].as_array().unwrap();
    assert_eq!(related.len(), 2);
    assert_eq!(related[0]["type"], "Sigma correlation");
    assert_eq!(related[0]["title"], "Many failed logins");
    assert!(related[0]["uid"].as_str().unwrap().starts_with("c-inner:"));
    assert_eq!(related[1]["type"], "Sigma rule match");
    assert_eq!(related[1]["title"], "Successful login");
    assert!(related[1]["uid"].as_str().unwrap().starts_with("r-ok:"));
    let corr = &c["unmapped"]["correlation"];
    assert_eq!(corr["type"], "temporal_ordered");
    assert_eq!(corr["timespan"], "10m");
    assert_eq!(corr["group_by"]["User"], "alice");
    assert_eq!(corr["condition"]["gte"], 2.0);
    assert_eq!(corr["event_count"], 4);
    let records: Vec<u64> = corr["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["record"].as_u64().unwrap())
        .collect();
    assert_eq!(records, vec![1, 2, 4, 5]);
    assert!(
        corr["events"][0]["source"]
            .as_str()
            .unwrap()
            .ends_with("events.ndjson")
    );
    let uids: Vec<&str> = corr["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["finding_uid"].as_str().unwrap())
        .collect();
    assert!(
        uids[..3].iter().all(|u| u.starts_with("r-failed:")),
        "{uids:?}"
    );
    assert_eq!(uids[3], related[1]["uid"]);
    let mut distinct = uids.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 4, "{uids:?}");
    // DRL attribution: the correlation's own and every contributing rule's.
    assert_eq!(c["unmapped"]["sigma"]["author"], "Corr Author");
    let contributing = c["unmapped"]["sigma"]["contributing_rules"]
        .as_array()
        .unwrap();
    assert_eq!(contributing[0]["id"], "r-failed");
    assert_eq!(contributing[0]["author"], "Base Author");
    assert_eq!(contributing[0]["references"][0], "https://example.com/base");
    assert_eq!(contributing[1]["id"], "r-ok");
}

#[test]
fn correlation_uid_is_stable_across_runs() {
    let dir = setup(BRUTE, &brute_events());
    let uid = |out: &[u8]| findings(out)[0]["finding_info"]["uid"].clone();
    let a = hunt(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let b = hunt(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(uid(&a), uid(&b));
}

#[test]
fn generate_true_keeps_the_rule_findings() {
    let rules = BRUTE.replacen(
        "    group-by: [User]\n    timespan: 10m\n    condition:",
        "    group-by: [User]\n    timespan: 10m\n    generate: true\n    condition:",
        1,
    );
    let dir = setup(&rules, &brute_events());
    let out = hunt(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("4 matches"))
        .get_output()
        .stdout
        .clone();
    let ids: Vec<String> = findings(&out)
        .iter()
        .map(|f| {
            f["finding_info"]["analytic"]["uid"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    // The inner correlation sets generate: true, so failed logins alert on their own;
    // the outer one does not, so the inner alert and successful logins stay silent.
    assert_eq!(
        ids,
        vec!["r-failed", "r-failed", "r-failed", "r-failed", "c-outer"]
    );
}

#[test]
fn out_of_order_matches_wait_for_the_watermark_or_are_late() {
    let shuffled = [
        line(40, 4624, "alice"),
        line(0, 4625, "alice"),
        line(10, 4625, "alice"),
        line(30, 4625, "alice"),
        line(50, 4624, "alice"),
    ]
    .concat();
    let dir = setup(BRUTE, &shuffled);
    // Default lateness (5m): reordered, so one alert.
    hunt(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "1 correlation alerts, 0 late matches",
        ));
    // No lateness: the three failed logins are late, counted and named.
    hunt(dir.path())
        .args(["--max-lateness", "0"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("0 correlation alerts, 3 late matches").and(
                predicate::str::contains(
                    "rule `Failed login` (r-failed): 3 match(es) arrived later than --max-lateness",
                ),
            ),
        );
}

#[test]
fn evicted_groups_are_reported() {
    let events = [
        line(0, 4625, "a"),
        line(1, 4625, "b"),
        line(2, 4625, "a"),
        line(3, 4625, "b"),
    ]
    .concat();
    let dir = setup(BRUTE, &events);
    hunt(dir.path())
        .args(["--max-correlation-groups", "1"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("3 evicted groups").and(predicate::str::contains(
                "evicted at --max-correlation-groups",
            )),
        );
}

#[test]
fn missing_timestamp_and_group_by_are_reported() {
    let events = "{\"EventID\": 4625, \"User\": \"a\"}\n{\"@timestamp\": \"2026-11-07T01:00:00Z\", \"EventID\": 4625}\n";
    let dir = setup(BRUTE, events);
    hunt(dir.path()).assert().success().stderr(
        predicate::str::contains(
            "rule `Failed login` (r-failed): 1 match(es) had no event timestamp",
        )
        .and(predicate::str::contains(
            "correlation `Many failed logins` (c-inner): 1 match(es) lacked a group-by field",
        )),
    );
}

#[test]
fn fail_on_match_counts_correlation_alerts() {
    let dir = setup(BRUTE, &brute_events());
    hunt(dir.path()).arg("--fail-on-match").assert().code(1);
}

#[test]
fn level_filter_keeps_the_rules_a_selected_correlation_needs() {
    let dir = setup(BRUTE, &brute_events());
    let out = hunt(dir.path())
        .args(["--min-level", "high"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(findings(&out).len(), 1);
}

#[test]
fn bad_durations_and_group_limits_are_usage_errors() {
    let dir = setup(BRUTE, &brute_events());
    for args in [
        ["--max-lateness", "5 minutes"],
        ["--max-lateness", "-1m"],
        ["--max-correlation-groups", "0"],
    ] {
        hunt(dir.path()).args(args).assert().code(2);
    }
    hunt(dir.path())
        .args(["--max-lateness", "0s"])
        .assert()
        .success();
}

#[test]
fn csv_output_shows_correlation_findings() {
    let dir = setup(BRUTE, &brute_events());
    zaaf()
        .arg("hunt")
        .arg("-r")
        .arg(dir.path().join("rules"))
        .arg(dir.path().join("events.ndjson"))
        .args(["-o", "csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "high,c-outer,Brute force then success,Corr Author,https://example.com/corr,",
        ));
}

#[test]
fn max_errors_abort_still_correlates_buffered_matches() {
    let dir = setup(BRUTE, &format!("{}not json\n", brute_events()));
    let out = hunt(dir.path())
        .args(["--max-errors", "0"])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let f = findings(&out);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0]["finding_info"]["analytic"]["uid"], "c-outer");
}
```

Create `crates/zaaf-cli/src/select.rs` containing only this test module for now (Step 3 puts the implementation above it):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use zaaf_ir::{Level, SourcedDocument, compile};
    use zaaf_pipeline::PipelineSet;

    fn compiled(src: &str) -> (Vec<CompiledRule>, Vec<CompiledCorrelation>) {
        let parsed = zaaf_sigma::parse_str(src);
        let out = compile(
            parsed
                .documents
                .into_iter()
                .map(|document| SourcedDocument {
                    document,
                    source: None,
                })
                .collect(),
            &PipelineSet::default(),
        );
        assert!(
            out.diagnostics.iter().all(|d| !d.is_error()),
            "{:?}",
            out.diagnostics
        );
        (out.rules, out.correlations)
    }

    fn rule(id: &str, level: &str) -> String {
        format!(
            "title: {id}\nid: {id}\nlevel: {level}\nlogsource:\n    product: t\ndetection:\n    s:\n        A: {id}\n    condition: s\n"
        )
    }

    const SRC: &str = "title: inner\nid: inner\nlevel: low\ncorrelation:\n    type: event_count\n    rules: [low1]\n    group-by: [U]\n    timespan: 1m\n    condition:\n        gte: 2\n---\ntitle: outer\nid: outer\nlevel: high\ncorrelation:\n    type: temporal\n    rules: [inner, low2]\n    group-by: [U]\n    timespan: 1m\n";

    #[test]
    fn filters_select_alerts_but_keep_what_correlations_need() {
        let src = format!(
            "{SRC}---\n{}---\n{}---\n{}",
            rule("low1", "low"),
            rule("low2", "low"),
            rule("low3", "low")
        );
        let (rules, corrs) = compiled(&src);
        let s = select(rules, corrs, |i| i.level >= Level::High);
        let ids: Vec<&str> = s.rules.iter().map(|r| r.info.id.as_str()).collect();
        assert_eq!(ids, vec!["low1", "low2"]);
        assert_eq!(s.original, vec![0, 1]);
        assert_eq!(s.standalone_rules, vec![false, false, false]);
        let cids: Vec<&str> = s.correlations.iter().map(|c| c.info.id.as_str()).collect();
        assert_eq!(cids, vec!["inner", "outer"]);
        assert_eq!(s.standalone_correlations, vec![false, true]);
        assert_eq!(s.rule_infos.len(), 3);
    }

    #[test]
    fn dropped_correlations_are_removed_and_indexes_remapped() {
        let src = format!(
            "title: other\nid: other\nlevel: low\ncorrelation:\n    type: event_count\n    rules: [low3]\n    group-by: [U]\n    timespan: 1m\n    condition:\n        gte: 2\n---\n{SRC}---\n{}---\n{}---\n{}",
            rule("low1", "low"),
            rule("low2", "low"),
            rule("low3", "high")
        );
        let (rules, corrs) = compiled(&src);
        assert_eq!(corrs.len(), 3);
        let s = select(rules, corrs, |i| i.id != "other");
        let cids: Vec<&str> = s.correlations.iter().map(|c| c.info.id.as_str()).collect();
        assert_eq!(cids, vec!["inner", "outer"]);
        assert_eq!(
            s.correlations[1].inputs[0].source,
            InputSource::Correlation(0)
        );
        // low3 is no longer referenced by a selected correlation: it alerts on its own.
        assert_eq!(s.standalone_rules, vec![false, false, true]);
    }
}
```

In `crates/zaaf-cli/src/output.rs`, replace:

```rust
    }

    #[test]
    fn csv_has_header_and_escapes() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
```

with:

```rust
    }

    #[test]
    fn fnv1a_matches_the_reference_vectors() {
        assert_eq!(fnv1a(*b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(*b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(*b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn csv_has_header_and_escapes() {
        let ev = JsonEvent::new(serde_json::json!({}));
        let mut buf = Vec::new();
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-cli --test correlate`
Expected: FAIL: the summary line lacks `2 correlations, 1 correlation alerts`, the binary rejects `--max-lateness` and `--max-correlation-groups` (`unexpected argument`), and no correlation finding is written (all five events produce single-event findings instead).

- [ ] **Step 3: Implement**

In `crates/zaaf-cli/Cargo.toml`, replace:

```toml
comfy-table.workspace = true
serde_json.workspace = true
walkdir.workspace = true
zaaf-eval.workspace = true
zaaf-event.workspace = true
zaaf-input.workspace = true
```

with:

```toml
comfy-table.workspace = true
serde_json.workspace = true
walkdir.workspace = true
zaaf-correlate.workspace = true
zaaf-eval.workspace = true
zaaf-event.workspace = true
zaaf-input.workspace = true
```

In `crates/zaaf-cli/src/main.rs`, replace:

```rust
mod hunt;
mod output;
mod rules;

use clap::{Parser, Subcommand};
use std::panic::{AssertUnwindSafe, catch_unwind};
```

with:

```rust
mod hunt;
mod output;
mod rules;
mod select;

use clap::{Parser, Subcommand};
use std::panic::{AssertUnwindSafe, catch_unwind};
```

At the top of `crates/zaaf-cli/src/select.rs`, above `#[cfg(test)]`, add the implementation:

```rust
//! Which rules and correlations `zaaf hunt` runs and which of them alert on their own.
//!
//! `--min-level`/`--status` select what *alerts*. A rule that a selected correlation
//! needs is still evaluated even when the filters would drop it, and a rule or inner
//! correlation that only feeds correlations (Sigma `generate: false`, the default) is
//! evaluated but produces no finding of its own.

use zaaf_ir::{CompiledCorrelation, CompiledRule, InputSource, RuleInfo, correlation_only};

pub struct Selection {
    /// Rules to evaluate.
    pub rules: Vec<CompiledRule>,
    /// For each entry of `rules`, its index among all compiled rules.
    pub original: Vec<usize>,
    /// Info of every compiled rule, by original index.
    pub rule_infos: Vec<RuleInfo>,
    /// By original rule index: whether its matches become findings.
    pub standalone_rules: Vec<bool>,
    /// Correlations to run (dependency order kept, indexes remapped).
    pub correlations: Vec<CompiledCorrelation>,
    /// By position in `correlations`: whether its alerts become findings.
    pub standalone_correlations: Vec<bool>,
}

pub fn select(
    rules: Vec<CompiledRule>,
    correlations: Vec<CompiledCorrelation>,
    keep: impl Fn(&RuleInfo) -> bool,
) -> Selection {
    let rule_kept: Vec<bool> = rules.iter().map(|r| keep(&r.info)).collect();
    let corr_kept: Vec<bool> = correlations.iter().map(|c| keep(&c.info)).collect();
    // Inner correlations always have lower indexes, so one backward pass closes the set.
    let mut corr_needed = corr_kept.clone();
    for c in (0..correlations.len()).rev() {
        if corr_needed[c] {
            for input in &correlations[c].inputs {
                if let InputSource::Correlation(j) = input.source {
                    corr_needed[j] = true;
                }
            }
        }
    }
    let mut rule_needed = rule_kept.clone();
    for (c, corr) in correlations.iter().enumerate() {
        if corr_needed[c] {
            for input in &corr.inputs {
                if let InputSource::Rule(r) = input.source {
                    rule_needed[r] = true;
                }
            }
        }
    }
    let mut position = vec![usize::MAX; correlations.len()];
    let mut selected = Vec::new();
    let mut selected_kept = Vec::new();
    for (c, mut corr) in correlations.into_iter().enumerate() {
        if !corr_needed[c] {
            continue;
        }
        for input in &mut corr.inputs {
            if let InputSource::Correlation(j) = input.source {
                input.source = InputSource::Correlation(position[j]);
            }
        }
        position[c] = selected.len();
        selected.push(corr);
        selected_kept.push(corr_kept[c]);
    }
    let only = correlation_only(rules.len(), &selected);
    let standalone_rules = rule_kept
        .iter()
        .zip(&only.rules)
        .map(|(k, o)| *k && !o)
        .collect();
    let standalone_correlations = selected_kept
        .iter()
        .zip(&only.correlations)
        .map(|(k, o)| *k && !o)
        .collect();
    let rule_infos = rules.iter().map(|r| r.info.clone()).collect();
    let mut original = Vec::new();
    let mut evaluated = Vec::new();
    for (i, r) in rules.into_iter().enumerate() {
        if rule_needed[i] {
            original.push(i);
            evaluated.push(r);
        }
    }
    Selection {
        rules: evaluated,
        original,
        rule_infos,
        standalone_rules,
        correlations: selected,
        standalone_correlations,
    }
}

```

In `crates/zaaf-cli/src/output.rs`, replace:

```rust

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde_json::{Value, json};
use std::io::{self, Write};
use zaaf_event::Event;
use zaaf_ir::{CompiledRule, Level};

pub const OCSF_VERSION: &str = "1.5.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
```

with:

```rust

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::sync::Arc;
use zaaf_correlate::{Contributor, CorrelationAlert, FieldText};
use zaaf_event::Event;
use zaaf_ir::{CompiledCorrelation, CompiledRule, Level, RuleInfo};

pub const OCSF_VERSION: &str = "1.5.0";

/// Contributors listed in one correlation finding; the full count is always given.
pub const MAX_LISTED_CONTRIBUTORS: usize = 1000;

/// How a correlation finding refers to one single-event match: by the uid its own
/// finding has (or would have, when the rule is correlation-only) and by where the
/// event was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchRef {
    pub uid: String,
    /// Input name (`<stdin>` or the path).
    pub source: Arc<str>,
    /// 1-based position of the event among the events read from `source`.
    pub record: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
```

In `crates/zaaf-cli/src/output.rs`, replace:

```rust
        "time": time,
        "message": info.title,
        "finding_info": {
            "uid": format!("{}:{:016x}", info.id, event_hash(&evidence)),
            "title": info.title,
            "desc": info.description,
            "types": info.tags,
```

with:

```rust
        "time": time,
        "message": info.title,
        "finding_info": {
            "uid": finding_uid(info, &evidence),
            "title": info.title,
            "desc": info.description,
            "types": info.tags,
```

In `crates/zaaf-cli/src/output.rs`, replace:

```rust
    }
}

/// FNV-1a 64-bit hash of the event's canonical JSON. Hand-rolled because it must stay
/// stable across Rust releases (`DefaultHasher` makes no such promise).
fn event_hash(event: &Value) -> u64 {
    let mut bytes = Vec::new();
    canonical_json(event, &mut bytes);
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

```

with:

```rust
    }
}

/// FNV-1a 64-bit. Hand-rolled because it must stay stable across Rust releases
/// (`DefaultHasher` makes no such promise).
fn fnv1a(bytes: impl IntoIterator<Item = u8>) -> u64 {
    bytes.into_iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// FNV-1a 64-bit hash of the event's canonical JSON.
fn event_hash(event: &Value) -> u64 {
    let mut bytes = Vec::new();
    canonical_json(event, &mut bytes);
    fnv1a(bytes)
}

/// `finding_info.uid` of the single-event finding of `info` on the event whose JSON is
/// `evidence` (see [`detection_finding`]).
pub fn finding_uid(info: &RuleInfo, evidence: &Value) -> String {
    format!("{}:{:016x}", info.id, event_hash(evidence))
}

/// `finding_info.uid` of a correlation finding: the correlation id and the FNV-1a hash
/// of the uids of every contributing match (each followed by a 0xff separator), so it is
/// the same whenever the same matches correlate.
pub fn correlation_uid(corr: &CompiledCorrelation, alert: &CorrelationAlert<MatchRef>) -> String {
    let matches = alert.matches();
    let digest = fnv1a(
        matches
            .iter()
            .flat_map(|(_, _, r)| r.uid.bytes().chain([0xff])),
    );
    format!("{}:{digest:016x}", corr.info.id)
}

fn group_json(names: &[String], values: &[FieldText]) -> Value {
    let mut m = Map::new();
    for (n, v) in names.iter().zip(values) {
        let value = match v.as_slice() {
            [one] => json!(one),
            many => json!(many),
        };
        m.insert(n.clone(), value);
    }
    Value::Object(m)
}

/// One OCSF Detection Finding per correlation alert. Contributing matches and inner
/// correlation alerts are referenced by uid (`finding_info.related_events`), not
/// embedded; `unmapped.correlation.events` says where each contributing event was read.
/// The attribution of every contributing rule is listed (DRL 1.1).
pub fn correlation_finding(
    corr: &CompiledCorrelation,
    alert: &CorrelationAlert<MatchRef>,
    correlations: &[CompiledCorrelation],
    rules: &[RuleInfo],
) -> Value {
    let info = &corr.info;
    let related: Vec<Value> = alert
        .contributors
        .iter()
        .take(MAX_LISTED_CONTRIBUTORS)
        .map(|c| match c {
            Contributor::Match {
                rule,
                time_ms,
                reference,
            } => json!({
                "uid": reference.uid,
                "type": "Sigma rule match",
                "title": rules.get(*rule).map(|r| r.title.as_str()),
                "first_seen_time": time_ms,
                "last_seen_time": time_ms,
            }),
            Contributor::Alert(inner) => {
                let inner_corr = &correlations[inner.correlation];
                json!({
                    "uid": correlation_uid(inner_corr, inner),
                    "type": "Sigma correlation",
                    "title": inner_corr.info.title,
                    "first_seen_time": inner.first_ms,
                    "last_seen_time": inner.time_ms,
                })
            }
        })
        .collect();
    let matches = alert.matches();
    let events: Vec<Value> = matches
        .iter()
        .take(MAX_LISTED_CONTRIBUTORS)
        .map(|(rule, time, r)| {
            json!({
                "rule_id": rules.get(*rule).map(|i| i.id.as_str()),
                "finding_uid": r.uid,
                "source": &*r.source,
                "record": r.record,
                "time": time,
            })
        })
        .collect();
    let rule_ids: BTreeSet<usize> = matches.iter().map(|(r, _, _)| *r).collect();
    let contributing_rules: Vec<Value> = rule_ids
        .iter()
        .filter_map(|r| rules.get(*r))
        .map(|r| {
            json!({
                "id": r.id,
                "title": r.title,
                "author": r.author,
                "references": r.references,
            })
        })
        .collect();
    let condition: Map<String, Value> = corr
        .bounds
        .iter()
        .map(|(op, b)| (op.as_str().to_string(), json!(b)))
        .collect();
    let source = matches
        .last()
        .map(|(_, _, r)| r.source.to_string())
        .unwrap_or_default();
    json!({
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "severity_id": info.level.ocsf_severity_id(),
        "severity": severity_name(info.level),
        "status_id": 1,
        "status": "New",
        "time": alert.time_ms,
        "message": info.title,
        "finding_info": {
            "uid": correlation_uid(corr, alert),
            "title": info.title,
            "desc": info.description,
            "types": info.tags,
            "analytic": { "uid": info.id, "name": info.title, "type_id": 1, "type": "Rule" },
            "first_seen_time": alert.first_ms,
            "last_seen_time": alert.time_ms,
            "related_events": related,
        },
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "ZAAFElegia",
                "vendor_name": "ZAAFElegia project",
                "version": env!("CARGO_PKG_VERSION")
            }
        },
        "unmapped": {
            "source": source,
            "sigma": {
                "level": info.level.as_str(),
                "status": info.status,
                "author": info.author,
                "references": info.references,
                "falsepositives": info.falsepositives,
                "rule_file": info.source.as_ref().map(|p| p.display().to_string()),
                "contributing_rules": contributing_rules,
            },
            "correlation": {
                "type": corr.kind.as_str(),
                "timespan": corr.timespan,
                "group_by": group_json(&corr.group_by, &alert.group),
                "condition": condition,
                "fields": corr.fields,
                "value": alert.value,
                "contributor_count": alert.contributors.len(),
                "event_count": matches.len(),
                "events": events,
            }
        }
    })
}

```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
//! `zaaf hunt`: run rules over log events.

use crate::exit;
use crate::output::{OutputFormat, Sink, detection_finding, sanitize};
use crate::rules::load_rules;
use chrono::{DateTime, Utc};
use clap::{Args, ValueEnum};
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use zaaf_eval::Evaluator;
use zaaf_event::Event;
use zaaf_input::{
    EventResult, MAX_ARRAY_BYTES, MAX_LINE_BYTES, open_path_with_limits,
    read_json_events_with_limits,
};
use zaaf_ir::{CompiledRule, Level};
use zaaf_pipeline::PipelineSet;

#[derive(Clone, Copy, ValueEnum)]
```

with:

```rust
//! `zaaf hunt`: run rules over log events.

use crate::exit;
use crate::output::{
    MatchRef, OutputFormat, Sink, correlation_finding, detection_finding, finding_uid, sanitize,
};
use crate::rules::load_rules;
use crate::select::{Selection, select};
use chrono::{DateTime, Utc};
use clap::{Args, ValueEnum};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use zaaf_correlate::{
    CorrelationAlert, CorrelationEngine, DEFAULT_MAX_GROUPS, EngineLimits, Limits, parse_lateness,
};
use zaaf_eval::Evaluator;
use zaaf_event::Event;
use zaaf_input::{
    EventResult, MAX_ARRAY_BYTES, MAX_LINE_BYTES, open_path_with_limits,
    read_json_events_with_limits,
};
use zaaf_ir::{Level, RuleInfo};
use zaaf_pipeline::PipelineSet;

#[derive(Clone, Copy, ValueEnum)]
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
    /// Also print rule warnings
    #[arg(short, long)]
    pub verbose: bool,
}

fn positive_usize(s: &str) -> Result<usize, String> {
```

with:

```rust
    /// Also print rule warnings
    #[arg(short, long)]
    pub verbose: bool,
    /// How long to wait for out-of-order matches before correlating (e.g. 30s, 5m, 0);
    /// later matches are counted as late and not correlated
    #[arg(long, value_parser = lateness, default_value = "5m")]
    pub max_lateness: i64,
    /// Open correlation groups kept at most; the least recently updated is evicted (and counted)
    #[arg(long, default_value_t = DEFAULT_MAX_GROUPS as u64, value_parser = clap::value_parser!(u64).range(1..))]
    pub max_correlation_groups: u64,
}

fn lateness(s: &str) -> Result<i64, String> {
    parse_lateness(s).ok_or_else(|| format!("`{s}` is not a duration such as 0, 30s, 5m, 1h or 1d"))
}

fn positive_usize(s: &str) -> Result<usize, String> {
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
    input_errors: usize,
    open_errors: usize,
    out_of_range: u64,
    matches: u64,
}

fn bound(value: &Option<String>, flag: &str) -> Result<Option<DateTime<Utc>>, String> {
```

with:

```rust
    input_errors: usize,
    open_errors: usize,
    out_of_range: u64,
    /// Single-event findings written.
    matches: u64,
    correlation_alerts: u64,
    /// By original rule index: correlated matches whose event had no timestamp.
    untimed: Vec<u64>,
}

fn bound(value: &Option<String>, flag: &str) -> Result<Option<DateTime<Utc>>, String> {
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
    }
}

fn keep(rule: &CompiledRule, min: Option<Level>, statuses: &[String]) -> bool {
    min.is_none_or(|m| rule.info.level >= m)
        && (statuses.is_empty()
            || rule
                .info
                .status
                .as_deref()
                .is_some_and(|s| statuses.iter().any(|w| w.eq_ignore_ascii_case(s))))
}

pub fn run(args: HuntArgs) -> u8 {
```

with:

```rust
    }
}

fn keep(info: &RuleInfo, min: Option<Level>, statuses: &[String]) -> bool {
    min.is_none_or(|m| info.level >= m)
        && (statuses.is_empty()
            || info
                .status
                .as_deref()
                .is_some_and(|s| statuses.iter().any(|w| w.eq_ignore_ascii_case(s))))
}

/// Everything one hunt run evaluates and emits.
struct Run {
    evaluator: Evaluator,
    selection: Selection,
    engine: CorrelationEngine<MatchRef>,
}

pub fn run(args: HuntArgs) -> u8 {
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
    }
    let rules_before = loaded.output.rules.len();
    let min = args.min_level.map(Level::from);
    let rules: Vec<CompiledRule> = loaded
        .output
        .rules
        .into_iter()
        .filter(|r| keep(r, min, &args.status))
        .collect();
    if rules.is_empty() {
        if rules_before > 0 {
            eprintln!("error: no rules left after --min-level/--status filters");
        } else {
```

with:

```rust
    }
    let rules_before = loaded.output.rules.len();
    let min = args.min_level.map(Level::from);
    let mut selection = select(loaded.output.rules, loaded.output.correlations, |i| {
        keep(i, min, &args.status)
    });
    if selection.rules.is_empty() {
        if rules_before > 0 {
            eprintln!("error: no rules left after --min-level/--status filters");
        } else {
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
        }
        return exit::RULE_ERRORS;
    }
    let rule_count = rules.len();
    let evaluator = Evaluator::new(rules);
    let code = scan(&args, &evaluator, from, to, rule_count);
    warn_limits(&evaluator);
    code
}

fn warn_limits(evaluator: &Evaluator) {
```

with:

```rust
        }
        return exit::RULE_ERRORS;
    }
    let limits = EngineLimits {
        correlator: Limits {
            max_groups: usize::try_from(args.max_correlation_groups).unwrap_or(usize::MAX),
            ..Limits::default()
        },
        max_lateness_ms: args.max_lateness,
        ..EngineLimits::default()
    };
    let engine = CorrelationEngine::new(
        std::mem::take(&mut selection.correlations),
        selection.rule_infos.len(),
        limits,
    );
    let evaluator = Evaluator::new(std::mem::take(&mut selection.rules));
    let mut run = Run {
        evaluator,
        selection,
        engine,
    };
    let mut stats = Stats {
        untimed: vec![0; run.selection.rule_infos.len()],
        ..Stats::default()
    };
    let code = scan(&args, &mut run, &mut stats, from, to);
    warn_limits(&run.evaluator);
    warn_correlation(&run, &stats);
    code
}

fn rule_label(info: &RuleInfo) -> String {
    format!("`{}` ({})", sanitize(&info.title), sanitize(&info.id))
}

/// Correlation counters that mean something was not correlated: never silent.
fn warn_correlation(run: &Run, stats: &Stats) {
    let infos = &run.selection.rule_infos;
    for (r, n) in run.engine.late_matches().iter().enumerate() {
        if *n > 0 {
            eprintln!(
                "warning: rule {}: {n} match(es) arrived later than --max-lateness and were not correlated",
                rule_label(&infos[r])
            );
        }
    }
    for (r, n) in stats.untimed.iter().enumerate() {
        if *n > 0 {
            eprintln!(
                "warning: rule {}: {n} match(es) had no event timestamp and were not correlated",
                rule_label(&infos[r])
            );
        }
    }
    let cs = run.engine.stats();
    for (c, n) in cs.missing_group_by.iter().enumerate() {
        if *n > 0 {
            eprintln!(
                "warning: correlation {}: {n} match(es) lacked a group-by field and were not counted",
                rule_label(&run.engine.correlations()[c].info)
            );
        }
    }
    if cs.evicted_groups > 0 {
        eprintln!(
            "warning: {} correlation group(s) were evicted at --max-correlation-groups; raise it to keep them",
            cs.evicted_groups
        );
    }
    if cs.truncated_entries > 0 {
        eprintln!(
            "warning: {} correlation window entries were dropped at the per-group cap of {}",
            cs.truncated_entries,
            zaaf_correlate::DEFAULT_MAX_ENTRIES_PER_GROUP
        );
    }
    if run.engine.forced_releases() > 0 {
        eprintln!(
            "warning: the reorder buffer was full; {} match(es) were correlated before the watermark",
            run.engine.forced_releases()
        );
    }
}

fn emit<W: Write>(
    run: &Run,
    alerts: Vec<CorrelationAlert<MatchRef>>,
    sink: &mut Sink<W>,
    stats: &mut Stats,
) -> io::Result<()> {
    for alert in alerts {
        if !run.selection.standalone_correlations[alert.correlation] {
            continue;
        }
        stats.correlation_alerts += 1;
        let correlations = run.engine.correlations();
        sink.write(correlation_finding(
            &correlations[alert.correlation],
            &alert,
            correlations,
            &run.selection.rule_infos,
        ))?;
    }
    Ok(())
}

fn warn_limits(evaluator: &Evaluator) {
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
/// every other condition (so it also hides 3 and 1).
fn scan(
    args: &HuntArgs,
    evaluator: &Evaluator,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    rule_count: usize,
) -> u8 {
    let format = args.output.unwrap_or(if io::stdout().is_terminal() {
        OutputFormat::Table
```

with:

```rust
/// every other condition (so it also hides 3 and 1).
fn scan(
    args: &HuntArgs,
    run: &mut Run,
    stats: &mut Stats,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> u8 {
    let format = args.output.unwrap_or(if io::stdout().is_terminal() {
        OutputFormat::Table
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
            .map(|p| (p.as_os_str() != "-").then(|| p.clone()))
            .collect()
    };
    let mut stats = Stats::default();
    for input in inputs {
        let (name, events): (String, io::Result<Box<dyn Iterator<Item = EventResult>>>) =
            match &input {
```

with:

```rust
            .map(|p| (p.as_os_str() != "-").then(|| p.clone()))
            .collect()
    };
    for input in inputs {
        let (name, events): (String, io::Result<Box<dyn Iterator<Item = EventResult>>>) =
            match &input {
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
                continue;
            }
        };
        for item in events {
            let event = match item {
                Ok(ev) => ev,
```

with:

```rust
                continue;
            }
        };
        let source: Arc<str> = Arc::from(name.as_str());
        let mut record = 0u64;
        for item in events {
            let event = match item {
                Ok(ev) => ev,
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
                            "error: more than {} malformed records, aborting",
                            args.max_errors
                        );
                        if let Err(e) = sink.finish() {
                            return exit::write_failed(e);
                        }
                        return exit::INPUT_ERRORS;
```

with:

```rust
                            "error: more than {} malformed records, aborting",
                            args.max_errors
                        );
                        // Buffered matches are still correlated before giving up.
                        let rest = run.engine.finish();
                        if let Err(e) =
                            emit(run, rest, &mut sink, stats).and_then(|()| sink.finish())
                        {
                            return exit::write_failed(e);
                        }
                        return exit::INPUT_ERRORS;
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
                }
            };
            stats.events += 1;
            if let Some(ts) = event.timestamp()
                && (from.is_some_and(|f| ts < f) || to.is_some_and(|t| ts > t))
            {
                stats.out_of_range += 1;
                continue;
            }
            for idx in evaluator.matching_rules(&event) {
                stats.matches += 1;
                let finding = detection_finding(&evaluator.rules()[idx], &event, &name);
                if let Err(e) = sink.write(finding) {
                    return exit::write_failed(e);
                }
            }
        }
    }
    if let Err(e) = sink.finish() {
        return exit::write_failed(e);
    }
    let range_note = if stats.out_of_range > 0 {
```

with:

```rust
                }
            };
            stats.events += 1;
            record += 1;
            if let Some(ts) = event.timestamp()
                && (from.is_some_and(|f| ts < f) || to.is_some_and(|t| ts > t))
            {
                stats.out_of_range += 1;
                continue;
            }
            for idx in run.evaluator.matching_rules(&event) {
                let original = run.selection.original[idx];
                let rule = &run.evaluator.rules()[idx];
                if run.selection.standalone_rules[original] {
                    stats.matches += 1;
                    let finding = detection_finding(rule, &event, &name);
                    if let Err(e) = sink.write(finding) {
                        return exit::write_failed(e);
                    }
                }
                if !run.engine.consumes(original) {
                    continue;
                }
                let Some(ts) = event.timestamp() else {
                    stats.untimed[original] += 1;
                    continue;
                };
                let reference = MatchRef {
                    uid: finding_uid(&rule.info, &event.to_json()),
                    source: source.clone(),
                    record,
                };
                let alerts = run
                    .engine
                    .push(original, &event, ts.timestamp_millis(), reference);
                if let Err(e) = emit(run, alerts, &mut sink, stats) {
                    return exit::write_failed(e);
                }
            }
        }
    }
    let rest = run.engine.finish();
    if let Err(e) = emit(run, rest, &mut sink, stats).and_then(|()| sink.finish()) {
        return exit::write_failed(e);
    }
    let range_note = if stats.out_of_range > 0 {
```

In `crates/zaaf-cli/src/hunt.rs`, replace:

```rust
    } else {
        String::new()
    };
    eprintln!(
        "{} events{range_note}, {} malformed records, {} unreadable inputs, {rule_count} rules, {} matches",
        stats.events, stats.input_errors, stats.open_errors, stats.matches
    );
    if stats.open_errors > 0 || (args.strict && stats.input_errors > 0) {
        return exit::INPUT_ERRORS;
    }
    if args.fail_on_match && stats.matches > 0 {
        exit::MATCHES
    } else {
        exit::OK
```

with:

```rust
    } else {
        String::new()
    };
    let cs = run.engine.stats();
    let late: u64 = run.engine.late_matches().iter().sum();
    eprintln!(
        "{} events{range_note}, {} malformed records, {} unreadable inputs, {} rules, {} matches, {} correlations, {} correlation alerts, {late} late matches, {} evicted groups",
        stats.events,
        stats.input_errors,
        stats.open_errors,
        run.evaluator.rules().len(),
        stats.matches,
        run.engine.correlations().len(),
        stats.correlation_alerts,
        cs.evicted_groups
    );
    if stats.open_errors > 0 || (args.strict && stats.input_errors > 0) {
        return exit::INPUT_ERRORS;
    }
    if args.fail_on_match && stats.matches + stats.correlation_alerts > 0 {
        exit::MATCHES
    } else {
        exit::OK
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-cli`
Expected: PASS (unit: 12 tests including 2 in `select::tests` and `fnv1a_matches_the_reference_vectors`; check: 18; correlate: 11; hunt: 22). Workspace total: 311.

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add Cargo.lock crates/zaaf-cli
git commit -m "feat(cli): correlate in zaaf hunt and write correlation findings" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 8: zaaf-testkit: correlation expectations in conformance cases

Extends the language-neutral case format (decision M2-D18) and runs every case's matches through the same `CorrelationEngine` the CLI uses. Absent keys mean "none", so the 30 M1 cases keep passing unchanged and a correlation case must list everything it produces.

**Files:**
- Modify: `crates/zaaf-testkit/tests/runner.rs`
- Modify: `crates/zaaf-testkit/Cargo.toml`
- Modify: `crates/zaaf-testkit/src/lib.rs`

**Interfaces:**
- Consumes: Task 6's `CorrelationEngine`, `EngineLimits`, `DEFAULT_MAX_LATENESS_MS`, `parse_lateness`; Task 3's `correlation_only`.
- Produces: `zaaf_testkit::ExpectedAlert { rule: String, events: Vec<usize> }`; `CaseSpec` gains `correlations: Vec<ExpectedAlert>`, `correlation_only: Vec<String>`, `max_lateness: Option<String>`, `late: BTreeMap<String, u64>`, `missing_group_by: BTreeMap<String, u64>`. Failure messages: `correlation alerts: expected [...], got [...]`, `correlation_only: expected [...], got [...]`, `late matches: expected {...}, got {...}`, `missing group-by: expected {...}, got {...}`, `case.yml: invalid max_lateness `X``.

- [ ] **Step 1: Write the failing tests**

In `crates/zaaf-testkit/tests/runner.rs`, replace:

```rust
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed(), "{:?}", results[0].failures);
}
```

with:

```rust
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed(), "{:?}", results[0].failures);
}

/// A case with rule `r` (A: x), correlation `c` (2 matches of `r` per `U` within 1m)
/// and `case.yml` body `tail` after `expected`.
fn write_correlation_case(events: &str, tail: &str) -> tempfile::TempDir {
    let dir = write_case("");
    fs::write(
        dir.path().join("rules/c.yml"),
        "title: c\nid: c\ncorrelation:\n    type: event_count\n    rules: [r]\n    group-by: [U]\n    timespan: 1m\n    condition:\n        gte: 2\n",
    )
    .unwrap();
    fs::write(dir.path().join("events.ndjson"), events).unwrap();
    let n = events.lines().count();
    let expected: String = (0..n).map(|_| "  - [r]\n").collect();
    fs::write(
        dir.path().join("case.yml"),
        format!("spec_ref: test\ndescription: correlation self-test\nexpected:\n{expected}{tail}"),
    )
    .unwrap();
    dir
}

const TWO: &str = "{\"@timestamp\": \"2026-11-07T00:00:00Z\", \"A\": \"x\", \"U\": \"u\"}\n{\"@timestamp\": \"2026-11-07T00:00:30Z\", \"A\": \"x\", \"U\": \"u\"}\n";

#[test]
fn correlation_expectations_pass() {
    let dir = write_correlation_case(
        TWO,
        "correlations:\n  - rule: c\n    events: [1, 0]\ncorrelation_only: [r]\n",
    );
    let result = zaaf_testkit::run_case(dir.path());
    assert!(result.passed(), "{:?}", result.failures);
}

#[test]
fn missing_correlation_alert_is_reported() {
    let dir = write_correlation_case(TWO, "correlation_only: [r]\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert_eq!(result.failures.len(), 1, "{:?}", result.failures);
    assert!(
        result.failures[0].starts_with("correlation alerts: expected [], got"),
        "{:?}",
        result.failures
    );
}

#[test]
fn correlation_only_mismatch_is_reported() {
    let dir = write_correlation_case(TWO, "correlations:\n  - rule: c\n    events: [0, 1]\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert_eq!(
        result.failures,
        vec!["correlation_only: expected [], got [\"r\"]".to_string()]
    );
}

#[test]
fn late_and_missing_group_by_counters_are_checked() {
    let events = "{\"@timestamp\": \"2026-11-07T00:10:00Z\", \"A\": \"x\", \"U\": \"u\"}\n{\"@timestamp\": \"2026-11-07T00:00:00Z\", \"A\": \"x\", \"U\": \"u\"}\n{\"@timestamp\": \"2026-11-07T00:10:01Z\", \"A\": \"x\"}\n";
    let dir = write_correlation_case(
        events,
        "correlation_only: [r]\nmax_lateness: 1m\nlate:\n  r: 1\nmissing_group_by:\n  c: 1\n",
    );
    let result = zaaf_testkit::run_case(dir.path());
    assert!(result.passed(), "{:?}", result.failures);
    let dir = write_correlation_case(events, "correlation_only: [r]\nmax_lateness: 1m\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert_eq!(result.failures.len(), 2, "{:?}", result.failures);
    assert!(result.failures[0].contains("late matches: expected {}, got {\"r\": 1}"));
    assert!(result.failures[1].contains("missing group-by: expected {}, got {\"c\": 1}"));
}

#[test]
fn invalid_max_lateness_is_reported() {
    let dir = write_correlation_case(TWO, "max_lateness: soon\n");
    let result = zaaf_testkit::run_case(dir.path());
    assert_eq!(
        result.failures,
        vec!["case.yml: invalid max_lateness `soon`".to_string()]
    );
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-testkit --test runner`
Expected: FAIL: the new tests report a `case.yml:` error naming the unknown field `correlations` or `correlation_only` (the M1 `CaseSpec` denies unknown fields).

- [ ] **Step 3: Implement**

In `crates/zaaf-testkit/Cargo.toml`, replace:

```toml
[dependencies]
serde.workspace = true
serde-saphyr.workspace = true
zaaf-eval.workspace = true
zaaf-input.workspace = true
zaaf-ir.workspace = true
zaaf-pipeline.workspace = true
```

with:

```toml
[dependencies]
serde.workspace = true
serde-saphyr.workspace = true
zaaf-correlate.workspace = true
zaaf-eval.workspace = true
zaaf-event.workspace = true
zaaf-input.workspace = true
zaaf-ir.workspace = true
zaaf-pipeline.workspace = true
```

In `crates/zaaf-testkit/src/lib.rs`, replace:

```rust
//! Runs the language-neutral Sigma conformance suite against the native evaluator.

use serde::Deserialize;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use zaaf_eval::Evaluator;
use zaaf_input::read_json_events;
use zaaf_ir::{SourcedDocument, compile};
use zaaf_pipeline::PipelineSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
```

with:

```rust
//! Runs the language-neutral Sigma conformance suite against the native evaluator.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use zaaf_correlate::{CorrelationEngine, DEFAULT_MAX_LATENESS_MS, EngineLimits, parse_lateness};
use zaaf_eval::Evaluator;
use zaaf_event::{Event, JsonEvent};
use zaaf_input::read_json_events;
use zaaf_ir::{CompiledCorrelation, CompiledRule, SourcedDocument, compile, correlation_only};
use zaaf_pipeline::PipelineSet;

/// One expected correlation alert.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ExpectedAlert {
    /// Id of the correlation rule.
    pub rule: String,
    /// Indexes (0-based) of every event whose match contributed, through chains.
    pub events: Vec<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
```

In `crates/zaaf-testkit/src/lib.rs`, replace:

```rust
    /// Number of rule errors (parse + compile) the case expects.
    #[serde(default)]
    pub compile_errors: usize,
    /// For each event, the ids of the rules that must match it (order irrelevant).
    pub expected: Vec<Vec<String>>,
}

#[derive(Debug)]
```

with:

```rust
    /// Number of rule errors (parse + compile) the case expects.
    #[serde(default)]
    pub compile_errors: usize,
    /// For each event, the ids of the rules that must match it (order irrelevant),
    /// including rules that only feed correlations.
    pub expected: Vec<Vec<String>>,
    /// Correlation alerts, in any order. Events are fed in file order; their
    /// timestamps decide the correlation order.
    #[serde(default)]
    pub correlations: Vec<ExpectedAlert>,
    /// Ids of rules and correlations that produce no alert of their own
    /// (`generate: false`, the default, on every correlation that references them).
    #[serde(default)]
    pub correlation_only: Vec<String>,
    /// Reorder-buffer lateness (`0`, `30s`, `5m`, ...); default `5m`.
    #[serde(default)]
    pub max_lateness: Option<String>,
    /// Per rule id: matches that arrived too late to be correlated.
    #[serde(default)]
    pub late: BTreeMap<String, u64>,
    /// Per correlation id: matches not counted because a group-by field was missing.
    #[serde(default)]
    pub missing_group_by: BTreeMap<String, u64>,
}

#[derive(Debug)]
```

In `crates/zaaf-testkit/src/lib.rs`, replace:

```rust
        return CaseResult { name, failures };
    }

    let evaluator = Evaluator::new(out.rules);
    for (i, (event, want)) in events.iter().zip(&spec.expected).enumerate() {
        let mut got: Vec<String> = evaluator
            .matching_rules(event)
            .into_iter()
            .map(|r| evaluator.rules()[r].info.id.clone())
            .collect();
        got.sort();
        let mut want = want.clone();
        want.sort();
        if got != want {
            failures.push(format!("event {i}: expected {want:?}, got {got:?}"));
        }
    }
    CaseResult { name, failures }
}
```

with:

```rust
        return CaseResult { name, failures };
    }

    let lateness = match spec.max_lateness.as_deref() {
        None => DEFAULT_MAX_LATENESS_MS,
        Some(s) => match parse_lateness(s) {
            Some(ms) => ms,
            None => return fail(format!("case.yml: invalid max_lateness `{s}`")),
        },
    };
    check_correlation_only(&spec, &out.rules, &out.correlations, &mut failures);
    let rule_ids: Vec<String> = out.rules.iter().map(|r| r.info.id.clone()).collect();
    let limits = EngineLimits {
        max_lateness_ms: lateness,
        ..EngineLimits::default()
    };
    let mut engine: CorrelationEngine<usize> =
        CorrelationEngine::new(out.correlations, out.rules.len(), limits);
    let evaluator = Evaluator::new(out.rules);
    let mut alerts = Vec::new();
    for (i, (event, want)) in events.iter().zip(&spec.expected).enumerate() {
        let matched = evaluator.matching_rules(event);
        let mut got: Vec<String> = matched.iter().map(|r| rule_ids[*r].clone()).collect();
        got.sort();
        let mut want = want.clone();
        want.sort();
        if got != want {
            failures.push(format!("event {i}: expected {want:?}, got {got:?}"));
        }
        feed(&mut engine, &matched, event, i, &mut alerts);
    }
    alerts.extend(engine.finish());
    let correlation_ids: Vec<String> = engine
        .correlations()
        .iter()
        .map(|c| c.info.id.clone())
        .collect();
    let mut got: Vec<ExpectedAlert> = alerts
        .iter()
        .map(|a| {
            let mut events: Vec<usize> = a.matches().iter().map(|(_, _, r)| **r).collect();
            events.sort();
            events.dedup();
            ExpectedAlert {
                rule: correlation_ids[a.correlation].clone(),
                events,
            }
        })
        .collect();
    got.sort();
    let mut want = spec.correlations.clone();
    for w in &mut want {
        w.events.sort();
    }
    want.sort();
    if got != want {
        failures.push(format!(
            "correlation alerts: expected {want:?}, got {got:?}"
        ));
    }
    let late = counts(&rule_ids, engine.late_matches());
    if late != spec.late {
        failures.push(format!(
            "late matches: expected {:?}, got {late:?}",
            spec.late
        ));
    }
    let missing = counts(&correlation_ids, &engine.stats().missing_group_by);
    if missing != spec.missing_group_by {
        failures.push(format!(
            "missing group-by: expected {:?}, got {missing:?}",
            spec.missing_group_by
        ));
    }
    CaseResult { name, failures }
}

/// Feeds the matches of event `i` to the correlation engine (events without a
/// timestamp are not correlated).
fn feed(
    engine: &mut CorrelationEngine<usize>,
    matched: &[usize],
    event: &JsonEvent,
    i: usize,
    alerts: &mut Vec<zaaf_correlate::CorrelationAlert<usize>>,
) {
    let Some(ts) = event.timestamp() else {
        return;
    };
    for r in matched {
        if engine.consumes(*r) {
            alerts.extend(engine.push(*r, event, ts.timestamp_millis(), i));
        }
    }
}

/// Non-zero counters keyed by id.
fn counts(ids: &[String], values: &[u64]) -> BTreeMap<String, u64> {
    ids.iter()
        .zip(values)
        .filter(|(_, n)| **n > 0)
        .map(|(id, n)| (id.clone(), *n))
        .collect()
}

fn check_correlation_only(
    spec: &CaseSpec,
    rules: &[CompiledRule],
    correlations: &[CompiledCorrelation],
    failures: &mut Vec<String>,
) {
    let only = correlation_only(rules.len(), correlations);
    let mut got: Vec<String> = rules
        .iter()
        .zip(&only.rules)
        .filter(|(_, o)| **o)
        .map(|(r, _)| r.info.id.clone())
        .chain(
            correlations
                .iter()
                .zip(&only.correlations)
                .filter(|(_, o)| **o)
                .map(|(c, _)| c.info.id.clone()),
        )
        .collect();
    got.sort();
    let mut want = spec.correlation_only.clone();
    want.sort();
    if got != want {
        failures.push(format!("correlation_only: expected {want:?}, got {got:?}"));
    }
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-testkit`
Expected: PASS (runner: 16 tests; conformance: the 30 M1 cases still pass). Workspace total: 316.

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add Cargo.lock crates/zaaf-testkit
git commit -m "feat(testkit): correlation expectations in conformance cases" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 9: Conformance: ten correlation cases and their interpretations

Adds cases 031 to 040, one directory each, covering every Sigma 2.1 correlation type, inclusive and exclusive window boundaries, group-by with missing fields and without group-by, aliases (the spec's example), `temporal_ordered` order and ties, chaining (the spec's example), `generate`, late events, upper-bound and `neq` conditions, and invalid correlations. Every expectation below was derived by hand from the decisions table before running the engine; the descriptions say why each alert happens. `value_median` is not in the suite (extension).

**Files:**
- Create: `conformance/cases/031-correlation-event-count/rules/count.yml`
- Create: `conformance/cases/031-correlation-event-count/rules/failed.yml`
- Create: `conformance/cases/031-correlation-event-count/events.ndjson`
- Create: `conformance/cases/031-correlation-event-count/case.yml`
- Create: `conformance/cases/032-correlation-value-count/rules/logon.yml`
- Create: `conformance/cases/032-correlation-value-count/rules/users.yml`
- Create: `conformance/cases/032-correlation-value-count/events.ndjson`
- Create: `conformance/cases/032-correlation-value-count/case.yml`
- Create: `conformance/cases/033-correlation-temporal-aliases/rules/conn.yml`
- Create: `conformance/cases/033-correlation-temporal-aliases/rules/error.yml`
- Create: `conformance/cases/033-correlation-temporal-aliases/rules/prox.yml`
- Create: `conformance/cases/033-correlation-temporal-aliases/events.ndjson`
- Create: `conformance/cases/033-correlation-temporal-aliases/case.yml`
- Create: `conformance/cases/034-correlation-temporal-ordered-chain/rules/brute.yml`
- Create: `conformance/cases/034-correlation-temporal-ordered-chain/events.ndjson`
- Create: `conformance/cases/034-correlation-temporal-ordered-chain/case.yml`
- Create: `conformance/cases/035-correlation-value-aggregates/rules/avg.yml`
- Create: `conformance/cases/035-correlation-value-aggregates/rules/pct.yml`
- Create: `conformance/cases/035-correlation-value-aggregates/rules/proc.yml`
- Create: `conformance/cases/035-correlation-value-aggregates/rules/sum.yml`
- Create: `conformance/cases/035-correlation-value-aggregates/rules/web.yml`
- Create: `conformance/cases/035-correlation-value-aggregates/events.ndjson`
- Create: `conformance/cases/035-correlation-value-aggregates/case.yml`
- Create: `conformance/cases/036-correlation-group-by-missing/rules/by-user.yml`
- Create: `conformance/cases/036-correlation-group-by-missing/rules/global.yml`
- Create: `conformance/cases/036-correlation-group-by-missing/rules/r.yml`
- Create: `conformance/cases/036-correlation-group-by-missing/events.ndjson`
- Create: `conformance/cases/036-correlation-group-by-missing/case.yml`
- Create: `conformance/cases/037-correlation-generate/rules/a.yml`
- Create: `conformance/cases/037-correlation-generate/rules/b.yml`
- Create: `conformance/cases/037-correlation-generate/rules/c.yml`
- Create: `conformance/cases/037-correlation-generate/rules/d.yml`
- Create: `conformance/cases/037-correlation-generate/rules/x.yml`
- Create: `conformance/cases/037-correlation-generate/rules/y.yml`
- Create: `conformance/cases/037-correlation-generate/rules/z.yml`
- Create: `conformance/cases/037-correlation-generate/events.ndjson`
- Create: `conformance/cases/037-correlation-generate/case.yml`
- Create: `conformance/cases/038-correlation-late-events/rules/c.yml`
- Create: `conformance/cases/038-correlation-late-events/rules/r.yml`
- Create: `conformance/cases/038-correlation-late-events/events.ndjson`
- Create: `conformance/cases/038-correlation-late-events/case.yml`
- Create: `conformance/cases/039-correlation-invalid/rules/bad.yml`
- Create: `conformance/cases/039-correlation-invalid/rules/r.yml`
- Create: `conformance/cases/039-correlation-invalid/events.ndjson`
- Create: `conformance/cases/039-correlation-invalid/case.yml`
- Create: `conformance/cases/040-correlation-upper-bounds/rules/few.yml`
- Create: `conformance/cases/040-correlation-upper-bounds/rules/neq.yml`
- Create: `conformance/cases/040-correlation-upper-bounds/rules/r.yml`
- Create: `conformance/cases/040-correlation-upper-bounds/events.ndjson`
- Create: `conformance/cases/040-correlation-upper-bounds/case.yml`
- Modify: `crates/zaaf-testkit/tests/conformance.rs`
- Modify: `conformance/README.md`

**Interfaces:**
- Consumes: Task 8's `case.yml` keys (`correlations`, `correlation_only`, `max_lateness`, `late`, `missing_group_by`, `compile_errors`).
- Produces: cases `031-correlation-event-count` to `040-correlation-upper-bounds`; `conformance/README.md` interpretations 21 to 36 and the extended format table; the suite floor of 40 cases.

- [ ] **Step 1: Raise the case-count floor**

In `crates/zaaf-testkit/tests/conformance.rs`, replace:

```rust
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cases");
    let results = zaaf_testkit::run_suite(&root).expect("conformance/cases is readable");
    assert!(
        results.len() >= 30,
        "expected at least 30 cases, found {}",
        results.len()
    );
    let failed: Vec<_> = results.iter().filter(|r| !r.passed()).collect();
```

with:

```rust
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cases");
    let results = zaaf_testkit::run_suite(&root).expect("conformance/cases is readable");
    assert!(
        results.len() >= 40,
        "expected at least 40 cases, found {}",
        results.len()
    );
    let failed: Vec<_> = results.iter().filter(|r| !r.passed()).collect();
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zaaf-testkit --test conformance`
Expected: FAIL with `expected at least 40 cases, found 30`.

- [ ] **Step 3: Write the ten cases and the README interpretations**

Each case is a directory with `rules/`, `events.ndjson` and `case.yml`. If a case fails, the message names the case and the differing alert list; re-derive the expectation from the decisions table before touching any code.

Create `conformance/cases/031-correlation-event-count/rules/count.yml`:

```yaml
title: c031 three failed logons per user in 5 minutes
id: c031-count
correlation:
    type: event_count
    rules:
        - c031-fail
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 3
```

Create `conformance/cases/031-correlation-event-count/rules/failed.yml`:

```yaml
title: c031 failed logon
id: c031-fail
logsource:
    product: test
detection:
    selection:
        EventID: 4625
    condition: selection
```

Create `conformance/cases/031-correlation-event-count/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "EventID": 4625, "User": "alice"}
{"@timestamp": "2026-11-07T00:01:00Z", "EventID": 4625, "User": "bob"}
{"@timestamp": "2026-11-07T00:02:00Z", "EventID": 4625, "User": "alice"}
{"@timestamp": "2026-11-07T00:05:00Z", "EventID": 4625, "User": "alice"}
{"@timestamp": "2026-11-07T00:05:01Z", "EventID": 4625, "User": "alice"}
{"@timestamp": "2026-11-07T00:06:00Z", "EventID": 4625, "User": "bob"}
{"@timestamp": "2026-11-07T00:06:01Z", "EventID": 4625, "User": "bob"}
{"@timestamp": "2026-11-07T00:07:00Z", "EventID": 4624, "User": "alice"}
{"@timestamp": "2026-11-07T00:10:00Z", "EventID": 4625, "User": "alice"}
{"@timestamp": "2026-11-07T00:10:01Z", "EventID": 4625, "User": "alice"}
```

Create `conformance/cases/031-correlation-event-count/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#event-count-event_count; #grouping; #time-selection
description: 'event_count with group-by and a sliding window. Interpretations (README items 21-23): the window of a match at time t is [t - timespan, t], both ends inclusive, so events 0 and 3 (exactly 5m apart) count together, and bob''s events 1 and 5 (5m apart) count together while 1 and 6 (5m01s) do not, so bob never reaches three; the condition is checked after every match; an alert lists every match in the window and clears the group, so event 4 starts a new count that completes at event 9. Event 7 is a different EventID. The base rule is not generated on its own (generate defaults to false).'
expected:
  - [c031-fail]
  - [c031-fail]
  - [c031-fail]
  - [c031-fail]
  - [c031-fail]
  - [c031-fail]
  - [c031-fail]
  - []
  - [c031-fail]
  - [c031-fail]
correlations:
  - rule: c031-count
    events: [0, 2, 3]
  - rule: c031-count
    events: [4, 8, 9]
correlation_only: [c031-fail]
```

Create `conformance/cases/032-correlation-value-count/rules/logon.yml`:

```yaml
title: c032 logon
id: c032-logon
logsource:
    product: test
detection:
    selection:
        EventID: 4624
    condition: selection
```

Create `conformance/cases/032-correlation-value-count/rules/users.yml`:

```yaml
title: c032 three distinct users per host in an hour
id: c032-users
correlation:
    type: value_count
    rules:
        - c032-logon
    group-by:
        - Host
    timespan: 1h
    condition:
        field: User
        gte: 3
```

Create `conformance/cases/032-correlation-value-count/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "EventID": 4624, "Host": "h1", "User": "alice"}
{"@timestamp": "2026-11-07T00:01:00Z", "EventID": 4624, "Host": "h1", "User": "alice"}
{"@timestamp": "2026-11-07T00:02:00Z", "EventID": 4624, "Host": "h2", "User": "bob"}
{"@timestamp": "2026-11-07T00:03:00Z", "EventID": 4624, "Host": "h1", "User": "ALICE"}
{"@timestamp": "2026-11-07T00:04:00Z", "EventID": 4624, "Host": "h1"}
{"@timestamp": "2026-11-07T00:05:00Z", "EventID": 4624, "Host": "h1", "User": null}
{"@timestamp": "2026-11-07T00:06:00Z", "EventID": 4624, "Host": "h1", "User": "carol"}
{"@timestamp": "2026-11-07T00:07:00Z", "EventID": 4624, "Host": "h2", "User": "bob"}
```

Create `conformance/cases/032-correlation-value-count/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#value-count-value_count
description: 'value_count counts distinct values of `field` per group. Interpretations (README items 24-25): values compare exactly (case-sensitive), so `alice` and `ALICE` are two values; a match whose field is missing or null stays in the window (it is listed in the alert) but adds no value. Host h1 reaches three users (alice, ALICE, carol) at event 6; h2 only ever sees bob.'
expected:
  - [c032-logon]
  - [c032-logon]
  - [c032-logon]
  - [c032-logon]
  - [c032-logon]
  - [c032-logon]
  - [c032-logon]
  - [c032-logon]
correlations:
  - rule: c032-users
    events: [0, 1, 3, 4, 5, 6]
correlation_only: [c032-logon]
```

Create `conformance/cases/033-correlation-temporal-aliases/rules/conn.yml`:

```yaml
title: c033 new network connection
id: c033-conn
name: new_network_connection
logsource:
    product: test
detection:
    selection:
        event.category: network
        event.type: connection
    condition: selection
```

Create `conformance/cases/033-correlation-temporal-aliases/rules/error.yml`:

```yaml
title: c033 internal error
id: c033-error
name: internal_error
logsource:
    product: test
detection:
    selection:
        http.response.status_code: 500
    condition: selection
```

Create `conformance/cases/033-correlation-temporal-aliases/rules/prox.yml`:

```yaml
title: c033 error and connection between the same hosts
id: c033-prox
correlation:
    type: temporal
    rules:
        - internal_error
        - new_network_connection
    group-by:
        - internal_ip
        - remote_ip
    timespan: 10s
    aliases:
        internal_ip:
            internal_error: destination.ip
            new_network_connection: source.ip
        remote_ip:
            internal_error: source.ip
            new_network_connection: destination.ip
```

Create `conformance/cases/033-correlation-temporal-aliases/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "event": {"category": "network", "type": "connection"}, "source": {"ip": "10.0.0.5"}, "destination": {"ip": "1.2.3.4"}}
{"@timestamp": "2026-11-07T00:00:05Z", "http": {"response": {"status_code": 500}}, "source": {"ip": "1.2.3.4"}, "destination": {"ip": "10.0.0.9"}}
{"@timestamp": "2026-11-07T00:00:10Z", "http": {"response": {"status_code": 500}}, "source": {"ip": "1.2.3.4"}, "destination": {"ip": "10.0.0.5"}}
{"@timestamp": "2026-11-07T00:00:20Z", "event": {"category": "network", "type": "connection"}, "source": {"ip": "10.0.0.9"}, "destination": {"ip": "1.2.3.4"}}
{"@timestamp": "2026-11-07T00:00:30Z", "http": {"response": {"status_code": 500}}, "source": {"ip": "5.6.7.8"}, "destination": {"ip": "10.0.0.7"}}
{"@timestamp": "2026-11-07T00:00:40Z", "event": {"category": "network", "type": "connection"}, "source": {"ip": "10.0.0.7"}, "destination": {"ip": "5.6.7.8"}}
```

Create `conformance/cases/033-correlation-temporal-aliases/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#temporal-proximity-temporal; #field-name-aliases
description: 'The specification''s alias example: rules referenced by name, and group-by on aliases that read different fields per rule. Events 0 and 2 have the same (internal_ip, remote_ip) pair through the aliases and are exactly 10s apart (inclusive window). Events 1 and 3 share a pair but are 15s apart. Events 4 and 5 arrive error-first: temporal ignores order.'
expected:
  - [c033-conn]
  - [c033-error]
  - [c033-error]
  - [c033-conn]
  - [c033-error]
  - [c033-conn]
correlations:
  - rule: c033-prox
    events: [0, 2]
  - rule: c033-prox
    events: [4, 5]
correlation_only: [c033-conn, c033-error]
```

Create `conformance/cases/034-correlation-temporal-ordered-chain/rules/brute.yml`:

```yaml
title: c034 failed logons followed by a successful logon
id: c034-brute
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    group-by:
        - User
    timespan: 10m
---
title: c034 multiple failed logons
id: c034-many
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 3
---
title: c034 failed logon
id: c034-failed
name: failed_login
logsource:
    product: test
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: c034 successful logon
id: c034-ok
name: successful_login
logsource:
    product: test
detection:
    selection:
        EventID: 4624
    condition: selection
```

Create `conformance/cases/034-correlation-temporal-ordered-chain/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "EventID": 4624, "User": "alice"}
{"@timestamp": "2026-11-07T00:01:00Z", "EventID": 4625, "User": "alice"}
{"@timestamp": "2026-11-07T00:02:00Z", "EventID": 4625, "User": "alice"}
{"@timestamp": "2026-11-07T00:03:00Z", "EventID": 4625, "User": "alice"}
{"@timestamp": "2026-11-07T00:04:00Z", "EventID": 4624, "User": "alice"}
{"@timestamp": "2026-11-07T00:05:00Z", "EventID": 4624, "User": "bob"}
{"@timestamp": "2026-11-07T00:06:00Z", "EventID": 4625, "User": "bob"}
{"@timestamp": "2026-11-07T00:06:00Z", "EventID": 4625, "User": "bob"}
{"@timestamp": "2026-11-07T00:06:00Z", "EventID": 4625, "User": "bob"}
{"@timestamp": "2026-11-07T00:06:00Z", "EventID": 4624, "User": "bob"}
```

Create `conformance/cases/034-correlation-temporal-ordered-chain/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#ordered-temporal-proximity-temporal_ordered; #failed-logins-followed-by-successful-login; #related-rules
description: 'The specification''s chained example in one multi-document file, with references by name. The inner event_count alert counts as one contribution to the outer rule at the time it fires (event 3, then event 8). Interpretations (README items 26-28): temporal_ordered needs the referenced rules in the listed order within the window, and equal timestamps count as in order (event 9 has the same time as the inner alert); the alert lists every contribution in the window, including the earlier success (event 0, event 5) that did not satisfy the order; contributing event indexes are listed through chains. Neither the base rules nor the inner correlation are generated on their own.'
expected:
  - [c034-ok]
  - [c034-failed]
  - [c034-failed]
  - [c034-failed]
  - [c034-ok]
  - [c034-ok]
  - [c034-failed]
  - [c034-failed]
  - [c034-failed]
  - [c034-ok]
correlations:
  - rule: c034-many
    events: [1, 2, 3]
  - rule: c034-brute
    events: [0, 1, 2, 3, 4]
  - rule: c034-many
    events: [6, 7, 8]
  - rule: c034-brute
    events: [5, 6, 7, 8, 9]
correlation_only: [c034-failed, c034-many, c034-ok]
```

Create `conformance/cases/035-correlation-value-aggregates/rules/avg.yml`:

```yaml
title: c035 average upload between 400 and 500 bytes
id: c035-avg
correlation:
    type: value_avg
    rules:
        - c035-web
    group-by:
        - User
    timespan: 1h
    condition:
        field: bytes_sent
        gt: 400
        lte: 500
```

Create `conformance/cases/035-correlation-value-aggregates/rules/pct.yml`:

```yaml
title: c035 image seen in at most 25 percent of a host's process starts
id: c035-pct
correlation:
    type: value_percentile
    rules:
        - c035-proc
    group-by:
        - Host
    timespan: 1h
    condition:
        field: Image
        lte: 25
```

Create `conformance/cases/035-correlation-value-aggregates/rules/proc.yml`:

```yaml
title: c035 process start
id: c035-proc
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
```

Create `conformance/cases/035-correlation-value-aggregates/rules/sum.yml`:

```yaml
title: c035 more than 1000 bytes per user in an hour
id: c035-sum
correlation:
    type: value_sum
    rules:
        - c035-web
    group-by:
        - User
    timespan: 1h
    condition:
        field: bytes_sent
        gt: 1000
```

Create `conformance/cases/035-correlation-value-aggregates/rules/web.yml`:

```yaml
title: c035 web upload
id: c035-web
logsource:
    product: test
detection:
    selection:
        EventID: 3
    condition: selection
```

Create `conformance/cases/035-correlation-value-aggregates/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "EventID": 3, "User": "u", "bytes_sent": 300}
{"@timestamp": "2026-11-07T00:01:00Z", "EventID": 3, "User": "u", "bytes_sent": "600"}
{"@timestamp": "2026-11-07T00:02:00Z", "EventID": 3, "User": "u", "bytes_sent": "n/a"}
{"@timestamp": "2026-11-07T00:03:00Z", "EventID": 3, "User": "u", "bytes_sent": 200}
{"@timestamp": "2026-11-07T00:04:00Z", "EventID": 3, "User": "u", "bytes_sent": 700}
{"@timestamp": "2026-11-07T00:10:00Z", "EventID": 1, "Host": "h", "Image": "svchost.exe"}
{"@timestamp": "2026-11-07T00:11:00Z", "EventID": 1, "Host": "h", "Image": "svchost.exe"}
{"@timestamp": "2026-11-07T00:12:00Z", "EventID": 1, "Host": "h", "Image": "svchost.exe"}
{"@timestamp": "2026-11-07T00:13:00Z", "EventID": 1, "Host": "h", "Image": "evil.exe"}
{"@timestamp": "2026-11-07T00:14:00Z", "EventID": 1, "Host": "h", "Image": "svchost.exe"}
```

Create `conformance/cases/035-correlation-value-aggregates/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#value-sum-value_sum; #value-average-value_avg; #value-percentile-value_percentile; #condition
description: 'Numeric aggregates and a range condition (gt AND lte). Interpretations (README items 29-31): numbers may be JSON numbers or numeric strings; a non-numeric value (event 2) stays in the window but adds nothing; value_avg divides by the numeric values only. The average reaches 450 at event 1 (alert, group cleared), then is undefined at event 2, 200 at event 3 and 450 again at event 4. The sum passes 1000 at event 3 (300 + 600 + 200). value_percentile is the share, in percent, of the group''s values in the window that equal the value of the arriving match: evil.exe is 1 of 4 process starts (25%) at event 8; svchost.exe is 100% at events 5 to 7 and at event 9 after the group was cleared.'
expected:
  - [c035-web]
  - [c035-web]
  - [c035-web]
  - [c035-web]
  - [c035-web]
  - [c035-proc]
  - [c035-proc]
  - [c035-proc]
  - [c035-proc]
  - [c035-proc]
correlations:
  - rule: c035-avg
    events: [0, 1]
  - rule: c035-sum
    events: [0, 1, 2, 3]
  - rule: c035-avg
    events: [2, 3, 4]
  - rule: c035-pct
    events: [5, 6, 7, 8]
correlation_only: [c035-proc, c035-web]
```

Create `conformance/cases/036-correlation-group-by-missing/rules/by-user.yml`:

```yaml
title: c036 two events per user
id: c036-by-user
correlation:
    type: event_count
    rules:
        - c036-r
    group-by:
        - User
    timespan: 1m
    condition:
        gte: 2
```

Create `conformance/cases/036-correlation-group-by-missing/rules/global.yml`:

```yaml
title: c036 three events overall
id: c036-global
correlation:
    type: event_count
    rules:
        - c036-r
    timespan: 1m
    condition:
        gte: 3
```

Create `conformance/cases/036-correlation-group-by-missing/rules/r.yml`:

```yaml
title: c036 event
id: c036-r
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
```

Create `conformance/cases/036-correlation-group-by-missing/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "EventID": 1, "User": "a"}
{"@timestamp": "2026-11-07T00:00:01Z", "EventID": 1}
{"@timestamp": "2026-11-07T00:00:02Z", "EventID": 1, "User": null}
{"@timestamp": "2026-11-07T00:00:03Z", "EventID": 1, "User": []}
{"@timestamp": "2026-11-07T00:00:04Z", "EventID": 1, "User": "a"}
{"@timestamp": "2026-11-07T00:00:05Z", "EventID": 1, "User": "b"}
```

Create `conformance/cases/036-correlation-group-by-missing/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#grouping
description: 'Interpretations (README items 32-33): a match whose group-by field is missing, null or an empty array belongs to no group and is not counted (the runner checks the count in missing_group_by); it is not grouped with other matches that lack the field. A correlation without group-by (a warning: the specification lists it as mandatory) treats all matches as one group. Both correlations see the same matches independently.'
expected:
  - [c036-r]
  - [c036-r]
  - [c036-r]
  - [c036-r]
  - [c036-r]
  - [c036-r]
correlations:
  - rule: c036-global
    events: [0, 1, 2]
  - rule: c036-by-user
    events: [0, 4]
  - rule: c036-global
    events: [3, 4, 5]
correlation_only: [c036-r]
missing_group_by:
  c036-by-user: 3
```

Create `conformance/cases/037-correlation-generate/rules/a.yml`:

```yaml
title: c037 rule a
id: c037-a
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
```

Create `conformance/cases/037-correlation-generate/rules/b.yml`:

```yaml
title: c037 rule b
id: c037-b
logsource:
    product: test
detection:
    selection:
        EventID: 2
    condition: selection
```

Create `conformance/cases/037-correlation-generate/rules/c.yml`:

```yaml
title: c037 rule c
id: c037-c
logsource:
    product: test
detection:
    selection:
        EventID: 3
    condition: selection
```

Create `conformance/cases/037-correlation-generate/rules/d.yml`:

```yaml
title: c037 rule d
id: c037-d
logsource:
    product: test
detection:
    selection:
        EventID: 4
    condition: selection
```

Create `conformance/cases/037-correlation-generate/rules/x.yml`:

```yaml
title: c037 a and b
id: c037-x
correlation:
    type: temporal
    rules:
        - c037-a
        - c037-b
    group-by:
        - U
    timespan: 1m
```

Create `conformance/cases/037-correlation-generate/rules/y.yml`:

```yaml
title: c037 b or c twice, generating its rules
id: c037-y
correlation:
    type: event_count
    rules:
        - c037-b
        - c037-c
    group-by:
        - U
    timespan: 1m
    generate: true
    condition:
        gte: 2
```

Create `conformance/cases/037-correlation-generate/rules/z.yml`:

```yaml
title: c037 any x alert
id: c037-z
correlation:
    type: event_count
    rules:
        - c037-x
    group-by:
        - U
    timespan: 1m
    condition:
        gte: 1
```

Create `conformance/cases/037-correlation-generate/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "EventID": 1, "U": "u"}
{"@timestamp": "2026-11-07T00:00:01Z", "EventID": 2, "U": "u"}
{"@timestamp": "2026-11-07T00:00:02Z", "EventID": 3, "U": "u"}
{"@timestamp": "2026-11-07T00:00:03Z", "EventID": 4, "U": "u"}
```

Create `conformance/cases/037-correlation-generate/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#generate; #correlation-rules
description: 'generate (default false) decides whether referenced rules still alert on their own. Interpretation (README item 34): a rule or correlation alerts on its own unless it is referenced and every correlation that references it has generate false. c037-a is referenced only by c037-x (false); c037-b by c037-x (false) and c037-y (true); c037-c by c037-y (true); c037-d by nothing; c037-x by c037-z (false). Chained: the c037-x alert is one match of c037-z.'
expected:
  - [c037-a]
  - [c037-b]
  - [c037-c]
  - [c037-d]
correlations:
  - rule: c037-x
    events: [0, 1]
  - rule: c037-z
    events: [0, 1]
  - rule: c037-y
    events: [1, 2]
correlation_only: [c037-a, c037-x]
```

Create `conformance/cases/038-correlation-late-events/rules/c.yml`:

```yaml
title: c038 two events per user in a minute
id: c038-c
correlation:
    type: event_count
    rules:
        - c038-r
    group-by:
        - U
    timespan: 1m
    condition:
        gte: 2
```

Create `conformance/cases/038-correlation-late-events/rules/r.yml`:

```yaml
title: c038 event
id: c038-r
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
```

Create `conformance/cases/038-correlation-late-events/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:05:00Z", "EventID": 1, "U": "u"}
{"@timestamp": "2026-11-07T00:04:30Z", "EventID": 1, "U": "u"}
{"@timestamp": "2026-11-07T00:03:00Z", "EventID": 1, "U": "u"}
{"@timestamp": "2026-11-07T00:10:00Z", "EventID": 1, "U": "v"}
{"@timestamp": "2026-11-07T00:09:30Z", "EventID": 1, "U": "v"}
```

Create `conformance/cases/038-correlation-late-events/case.yml`:

```yaml
spec_ref: design spec §3.3 (reorder buffer and watermark); sigma-correlation-rules-specification.md#time-selection
description: 'Events arrive out of order and are correlated in timestamp order. Interpretation (README item 35): with max_lateness 1m the watermark is the newest timestamp seen minus 1m; a match older than the watermark when it arrives is late, counted per rule and not correlated (event 2, 00:03:00, arrives when the watermark is 00:04:00). Events 0 and 1 and events 3 and 4 arrive newest first and still correlate.'
max_lateness: 1m
expected:
  - [c038-r]
  - [c038-r]
  - [c038-r]
  - [c038-r]
  - [c038-r]
correlations:
  - rule: c038-c
    events: [0, 1]
  - rule: c038-c
    events: [3, 4]
correlation_only: [c038-r]
late:
  c038-r: 1
```

Create `conformance/cases/039-correlation-invalid/rules/bad.yml`:

```yaml
title: c039 unknown reference
id: c039-unknown
correlation:
    type: temporal
    rules:
        - nope
    group-by:
        - U
    timespan: 1m
---
title: c039 missing timespan
id: c039-no-timespan
correlation:
    type: temporal
    rules:
        - c039-r
    group-by:
        - U
---
title: c039 week timespan
id: c039-week
correlation:
    type: temporal
    rules:
        - c039-r
    group-by:
        - U
    timespan: 1w
---
title: c039 cycle one
id: c039-loop1
correlation:
    type: temporal
    rules:
        - c039-loop2
    group-by:
        - U
    timespan: 1m
---
title: c039 cycle two
id: c039-loop2
correlation:
    type: temporal
    rules:
        - c039-loop1
    group-by:
        - U
    timespan: 1m
---
title: c039 event count without condition
id: c039-no-condition
correlation:
    type: event_count
    rules:
        - c039-r
    group-by:
        - U
    timespan: 1m
---
title: c039 value sum without field
id: c039-no-field
correlation:
    type: value_sum
    rules:
        - c039-r
    group-by:
        - U
    timespan: 1m
    condition:
        gt: 10
---
title: c039 alias for a rule not in rules
id: c039-alias
correlation:
    type: temporal
    rules:
        - c039-r
    group-by:
        - ip
    timespan: 1m
    aliases:
        ip:
            other: source.ip
```

Create `conformance/cases/039-correlation-invalid/rules/r.yml`:

```yaml
title: c039 event
id: c039-r
name: event
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
```

Create `conformance/cases/039-correlation-invalid/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "EventID": 1, "U": "u"}
```

Create `conformance/cases/039-correlation-invalid/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#correlation-section; #related-rules; #time-selection; #aliases
description: 'Invalid correlations are rule errors and are skipped; the base rule still runs and, with no valid correlation referencing it, alerts on its own. One error each: an unknown reference, a missing timespan, a timespan unit the specification does not list (w), event_count without a condition, value_sum without a condition field, an alias naming a rule that is not in `rules`; and one error per correlation in a reference cycle (two).'
compile_errors: 8
expected:
  - [c039-r]
```

Create `conformance/cases/040-correlation-upper-bounds/rules/few.yml`:

```yaml
title: c040 fewer than two events per user
id: c040-few
correlation:
    type: event_count
    rules:
        - c040-r
    group-by:
        - U
    timespan: 1m
    condition:
        lt: 2
```

Create `conformance/cases/040-correlation-upper-bounds/rules/neq.yml`:

```yaml
title: c040 event count other than one
id: c040-neq
correlation:
    type: event_count
    rules:
        - c040-r
    group-by:
        - U
    timespan: 1m
    condition:
        neq: 1
```

Create `conformance/cases/040-correlation-upper-bounds/rules/r.yml`:

```yaml
title: c040 event
id: c040-r
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
```

Create `conformance/cases/040-correlation-upper-bounds/events.ndjson`:

```json
{"@timestamp": "2026-11-07T00:00:00Z", "EventID": 1, "U": "u"}
{"@timestamp": "2026-11-07T00:00:01Z", "EventID": 1, "U": "u"}
```

Create `conformance/cases/040-correlation-upper-bounds/case.yml`:

```yaml
spec_ref: sigma-correlation-rules-specification.md#condition
description: 'Interpretation (README item 22): the condition is checked on the window ending at each match. `lt: 2` holds as soon as the first match arrives (count 1), and the alert clears the group, so the second match alerts again. `neq: 1` does not hold for one match and holds for two.'
expected:
  - [c040-r]
  - [c040-r]
correlations:
  - rule: c040-few
    events: [0]
  - rule: c040-few
    events: [1]
  - rule: c040-neq
    events: [0, 1]
correlation_only: [c040-r]
```

In `conformance/README.md`, replace:

```markdown
# Sigma conformance suite

A language-neutral test suite for Sigma 2.1 rule semantics. Any engine can run it:
load `rules/*.yml` (plus `pipelines` from `case.yml`, if any), evaluate every line of
`events.ndjson`, and compare the matching rule ids with `expected` in `case.yml`.

| File | Content |
|---|---|
| `case.yml` | `spec_ref` (spec section), `description` (what is tested, including any interpretation of an ambiguous point), optional `pipelines` and `compile_errors`, and `expected`: one list of rule ids per event |
| `rules/*.yml` | Standard Sigma rules (no extensions); the interpretations below are pinned, not extended |
| `events.ndjson` | One JSON event per line |

Interpretations used where the specification is silent (each is pinned by a case; see the final note for engine behaviour the suite does not cover):

```

with:

```markdown
# Sigma conformance suite

A language-neutral test suite for Sigma 2.1 rule and correlation semantics. Any engine
can run it: load `rules/*.yml` (plus `pipelines` from `case.yml`, if any), evaluate every
line of `events.ndjson`, and compare the matching rule ids with `expected` in `case.yml`.
Cases with correlation rules also feed every match, in file order, to the correlation
engine and compare its alerts with `correlations`.

| File | Content |
|---|---|
| `case.yml` | `spec_ref` (spec section), `description` (what is tested, including any interpretation of an ambiguous point), optional `pipelines` and `compile_errors`, and `expected`: one list of rule ids per event (every match, including rules that only feed correlations). Correlation keys, all optional: `correlations` (expected alerts in any order, each `{rule: <correlation id>, events: [<0-based indexes of every contributing event, through chained correlations>]}`), `correlation_only` (ids of rules and correlations that produce no alert of their own; must be listed exactly, so an absent key means none), `max_lateness` (reorder-buffer lateness such as `0`, `30s` or `5m`; default `5m`), `late` (per rule id, matches that arrived too late to be correlated) and `missing_group_by` (per correlation id, matches not counted because a group-by field was missing); absent counters mean zero |
| `rules/*.yml` | Standard Sigma rules (no extensions); the interpretations below are pinned, not extended |
| `events.ndjson` | One JSON event per line, in arrival order; correlation cases give every event an `@timestamp` |

Interpretations used where the specification is silent (each is pinned by a case; see the final note for engine behaviour the suite does not cover):

```

In `conformance/README.md`, replace:

```markdown
19. `not` over a field that is absent is true: the filter does not hold (030).
20. An integer value given to a time modifier is epoch seconds, or epoch milliseconds when it is 1e11 or more (030).

### Engine behaviour not covered by the suite

ZAAFElegia implements the following, but no case pins them yet, so other engines are not
```

with:

```markdown
19. `not` over a field that is absent is true: the filter does not hold (030).
20. An integer value given to a time modifier is epoch seconds, or epoch milliseconds when it is 1e11 or more (030).

Correlation interpretations (cases 031 to 040):

21. The window of a match at time `t` is `[t - timespan, t]`, inclusive at both ends: matches exactly `timespan` apart correlate (031, 033).
22. The condition is checked after every match, on the window ending at that match. A condition with only an upper bound (`lt: 2`) therefore holds from the first match (040).
23. An alert lists every match in the window and clears its group, so one match never counts towards two alerts of the same correlation (031).
24. Group-by and `value_count` values compare exactly, case-sensitively (032).
25. A match whose `value_count` or `value_percentile` field is missing or null stays in the window, and in the alert, but adds no value (032).
26. `temporal_ordered` needs the referenced rules in the listed order inside the window; equal timestamps count as in order (034).
27. A referenced (chained) correlation contributes one match, at the time its alert fires; expected events are listed through chains (034, 037).
28. An alert lists every contribution in its window, including ones that are not part of the satisfied order (034).
29. Numeric fields accept JSON numbers and numeric strings; a non-numeric value stays in the window but adds nothing (035).
30. `value_avg` and `value_median` are computed over the numeric values only; with none, the condition is not evaluated (035).
31. `value_percentile` is the share, in percent, of the group's values in the window that equal the value of the arriving match: `lte: 1` finds a value seen in at most 1% of the group's matches (035).
32. A match whose group-by field is missing, null or an empty array belongs to no group and is not counted (036).
33. A correlation without `group-by` treats all matches as one group (036).
34. A rule or correlation alerts on its own unless it is referenced and every correlation that references it has `generate: false` (the default) (037).
35. Matches are correlated in timestamp order (ties in arrival order). The watermark is the newest timestamp seen minus `max_lateness`; a match older than the watermark when it arrives is late: counted per rule, not correlated (038).
36. Invalid correlations are rule errors: unknown or ambiguous references, reference cycles, a `timespan` other than a positive number with `s`, `m`, `h` or `d`, a missing `condition` (except for `temporal` and `temporal_ordered`, whose default is all referenced rules), a value type without condition `field`, and an alias naming a rule not listed in `rules` (039).

### Engine behaviour not covered by the suite

ZAAFElegia implements the following, but no case pins them yet, so other engines are not
```

In `conformance/README.md`, replace:

```markdown
- `exists: true` on a field mapped to several names is true if any of the names is present.
- `rule_conditions` in a pipeline apply a mapping only when the rule's logsource matches
  every key of at least one condition (case 024 pins the `product` key only).

## Pipeline format (ZAAFElegia)

```

with:

```markdown
- `exists: true` on a field mapped to several names is true if any of the names is present.
- `rule_conditions` in a pipeline apply a mapping only when the rule's logsource matches
  every key of at least one condition (case 024 pins the `product` key only).
- Correlation group-by, alias and condition fields are mapped by the pipelines of the
  referenced rule's logsource; with several mapped names, the first one present with a
  non-null value is used.
- A group-by field holding an array groups by the whole list of its non-null values.
- `value_median` (not part of Sigma 2.1.0) is accepted with a warning and evaluated as the
  median of `field`.
- A match whose event has no timestamp is not correlated (it is counted and reported).

## Pipeline format (ZAAFElegia)

```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zaaf-testkit --test conformance`
Expected: PASS (40 cases). Workspace total: 316 (the suite is one test).

- [ ] **Step 5: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add conformance crates/zaaf-testkit/tests/conformance.rs
git commit -m "test(conformance): correlation cases 031-040 and written interpretations" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 10: Fuzz target for correlation parsing and evaluation

A `correlate` target feeds NDJSON events through a fixed rule set that uses every correlation type (including a chain, aliases, `generate` and tiny caps so eviction, truncation and early release run), or through extra fuzzer-written rule documents placed before a `%%` line, which exercises correlation parsing and compilation against the fixed rules. It gets a seed directory and a dictionary in the layout `main` uses (`fuzz/seeds/<target>/`, `fuzz/dictionaries/<target>.dict`); the pinned CI fuzz job passes both by target name, so only its matrix line changes. The existing `parse_rule` target also reaches correlation compilation now, because `compile` handles correlation documents; two correlation documents join its seeds.

**Files:**
- Create: `fuzz/fuzz_targets/correlate.rs`
- Create: `fuzz/dictionaries/correlate.dict`
- Create: `fuzz/seeds/correlate/events.ndjson`
- Create: `fuzz/seeds/correlate/extra-rules.txt`
- Create: `fuzz/seeds/parse_rule/034-correlation-chain.yml`
- Create: `fuzz/seeds/parse_rule/039-correlation-invalid.yml`
- Modify: `fuzz/Cargo.toml`
- Modify: `.github/workflows/fuzz.yml`

**Interfaces:**
- Consumes: `zaaf_correlate::{CorrelationEngine, EngineLimits, Limits}`, `zaaf_ir::{CompileOutput, SourcedDocument, compile}`, `zaaf_eval::Evaluator`.
- Produces: fuzz binary `correlate`; `fuzz/seeds/correlate/{events.ndjson,extra-rules.txt}`; `fuzz/dictionaries/correlate.dict`; `fuzz/seeds/parse_rule/034-correlation-chain.yml` and `039-correlation-invalid.yml` (copies of the conformance rules files from Task 9); CI fuzz matrix `[parse_rule, read_ndjson, eval_event, correlate]`.

- [ ] **Step 1: Implement**

In `fuzz/Cargo.toml`, replace:

```toml
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
serde_json = "1.0"
zaaf-eval = { path = "../crates/zaaf-eval" }
zaaf-event = { path = "../crates/zaaf-event" }
zaaf-input = { path = "../crates/zaaf-input" }
zaaf-ir = { path = "../crates/zaaf-ir" }
zaaf-pipeline = { path = "../crates/zaaf-pipeline" }
```

with:

```toml
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
serde_json = "1.0"
zaaf-correlate = { path = "../crates/zaaf-correlate" }
zaaf-eval = { path = "../crates/zaaf-eval" }
zaaf-event = { path = "../crates/zaaf-event" }
zaaf-input = { path = "../crates/zaaf-input" }
zaaf-ir = { path = "../crates/zaaf-ir" }
zaaf-pipeline = { path = "../crates/zaaf-pipeline" }
```

In `fuzz/Cargo.toml`, replace:

```toml
name = "eval_event"
path = "fuzz_targets/eval_event.rs"
test = false
doc = false
bench = false
```

with:

```toml
name = "eval_event"
path = "fuzz_targets/eval_event.rs"
test = false
doc = false
bench = false

[[bin]]
name = "correlate"
path = "fuzz_targets/correlate.rs"
test = false
doc = false
bench = false
```

Create `fuzz/fuzz_targets/correlate.rs`:

```rust
#![no_main]
//! Correlation parsing and evaluation. The input is NDJSON events, optionally preceded
//! by extra rule documents and a `%%` line; the extra documents are compiled together
//! with BASE, so they can reference its rules and correlations.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zaaf_correlate::{CorrelationEngine, EngineLimits, Limits};
use zaaf_eval::Evaluator;
use zaaf_event::{Event, JsonEvent};
use zaaf_ir::{CompileOutput, SourcedDocument, compile};
use zaaf_pipeline::PipelineSet;

const BASE: &str = r#"
title: r1
id: r1
name: one
logsource: {product: fuzz}
detection: {s: {EventID: 1}, condition: s}
---
title: r2
id: r2
name: two
logsource: {product: fuzz}
detection: {s: {EventID: 2}, condition: s}
---
title: count
id: c-count
name: count
correlation: {type: event_count, rules: [one], group-by: [U], timespan: 10s, condition: {gte: 3}}
---
title: values
id: c-values
correlation: {type: value_count, rules: [one, two], group-by: [U], timespan: 1m, condition: {field: [V, W], gte: 2}}
---
title: temporal
id: c-temporal
correlation: {type: temporal, rules: [one, two], group-by: [ip], timespan: 5s, aliases: {ip: {one: S, two: D}}}
---
title: ordered
id: c-ordered
correlation: {type: temporal_ordered, rules: [count, two], group-by: [U], timespan: 1m}
---
title: sum
id: c-sum
correlation: {type: value_sum, rules: [one], group-by: [U], timespan: 1m, condition: {field: N, gt: 10, lte: 1000}}
---
title: avg
id: c-avg
correlation: {type: value_avg, rules: [two], timespan: 1m, condition: {field: N, gte: 5}}
---
title: median
id: c-median
correlation: {type: value_median, rules: [one, two], group-by: [U], timespan: 1m, condition: {field: N, neq: 3}}
---
title: pct
id: c-pct
correlation: {type: value_percentile, rules: [one], group-by: [U], timespan: 1m, generate: true, condition: {field: V, lt: 30}}
"#;

fn compiled(extra: Option<&str>) -> CompileOutput {
    let src = match extra {
        Some(e) => format!("{BASE}---\n{e}"),
        None => BASE.to_string(),
    };
    let docs = zaaf_sigma::parse_str(&src)
        .documents
        .into_iter()
        .map(|document| SourcedDocument {
            document,
            source: None,
        })
        .collect();
    compile(docs, &PipelineSet::default())
}

fn base() -> &'static CompileOutput {
    static B: OnceLock<CompileOutput> = OnceLock::new();
    B.get_or_init(|| {
        let out = compiled(None);
        assert_eq!(out.correlations.len(), 8, "{:?}", out.diagnostics);
        out
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (out, events) = match text.split_once("\n%%\n") {
        Some((rules, events)) => (compiled(Some(rules)), events),
        None => {
            let b = base();
            (
                CompileOutput {
                    rules: b.rules.clone(),
                    correlations: b.correlations.clone(),
                    ..CompileOutput::default()
                },
                text,
            )
        }
    };
    let limits = EngineLimits {
        correlator: Limits {
            max_groups: 8,
            max_entries_per_group: 16,
        },
        max_lateness_ms: 1_000,
        max_buffered: 32,
    };
    let rule_count = out.rules.len();
    let mut engine: CorrelationEngine<usize> =
        CorrelationEngine::new(out.correlations, rule_count, limits);
    let evaluator = Evaluator::new(out.rules);
    for (i, line) in events.lines().enumerate() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let event = JsonEvent::new(value);
        let Some(ts) = event.timestamp() else {
            continue;
        };
        for r in evaluator.matching_rules(&event) {
            for alert in engine.push(r, &event, ts.timestamp_millis(), i) {
                let _ = alert.matches();
            }
        }
    }
    for alert in engine.finish() {
        let _ = alert.matches();
    }
});
```

In `.github/workflows/fuzz.yml`, replace:

```yaml
    strategy:
      fail-fast: false
      matrix:
        target: [parse_rule, read_ndjson, eval_event]
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      - uses: dtolnay/rust-toolchain@b725eda525362e7cf34af9a7243cac1e3f01a7ec # stable branch
```

with:

```yaml
    strategy:
      fail-fast: false
      matrix:
        target: [parse_rule, read_ndjson, eval_event, correlate]
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      - uses: dtolnay/rust-toolchain@b725eda525362e7cf34af9a7243cac1e3f01a7ec # stable branch
```

Create `fuzz/dictionaries/correlate.dict`:

```text
# Separator between extra rule documents and events.
"\x0a%%\x0a"
"\x0a---\x0a"
"correlation:"
"type:"
"event_count"
"value_count"
"temporal"
"temporal_ordered"
"value_sum"
"value_avg"
"value_median"
"value_percentile"
"rules:"
"group-by:"
"timespan:"
"aliases:"
"generate: true"
"condition:"
"field:"
"gte:"
"neq:"
"lt:"
"1s"
"5m"
"c-ordered"
"c-count"
"\"@timestamp\":"
"\"2026-11-07T00:00:00Z\""
"\"EventID\":1"
"\"EventID\":2"
"\"U\":"
"\"V\":"
"\"N\":"
"\"S\":"
"\"D\":"
```

Create `fuzz/seeds/correlate/events.ndjson`:

```json
{"@timestamp":"2026-11-07T00:00:00Z","EventID":1,"U":"u","V":"a","W":"b","N":4,"S":"1.1.1.1"}
{"@timestamp":"2026-11-07T00:00:01Z","EventID":1,"U":"u","V":"c","W":"b","N":"7"}
{"@timestamp":"2026-11-07T00:00:02Z","EventID":1,"U":"u","N":20}
{"@timestamp":"2026-11-07T00:00:01Z","EventID":2,"U":"u","D":"1.1.1.1","N":9}
```

Create `fuzz/seeds/correlate/extra-rules.txt`:

```text
title: x
correlation: {type: event_count, rules: [c-ordered, r2], group-by: [U], timespan: 1s, condition: {gte: 1}}
%%
{"ts": 1794021300, "EventID": 2, "U": "u"}
```

Create `fuzz/seeds/parse_rule/034-correlation-chain.yml`:

```yaml
title: c034 failed logons followed by a successful logon
id: c034-brute
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    group-by:
        - User
    timespan: 10m
---
title: c034 multiple failed logons
id: c034-many
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 3
---
title: c034 failed logon
id: c034-failed
name: failed_login
logsource:
    product: test
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: c034 successful logon
id: c034-ok
name: successful_login
logsource:
    product: test
detection:
    selection:
        EventID: 4624
    condition: selection
```

Create `fuzz/seeds/parse_rule/039-correlation-invalid.yml`:

```yaml
title: c039 unknown reference
id: c039-unknown
correlation:
    type: temporal
    rules:
        - nope
    group-by:
        - U
    timespan: 1m
---
title: c039 missing timespan
id: c039-no-timespan
correlation:
    type: temporal
    rules:
        - c039-r
    group-by:
        - U
---
title: c039 week timespan
id: c039-week
correlation:
    type: temporal
    rules:
        - c039-r
    group-by:
        - U
    timespan: 1w
---
title: c039 cycle one
id: c039-loop1
correlation:
    type: temporal
    rules:
        - c039-loop2
    group-by:
        - U
    timespan: 1m
---
title: c039 cycle two
id: c039-loop2
correlation:
    type: temporal
    rules:
        - c039-loop1
    group-by:
        - U
    timespan: 1m
---
title: c039 event count without condition
id: c039-no-condition
correlation:
    type: event_count
    rules:
        - c039-r
    group-by:
        - U
    timespan: 1m
---
title: c039 value sum without field
id: c039-no-field
correlation:
    type: value_sum
    rules:
        - c039-r
    group-by:
        - U
    timespan: 1m
    condition:
        gt: 10
---
title: c039 alias for a rule not in rules
id: c039-alias
correlation:
    type: temporal
    rules:
        - c039-r
    group-by:
        - ip
    timespan: 1m
    aliases:
        ip:
            other: source.ip
```

- [ ] **Step 2: Build and run the targets briefly (nightly toolchain)**

```bash
cd fuzz
cargo +nightly fuzz build correlate
mkdir -p corpus/correlate corpus/parse_rule
cargo +nightly fuzz run correlate corpus/correlate seeds/correlate -- -max_total_time=60 -timeout=10 -dict=dictionaries/correlate.dict
cargo +nightly fuzz run parse_rule corpus/parse_rule seeds/parse_rule -- -max_total_time=60 -timeout=10
cd ..
```
Expected: the `correlate` run prints `Dictionary: 35 entries`; both runs end with `Done N runs in 6x second(s)` and leave no crash file in `fuzz/artifacts/`. `fuzz/Cargo.lock` gains `zaaf-correlate`; commit it (`fuzz/corpus` and `fuzz/artifacts` are git-ignored).

- [ ] **Step 3: Run the tests to see them pass**

Run: `cargo test --workspace --locked`
Expected: PASS, 316 tests (the fuzz crate is not a workspace member; this confirms nothing else changed).

- [ ] **Step 4: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add fuzz/Cargo.toml fuzz/Cargo.lock fuzz/fuzz_targets/correlate.rs fuzz/seeds fuzz/dictionaries/correlate.dict .github/workflows/fuzz.yml
git commit -m "test(fuzz): correlate target for correlation parsing and evaluation" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

### Task 11: Docs, release notes and version 0.0.2 (no tag)

Documents correlation rules, the new flags, the output and the limits; replaces the README's "a per-event work budget is planned" with the shipped budget; adds release notes and bumps the workspace to `0.0.2`. Tagging, pushing and publishing the pre-release need Rifqi's confirmation, as in M1 Task 16, and are not part of this task.

**Files:**
- Create: `docs/releases/0.0.2.md`
- Modify: `README.md`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: everything above.
- Produces: `zaaf --version` prints `zaaf 0.0.2`; README sections "Correlation rules" and updated "Output formats" and "Limits"; `docs/releases/0.0.2.md`.

- [ ] **Step 1: Implement**

In `README.md`, replace:

```markdown
</p>

> [!NOTE]
> **0.0.1 pre-release (milestone M1).** Single-event rules over JSON and NDJSON.
> Correlation rules, EVTX and cloud logs, Parquet and the AI-attack rule pack are planned,
> not yet available. See the [roadmap](#roadmap) and the [design spec](docs/superpowers/specs/2026-11-07-zaafelegia-v0.1-design.md).

## How it works

```

with:

```markdown
</p>

> [!NOTE]
> **0.0.2 pre-release (milestone M2).** Single-event and correlation rules over JSON and
> NDJSON. EVTX and cloud logs, Parquet and the AI-attack rule pack are planned, not yet
> available. See the [roadmap](#roadmap) and the [design spec](docs/superpowers/specs/2026-11-07-zaafelegia-v0.1-design.md).

## How it works

```

In `README.md`, replace:

````markdown

# Read from stdin and fail a CI job on any match
cat today.ndjson | zaaf hunt -r rules/ -o ndjson --fail-on-match -
```

Table and json output appear at the end of the input; ndjson and csv stream as events arrive.
````

with:

````markdown

# Read from stdin and fail a CI job on any match
cat today.ndjson | zaaf hunt -r rules/ -o ndjson --fail-on-match -

# Correlation rules run with the rules they reference; allow 30s of out-of-order input
zaaf hunt -r rules/ --max-lateness 30s logs/*.ndjson
```

Table and json output appear at the end of the input; ndjson and csv stream as events arrive.
````

In `README.md`, replace:

```markdown
| Claim | Where to verify |
|---|---|
| **3,807 of 3,807** SigmaHQ rule files parse and compile, with no warnings | [`scripts/sigmahq-corpus.sh`](scripts/sigmahq-corpus.sh) runs in CI against SigmaHQ commit `53b90df`, using the placeholder pipeline [`tests/sigmahq/placeholders.yml`](tests/sigmahq/placeholders.yml). This measures parse and compile only, not detection accuracy. |
| **30-case** language-neutral Sigma 2.1 conformance suite, with every interpretation written down | [`conformance/`](conformance/README.md). Any engine can run it. |
| **Fuzzed** rule parser, input reader and evaluator | [`fuzz/`](fuzz/) runs on every pull request and nightly ([workflow](.github/workflows/fuzz.yml)). |

Every dependency must pass a `cargo-deny` licence policy that rejects copyleft licences.

```

with:

```markdown
| Claim | Where to verify |
|---|---|
| **3,807 of 3,807** SigmaHQ rule files parse and compile, with no warnings | [`scripts/sigmahq-corpus.sh`](scripts/sigmahq-corpus.sh) runs in CI against SigmaHQ commit `53b90df`, using the placeholder pipeline [`tests/sigmahq/placeholders.yml`](tests/sigmahq/placeholders.yml). This measures parse and compile only, not detection accuracy. |
| **40-case** language-neutral Sigma 2.1 conformance suite, covering every correlation type, with every interpretation written down | [`conformance/`](conformance/README.md). Any engine can run it. |
| **Fuzzed** rule parser, input reader, evaluator and correlator | [`fuzz/`](fuzz/) runs on every pull request and nightly ([workflow](.github/workflows/fuzz.yml)). |

Every dependency must pass a `cargo-deny` licence policy that rejects copyleft licences.

```

In `README.md`, replace:

```markdown
| Milestone | Scope | Status |
|---|---|---|
| **M1 · Engine core** | Sigma 2.1 parser, compiler and native evaluator; `zaaf check` and `zaaf hunt`; OCSF output; conformance suite; SigmaHQ corpus in CI; fuzzing | Shipped in [v0.0.1](https://github.com/rifqifitriady/ZAAFElegia/releases/tag/v0.0.1) |
| **M2 · Correlation** | Sigma v2 correlation rules (`event_count`, `value_count`, `temporal`, `temporal_ordered`, value aggregations) with an ordering buffer and watermark | Next |
| **M3 · Real log sources** | Windows EVTX; CloudTrail (including Bedrock), Entra ID, Okta, M365 and GitHub audit presets; Sysmon, ECS and OCSF pipelines; SigmaHQ `regression_data` | Planned |
| **M4 · Fast history** | The same rules over Parquet through Apache DataFusion, `zaaf explain`, differential tests against the native evaluator | Planned |
| **M5 · AI-era detection** | `zaaf test` and `zaaf coverage` (ATT&CK and ATLAS); a rule pack for LLM gateways and MCP tool calls; a GitHub Action | Planned |
```

with:

```markdown
| Milestone | Scope | Status |
|---|---|---|
| **M1 · Engine core** | Sigma 2.1 parser, compiler and native evaluator; `zaaf check` and `zaaf hunt`; OCSF output; conformance suite; SigmaHQ corpus in CI; fuzzing | Shipped in [v0.0.1](https://github.com/rifqifitriady/ZAAFElegia/releases/tag/v0.0.1) |
| **M2 · Correlation** | Sigma v2 correlation rules (`event_count`, `value_count`, `temporal`, `temporal_ordered`, value aggregations) with an ordering buffer and watermark | Shipped in v0.0.2 |
| **M3 · Real log sources** | Windows EVTX; CloudTrail (including Bedrock), Entra ID, Okta, M365 and GitHub audit presets; Sysmon, ECS and OCSF pipelines; SigmaHQ `regression_data` | Planned |
| **M4 · Fast history** | The same rules over Parquet through Apache DataFusion, `zaaf explain`, differential tests against the native evaluator | Planned |
| **M5 · AI-era detection** | `zaaf test` and `zaaf coverage` (ATT&CK and ATLAS); a rule pack for LLM gateways and MCP tool calls; a GitHub Action | Planned |
```

In `README.md`, replace:

```markdown
That is the `json` and `ndjson` output (`-o json|ndjson`). The rule's `author` and
`references` are always included under `unmapped.sigma`, as the Detection Rule License
(DRL 1.1) requires for SigmaHQ rules.

`-o csv` and `-o table` are summaries, not OCSF. CSV has the columns
`time,level,rule_id,title,author,references,source` (references joined with ` | `).
```

with:

```markdown
That is the `json` and `ndjson` output (`-o json|ndjson`). The rule's `author` and
`references` are always included under `unmapped.sigma`, as the Detection Rule License
(DRL 1.1) requires for SigmaHQ rules.

A correlation alert is also a Detection Finding. It references what contributed instead of
embedding the events: `finding_info.related_events` lists each contributing match (by the
uid its own finding has, even when the rule only feeds correlations) or inner correlation
alert, and `unmapped.correlation` holds the type, timespan, group-by values, condition, the
aggregate value and `events`: the input and record number of every contributing event
(the first 1,000 are listed; `event_count` gives the total). `unmapped.sigma` has the
correlation's own `author` and `references` plus `contributing_rules` with those of every
contributing rule. Its `finding_info.uid` is `<correlation id>:<16 hex digits>`, a hash of the
uids of every contributing match, so the same matches correlating give the same uid on every run.

`-o csv` and `-o table` are summaries, not OCSF. CSV has the columns
`time,level,rule_id,title,author,references,source` (references joined with ` | `).
```

In `README.md`, replace:

```markdown
</details>

<details>
<summary><b>Limits</b></summary>

To keep rules from exhausting memory or time, ZAAFElegia enforces these limits:
```

with:

```markdown
</details>

<details>
<summary><b>Correlation rules</b></summary>

`zaaf hunt` runs every correlation rule it loads with the rules it references, by `id` or
`name`, across files. All Sigma 2.1 types work: `event_count`, `value_count`, `temporal`,
`temporal_ordered`, `value_sum`, `value_avg` and `value_percentile`, plus `value_median`
(accepted with a warning: not part of Sigma 2.1). Chained correlations, aliases and
`generate` work as the specification describes; rules referenced only by correlations with
`generate: false` (the default) produce no finding of their own. Group-by and condition
fields go through the referenced rule's pipelines.

The window of a match at time `t` is `[t - timespan, t]`. The condition is checked after
every match; an alert lists every match in its window and clears the group. These and the
other interpretations are written down in the [conformance suite](conformance/README.md).

Matches are correlated in timestamp order. `--max-lateness` (default `5m`, `0` disables)
says how long to wait for out-of-order matches; a later match is not correlated, and the
summary and a warning naming the rule count it. Matches whose event has no timestamp, or
lacks a group-by field, are counted and reported the same way. `--min-level` and
`--status` choose which rules and correlations alert; rules a selected correlation needs
are still evaluated.

</details>

<details>
<summary><b>Limits</b></summary>

To keep rules from exhausting memory or time, ZAAFElegia enforces these limits:
```

In `README.md`, replace:

```markdown
- Regular expressions use a linear-time engine. Patterns it cannot run fall back to a
  backtracking engine capped at 1,000,000 steps. Hitting that cap counts as no match, and
  `zaaf hunt` prints a warning naming the rule.
- `fieldref|contains` (and the other `fieldref` modes) compares every pair of values of the
  two fields, so its cost grows with the square of the array sizes in the referenced fields.
  Each event is bounded by the 8 MiB line cap; a per-event work budget is planned.

</details>

```

with:

```markdown
- Regular expressions use a linear-time engine. Patterns it cannot run fall back to a
  backtracking engine capped at 1,000,000 steps. Hitting that cap counts as no match, and
  `zaaf hunt` prints a warning naming the rule.
- Per-event work budget: one rule may spend about 64 MiB of compared text (every value
  comparison costs its length; `fieldref` pays for both sides of every pair) on one event.
  Past that the rule counts as not matching that event, and `zaaf hunt` prints a warning
  naming the rule. This bounds keyword searches over huge events and `fieldref` over large
  arrays.
- Correlation state: at most `--max-correlation-groups` open groups (default 100,000;
  the least recently updated group is evicted) and 65,536 matches per group (the oldest
  are dropped); the reorder buffer holds at most 1,000,000 matches (the oldest is then
  correlated early). Every eviction or drop is counted and reported.

</details>

```

Create `docs/releases/0.0.2.md`:

```markdown
# ZAAFElegia 0.0.2 (M2: correlation), pre-release

- Sigma 2.1 correlation rules: `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, plus `value_median` (with a warning: not in Sigma 2.1). References by id or name across files, chained correlations, aliases, `generate`.
- `zaaf check` lints correlations with positions: unknown or ambiguous references, reference cycles, timespan, condition and alias shape.
- `zaaf hunt` correlates in timestamp order through a reorder buffer: `--max-lateness` (default 5m) and `--max-correlation-groups` (default 100,000). Late matches, evicted groups, matches without a timestamp or a group-by field are counted in the summary and named in warnings, never dropped silently.
- Correlation alerts are OCSF Detection Findings that reference their contributing matches (`finding_info.related_events`) and say where each event was read; attribution of every contributing rule is included (DRL 1.1). Their uid is a hash of the contributing match uids, stable across runs.
- Per-event evaluation work budget: one rule may spend about 64 MiB of compared text per event; over-budget evaluations are counted and reported.
- Conformance suite: 40 cases, 10 of them for correlations, with every interpretation written down. SigmaHQ corpus: 3807/3807 files parse and compile (SigmaHQ commit 53b90df).
- New fuzz target `correlate`.

Exit codes are unchanged. Not yet: EVTX and cloud logs (M3), Parquet (M4), the AI rule pack and `zaaf test` (M5).
```

In `Cargo.toml`, replace:

```toml
exclude = ["fuzz"]

[workspace.package]
version = "0.0.1"
edition = "2024"
license = "Apache-2.0"
repository = "https://github.com/rifqifitriady/ZAAFElegia"
```

with:

```toml
exclude = ["fuzz"]

[workspace.package]
version = "0.0.2"
edition = "2024"
license = "Apache-2.0"
repository = "https://github.com/rifqifitriady/ZAAFElegia"
```

In `Cargo.toml`, replace:

```toml
assert_cmd = "2.2"
predicates = "3.1"
tempfile = "3.27"
zaaf-sigma = { path = "crates/zaaf-sigma", version = "0.0.1" }
zaaf-pipeline = { path = "crates/zaaf-pipeline", version = "0.0.1" }
zaaf-ir = { path = "crates/zaaf-ir", version = "0.0.1" }
zaaf-event = { path = "crates/zaaf-event", version = "0.0.1" }
zaaf-eval = { path = "crates/zaaf-eval", version = "0.0.1" }
zaaf-input = { path = "crates/zaaf-input", version = "0.0.1" }
zaaf-testkit = { path = "crates/zaaf-testkit", version = "0.0.1" }
zaaf-correlate = { path = "crates/zaaf-correlate", version = "0.0.1" }

[profile.release]
# panic must stay "unwind": zaaf maps panics to exit code 4 via catch_unwind.
```

with:

```toml
assert_cmd = "2.2"
predicates = "3.1"
tempfile = "3.27"
zaaf-sigma = { path = "crates/zaaf-sigma", version = "0.0.2" }
zaaf-pipeline = { path = "crates/zaaf-pipeline", version = "0.0.2" }
zaaf-ir = { path = "crates/zaaf-ir", version = "0.0.2" }
zaaf-event = { path = "crates/zaaf-event", version = "0.0.2" }
zaaf-eval = { path = "crates/zaaf-eval", version = "0.0.2" }
zaaf-input = { path = "crates/zaaf-input", version = "0.0.2" }
zaaf-testkit = { path = "crates/zaaf-testkit", version = "0.0.2" }
zaaf-correlate = { path = "crates/zaaf-correlate", version = "0.0.2" }

[profile.release]
# panic must stay "unwind": zaaf maps panics to exit code 4 via catch_unwind.
```

- [ ] **Step 2: Regenerate lockfiles; check the version, licences, MSRV and the SigmaHQ corpus**

```bash
cargo build --workspace                                             # updates Cargo.lock to 0.0.2
cargo tree --manifest-path fuzz/Cargo.toml -e normal > /dev/null   # updates fuzz/Cargo.lock to 0.0.2 without building
./target/debug/zaaf --version
cargo deny check
cargo +1.89 check --workspace --all-targets --locked
scripts/sigmahq-corpus.sh
```
Expected: `zaaf 0.0.2`; `cargo deny check` ends with `advisories ok, bans ok, licenses ok, sources ok` (the `syn` duplicate warning is already on `main`); the 1.89 check finishes without errors; the corpus script prints `SigmaHQ corpus: 3807/3807 files parse and compile (100.00%)` and `known unsupported: 0, unexpected failures: 0, now passing: 0` and exits 0 (it needs network access to fetch SigmaHQ; it passes `--expect-counts 3807,3807` for the pinned commit).

- [ ] **Step 3: Run the tests to see them pass**

Run: `cargo test --workspace --locked`
Expected: PASS (316 tests).

- [ ] **Step 4: Format, lint, test, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
git add README.md docs/releases/0.0.2.md Cargo.toml Cargo.lock fuzz/Cargo.lock
git commit -m "docs: correlation rules, limits and 0.0.2 release notes; bump to 0.0.2" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Expected: clippy prints no warnings (it also brings `Cargo.lock` up to date when the task adds a dependency); every test passes with `--locked`.

---

## Self-review against the spec (M2 scope)

| Spec item | Where |
|---|---|
| §3.2 `zaaf-correlate`: consumes a time-ordered match stream, emits alerts; every type incl. `temporal_ordered` and the value types; `timespan`, `group-by`, aliases, generated-rule suppression; one implementation | Tasks 4-6 (window, correlator, engine); `generate` in Tasks 3 and 7 |
| §3.2 `zaaf-ir`: `CompiledCorrelation` references `CompiledRule` ids | Task 3 (`InputSource` indexes, ids in `RuleInfo`) |
| §3.2 `zaaf-sigma`: `CorrelationRule` AST with spans | Task 2 |
| §3.3 reorder buffer, watermark, `--max-lateness` default 5 min, late matches counted and reported, only matches buffered | Tasks 6 and 7 (M2-D11) |
| §3.3 memory cap `--max-correlation-groups`, oldest evicted, metric | Tasks 5 and 7 (M2-D13) |
| §3.4 correlation alert carries every contributing event id; DRL attribution | Task 7 (M2-D14) |
| §4 `hunt` options `--max-lateness`, `--max-correlation-groups`; `check` error for correlations referencing missing rules; exit codes | Tasks 3 and 7 |
| §5.3 conformance: every correlation type, window boundaries, group-by with missing fields, aliases; `spec_ref` notes | Tasks 8 and 9 |
| §6 correlator memory cap and late events in the summary; no panics; fuzzing | Tasks 7 and 10 |
| §7 unit tests in every crate, conformance gate, fuzzing | every task; Task 10 |
| §8 M2 "done when: correlation conformance passes" | Task 9 |
| M1 final review: per-event work budget | Task 1 |
| SigmaHQ corpus stays 3807/3807 | Task 11 Step 2 (verified: exact counts 3807/3807, 0 errors, 0 warnings; the pinned corpus has no correlation documents) |

**Placeholder scan:** no step says "TBD", "add error handling" or "similar to"; every code step shows the code.

**Type consistency:** names used across tasks were checked against the code that compiled: `CompiledCorrelation`, `InputSource::{Rule, Correlation}`, `FieldSource::{Event, Group}`, `CorrelationOnly`, `correlation_only`, `Correlator::{observe, process, consumes}`, `CorrelationEngine::{push, finish, late_matches, stats, forced_releases}`, `EngineLimits`, `Limits`, `parse_lateness`, `MatchRef`, `finding_uid`, `correlation_finding`, `Selection`.

**Verified (on a fresh `git archive` export of `main` at `9096ecc`, macOS arm64):** after each task: code already rustfmt-clean, clippy `-D warnings`, `cargo test --workspace --locked` (totals 245, 255, 264, 272, 288, 297, 311, 316, 316, 316, 316); after Task 11: `cargo deny check` (advisories, bans, licences and sources ok), `cargo +1.89 check --workspace --all-targets --locked`, SigmaHQ corpus 3807/3807 with `--expect-counts 3807,3807`, 0 errors and 0 warnings (run locally with the pinned checkout, not through the script's network fetch); the result of the replay is identical to the prototype except for `fuzz/Cargo.lock`, which Steps in Tasks 10 and 11 regenerate (the regenerated file was compared and matches); the conformance runner fails when a correlation expectation is altered; `correlate` fuzzed 90 s (268k runs) with its seeds and dictionary and `parse_rule` 60 s (556k runs) with the new seeds, no crash.

**Not verified:** CI on Linux and Windows (the workflows themselves were not run; only their matrix line changes); `cargo test` on Rust 1.89 (only `cargo +1.89 check`); fuzzing beyond a few minutes; throughput on large inputs (the work budget adds per-value bookkeeping; no benchmark exists yet, design §7 item 6 is later); the README roadmap images, which still say "next M2" and stay out of scope.
