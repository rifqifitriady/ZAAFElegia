# Sigma conformance suite

A language-neutral test suite for Sigma 2.1 rule semantics. Any engine can run it:
load `rules/*.yml` (plus `pipelines` from `case.yml`, if any), evaluate every line of
`events.ndjson`, and compare the matching rule ids with `expected` in `case.yml`.

| File | Content |
|---|---|
| `case.yml` | `spec_ref` (spec section), `description` (what is tested, including any interpretation of an ambiguous point), optional `pipelines` and `compile_errors`, and `expected`: one list of rule ids per event |
| `rules/*.yml` | Standard Sigma rules (no extensions); the interpretations below are pinned, not extended |
| `events.ndjson` | One JSON event per line |

Interpretations used where the specification is silent (each is pinned by a case):

1. Keyword values match as `contains` over every value of the event (case 008).
2. `field: null` matches an absent field or a JSON null; `exists` checks presence only (009, 010).
3. `neq` is a negation, so an absent field satisfies it (012).
4. Regular expressions are unanchored searches; `re` is case-sensitive unless `|i` is given (003, 013).
5. Encoded values (`base64`, `base64offset`, `wide`) are matched case-insensitively like every other string (016, 017).
6. Field paths resolve an exact dotted key first, then nested objects; arrays match if any element matches (023).
7. `all` combined with an expanding modifier (`windash`, `base64offset`, `expand`) is AND across the original values and OR across each value's variants (026).
8. `null` on a field mapped to several names is true only if every mapped alternative is absent or JSON null, mirroring `exists` (027).
9. `cidr` canonicalizes IPv4-mapped IPv6 event addresses (`::ffff:10.1.2.3` matches `10.0.0.0/8`), ignores a `%zone` suffix, and accepts a bare address in the rule as a /32 or /128 (028).
10. Modifier combinations whose effect would be silently ignored are rule errors: string transforms on `re`, `cidr`, numeric, time or `exists`; more than one comparison or time modifier; `exists` with other modifiers; `fieldref` with anything but one of `contains`, `startswith`, `endswith` (029).

11. `fieldref` compares case-insensitively and combines with exactly one of `contains`, `startswith`, `endswith`; a missing field never matches (018).
12. Numeric comparisons accept JSON numbers and numeric strings; a non-numeric string never matches (011).
13. Time modifiers (`hour`, `day`, ...) work in UTC on a parseable timestamp; an unparseable value never matches (022).
14. `expand` values taken from a pipeline may contain wildcards (019).
15. A regex flag modifier (`i`, `m`, `s`) without `re` is a rule error (025).

## Pipeline format (ZAAFElegia)

Cases 019, 024 and 027 use a small pipeline file. Other engines can translate it to their own format:

```yaml
name: example
vars:                        # placeholders for the `expand` modifier
  Admins: ['adm_*', root]    # %Admins% expands to this list (values may contain wildcards)
transformations:
  - type: field_name_mapping
    mapping:
      Image: process.executable                  # rename a field
      CommandLine: [process.command_line, process.args]   # several names: OR (any), `null`/`exists`: all names
    rule_conditions:         # apply only to rules whose logsource matches every key
      - product: windows
```

Other engines are welcome to run the suite and to propose new cases or challenge an interpretation by opening an issue.
