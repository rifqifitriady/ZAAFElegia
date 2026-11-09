# Logsource: ZAAFVesper

[ZAAFVesper](https://github.com/rifqifitriady/ZAAFVesper) is a behaviour sensor for macOS. It also reads Sysmon on Windows and Linux. It writes its events as NDJSON with Sigma field names, so `zaaf hunt` can run Sigma rules over them:

```bash
# live, from the sensor
sudo zaafvesper run --elegia-out - | zaaf hunt -p pipelines/zaafvesper.yml -r rules/ -o ndjson -

# scheduled, over closed segment files
zaaf hunt -p pipelines/zaafvesper.yml -r rules/ /var/db/zaafvesper/elegia/*.ndjson

# offline, from a capture
zaafvesper replay --elegia-host mac-01 --elegia-out - capture.rcap | zaaf hunt -p pipelines/zaafvesper.yml -r rules/ -
```

## Logsources

| `product` | Source on that platform |
|---|---|
| `macos` | Endpoint Security (eslogger); socket polling for network events |
| `windows` | Sysmon (Microsoft-Windows-Sysmon/Operational) |
| `linux` | Sysmon for Linux |

Categories: `process_creation`, `process_termination`, `file_event`, `file_delete`, `file_rename`, `network_connection`, `dns_query`, `image_load`, `driver_load`, `registry_add`, `registry_delete`, `registry_set`, `registry_rename`, `create_remote_thread`, `process_access`, `pipe_created`, `wmi_event`, `process_tampering`, `create_stream_hash`. Each record names its own in `logsource.category`. On macOS, `dns_query` never occurs, and network events come from polling, so connections shorter than a poll interval are missed.

## Record format (schema `zaafvesper.elegia/1`)

- **Sigma fields** of the record's category, with Sysmon names: `Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `DestinationIp`, `DestinationPort`, `Initiated` (`"true"`/`"false"`), and so on. Pids and ports are numbers, booleans are the strings `true`/`false` as in Sysmon, and empty values are left out.
- **Fixed fields:**
  - `logsource.product` and `logsource.category`;
  - `EventID` (Sysmon-compatible);
  - `UtcTime` (Sysmon format, UTC, which zaaf reads as the event time);
  - `Computer` (the host).
- **`zaafvesper`:** ZAAFVesper's own fields.
  - `schema`, `name` (the canonical event), `seq`, `source`, `platform`;
  - `identity: unverified`;
  - on macOS, `proc` and `parent` with the code-signing identity and the kernel's unique process id.

The JSON Schema and its versioning rules live in ZAAFVesper: [`integrations/zaafelegia/schema/`](https://github.com/rifqifitriady/ZAAFVesper/tree/main/integrations/zaafelegia/schema).

## The `zaafvesper` pipeline (`pipelines/zaafvesper.yml`)

The records already use Sigma field names, so standard Sigma rules need no mapping. The preset does three things:
- **Declares ZAAFVesper's fields.** It maps every Sigma field ZAAFVesper emits to itself, so `zaaf` does not warn that the fields are "not mapped by any pipeline".
- **Gives macOS processes a key for correlations.** macOS has no `ProcessGuid`, so on macOS `ProcessGuid` and `ParentProcessGuid` fall back to the kernel's per-boot unique process ids (`zaafvesper.proc.unique_id`, `zaafvesper.parent.unique_id`). A real `ProcessGuid` stays first.
- **Names the macOS code-signing identity.** Sigma has no fields for it, so on macOS the preset adds:

| Rule field | Record path |
|---|---|
| `SigningId` | `zaafvesper.proc.signing_id` |
| `TeamId` | `zaafvesper.proc.team_id` |
| `SigningCategory` | `zaafvesper.proc.cs_category` (`platform`, `developer_id`, `app_store`, `local_signing`, ...) |
| `PlatformBinary` | `zaafvesper.proc.is_platform` |
| `Signed` | `zaafvesper.proc.is_signed` |
| `ParentSigningId` | `zaafvesper.parent.signing_id` |
| `ParentPlatformBinary` | `zaafvesper.parent.is_platform` |
| `IdentityUnverified` | `zaafvesper.identity` |
| `ZaafEventName` | `zaafvesper.name` |

The preset is generated in ZAAFVesper from its field map (`integrations/zaafelegia/samples/gen -pipeline`). Change it there and copy it here.

## Sample events

[`tests/zaafvesper/macos-scenarios.ndjson`](../../tests/zaafvesper/macos-scenarios.ndjson) holds 18 macOS records:
- download, `chmod +x` and execution from `/tmp`;
- a burst of discovery commands from one script;
- a shell connecting out to three ports;
- quarantine removed from five files;
- benign lookalikes.

They are the scenarios behind ZAAFVesper's Sigma base and correlation rules (`integrations/zaafelegia/rules` there). ZAAFVesper's CI workflow `elegia-e2e` builds `zaaf` at a pinned commit of this repository and checks the preset, the rules and the expected findings against these samples, both from files and through a live pipe. This change adds no test or code here.

## Limits

- **Logsource is not enforced by the engine yet.** A rule written for `process_creation` is evaluated against every record, so a rule that only tests `Image` can also match that process's network or file records. pySigma's Sysmon pipeline restricts a rule to its category with `add_condition` on `EventID`. The records carry `EventID` and `logsource.category`, ready for such a transformation, but the pipeline format here does not have one yet.
- **Correlation rules** written for these records need milestone M2. Until then `zaaf` parses and skips them.
