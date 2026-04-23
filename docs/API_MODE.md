# API mode — running Sigma against Splunk's REST API

`splunk-sigma` ships in two modes. You've already seen Mode 1 in the README.

| | **Mode 1: `\| sigma` command** | **Mode 2: `sigma_watch`** |
|---|---|---|
| Where rules run | Inside Splunk (StreamingCommand) | Outside Splunk (Python process) |
| Integration | Custom search command | Splunk REST API (port 8089) |
| Install surface | Splunk app on the indexer / search head | None — standalone script |
| Good for | Interactive SPL, dashboards | Polling detections, multi-instance monitoring, CI |
| Writes alerts where | Back into the search pipeline | stdout, or back to a Splunk index |

Both modes share the **same rule files** and the **same evaluator** — just different front-ends.

## Architecture

```
Mode 1 (in-Splunk)                 Mode 2 (API)

┌──────────────┐                   ┌──────────────┐
│ SPL search   │                   │ sigma_watch  │
│ | sigma      │                   │ (external)   │
└──────┬───────┘                   └──────┬───────┘
       │                                  │ REST (8089)
       ▼                                  ▼
┌──────────────┐                   ┌──────────────┐
│ Sigma engine │                   │   Splunk     │
│ (app/bin/)   │                   │  (any host)  │
└──────────────┘                   └──────┬───────┘
                                          │
                                          ▼
                                   ┌──────────────┐
                                   │ Sigma engine │
                                   │ (local copy) │
                                   └──────────────┘
```

## Quickstart

```bash
# one-time setup
pip install .[dev]

# credentials (replace with your Splunk login)
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD='<your-password>'

# one-shot scan of the main index
python3 scripts/sigma_watch.py --once

# only T1059.001 (PowerShell) rules
python3 scripts/sigma_watch.py --once --rules 'attack:T1059.001'

# poll every 60s and write alerts into a Splunk index
python3 scripts/sigma_watch.py --interval 60 --output-index sigma_alerts
```

## Example output

```
Connecting to https://localhost:8089 as admin…
Loaded 7 rule(s). Search: search index=main | fields *

[HIGH] PowerShell Encoded Command Execution
  rule: t1059_001_pwsh_encoded    ATT&CK: T1059.001
  time: 2026-04-22T14:03:11Z      user: CORP\alice
  evidence: powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=

[CRITICAL] LSASS Credential Dump Indicators
  rule: t1003_001_lsass_dump      ATT&CK: T1003.001
  time: 2026-04-22T14:05:02Z      user: CORP\attacker
  evidence: mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

...

scanned 11 event(s), 8 alert(s)
```

## Writing alerts back to Splunk

With `--output-index sigma_alerts`, each alert is written back as a JSON
event with sourcetype `sigma:alert`. You can then build dashboards off it
with normal SPL:

```
index=sigma_alerts | stats count by sigma_rule_title, sigma_level
```

First create the index in Splunk Web (Settings → Indexes → New Index) or via:

```bash
$SPLUNK_HOME/bin/splunk add index sigma_alerts
```

## Why build it this way

Real SOC detection pipelines often decouple "where logs live" from "where
detections run." A service that polls the SIEM's API is:

- **Portable** — point it at any Splunk instance, including Splunk Cloud
- **Testable** — runs in CI, in a container, on a laptop
- **Versionable** — the detection service is just code, deployed like any other service
- **Independent of indexer load** — long evaluations don't block search heads

Mode 1 is better for interactive analyst work. Mode 2 is better for
always-on detection services. Real shops run both.
