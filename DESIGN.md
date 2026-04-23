# `splunk-sigma` — Design Doc

A Splunk app that brings detection-as-code to Splunk by implementing a custom `| sigma` search command. Pipe any Splunk search result through it to evaluate Sigma rules without leaving the SIEM.

## Why this exists

Splunk shops want Sigma (vendor-neutral, shareable rules) but Sigma's converter produces static SPL that's hard to maintain. This app executes Sigma rules **natively inside Splunk** — one codebase, runs anywhere Splunk runs, always in sync with the upstream rules.

## What it does (one-liner)

```
index=sysmon EventCode=1 | sigma rules="app:powershell_*"
```
Pipes Sysmon process-creation events through the Sigma engine, emits alerts for any matching rules.

## Scope for v1

**In scope:**
- Custom Splunk search command `| sigma` (StreamingCommand)
- Bundled Sigma rule library (7 rules, ATT&CK-mapped)
- Embedded Python Sigma evaluator (no external deps at Splunk runtime)
- Pre-built saved searches wiring rules to common data sources
- ATT&CK coverage dashboard (Splunk XML)
- Sample attack data + install script for local testing
- CI: lints rules, runs pytest on the evaluator, builds `.tgz` for Splunkbase

**Out of scope (v1):**
- Sigma correlations / aggregations
- Real-time modular alerts
- Splunk Cloud app certification (Enterprise-only for v1)
- Web UI for rule management

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│ Splunk search   │     │  | sigma command │     │ Alert events   │
│ (any index)     │ ──▶ │  (StreamingCmd)  │ ──▶ │ back to SPL    │
└─────────────────┘     └──────────────────┘     └────────────────┘
                                │
                                ▼
                        ┌──────────────────┐
                        │  Sigma engine    │
                        │  (bundled in bin)│
                        └──────────────────┘
                                │
                                ▼
                        ┌──────────────────┐
                        │  rules/*.yml     │
                        │  (bundled)       │
                        └──────────────────┘
```

## Repo layout

```
splunk-sigma/
├── README.md
├── DESIGN.md
├── pyproject.toml               # dev tooling only (pytest, ruff)
├── app/                         # ← the actual Splunk app (what gets packaged)
│   ├── default/
│   │   ├── app.conf
│   │   ├── commands.conf        # registers | sigma
│   │   ├── savedsearches.conf   # pre-built detections
│   │   ├── macros.conf
│   │   └── data/ui/views/
│   │       └── attack_coverage.xml
│   ├── bin/
│   │   ├── sigma_command.py     # Splunk entrypoint (StreamingCommand)
│   │   ├── sigma_engine/        # the evaluator
│   │   │   ├── rules.py
│   │   │   ├── evaluator.py
│   │   │   └── operators.py
│   │   └── rules/               # bundled Sigma YAML
│   ├── metadata/default.meta
│   ├── README.md
│   └── LICENSE
├── tests/                       # pytest, run outside Splunk
│   ├── test_evaluator.py
│   └── fixtures/*.jsonl
├── samples/                     # load-into-Splunk sample data
├── scripts/
│   ├── package.sh               # tar czf splunk-sigma.tgz
│   └── install_local.sh         # symlink to $SPLUNK_HOME/etc/apps/
└── .github/workflows/ci.yml
```

## Tech decisions

- **Language**: Python 3 (Splunk bundles it)
- **Splunk SDK**: `splunklib.searchcommands.StreamingCommand`
- **Rule parser**: custom (same evaluator as standalone Python project, adapted)
- **YAML**: `pyyaml` (bundled with Splunk — no wheels needed)
- **No runtime deps beyond what ships with Splunk** — critical for app certification later

## Sigma feature subset for v1

Same as standalone engine:
- `detection.selection` (single + multiple)
- Conditions: `selection`, `a and b`, `a and not b`, `1 of selection_*`
- Modifiers: `contains`, `startswith`, `endswith`, `re`
- Field list values (OR semantics)
- **Not v1**: aggregations, correlations, timeframes

## Sample rules for v1 (ATT&CK-mapped)

1. **T1059.001** — PowerShell encoded command
2. **T1003.001** — LSASS memory dump indicators
3. **T1053.005** — Scheduled task creation
4. **T1547.001** — Registry Run key persistence
5. **T1021.001** — Unusual RDP logon source
6. **T1105** — certutil.exe download
7. **T1070.004** — Secure file deletion (cipher /w)

## Demo flow (README)

```
index=sysmon | sigma rules="app:*"
→ results:
  _time  rule_id           rule_title                       attack
  14:03  t1059_001_pwsh    PowerShell Encoded Command       T1059.001
  14:07  t1053_005_schtsk  Scheduled Task Persistence       T1053.005
```

Plus a dashboard screenshot showing ATT&CK coverage heatmap.

## What you need to set up outside Claude Code

1. **Install Splunk Enterprise** (free dev license) — ~20 min
   - Download from splunk.com/download
   - Default install: `/Applications/Splunk` on Mac
2. **Set `SPLUNK_HOME` env var** pointing at that install
3. **Run `scripts/install_local.sh`** (I'll write it) to symlink the app in
4. **Restart Splunk, load sample data, run searches** — ~10 min
5. **Capture screenshots** of searches + dashboard for the README

Claude Code handles: all code, configs, rules, tests, CI, packaging, docs.
You handle: install Splunk, test in UI, screenshots.

## Open questions

1. **App name**: `splunk-sigma`, `sigmasplunk`, `splunk-attack-detect`, other?
2. **Splunk already installed?** If yes, I'll write scripts assuming `/Applications/Splunk`. If no, I'll include install instructions.
3. **Rule set**: the 7 techniques above — swap any?
4. **Screenshots**: willing to install Splunk + load sample data to get real screenshots, or skip and ship without?

Once you answer these I'll scaffold the repo and start building.
