# splunk-sigma

**Run [Sigma](https://github.com/SigmaHQ/sigma) detection rules natively inside Splunk** via a custom `| sigma` search command. Bundled content maps to [MITRE ATT&CK](https://attack.mitre.org/) and ships with a coverage dashboard.

```
index=sysmon EventCode=1 | sigma rules="attack:T1059.001"
```

---

## Why this exists

Splunk shops want Sigma — vendor-neutral, shareable detections — but the standard path (convert Sigma → static SPL) produces fragile search strings that drift from the upstream rules. `splunk-sigma` takes the other path: it runs the Sigma rule evaluator **inside Splunk** as a streaming command. One rule file, always in sync.

## Features

- **`| sigma` streaming search command** — evaluates Sigma YAML rules against any piped events
- **7 bundled rules** mapped to MITRE ATT&CK (credential access, persistence, lateral movement, LOLBins, defense evasion)
- **ATT&CK coverage dashboard** showing alerts per technique / severity
- **Pre-wired saved searches** for common Sysmon / Security log sources
- **Zero external runtime deps** beyond what ships with Splunk
- **GitHub Actions CI** — lints rules, runs the evaluator test suite, builds the app tarball

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│ Splunk search   │     │  | sigma command │     │ Enriched events│
│ (any index)     │ ──▶ │  (StreamingCmd)  │ ──▶ │ back to SPL    │
└─────────────────┘     └──────────────────┘     └────────────────┘
                                │
                                ▼
                        ┌──────────────────┐
                        │  Sigma engine    │  (bundled in app/bin/)
                        │  rules + eval    │
                        └──────────────────┘
```

## Quickstart (no Splunk needed)

The engine runs standalone — useful for CI and for testing rules without spinning up Splunk.

```bash
git clone https://github.com/<you>/splunk-sigma
cd splunk-sigma
pip install .[dev]
PYTHONPATH=app/bin pytest -v
```

## Install into Splunk Enterprise

1. Install [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) (free developer license).
2. Set `SPLUNK_HOME` to your install path (defaults to `/Applications/Splunk` on macOS).
3. Symlink the app into Splunk and restart:
   ```bash
   export SPLUNK_HOME=/Applications/Splunk
   bash scripts/install_local.sh
   $SPLUNK_HOME/bin/splunk restart
   ```
4. Load the sample attack data:
   ```bash
   $SPLUNK_HOME/bin/splunk add oneshot samples/attack_samples.jsonl \
       -sourcetype _json -index main
   ```
5. In Splunk Web, run:
   ```
   index=main | sigma rules="*"
   ```

You should see alerts for all 7 bundled techniques.

## Bundled detections

| Rule | ATT&CK | Severity |
|------|--------|----------|
| PowerShell Encoded Command Execution | T1059.001 | high |
| LSASS Credential Dump Indicators | T1003.001 | critical |
| Scheduled Task Creation via schtasks.exe | T1053.005 | medium |
| Registry Run Key Persistence via reg.exe | T1547.001 | high |
| RDP Logon from External Source | T1021.001 | high |
| Suspicious Download via certutil.exe | T1105 | high |
| Secure File Deletion via cipher.exe | T1070.004 | high |

## Command reference

```
| sigma [rules=<selector>] [rules_dir=<path>]
```

- `rules` — selector. Examples:
  - `"*"` (default) — all loaded rules
  - `"attack:T1059.001"` — rules tagged with a specific ATT&CK technique
  - `"id:t1053*"` — rule ID glob
- `rules_dir` — override the bundled rules directory (absolute path)

Each matching event is emitted with additional fields:
`sigma_rule_id`, `sigma_rule_title`, `sigma_level`, `sigma_attack`, `sigma_matched_selections`.

## Supported Sigma features (v1)

- Multiple selections, `and` / `or` / `not`, parentheses
- `1 of selection_*`, `all of selection_*` quantifiers
- Modifiers: `contains`, `startswith`, `endswith`, `re`
- Field list values (OR semantics)

**Not supported in v1**: aggregations (`count()`), correlations across events, timeframes.

## Repo layout

```
splunk-sigma/
├── app/                     Splunk app (what gets packaged)
│   ├── default/             app.conf, commands.conf, dashboards, saved searches
│   ├── bin/
│   │   ├── sigma_command.py   StreamingCommand entrypoint
│   │   ├── sigma_engine/      rule loader + evaluator
│   │   └── rules/             bundled Sigma YAML
│   └── metadata/
├── samples/                 attack log fixtures
├── scripts/                 install_local.sh, package.sh
├── tests/                   pytest suite
└── .github/workflows/ci.yml
```

## License

MIT — see [`app/LICENSE`](app/LICENSE).
