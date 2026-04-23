# splunk-sigma (Splunk app)

Custom Splunk search command `| sigma` that evaluates [Sigma](https://github.com/SigmaHQ/sigma) YAML detection rules against piped events. Bundled rules map to MITRE ATT&CK.

## Quick demo

```
index=* sourcetype=_json | sigma rules="*"
```

Matching events are enriched with:
- `sigma_rule_id`
- `sigma_rule_title`
- `sigma_level` — low / medium / high / critical
- `sigma_attack` — comma-separated ATT&CK technique IDs
- `sigma_matched_selections`

## Filter by ATT&CK technique

```
index=* sourcetype=_json | sigma rules="attack:T1059.001"
```

## Dashboards

- **ATT&CK Coverage** — alerts per technique, severity breakdown, recent detections

## Saved searches

Pre-wired, disabled by default — enable/schedule in Splunk Web:

- `sigma_all_process_creation`
- `sigma_credential_access`
- `sigma_persistence`
- `sigma_lateral_rdp_external`
- `sigma_lolbin_downloads`

See the project repo README for full command reference, architecture, and supported Sigma features.
