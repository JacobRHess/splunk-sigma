# Installing splunk-sigma into Splunk Enterprise

This guide gets the app running in a local Splunk Enterprise instance so you can see the `| sigma` command in action and capture screenshots for the README.

Estimated time: **~25 minutes**, most of which is waiting for the Splunk download.

## 1. Create a Splunk account (free)

1. Go to <https://www.splunk.com/en_us/sign-up.html> and create an account.
2. Accept the free developer license.

## 2. Download Splunk Enterprise

1. Go to <https://www.splunk.com/en_us/download/splunk-enterprise.html>.
2. Pick the macOS `.dmg` for your architecture (Apple Silicon or Intel).
3. Download (~500 MB).

## 3. Install

1. Open the `.dmg` and run the installer. Accept defaults. Install location: `/Applications/Splunk`.
2. The installer will prompt you for an admin password — this becomes your Splunk admin password.
3. After install, Splunk starts automatically and opens <http://localhost:8000> in your browser. Log in with `admin` + the password you set.

## 4. Symlink the app

From inside the repo:

```bash
export SPLUNK_HOME=/Applications/Splunk
bash scripts/install_local.sh
$SPLUNK_HOME/bin/splunk restart
```

Refresh <http://localhost:8000> — you should see **Sigma Detections** in the app list on the left.

## 5. Load the sample attack data

```bash
$SPLUNK_HOME/bin/splunk add oneshot samples/attack_samples.jsonl \
    -sourcetype _json -index main
```

## 6. Run the command

In the Splunk **Search & Reporting** app, run:

```
index=main | sigma rules="*"
```

You should see **8 alerts** (one per attack event in the sample data) with fields like `sigma_rule_id`, `sigma_rule_title`, `sigma_level`, `sigma_attack`.

## 7. Open the ATT&CK Coverage dashboard

Click **Sigma Detections** in the left nav → **ATT&CK Coverage**.

## 8. Screenshots worth capturing

For the README / LinkedIn post:

1. **Search results**: `index=main | sigma rules="*"` showing the enriched `sigma_*` fields
2. **Filter by technique**: `index=main | sigma rules="attack:T1003.001"` showing only LSASS alerts
3. **Dashboard**: the ATT&CK Coverage view with the sample data loaded
4. **Apps list**: showing "Sigma Detections" installed

## Troubleshooting

- **`| sigma` errors with "external search command 'sigma' not found"**
  - Run `$SPLUNK_HOME/bin/splunk restart` — `commands.conf` only reloads on restart.
- **ImportError from splunklib**
  - Make sure `app/default/commands.conf` has `python.version = python3`.
- **No results**
  - Verify data loaded: `index=main | head 5`
  - Check sourcetype is `_json` so fields parse correctly
