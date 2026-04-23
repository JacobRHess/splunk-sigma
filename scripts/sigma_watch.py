#!/usr/bin/env python3
"""sigma_watch — run Sigma rules against Splunk via the REST API.

This is the "external service" counterpart to the `| sigma` search command.
Instead of evaluating rules inside Splunk as a streaming command, this script:

  1. Connects to Splunk via its REST API (the same API the Web UI uses)
  2. Runs a Splunk search and pulls results back
  3. Evaluates each event against the bundled Sigma rules
  4. Emits alerts to stdout (and optionally writes them back to a Splunk index)

Why this exists alongside the in-Splunk command:
  - Portable: one process can monitor many Splunk instances
  - Doesn't require installing a custom app on the Splunk server
  - Mirrors how production SOC detection services are actually built

Usage:
  # One-shot scan of everything in main index
  python3 scripts/sigma_watch.py --once

  # Custom search, only T1059.001 rules
  python3 scripts/sigma_watch.py --once \\
      --search 'search index=main sourcetype=_json' \\
      --rules 'attack:T1059.001'

  # Poll every 60s, write alerts back to a 'sigma_alerts' index
  python3 scripts/sigma_watch.py --interval 60 --output-index sigma_alerts

Environment variables (used as defaults, overridden by CLI flags):
  SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USERNAME, SPLUNK_PASSWORD, SPLUNK_SCHEME
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# Engine lives under app/bin so Splunk can load it too.
sys.path.insert(0, str(REPO / "app" / "bin"))
# Vendored splunklib (installed into app/bin/lib for the Splunk app).
sys.path.insert(0, str(REPO / "app" / "bin" / "lib"))

from sigma_engine import Evaluator, load_rules_from_dir  # noqa: E402
from sigma_engine.rules import filter_rules  # noqa: E402

try:
    import splunklib.client as splunk_client  # noqa: E402
    import splunklib.results as splunk_results  # noqa: E402
except ImportError:
    sys.stderr.write(
        "error: splunk-sdk not installed.\n"
        "  pip install splunk-sdk\n"
        "  or: pip install .[dev]\n"
    )
    sys.exit(2)


LEVEL_COLORS = {
    "critical": "\033[1;97;41m",
    "high":     "\033[1;31m",
    "medium":   "\033[1;33m",
    "low":      "\033[1;36m",
}
RESET = "\033[0m"
DIM = "\033[2m"


def _colorize(level: str, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{LEVEL_COLORS.get(level.lower(), '')}{text}{RESET}"


def _print_alert(m, use_color: bool) -> None:
    tag = _colorize(m.rule.level, f"[{m.rule.level.upper()}]", use_color)
    attack = ",".join(m.rule.attack) or "—"
    evt = m.event
    who = evt.get("User") or evt.get("TargetUserName") or evt.get("user") or "—"
    when = evt.get("_time") or evt.get("time") or "?"
    evidence = evt.get("CommandLine") or evt.get("IpAddress") or evt.get("_raw") or ""
    if isinstance(evidence, str) and len(evidence) > 120:
        evidence = evidence[:119] + "…"
    print(f"{tag} {m.rule.title}")
    print(f"  {DIM}rule:{RESET} {m.rule.id}    {DIM}ATT&CK:{RESET} {attack}")
    print(f"  {DIM}time:{RESET} {when}    {DIM}user:{RESET} {who}")
    if evidence:
        print(f"  {DIM}evidence:{RESET} {evidence}")
    print()


def _connect(args) -> splunk_client.Service:
    return splunk_client.connect(
        host=args.host,
        port=int(args.port),
        scheme=args.scheme,
        username=args.username,
        password=args.password,
        autologin=True,
    )


def _iter_search_results(service, search: str, max_count: int):
    """Run an exportSearch and yield each result as a dict.

    Uses oneshot for simplicity — fine for demos and moderate result sets.
    For long-running / large searches you'd swap this for a normal job with
    paginated .results() calls.
    """
    if not search.lstrip().startswith("search "):
        search = f"search {search}"
    kwargs = {"output_mode": "json", "count": max_count}
    stream = service.jobs.oneshot(search, **kwargs)
    reader = splunk_results.JSONResultsReader(stream)
    for item in reader:
        if isinstance(item, dict):
            yield item


def _write_alert_to_index(service, index_name: str, match) -> None:
    payload = {
        "sigma_rule_id": match.rule.id,
        "sigma_rule_title": match.rule.title,
        "sigma_level": match.rule.level,
        "sigma_attack": ",".join(match.rule.attack),
        "sigma_matched_selections": ",".join(match.matched_selections),
        "source_event": match.event,
    }
    idx = service.indexes[index_name]
    idx.submit(json.dumps(payload), sourcetype="sigma:alert")


def _scan_once(service, evaluator, args, use_color: bool) -> int:
    total_events = 0
    alerts = 0
    for event in _iter_search_results(service, args.search, args.max_events):
        total_events += 1
        matches = evaluator.match(event)
        for m in matches:
            alerts += 1
            _print_alert(m, use_color)
            if args.output_index:
                _write_alert_to_index(service, args.output_index, m)
    summary = (
        f"scanned {total_events} event(s), {alerts} alert(s)"
        + (f", wrote to index={args.output_index}" if args.output_index else "")
    )
    print(_colorize("high" if alerts else "low", summary, use_color))
    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", default=os.environ.get("SPLUNK_HOST", "localhost"))
    parser.add_argument("--port", default=os.environ.get("SPLUNK_PORT", "8089"))
    parser.add_argument("--scheme", default=os.environ.get("SPLUNK_SCHEME", "https"),
                        choices=["http", "https"])
    parser.add_argument("--username", default=os.environ.get("SPLUNK_USERNAME"))
    parser.add_argument("--password", default=os.environ.get("SPLUNK_PASSWORD"))
    parser.add_argument("--search", default='search index=main | fields *',
                        help='Splunk search (default: "search index=main | fields *")')
    parser.add_argument("--rules-dir", default=str(REPO / "app" / "bin" / "rules"))
    parser.add_argument("--rules", default="*", help='Selector (default "*")')
    parser.add_argument("--max-events", type=int, default=1000,
                        help="Max events per scan (default 1000)")
    parser.add_argument("--output-index", default=None,
                        help="If set, write alerts back to this Splunk index")
    parser.add_argument("--once", action="store_true",
                        help="Run one scan and exit (default)")
    parser.add_argument("--interval", type=int, default=0,
                        help="Poll every N seconds (instead of --once)")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    if not args.username or not args.password:
        parser.error("Splunk credentials required: set --username/--password "
                     "or SPLUNK_USERNAME/SPLUNK_PASSWORD env vars")

    all_rules = load_rules_from_dir(args.rules_dir)
    selected = filter_rules(all_rules, args.rules)
    evaluator = Evaluator(selected)
    use_color = not args.no_color and sys.stdout.isatty()

    print(f"{DIM}Connecting to {args.scheme}://{args.host}:{args.port} as {args.username}…{RESET}")
    service = _connect(args)
    print(f"{DIM}Loaded {len(selected)} rule(s). Search: {args.search}{RESET}")
    print()

    if args.interval and not args.once:
        try:
            while True:
                _scan_once(service, evaluator, args, use_color)
                print(f"{DIM}sleeping {args.interval}s…{RESET}")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n{DIM}stopped.{RESET}")
            return 0
    else:
        alerts = _scan_once(service, evaluator, args, use_color)
        return 0 if alerts or True else 1


if __name__ == "__main__":
    sys.exit(main())
