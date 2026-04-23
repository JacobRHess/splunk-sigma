#!/usr/bin/env python3
"""Standalone CLI demo — runs the Sigma engine against a JSONL log file.

Useful for:
  - showing the project works without needing Splunk installed
  - README screenshots / terminal-recording demos
  - CI sanity checks

Usage:
  python3 scripts/demo.py samples/attack_samples.jsonl
  python3 scripts/demo.py <logfile> --rules "attack:T1059.001"
  python3 scripts/demo.py <logfile> --format json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "app" / "bin"))

from sigma_engine import Evaluator, load_rules_from_dir  # noqa: E402
from sigma_engine.rules import filter_rules  # noqa: E402


LEVEL_COLORS = {
    "critical": "\033[1;97;41m",  # bold white on red
    "high":     "\033[1;31m",      # bold red
    "medium":   "\033[1;33m",      # bold yellow
    "low":      "\033[1;36m",      # bold cyan
}
RESET = "\033[0m"
DIM = "\033[2m"


def _colorize(level: str, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    c = LEVEL_COLORS.get(level.lower(), "")
    return f"{c}{text}{RESET}"


def _truncate(s: str, n: int = 90) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("logfile", help="JSONL file, one event per line")
    parser.add_argument("--rules-dir", default=str(REPO / "app" / "bin" / "rules"),
                        help="Directory of Sigma YAML rules (default: bundled)")
    parser.add_argument("--rules", default="*", help='Selector (default "*")')
    parser.add_argument("--format", choices=["pretty", "json"], default="pretty")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    all_rules = load_rules_from_dir(args.rules_dir)
    selected = filter_rules(all_rules, args.rules)
    evaluator = Evaluator(selected)

    events = [json.loads(line) for line in Path(args.logfile).read_text().splitlines() if line.strip()]
    matches = evaluator.match_many(events)

    use_color = not args.no_color and sys.stdout.isatty()

    if args.format == "json":
        out = [
            {
                "rule_id": m.rule.id,
                "rule_title": m.rule.title,
                "level": m.rule.level,
                "attack": m.rule.attack,
                "matched_selections": m.matched_selections,
                "event": m.event,
            }
            for m in matches
        ]
        print(json.dumps(out, indent=2))
        return 0

    # pretty format
    print(f"{DIM}Loaded {len(selected)} rule(s). Scanned {len(events)} event(s).{RESET}")
    print()
    for m in matches:
        level_tag = _colorize(m.rule.level, f"[{m.rule.level.upper()}]", use_color)
        attack = ",".join(m.rule.attack) or "—"
        print(f"{level_tag} {m.rule.title}")
        print(f"  {DIM}rule:{RESET} {m.rule.id}    {DIM}ATT&CK:{RESET} {attack}")
        print(f"  {DIM}time:{RESET} {m.event.get('_time', '?')}    "
              f"{DIM}user:{RESET} {m.event.get('User') or m.event.get('TargetUserName') or '—'}")
        cmd = m.event.get("CommandLine") or m.event.get("IpAddress") or ""
        if cmd:
            print(f"  {DIM}evidence:{RESET} {_truncate(str(cmd))}")
        print()

    summary = f"{len(matches)} alert(s) across {len(set(m.rule.id for m in matches))} rule(s)."
    print(_colorize("high" if matches else "low", summary, use_color))
    return 0 if matches or not events else 1


if __name__ == "__main__":
    sys.exit(main())
