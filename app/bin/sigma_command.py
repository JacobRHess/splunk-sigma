#!/usr/bin/env python
"""Custom Splunk search command: | sigma

Usage inside Splunk:
    index=sysmon EventCode=1 | sigma
    index=sysmon EventCode=1 | sigma rules="attack:T1059.001"
    index=wineventlog | sigma rules="id:t1053*" rules_dir="/opt/custom/rules"

Each input event is evaluated against every loaded Sigma rule. Events that match
at least one rule are emitted with these additional fields:
    sigma_rule_id, sigma_rule_title, sigma_level, sigma_attack, sigma_matched_selections

Non-matching events are dropped (filter semantics).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure our bundled engine is importable when Splunk invokes this script.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from sigma_engine import Evaluator, load_rules_from_dir  # noqa: E402
from sigma_engine.rules import filter_rules  # noqa: E402
from splunklib.searchcommands import (  # noqa: E402
    Configuration,
    Option,
    StreamingCommand,
    dispatch,
    validators,
)

DEFAULT_RULES_DIR = str(_HERE / "rules")


@Configuration()
class SigmaCommand(StreamingCommand):
    """Evaluate bundled Sigma rules against piped events."""

    rules = Option(
        doc="Rule selector. Examples: '*' (all), 'attack:T1059.001', 'id:t1053*'. Default '*'.",
        default="*",
        validate=validators.Fieldname() if False else None,  # accept any string
    )

    rules_dir = Option(
        doc="Directory of Sigma YAML rules. Defaults to the app's bundled rules/.",
        default=None,
    )

    def _build_evaluator(self) -> Evaluator:
        rules_dir = self.rules_dir or os.environ.get("SIGMA_RULES_DIR") or DEFAULT_RULES_DIR
        all_rules = load_rules_from_dir(rules_dir)
        selected = filter_rules(all_rules, self.rules or "*")
        return Evaluator(selected)

    def stream(self, records):
        evaluator = self._build_evaluator()
        for record in records:
            matches = evaluator.match(record)
            if not matches:
                continue
            # If multiple rules match the same event, emit one enriched record per rule.
            for m in matches:
                out = dict(record)
                out["sigma_rule_id"] = m.rule.id
                out["sigma_rule_title"] = m.rule.title
                out["sigma_level"] = m.rule.level
                out["sigma_attack"] = ",".join(m.rule.attack)
                out["sigma_matched_selections"] = ",".join(m.matched_selections)
                yield out


if __name__ == "__main__":
    dispatch(SigmaCommand, sys.argv, sys.stdin, sys.stdout, __name__)
