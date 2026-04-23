"""Integration test: run the real bundled rules against the real sample logs.

Asserts every rule fires at least once against the attack samples, and that
benign events do not produce false positives.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from sigma_engine import Evaluator, load_rules_from_dir

REPO = Path(__file__).resolve().parents[1]
RULES_DIR = REPO / "app" / "bin" / "rules"
SAMPLES = REPO / "samples" / "attack_samples.jsonl"


@pytest.fixture(scope="module")
def rules():
    loaded = load_rules_from_dir(RULES_DIR)
    assert len(loaded) == 7, f"expected 7 bundled rules, found {len(loaded)}"
    return loaded


@pytest.fixture(scope="module")
def events():
    return [json.loads(line) for line in SAMPLES.read_text().splitlines() if line.strip()]


def test_every_rule_fires_at_least_once(rules, events):
    ev = Evaluator(rules)
    matches_by_rule: dict[str, int] = {r.id: 0 for r in rules}
    for e in events:
        for m in ev.match(e):
            matches_by_rule[m.rule.id] += 1

    missed = [rid for rid, n in matches_by_rule.items() if n == 0]
    assert not missed, f"rules with no matches: {missed}"


def test_benign_events_do_not_match(rules, events):
    """The two benign events at the end of the sample file should not trigger any rule."""
    ev = Evaluator(rules)
    benign = [e for e in events
              if e.get("Image", "").endswith("notepad.exe")
              or (e.get("EventID") == 4624 and e.get("IpAddress", "").startswith("10."))]
    assert len(benign) == 2
    for e in benign:
        assert ev.match(e) == [], f"benign event produced false positive: {e}"


def test_attack_techniques_cover_expected(rules):
    technique_ids = sorted({t for r in rules for t in r.attack})
    expected = {"T1003.001", "T1021.001", "T1053.005", "T1059.001",
                "T1070.004", "T1105", "T1547.001"}
    assert set(technique_ids) == expected
