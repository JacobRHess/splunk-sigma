"""Sigma rule loader and in-memory representation.

Supports the v1 subset documented in DESIGN.md:
- detection.selection (single or multiple)
- conditions: plain selection, 'and', 'or', 'not', parentheses,
  '1 of selection_*', 'all of selection_*'
- field modifiers: contains, startswith, endswith, re
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

ATTACK_TAG_PREFIX = "attack."


@dataclass
class FieldMatcher:
    """A single field check: event[field] OP pattern."""
    field_name: str
    operator: str          # "equals" | "contains" | "startswith" | "endswith" | "re"
    patterns: list[Any]    # list semantics = OR unless 'all' modifier (not in v1)

    def __repr__(self) -> str:
        return f"{self.field_name}|{self.operator}={self.patterns!r}"


@dataclass
class Selection:
    """A named group of field matchers. All matchers must match (AND) for a selection hit."""
    name: str
    matchers: list[FieldMatcher]


@dataclass
class Rule:
    id: str
    title: str
    description: str
    level: str                          # "low" | "medium" | "high" | "critical"
    attack: list[str]                   # e.g. ["T1059.001"]
    logsource: dict[str, str]           # category/product/service
    selections: dict[str, Selection]    # name → Selection
    condition: str                      # raw condition string; parsed at evaluation time
    source_path: str = ""               # for diagnostics
    tags: list[str] = field(default_factory=list)

    def attack_techniques(self) -> list[str]:
        """Return ATT&CK technique IDs from tags like 'attack.t1059.001'."""
        out = []
        for t in self.tags:
            if t.startswith(ATTACK_TAG_PREFIX):
                rest = t[len(ATTACK_TAG_PREFIX):]
                if rest.lower().startswith("t") and any(c.isdigit() for c in rest):
                    out.append(rest.upper().replace(".", "."))
        return out


def _parse_field_key(key: str) -> tuple[str, str]:
    """'CommandLine|contains' -> ('CommandLine', 'contains'). Bare field -> 'equals'."""
    if "|" not in key:
        return key, "equals"
    parts = key.split("|")
    if len(parts) > 2:
        # Modifier chains (e.g. 'contains|all') not supported in v1; take first modifier.
        return parts[0], parts[1]
    return parts[0], parts[1]


def _parse_selection(name: str, body: Any) -> Selection:
    if not isinstance(body, dict):
        raise ValueError(f"Selection '{name}' must be a mapping, got {type(body).__name__}")
    matchers: list[FieldMatcher] = []
    for raw_key, raw_val in body.items():
        field_name, operator = _parse_field_key(raw_key)
        patterns = raw_val if isinstance(raw_val, list) else [raw_val]
        matchers.append(FieldMatcher(field_name, operator, patterns))
    return Selection(name=name, matchers=matchers)


def load_rule_from_file(path: str | Path) -> Rule:
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: rule file must be a YAML mapping")

    detection = data.get("detection") or {}
    if not isinstance(detection, dict) or "condition" not in detection:
        raise ValueError(f"{path}: rule missing detection.condition")

    selections: dict[str, Selection] = {}
    for k, v in detection.items():
        if k == "condition":
            continue
        selections[k] = _parse_selection(k, v)

    tags = data.get("tags") or []
    attack_ids = [
        t[len(ATTACK_TAG_PREFIX):].upper()
        for t in tags
        if isinstance(t, str)
        and t.startswith(ATTACK_TAG_PREFIX)
        and t[len(ATTACK_TAG_PREFIX):].lower().startswith("t")
    ]

    return Rule(
        id=str(data.get("id") or path.stem),
        title=str(data.get("title") or path.stem),
        description=str(data.get("description") or ""),
        level=str(data.get("level") or "medium"),
        attack=attack_ids,
        logsource=dict(data.get("logsource") or {}),
        selections=selections,
        condition=str(detection["condition"]).strip(),
        source_path=str(path),
        tags=list(tags),
    )


def load_rules_from_dir(root: str | Path) -> list[Rule]:
    root = Path(root)
    rules: list[Rule] = []
    for p in sorted(root.rglob("*.yml")):
        rules.append(load_rule_from_file(p))
    for p in sorted(root.rglob("*.yaml")):
        rules.append(load_rule_from_file(p))
    return rules


def filter_rules(rules: Iterable[Rule], selector: str) -> list[Rule]:
    """Filter rules by a simple selector.

    Selectors:
      '*'                  -> all rules
      'app:*'              -> all bundled rules (matches any)
      'id:<glob>'          -> match rule.id
      'attack:T1059.001'   -> match rules tagged with the ATT&CK technique
      '<glob>'             -> fnmatch against rule.id or rule.title
    """
    selector = (selector or "*").strip()
    if selector in ("*", "app:*", ""):
        return list(rules)
    if selector.startswith("attack:"):
        target = selector.split(":", 1)[1].upper()
        return [r for r in rules if target in [a.upper() for a in r.attack]]
    if selector.startswith("id:"):
        pat = selector.split(":", 1)[1]
        return [r for r in rules if fnmatch.fnmatch(r.id, pat)]
    return [
        r for r in rules
        if fnmatch.fnmatch(r.id, selector) or fnmatch.fnmatch(r.title, selector)
    ]
