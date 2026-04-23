"""Sigma rule evaluator.

Given a Rule and an event (dict), determine whether the rule matches.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any

from .operators import get_operator
from .rules import FieldMatcher, Rule, Selection


@dataclass
class Match:
    rule: Rule
    event: dict[str, Any]
    matched_selections: list[str]


def _event_field(event: dict[str, Any], name: str) -> Any:
    """Look up a field; allow case-insensitive exact match if no literal hit."""
    if name in event:
        return event[name]
    lower_name = name.lower()
    for k, v in event.items():
        if k.lower() == lower_name:
            return v
    return None


def _matcher_hit(matcher: FieldMatcher, event: dict[str, Any]) -> bool:
    """True iff any pattern matches (OR semantics within a field's value list)."""
    op = get_operator(matcher.operator)
    value = _event_field(event, matcher.field_name)
    if value is None:
        return False
    # If the event value itself is a list, match against any of its items.
    event_values = value if isinstance(value, list) else [value]
    for ev in event_values:
        for pat in matcher.patterns:
            if op(ev, pat):
                return True
    return False


def _selection_hit(selection: Selection, event: dict[str, Any]) -> bool:
    """All matchers in a selection must hit (AND)."""
    return all(_matcher_hit(m, event) for m in selection.matchers)


# --- condition language --------------------------------------------------------
# Supports: <name>, 'and', 'or', 'not', parentheses, '1 of <pat>', 'all of <pat>'

_TOKEN_RE = re.compile(
    r"\(|\)|\band\b|\bor\b|\bnot\b|\b\d+\s+of\b|\ball\s+of\b|[A-Za-z_][A-Za-z0-9_*]*",
    re.IGNORECASE,
)


def _tokenize(expr: str) -> list[str]:
    return [m.group(0).lower() if m.group(0).lower() in {"and", "or", "not"} else m.group(0)
            for m in _TOKEN_RE.finditer(expr)]


def _evaluate_condition(expr: str, selection_results: dict[str, bool]) -> bool:
    tokens = _tokenize(expr)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def consume() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def match_glob(pat: str) -> list[bool]:
        return [v for name, v in selection_results.items() if fnmatch.fnmatch(name, pat)]

    def parse_primary() -> bool:
        tok = peek()
        if tok is None:
            raise ValueError(f"Unexpected end of condition: {expr!r}")
        if tok == "(":
            consume()
            val = parse_or()
            if peek() != ")":
                raise ValueError(f"Missing ')' in condition: {expr!r}")
            consume()
            return val
        if tok.lower() == "not":
            consume()
            return not parse_primary()
        # '1 of X_*' / 'all of X_*'
        lower = tok.lower()
        if lower.endswith(" of") or lower == "all of":
            consume()
            pat_tok = peek()
            if pat_tok is None:
                raise ValueError(f"Quantifier missing pattern in: {expr!r}")
            consume()
            hits = match_glob(pat_tok)
            if lower == "all of":
                return bool(hits) and all(hits)
            # "N of"
            n = int(lower.split()[0])
            return sum(1 for h in hits if h) >= n
        # plain selection name
        consume()
        return selection_results.get(tok, False)

    def parse_and() -> bool:
        left = parse_primary()
        while peek() and peek().lower() == "and":
            consume()
            right = parse_primary()
            left = left and right
        return left

    def parse_or() -> bool:
        left = parse_and()
        while peek() and peek().lower() == "or":
            consume()
            right = parse_and()
            left = left or right
        return left

    result = parse_or()
    if pos != len(tokens):
        raise ValueError(f"Trailing tokens in condition: {expr!r}")
    return result


# --- public API ----------------------------------------------------------------

class Evaluator:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def match(self, event: dict[str, Any]) -> list[Match]:
        hits: list[Match] = []
        for rule in self.rules:
            sel_results = {
                name: _selection_hit(sel, event)
                for name, sel in rule.selections.items()
            }
            try:
                if _evaluate_condition(rule.condition, sel_results):
                    matched = [name for name, v in sel_results.items() if v]
                    hits.append(Match(rule=rule, event=event, matched_selections=matched))
            except ValueError:
                # Malformed condition — skip this rule for this event.
                continue
        return hits

    def match_many(self, events: list[dict[str, Any]]) -> list[Match]:
        out: list[Match] = []
        for e in events:
            out.extend(self.match(e))
        return out
