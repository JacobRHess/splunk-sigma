"""Value-matching operators for Sigma field modifiers.

Each operator takes a field value from an event and a pattern from the rule,
and returns True iff the value matches.
"""
from __future__ import annotations

import re
from typing import Any, Callable


def _as_str(v: Any) -> str:
    return "" if v is None else str(v)


def op_equals(value: Any, pattern: Any) -> bool:
    # Sigma default matching is case-insensitive for strings.
    if isinstance(value, str) and isinstance(pattern, str):
        return value.lower() == pattern.lower()
    return value == pattern


def op_contains(value: Any, pattern: Any) -> bool:
    return _as_str(pattern).lower() in _as_str(value).lower()


def op_startswith(value: Any, pattern: Any) -> bool:
    return _as_str(value).lower().startswith(_as_str(pattern).lower())


def op_endswith(value: Any, pattern: Any) -> bool:
    return _as_str(value).lower().endswith(_as_str(pattern).lower())


def op_re(value: Any, pattern: Any) -> bool:
    try:
        return re.search(_as_str(pattern), _as_str(value)) is not None
    except re.error:
        return False


OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "equals": op_equals,
    "contains": op_contains,
    "startswith": op_startswith,
    "endswith": op_endswith,
    "re": op_re,
}


def get_operator(name: str) -> Callable[[Any, Any], bool]:
    if name not in OPERATORS:
        raise ValueError(f"Unsupported Sigma modifier: {name}")
    return OPERATORS[name]
