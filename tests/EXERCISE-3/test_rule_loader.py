from __future__ import annotations

from pathlib import Path
from ids_rule_engine.loader import RuleLoader


def test_t01_load_from_string_ignores_comments_and_blank_lines():
    raw_content = """
    # This is a comment
    
    alert tcp any any -> any 80 (msg:"HTTP Request"; sid:1001; rev:1;)
       # Indented comment
    
    alert udp any any -> any 53 (msg:"DNS Request"; sid:1002; rev:1;)
    
    # Another comment
    """
    loader = RuleLoader()
    rules = loader.load_from_string(raw_content)

    assert len(rules) == 2
    assert rules[0][1] == 'alert tcp any any -> any 80 (msg:"HTTP Request"; sid:1001; rev:1;)'
    assert rules[1][1] == 'alert udp any any -> any 53 (msg:"DNS Request"; sid:1002; rev:1;)'


def test_t01_load_file_from_disk():
    path = Path("TEST/BT3/rules/case01_loader.rules")
    loader = RuleLoader()
    rules = loader.load_rule_strings(path)

    assert len(rules) == 3
    assert all(not r.startswith("#") for r in rules)
    assert all(len(r.strip()) > 0 for r in rules)
    assert "sid:1000001" in rules[0]
    assert "sid:1000002" in rules[1]
    assert "sid:1000003" in rules[2]


def test_t01_disabled_file_config():
    path = Path("TEST/BT3/rules/case01_loader.rules")
    loader = RuleLoader(disabled_files={"case01_loader.rules"})
    rules = loader.load_rule_strings(path)

    assert len(rules) == 0


def test_t01_nonexistent_file_handling():
    loader = RuleLoader()
    rules = loader.load_rule_strings("non_existent_file.rules")

    assert len(rules) == 0
    assert len(loader.warnings) == 1
    assert "File not found" in loader.warnings[0]

