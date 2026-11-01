from __future__ import annotations

from pathlib import Path
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.parser import RuleParser


def test_t02_missing_parentheses():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp any any -> any 80 msg:"no parens"; sid:101;')
    assert rule.status == "invalid"
    assert rule.reason is not None
    assert "parentheses" in rule.reason.lower()


def test_t02_header_missing_tokens():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp any -> 80 (msg:"short header"; sid:102;)')
    assert rule.status == "invalid"
    assert rule.reason is not None
    assert "7 fields" in rule.reason


def test_t02_invalid_port():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp any 70000 -> any 80 (msg:"invalid port"; sid:103;)')
    assert rule.status == "invalid"
    assert rule.reason is not None
    assert "port" in rule.reason.lower()


def test_t02_invalid_ip():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp 999.1.1.1 any -> any 80 (msg:"bad ip"; sid:104;)')
    assert rule.status == "invalid"
    assert rule.reason is not None
    assert "ip" in rule.reason.lower()


def test_t02_missing_mandatory_sid():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"no sid";)')
    assert rule.status == "invalid"
    assert rule.reason is not None
    assert "sid" in rule.reason.lower()


def test_t02_invalid_direction():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp any any <- any 80 (msg:"bad dir"; sid:105;)')
    assert rule.status == "invalid"
    assert rule.reason is not None
    assert "direction" in rule.reason.lower()


def test_t02_unclosed_quote_and_missing_semicolon():
    parser = RuleParser()
    rule1 = parser.parse_rule('alert tcp any any -> any 80 (msg:"unclosed; sid:106;)')
    assert rule1.status == "invalid"
    assert "unclosed" in rule1.reason.lower()

    rule2 = parser.parse_rule('alert tcp any any -> any 80 (msg:"no semi"; sid:107; trailing_without_semi)')
    assert rule2.status == "invalid"
    assert "semicolon" in rule2.reason.lower()


def test_t02_batch_parsing_continues_on_invalid_rules():
    loader = RuleLoader()
    raw_rules = loader.load_file(Path("TEST/BT3/rules/case02_syntax_error.rules"))

    parser = RuleParser()
    parsed_rules = parser.parse_rules(raw_rules)

    assert len(parsed_rules) == 9

    invalid_rules = [r for r in parsed_rules if r.status == "invalid"]
    valid_rules = [r for r in parsed_rules if r.status == "valid"]

    assert len(invalid_rules) == 8
    assert len(valid_rules) == 1
    assert valid_rules[0].sid == 108
    assert all(r.reason is not None for r in invalid_rules)


def test_t03_pcre_keyword_unsupported():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"PCRE"; pcre:"/[0-9]/"; sid:201;)')
    assert rule.status == "unsupported"
    assert rule.reason is not None
    assert "pcre" in rule.reason.lower()


def test_t03_byte_test_and_jump_unsupported():
    parser = RuleParser()
    r1 = parser.parse_rule('alert tcp any any -> any 80 (msg:"Byte test"; byte_test:4,>,100,0; sid:202;)')
    assert r1.status == "unsupported"
    assert "byte_test" in r1.reason.lower()

    r2 = parser.parse_rule('alert tcp any any -> any 80 (msg:"Byte jump"; byte_jump:4,0; sid:203;)')
    assert r2.status == "unsupported"
    assert "byte_jump" in r2.reason.lower()


def test_t03_unsupported_protocol_icmp():
    parser = RuleParser()
    rule = parser.parse_rule('alert icmp any any -> any any (msg:"ICMP Ping"; sid:204;)')
    assert rule.status == "unsupported"
    assert rule.reason is not None
    assert "icmp" in rule.reason.lower()


def test_t03_batch_parsing_unsupported_rules():
    loader = RuleLoader()
    raw_rules = loader.load_file(Path("TEST/BT3/rules/case03_unsupported.rules"))

    parser = RuleParser()
    parsed_rules = parser.parse_rules(raw_rules)

    assert len(parsed_rules) == 7

    unsupported_rules = [r for r in parsed_rules if r.status == "unsupported"]
    valid_rules = [r for r in parsed_rules if r.status == "valid"]

    assert len(unsupported_rules) == 6
    assert len(valid_rules) == 1
    assert valid_rules[0].sid == 207
    assert all(r.reason is not None for r in unsupported_rules)

