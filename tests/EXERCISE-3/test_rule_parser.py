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
    raw_rules = loader.load_file(Path("TEST/EXERCISE-3/rules/case02_syntax_error.rules"))

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
    raw_rules = loader.load_file(Path("TEST/EXERCISE-3/rules/case03_unsupported.rules"))

    parser = RuleParser()
    parsed_rules = parser.parse_rules(raw_rules)

    assert len(parsed_rules) == 7

    unsupported_rules = [r for r in parsed_rules if r.status == "unsupported"]
    valid_rules = [r for r in parsed_rules if r.status == "valid"]

    assert len(unsupported_rules) == 6
    assert len(valid_rules) == 1
    assert valid_rules[0].sid == 207
    assert all(r.reason is not None for r in unsupported_rules)


def test_t04_header_tcp_any_to_any():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"HTTP any"; sid:401;)')
    assert rule.status == "valid"
    assert rule.header is not None
    assert rule.header.protocol == "TCP"
    assert rule.header.src_ip == "any"
    assert rule.header.src_port_range == (0, 65535)
    assert rule.header.dst_port_range == (80, 80)
    assert rule.header.matches("TCP", "10.0.0.1", 12345, "192.168.1.1", 80) is True
    assert rule.header.matches("TCP", "10.0.0.1", 12345, "192.168.1.1", 8080) is False
    assert rule.header.matches("UDP", "10.0.0.1", 12345, "192.168.1.1", 80) is False


def test_t04_header_single_ip_and_port():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp 192.168.1.100 50000 -> 10.0.0.1 80 (msg:"Exact match"; sid:402;)')
    assert rule.status == "valid"
    assert rule.header is not None
    assert rule.header.matches("TCP", "192.168.1.100", 50000, "10.0.0.1", 80) is True
    assert rule.header.matches("TCP", "192.168.1.101", 50000, "10.0.0.1", 80) is False
    assert rule.header.matches("TCP", "192.168.1.100", 50001, "10.0.0.1", 80) is False


def test_t04_header_cidr_and_ranges():
    parser = RuleParser()
    rule = parser.parse_rule('alert tcp 192.168.1.0/24 1024:65535 -> 10.0.0.0/16 80 (msg:"CIDR and range"; sid:403;)')
    assert rule.status == "valid"
    assert rule.header is not None
    assert rule.header.src_port_range == (1024, 65535)
    assert rule.header.matches("TCP", "192.168.1.55", 50000, "10.0.5.1", 80) is True
    assert rule.header.matches("TCP", "192.168.2.55", 50000, "10.0.5.1", 80) is False
    assert rule.header.matches("TCP", "192.168.1.55", 80, "10.0.5.1", 80) is False
    assert rule.header.matches("TCP", "192.168.1.55", 50000, "11.0.5.1", 80) is False


def test_t04_header_open_port_ranges():
    parser = RuleParser()
    r1 = parser.parse_rule('alert udp 10.0.0.5 :1024 -> 8.8.8.8 53 (msg:"UDP lower"; sid:404;)')
    assert r1.status == "valid"
    assert r1.header is not None
    assert r1.header.src_port_range == (0, 1024)
    assert r1.header.matches("UDP", "10.0.0.5", 53, "8.8.8.8", 53) is True
    assert r1.header.matches("UDP", "10.0.0.5", 1024, "8.8.8.8", 53) is True
    assert r1.header.matches("UDP", "10.0.0.5", 1025, "8.8.8.8", 53) is False

    r2 = parser.parse_rule('alert tcp 172.16.0.0/12 1024: -> any 443 (msg:"TCP upper"; sid:405;)')
    assert r2.status == "valid"
    assert r2.header is not None
    assert r2.header.src_port_range == (1024, 65535)
    assert r2.header.matches("TCP", "172.20.1.1", 1024, "1.1.1.1", 443) is True
    assert r2.header.matches("TCP", "172.20.1.1", 80, "1.1.1.1", 443) is False


def test_t04_batch_case04_rules_parsed_correctly():
    loader = RuleLoader()
    raw_rules = loader.load_file(Path("TEST/EXERCISE-3/rules/case04_headers.rules"))

    parser = RuleParser()
    parsed_rules = parser.parse_rules(raw_rules)

    assert len(parsed_rules) == 6
    assert all(r.status == "valid" for r in parsed_rules)
    assert all(r.header is not None for r in parsed_rules)
    sids = [r.sid for r in parsed_rules]
    assert sids == [401, 402, 403, 404, 405, 406]


