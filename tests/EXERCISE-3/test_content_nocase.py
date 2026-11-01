from __future__ import annotations

import base64
from pathlib import Path
from ids_parser.capture import iter_packets
from ids_parser.flow_tracker import FlowTracker
from ids_parser.models import NormalizedEvent
from ids_rule_engine.evaluator import RuleEvaluationEngine
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.matcher import RuleMatcher, extract_content_options
from ids_rule_engine.parser import RuleParser
from main import build_event


def test_t09_case_sensitive_content_matches_only_exact_case():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Exact"; content:"MALICIOUS"; sid:911;)')
    assert rule.status == "valid"

    content_items = extract_content_options(rule)
    assert len(content_items) == 1
    assert content_items[0].nocase is False

    ev_exact = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"contains MALICIOUS code").decode("ascii"),
    )
    assert matcher.match(rule, ev_exact).matched is True

    ev_lower = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"contains malicious code").decode("ascii"),
    )
    res_lower = matcher.match(rule, ev_lower)
    assert res_lower.matched is False
    assert res_lower.rejection_reason == "content_mismatch"

    ev_mixed = NormalizedEvent(
        packet_id=3,
        timestamp=100.2,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"contains MalIcioUs code").decode("ascii"),
    )
    res_mixed = matcher.match(rule, ev_mixed)
    assert res_mixed.matched is False
    assert res_mixed.rejection_reason == "content_mismatch"


def test_t09_nocase_content_matches_any_case():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Nocase"; content:"malicious"; nocase; sid:912;)')
    assert rule.status == "valid"

    content_items = extract_content_options(rule)
    assert len(content_items) == 1
    assert content_items[0].nocase is True

    for payload_variant in [b"MALICIOUS", b"malicious", b"MalIcioUs", b"mALICIOUS"]:
        ev = NormalizedEvent(
            packet_id=1,
            timestamp=100.0,
            transport_protocol="TCP",
            dst_port=80,
            payload_b64=base64.b64encode(payload_variant).decode("ascii"),
        )
        res = matcher.match(rule, ev)
        assert res.matched is True
        assert res.content_evaluated is True


def test_t09_mixed_content_modifiers_within_single_rule():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Mixed"; content:"USER="; content:"admin"; nocase; sid:913;)')
    assert rule.status == "valid"

    items = extract_content_options(rule)
    assert len(items) == 2
    assert items[0].nocase is False
    assert items[1].nocase is True

    ev_both_ok = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"data USER=1&name=ADMINISTRATOR").decode("ascii"),
    )
    assert matcher.match(rule, ev_both_ok).matched is True

    ev_first_fail = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"data user=1&name=ADMINISTRATOR").decode("ascii"),
    )
    res_first_fail = matcher.match(rule, ev_first_fail)
    assert res_first_fail.matched is False
    assert res_first_fail.rejection_reason == "content_mismatch"


def test_t09_hex_content_with_nocase():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Hex Nocase"; content:"|61 62 63|"; nocase; sid:914;)')
    assert rule.status == "valid"

    ev = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"prefix ABC suffix").decode("ascii"),
    )
    assert matcher.match(rule, ev).matched is True


def test_t09_end_to_end_pcap_evaluation():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/BT3/rules/case09_content_nocase.rules")))

    matcher = RuleMatcher()
    engine = RuleEvaluationEngine(rules=rules, matcher=matcher)
    tracker = FlowTracker()

    pcap_path = "TEST/BT3/pcap/case09_content_nocase.pcap"
    packets = list(iter_packets(pcap=pcap_path))
    assert len(packets) == 3

    events = [build_event(i, pkt, flow_tracker=tracker) for i, pkt in enumerate(packets, start=1)]

    alerts_pkt1 = [d.sid for d in engine.evaluate_event(events[0])]
    assert alerts_pkt1 == [902]

    alerts_pkt2 = sorted([d.sid for d in engine.evaluate_event(events[1])])
    assert alerts_pkt2 == [901, 902]

    alerts_pkt3 = [d.sid for d in engine.evaluate_event(events[2])]
    assert alerts_pkt3 == [903]

