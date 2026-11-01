from __future__ import annotations

import base64
from pathlib import Path
from ids_parser.capture import iter_packets
from ids_parser.flow_tracker import FlowTracker
from ids_parser.models import NormalizedEvent
from ids_rule_engine.evaluator import RuleEvaluationEngine
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.matcher import RuleMatcher
from ids_rule_engine.parser import RuleParser
from main import build_event


def test_t07_header_mismatch_bypasses_content_matching():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp 192.168.1.200 any -> 10.0.0.1 80 (msg:"Attack"; content:"MALICIOUS"; sid:702;)')
    assert rule.status == "valid"

    payload_bytes = b"GET /index HTTP/1.1\r\n\r\nMALICIOUS"
    ev = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=54321,
        dst_port=80,
        payload_b64=base64.b64encode(payload_bytes).decode("ascii"),
    )

    res = matcher.match(rule, ev)
    assert res.matched is False
    assert res.header_matched is False
    assert res.content_evaluated is False
    assert res.rejection_reason == "header_mismatch"
    assert matcher.header_rejections == 1
    assert matcher.content_evaluations == 0


def test_t07_port_protocol_direction_mismatches_bypass_content():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule_port = parser.parse_rule('alert tcp any any -> 10.0.0.1 8080 (msg:"Port"; content:"MALICIOUS"; sid:703;)')
    rule_proto = parser.parse_rule('alert udp any any -> 10.0.0.1 80 (msg:"Proto"; content:"MALICIOUS"; sid:704;)')
    rule_dir = parser.parse_rule('alert tcp 10.0.0.1 80 -> 192.168.1.100 any (msg:"Dir"; content:"MALICIOUS"; sid:705;)')

    payload_bytes = b"MALICIOUS"
    ev = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=54321,
        dst_port=80,
        payload_b64=base64.b64encode(payload_bytes).decode("ascii"),
    )

    for rule in [rule_port, rule_proto, rule_dir]:
        res = matcher.match(rule, ev)
        assert res.matched is False
        assert res.header_matched is False
        assert res.content_evaluated is False
        assert res.rejection_reason == "header_mismatch"

    assert matcher.content_evaluations == 0


def test_t07_header_match_proceeds_to_content():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp 192.168.1.100 any -> 10.0.0.1 80 (msg:"Hit"; content:"MALICIOUS"; sid:701;)')

    payload_hit = b"MALICIOUS"
    ev_hit = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=54321,
        dst_port=80,
        payload_b64=base64.b64encode(payload_hit).decode("ascii"),
    )

    res_hit = matcher.match(rule, ev_hit)
    assert res_hit.matched is True
    assert res_hit.header_matched is True
    assert res_hit.content_evaluated is True
    assert res_hit.rejection_reason is None

    payload_miss = b"BENIGN_TRAFFIC"
    ev_miss = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=54321,
        dst_port=80,
        payload_b64=base64.b64encode(payload_miss).decode("ascii"),
    )

    res_miss = matcher.match(rule, ev_miss)
    assert res_miss.matched is False
    assert res_miss.header_matched is True
    assert res_miss.content_evaluated is True
    assert res_miss.rejection_reason == "content_mismatch"


def test_t07_end_to_end_pcap_evaluation():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/BT3/rules/case07_header_filter.rules")))

    matcher = RuleMatcher()
    engine = RuleEvaluationEngine(rules=rules, matcher=matcher)
    tracker = FlowTracker()

    pcap_path = "TEST/BT3/pcap/case07_header_filter.pcap"
    packets = list(iter_packets(pcap=pcap_path))
    assert len(packets) == 1

    event = build_event(1, packets[0], flow_tracker=tracker)
    alerts = engine.evaluate_event(event)

    assert len(alerts) == 1
    assert alerts[0].sid == 701
    assert alerts[0].matched_info == 'content="MALICIOUS_PAYLOAD"'

    details = engine.evaluate_event_detailed(event)
    candidate_sids = [res.sid for res in details]
    assert candidate_sids == [701, 702]

    status_by_sid = {res.sid: res for res in details}
    assert status_by_sid[701].matched is True
    assert status_by_sid[701].content_evaluated is True

    assert status_by_sid[702].matched is False
    assert status_by_sid[702].header_matched is False
    assert status_by_sid[702].content_evaluated is False
    assert status_by_sid[702].rejection_reason == "header_mismatch"

    for r in rules:
        if r.sid != 701:
            direct_res = matcher.match(r, event)
            assert direct_res.matched is False
            assert direct_res.header_matched is False
            assert direct_res.content_evaluated is False
            assert direct_res.rejection_reason == "header_mismatch"
