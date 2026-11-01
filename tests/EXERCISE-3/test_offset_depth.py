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


def test_t10_depth_only_matches_within_limit():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Depth 4"; content:"GET "; depth:4; sid:1011;)')
    assert rule.status == "valid"

    ev_hit = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"GET /index.html HTTP/1.1").decode("ascii"),
    )
    assert matcher.match(rule, ev_hit).matched is True

    ev_miss = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b" POST GET /index.html").decode("ascii"),
    )
    res_miss = matcher.match(rule, ev_miss)
    assert res_miss.matched is False
    assert res_miss.rejection_reason == "content_mismatch"


def test_t10_offset_only_matches_at_or_after_start():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Offset 10"; content:"SECRET"; offset:10; sid:1012;)')
    assert rule.status == "valid"

    ev_after = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"0123456789---SECRET---").decode("ascii"),
    )
    assert matcher.match(rule, ev_after).matched is True

    ev_before = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"SECRET---0123456789").decode("ascii"),
    )
    res_before = matcher.match(rule, ev_before)
    assert res_before.matched is False
    assert res_before.rejection_reason == "content_mismatch"


def test_t10_offset_and_depth_window_bounded_matching():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Bounded"; content:"FLAG"; offset:5; depth:10; sid:1013;)')
    assert rule.status == "valid"

    ev_inside = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"01234--FLAG--012345").decode("ascii"),
    )
    assert matcher.match(rule, ev_inside).matched is True

    ev_early = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"FLAG-012345678901234").decode("ascii"),
    )
    res_early = matcher.match(rule, ev_early)
    assert res_early.matched is False
    assert res_early.rejection_reason == "content_mismatch"

    ev_late = NormalizedEvent(
        packet_id=3,
        timestamp=100.2,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"01234567890123456789--FLAG").decode("ascii"),
    )
    res_late = matcher.match(rule, ev_late)
    assert res_late.matched is False
    assert res_late.rejection_reason == "content_mismatch"


def test_t10_offset_exceeds_payload_length_handled_safely():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Large Offset"; content:"TEST"; offset:100; sid:1014;)')
    assert rule.status == "valid"

    ev_short = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"SHORT TEST").decode("ascii"),
    )
    res = matcher.match(rule, ev_short)
    assert res.matched is False
    assert res.rejection_reason == "content_mismatch"


def test_t10_end_to_end_pcap_evaluation():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/EXERCISE-3/rules/case10_offset_depth.rules")))

    matcher = RuleMatcher()
    engine = RuleEvaluationEngine(rules=rules, matcher=matcher)
    tracker = FlowTracker()

    pcap_path = "TEST/EXERCISE-3/pcap/case10_offset_depth.pcap"
    packets = list(iter_packets(pcap=pcap_path))
    assert len(packets) == 2

    events = [build_event(i, pkt, flow_tracker=tracker) for i, pkt in enumerate(packets, start=1)]

    alerts_pkt1 = sorted([d.sid for d in engine.evaluate_event(events[0])])
    assert alerts_pkt1 == [1001, 1002, 1003]

    alerts_pkt2 = [d.sid for d in engine.evaluate_event(events[1])]
    assert alerts_pkt2 == [1005]

