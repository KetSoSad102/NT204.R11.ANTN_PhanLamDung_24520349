from __future__ import annotations

from pathlib import Path
from ids_parser.capture import iter_packets
from ids_parser.flow_tracker import FlowTracker
from ids_parser.models import NormalizedEvent
from ids_rule_engine.evaluator import RuleEvaluationEngine
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.matcher import RuleMatcher
from ids_rule_engine.parser import RuleParser
from main import build_event


def test_t05_unidirectional_match_and_mismatch():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp 192.168.1.100 any -> 10.0.0.1 80 (msg:"Uni"; sid:501;)')
    assert rule.status == "valid"

    ev_forward = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=54321,
        dst_port=80,
    )
    res_forward = matcher.match(rule, ev_forward)
    assert res_forward.matched is True
    assert res_forward.sid == 501

    ev_backward = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=80,
        dst_port=54321,
    )
    res_backward = matcher.match(rule, ev_backward)
    assert res_backward.matched is False


def test_t05_bidirectional_matches_both_directions():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp 192.168.1.100 any <> 10.0.0.1 80 (msg:"Bi"; sid:502;)')
    assert rule.status == "valid"

    ev_forward = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=54321,
        dst_port=80,
    )
    res_forward = matcher.match(rule, ev_forward)
    assert res_forward.matched is True
    assert res_forward.sid == 502

    ev_backward = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=80,
        dst_port=54321,
    )
    res_backward = matcher.match(rule, ev_backward)
    assert res_backward.matched is True
    assert res_backward.sid == 502


def test_t05_end_to_end_pcap_direction_matching():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/EXERCISE-3/rules/case05_direction.rules")))

    evaluator = RuleEvaluationEngine(rules=rules)
    tracker = FlowTracker()

    detection_events = []
    for i, captured in enumerate(iter_packets(pcap="TEST/EXERCISE-3/pcap/case05_direction.pcap"), 1):
        event = build_event(i, captured, flow_tracker=tracker)
        flow = tracker.get_flow(event.flow_id) if event.flow_id else None
        alerts = evaluator.evaluate_event(event, flow=flow)
        detection_events.extend(alerts)

    assert evaluator.events_evaluated == 2
    assert len(detection_events) == 3

    pkt1_sids = [d.sid for d in detection_events if d.timestamp == 1700000000.0]
    pkt2_sids = [d.sid for d in detection_events if d.timestamp == 1700000000.1]

    assert sorted(pkt1_sids) == [501, 502]
    assert pkt2_sids == [502]

