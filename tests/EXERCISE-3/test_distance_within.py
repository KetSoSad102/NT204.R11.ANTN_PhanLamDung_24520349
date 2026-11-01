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


def test_t11_adjacent_relative_match_with_distance_and_within():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule_ok = parser.parse_rule('alert tcp any any -> any 80 (msg:"R1"; content:"AAA"; content:"BBB"; distance:2; within:5; sid:1111;)')
    rule_far = parser.parse_rule('alert tcp any any -> any 80 (msg:"R2"; content:"AAA"; content:"BBB"; distance:10; within:5; sid:1112;)')
    rule_tight = parser.parse_rule('alert tcp any any -> any 80 (msg:"R3"; content:"AAA"; content:"BBB"; distance:2; within:2; sid:1113;)')

    ev = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"---AAA--BBB---").decode("ascii"),
    )

    assert matcher.match(rule_ok, ev).matched is True

    res_far = matcher.match(rule_far, ev)
    assert res_far.matched is False
    assert res_far.rejection_reason == "content_mismatch"

    res_tight = matcher.match(rule_tight, ev)
    assert res_tight.matched is False
    assert res_tight.rejection_reason == "content_mismatch"


def test_t11_within_only_relative_to_previous_match():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Within"; content:"CMD:"; content:"EXEC"; within:8; sid:1120;)')

    ev_hit = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"PREFIX CMD: EXEC SUFFIX").decode("ascii"),
    )
    assert matcher.match(rule, ev_hit).matched is True

    ev_miss = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"PREFIX CMD: ------------ EXEC").decode("ascii"),
    )
    res_miss = matcher.match(rule, ev_miss)
    assert res_miss.matched is False
    assert res_miss.rejection_reason == "content_mismatch"


def test_t11_distance_only_relative_to_previous_match():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Dist"; content:"START"; content:"END"; distance:5; sid:1130;)')

    ev_hit = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"START-----END").decode("ascii"),
    )
    assert matcher.match(rule, ev_hit).matched is True

    ev_too_close = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"START-END").decode("ascii"),
    )
    res_too_close = matcher.match(rule, ev_too_close)
    assert res_too_close.matched is False
    assert res_too_close.rejection_reason == "content_mismatch"


def test_t11_chained_three_content_relative_matches():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule(
        'alert tcp any any -> any 80 (msg:"Chain"; content:"A"; content:"B"; distance:1; within:3; content:"C"; distance:1; within:3; sid:1140;)'
    )

    ev_ok = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"A-B-C").decode("ascii"),
    )
    assert matcher.match(rule, ev_ok).matched is True

    ev_broken = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"A-B-------C").decode("ascii"),
    )
    res_broken = matcher.match(rule, ev_broken)
    assert res_broken.matched is False
    assert res_broken.rejection_reason == "content_mismatch"


def test_t11_end_to_end_pcap_evaluation():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/EXERCISE-3/rules/case11_distance_within.rules")))

    matcher = RuleMatcher()
    engine = RuleEvaluationEngine(rules=rules, matcher=matcher)
    tracker = FlowTracker()

    pcap_path = "TEST/EXERCISE-3/pcap/case11_distance_within.pcap"
    packets = list(iter_packets(pcap=pcap_path))
    assert len(packets) == 2

    events = [build_event(i, pkt, flow_tracker=tracker) for i, pkt in enumerate(packets, start=1)]

    alerts_pkt1 = sorted([d.sid for d in engine.evaluate_event(events[0])])
    assert alerts_pkt1 == [1101, 1102, 1105]

    alerts_pkt2 = [d.sid for d in engine.evaluate_event(events[1])]
    assert alerts_pkt2 == []

