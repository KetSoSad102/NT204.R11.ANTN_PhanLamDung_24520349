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


def test_t13_single_event_matches_multiple_rules_without_early_exit():
    parser = RuleParser()
    rules = [
        parser.parse_rule('alert tcp any any -> any 80 (msg:"R1"; content:"ATTACK"; priority:1; sid:1311;)'),
        parser.parse_rule('alert tcp any any -> any 80 (msg:"R2"; content:"TEST"; priority:2; sid:1312;)'),
        parser.parse_rule('alert tcp any any -> any 80 (msg:"R3"; priority:3; sid:1313;)'),
        parser.parse_rule('alert tcp any any -> any 80 (msg:"R4"; content:"NOMATCH"; sid:1314;)'),
    ]

    engine = RuleEvaluationEngine(rules=rules)
    ev = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"ATTACK IN TEST PAYLOAD").decode("ascii"),
    )

    alerts = engine.evaluate_event(ev)
    matched_sids = [d.sid for d in alerts]

    assert len(alerts) == 3
    assert matched_sids == [1311, 1312, 1313]
    assert 1314 not in matched_sids
    assert engine.matches_count == 3


def test_t13_matches_count_and_evaluation_metrics():
    parser = RuleParser()
    rules = [
        parser.parse_rule('alert tcp any any -> any 80 (msg:"Rule A"; content:"A"; sid:1321;)'),
        parser.parse_rule('alert tcp any any -> any 80 (msg:"Rule B"; content:"B"; sid:1322;)'),
    ]

    engine = RuleEvaluationEngine(rules=rules)

    ev1 = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"A and B").decode("ascii"),
    )
    ev2 = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        payload_b64=base64.b64encode(b"only A").decode("ascii"),
    )

    alerts1 = engine.evaluate_event(ev1)
    alerts2 = engine.evaluate_event(ev2)

    assert len(alerts1) == 2
    assert len(alerts2) == 1
    assert engine.events_evaluated == 2
    assert engine.candidate_rules_evaluated == 4
    assert engine.matches_count == 3


def test_t13_detection_events_contain_correct_rule_specific_fields():
    parser = RuleParser()
    rules = [
        parser.parse_rule('alert tcp any any -> any 80 (msg:"High Pri"; content:"HIT"; priority:1; sid:1331; rev:2;)'),
        parser.parse_rule('alert tcp any any -> any 80 (msg:"Low Pri"; content:"HIT"; priority:4; sid:1332; rev:5;)'),
    ]

    engine = RuleEvaluationEngine(rules=rules)
    ev = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.5",
        src_port=12345,
        dst_ip="10.0.0.1",
        dst_port=80,
        transport_protocol="TCP",
        payload_b64=base64.b64encode(b"HIT").decode("ascii"),
    )

    alerts = engine.evaluate_event(ev)
    assert len(alerts) == 2

    a1 = next(a for a in alerts if a.sid == 1331)
    assert a1.msg == "High Pri"
    assert a1.priority == 1
    assert a1.rev == 2
    assert a1.matched_info == 'content="HIT"'

    a2 = next(a for a in alerts if a.sid == 1332)
    assert a2.msg == "Low Pri"
    assert a2.priority == 4
    assert a2.rev == 5
    assert a2.matched_info == 'content="HIT"'


def test_t13_end_to_end_pcap_evaluation():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/EXERCISE-3/rules/case13_multi_match.rules")))

    matcher = RuleMatcher()
    engine = RuleEvaluationEngine(rules=rules, matcher=matcher)
    tracker = FlowTracker()

    pcap_path = "TEST/EXERCISE-3/pcap/case13_multi_match.pcap"
    packets = list(iter_packets(pcap=pcap_path))
    assert len(packets) == 2

    events = [build_event(i, pkt, flow_tracker=tracker) for i, pkt in enumerate(packets, start=1)]

    alerts_pkt1 = [d.sid for d in engine.evaluate_event(events[0])]
    assert len(alerts_pkt1) == 4
    assert set(alerts_pkt1) == {1301, 1302, 1303, 1304}

    alerts_pkt2 = [d.sid for d in engine.evaluate_event(events[1])]
    assert len(alerts_pkt2) == 2
    assert set(alerts_pkt2) == {1303, 1304}

