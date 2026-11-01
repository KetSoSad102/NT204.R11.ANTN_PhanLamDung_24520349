from __future__ import annotations

from pathlib import Path
from ids_parser.capture import iter_packets
from ids_parser.flow_tracker import Flow, FlowTracker
from ids_parser.models import NormalizedEvent
from ids_rule_engine.evaluator import RuleEvaluationEngine
from ids_rule_engine.generator import DetectionEventGenerator
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.matcher import MatchResult, RuleMatcher
from ids_rule_engine.models import DetectionEvent, SnortRule
from ids_rule_engine.parser import RuleParser
from main import build_event


def test_t14_detection_event_structure_and_types():
    det = DetectionEvent(
        timestamp=1700000000.0,
        sid=100001,
        rev=1,
        msg="Directory traversal detected",
        priority=1,
        classtype="web-application-attack",
        src_ip="10.0.0.5",
        src_port=52133,
        dst_ip="192.168.1.20",
        dst_port=80,
        protocol="TCP",
        application_protocol="HTTP",
        flow_id="F123",
        matched_info='content="../"',
    )

    d = det.to_dict()
    assert isinstance(d["timestamp"], float)
    assert isinstance(d["sid"], int)
    assert isinstance(d["rev"], int)
    assert isinstance(d["msg"], str)
    assert isinstance(d["priority"], int)
    assert isinstance(d["classtype"], str)
    assert isinstance(d["src_ip"], str)
    assert isinstance(d["src_port"], int)
    assert isinstance(d["dst_ip"], str)
    assert isinstance(d["dst_port"], int)
    assert isinstance(d["protocol"], str)
    assert isinstance(d["application_protocol"], str)
    assert isinstance(d["flow_id"], str)
    assert isinstance(d["matched_info"], str)


def test_t14_detection_event_generator_creates_complete_event():
    generator = DetectionEventGenerator()
    parser = RuleParser()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Attack"; priority:1; classtype:trojan; sid:999; rev:3;)')
    match_res = MatchResult(
        matched=True,
        sid=999,
        rev=3,
        msg="Attack",
        matched_info='content="MALWARE"',
    )

    ev = NormalizedEvent(
        packet_id=1,
        timestamp=123456.78,
        src_ip="1.1.1.1",
        src_port=1000,
        dst_ip="2.2.2.2",
        dst_port=80,
        transport_protocol="TCP",
        flow_id=None,
        application_protocol="UNKNOWN",
    )

    flow = Flow(
        flow_id="TCP_1.1.1.1:1000_2.2.2.2:80",
        protocol="TCP",
        application_protocol="HTTP",
    )

    det = generator.generate(rule, match_res, ev, flow=flow)
    assert det.sid == 999
    assert det.rev == 3
    assert det.msg == "Attack"
    assert det.priority == 1
    assert det.classtype == "trojan"
    assert det.flow_id == "TCP_1.1.1.1:1000_2.2.2.2:80"
    assert det.application_protocol == "HTTP"
    assert det.matched_info == 'content="MALWARE"'


def test_t14_end_to_end_pcap_detection_event_fields_validation():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/BT3/rules/case14_detection_event.rules")))

    matcher = RuleMatcher()
    tracker = FlowTracker()
    engine = RuleEvaluationEngine(rules=rules, matcher=matcher, flow_tracker=tracker)

    pcap_path = "TEST/BT3/pcap/case14_detection_event.pcap"
    packets = list(iter_packets(pcap=pcap_path))
    assert len(packets) == 2

    events = [build_event(i, pkt, flow_tracker=tracker) for i, pkt in enumerate(packets, start=1)]

    det1 = engine.evaluate_event(events[0])
    assert len(det1) == 1
    d1 = det1[0]
    assert d1.sid == 140001
    assert d1.rev == 1
    assert d1.msg == "Directory traversal detected"
    assert d1.priority == 1
    assert d1.classtype == "web-application-attack"
    assert d1.src_ip == "10.0.0.5"
    assert d1.src_port == 52133
    assert d1.dst_ip == "192.168.1.20"
    assert d1.dst_port == 80
    assert d1.protocol == "TCP"
    assert d1.application_protocol == "HTTP"
    assert d1.flow_id == "TCP_10.0.0.5:52133_192.168.1.20:80"
    assert d1.matched_info == 'content="../"'

    det2 = engine.evaluate_event(events[1])
    assert len(det2) == 1
    d2 = det2[0]
    assert d2.sid == 140002
    assert d2.rev == 1
    assert d2.msg == "Malicious DNS Query evil.com"
    assert d2.priority == 2
    assert d2.classtype == "bad-unknown"
    assert d2.src_ip == "10.0.0.5"
    assert d2.src_port == 45678
    assert d2.dst_ip == "8.8.8.8"
    assert d2.dst_port == 53
    assert d2.protocol == "UDP"
    assert d2.application_protocol == "DNS"
    assert d2.flow_id == "UDP_10.0.0.5:45678_8.8.8.8:53"
    assert d2.matched_info == 'content="|04|evil|03|com"'

