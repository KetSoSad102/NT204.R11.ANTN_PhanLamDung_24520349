from __future__ import annotations

import base64
from pathlib import Path
from ids_parser.capture import iter_packets
from ids_parser.flow_tracker import FlowTracker
from ids_parser.models import NormalizedEvent
from ids_rule_engine.evaluator import RuleEvaluationEngine
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.matcher import RuleMatcher, match_packet_dsize, match_tcp_flags
from ids_rule_engine.parser import RuleParser
from main import build_event


def test_t12_tcp_flags_matching_operators():
    assert match_tcp_flags("S", "S") is True
    assert match_tcp_flags("S", "SA") is False
    assert match_tcp_flags("SA", "SA") is True
    assert match_tcp_flags("PA", "PA") is True

    assert match_tcp_flags("S+", "SA") is True
    assert match_tcp_flags("+S", "SPA") is True
    assert match_tcp_flags("S+", "A") is False

    assert match_tcp_flags("*SF", "S") is True
    assert match_tcp_flags("*SF", "F") is True
    assert match_tcp_flags("*SF", "A") is False

    assert match_tcp_flags("!A", "S") is True
    assert match_tcp_flags("!A", "SA") is False

    assert match_tcp_flags("0", "") is True
    assert match_tcp_flags("0", "S") is False


def test_t12_dsize_comparators():
    assert match_packet_dsize("0", 0) is True
    assert match_packet_dsize("0", 10) is False
    assert match_packet_dsize("50", 50) is True

    assert match_packet_dsize(">50", 60) is True
    assert match_packet_dsize(">50", 50) is False

    assert match_packet_dsize("<50", 40) is True
    assert match_packet_dsize("<50", 50) is False

    assert match_packet_dsize(">=50", 50) is True
    assert match_packet_dsize("<=50", 50) is True

    assert match_packet_dsize("20<>60", 30) is True
    assert match_packet_dsize("20<>60", 20) is True
    assert match_packet_dsize("20<>60", 60) is True
    assert match_packet_dsize("20<>60", 10) is False
    assert match_packet_dsize("20<>60", 70) is False

    assert match_packet_dsize("!20<>60", 10) is True
    assert match_packet_dsize("!20<>60", 30) is False


def test_t12_flags_and_dsize_combined_evaluation():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Syn Empty"; flags:S; dsize:0; content:"DATA"; sid:1210;)')

    ev_match_flags_and_dsize = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        dst_port=80,
        tcp_flags="S",
        payload_b64=None,
    )
    res1 = matcher.match(rule, ev_match_flags_and_dsize)
    assert res1.matched is False
    assert res1.flags_matched is True
    assert res1.dsize_matched is True
    assert res1.rejection_reason == "content_mismatch"

    ev_flags_mismatch = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        dst_port=80,
        tcp_flags="A",
        payload_b64=None,
    )
    res2 = matcher.match(rule, ev_flags_mismatch)
    assert res2.matched is False
    assert res2.flags_matched is False
    assert res2.rejection_reason == "flags_mismatch"
    assert res2.content_evaluated is False

    ev_dsize_mismatch = NormalizedEvent(
        packet_id=3,
        timestamp=100.2,
        transport_protocol="TCP",
        dst_port=80,
        tcp_flags="S",
        payload_b64=base64.b64encode(b"SOME PAYLOAD").decode("ascii"),
    )
    res3 = matcher.match(rule, ev_dsize_mismatch)
    assert res3.matched is False
    assert res3.flags_matched is True
    assert res3.dsize_matched is False
    assert res3.rejection_reason == "dsize_mismatch"
    assert res3.content_evaluated is False


def test_t12_parser_empty_flags_or_dsize_invalid():
    parser = RuleParser()

    r_empty_flags = parser.parse_rule('alert tcp any any -> any 80 (msg:"Bad"; flags:; sid:1220;)')
    assert r_empty_flags.status == "invalid"
    assert "Empty flags" in (r_empty_flags.reason or "")

    r_empty_dsize = parser.parse_rule('alert tcp any any -> any 80 (msg:"Bad"; dsize:; sid:1221;)')
    assert r_empty_dsize.status == "invalid"
    assert "Empty dsize" in (r_empty_dsize.reason or "")


def test_t12_end_to_end_pcap_evaluation():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/BT3/rules/case12_flags_dsize.rules")))

    matcher = RuleMatcher()
    engine = RuleEvaluationEngine(rules=rules, matcher=matcher)
    tracker = FlowTracker()

    pcap_path = "TEST/BT3/pcap/case12_flags_dsize.pcap"
    packets = list(iter_packets(pcap=pcap_path))
    assert len(packets) == 3

    events = [build_event(i, pkt, flow_tracker=tracker) for i, pkt in enumerate(packets, start=1)]

    alerts_pkt1 = sorted([d.sid for d in engine.evaluate_event(events[0])])
    assert alerts_pkt1 == [1201, 1204]

    alerts_pkt2 = [d.sid for d in engine.evaluate_event(events[1])]
    assert alerts_pkt2 == [1202]

    alerts_pkt3 = [d.sid for d in engine.evaluate_event(events[2])]
    assert alerts_pkt3 == [1203]

