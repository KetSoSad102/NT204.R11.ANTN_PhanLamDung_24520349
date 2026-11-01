from __future__ import annotations

import base64
from pathlib import Path
from ids_parser.capture import iter_packets
from ids_parser.flow_tracker import Flow, FlowTracker
from ids_parser.models import NormalizedEvent
from ids_rule_engine.evaluator import RuleEvaluationEngine
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.matcher import RuleMatcher
from ids_rule_engine.parser import RuleParser
from main import build_event


def test_t08_flow_parser_supported_and_unsupported_tokens():
    parser = RuleParser()

    valid1 = parser.parse_rule('alert tcp any any -> any 80 (msg:"T1"; flow:to_server, established; sid:810;)')
    assert valid1.status == "valid"

    valid2 = parser.parse_rule('alert tcp any any -> any 80 (msg:"T2"; flow:not_established; sid:811;)')
    assert valid2.status == "valid"

    invalid_empty = parser.parse_rule('alert tcp any any -> any 80 (msg:"T3"; flow:; sid:812;)')
    assert invalid_empty.status == "invalid"
    assert "Empty flow option" in (invalid_empty.reason or "")

    unsupported_tok = parser.parse_rule('alert tcp any any -> any 80 (msg:"T4"; flow:only_stream; sid:813;)')
    assert unsupported_tok.status == "unsupported"
    assert "only_stream" in (unsupported_tok.reason or "")


def test_t08_flow_direction_matching_to_server_and_to_client():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule_to_server = parser.parse_rule('alert tcp any any -> any any (msg:"To Server"; flow:to_server; sid:820;)')
    rule_to_client = parser.parse_rule('alert tcp any any -> any any (msg:"To Client"; flow:to_client; sid:821;)')

    flow = Flow(
        flow_id="TCP_192.168.1.50:49152_10.0.0.1:80",
        protocol="TCP",
        initiator="192.168.1.50:49152",
        state="ESTABLISHED",
    )

    ev_forward = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.50",
        src_port=49152,
        dst_ip="10.0.0.1",
        dst_port=80,
        transport_protocol="TCP",
        flow_id=flow.flow_id,
        flow_direction="forward",
    )

    res_fwd_srv = matcher.match(rule_to_server, ev_forward, flow=flow)
    assert res_fwd_srv.matched is True
    assert res_fwd_srv.flow_matched is True

    res_fwd_cli = matcher.match(rule_to_client, ev_forward, flow=flow)
    assert res_fwd_cli.matched is False
    assert res_fwd_cli.flow_matched is False
    assert res_fwd_cli.rejection_reason == "flow_mismatch"

    ev_backward = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        src_ip="10.0.0.1",
        src_port=80,
        dst_ip="192.168.1.50",
        dst_port=49152,
        transport_protocol="TCP",
        flow_id=flow.flow_id,
        flow_direction="backward",
    )

    res_bk_cli = matcher.match(rule_to_client, ev_backward, flow=flow)
    assert res_bk_cli.matched is True
    assert res_bk_cli.flow_matched is True

    res_bk_srv = matcher.match(rule_to_server, ev_backward, flow=flow)
    assert res_bk_srv.matched is False
    assert res_bk_srv.flow_matched is False
    assert res_bk_srv.rejection_reason == "flow_mismatch"


def test_t08_flow_state_established_vs_not_established():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule_est = parser.parse_rule('alert tcp any any -> any any (msg:"Est"; flow:established; sid:830;)')
    rule_not_est = parser.parse_rule('alert tcp any any -> any any (msg:"Not Est"; flow:not_established; sid:831;)')

    flow_handshake = Flow(
        flow_id="TCP_192.168.1.50:49152_10.0.0.1:80",
        protocol="TCP",
        initiator="192.168.1.50:49152",
        state="NEW/HANDSHAKE",
    )

    ev_syn = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.50",
        src_port=49152,
        dst_ip="10.0.0.1",
        dst_port=80,
        transport_protocol="TCP",
        flow_id=flow_handshake.flow_id,
        flow_state="NEW/HANDSHAKE",
    )

    assert matcher.match(rule_est, ev_syn, flow=flow_handshake).matched is False
    assert matcher.match(rule_not_est, ev_syn, flow=flow_handshake).matched is True

    flow_est = Flow(
        flow_id="TCP_192.168.1.50:49152_10.0.0.1:80",
        protocol="TCP",
        initiator="192.168.1.50:49152",
        state="ESTABLISHED",
    )

    ev_data = NormalizedEvent(
        packet_id=2,
        timestamp=100.2,
        src_ip="192.168.1.50",
        src_port=49152,
        dst_ip="10.0.0.1",
        dst_port=80,
        transport_protocol="TCP",
        flow_id=flow_est.flow_id,
        flow_state="ESTABLISHED",
    )

    assert matcher.match(rule_est, ev_data, flow=flow_est).matched is True
    assert matcher.match(rule_not_est, ev_data, flow=flow_est).matched is False


def test_t08_flow_mismatch_bypasses_content_matching():
    parser = RuleParser()
    matcher = RuleMatcher()

    rule = parser.parse_rule('alert tcp any any -> any 80 (msg:"Attack"; flow:to_server, established; content:"EXPLOIT"; sid:840;)')

    flow = Flow(
        flow_id="TCP_192.168.1.50:49152_10.0.0.1:80",
        protocol="TCP",
        initiator="192.168.1.50:49152",
        state="NEW/HANDSHAKE",
    )

    ev = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        src_ip="192.168.1.50",
        src_port=49152,
        dst_ip="10.0.0.1",
        dst_port=80,
        transport_protocol="TCP",
        flow_id=flow.flow_id,
        flow_direction="forward",
        flow_state="NEW/HANDSHAKE",
        payload_b64=base64.b64encode(b"ATTACK WITH EXPLOIT HERE").decode("ascii"),
    )

    res = matcher.match(rule, ev, flow=flow)
    assert res.matched is False
    assert res.header_matched is True
    assert res.flow_matched is False
    assert res.content_evaluated is False
    assert res.rejection_reason == "flow_mismatch"


def test_t08_end_to_end_pcap_flow_evaluation():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/BT3/rules/case08_flow.rules")))

    matcher = RuleMatcher()
    tracker = FlowTracker()
    engine = RuleEvaluationEngine(rules=rules, matcher=matcher, flow_tracker=tracker)

    pcap_path = "TEST/BT3/pcap/case08_flow.pcap"
    packets = list(iter_packets(pcap=pcap_path))
    assert len(packets) == 5

    alerts_by_packet = {}
    for idx, pkt in enumerate(packets, start=1):
        event = build_event(idx, pkt, flow_tracker=tracker)
        flow = tracker.get_flow(event.flow_id) if event.flow_id else None
        alerts = engine.evaluate_event(event, flow=flow)
        alerts_by_packet[idx] = alerts

    assert len(alerts_by_packet[1]) == 1
    assert alerts_by_packet[1][0].sid == 803

    assert len(alerts_by_packet[2]) == 0
    assert len(alerts_by_packet[3]) == 0

    assert len(alerts_by_packet[4]) == 1
    assert alerts_by_packet[4][0].sid == 801
    assert alerts_by_packet[4][0].matched_info == 'content="EXPLOIT"'

    assert len(alerts_by_packet[5]) == 1
    assert alerts_by_packet[5][0].sid == 802
    assert alerts_by_packet[5][0].matched_info == 'content="RESPONSE"'

