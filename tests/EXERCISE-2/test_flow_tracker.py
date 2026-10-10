from __future__ import annotations

from ids_parser.flow_tracker import FlowTracker
from ids_parser.models import NormalizedEvent


def test_t07_tcp_handshake():
    tracker = FlowTracker()

    syn_event = NormalizedEvent(
        packet_id=1,
        timestamp=1700000000.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50000,
        dst_port=80,
        tcp_flags="S",
    )
    flow1 = tracker.track_packet(syn_event)
    assert len(tracker.flows) == 1
    assert flow1.state == "NEW/HANDSHAKE"
    assert syn_event.flow_state == "NEW/HANDSHAKE"

    syn_ack_event = NormalizedEvent(
        packet_id=2,
        timestamp=1700000000.001,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=80,
        dst_port=50000,
        tcp_flags="SA",
    )
    flow2 = tracker.track_packet(syn_ack_event)
    assert len(tracker.flows) == 1
    assert flow2.flow_id == flow1.flow_id
    assert flow2.state == "NEW/HANDSHAKE"
    assert syn_ack_event.flow_state == "NEW/HANDSHAKE"

    ack_event = NormalizedEvent(
        packet_id=3,
        timestamp=1700000000.002,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50000,
        dst_port=80,
        tcp_flags="A",
    )
    flow3 = tracker.track_packet(ack_event)
    assert len(tracker.flows) == 1
    assert flow3.flow_id == flow1.flow_id
    assert flow3.state == "ESTABLISHED"
    assert ack_event.flow_state == "ESTABLISHED"
    assert flow3.syn_count == 2
    assert flow3.ack_count == 2


def test_t08_bidirectional_flow():
    tracker = FlowTracker()

    ev1 = NormalizedEvent(
        packet_id=1,
        timestamp=1700000000.0,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=45000,
        dst_port=80,
        tcp_flags="PA",
    )
    flow1 = tracker.track_packet(ev1, payload_len=100)

    ev2 = NormalizedEvent(
        packet_id=2,
        timestamp=1700000000.1,
        src_ip="192.168.1.20",
        dst_ip="192.168.1.10",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=80,
        dst_port=45000,
        tcp_flags="PA",
    )
    flow2 = tracker.track_packet(ev2, payload_len=200)

    ev3 = NormalizedEvent(
        packet_id=3,
        timestamp=1700000000.2,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=45000,
        dst_port=80,
        tcp_flags="PA",
    )
    flow3 = tracker.track_packet(ev3, payload_len=50)

    assert len(tracker.flows) == 1
    assert ev1.flow_id == ev2.flow_id == ev3.flow_id
    assert ev1.flow_direction == "forward"
    assert ev2.flow_direction == "backward"
    assert ev3.flow_direction == "forward"

    assert flow3.packet_count == 3
    assert flow3.byte_count == 350
    assert flow3.forward_packet_count == 2
    assert flow3.forward_byte_count == 150
    assert flow3.backward_packet_count == 1
    assert flow3.backward_byte_count == 200


def test_t09_tcp_close_rst():
    tracker = FlowTracker()

    ev1 = NormalizedEvent(packet_id=1, timestamp=1700000000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", network_protocol="IPv4", transport_protocol="TCP", src_port=50000, dst_port=80, tcp_flags="S")
    ev2 = NormalizedEvent(packet_id=2, timestamp=1700000000.1, src_ip="10.0.0.2", dst_ip="10.0.0.1", network_protocol="IPv4", transport_protocol="TCP", src_port=80, dst_port=50000, tcp_flags="SA")
    ev3 = NormalizedEvent(packet_id=3, timestamp=1700000000.2, src_ip="10.0.0.1", dst_ip="10.0.0.2", network_protocol="IPv4", transport_protocol="TCP", src_port=50000, dst_port=80, tcp_flags="A")
    tracker.track_packet(ev1)
    tracker.track_packet(ev2)
    flow = tracker.track_packet(ev3)
    assert flow.state == "ESTABLISHED"

    ev_rst = NormalizedEvent(packet_id=4, timestamp=1700000000.3, src_ip="10.0.0.2", dst_ip="10.0.0.1", network_protocol="IPv4", transport_protocol="TCP", src_port=80, dst_port=50000, tcp_flags="R")
    flow_closed = tracker.track_packet(ev_rst)
    assert flow_closed.state == "CLOSED/RESET"
    assert flow_closed.rst_count == 1
    assert ev_rst.flow_state == "CLOSED/RESET"


def test_t09_tcp_close_fin_ack():
    tracker = FlowTracker()

    ev1 = NormalizedEvent(packet_id=1, timestamp=1700000000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", network_protocol="IPv4", transport_protocol="TCP", src_port=50000, dst_port=80, tcp_flags="S")
    ev2 = NormalizedEvent(packet_id=2, timestamp=1700000000.1, src_ip="10.0.0.2", dst_ip="10.0.0.1", network_protocol="IPv4", transport_protocol="TCP", src_port=80, dst_port=50000, tcp_flags="SA")
    ev3 = NormalizedEvent(packet_id=3, timestamp=1700000000.2, src_ip="10.0.0.1", dst_ip="10.0.0.2", network_protocol="IPv4", transport_protocol="TCP", src_port=50000, dst_port=80, tcp_flags="A")
    tracker.track_packet(ev1)
    tracker.track_packet(ev2)
    tracker.track_packet(ev3)

    ev_fin = NormalizedEvent(packet_id=4, timestamp=1700000000.3, src_ip="10.0.0.1", dst_ip="10.0.0.2", network_protocol="IPv4", transport_protocol="TCP", src_port=50000, dst_port=80, tcp_flags="FA")
    flow_closing = tracker.track_packet(ev_fin)
    assert flow_closing.state == "CLOSING"
    assert flow_closing.fin_count == 1
    assert ev_fin.flow_state == "CLOSING"

    ev_ack = NormalizedEvent(packet_id=5, timestamp=1700000000.4, src_ip="10.0.0.2", dst_ip="10.0.0.1", network_protocol="IPv4", transport_protocol="TCP", src_port=80, dst_port=50000, tcp_flags="A")
    flow_closed = tracker.track_packet(ev_ack)
    assert flow_closed.state == "CLOSED/RESET"
    assert ev_ack.flow_state == "CLOSED/RESET"

