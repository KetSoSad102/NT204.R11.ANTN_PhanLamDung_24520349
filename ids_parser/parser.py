from __future__ import annotations

from typing import Any

from scapy.layers.inet import IP, TCP, UDP

from ids_parser.capture import CapturedPacket


def parse_ipv4(captured: CapturedPacket) -> dict[str, Any]:
    """
    Extract basic IPv4 information from a captured packet.

    Raises:
        ValueError: if the packet does not contain an IPv4 header.
    """
    packet = captured.packet

    if IP not in packet:
        raise ValueError("Packet does not contain an IPv4 header")

    ip = packet[IP]

    return {
        "timestamp": captured.timestamp,
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "protocol": ip.proto,
        "ttl": ip.ttl,
    }

def parse_tcp(captured: CapturedPacket) -> dict[str, Any]:
    """
    Extract TCP information from a captured IPv4 packet.

    Raises:
        ValueError: if the packet does not contain TCP.
    """
    packet = captured.packet

    if IP not in packet:
        raise ValueError("Packet does not contain an IPv4 header")

    if TCP not in packet:
        raise ValueError("Packet does not contain a TCP header")

    tcp = packet[TCP]

    payload = bytes(tcp.payload)

    return {
        "timestamp": captured.timestamp,
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "src_port": tcp.sport,
        "dst_port": tcp.dport,
        "seq": tcp.seq,
        "ack": tcp.ack,
        "flags": str(tcp.flags),
        "window": tcp.window,
        "payload": payload,
    }

def parse_udp(captured: CapturedPacket) -> dict[str, Any]:
    """
    Extract UDP information from a captured IPv4 packet.

    Raises:
        ValueError: if the packet does not contain IPv4 or UDP.
    """
    packet = captured.packet

    if IP not in packet:
        raise ValueError("Packet does not contain an IPv4 header")

    if UDP not in packet:
        raise ValueError("Packet does not contain a UDP header")

    udp = packet[UDP]

    payload = bytes(udp.payload)

    udp_length = udp.len
    if udp_length is None:
        udp_length = 8 + len(payload)

    return {
        "timestamp": captured.timestamp,
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "src_port": udp.sport,
        "dst_port": udp.dport,
        "length": udp_length,
        "payload": payload,
    }