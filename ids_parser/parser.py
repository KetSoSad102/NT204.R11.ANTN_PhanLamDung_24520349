from __future__ import annotations

from typing import Any

from scapy.layers.inet import IP,TCP

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