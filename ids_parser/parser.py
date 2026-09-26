from __future__ import annotations

from typing import Any

from scapy.layers.inet import IP

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
