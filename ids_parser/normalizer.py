from __future__ import annotations

import base64
from typing import Any

from ids_parser.models import NormalizedEvent


def normalize_event(
    packet_id: int,
    network: dict[str, Any],
    transport: dict[str, Any] | None = None,
    *,
    transport_protocol: str | None = None,
    application_protocol: str = "UNKNOWN",
    application_data: dict[str, Any] | None = None,
    parser_status: str = "ok",
) -> NormalizedEvent:
    """
    Convert parsed network/transport information into a
    normalized IDS event.
    """
    transport = transport or {}
    application_data = application_data or {}

    payload = transport.get("payload")

    payload_b64: str | None = None

    if payload:
        payload_b64 = base64.b64encode(payload).decode("ascii")

    return NormalizedEvent(
        packet_id=packet_id,
        timestamp=float(network["timestamp"]),
        src_ip=network.get("src_ip"),
        dst_ip=network.get("dst_ip"),
        network_protocol="IPv4",
        transport_protocol=transport_protocol,
        src_port=transport.get("src_port"),
        dst_port=transport.get("dst_port"),
        tcp_flags=transport.get("flags"),
        application_protocol=application_protocol,
        application_data=application_data,
        payload_b64=payload_b64,
        parser_status=parser_status,
    )
