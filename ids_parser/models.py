from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class NormalizedEvent:
    """
    Standardized IDS event.

    This object contains only normalized data that later IDS
    detection modules can consume without accessing Scapy.
    """

    packet_id: int
    timestamp: float

    src_ip: str | None = None
    dst_ip: str | None = None

    network_protocol: str = "IPv4"

    transport_protocol: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None

    application_protocol: str = "UNKNOWN"
    application_data: dict[str, Any] = field(default_factory=dict)

    payload_b64: str | None = None

    parser_status: str = "ok"

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the event to a JSON-compatible dictionary.
        """
        return asdict(self)
