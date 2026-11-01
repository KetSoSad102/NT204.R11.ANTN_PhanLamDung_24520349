from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RuleHeader:
    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str
    src_port_range: tuple[int, int] | None = None
    dst_port_range: tuple[int, int] | None = None

    def match_ip(self, target_ip: str, rule_ip: str) -> bool:
        if rule_ip == "any" or not target_ip:
            return True
        try:
            if "/" in rule_ip:
                net = ipaddress.IPv4Network(rule_ip, strict=False)
                addr = ipaddress.IPv4Address(target_ip)
                return addr in net
            return ipaddress.IPv4Address(target_ip) == ipaddress.IPv4Address(rule_ip)
        except ValueError:
            return False

    def match_port(self, target_port: int, port_range: tuple[int, int] | None) -> bool:
        if port_range is None:
            return True
        return port_range[0] <= target_port <= port_range[1]

    def matches(self, packet_proto: str, s_ip: str, s_port: int, d_ip: str, d_port: int) -> bool:
        proto_up = packet_proto.upper()
        if self.protocol != "IP" and self.protocol != proto_up:
            return False

        forward_match = (
            self.match_ip(s_ip, self.src_ip)
            and self.match_port(s_port, self.src_port_range)
            and self.match_ip(d_ip, self.dst_ip)
            and self.match_port(d_port, self.dst_port_range)
        )
        if forward_match:
            return True

        if self.direction == "<>":
            backward_match = (
                self.match_ip(s_ip, self.dst_ip)
                and self.match_port(s_port, self.dst_port_range)
                and self.match_ip(d_ip, self.src_ip)
                and self.match_port(d_port, self.src_port_range)
            )
            return backward_match

        return False


@dataclass
class RuleOption:
    name: str
    value: str | None = None


@dataclass
class SnortRule:
    raw_text: str
    header: RuleHeader | None = None
    options: list[RuleOption] = field(default_factory=list)
    sid: int | None = None
    rev: int = 1
    msg: str = ""
    classtype: str | None = None
    priority: int | None = None
    status: str = "valid"
    reason: str | None = None
    enabled: bool = True
    file_path: str | None = None
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionEvent:
    timestamp: float
    sid: int
    rev: int
    msg: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    priority: int | None = None
    classtype: str | None = None
    application_protocol: str | None = None
    flow_id: str | None = None
    matched_info: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
