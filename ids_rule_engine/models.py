from __future__ import annotations

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

