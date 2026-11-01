from __future__ import annotations

from dataclasses import dataclass
from ids_parser.flow_tracker import Flow
from ids_parser.models import NormalizedEvent
from ids_rule_engine.models import SnortRule


@dataclass
class MatchResult:
    matched: bool
    sid: int | None = None
    rev: int = 1
    msg: str = ""
    rule: SnortRule | None = None
    matched_info: str = ""


class RuleMatcher:
    def match_header(self, rule: SnortRule, event: NormalizedEvent) -> bool:
        if not rule.header:
            return False
        proto = event.transport_protocol or event.network_protocol or "UNKNOWN"
        src_ip = event.src_ip or ""
        dst_ip = event.dst_ip or ""
        src_port = event.src_port or 0
        dst_port = event.dst_port or 0
        return rule.header.matches(proto, src_ip, src_port, dst_ip, dst_port)

    def match(
        self,
        rule: SnortRule,
        event: NormalizedEvent,
        flow: Flow | None = None,
    ) -> MatchResult:
        if rule.status != "valid" or not rule.enabled:
            return MatchResult(matched=False)

        if not self.match_header(rule, event):
            return MatchResult(matched=False)

        matched_info = f"header={rule.header.protocol} {rule.header.direction}" if rule.header else ""
        return MatchResult(
            matched=True,
            sid=rule.sid,
            rev=rule.rev,
            msg=rule.msg,
            rule=rule,
            matched_info=matched_info,
        )

