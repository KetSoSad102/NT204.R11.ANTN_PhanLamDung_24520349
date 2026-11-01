from __future__ import annotations

from ids_parser.flow_tracker import Flow
from ids_parser.models import NormalizedEvent
from ids_rule_engine.matcher import MatchResult
from ids_rule_engine.models import DetectionEvent, SnortRule


class DetectionEventGenerator:
    def generate(
        self,
        rule: SnortRule,
        match_result: MatchResult,
        event: NormalizedEvent,
        flow: Flow | None = None,
    ) -> DetectionEvent:
        flow_id = event.flow_id
        if not flow_id and flow is not None:
            flow_id = flow.flow_id

        app_proto = event.application_protocol
        if (not app_proto or app_proto == "UNKNOWN") and flow is not None and flow.application_protocol:
            app_proto = flow.application_protocol

        return DetectionEvent(
            timestamp=float(event.timestamp),
            sid=match_result.sid or rule.sid or 0,
            rev=match_result.rev or rule.rev,
            msg=match_result.msg or rule.msg,
            priority=rule.priority,
            classtype=rule.classtype,
            src_ip=event.src_ip or "",
            src_port=event.src_port or 0,
            dst_ip=event.dst_ip or "",
            dst_port=event.dst_port or 0,
            protocol=event.transport_protocol or event.network_protocol or "UNKNOWN",
            application_protocol=app_proto,
            flow_id=flow_id,
            matched_info=match_result.matched_info,
        )

