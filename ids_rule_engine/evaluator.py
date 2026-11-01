from __future__ import annotations

from ids_parser.flow_tracker import Flow
from ids_parser.models import NormalizedEvent
from ids_rule_engine.indexer import RuleIndexer
from ids_rule_engine.matcher import MatchResult, RuleMatcher
from ids_rule_engine.models import DetectionEvent, SnortRule


class RuleEvaluationEngine:
    def __init__(
        self,
        rules: list[SnortRule] | None = None,
        indexer: RuleIndexer | None = None,
        matcher: RuleMatcher | None = None,
    ):
        if indexer is not None:
            self.indexer = indexer
        else:
            self.indexer = RuleIndexer(rules=rules or [])
        self.rules: list[SnortRule] = self.indexer.rules
        self.matcher: RuleMatcher = matcher or RuleMatcher()
        self.events_evaluated: int = 0
        self.candidate_rules_evaluated: int = 0
        self.matches_count: int = 0

    @property
    def header_evaluations(self) -> int:
        return self.matcher.header_evaluations

    @property
    def header_rejections(self) -> int:
        return self.matcher.header_rejections

    @property
    def content_evaluations(self) -> int:
        return self.matcher.content_evaluations

    def get_candidate_rules(self, event: NormalizedEvent) -> list[SnortRule]:
        return self.indexer.get_candidate_rules(event)

    def evaluate_event_detailed(
        self,
        event: NormalizedEvent,
        flow: Flow | None = None,
    ) -> list[MatchResult]:
        candidates = self.get_candidate_rules(event)
        results: list[MatchResult] = []
        for rule in candidates:
            results.append(self.matcher.match(rule, event, flow=flow))
        return results

    def evaluate_event(
        self,
        event: NormalizedEvent,
        flow: Flow | None = None,
    ) -> list[DetectionEvent]:
        self.events_evaluated += 1
        candidates = self.get_candidate_rules(event)
        self.candidate_rules_evaluated += len(candidates)

        detection_events: list[DetectionEvent] = []

        for rule in candidates:
            match_res: MatchResult = self.matcher.match(rule, event, flow=flow)
            if match_res.matched:
                self.matches_count += 1
                det = DetectionEvent(
                    timestamp=float(event.timestamp),
                    sid=match_res.sid or 0,
                    rev=match_res.rev,
                    msg=match_res.msg,
                    priority=rule.priority,
                    classtype=rule.classtype,
                    src_ip=event.src_ip or "",
                    src_port=event.src_port or 0,
                    dst_ip=event.dst_ip or "",
                    dst_port=event.dst_port or 0,
                    protocol=event.transport_protocol or event.network_protocol or "UNKNOWN",
                    application_protocol=event.application_protocol,
                    flow_id=event.flow_id,
                    matched_info=match_res.matched_info,
                )
                detection_events.append(det)

        return detection_events
