from __future__ import annotations

from ids_parser.flow_tracker import Flow, FlowTracker
from ids_parser.models import NormalizedEvent
from ids_rule_engine.generator import DetectionEventGenerator
from ids_rule_engine.indexer import RuleIndexer
from ids_rule_engine.matcher import MatchResult, RuleMatcher
from ids_rule_engine.models import DetectionEvent, SnortRule


class RuleEvaluationEngine:
    def __init__(
        self,
        rules: list[SnortRule] | None = None,
        indexer: RuleIndexer | None = None,
        matcher: RuleMatcher | None = None,
        flow_tracker: FlowTracker | None = None,
        generator: DetectionEventGenerator | None = None,
    ):
        if indexer is not None:
            self.indexer = indexer
        else:
            self.indexer = RuleIndexer(rules=rules or [])
        self.rules: list[SnortRule] = self.indexer.rules
        self.matcher: RuleMatcher = matcher or RuleMatcher()
        self.flow_tracker: FlowTracker | None = flow_tracker
        self.generator: DetectionEventGenerator = generator or DetectionEventGenerator()
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
    def flow_evaluations(self) -> int:
        return self.matcher.flow_evaluations

    @property
    def flow_matches(self) -> int:
        return self.matcher.flow_matches

    @property
    def flow_rejections(self) -> int:
        return self.matcher.flow_rejections

    @property
    def flags_evaluations(self) -> int:
        return self.matcher.flags_evaluations

    @property
    def flags_matches(self) -> int:
        return self.matcher.flags_matches

    @property
    def flags_rejections(self) -> int:
        return self.matcher.flags_rejections

    @property
    def dsize_evaluations(self) -> int:
        return self.matcher.dsize_evaluations

    @property
    def dsize_matches(self) -> int:
        return self.matcher.dsize_matches

    @property
    def dsize_rejections(self) -> int:
        return self.matcher.dsize_rejections

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
        if flow is None and self.flow_tracker is not None and event.flow_id:
            flow = self.flow_tracker.get_flow(event.flow_id)

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
        if flow is None and self.flow_tracker is not None and event.flow_id:
            flow = self.flow_tracker.get_flow(event.flow_id)

        candidates = self.get_candidate_rules(event)
        self.candidate_rules_evaluated += len(candidates)

        detection_events: list[DetectionEvent] = []

        for rule in candidates:
            match_res: MatchResult = self.matcher.match(rule, event, flow=flow)
            if match_res.matched:
                self.matches_count += 1
                det = self.generator.generate(rule, match_res, event, flow=flow)
                detection_events.append(det)

        return detection_events
