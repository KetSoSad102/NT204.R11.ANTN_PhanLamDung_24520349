from __future__ import annotations

from ids_parser.models import NormalizedEvent
from ids_rule_engine.models import SnortRule


class RuleIndexer:
    def __init__(self, rules: list[SnortRule] | None = None):
        self.rules: list[SnortRule] = []
        self.by_protocol: dict[str, list[SnortRule]] = {
            "TCP": [],
            "UDP": [],
            "IP": [],
        }
        self.by_sid: dict[int, SnortRule] = {}
        if rules:
            for rule in rules:
                self.add_rule(rule)

    def add_rule(self, rule: SnortRule) -> None:
        if rule.status != "valid" or not rule.enabled or not rule.header:
            return
        self.rules.append(rule)
        if rule.sid is not None:
            self.by_sid[rule.sid] = rule
        proto = rule.header.protocol.upper()
        if proto in self.by_protocol:
            self.by_protocol[proto].append(rule)
        else:
            self.by_protocol["IP"].append(rule)

    def get_rule_by_sid(self, sid: int) -> SnortRule | None:
        return self.by_sid.get(sid)

    def get_candidates_by_protocol(self, protocol: str) -> list[SnortRule]:
        proto_up = protocol.upper()
        if proto_up == "TCP":
            return self.by_protocol["TCP"] + self.by_protocol["IP"]
        elif proto_up == "UDP":
            return self.by_protocol["UDP"] + self.by_protocol["IP"]
        return list(self.by_protocol["IP"])

    def get_candidate_rules(self, event: NormalizedEvent) -> list[SnortRule]:
        proto = (event.transport_protocol or event.network_protocol or "").upper()
        base_candidates = self.get_candidates_by_protocol(proto)

        src_port = event.src_port
        dst_port = event.dst_port

        if src_port is None and dst_port is None:
            return base_candidates

        candidates: list[SnortRule] = []
        s_port = src_port or 0
        d_port = dst_port or 0

        for rule in base_candidates:
            header = rule.header
            if not header:
                continue

            if header.src_port_range == (0, 65535) and header.dst_port_range == (0, 65535):
                candidates.append(rule)
                continue

            if header.direction == "->":
                port_match = (
                    header.match_port(s_port, header.src_port_range)
                    and header.match_port(d_port, header.dst_port_range)
                )
            else:
                forward_port = (
                    header.match_port(s_port, header.src_port_range)
                    and header.match_port(d_port, header.dst_port_range)
                )
                backward_port = (
                    header.match_port(s_port, header.dst_port_range)
                    and header.match_port(d_port, header.src_port_range)
                )
                port_match = forward_port or backward_port

            if port_match:
                candidates.append(rule)

        return candidates

