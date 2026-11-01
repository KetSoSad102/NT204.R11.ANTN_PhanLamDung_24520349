from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any
from ids_parser.flow_tracker import Flow
from ids_parser.models import NormalizedEvent
from ids_rule_engine.models import SnortRule


def parse_snort_pattern(raw_pattern: str) -> bytes:
    val = raw_pattern.strip()
    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
        val = val[1:-1]
    if "|" not in val:
        return val.encode("latin1")
    parts = val.split("|")
    out = bytearray()
    for idx, part in enumerate(parts):
        if idx % 2 == 0:
            out.extend(part.encode("latin1"))
        else:
            hex_str = part.replace(" ", "").replace("\t", "")
            if hex_str:
                out.extend(bytes.fromhex(hex_str))
    return bytes(out)


def get_event_payload(event: NormalizedEvent) -> bytes:
    if event.payload_b64:
        try:
            return base64.b64decode(event.payload_b64)
        except Exception:
            return b""
    return b""


def match_tcp_flags(spec: str, event_flags: str | None) -> bool:
    s = spec.strip().upper()
    act = set(event_flags.upper()) if event_flags else set()

    if "!" in s:
        target = set(s.replace("!", "").strip())
        return not any(f in act for f in target)
    elif "*" in s:
        target = set(s.replace("*", "").strip())
        return any(f in act for f in target)
    elif "+" in s:
        target = set(s.replace("+", "").strip())
        return target.issubset(act)
    else:
        if s == "0":
            return len(act) == 0
        target = set(s)
        return target == act


def match_packet_dsize(spec: str, actual_size: int) -> bool:
    s = spec.strip()
    if "<>" in s:
        negated = False
        if s.startswith("!"):
            negated = True
            s = s[1:].strip()
        parts = s.split("<>")
        low = int(parts[0].strip())
        high = int(parts[1].strip())
        in_range = (low <= actual_size <= high)
        return not in_range if negated else in_range
    elif s.startswith(">="):
        target = int(s[2:].strip())
        return actual_size >= target
    elif s.startswith("<="):
        target = int(s[2:].strip())
        return actual_size <= target
    elif s.startswith(">"):
        target = int(s[1:].strip())
        return actual_size > target
    elif s.startswith("<"):
        target = int(s[1:].strip())
        return actual_size < target
    elif s.startswith("!="):
        target = int(s[2:].strip())
        return actual_size != target
    elif s.startswith("!"):
        target = int(s[1:].strip())
        return actual_size != target
    else:
        target = int(s)
        return actual_size == target


@dataclass
class ContentOption:
    pattern: bytes
    raw_pattern: str
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None
    negated: bool = False


def extract_content_options(rule: SnortRule) -> list[ContentOption]:
    content_list: list[ContentOption] = []
    current: ContentOption | None = None

    for opt in rule.options:
        if opt.name == "content":
            if opt.value is not None:
                val = opt.value.strip()
                negated = False
                if val.startswith("!"):
                    negated = True
                    val = val[1:].strip()
                pattern_bytes = parse_snort_pattern(val)
                raw = val.strip('"')
                current = ContentOption(
                    pattern=pattern_bytes,
                    raw_pattern=raw,
                    nocase=False,
                    negated=negated,
                )
                content_list.append(current)
        elif current is not None:
            if opt.name == "nocase":
                current.nocase = True
            elif opt.name == "offset" and opt.value is not None:
                current.offset = int(opt.value)
            elif opt.name == "depth" and opt.value is not None:
                current.depth = int(opt.value)
            elif opt.name == "distance" and opt.value is not None:
                current.distance = int(opt.value)
            elif opt.name == "within" and opt.value is not None:
                current.within = int(opt.value)

    return content_list


@dataclass
class MatchResult:
    matched: bool
    sid: int | None = None
    rev: int = 1
    msg: str = ""
    rule: SnortRule | None = None
    matched_info: str = ""
    rejection_reason: str | None = None
    header_matched: bool = False
    flow_matched: bool = False
    flags_matched: bool = True
    dsize_matched: bool = True
    content_evaluated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "sid": self.sid,
            "header_matched": self.header_matched,
            "flow_matched": self.flow_matched,
            "flags_matched": self.flags_matched,
            "dsize_matched": self.dsize_matched,
            "content_evaluated": self.content_evaluated,
            "matched": self.matched,
            "rejection_reason": self.rejection_reason,
            "matched_info": self.matched_info,
        }


class RuleMatcher:
    def __init__(self) -> None:
        self.header_evaluations: int = 0
        self.header_matches: int = 0
        self.header_rejections: int = 0
        self.flow_evaluations: int = 0
        self.flow_matches: int = 0
        self.flow_rejections: int = 0
        self.flags_evaluations: int = 0
        self.flags_matches: int = 0
        self.flags_rejections: int = 0
        self.dsize_evaluations: int = 0
        self.dsize_matches: int = 0
        self.dsize_rejections: int = 0
        self.content_evaluations: int = 0

    def match_header(self, rule: SnortRule, event: NormalizedEvent) -> bool:
        if not rule.header:
            return False
        proto = event.transport_protocol or event.network_protocol or "UNKNOWN"
        src_ip = event.src_ip or ""
        dst_ip = event.dst_ip or ""
        src_port = event.src_port or 0
        dst_port = event.dst_port or 0
        return rule.header.matches(proto, src_ip, src_port, dst_ip, dst_port)

    def match_flow(
        self,
        rule: SnortRule,
        event: NormalizedEvent,
        flow: Flow | None = None,
    ) -> tuple[bool, str]:
        flow_opts = [opt for opt in rule.options if opt.name == "flow"]
        if not flow_opts:
            return True, ""

        self.flow_evaluations += 1

        current_state = ""
        current_direction = ""

        if flow is not None:
            current_state = flow.state
            src_ep = f"{event.src_ip}:{event.src_port}"
            if flow.initiator:
                current_direction = "to_server" if src_ep == flow.initiator else "to_client"

        if not current_state and event.flow_state:
            current_state = event.flow_state
        if not current_direction and event.flow_direction:
            current_direction = "to_server" if event.flow_direction == "forward" else "to_client"

        for opt in flow_opts:
            if not opt.value:
                continue
            tokens = [t.strip().lower() for t in opt.value.split(",") if t.strip()]
            for tok in tokens:
                if tok in ("to_server", "from_client"):
                    if current_direction != "to_server":
                        return False, f"flow direction mismatch: expected to_server, got {current_direction}"
                elif tok in ("to_client", "from_server"):
                    if current_direction != "to_client":
                        return False, f"flow direction mismatch: expected to_client, got {current_direction}"
                elif tok == "established":
                    if current_state != "ESTABLISHED":
                        return False, f"flow state mismatch: expected ESTABLISHED, got {current_state}"
                elif tok == "not_established":
                    if current_state == "ESTABLISHED":
                        return False, f"flow state mismatch: expected not_established, got {current_state}"

        return True, "flow=ok"

    def match_flags(self, rule: SnortRule, event: NormalizedEvent) -> tuple[bool, str]:
        flags_opts = [opt for opt in rule.options if opt.name == "flags"]
        if not flags_opts:
            return True, ""
        self.flags_evaluations += 1
        for opt in flags_opts:
            if not opt.value:
                continue
            if not match_tcp_flags(opt.value, event.tcp_flags):
                return False, f"flags mismatch: expected {opt.value}, got {event.tcp_flags}"
        return True, "flags=ok"

    def match_dsize(self, rule: SnortRule, event: NormalizedEvent) -> tuple[bool, str]:
        dsize_opts = [opt for opt in rule.options if opt.name == "dsize"]
        if not dsize_opts:
            return True, ""
        self.dsize_evaluations += 1
        payload = get_event_payload(event)
        payload_len = len(payload)
        for opt in dsize_opts:
            if not opt.value:
                continue
            if not match_packet_dsize(opt.value, payload_len):
                return False, f"dsize mismatch: expected {opt.value}, got {payload_len}"
        return True, "dsize=ok"

    def match_content(self, rule: SnortRule, event: NormalizedEvent) -> tuple[bool, str]:
        self.content_evaluations += 1
        content_items = extract_content_options(rule)
        if not content_items:
            return True, ""

        payload = get_event_payload(event)
        matched_patterns: list[str] = []
        last_match_end = 0

        for item in content_items:
            if item.distance is not None:
                start = last_match_end + item.distance
            elif item.within is not None:
                start = last_match_end
            elif item.offset is not None:
                start = item.offset
            else:
                start = 0

            if item.within is not None:
                end = start + item.within
            elif item.depth is not None:
                end = start + item.depth
            else:
                end = len(payload)

            start = max(0, start)
            end = min(len(payload), end)

            if start > len(payload) or start >= end:
                if item.negated:
                    matched_patterns.append(f'!content="{item.raw_pattern}"')
                    continue
                return False, ""

            window = payload[start:end]
            search_window = window.lower() if item.nocase else window
            search_pattern = item.pattern.lower() if item.nocase else item.pattern

            idx = search_window.find(search_pattern)
            found = (idx != -1)

            if item.negated:
                if found:
                    return False, ""
                matched_patterns.append(f'!content="{item.raw_pattern}"')
            else:
                if not found:
                    return False, ""
                matched_patterns.append(f'content="{item.raw_pattern}"')
                last_match_end = start + idx + len(search_pattern)

        return True, "; ".join(matched_patterns)

    def match(
        self,
        rule: SnortRule,
        event: NormalizedEvent,
        flow: Flow | None = None,
    ) -> MatchResult:
        if rule.status != "valid" or not rule.enabled:
            return MatchResult(
                matched=False,
                sid=rule.sid,
                rev=rule.rev,
                msg=rule.msg,
                rule=rule,
                rejection_reason="invalid_or_disabled",
                header_matched=False,
                flow_matched=False,
                content_evaluated=False,
            )

        self.header_evaluations += 1
        if not self.match_header(rule, event):
            self.header_rejections += 1
            return MatchResult(
                matched=False,
                sid=rule.sid,
                rev=rule.rev,
                msg=rule.msg,
                rule=rule,
                rejection_reason="header_mismatch",
                header_matched=False,
                flow_matched=False,
                content_evaluated=False,
            )

        self.header_matches += 1

        has_flow = any(opt.name == "flow" for opt in rule.options)
        if has_flow:
            flow_ok, flow_info = self.match_flow(rule, event, flow=flow)
            if not flow_ok:
                self.flow_rejections += 1
                return MatchResult(
                    matched=False,
                    sid=rule.sid,
                    rev=rule.rev,
                    msg=rule.msg,
                    rule=rule,
                    rejection_reason="flow_mismatch",
                    header_matched=True,
                    flow_matched=False,
                    content_evaluated=False,
                )
            self.flow_matches += 1

        has_flags = any(opt.name == "flags" for opt in rule.options)
        if has_flags:
            flags_ok, _ = self.match_flags(rule, event)
            if not flags_ok:
                self.flags_rejections += 1
                return MatchResult(
                    matched=False,
                    sid=rule.sid,
                    rev=rule.rev,
                    msg=rule.msg,
                    rule=rule,
                    rejection_reason="flags_mismatch",
                    header_matched=True,
                    flow_matched=has_flow,
                    flags_matched=False,
                    content_evaluated=False,
                )
            self.flags_matches += 1

        has_dsize = any(opt.name == "dsize" for opt in rule.options)
        if has_dsize:
            dsize_ok, _ = self.match_dsize(rule, event)
            if not dsize_ok:
                self.dsize_rejections += 1
                return MatchResult(
                    matched=False,
                    sid=rule.sid,
                    rev=rule.rev,
                    msg=rule.msg,
                    rule=rule,
                    rejection_reason="dsize_mismatch",
                    header_matched=True,
                    flow_matched=has_flow,
                    flags_matched=has_flags,
                    dsize_matched=False,
                    content_evaluated=False,
                )
            self.dsize_matches += 1

        has_content = any(opt.name == "content" for opt in rule.options)
        if has_content:
            content_matched, content_info = self.match_content(rule, event)
            if not content_matched:
                return MatchResult(
                    matched=False,
                    sid=rule.sid,
                    rev=rule.rev,
                    msg=rule.msg,
                    rule=rule,
                    rejection_reason="content_mismatch",
                    header_matched=True,
                    flow_matched=has_flow,
                    flags_matched=has_flags,
                    dsize_matched=has_dsize,
                    content_evaluated=True,
                )
            matched_info = content_info
        else:
            matched_info = f"header={rule.header.protocol} {rule.header.direction}" if rule.header else ""

        return MatchResult(
            matched=True,
            sid=rule.sid,
            rev=rule.rev,
            msg=rule.msg,
            rule=rule,
            matched_info=matched_info,
            rejection_reason=None,
            header_matched=True,
            flow_matched=has_flow,
            flags_matched=has_flags,
            dsize_matched=has_dsize,
            content_evaluated=has_content,
        )
