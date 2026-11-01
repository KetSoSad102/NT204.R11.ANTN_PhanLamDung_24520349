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
    content_evaluated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "sid": self.sid,
            "header_matched": self.header_matched,
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

    def match_content(self, rule: SnortRule, event: NormalizedEvent) -> tuple[bool, str]:
        self.content_evaluations += 1
        payload = get_event_payload(event)

        content_opts = [opt for opt in rule.options if opt.name == "content"]
        if not content_opts:
            return True, ""

        matched_patterns: list[str] = []
        for opt in content_opts:
            if not opt.value:
                continue
            pattern_bytes = parse_snort_pattern(opt.value)
            clean_str = opt.value.strip().strip('"')
            if pattern_bytes not in payload:
                return False, ""
            matched_patterns.append(f'content="{clean_str}"')

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
                content_evaluated=False,
            )

        self.header_matches += 1

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
            content_evaluated=has_content,
        )
