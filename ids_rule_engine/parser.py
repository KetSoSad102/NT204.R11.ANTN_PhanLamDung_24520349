from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from ids_rule_engine.models import RuleHeader, RuleOption, SnortRule

SUPPORTED_KEYWORDS = {
    "msg",
    "sid",
    "rev",
    "content",
    "nocase",
    "offset",
    "depth",
    "distance",
    "within",
    "flags",
    "dsize",
    "flow",
    "classtype",
    "priority",
}

SUPPORTED_PROTOCOLS = {"TCP", "UDP", "IP"}
SUPPORTED_ACTIONS = {"ALERT", "LOG", "PASS", "DROP", "REJECT"}
SUPPORTED_DIRECTIONS = {"->", "<>"}
KNOWN_UNSUPPORTED_PROTOCOLS = {"ICMP", "HTTP", "DNS", "FTP", "SMTP", "TLS", "SSH"}
SUPPORTED_FLOW_TOKENS = {
    "to_server",
    "to_client",
    "from_server",
    "from_client",
    "established",
    "not_established",
    "stateless",
}


def is_valid_ip_or_cidr(ip_str: str) -> bool:
    if ip_str == "any":
        return True
    try:
        if "/" in ip_str:
            ipaddress.IPv4Network(ip_str, strict=False)
        else:
            ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_port_spec(port_str: str) -> bool:
    if port_str == "any":
        return True
    if port_str.isdigit():
        val = int(port_str)
        return 0 <= val <= 65535
    if ":" in port_str:
        parts = port_str.split(":")
        if len(parts) != 2:
            return False
        start_str, end_str = parts[0].strip(), parts[1].strip()
        if not start_str and not end_str:
            return False
        start = int(start_str) if start_str else 0
        end = int(end_str) if end_str else 65535
        if start_str and not start_str.isdigit():
            return False
        if end_str and not end_str.isdigit():
            return False
        return 0 <= start <= end <= 65535
    return False


def parse_port_range(port_str: str) -> tuple[int, int] | None:
    if port_str == "any":
        return (0, 65535)
    if port_str.isdigit():
        val = int(port_str)
        return (val, val)
    if ":" in port_str:
        parts = port_str.split(":")
        start_str, end_str = parts[0].strip(), parts[1].strip()
        start = int(start_str) if start_str else 0
        end = int(end_str) if end_str else 65535
        return (start, end)
    return None


def split_rule_options(options_str: str) -> tuple[list[RuleOption] | None, str | None]:
    options: list[RuleOption] = []
    curr: list[str] = []
    in_quotes = False
    escaped = False

    for ch in options_str:
        if ch == "\\" and in_quotes and not escaped:
            escaped = True
            curr.append(ch)
            continue
        if ch == '"' and not escaped:
            in_quotes = not in_quotes
            curr.append(ch)
            continue
        escaped = False

        if ch == ";" and not in_quotes:
            token = "".join(curr).strip()
            curr = []
            if not token:
                continue
            colon_idx = -1
            t_in_quotes = False
            t_escaped = False
            for i, c in enumerate(token):
                if c == "\\" and t_in_quotes and not t_escaped:
                    t_escaped = True
                    continue
                if c == '"' and not t_escaped:
                    t_in_quotes = not t_in_quotes
                    continue
                t_escaped = False
                if c == ":" and not t_in_quotes:
                    colon_idx = i
                    break

            if colon_idx != -1:
                name = token[:colon_idx].strip()
                val = token[colon_idx + 1 :].strip()
            else:
                name = token.strip()
                val = None

            if not name:
                return None, "Empty option name before semicolon"

            options.append(RuleOption(name=name, value=val))
        else:
            curr.append(ch)

    if in_quotes:
        return None, "Unclosed quote in rule options"

    rem = "".join(curr).strip()
    if rem:
        return None, f"Option not terminated with semicolon: {rem}"

    return options, None


class RuleParser:
    def parse_rule(
        self,
        raw_text: str,
        file_path: str | None = None,
        line_number: int | None = None,
    ) -> SnortRule:
        stripped = raw_text.strip()
        if not stripped:
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason="Empty rule text",
                file_path=file_path,
                line_number=line_number,
            )

        open_idx = stripped.find("(")
        close_idx = stripped.rfind(")")

        if open_idx == -1 or close_idx == -1 or open_idx >= close_idx:
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason="Missing or malformed rule options enclosed in parentheses ()",
                file_path=file_path,
                line_number=line_number,
            )

        header_str = stripped[:open_idx].strip()
        options_str = stripped[open_idx + 1 : close_idx].strip()

        trailing = stripped[close_idx + 1 :].strip()
        if trailing:
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason=f"Unexpected content after closing parenthesis: {trailing}",
                file_path=file_path,
                line_number=line_number,
            )

        header_tokens = header_str.split()
        if len(header_tokens) != 7:
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason=f"Invalid rule header: expected 7 fields, got {len(header_tokens)}",
                file_path=file_path,
                line_number=line_number,
            )

        action, proto, src_ip, src_port, direction, dst_ip, dst_port = header_tokens

        if action.upper() not in SUPPORTED_ACTIONS:
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason=f"Invalid or unsupported rule action: {action}",
                file_path=file_path,
                line_number=line_number,
            )

        proto_upper = proto.upper()
        if proto_upper not in SUPPORTED_PROTOCOLS:
            status = "unsupported" if proto_upper in KNOWN_UNSUPPORTED_PROTOCOLS else "invalid"
            return SnortRule(
                raw_text=raw_text,
                status=status,
                reason=f"Unsupported or invalid protocol: {proto}",
                file_path=file_path,
                line_number=line_number,
            )

        if direction not in SUPPORTED_DIRECTIONS:
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason=f"Invalid direction operator: {direction}",
                file_path=file_path,
                line_number=line_number,
            )

        if not is_valid_ip_or_cidr(src_ip):
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason=f"Invalid source IP or CIDR: {src_ip}",
                file_path=file_path,
                line_number=line_number,
            )

        if not is_valid_ip_or_cidr(dst_ip):
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason=f"Invalid destination IP or CIDR: {dst_ip}",
                file_path=file_path,
                line_number=line_number,
            )

        if not is_valid_port_spec(src_port):
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason=f"Invalid source port specification: {src_port}",
                file_path=file_path,
                line_number=line_number,
            )

        if not is_valid_port_spec(dst_port):
            return SnortRule(
                raw_text=raw_text,
                status="invalid",
                reason=f"Invalid destination port specification: {dst_port}",
                file_path=file_path,
                line_number=line_number,
            )

        header = RuleHeader(
            action=action.lower(),
            protocol=proto_upper,
            src_ip=src_ip,
            src_port=src_port,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            src_port_range=parse_port_range(src_port),
            dst_port_range=parse_port_range(dst_port),
        )

        options, err = split_rule_options(options_str)
        if err:
            return SnortRule(
                raw_text=raw_text,
                header=header,
                status="invalid",
                reason=err,
                file_path=file_path,
                line_number=line_number,
            )

        assert options is not None

        sid_val: int | None = None
        rev_val = 1
        msg_val = ""
        classtype_val: str | None = None
        priority_val: int | None = None

        for opt in options:
            if opt.name not in SUPPORTED_KEYWORDS:
                return SnortRule(
                    raw_text=raw_text,
                    header=header,
                    options=options,
                    status="unsupported",
                    reason=f"Unsupported option keyword: {opt.name}",
                    file_path=file_path,
                    line_number=line_number,
                )

            if opt.name == "sid":
                if not opt.value or not opt.value.isdigit() or int(opt.value) <= 0:
                    return SnortRule(
                        raw_text=raw_text,
                        header=header,
                        options=options,
                        status="invalid",
                        reason=f"Invalid sid value: {opt.value}",
                        file_path=file_path,
                        line_number=line_number,
                    )
                sid_val = int(opt.value)

            elif opt.name == "rev":
                if not opt.value or not opt.value.isdigit() or int(opt.value) <= 0:
                    return SnortRule(
                        raw_text=raw_text,
                        header=header,
                        options=options,
                        status="invalid",
                        reason=f"Invalid rev value: {opt.value}",
                        file_path=file_path,
                        line_number=line_number,
                    )
                rev_val = int(opt.value)

            elif opt.name == "priority":
                if not opt.value or not opt.value.isdigit():
                    return SnortRule(
                        raw_text=raw_text,
                        header=header,
                        options=options,
                        status="invalid",
                        reason=f"Invalid priority value: {opt.value}",
                        file_path=file_path,
                        line_number=line_number,
                    )
                priority_val = int(opt.value)

            elif opt.name == "msg":
                if opt.value:
                    val = opt.value
                    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
                        val = val[1:-1]
                    msg_val = val

            elif opt.name == "classtype":
                classtype_val = opt.value

            elif opt.name in ("offset", "depth", "distance", "within"):
                if not opt.value or not opt.value.lstrip("-").isdigit():
                    return SnortRule(
                        raw_text=raw_text,
                        header=header,
                        options=options,
                        status="invalid",
                        reason=f"Invalid integer value for {opt.name}: {opt.value}",
                        file_path=file_path,
                        line_number=line_number,
                    )

            elif opt.name == "flow":
                if not opt.value or not opt.value.strip():
                    return SnortRule(
                        raw_text=raw_text,
                        header=header,
                        options=options,
                        status="invalid",
                        reason="Empty flow option value",
                        file_path=file_path,
                        line_number=line_number,
                    )
                flow_tokens = [t.strip().lower() for t in opt.value.split(",") if t.strip()]
                for tok in flow_tokens:
                    if tok not in SUPPORTED_FLOW_TOKENS:
                        return SnortRule(
                            raw_text=raw_text,
                            header=header,
                            options=options,
                            status="unsupported",
                            reason=f"Unsupported flow modifier: {tok}",
                            file_path=file_path,
                            line_number=line_number,
                        )

            elif opt.name == "flags":
                if not opt.value or not opt.value.strip():
                    return SnortRule(
                        raw_text=raw_text,
                        header=header,
                        options=options,
                        status="invalid",
                        reason="Empty flags option value",
                        file_path=file_path,
                        line_number=line_number,
                    )

            elif opt.name == "dsize":
                if not opt.value or not opt.value.strip():
                    return SnortRule(
                        raw_text=raw_text,
                        header=header,
                        options=options,
                        status="invalid",
                        reason="Empty dsize option value",
                        file_path=file_path,
                        line_number=line_number,
                    )

        if sid_val is None:
            return SnortRule(
                raw_text=raw_text,
                header=header,
                options=options,
                status="invalid",
                reason="Missing mandatory 'sid' option",
                file_path=file_path,
                line_number=line_number,
            )

        return SnortRule(
            raw_text=raw_text,
            header=header,
            options=options,
            sid=sid_val,
            rev=rev_val,
            msg=msg_val,
            classtype=classtype_val,
            priority=priority_val,
            status="valid",
            reason=None,
            file_path=file_path,
            line_number=line_number,
        )

    def parse_rules(
        self,
        raw_rules: list[tuple[int, str] | str],
        file_path: str | None = None,
    ) -> list[SnortRule]:
        parsed_rules: list[SnortRule] = []
        for item in raw_rules:
            if isinstance(item, tuple):
                line_no, text = item
                rule = self.parse_rule(text, file_path=file_path, line_number=line_no)
            else:
                rule = self.parse_rule(item, file_path=file_path)
            parsed_rules.append(rule)
        return parsed_rules

