from __future__ import annotations

from typing import Any


SMTP_COMMANDS = {
    "HELO",
    "EHLO",
    "MAIL FROM",
    "RCPT TO",
}


def _decode_text(payload: bytes) -> str:
    return payload.decode("ascii", errors="replace")


def parse_smtp(payload: bytes) -> dict[str, Any]:
    """
    Parse a basic SMTP command or response.

    Raises:
        ValueError: if the payload cannot be recognized as SMTP.
    """
    if not payload:
        raise ValueError("Empty SMTP payload")

    text = _decode_text(payload).strip()

    if not text:
        raise ValueError("Empty SMTP message")

    first_line = text.splitlines()[0].strip()

    # SMTP response: three-digit status code.
    if len(first_line) >= 3 and first_line[:3].isdigit():
        return _parse_response(first_line)

    return _parse_command(first_line)


def _parse_command(line: str) -> dict[str, Any]:
    upper_line = line.upper()

    if upper_line.startswith("MAIL FROM:"):
        command = "MAIL FROM"
        argument = line[len("MAIL FROM:"):].strip()

    elif upper_line.startswith("RCPT TO:"):
        command = "RCPT TO"
        argument = line[len("RCPT TO:"):].strip()

    else:
        parts = line.split(None, 1)

        command = parts[0].upper()

        if command not in {"HELO", "EHLO"}:
            raise ValueError("Unsupported SMTP command")

        argument = parts[1].strip() if len(parts) == 2 else ""

    return {
        "message_type": "command",
        "command": command,
        "argument": argument,
    }


def _parse_response(line: str) -> dict[str, Any]:
    status_code = int(line[:3])

    separator = line[3:4]
    message = line[4:].strip() if len(line) > 4 else ""

    return {
        "message_type": "response",
        "status_code": status_code,
        "separator": separator,
        "message": message,
    }
