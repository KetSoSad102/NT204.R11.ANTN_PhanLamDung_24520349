from __future__ import annotations

from typing import Any


def _decode_text(data: bytes) -> str:
    """
    Decode HTTP text safely.
    """
    return data.decode("utf-8", errors="replace")


def _parse_headers(lines: list[str]) -> dict[str, str]:
    """
    Parse HTTP header lines into a dictionary.
    """
    headers: dict[str, str] = {}

    for line in lines:
        if not line:
            continue

        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        headers[name.strip()] = value.strip()

    return headers


def parse_http(payload: bytes) -> dict[str, Any]:
    """
    Parse a HTTP/1.x request or response.

    Returns:
        A JSON-compatible dictionary.

    Raises:
        ValueError: if the payload does not look like HTTP/1.x.
    """
    if not payload:
        raise ValueError("Empty HTTP payload")

    header_part, separator, body = payload.partition(b"\r\n\r\n")

    if not separator:
        header_part = payload
        body = b""

    lines = header_part.split(b"\r\n")

    if not lines:
        raise ValueError("Malformed HTTP message")

    start_line = _decode_text(lines[0])

    if start_line.startswith("HTTP/1.0 ") or start_line.startswith("HTTP/1.1 "):
        return _parse_response(start_line, lines[1:], body)

    parts = start_line.split(" ", 2)

    if len(parts) == 3 and parts[2].startswith("HTTP/1."):
        return _parse_request(start_line, parts, lines[1:], body)

    raise ValueError("Not an HTTP/1.x message")


def _parse_request(
    start_line: str,
    parts: list[str],
    header_lines: list[bytes],
    body: bytes,
) -> dict[str, Any]:
    """
    Parse an HTTP request.
    """
    method, target, version = parts

    headers = _parse_headers(
        [_decode_text(line) for line in header_lines]
    )

    return {
        "message_type": "request",
        "method": method,
        "target": target,
        "version": version,
        "headers": headers,
        "body": _decode_text(body),
    }


def _parse_response(
    start_line: str,
    header_lines: list[bytes],
    body: bytes,
) -> dict[str, Any]:
    """
    Parse an HTTP response.
    """
    parts = start_line.split(" ", 2)

    if len(parts) < 2:
        raise ValueError("Malformed HTTP response")

    version = parts[0]

    try:
        status_code = int(parts[1])
    except ValueError as exc:
        raise ValueError("Invalid HTTP status code") from exc

    reason = parts[2] if len(parts) == 3 else ""

    headers = _parse_headers(
        [_decode_text(line) for line in header_lines]
    )

    return {
        "message_type": "response",
        "version": version,
        "status_code": status_code,
        "reason": reason,
        "headers": headers,
        "body": _decode_text(body),
    }
