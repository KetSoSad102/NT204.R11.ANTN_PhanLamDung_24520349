from __future__ import annotations

from scapy.layers.dns import DNS
from scapy.packet import Packet


HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
)

SMTP_COMMANDS = (
    b"HELO ",
    b"EHLO ",
    b"MAIL FROM:",
    b"RCPT TO:",
)

SMTP_RESPONSES = (
    b"220 ",
    b"221 ",
    b"250 ",
    b"251 ",
    b"354 ",
    b"421 ",
    b"450 ",
    b"451 ",
    b"452 ",
    b"500 ",
    b"501 ",
    b"502 ",
    b"503 ",
    b"504 ",
    b"550 ",
    b"551 ",
    b"552 ",
    b"553 ",
    b"554 ",
)


def _payload_starts_with_http(payload: bytes) -> bool:
    """
    Detect common HTTP/1.x request methods or response status line.
    """
    upper_payload = payload.upper()

    if any(upper_payload.startswith(method) for method in HTTP_METHODS):
        return True

    return upper_payload.startswith(b"HTTP/1.0 ") or upper_payload.startswith(
        b"HTTP/1.1 "
    )


def _payload_looks_like_smtp(payload: bytes) -> bool:
    """
    Detect common SMTP commands and response status lines.
    """
    upper_payload = payload.upper()

    if any(upper_payload.startswith(command) for command in SMTP_COMMANDS):
        return True

    return any(upper_payload.startswith(response) for response in SMTP_RESPONSES)


def _payload_looks_like_dns(packet: Packet, payload: bytes) -> bool:
    """
    Use Scapy's DNS decoder as a payload-based DNS signal.
    """
    if not payload:
        return False

    try:
        return DNS(payload) is not None
    except Exception:
        return False


def detect_application_protocol(
    packet: Packet,
    *,
    transport_protocol: str | None,
    src_port: int | None,
    dst_port: int | None,
    payload: bytes,
) -> str:
    """
    Detect the application protocol using both port-based and
    payload-based signals.

    Returns:
        HTTP, DNS, SMTP, or UNKNOWN.
    """
    payload = payload or b""

    ports = {src_port, dst_port}

    # Strong payload-based signatures first.
    if _payload_starts_with_http(payload):
        return "HTTP"

    if _payload_looks_like_smtp(payload):
        return "SMTP"

    # DNS commonly uses UDP/TCP port 53. Combine port information
    # with the DNS payload decoder instead of relying only on port.
    if 53 in ports and transport_protocol in {"TCP", "UDP"}:
        if _payload_looks_like_dns(packet, payload):
            return "DNS"

    return "UNKNOWN"
