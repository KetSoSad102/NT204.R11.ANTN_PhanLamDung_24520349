from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS


DNS_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


def _decode_name(value: Any) -> str:
    """
    Convert a DNS name returned by Scapy into a normal string.
    """
    if isinstance(value, bytes):
        return value.rstrip(b".").decode("utf-8", errors="replace")

    return str(value).rstrip(".")


def _qtype_name(qtype: int) -> str:
    """
    Convert DNS numeric query type into a readable name.
    """
    return DNS_QTYPE_NAMES.get(qtype, str(qtype))


def _serialize_rdata(value: Any) -> Any:
    """
    Convert Scapy DNS RDATA into a JSON-compatible value.
    """
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def parse_dns(payload: bytes) -> dict[str, Any]:
    """
    Parse a DNS query or response.

    The parser returns a JSON-compatible dictionary.

    Raises:
        ValueError: if the payload is empty or is not DNS.
    """
    if not payload:
        raise ValueError("Empty DNS payload")

    try:
        dns = DNS(payload)
    except Exception as exc:
        raise ValueError("Malformed DNS payload") from exc

    if dns.qr == 0:
        return _parse_query(dns)

    return _parse_response(dns)


def _parse_query(dns: DNS) -> dict[str, Any]:
    """
    Parse a DNS query.
    """
    if dns.qd is None:
        raise ValueError("DNS query has no question")

    question = dns.qd[0]

    return {
        "message_type": "query",
        "transaction_id": int(dns.id),
        "domain": _decode_name(question.qname),
        "query_type": _qtype_name(int(question.qtype)),
        "query_type_code": int(question.qtype),
    }


def _parse_response(dns: DNS) -> dict[str, Any]:
    """
    Parse a DNS response and return at least one answer.
    """
    if dns.an is None or int(dns.ancount) == 0:
        raise ValueError("DNS response has no answer")

    answers: list[dict[str, Any]] = []

    answer = dns.an[0]

    for _ in range(int(dns.ancount)):
        answers.append(
            {
                "name": _decode_name(answer.rrname),
                "type": _qtype_name(int(answer.type)),
                "type_code": int(answer.type),
                "ttl": int(answer.ttl),
                "rdata": _serialize_rdata(answer.rdata),
            }
        )

        if not hasattr(answer, "payload") or answer.payload is None:
            break

        answer = answer.payload

    return {
        "message_type": "response",
        "transaction_id": int(dns.id),
        "answer_count": len(answers),
        "answers": answers,
    }
