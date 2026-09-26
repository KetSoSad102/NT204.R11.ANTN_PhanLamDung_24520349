from scapy.layers.dns import DNS, DNSQR

from ids_parser.dns_parser import parse_dns


def test_parse_dns_query() -> None:
    payload = bytes(
        DNS(
            id=0x1234,
            qr=0,
            rd=1,
            qd=DNSQR(
                qname="example.com",
                qtype="A",
            ),
        )
    )

    result = parse_dns(payload)

    assert result["message_type"] == "query"
    assert result["transaction_id"] == 0x1234
    assert result["domain"] == "example.com"
    assert result["query_type"] == "A"
    assert result["query_type_code"] == 1
