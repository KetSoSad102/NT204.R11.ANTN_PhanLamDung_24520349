from scapy.layers.dns import DNS, DNSQR, DNSRR

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

def test_parse_dns_response() -> None:
    payload = bytes(
        DNS(
            id=0x1234,
            qr=1,
            aa=1,
            qd=DNSQR(
                qname="example.com",
                qtype="A",
            ),
            an=DNSRR(
                rrname="example.com.",
                type="A",
                ttl=300,
                rdata="93.184.216.34",
            ),
        )
    )

    result = parse_dns(payload)

    assert result["message_type"] == "response"
    assert result["transaction_id"] == 0x1234
    assert result["answer_count"] == 1

    answer = result["answers"][0]

    assert answer["name"] == "example.com"
    assert answer["type"] == "A"
    assert answer["type_code"] == 1
    assert answer["ttl"] == 300
    assert answer["rdata"] == "93.184.216.34"