from __future__ import annotations

import base64
from ids_parser.decoder import decode_event, decode_html_entities, decode_mime, decode_url
from ids_parser.models import NormalizedEvent


def test_t01_http_url_decode_direct():
    raw_encoded = "/search?query=%27%20OR%201%3D1"
    decoded = decode_url(raw_encoded)
    assert decoded == "/search?query=' OR 1=1"


def test_t01_http_url_decode_event():
    raw_uri = "/login?user=admin%27%20OR%201%3D1&pass=123%23"
    event = NormalizedEvent(
        packet_id=1,
        timestamp=1700000000.0,
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50000,
        dst_port=80,
        application_protocol="HTTP",
        application_data={
            "message_type": "request",
            "method": "GET",
            "target": raw_uri,
            "version": "HTTP/1.1",
            "headers": {"Host": "example.com"},
            "body": "",
        },
    )

    processed_event = decode_event(event)
    app_data = processed_event.application_data

    assert app_data["raw_uri"] == raw_uri
    assert app_data["target"] == raw_uri
    assert app_data["decoded_uri"] == "/login?user=admin' OR 1=1&pass=123#"


def test_t02_html_entity_decode_direct():
    raw_text = "&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt; &amp; test"
    decoded = decode_html_entities(raw_text)
    assert decoded == "<script>alert(\"XSS\")</script> & test"


def test_t02_html_entity_decode_event():
    raw_body = "content=&lt;script&gt;alert(1)&lt;/script&gt;&amp;status=ok"
    event = NormalizedEvent(
        packet_id=2,
        timestamp=1700000001.0,
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50001,
        dst_port=80,
        application_protocol="HTTP",
        application_data={
            "message_type": "request",
            "method": "POST",
            "target": "/post_comment",
            "version": "HTTP/1.1",
            "headers": {"Host": "example.com", "Content-Type": "application/x-www-form-urlencoded"},
            "body": raw_body,
        },
    )

    processed_event = decode_event(event)
    app_data = processed_event.application_data

    assert app_data["raw_body"] == raw_body
    assert app_data["decoded_body"] == "content=<script>alert(1)</script>&status=ok"


def test_t03_mime_base64_decode_direct():
    data = "SGVsbG8gV29ybGQh"
    decoded, status = decode_mime(data, "base64")
    assert status == "ok"
    assert decoded == "Hello World!"


def test_t03_mime_quoted_printable_decode_direct():
    data = "Hello=20World=3D1"
    decoded, status = decode_mime(data, "quoted-printable")
    assert status == "ok"
    assert decoded == "Hello World=1"


def test_t03_smtp_mime_base64_event():
    raw_mail = (
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "SGVsbG8gZnJvbSBJRFMh"
    )
    b64_payload = base64.b64encode(raw_mail.encode("utf-8")).decode("ascii")

    event = NormalizedEvent(
        packet_id=3,
        timestamp=1700000002.0,
        src_ip="192.168.1.100",
        dst_ip="192.168.1.25",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50025,
        dst_port=25,
        application_protocol="SMTP",
        application_data={"message_type": "command", "command": "DATA", "argument": ""},
        payload_b64=b64_payload,
    )

    processed = decode_event(event)
    app_data = processed.application_data

    assert app_data["raw_body"] == "SGVsbG8gZnJvbSBJRFMh"
    assert app_data["decoded_body"] == "Hello from IDS!"
    assert app_data["decode_status"] == "ok"


def test_t03_smtp_mime_quoted_printable_event():
    raw_mail = (
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: quoted-printable\r\n"
        "\r\n"
        "Alert:=20Intrusion=20Detected=3DTrue"
    )
    b64_payload = base64.b64encode(raw_mail.encode("utf-8")).decode("ascii")

    event = NormalizedEvent(
        packet_id=4,
        timestamp=1700000003.0,
        src_ip="192.168.1.100",
        dst_ip="192.168.1.25",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50025,
        dst_port=25,
        application_protocol="SMTP",
        application_data={"message_type": "command", "command": "DATA", "argument": ""},
        payload_b64=b64_payload,
    )

    processed = decode_event(event)
    app_data = processed.application_data

    assert app_data["raw_body"] == "Alert:=20Intrusion=20Detected=3DTrue"
    assert app_data["decoded_body"] == "Alert: Intrusion Detected=True"
    assert app_data["decode_status"] == "ok"
