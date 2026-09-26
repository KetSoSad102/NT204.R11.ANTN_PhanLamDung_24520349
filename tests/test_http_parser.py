from ids_parser.http_parser import parse_http


def test_http_get() -> None:
    payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: test-client\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )

    result = parse_http(payload)

    assert result["message_type"] == "request"
    assert result["method"] == "GET"
    assert result["target"] == "/index.html"
    assert result["version"] == "HTTP/1.1"

    assert result["headers"]["Host"] == "example.com"
    assert result["headers"]["User-Agent"] == "test-client"
    assert result["headers"]["Accept"] == "*/*"

    assert result["body"] == ""
