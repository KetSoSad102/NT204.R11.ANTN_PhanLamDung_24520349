from ids_parser.smtp_parser import parse_smtp


def test_parse_smtp_helo() -> None:
    result = parse_smtp(b"HELO mail.example.com\r\n")

    assert result["message_type"] == "command"
    assert result["command"] == "HELO"
    assert result["argument"] == "mail.example.com"


def test_parse_smtp_ehlo() -> None:
    result = parse_smtp(b"EHLO mail.example.com\r\n")

    assert result["message_type"] == "command"
    assert result["command"] == "EHLO"
    assert result["argument"] == "mail.example.com"


def test_parse_smtp_mail_from() -> None:
    result = parse_smtp(
        b"MAIL FROM:<alice@example.com>\r\n"
    )

    assert result["message_type"] == "command"
    assert result["command"] == "MAIL FROM"
    assert result["argument"] == "<alice@example.com>"


def test_parse_smtp_rcpt_to() -> None:
    result = parse_smtp(
        b"RCPT TO:<bob@example.com>\r\n"
    )

    assert result["message_type"] == "command"
    assert result["command"] == "RCPT TO"
    assert result["argument"] == "<bob@example.com>"


def test_parse_smtp_response() -> None:
    result = parse_smtp(
        b"250 mail.example.com OK\r\n"
    )

    assert result["message_type"] == "response"
    assert result["status_code"] == 250
    assert result["message"] == "mail.example.com OK"
