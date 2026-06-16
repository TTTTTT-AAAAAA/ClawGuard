from app.security.sanitizer import sanitized_json


def test_audit_sanitizes_detail():
    text = sanitized_json({"token": "token=secret"})
    assert "secret" not in text
    assert "[REDACTED]" in text

