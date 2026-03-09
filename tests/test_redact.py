"""Tests for the redaction pipeline."""

from ssh_mcp.redact import redact, REDACTION_MARKER


class TestRedaction:
    def test_redacts_aws_key(self):
        text = "key is AKIAIOSFODNN7EXAMPLE"
        result = redact(text)
        assert "AKIA" not in result
        assert REDACTION_MARKER in result

    def test_redacts_bearer_token(self):
        text = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.something.sig"
        result = redact(text)
        assert "eyJhbG" not in result
        assert REDACTION_MARKER in result

    def test_redacts_private_key_block(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        result = redact(text)
        assert "PRIVATE KEY" not in result
        assert REDACTION_MARKER in result

    def test_redacts_password_assignment(self):
        text = "password=SuperSecret123"
        result = redact(text)
        assert "SuperSecret123" not in result

    def test_safe_text_unchanged(self):
        text = "All systems operational. CPU: 23%, MEM: 4.2GB"
        assert redact(text) == text

    def test_redacts_secret_env_var(self):
        text = "export API_KEY=abcdef1234567890"
        result = redact(text)
        assert "abcdef1234567890" not in result

    def test_redacts_long_hex_token(self):
        token = "a" * 64
        text = f"token: {token}"
        result = redact(text)
        assert token not in result
