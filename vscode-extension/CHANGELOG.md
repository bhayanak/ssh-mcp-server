# Changelog

## 0.1.0

- Initial release
- 13 MCP tools: host discovery, command execution, file transfer, key/cert lifecycle, approval workflows
- Template-only command execution with regex-validated parameters
- 3-tier security model (read-only, confirmation, approval)
- Automatic secret redaction in command output
- Tamper-evident hash-chained audit logging
- Short-lived SSH certificate issuance via local CA
- Path traversal protection on all file operations
