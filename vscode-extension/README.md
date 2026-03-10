# SSH MCP Server — VS Code Extension

Hardened SSH operations for **VS Code Copilot Chat** via the Model Context Protocol.

Manage remote Linux servers through natural language — check disk usage, tail logs, restart services, transfer files — all with strict security policies, audit trails, and approval workflows.

## Prerequisites

This extension requires the `ssh-mcp-server-copilot` Python package:

```bash
pip install ssh-mcp-server-copilot
ssh-mcp-server-copilot init
```


## Setup

### 1. Install the Python package

```bash
pip install ssh-mcp-server-copilot
```

### 2. Initialize configuration

```bash
ssh-mcp-server-copilot init
```

This creates `~/.ssh-mcp/` with default configuration files.

### 3. Add your servers

Edit `~/.ssh-mcp/hosts.json` with your actual servers:

```json
[
  {
    "host_id": "my-server",
    "hostname": "192.168.1.10",
    "port": 22,
    "ssh_user": "deploy",
    "description": "My production server"
  }
]
```

### 4. Load SSH keys

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

### 5. Start using

Open **Copilot Chat** (`Cmd+Shift+I` / `Ctrl+Shift+I`), switch to **Agent mode**, and ask:

> "List all my SSH hosts"

> "Check disk usage on my-server"

> "Show me the last 100 lines of /var/log/syslog on my-server"

## Features

- **23 MCP tools** — host discovery, command execution, file transfer, persistent sessions, background jobs, SFTP, SSH key & certificate management, approval workflows
- **Persistent SSH sessions** — connect once, run multiple commands with keepalive
- **Background job execution** — start long-running commands, poll output, cancel
- **Enhanced SFTP** — list, upload, download, and delete remote files
- **Template-only execution** — no raw shell; every command matches a pre-approved template
- **3-tier security model** — read-only, confirmation-required, and approval-required operations
- **Automatic secret redaction** — AWS keys, tokens, passwords scrubbed from output
- **Tamper-evident audit log** — every operation hash-chained for forensic analysis
- **Short-lived SSH certificates** — issue/revoke certs with TTL enforcement

## VS Code Settings

Configure the server through VS Code settings (`sshMcp.*`):

| Setting | Default | Description |
|---------|---------|-------------|
| `sshMcp.configDir` | `~/.ssh-mcp` | Config directory path |
| `sshMcp.maxSessions` | `10` | Max simultaneous SSH sessions |
| `sshMcp.sessionIdleTimeout` | `300` | Session idle timeout (seconds) |
| `sshMcp.keepaliveInterval` | `15` | SSH keepalive probe interval (seconds) |
| `sshMcp.maxBackgroundJobs` | `10` | Max concurrent background jobs |
| `sshMcp.requireTwoPartyApproval` | `true` | Require different approver for Tier 2 ops |

## Configuration

All configuration lives in `~/.ssh-mcp/` (or set `SSH_MCP_CONFIG_DIR` to customize):

| File | Purpose |
|------|---------|
| `hosts.json` | Your SSH hosts |
| `templates.json` | Allowed command templates |
| `audit_logs/` | Tamper-evident audit trail |
| `cert_data/` | SSH certificate authority data |
| `approval_data/` | Approval workflow state |

See the [full documentation](https://github.com/bhayanak/ssh-mcp-server) for complete configuration options.

## Links

- [GitHub Repository](https://github.com/bhayanak/ssh-mcp-server)
- [Full Documentation](https://github.com/bhayanak/ssh-mcp-server#readme)
- [Issue Tracker](https://github.com/bhayanak/ssh-mcp-server/issues)

## License

MIT
