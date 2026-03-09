"""CLI entry point for ssh-mcp-server.

Subcommands:
    (default)   Start the MCP server (stdio transport)
    init        Create ~/.ssh-mcp with default configs
    version     Print version and exit
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.resources
import json
import shutil
import sys
from pathlib import Path

from .config import default_config_dir


def _get_version() -> str:
    try:
        return importlib.metadata.version("ssh-mcp-server")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0-dev"


def _copy_default_file(name: str, dest: Path) -> bool:
    """Copy a bundled default file to *dest*. Returns True if written."""
    if dest.exists():
        return False
    pkg = importlib.resources.files("ssh_mcp.defaults")
    src = pkg.joinpath(name)
    dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return True


def cmd_init(args: argparse.Namespace) -> None:
    """Create the config directory with default files."""
    config_dir = Path(args.config_dir).expanduser()
    print(f"Initializing SSH MCP Server config in: {config_dir}")

    config_dir.mkdir(parents=True, exist_ok=True)

    # Copy default templates
    wrote_templates = _copy_default_file("templates.json", config_dir / "templates.json")
    if wrote_templates:
        print(f"  Created {config_dir / 'templates.json'}")
    else:
        print(f"  Skipped {config_dir / 'templates.json'} (already exists)")

    # Copy example hosts (as hosts.json if missing)
    hosts_path = config_dir / "hosts.json"
    if not hosts_path.exists():
        _copy_default_file("hosts.example.json", hosts_path)
        print(f"  Created {hosts_path}  <- edit this with your servers")
    else:
        print(f"  Skipped {hosts_path} (already exists)")

    # Create runtime directories
    for subdir in ("audit_logs", "cert_data", "approval_data"):
        p = config_dir / subdir
        p.mkdir(exist_ok=True)
        print(f"  Created {p}/")

    print()
    print("Next steps:")
    print(f"  1. Edit {hosts_path} with your real servers")
    print(f"  2. Ensure ssh-agent is running: eval \"$(ssh-agent -s)\" && ssh-add")
    print(f"  3. Add to any VS Code project's .vscode/mcp.json:")
    print()
    print('     {')
    print('       "servers": {')
    print('         "ssh-mcp": {')
    print('           "type": "stdio",')
    print('           "command": "ssh-mcp-server"')
    print('         }')
    print('       }')
    print('     }')
    print()
    print("  Or add to VS Code User Settings (JSON) to enable globally:")
    print()
    print('     "mcp": {')
    print('       "servers": {')
    print('         "ssh-mcp": {')
    print('           "type": "stdio",')
    print('           "command": "ssh-mcp-server"')
    print('         }')
    print('       }')
    print('     }')
    print()
    print("  4. Open Copilot Chat in Agent mode and start asking!")


def cmd_run(args: argparse.Namespace) -> None:
    """Start the MCP server."""
    import os

    # If --config-dir was explicitly set, propagate to env so ServerConfig picks it up
    if args.config_dir != str(default_config_dir()):
        os.environ["SSH_MCP_CONFIG_DIR"] = str(Path(args.config_dir).expanduser())

    from .server import main as server_main

    server_main()


def cli() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ssh-mcp-server",
        description="Hardened SSH MCP server for VS Code Copilot Chat",
    )
    parser.add_argument(
        "--version", action="version", version=f"ssh-mcp-server {_get_version()}"
    )
    parser.add_argument(
        "--config-dir",
        default=str(default_config_dir()),
        help=f"Config directory (default: {default_config_dir()})",
    )

    subparsers = parser.add_subparsers(dest="command")

    # init subcommand
    subparsers.add_parser("init", help="Initialize config directory with defaults")

    # run subcommand (also the default when no subcommand given)
    subparsers.add_parser("run", help="Start the MCP server (default)")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    else:
        # Default: run the server
        cmd_run(args)
