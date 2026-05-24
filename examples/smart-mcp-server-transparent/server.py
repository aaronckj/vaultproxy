"""Minimal MCP server demonstrating zero-credential code via the
vault-proxy transparent HTTPS_PROXY listener.

This server exposes a single tool, `ha_get_states`, that calls the
Home Assistant REST API. There is NO authentication code here — the
agent's outbound HTTPS request gets intercepted by vault-proxy's
transparent listener, which injects the Bearer token resolved from
Vaultwarden at egress.

Run with:

    HTTPS_PROXY=http://127.0.0.1:3203 \\
    REQUESTS_CA_BUNDLE=/config/transparent-ca.crt \\
    python3 server.py

See README.md for the full setup.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import requests
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool


HA_URL = os.environ.get("HA_URL", "https://homeassistant.local:8123")


def _check_proxy_env() -> None:
    """Refuse to start if HTTPS_PROXY isn't set — the whole point of
    this example is that the transparent listener is in the path. If
    operators forget to set it, the request would go direct and fail
    with 401 from Home Assistant. Bail loudly so the misconfiguration
    is obvious."""
    if not os.environ.get("HTTPS_PROXY"):
        print(
            "FATAL: HTTPS_PROXY is not set. This example MCP server only "
            "works behind vault-proxy's transparent listener. Run with:\n"
            "    HTTPS_PROXY=http://127.0.0.1:3203 "
            "REQUESTS_CA_BUNDLE=/config/transparent-ca.crt python3 server.py",
            file=sys.stderr,
        )
        sys.exit(1)


server: Server = Server("smart-mcp-server-transparent")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ha_get_states",
            description=(
                "Fetch the current state of every entity from Home Assistant. "
                "Calls GET /api/states with no auth code on this side — "
                "vault-proxy's transparent listener injects the Bearer "
                "token automatically."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, object]) -> list[TextContent]:
    if name != "ha_get_states":
        raise ValueError(f"unknown tool: {name}")

    # No Authorization header. No vault lookup code. The transparent
    # listener handles it.
    r = requests.get(f"{HA_URL}/api/states", timeout=30)
    r.raise_for_status()
    body = r.json()
    return [TextContent(type="text", text=json.dumps(body, indent=2))]


async def main() -> None:
    _check_proxy_env()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
