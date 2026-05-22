"""Minimal smart MCP server that calls Home Assistant via vault-proxy.

The HA Bearer token never enters this process — vault-proxy injects it on
the outbound request based on the `ha_home` entry in `services.toml`.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

VAULT_PROXY_URL = os.environ.get("VAULT_PROXY_URL", "http://127.0.0.1:3201")
CALLER_ID = os.environ.get("VAULT_PROXY_CALLER_ID", "smart-mcp-server-py")

server: Server = Server("smart-mcp-server-py")


async def call_proxy(payload: dict[str, Any]) -> Any:
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(
            f"{VAULT_PROXY_URL}/proxy",
            json=payload,
            headers={"X-Caller-Id": CALLER_ID},
        )
        if r.status_code >= 400:
            raise RuntimeError(f"vault-proxy {r.status_code}: {r.text}")
        try:
            return r.json()
        except ValueError:
            return r.text


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ha_call_service",
            description=(
                "Call a Home Assistant service via vault-proxy. "
                "Example: turn a light on or off."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "HA domain, e.g. 'light'"},
                    "service": {"type": "string", "description": "HA service, e.g. 'turn_on'"},
                    "entity_id": {"type": "string", "description": "HA entity id"},
                },
                "required": ["domain", "service", "entity_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name != "ha_call_service":
        raise ValueError(f"unknown tool: {name}")

    domain = arguments["domain"]
    service = arguments["service"]
    entity_id = arguments["entity_id"]

    result = await call_proxy(
        {
            "service": "ha_home",
            "method": "POST",
            "path": f"/api/services/{domain}/{service}",
            "body": {"entity_id": entity_id},
        }
    )
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
