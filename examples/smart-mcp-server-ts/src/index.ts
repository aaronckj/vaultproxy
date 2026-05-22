import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const VAULT_PROXY_URL = process.env.VAULT_PROXY_URL ?? "http://127.0.0.1:3201";
const CALLER_ID = process.env.VAULT_PROXY_CALLER_ID ?? "smart-mcp-server-ts";

interface ProxyRequest {
  service: string;
  method?: string;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
  query?: Record<string, string>;
}

async function callProxy(req: ProxyRequest): Promise<unknown> {
  const res = await fetch(`${VAULT_PROXY_URL}/proxy`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Caller-Id": CALLER_ID,
    },
    body: JSON.stringify(req),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`vault-proxy ${res.status}: ${text}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

const server = new Server(
  { name: "smart-mcp-server-ts", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "ha_call_service",
      description:
        "Call a Home Assistant service via vault-proxy. Example: turn a light on or off.",
      inputSchema: {
        type: "object",
        properties: {
          domain: { type: "string", description: "HA domain, e.g. 'light'" },
          service: { type: "string", description: "HA service, e.g. 'turn_on'" },
          entity_id: { type: "string", description: "HA entity id" },
        },
        required: ["domain", "service", "entity_id"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name !== "ha_call_service") {
    throw new Error(`unknown tool: ${req.params.name}`);
  }
  const { domain, service, entity_id } = req.params.arguments as {
    domain: string;
    service: string;
    entity_id: string;
  };

  const result = await callProxy({
    service: "ha_home",
    method: "POST",
    path: `/api/services/${domain}/${service}`,
    body: { entity_id },
  });

  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
