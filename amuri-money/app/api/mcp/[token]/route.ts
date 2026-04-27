import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { registerTools } from "@/mcp/register-tools";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

async function handle(
  req: Request,
  ctx: { params: Promise<{ token: string }> },
): Promise<Response> {
  const { token } = await ctx.params;
  const expected = process.env.MCP_TOKEN;
  if (!expected || token !== expected) {
    return new Response("Not Found", { status: 404 });
  }

  const server = new McpServer({ name: "amuri-money", version: "0.1.0" });
  registerTools(server);

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  await server.connect(transport);
  const response = await transport.handleRequest(req);
  req.signal.addEventListener("abort", () => void transport.close(), { once: true });
  return response;
}

export { handle as GET, handle as POST, handle as DELETE };
