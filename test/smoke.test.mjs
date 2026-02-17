import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

function createClient() {
  const transport = new StdioClientTransport({
    command: "node",
    args: ["dist/index.js"],
  });
  return {
    transport,
    client: new Client(
      { name: "agentverus-mcp-server-smoke", version: "0.1.0" },
      { capabilities: {} }
    ),
  };
}

test("exposes expected tool surface", async () => {
  const { client, transport } = createClient();
  await client.connect(transport);

  try {
    const tools = await client.listTools();
    const names = tools.tools.map((tool) => tool.name).sort();
    assert.deepEqual(names, [
      "check_skill",
      "explain_finding",
      "scan_skill",
      "scan_url",
    ]);
  } finally {
    await client.close();
  }
});

test("scan_skill and explain_finding work for local inputs", async () => {
  const { client, transport } = createClient();
  await client.connect(transport);

  try {
    const explain = await client.callTool({
      name: "explain_finding",
      arguments: { id: "ASST-06" },
    });
    assert.equal(explain.isError, undefined);
    assert.ok(explain.content[0]?.type === "text");
    assert.ok(explain.content[0]?.text.includes("ASST-06"));

    const scan = await client.callTool({
      name: "scan_skill",
      arguments: {
        content: "---\nname: smoke-test\ndescription: smoke test\n---\n# Smoke Test\nSafe content.",
      },
    });
    assert.equal(scan.isError, undefined);
    assert.ok(scan.content[0]?.type === "text");

    const payload = JSON.parse(scan.content[0]?.text ?? "{}");
    assert.equal(typeof payload.score, "number");
    assert.equal(typeof payload.badge, "string");
  } finally {
    await client.close();
  }
});
