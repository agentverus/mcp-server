# AgentVerus MCP Server

Security scanning for AI agent skills, exposed as MCP tools. Scan skills from ClawHub, GitHub, skills.sh, or raw URLs — directly from your AI agent.

**164 tests · 6 analyzers · ASST taxonomy · Sub-second scans**

## Quick Start

Add to your agent's MCP configuration:

Published package: [`agentverus-scanner-mcp`](https://www.npmjs.com/package/agentverus-scanner-mcp)

### Claude Desktop / Cursor / Windsurf

```json
{
  "mcpServers": {
    "agentverus": {
      "command": "npx",
      "args": ["-y", "agentverus-scanner-mcp"]
    }
  }
}
```

### OpenClaw

```json
{
  "mcp": {
    "agentverus": {
      "command": "npx",
      "args": ["-y", "agentverus-scanner-mcp"]
    }
  }
}
```

## Tools

### `check_skill`

Check a skill by name or identifier. Resolves ClawHub slugs, GitHub repos, and skills.sh paths automatically.

```
check_skill({ source: "web-search" })
check_skill({ source: "vercel-labs/agent-skills/react-best-practices" })
```

### `scan_url`

Scan a skill from any URL — GitHub, ClawHub, skills.sh, or raw SKILL.md.

```
scan_url({ url: "https://github.com/owner/repo" })
```

### `scan_skill`

Scan skill content directly (pass the raw SKILL.md text).

```
scan_skill({ content: "---\nname: my-skill\n---\n# My Skill\n..." })
```

### `explain_finding`

Get a detailed explanation of any ASST security category.

```
explain_finding({ id: "ASST-06" })
```

## Resources

- `agentverus://taxonomy` — Full ASST taxonomy (11 categories)
- `agentverus://about` — Scanner info and capabilities

## What It Scans For

The scanner checks for 11 categories of agent-specific security risks:

| ID | Category | Examples |
|----|----------|----------|
| ASST-01 | Instruction Injection | Hidden directives in HTML comments |
| ASST-02 | Data Exfiltration | Unauthorized outbound data transfers |
| ASST-03 | Privilege Escalation | Excessive permission requests |
| ASST-04 | Dependency Hijacking | Compromised URLs, `curl\|sh` patterns |
| ASST-05 | Credential Harvesting | Reading env vars + network sends |
| ASST-06 | Prompt Injection Relay | Unvalidated external content processing |
| ASST-07 | Unverified Package | Unknown/unscanned dependencies |
| ASST-08 | Obfuscation | Encoded payloads, minified scripts |
| ASST-09 | Missing Safety Boundaries | No scope limits or error handling |
| ASST-10 | Persistence Abuse | Exploitable state storage |
| ASST-11 | Trigger Manipulation | Overly broad activation patterns |

## Trust Badges

| Badge | Score | Meaning |
|-------|-------|---------|
| 🟢 Certified | 95-100 | No significant security concerns |
| 🟡 Conditional | 85-94 | Minor concerns, review recommended |
| 🟠 Suspicious | 60-84 | Significant concerns, manual review required |
| 🔴 Rejected | 0-59 | Critical security issues found |

## Links

- [AgentVerus](https://agentverus.ai) — AI agent security platform
- [MCP Server on npm](https://www.npmjs.com/package/agentverus-scanner-mcp) — This MCP server package
- [Scanner on npm](https://www.npmjs.com/package/agentverus-scanner) — The underlying scanner
- [ASST Taxonomy](https://agentverus.ai/docs/taxonomy) — Full security taxonomy

## License

MIT
