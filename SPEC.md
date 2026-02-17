# AgentVerus MCP Server — Build Spec

## Overview
An MCP (Model Context Protocol) server that wraps the `agentverus-scanner` npm package, exposing agent skill security scanning as MCP tools that any AI agent can call.

## Dependencies
- `@modelcontextprotocol/sdk` — MCP SDK for building servers
- `agentverus-scanner` — The existing security scanner (import from npm or local path)

## MCP Tools to Expose

### 1. `scan_skill`
Scan a skill from raw text content (e.g., a SKILL.md file contents).

**Input:**
- `content` (string, required): The raw text content of the SKILL.md file
- `semantic` (boolean, optional): Enable LLM-assisted semantic analysis

**Output:**
- `score` (number): Overall trust score 0-100
- `badge` (string): "certified" | "conditional" | "suspicious" | "rejected"
- `findings` (array): List of security findings with id, severity, title, description, recommendation
- `metadata` (object): Scanner version, scan duration, skill name

### 2. `scan_url`
Scan a skill from a URL (GitHub, ClawHub, skills.sh, or raw URL).

**Input:**
- `url` (string, required): URL to the SKILL.md file or GitHub repo
- `semantic` (boolean, optional): Enable LLM-assisted semantic analysis

**Output:** Same as `scan_skill`

### 3. `check_skill`
Check a skill by name using the universal resolver (ClawHub, GitHub, skills.sh).
This mirrors the CLI's `agentverus check <source>` command.

**Input:**
- `source` (string, required): Skill name, GitHub "owner/repo", or skills.sh path
- `semantic` (boolean, optional): Enable LLM-assisted semantic analysis

**Output:** Same as `scan_skill`

### 4. `explain_finding`
Get a detailed explanation of a specific ASST finding category.

**Input:**
- `id` (string, required): Finding ID (e.g., "ASST-01", "ASST-06", "BEH-UNRESTRICTED-SCOPE-1")

**Output:**
- `category` (string): ASST category name
- `description` (string): What this finding means
- `risk` (string): Why this matters
- `remediation` (string): How to fix it
- `examples` (string): Common examples of this vulnerability

## MCP Resources to Expose

### 1. `agentverus://taxonomy`
The full ASST taxonomy reference — all 11 categories with descriptions.

### 2. `agentverus://about`
Information about AgentVerus Scanner, version, capabilities.

## Technical Requirements
- TypeScript with ES modules
- Use `@modelcontextprotocol/sdk` Server class with stdio transport
- Import `agentverus-scanner` functions: `scanSkill`, `scanSkillFromUrl`
- For `check_skill`, reuse the check/source resolver logic from the scanner
- Package as `agentverus-scanner-mcp` on npm
- Support `npx agentverus-scanner-mcp` for zero-install usage
- Include a `bin` entry in package.json pointing to the compiled entry point
- Add proper shebang (`#!/usr/bin/env node`) to the entry point

## Project Structure
```
agentverus-mcp-server/
├── src/
│   └── index.ts          # Main MCP server implementation
├── package.json
├── tsconfig.json
├── README.md
└── .gitignore
```

## Scanner API Reference
From `agentverus-scanner/src/scanner/index.ts`:

```typescript
// Scan from raw content
export async function scanSkill(content: string, options?: ScanOptions): Promise<TrustReport>;

// Scan from URL (handles GitHub, ClawHub, skills.sh, raw URLs)
export async function scanSkillFromUrl(url: string, options?: ScanOptions): Promise<TrustReport>;

// Types
interface TrustReport {
  overall: number;        // 0-100
  badge: BadgeTier;       // "certified" | "conditional" | "suspicious" | "rejected"
  categories: Record<Category, CategoryScore>;
  metadata?: ScanMetadata;
}

interface CategoryScore {
  score: number;
  weight: number;
  findings: Finding[];
  summary: string;
}

interface Finding {
  id: string;
  category: Category;
  severity: Severity;     // "critical" | "high" | "medium" | "low" | "info"
  title: string;
  description: string;
  evidence: string;
  deduction: number;
  recommendation: string;
  owaspCategory: string;
  lineNumber?: number;
}
```

## README Content
Include:
1. What AgentVerus is (AI agent security scanner)
2. Installation: `npx agentverus-scanner-mcp` 
3. Configuration examples for Claude Desktop, Cursor, Windsurf
4. Tool descriptions with example usage
5. Link to agentverus.ai and the scanner repo

## Important Notes
- The scanner source resolver (`check` command) handles: ClawHub names, GitHub "owner/repo", skills.sh paths, local files, and raw URLs
- The check_skill tool should import from the scanner's CLI/source module to reuse the resolution logic
- Keep the server lightweight — no database, no external API calls beyond what the scanner does
- Error handling: return structured errors for invalid inputs, network failures, etc.
