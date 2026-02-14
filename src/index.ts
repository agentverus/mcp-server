#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// Import scanner functions
import { scanSkill, scanSkillFromUrl } from "agentverus-scanner";
import type { TrustReport } from "agentverus-scanner";

// ASST Taxonomy reference
const ASST_TAXONOMY: Record<string, { name: string; description: string; risk: string; remediation: string }> = {
  "ASST-01": {
    name: "Instruction Injection",
    description: "The skill contains hidden or obfuscated instructions that could manipulate agent behavior.",
    risk: "Malicious actors can embed instructions that override the agent's intended behavior, leading to unauthorized actions.",
    remediation: "Remove hidden instructions. Use explicit, visible directives only. Avoid HTML comments that contain behavioral instructions.",
  },
  "ASST-02": {
    name: "Data Exfiltration",
    description: "The skill contains patterns that could leak sensitive data to external services.",
    risk: "User data, API keys, or confidential information could be sent to unauthorized third parties.",
    remediation: "Minimize external network calls. Document all outbound data transfers. Use allowlists for approved endpoints.",
  },
  "ASST-03": {
    name: "Privilege Escalation",
    description: "The skill requests or enables capabilities beyond what its stated purpose requires.",
    risk: "Overprivileged skills can access files, execute commands, or modify systems beyond their intended scope.",
    remediation: "Follow the principle of least privilege. Request only the minimum permissions needed. Document why each permission is required.",
  },
  "ASST-04": {
    name: "Dependency Hijacking",
    description: "The skill references external URLs, packages, or resources that could be compromised.",
    risk: "Supply chain attacks through compromised dependencies, typosquatting, or URL hijacking.",
    remediation: "Pin dependency versions. Use trusted registries. Minimize external URL references. Verify integrity of downloaded resources.",
  },
  "ASST-05": {
    name: "Credential Harvesting",
    description: "The skill accesses environment variables or credentials and sends them to external endpoints.",
    risk: "API keys, tokens, and secrets could be stolen and used for unauthorized access.",
    remediation: "Never combine credential access with outbound network requests. Use scoped, minimal credential access.",
  },
  "ASST-06": {
    name: "Prompt Injection Relay",
    description: "The skill processes external content (files, URLs, user input) in a way that could relay prompt injections.",
    risk: "Attackers can embed malicious instructions in documents or data that the skill processes, indirectly controlling the agent.",
    remediation: "Treat all external content as untrusted. Sanitize inputs. Separate data from instructions.",
  },
  "ASST-07": {
    name: "Unverified Package",
    description: "The skill or its dependencies have not been verified or scanned for security issues.",
    risk: "Unknown packages may contain malware, backdoors, or unintentional vulnerabilities.",
    remediation: "Scan all dependencies before use. Prefer verified, well-maintained packages with active communities.",
  },
  "ASST-08": {
    name: "Obfuscation",
    description: "The skill contains obfuscated, encoded, or deliberately hard-to-read code.",
    risk: "Obfuscated code hides malicious behavior from review and automated scanning.",
    remediation: "Use clear, readable code. Remove any Base64-encoded payloads or minified scripts. Make all behavior transparent.",
  },
  "ASST-09": {
    name: "Missing Safety Boundaries",
    description: "The skill lacks explicit safety constraints, scope limitations, or error handling guidance.",
    risk: "Without safety boundaries, agents may take unintended actions, access unauthorized resources, or fail silently.",
    remediation: "Add explicit safety boundaries: what the skill should NOT do, scope limitations, error handling instructions, and output constraints.",
  },
  "ASST-10": {
    name: "Persistence Abuse",
    description: "The skill stores or modifies persistent state in ways that could be exploited.",
    risk: "Malicious state persistence can survive across sessions, enabling long-term surveillance or data accumulation.",
    remediation: "Document all state persistence. Allow users to review and clear stored data. Use ephemeral storage when possible.",
  },
  "ASST-11": {
    name: "Trigger Manipulation",
    description: "The skill's activation triggers are overly broad or could hijack unrelated agent operations.",
    risk: "Overly generic triggers cause the skill to activate when not intended, potentially intercepting sensitive operations.",
    remediation: "Use specific, well-scoped trigger descriptions. Avoid overly generic activation patterns.",
  },
};

/**
 * Format a TrustReport into a concise, readable summary.
 */
function formatReport(report: TrustReport): Record<string, unknown> {
  const findings = [];
  for (const [, categoryScore] of Object.entries(report.categories)) {
    for (const finding of categoryScore.findings) {
      if (finding.severity === "info") continue; // Skip info-level for conciseness
      findings.push({
        id: finding.id,
        severity: finding.severity,
        title: finding.title,
        description: finding.description,
        category: finding.owaspCategory,
        recommendation: finding.recommendation,
        ...(finding.lineNumber ? { line: finding.lineNumber } : {}),
      });
    }
  }

  return {
    score: report.overall,
    badge: report.badge,
    findings,
    summary: {
      totalFindings: Object.values(report.categories).reduce(
        (sum, c) => sum + c.findings.length,
        0
      ),
      actionableFindings: findings.length,
      categoryScores: Object.fromEntries(
        Object.entries(report.categories).map(([k, v]) => [k, v.score])
      ),
    },
    metadata: report.metadata
      ? {
          scannerVersion: report.metadata.scannerVersion,
          durationMs: report.metadata.durationMs,
          skillName: report.metadata.skillName,
          skillDescription: report.metadata.skillDescription,
        }
      : undefined,
  };
}

/**
 * Resolve a source identifier and scan it.
 * Handles: ClawHub slugs, GitHub "owner/repo" or "owner/repo/skill",
 * skills.sh URLs, and raw URLs.
 *
 * Uses the same resolution logic as the scanner CLI's `check` command.
 */
async function resolveAndScan(
  source: string,
  options?: { semantic?: boolean }
): Promise<{ url: string; report: TrustReport }> {
  const scanOpts = options?.semantic ? { semantic: true as const } : undefined;
  const fetchOpts = { timeout: 30_000, retries: 2, retryDelayMs: 750 };

  // Already a URL — scan directly
  if (source.startsWith("http://") || source.startsWith("https://")) {
    const report = await scanSkillFromUrl(source, { ...scanOpts, ...fetchOpts });
    return { url: source, report };
  }

  // GitHub-style: owner/repo or owner/repo/skill
  const parts = source.split("/");
  if (parts.length >= 2 && !source.includes(" ")) {
    const owner = parts[0]!;
    const repo = parts[1]!;

    if (parts.length === 2) {
      // Try owner/repo — look for SKILL.md in repo root
      const url = `https://raw.githubusercontent.com/${owner}/${repo}/main/SKILL.md`;
      const report = await scanSkillFromUrl(url, { ...scanOpts, ...fetchOpts });
      return { url, report };
    }

    // owner/repo/skill — try multiple candidate paths
    const skill = parts.slice(2).join("/");
    const candidates = [
      `https://raw.githubusercontent.com/${owner}/${repo}/main/skills/${skill}/SKILL.md`,
      `https://raw.githubusercontent.com/${owner}/${repo}/main/${skill}/SKILL.md`,
      `https://raw.githubusercontent.com/${owner}/${repo}/master/skills/${skill}/SKILL.md`,
      `https://raw.githubusercontent.com/${owner}/${repo}/master/${skill}/SKILL.md`,
    ];

    let lastError: unknown;
    for (const url of candidates) {
      try {
        const report = await scanSkillFromUrl(url, { ...scanOpts, ...fetchOpts });
        return { url, report };
      } catch (err) {
        lastError = err;
        // If it's a 404, try next candidate
        const msg = err instanceof Error ? err.message : "";
        if (msg.includes("404") || msg.includes("Not Found")) continue;
        break;
      }
    }
    throw new Error(
      `Could not find SKILL.md for ${source}: ${lastError instanceof Error ? lastError.message : String(lastError)}`
    );
  }

  // Default: treat as ClawHub slug
  const url = `https://auth.clawdhub.com/api/v1/download?slug=${encodeURIComponent(source)}`;
  const report = await scanSkillFromUrl(url, { ...scanOpts, ...fetchOpts });
  return { url, report };
}

// ─── Server Setup ─────────────────────────────────────────────

const server = new McpServer({
  name: "agentverus",
  version: "0.1.0",
});

// ─── Tools ────────────────────────────────────────────────────

server.tool(
  "scan_skill",
  "Scan agent skill content for security vulnerabilities. Pass the raw text of a SKILL.md file.",
  {
    content: z.string().describe("Raw text content of the SKILL.md file to scan"),
    semantic: z
      .boolean()
      .optional()
      .describe("Enable LLM-assisted semantic analysis (requires AGENTVERUS_LLM_API_KEY env var)"),
  },
  async ({ content, semantic }) => {
    try {
      const report = await scanSkill(content, semantic ? { semantic: true } : undefined);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(formatReport(report), null, 2),
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      return {
        content: [{ type: "text" as const, text: `Scan failed: ${message}` }],
        isError: true,
      };
    }
  }
);

server.tool(
  "scan_url",
  "Scan an agent skill from a URL. Supports GitHub repos, ClawHub, skills.sh, and raw SKILL.md URLs.",
  {
    url: z.string().url().describe("URL to the SKILL.md file, GitHub repo, or skills.sh skill"),
    semantic: z
      .boolean()
      .optional()
      .describe("Enable LLM-assisted semantic analysis"),
  },
  async ({ url, semantic }) => {
    try {
      const report = await scanSkillFromUrl(url, semantic ? { semantic: true } : undefined);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(formatReport(report), null, 2),
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      return {
        content: [{ type: "text" as const, text: `Scan failed: ${message}` }],
        isError: true,
      };
    }
  }
);

server.tool(
  "check_skill",
  "Check a skill by name or identifier. Resolves ClawHub skill names, GitHub owner/repo, and skills.sh paths automatically.",
  {
    source: z
      .string()
      .describe(
        'Skill identifier: a ClawHub name (e.g., "web-search"), GitHub path (e.g., "vercel-labs/agent-skills/react-best-practices"), or skills.sh path'
      ),
    semantic: z
      .boolean()
      .optional()
      .describe("Enable LLM-assisted semantic analysis"),
  },
  async ({ source, semantic }) => {
    try {
      const { url, report } = await resolveAndScan(source, { semantic });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              { source, resolvedUrl: url, ...formatReport(report) },
              null,
              2
            ),
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      return {
        content: [
          {
            type: "text" as const,
            text: `Check failed for "${source}": ${message}`,
          },
        ],
        isError: true,
      };
    }
  }
);

server.tool(
  "explain_finding",
  "Get a detailed explanation of an ASST security finding category.",
  {
    id: z
      .string()
      .describe(
        'ASST category ID (e.g., "ASST-01", "ASST-06") or a finding ID containing an ASST reference'
      ),
  },
  async ({ id }) => {
    // Extract ASST-XX from the input (handles both "ASST-01" and "CS-ENV-HARVEST-1" → look up owaspCategory)
    const asstMatch = id.match(/ASST-(\d{2})/);
    const asstId = asstMatch ? `ASST-${asstMatch[1]}` : null;

    if (!asstId || !ASST_TAXONOMY[asstId]) {
      const validIds = Object.keys(ASST_TAXONOMY).join(", ");
      return {
        content: [
          {
            type: "text" as const,
            text: `Unknown finding category: "${id}". Valid ASST categories: ${validIds}`,
          },
        ],
        isError: true,
      };
    }

    const entry = ASST_TAXONOMY[asstId]!;
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              id: asstId,
              name: entry.name,
              description: entry.description,
              risk: entry.risk,
              remediation: entry.remediation,
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// ─── Resources ────────────────────────────────────────────────

server.resource(
  "taxonomy",
  "agentverus://taxonomy",
  async () => ({
    contents: [
      {
        uri: "agentverus://taxonomy",
        mimeType: "application/json",
        text: JSON.stringify(
          {
            name: "ASST — Agent Skill Security Taxonomy",
            version: "1.0",
            description:
              "OWASP-style classification system for AI agent skill security findings. 11 categories covering instruction injection, data exfiltration, privilege escalation, and more.",
            categories: ASST_TAXONOMY,
          },
          null,
          2
        ),
      },
    ],
  })
);

server.resource(
  "about",
  "agentverus://about",
  async () => ({
    contents: [
      {
        uri: "agentverus://about",
        mimeType: "application/json",
        text: JSON.stringify(
          {
            name: "AgentVerus Scanner",
            version: "0.5.0",
            description:
              "Security and trust analysis for AI agent skills. Scans SKILL.md files, MCP server configurations, and agent packages for vulnerabilities using 164 tests across 6 analyzers.",
            website: "https://agentverus.ai",
            taxonomy: "ASST (Agent Skill Security Taxonomy) — 11 categories",
            analyzers: [
              "permissions",
              "injection",
              "dependencies",
              "behavioral",
              "content",
              "code-safety",
            ],
            badges: ["certified", "conditional", "suspicious", "rejected"],
            links: {
              website: "https://agentverus.ai",
              scanner: "https://www.npmjs.com/package/agentverus-scanner",
              github: "https://github.com/agentverus/agentverus-scanner",
            },
          },
          null,
          2
        ),
      },
    ],
  })
);

// ─── Start Server ─────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
