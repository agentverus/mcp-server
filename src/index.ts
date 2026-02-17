#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// Import scanner functions
import { scanSkill, scanSkillFromUrl } from "agentverus-scanner";
import { resolveSkillsShUrls } from "agentverus-scanner/registry";
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

type SkillsShEntry = {
  owner: string;
  repo: string;
  slug: string;
  skillsShUrl: string;
};

type GithubRepoResponse = {
  default_branch?: string;
};

type GithubTreeEntry = {
  path?: string;
  type?: string;
};

type GithubTreeResponse = {
  tree?: GithubTreeEntry[];
};

const GITHUB_API_BASE = "https://api.github.com";
const GITHUB_RAW_BASE = "https://raw.githubusercontent.com";
const GITHUB_API_TIMEOUT_MS = 15_000;
const GITHUB_BRANCH_FALLBACKS = ["main", "master"] as const;

function isHttpUrl(source: string): boolean {
  return source.startsWith("http://") || source.startsWith("https://");
}

function isNotFoundError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes("404") || msg.includes("Not Found");
}

function formatHttpErrorBodySnippet(text: string): string {
  const cleaned = text.replace(/\s+/g, " ").trim();
  if (!cleaned) return "";
  return cleaned.length > 200 ? `${cleaned.slice(0, 200)}...` : cleaned;
}

function isSkillMarkdownPath(path: string): boolean {
  const lower = path.toLowerCase();
  return (
    lower === "skill.md" ||
    lower.endsWith("/skill.md") ||
    lower === "skills.md" ||
    lower.endsWith("/skills.md")
  );
}

function rankSkillPath(path: string): number {
  const lower = path.toLowerCase();
  if (lower === "skill.md") return 0;
  if (lower === "skills.md") return 1;
  if (lower.startsWith("skills/") && lower.endsWith("/skill.md")) return 2;
  if (lower.endsWith("/skill.md")) return 3;
  if (lower.startsWith("skills/") && lower.endsWith("/skills.md")) return 4;
  return 5;
}

function pathSort(a: string, b: string): number {
  const byRank = rankSkillPath(a) - rankSkillPath(b);
  if (byRank !== 0) return byRank;
  const byDepth = a.split("/").length - b.split("/").length;
  if (byDepth !== 0) return byDepth;
  const byLength = a.length - b.length;
  if (byLength !== 0) return byLength;
  return a.localeCompare(b);
}

function buildRawGithubUrl(owner: string, repo: string, branch: string, path: string): string {
  return `${GITHUB_RAW_BASE}/${owner}/${repo}/${branch}/${path}`;
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "agentverus-mcp-server/0.1.0",
    },
    signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
  });

  if (!response.ok) {
    const bodyText = await response.text();
    const suffix = formatHttpErrorBodySnippet(bodyText);
    throw new Error(
      `GitHub API request failed (${response.status} ${response.statusText}) for ${url}${suffix ? ` — ${suffix}` : ""}`
    );
  }

  return (await response.json()) as T;
}

async function fetchGithubSkillPaths(
  owner: string,
  repo: string,
  branch: string
): Promise<string[]> {
  const treeUrl = `${GITHUB_API_BASE}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`;
  const tree = await fetchJson<GithubTreeResponse>(treeUrl);
  return (tree.tree ?? [])
    .filter((entry) => entry.type === "blob" && typeof entry.path === "string")
    .map((entry) => entry.path!)
    .filter(isSkillMarkdownPath)
    .sort(pathSort);
}

function scorePathMatch(path: string, skillPath: string): number {
  const lowerPath = path.toLowerCase();
  const normalizedInput = skillPath
    .trim()
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .toLowerCase();

  const directMatches = new Set([
    normalizedInput,
    `${normalizedInput}/skill.md`,
    `${normalizedInput}/skills.md`,
    `skills/${normalizedInput}/skill.md`,
    `skills/${normalizedInput}/skills.md`,
  ]);

  if (directMatches.has(lowerPath)) return 0;

  const inputLeaf = normalizedInput.split("/").filter(Boolean).pop();
  if (
    inputLeaf &&
    (lowerPath.endsWith(`/${inputLeaf}/skill.md`) || lowerPath.endsWith(`/${inputLeaf}/skills.md`))
  ) {
    return 10;
  }

  return Number.POSITIVE_INFINITY;
}

function selectGithubSkillPaths(skillPaths: string[], skillPath?: string): string[] {
  if (!skillPath) return [...skillPaths].sort(pathSort);

  const scored = skillPaths
    .map((path) => ({ path, score: scorePathMatch(path, skillPath) }))
    .filter((entry) => Number.isFinite(entry.score))
    .sort((a, b) => {
      const byScore = a.score - b.score;
      if (byScore !== 0) return byScore;
      return pathSort(a.path, b.path);
    })
    .map((entry) => entry.path);

  if (scored.length > 0) return scored;

  // If caller supplied a path that doesn't match and repo has a single skill file, use it.
  return skillPaths.length === 1 ? [skillPaths[0]!] : [];
}

function buildFallbackGithubCandidates(
  owner: string,
  repo: string,
  skillPath?: string
): string[] {
  if (!skillPath) {
    return [
      buildRawGithubUrl(owner, repo, "main", "SKILL.md"),
      buildRawGithubUrl(owner, repo, "master", "SKILL.md"),
    ];
  }

  return [
    buildRawGithubUrl(owner, repo, "main", `skills/${skillPath}/SKILL.md`),
    buildRawGithubUrl(owner, repo, "main", `${skillPath}/SKILL.md`),
    buildRawGithubUrl(owner, repo, "master", `skills/${skillPath}/SKILL.md`),
    buildRawGithubUrl(owner, repo, "master", `${skillPath}/SKILL.md`),
  ];
}

async function resolveSkillsShToRawUrl(skillsShUrl: string): Promise<string> {
  let parsed: URL;
  try {
    parsed = new URL(skillsShUrl);
  } catch {
    throw new Error(`Invalid URL: ${skillsShUrl}`);
  }

  if (parsed.hostname !== "skills.sh") return skillsShUrl;

  const parts = parsed.pathname.split("/").filter(Boolean);
  const owner = parts[0];
  const repo = parts[1];
  const slug = parts[2];
  if (!owner || !repo || !slug) {
    throw new Error(`Invalid skills.sh URL (expected /owner/repo/skill): ${skillsShUrl}`);
  }

  const entry: SkillsShEntry = { owner, repo, slug, skillsShUrl };
  const resolved = await resolveSkillsShUrls([entry], {
    concurrency: 1,
    timeout: 10_000,
  });

  const match = resolved.resolved[0];
  if (!match) {
    throw new Error(`Could not resolve skills.sh URL to raw SKILL.md: ${skillsShUrl}`);
  }

  return match.rawUrl;
}

async function resolveGithubCandidates(owner: string, repo: string, skillPath?: string): Promise<string[]> {
  const candidateUrls: string[] = [];
  const seen = new Set<string>();

  const addCandidate = (url: string) => {
    if (seen.has(url)) return;
    seen.add(url);
    candidateUrls.push(url);
  };

  try {
    const repoInfoUrl = `${GITHUB_API_BASE}/repos/${owner}/${repo}`;
    const repoInfo = await fetchJson<GithubRepoResponse>(repoInfoUrl);
    const preferredBranch = repoInfo.default_branch ?? "main";
    const branches = [preferredBranch, ...GITHUB_BRANCH_FALLBACKS.filter((b) => b !== preferredBranch)];

    for (const branch of branches) {
      const skillPaths = await fetchGithubSkillPaths(owner, repo, branch);
      const selected = selectGithubSkillPaths(skillPaths, skillPath);
      for (const path of selected) {
        addCandidate(buildRawGithubUrl(owner, repo, branch, path));
      }
    }
  } catch {
    // Fall back to deterministic URL patterns below when GitHub API discovery is unavailable.
  }

  for (const url of buildFallbackGithubCandidates(owner, repo, skillPath)) {
    addCandidate(url);
  }

  return candidateUrls;
}

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
  if (isHttpUrl(source)) {
    const resolvedUrl = await resolveSkillsShToRawUrl(source);
    const report = await scanSkillFromUrl(resolvedUrl, { ...scanOpts, ...fetchOpts });
    return { url: resolvedUrl, report };
  }

  // GitHub-style: owner/repo or owner/repo/skill
  const parts = source.split("/");
  if (parts.length >= 2 && !source.includes(" ")) {
    const owner = parts[0]!;
    const repo = parts[1]!;
    const skill = parts.length > 2 ? parts.slice(2).join("/") : undefined;
    const candidates = await resolveGithubCandidates(owner, repo, skill);

    let lastError: unknown;
    for (const url of candidates) {
      try {
        const report = await scanSkillFromUrl(url, { ...scanOpts, ...fetchOpts });
        return { url, report };
      } catch (err) {
        lastError = err;
        // If it's a 404, try next candidate
        if (isNotFoundError(err)) continue;
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
      const { url: resolvedUrl, report } = await resolveAndScan(url, { semantic });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              { sourceUrl: url, resolvedUrl, ...formatReport(report) },
              null,
              2
            ),
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
