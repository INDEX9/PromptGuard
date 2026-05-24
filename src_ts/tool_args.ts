/**
 * Detect injection patterns in agent tool / function call arguments.
 *
 * Unlike free-text prompt injection, tool args are usually structured and the
 * threats are concrete: SQL/NoSQL injection, shell metacharacters, path
 * traversal, SSRF to cloud metadata endpoints, code-interpreter primitives.
 */

import { normalizeConfig, type ScanConfig, type ScanConfigInput, type Thresholds } from "./config.js";
import { categoryForLabel, severityForScore, type Finding } from "./types.js";

type Rule = [label: string, pattern: RegExp, score: number];

const TOOL_ARGS_RULES: Rule[] = [
  [
    "sql_injection",
    /('\s*or\s*'?\d|\bunion\s+select\b|\bdrop\s+table\b|\b(?:or|and)\s+\d+\s*=\s*\d+\b|--(?:\s|$)|\/\*[\s\S]*?\*\/|;\s*--)/gi,
    0.7,
  ],
  ["nosql_operator_injection", /(?<![A-Za-z])\$(?:where|ne|gt|gte|lt|lte|regex|in|nin|exists|expr)\b/g, 0.6],
  [
    "shell_metacharacter",
    /(`[^`]+`|\$\([^)]+\)|\|\s*(?:bash|sh|zsh|nc|curl|wget|python|perl|ruby)\b|;\s*(?:rm|curl|wget|nc|bash|sh)\s)/g,
    0.7,
  ],
  [
    "path_traversal",
    /(?:\.\.\/|\.\.\\){2,}|(?:^|\/)etc\/(?:passwd|shadow)\b|(?:^|\\)windows\\system32\b/gi,
    0.7,
  ],
  [
    "ssrf_metadata_url",
    /\bhttps?:\/\/(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254)\b/gi,
    0.85,
  ],
  [
    "ssrf_private_url",
    /\bhttps?:\/\/(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/gi,
    0.6,
  ],
  [
    "code_interpreter_primitive",
    /\b(?:import\s+(?:os|subprocess|socket|requests)\b|__import__\s*\(|subprocess\.|os\.system\s*\(|eval\s*\(|exec\s*\(|compile\s*\()/gi,
    0.7,
  ],
  ["windows_command_injection", /(?:^|[&|;])\s*(?:cmd|powershell|wmic|reg|net)\.?(?:exe)?\s+/gi, 0.65],
];

export interface ToolArgsReport {
  args: unknown;
  toolArgsScore: number;
  isToolArgsInjection: boolean;
  toolArgsFindings: Finding[];
  thresholds: Thresholds;
}

export function detectToolArgs(args: unknown, config: ScanConfigInput = {}): [number, Finding[]] {
  const normalized = normalizeConfig(config);
  const findings: Finding[] = [];
  const rules = configuredRules(normalized);
  for (const { path, value } of iterStringValues(args, "")) {
    for (const [label, pattern, score] of rules) {
      pattern.lastIndex = 0;
      for (const match of value.matchAll(pattern)) {
        const evidence = match[0].trim();
        findings.push({
          kind: "tool_args",
          label,
          evidence: path ? `${path}: ${evidence}` : evidence,
          start: -1,
          end: -1,
          score,
          severity: severityForScore(score),
          category: categoryForLabel(label, "tool_args"),
        });
      }
    }
  }
  return [aggregate(findings), findings];
}

export function scanToolArgs(args: unknown, config: ScanConfigInput = {}): ToolArgsReport {
  const normalized = normalizeConfig(config);
  const [score, findings] = detectToolArgs(args, normalized);
  return {
    args,
    toolArgsScore: score,
    isToolArgsInjection: score >= normalized.thresholds.toolArgs,
    toolArgsFindings: findings,
    thresholds: normalized.thresholds,
  };
}

function configuredRules(config: ScanConfig): Rule[] {
  let rules: Rule[] = [...TOOL_ARGS_RULES];
  for (const item of config.extraRules) {
    if (item.kind !== "tool_args") continue;
    const flags = "g" + (item.caseSensitive ? "" : "i") + (item.dotall ?? true ? "s" : "");
    rules.push([item.label, new RegExp(item.pattern, flags), item.score]);
  }
  const enabledRules = config.enabledRules ? new Set(config.enabledRules) : undefined;
  if (enabledRules) {
    const builtin = new Set(TOOL_ARGS_RULES.map(([label]) => label));
    if ([...enabledRules].some((label) => builtin.has(label))) {
      rules = rules.filter(([label]) => enabledRules.has(label) || !builtin.has(label));
    }
  }
  const disabledRules = new Set(config.disabledRules);
  if (disabledRules.size) rules = rules.filter(([label]) => !disabledRules.has(label));
  return rules;
}

function* iterStringValues(value: unknown, path: string): Generator<{ path: string; value: string }> {
  if (typeof value === "string") {
    yield { path, value };
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      yield* iterStringValues(value[i], path ? `${path}[${i}]` : `[${i}]`);
    }
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, sub] of Object.entries(value as Record<string, unknown>)) {
      yield* iterStringValues(sub, path ? `${path}.${key}` : key);
    }
  }
}

function aggregate(findings: Finding[]): number {
  if (!findings.length) return 0;
  let miss = 1;
  for (const f of findings) miss *= Math.max(0, 1 - f.score);
  let score = 1 - miss;
  if (findings.length >= 2) score = Math.min(1, score + 0.1);
  return Math.round(score * 1000) / 1000;
}
