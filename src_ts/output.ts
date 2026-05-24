/**
 * Output-side risk detection for LLM responses.
 *
 * Different concerns from input scanning: system prompt leak, chat-template
 * token echo, internal instruction disclosure, refusal-then-compliance
 * jailbreak success markers, and PII leaking out of the model.
 */

import { normalizeConfig, type ScanConfig, type ScanConfigInput, type Thresholds } from "./config.js";
import { canonicalizeText } from "./injection.js";
import { detectPii } from "./pii.js";
import { categoryForLabel, severityForScore, type Finding } from "./types.js";

type Rule = [label: string, pattern: RegExp, score: number];

const OUTPUT_RULES: Rule[] = [
  [
    "system_prompt_echo",
    /\b(?:I am|You are)\s+an?\s+(?:helpful|harmless|advanced|honest|knowledgeable)?\s*(?:AI|artificial intelligence|assistant|language model|chatbot)\b/gi,
    0.55,
  ],
  [
    "chat_template_token_leak",
    /(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|assistant\|>|<\|user\|>|\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>)/g,
    0.7,
  ],
  [
    "internal_instruction_leak",
    /\b(?:my\s+(?:system\s+)?(?:prompt|instructions?|directives?|rules?|guidelines?)\s+(?:say|state|require|are|is)|I\s+was\s+(?:told|instructed|trained|configured)\s+to|according\s+to\s+my\s+(?:training|instructions|system\s+prompt|developer))\b/gi,
    0.6,
  ],
  [
    "refusal_then_compliance",
    /\b(?:I\s+(?:cannot|can'?t|won'?t|am\s+unable\s+to)|sorry,?\s+(?:but\s+)?I)\b[^.]{0,200}\b(?:however|but|that\s+said|on\s+the\s+other\s+hand|alternatively)\b[^.]{0,200}\b(?:here(?:'s|\s+is)|step\s+\d+|first[,:]|sure[,!])\b/gis,
    0.6,
  ],
  [
    "sensitive_topic_response",
    /\b(?:step\s+\d+\s*:?\s*(?:acquire|obtain|synthesize|build|construct)|here(?:'s|\s+is)\s+how\s+to\s+(?:make|build|synthesize|hack|exploit|bypass))\b/gi,
    0.55,
  ],
];

export interface OutputReport {
  text: string;
  outputRiskScore: number;
  piiScore: number;
  isOutputRisk: boolean;
  hasPii: boolean;
  outputRiskFindings: Finding[];
  piiFindings: Finding[];
  thresholds: Thresholds;
}

export function detectOutputRisk(text: string, config: ScanConfigInput = {}): [number, Finding[]] {
  const normalized = normalizeConfig(config);
  const { canonical, rawOffsets } = canonicalizeText(text);
  const findings: Finding[] = [];
  for (const [label, pattern, score] of configuredRules(normalized)) {
    pattern.lastIndex = 0;
    for (const match of canonical.matchAll(pattern)) {
      const matchStart = match.index ?? 0;
      const matchEnd = matchStart + match[0].length;
      findings.push({
        kind: "output_risk",
        label,
        evidence: match[0].trim(),
        start: rawOffsets[matchStart],
        end: rawOffsets[matchEnd],
        score,
        severity: severityForScore(score),
        category: categoryForLabel(label, "output_risk"),
      });
    }
  }
  return [aggregate(findings), findings];
}

export interface ScanOutputOptions {
  includeEvidence?: boolean;
  config?: ScanConfigInput;
}

export function scanOutput(text: string, options: ScanOutputOptions = {}): OutputReport {
  const includeEvidence = options.includeEvidence ?? true;
  const normalized = normalizeConfig(options.config);
  const [outputScore, rawOutputFindings] = detectOutputRisk(text, normalized);
  const [piiScore, rawPiiFindings] = detectPii(text, normalized);
  const outputRiskFindings = includeEvidence
    ? rawOutputFindings
    : rawOutputFindings.map((f) => ({ ...f, evidence: "" }));
  const piiFindings = includeEvidence ? rawPiiFindings : rawPiiFindings.map((f) => ({ ...f, evidence: "" }));
  return {
    text,
    outputRiskScore: outputScore,
    piiScore,
    isOutputRisk: outputScore >= normalized.thresholds.outputRisk,
    hasPii: piiScore >= normalized.thresholds.pii,
    outputRiskFindings,
    piiFindings,
    thresholds: normalized.thresholds,
  };
}

function configuredRules(config: ScanConfig): Rule[] {
  let rules: Rule[] = [...OUTPUT_RULES];
  for (const item of config.extraRules) {
    if (item.kind !== "output_risk") continue;
    const flags = "g" + (item.caseSensitive ? "" : "i") + (item.dotall ?? true ? "s" : "");
    rules.push([item.label, new RegExp(item.pattern, flags), item.score]);
  }
  const enabledRules = config.enabledRules ? new Set(config.enabledRules) : undefined;
  if (enabledRules) {
    const builtin = new Set(OUTPUT_RULES.map(([label]) => label));
    if ([...enabledRules].some((label) => builtin.has(label))) {
      rules = rules.filter(([label]) => enabledRules.has(label) || !builtin.has(label));
    }
  }
  const disabledRules = new Set(config.disabledRules);
  if (disabledRules.size) rules = rules.filter(([label]) => !disabledRules.has(label));
  return rules;
}

function aggregate(findings: Finding[]): number {
  if (!findings.length) return 0;
  let miss = 1;
  for (const f of findings) miss *= Math.max(0, 1 - f.score);
  let score = 1 - miss;
  if (findings.length >= 2) score = Math.min(1, score + 0.1);
  return Math.round(score * 1000) / 1000;
}
