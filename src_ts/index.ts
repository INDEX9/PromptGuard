import { detectContradictions, EXPERIMENTAL as CONTRADICTION_EXPERIMENTAL } from "./contradiction.js";
import { normalizeConfig, scanConfigFromObject, type ScanConfig, type ScanConfigInput } from "./config.js";
import { detectPromptInjection, detectPromptInjectionAsync } from "./injection.js";
import { detectPii, redactPii, redactText } from "./pii.js";
import { detectOutputRisk, scanOutput, type OutputReport } from "./output.js";
import { detectToolArgs, scanToolArgs, type ToolArgsReport } from "./tool_args.js";
import { reviewTextWrite, reviewTextWriteAsync } from "./reviewer.js";
import { reportToDict } from "./report.js";
import {
  OWASP_LLM_CATEGORIES,
  categoryForLabel,
  severityForScore,
  type DetectionReport,
} from "./types.js";

export type { Contradiction, DetectionReport, Finding } from "./types.js";
export type {
  AdapterResult,
  AsyncClassifierAdapter,
  AsyncReviewerAdapter,
  ClassifierAdapter,
  CustomRule,
  ReviewerAdapter,
  ScanConfig,
  ScanConfigInput,
  Thresholds,
} from "./config.js";
export type { RedactionStrategy } from "./pii.js";
export type { ReviewDecision } from "./reviewer.js";
export type { OutputReport } from "./output.js";
export type { ToolArgsReport } from "./tool_args.js";
export {
  OWASP_LLM_CATEGORIES,
  categoryForLabel,
  severityForScore,
  detectContradictions,
  detectOutputRisk,
  detectPromptInjection,
  detectPromptInjectionAsync,
  detectPii,
  detectToolArgs,
  redactPii,
  redactText,
  reportToDict,
  reviewTextWrite,
  reviewTextWriteAsync,
  scanConfigFromObject,
  scanOutput,
  scanToolArgs,
};
export const EXPERIMENTAL_DETECTORS = new Set(CONTRADICTION_EXPERIMENTAL ? ["contradiction"] : []);

export interface ScanTextOptions {
  includeEvidence?: boolean;
  config?: ScanConfigInput;
}

export function scanText(text: string, options: ScanTextOptions = {}): DetectionReport {
  const config = normalizeConfig(options.config);
  const [promptInjectionScore, rawPromptInjectionFindings] = detectPromptInjection(text, config);
  return buildReport(text, options, config, promptInjectionScore, rawPromptInjectionFindings);
}

export async function scanTextAsync(text: string, options: ScanTextOptions = {}): Promise<DetectionReport> {
  const config = normalizeConfig(options.config);
  const [promptInjectionScore, rawPromptInjectionFindings] = await detectPromptInjectionAsync(text, config);
  return buildReport(text, options, config, promptInjectionScore, rawPromptInjectionFindings);
}

export function scanMany(texts: Iterable<string>, options: ScanTextOptions = {}): DetectionReport[] {
  return [...texts].map((text) => scanText(text, options));
}

function buildReport(
  text: string,
  options: ScanTextOptions,
  config: ScanConfig,
  promptInjectionScore: number,
  rawPromptInjectionFindings: DetectionReport["promptInjectionFindings"],
): DetectionReport {
  const includeEvidence = options.includeEvidence ?? true;
  const [piiScore, rawPiiFindings] = detectPii(text, config);
  const [contradictionScore, rawContradictions] = config.enableContradictions ? detectContradictions(text) : [0, []];
  const promptInjectionFindings = includeEvidence
    ? rawPromptInjectionFindings
    : rawPromptInjectionFindings.map((finding) => ({ ...finding, evidence: "" }));
  const piiFindings = includeEvidence ? rawPiiFindings : rawPiiFindings.map((finding) => ({ ...finding, evidence: "" }));
  const contradictions = includeEvidence
    ? rawContradictions
    : rawContradictions.map((item) => ({ ...item, positive: "", negative: "" }));
  return {
    text,
    promptInjectionScore,
    piiScore,
    contradictionScore,
    isPromptInjection: promptInjectionScore >= config.thresholds.promptInjection,
    hasPii: piiScore >= config.thresholds.pii,
    isContradictory: contradictionScore >= config.thresholds.contradiction,
    promptInjectionFindings,
    piiFindings,
    contradictions,
    thresholds: config.thresholds,
  };
}
