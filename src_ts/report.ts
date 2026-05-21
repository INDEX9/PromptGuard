import type { Contradiction, DetectionReport, Finding } from "./types.js";

/**
 * Serialize a DetectionReport into the canonical snake_case wire format that is
 * byte-for-byte compatible with the Python package's DetectionReport.as_dict().
 */
export function reportToDict(report: DetectionReport): Record<string, unknown> {
  return {
    text: report.text,
    is_prompt_injection: report.isPromptInjection,
    has_pii: report.hasPii,
    is_contradictory: report.isContradictory,
    prompt_injection_score: report.promptInjectionScore,
    pii_score: report.piiScore,
    contradiction_score: report.contradictionScore,
    thresholds: {
      prompt_injection: report.thresholds.promptInjection,
      pii: report.thresholds.pii,
      contradiction: report.thresholds.contradiction,
      reviewer_block: report.thresholds.reviewerBlock,
    },
    prompt_injection_findings: report.promptInjectionFindings.map(findingToDict),
    pii_findings: report.piiFindings.map(findingToDict),
    contradictions: report.contradictions.map(contradictionToDict),
  };
}

function findingToDict(finding: Finding): Record<string, unknown> {
  return {
    kind: finding.kind,
    label: finding.label,
    evidence: finding.evidence,
    start: finding.start,
    end: finding.end,
    score: finding.score,
    severity: finding.severity,
    category: finding.category,
  };
}

function contradictionToDict(item: Contradiction): Record<string, unknown> {
  return {
    subject: item.subject,
    positive: item.positive,
    negative: item.negative,
    confidence: item.confidence,
  };
}
