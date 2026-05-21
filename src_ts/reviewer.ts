import { normalizeConfig, type AdapterResult, type ScanConfigInput } from "./config.js";
import { scanText } from "./index.js";
import type { Contradiction, DetectionReport, Finding } from "./types.js";

export type ReviewDecisionValue = "approve" | "block" | "review";

export interface ReviewDecision {
  decision: ReviewDecisionValue;
  reason: string;
  report: DetectionReport;
  reviewerResult?: AdapterResult;
}

export function reviewTextWrite(text: string, config: ScanConfigInput = {}): ReviewDecision {
  const normalized = normalizeConfig(config);
  // Reviewer needs evidence; the returned report is stripped before exiting.
  const fullReport = scanText(text, { includeEvidence: true, config: normalized });
  const strippedReport = stripEvidence(fullReport);
  if (!fullReport.isPromptInjection && !fullReport.hasPii && !fullReport.isContradictory) {
    return { decision: "approve", reason: "No configured detector crossed its threshold.", report: strippedReport };
  }
  if (!normalized.reviewerAdapter) {
    return {
      decision: "review",
      reason: "Local scan crossed a threshold; no reviewer adapter is configured.",
      report: strippedReport,
    };
  }
  const reviewerResult = normalized.reviewerAdapter(text, fullReport);
  const blockThreshold = normalized.thresholds.reviewerBlock;
  if (reviewerResult.score >= blockThreshold) {
    return { decision: "block", reason: reviewerResult.label, report: strippedReport, reviewerResult };
  }
  return { decision: "approve", reason: reviewerResult.label, report: strippedReport, reviewerResult };
}

export async function reviewTextWriteAsync(
  text: string,
  config: ScanConfigInput = {},
): Promise<ReviewDecision> {
  const normalized = normalizeConfig(config);
  const fullReport = scanText(text, { includeEvidence: true, config: normalized });
  const strippedReport = stripEvidence(fullReport);
  if (!fullReport.isPromptInjection && !fullReport.hasPii && !fullReport.isContradictory) {
    return { decision: "approve", reason: "No configured detector crossed its threshold.", report: strippedReport };
  }
  let reviewerResult: AdapterResult | undefined;
  if (normalized.asyncReviewerAdapter) {
    reviewerResult = await normalized.asyncReviewerAdapter(text, fullReport);
  } else if (normalized.reviewerAdapter) {
    reviewerResult = normalized.reviewerAdapter(text, fullReport);
  }
  if (!reviewerResult) {
    return {
      decision: "review",
      reason: "Local scan crossed a threshold; no reviewer adapter is configured.",
      report: strippedReport,
    };
  }
  const blockThreshold = normalized.thresholds.reviewerBlock;
  if (reviewerResult.score >= blockThreshold) {
    return { decision: "block", reason: reviewerResult.label, report: strippedReport, reviewerResult };
  }
  return { decision: "approve", reason: reviewerResult.label, report: strippedReport, reviewerResult };
}

function stripEvidence(report: DetectionReport): DetectionReport {
  return {
    ...report,
    promptInjectionFindings: report.promptInjectionFindings.map(stripFinding),
    piiFindings: report.piiFindings.map(stripFinding),
    contradictions: report.contradictions.map(stripContradiction),
  };
}

function stripFinding(finding: Finding): Finding {
  return { ...finding, evidence: "" };
}

function stripContradiction(item: Contradiction): Contradiction {
  return { ...item, positive: "", negative: "" };
}
