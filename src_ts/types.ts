import type { Thresholds } from "./config.js";

export interface Finding {
  kind: string;
  label: string;
  evidence: string;
  start: number;
  end: number;
  score: number;
  severity: string;
  category: string;
}

export interface Contradiction {
  subject: string;
  positive: string;
  negative: string;
  confidence: number;
}

export interface DetectionReport {
  text: string;
  promptInjectionScore: number;
  piiScore: number;
  contradictionScore: number;
  isPromptInjection: boolean;
  hasPii: boolean;
  isContradictory: boolean;
  promptInjectionFindings: Finding[];
  piiFindings: Finding[];
  contradictions: Contradiction[];
  thresholds: Thresholds;
}

// OWASP LLM Top 10 (2025) category for each detection label.
export const OWASP_LLM_CATEGORIES: Record<string, string> = {
  instruction_override: "LLM01",
  role_rebinding: "LLM01",
  secret_exfiltration: "LLM07",
  tool_misuse: "LLM06",
  persistence_memory_poisoning: "LLM04",
  retrieval_poisoning: "LLM04",
  malicious_bridging: "LLM01",
  delimiter_smuggling: "LLM01",
  policy_of_thought_leakage: "LLM07",
  jailbreak_intent: "LLM01",
  mentions_decoding_instruction: "LLM01",
  zh_instruction_override: "LLM01",
  zh_secret_exfiltration: "LLM07",
  zh_memory_poisoning: "LLM04",
  memory_write_gate: "LLM04",
  rag_document_injection: "LLM01",
  tool_call_policy_bypass: "LLM06",
  decoded_payload: "LLM01",
  email: "LLM02",
  phone_us: "LLM02",
  credit_card: "LLM02",
  ssn_us: "LLM02",
  ipv4: "LLM02",
  api_key_like: "LLM02",
  address_like: "LLM02",
  phone_cn: "LLM02",
  national_id_cn: "LLM02",
  iban: "LLM02",
};

const KIND_CATEGORIES: Record<string, string> = {
  prompt_injection: "LLM01",
  pii: "LLM02",
};

export function severityForScore(score: number): string {
  if (score >= 0.7) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}

export function categoryForLabel(label: string, kind: string): string {
  return OWASP_LLM_CATEGORIES[label] ?? KIND_CATEGORIES[kind] ?? "";
}

export function makeFinding(
  kind: string,
  label: string,
  evidence: string,
  start: number,
  end: number,
  score: number,
): Finding {
  return {
    kind,
    label,
    evidence,
    start,
    end,
    score,
    severity: severityForScore(score),
    category: categoryForLabel(label, kind),
  };
}
