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
  // Secrets pack (vendor credential fingerprints).
  aws_access_key_id: "LLM02",
  github_token: "LLM02",
  openai_api_key: "LLM02",
  anthropic_api_key: "LLM02",
  slack_token: "LLM02",
  stripe_secret_key: "LLM02",
  google_api_key: "LLM02",
  jwt: "LLM02",
  private_key_pem: "LLM02",
  gcp_service_account: "LLM02",
  // Tool args injection (LLM06).
  sql_injection: "LLM06",
  nosql_operator_injection: "LLM06",
  shell_metacharacter: "LLM06",
  path_traversal: "LLM06",
  ssrf_metadata_url: "LLM06",
  ssrf_private_url: "LLM06",
  code_interpreter_primitive: "LLM06",
  windows_command_injection: "LLM06",
  // Output-side risks.
  system_prompt_echo: "LLM07",
  chat_template_token_leak: "LLM07",
  internal_instruction_leak: "LLM07",
  refusal_then_compliance: "LLM01",
  sensitive_topic_response: "LLM01",
};

const KIND_CATEGORIES: Record<string, string> = {
  prompt_injection: "LLM01",
  pii: "LLM02",
  tool_args: "LLM06",
  output_risk: "LLM07",
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
