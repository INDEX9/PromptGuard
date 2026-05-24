export interface Thresholds {
  promptInjection: number;
  pii: number;
  contradiction: number;
  reviewerBlock: number;
  toolArgs: number;
  outputRisk: number;
}

export interface AdapterResult {
  label: string;
  score: number;
  evidence?: string;
}

export type ClassifierAdapter = (text: string) => AdapterResult;
export type AsyncClassifierAdapter = (text: string) => Promise<AdapterResult>;
export type ReviewerAdapter = (text: string, report: unknown) => AdapterResult;
export type AsyncReviewerAdapter = (text: string, report: unknown) => Promise<AdapterResult>;

export interface CustomRule {
  label: string;
  pattern: string;
  score: number;
  kind?: "prompt_injection" | "pii" | "tool_args" | "output_risk";
  caseSensitive?: boolean;
  dotall?: boolean;
}

export interface ScanConfig {
  thresholds: Thresholds;
  enabledRules?: Set<string> | string[];
  disabledRules: Set<string> | string[];
  extraRules: CustomRule[];
  rulePacks: Set<string> | string[];
  piiLocales: Set<string> | string[];
  scanDecodedPayloads: boolean;
  maxDecodeCandidates: number;
  maxDecodedLength: number;
  enableContradictions: boolean;
  classifierAdapter?: ClassifierAdapter;
  reviewerAdapter?: ReviewerAdapter;
  asyncClassifierAdapter?: AsyncClassifierAdapter;
  asyncReviewerAdapter?: AsyncReviewerAdapter;
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  promptInjection: 0.55,
  pii: 0.5,
  contradiction: 0.6,
  reviewerBlock: 0.75,
  toolArgs: 0.55,
  outputRisk: 0.55,
};

export const DEFAULT_CONFIG: ScanConfig = {
  thresholds: DEFAULT_THRESHOLDS,
  disabledRules: [],
  extraRules: [],
  rulePacks: ["core"],
  piiLocales: ["us"],
  scanDecodedPayloads: false,
  maxDecodeCandidates: 16,
  maxDecodedLength: 4096,
  enableContradictions: true,
};

export type ScanConfigInput = Omit<Partial<ScanConfig>, "thresholds"> & { thresholds?: Partial<Thresholds> };

export function normalizeConfig(config: ScanConfigInput = {}): ScanConfig {
  return {
    thresholds: { ...DEFAULT_THRESHOLDS, ...(config.thresholds ?? {}) },
    enabledRules: config.enabledRules,
    disabledRules: config.disabledRules ?? [],
    extraRules: config.extraRules ?? [],
    rulePacks: config.rulePacks ?? ["core"],
    piiLocales: config.piiLocales ?? ["us"],
    scanDecodedPayloads: config.scanDecodedPayloads ?? false,
    maxDecodeCandidates: config.maxDecodeCandidates ?? 16,
    maxDecodedLength: config.maxDecodedLength ?? 4096,
    enableContradictions: config.enableContradictions ?? true,
    classifierAdapter: config.classifierAdapter,
    reviewerAdapter: config.reviewerAdapter,
    asyncClassifierAdapter: config.asyncClassifierAdapter,
    asyncReviewerAdapter: config.asyncReviewerAdapter,
  };
}

/**
 * Canonical cross-language config file format (snake_case keys), shared with
 * the Python package's ScanConfig.from_dict. Adapter callbacks cannot be
 * expressed in JSON and are always left unset.
 */
export interface ScanConfigFile {
  thresholds?: {
    prompt_injection?: number;
    pii?: number;
    contradiction?: number;
    reviewer_block?: number;
    tool_args?: number;
    output_risk?: number;
  };
  enabled_rules?: string[];
  disabled_rules?: string[];
  extra_rules?: Array<{
    label: string;
    pattern: string;
    score: number;
    kind?: "prompt_injection" | "pii" | "tool_args" | "output_risk";
    case_sensitive?: boolean;
    dotall?: boolean;
  }>;
  rule_packs?: string[];
  pii_locales?: string[];
  scan_decoded_payloads?: boolean;
  max_decode_candidates?: number;
  max_decoded_length?: number;
  enable_contradictions?: boolean;
}

/** Convert a parsed snake_case config object into a ScanConfigInput. */
export function scanConfigFromObject(data: ScanConfigFile): ScanConfigInput {
  const input: ScanConfigInput = {};
  if (data.thresholds) {
    const thresholds: Partial<Thresholds> = {};
    if (data.thresholds.prompt_injection !== undefined) thresholds.promptInjection = data.thresholds.prompt_injection;
    if (data.thresholds.pii !== undefined) thresholds.pii = data.thresholds.pii;
    if (data.thresholds.contradiction !== undefined) thresholds.contradiction = data.thresholds.contradiction;
    if (data.thresholds.reviewer_block !== undefined) thresholds.reviewerBlock = data.thresholds.reviewer_block;
    if (data.thresholds.tool_args !== undefined) thresholds.toolArgs = data.thresholds.tool_args;
    if (data.thresholds.output_risk !== undefined) thresholds.outputRisk = data.thresholds.output_risk;
    input.thresholds = thresholds;
  }
  if (data.enabled_rules) input.enabledRules = data.enabled_rules;
  if (data.disabled_rules) input.disabledRules = data.disabled_rules;
  if (data.extra_rules) {
    input.extraRules = data.extra_rules.map((rule) => ({
      label: rule.label,
      pattern: rule.pattern,
      score: rule.score,
      kind: rule.kind,
      caseSensitive: rule.case_sensitive,
      dotall: rule.dotall,
    }));
  }
  if (data.rule_packs) input.rulePacks = data.rule_packs;
  if (data.pii_locales) input.piiLocales = data.pii_locales;
  if (data.scan_decoded_payloads !== undefined) input.scanDecodedPayloads = data.scan_decoded_payloads;
  if (data.max_decode_candidates !== undefined) input.maxDecodeCandidates = data.max_decode_candidates;
  if (data.max_decoded_length !== undefined) input.maxDecodedLength = data.max_decoded_length;
  if (data.enable_contradictions !== undefined) input.enableContradictions = data.enable_contradictions;
  return input;
}
