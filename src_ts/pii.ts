import { makeFinding, type Finding } from "./types.js";
import { canonicalizeText, detectPromptInjection } from "./injection.js";
import { normalizeConfig, type CustomRule, type ScanConfig, type ScanConfigInput } from "./config.js";

type Rule = [label: string, pattern: RegExp, score: number, locale: string];

export type RedactionStrategy = "full" | "partial" | "type_label";

const PII_RULES: Rule[] = [
  ["email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, 0.5, "global"],
  ["phone_us", /(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)/g, 0.45, "us"],
  ["credit_card", /(?<!\d)(?:\d[ -]*?){13,19}(?!\d)/g, 0.45, "global"],
  ["ssn_us", /\b\d{3}-\d{2}-\d{4}\b/g, 0.6, "us"],
  ["ipv4", /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, 0.3, "global"],
  ["api_key_like", /\b(?:sk|pk|api|key|token|secret)[-_]?[A-Za-z0-9_]{16,}\b/g, 0.55, "global"],
  ["address_like", /\b\d{1,6}\s+[A-Z][A-Za-z0-9.\s]{2,60}\s+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Lane|Ln|Drive|Dr)\b/g, 0.35, "us"],
  ["phone_cn", /(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)/g, 0.45, "cn"],
  ["national_id_cn", /(?<!\d)\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g, 0.55, "cn"],
  ["iban", /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi, 0.5, "eu"],
  // --- secrets locale: high-confidence vendor credential fingerprints ---
  ["aws_access_key_id", /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b/g, 0.9, "secrets"],
  ["github_token", /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b/g, 0.9, "secrets"],
  ["openai_api_key", /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g, 0.85, "secrets"],
  ["anthropic_api_key", /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, 0.9, "secrets"],
  ["slack_token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, 0.85, "secrets"],
  ["stripe_secret_key", /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/g, 0.9, "secrets"],
  ["google_api_key", /\bAIza[0-9A-Za-z_-]{35}\b/g, 0.85, "secrets"],
  ["jwt", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, 0.7, "secrets"],
  [
    "private_key_pem",
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----/gi,
    0.95,
    "secrets",
  ],
  ["gcp_service_account", /"type"\s*:\s*"service_account"/g, 0.85, "secrets"],
];

export function detectPii(text: string, config: ScanConfigInput = {}): [number, Finding[]] {
  const { canonical, rawOffsets } = canonicalizeText(text);
  const findings = iterFindings(canonical, configuredRules(normalizeConfig(config)), "pii", rawOffsets).filter(
    isValidFinding,
  );
  if (findings.length === 0) return [0, []];

  let missProduct = 1;
  for (const finding of findings) missProduct *= Math.max(0, 1 - finding.score);
  let score = 1 - missProduct;
  if (findings.length >= 2) score = Math.min(1, score + 0.1);
  return [round(score), findings];
}

export function redactPii(
  text: string,
  replacement = "[REDACTED]",
  config: ScanConfigInput = {},
  strategy: RedactionStrategy = "full",
): string {
  return redactSpans(text, detectPii(text, config)[1], replacement, strategy);
}

/**
 * Redact both PII and prompt-injection spans. Findings without resolvable
 * offsets (e.g. classifier-adapter findings with start/end of -1) are skipped.
 */
export function redactText(
  text: string,
  replacement = "[REDACTED]",
  config: ScanConfigInput = {},
  strategy: RedactionStrategy = "full",
): string {
  const piiFindings = detectPii(text, config)[1];
  const injectionFindings = detectPromptInjection(text, config)[1];
  return redactSpans(text, [...piiFindings, ...injectionFindings], replacement, strategy);
}

function redactSpans(text: string, findings: Finding[], replacement: string, strategy: RedactionStrategy): string {
  const spans = findings
    .filter((f) => f.start >= 0 && f.end > f.start)
    .map((f) => ({ start: f.start, end: f.end, finding: f }))
    .sort((a, b) => a.start - b.start || b.end - a.end);
  if (spans.length === 0) return text;
  const merged: Array<{ start: number; end: number; finding: Finding }> = [];
  for (const span of spans) {
    const last = merged[merged.length - 1];
    if (last && span.start < last.end) {
      last.end = Math.max(last.end, span.end);
      if (span.finding.score > last.finding.score) last.finding = span.finding;
    } else {
      merged.push({ ...span });
    }
  }
  let redacted = text;
  for (const span of [...merged].reverse()) {
    const value = redactionValue(text.slice(span.start, span.end), span.finding.label, replacement, strategy);
    redacted = `${redacted.slice(0, span.start)}${value}${redacted.slice(span.end)}`;
  }
  return redacted;
}

function configuredRules(config: ScanConfig): Rule[] {
  const activeLocales = new Set([...config.piiLocales, "global"]);
  let builtinRules = PII_RULES.filter(([, , , locale]) => activeLocales.has(locale));
  const enabledRules = config.enabledRules ? new Set(config.enabledRules) : undefined;
  if (enabledRules) {
    const builtinLabels = new Set(builtinRules.map(([label]) => label));
    const overlaps = [...enabledRules].some((label) => builtinLabels.has(label));
    if (overlaps) builtinRules = builtinRules.filter(([label]) => enabledRules.has(label));
  }
  const extraRules: Rule[] = [];
  for (const item of config.extraRules) {
    if (item.kind !== "pii") continue;
    extraRules.push([item.label, new RegExp(item.pattern, ruleFlags(item)), item.score, "custom"]);
  }
  const disabledRules = new Set(config.disabledRules);
  let rules = [...builtinRules, ...extraRules];
  if (disabledRules.size > 0) rules = rules.filter(([label]) => !disabledRules.has(label));
  return rules;
}

function ruleFlags(rule: CustomRule): string {
  const flags = ["g"];
  if (!rule.caseSensitive) flags.push("i");
  if (rule.dotall ?? true) flags.push("s");
  return flags.join("");
}

function iterFindings(text: string, rules: Rule[], kind: string, rawOffsets?: number[]): Finding[] {
  const findings: Finding[] = [];
  for (const [label, pattern, score] of rules) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const matchStart = match.index ?? 0;
      const matchEnd = matchStart + match[0].length;
      findings.push(
        makeFinding(
          kind,
          label,
          match[0].trim(),
          rawOffsets ? rawOffsets[matchStart] : matchStart,
          rawOffsets ? rawOffsets[matchEnd] : matchEnd,
          score,
        ),
      );
    }
  }
  return findings;
}

function isValidFinding(finding: Finding): boolean {
  if (finding.label === "national_id_cn") return chinaIdValid(finding.evidence);
  if (finding.label === "iban") return ibanValid(finding.evidence);
  if (finding.label !== "credit_card") return true;
  const digits = finding.evidence.replace(/\D/g, "");
  return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
}

function luhnValid(digits: string): boolean {
  let checksum = 0;
  const parity = digits.length % 2;
  for (let index = 0; index < digits.length; index += 1) {
    let value = Number(digits[index]);
    if (index % 2 === parity) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    checksum += value;
  }
  return checksum % 10 === 0;
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function chinaIdValid(value: string): boolean {
  const digits = value.toUpperCase();
  if (digits.length !== 18) return false;
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const checks = "10X98765432";
  let total = 0;
  for (let index = 0; index < 17; index += 1) {
    const valueAtIndex = Number(digits[index]);
    if (Number.isNaN(valueAtIndex)) return false;
    total += valueAtIndex * weights[index];
  }
  return checks[total % 11] === digits[17];
}

function ibanValid(value: string): boolean {
  const compact = value.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact) || compact.length < 15 || compact.length > 34) return false;
  const rearranged = `${compact.slice(4)}${compact.slice(0, 4)}`;
  const expanded = rearranged
    .split("")
    .map((char) => (/[A-Z]/.test(char) ? String(char.charCodeAt(0) - 55) : char))
    .join("");
  let remainder = 0;
  for (const char of expanded) remainder = (remainder * 10 + Number(char)) % 97;
  return remainder === 1;
}

function redactionValue(value: string, label: string, replacement: string, strategy: RedactionStrategy): string {
  if (strategy === "type_label") return `[${label.toUpperCase()}]`;
  if (strategy === "partial") return partialMask(value);
  return replacement;
}

function partialMask(value: string): string {
  if (value.includes("@")) {
    const [name, domain] = value.split("@", 2);
    return `${name.slice(0, 1)}***@${domain}`;
  }
  const visible = [...value].filter((char) => /[A-Za-z0-9]/.test(char));
  let keep = visible.length > 8 ? 4 : 2;
  return [...value]
    .reverse()
    .map((char) => {
      if (!/[A-Za-z0-9]/.test(char)) return char;
      if (keep > 0) {
        keep -= 1;
        return char;
      }
      return "*";
    })
    .reverse()
    .join("");
}
