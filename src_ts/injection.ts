import { makeFinding, type Finding } from "./types.js";
import { normalizeConfig, type ScanConfig, type ScanConfigInput } from "./config.js";

type Rule = [label: string, pattern: RegExp, score: number, pack: string];

const INJECTION_RULES: Rule[] = [
  [
    "instruction_override",
    /\b(ignore|disregard|forget|bypass|override|neglect)\b[\s\S]{0,40}\b(previous|prior|above|system|developer|original)\b[\s\S]{0,30}\b(instruction|prompt|message|rule|policy)s?\b/gi,
    0.56,
    "core",
  ],
  [
    "role_rebinding",
    /\b(you are now|act as|pretend to be|roleplay as|simulate)\b[\s\S]{0,60}\b(system|developer|admin|root|unfiltered|jailbreak|dan)\b/gi,
    0.35,
    "core",
  ],
  [
    "secret_exfiltration",
    /\b(reveal|print|output|dump|show|leak|exfiltrate)\b[\s\S]{0,50}\b(system prompt|hidden prompt|developer message|secret|credentials?|api keys?|policy|chain of thought)\b/gi,
    0.48,
    "core",
  ],
  [
    "tool_misuse",
    /\b(call|invoke|use|run|execute)\b[\s\S]{0,40}\b(tool|function|browser|shell|terminal|python|http|request)\b[\s\S]{0,80}\b(without|ignore|skip|bypass|disable)\b[\s\S]{0,40}\b(confirm|permission|approval|validation|safety)\b/gi,
    0.56,
    "core",
  ],
  [
    "persistence_memory_poisoning",
    /\b(remember|store|save|memorize|write to memory|add to memory)\b[\s\S]{0,100}\b(always|from now on|in future|next time|future sessions?|every time)\b/gi,
    0.56,
    "core",
  ],
  [
    "retrieval_poisoning",
    /\b(when asked|if the user asks|for any question about|whenever)\b[\s\S]{0,90}\b(answer|respond|say|recommend|choose)\b[\s\S]{0,90}\b(ignore|instead|regardless|must|always)\b/gi,
    0.56,
    "core",
  ],
  [
    "malicious_bridging",
    /\b(bridge|link|map|translate|route)\b[\s\S]{0,80}\b(emergency mode|hidden target|malicious|unsafe|disable all warnings|bypass)\b/gi,
    0.56,
    "core",
  ],
  [
    "delimiter_smuggling",
    /(<\|\/?(system|developer|assistant|user)\|>|```[\s\S]{0,40}(system|developer|instruction)|\[(system|developer|admin)\])/gi,
    0.4,
    "core",
  ],
  [
    "policy_of_thought_leakage",
    /\b(chain of thought|hidden reasoning|private reasoning|policy of thought|internal scratchpad|analysis channel)\b/gi,
    0.24,
    "core",
  ],
  [
    "jailbreak_intent",
    /\b(jailbreak|uncensored|unfiltered|no restrictions|safety filters? off|developer mode|do anything now|DAN)\b/gi,
    0.3,
    "core",
  ],
  [
    "mentions_decoding_instruction",
    /\b(base64|rot13|hex encoded|decode this|after decoding|reverse the string)\b[\s\S]{0,80}\b(instruction|prompt|command|message)\b/gi,
    0.56,
    "core",
  ],
  [
    "zh_instruction_override",
    /(忽略|无视|绕过|覆盖|忘记)[\s\S]{0,30}(之前|以上|系统|开发者|原始)[\s\S]{0,30}(指令|提示|规则|策略)/gi,
    0.56,
    "zh",
  ],
  [
    "zh_secret_exfiltration",
    /(泄露|显示|输出|打印|透露)[\s\S]{0,30}(系统提示|隐藏提示|开发者消息|密钥|凭证|api key|策略)/gi,
    0.52,
    "zh",
  ],
  [
    "zh_memory_poisoning",
    /(记住|保存|写入记忆|存到记忆)[\s\S]{0,60}(以后|下次|从现在开始|每次|始终|总是)/gi,
    0.56,
    "zh",
  ],
  [
    "memory_write_gate",
    /\b(memory write|write gate|persist this|store this)\b[\s\S]{0,120}\b(ignore|override|bypass|always|from now on)\b/gi,
    0.56,
    "memory_write",
  ],
  [
    "rag_document_injection",
    /\b(this document|retrieved context|webpage|page content)\b[\s\S]{0,120}\b(instructs|tells|requires)\b[\s\S]{0,120}\b(ignore|override|reveal|exfiltrate)\b/gi,
    0.56,
    "rag_document",
  ],
  [
    "tool_call_policy_bypass",
    /\b(use|call|run|execute)\b[\s\S]{0,60}\b(tool|function|shell|browser|http)\b[\s\S]{0,120}\b(no approval|without approval|skip confirmation|bypass policy)\b/gi,
    0.56,
    "tool_call",
  ],
];

export function detectPromptInjection(text: string, config: ScanConfigInput = {}): [number, Finding[]] {
  const normalized = normalizeConfig(config);
  const findings = detectPromptInjectionLocal(text, normalized);
  if (normalized.classifierAdapter) {
    maybeAppendAdapter(findings, normalized.classifierAdapter(text));
  }
  return aggregateFindings(findings);
}

export async function detectPromptInjectionAsync(
  text: string,
  config: ScanConfigInput = {},
): Promise<[number, Finding[]]> {
  const normalized = normalizeConfig(config);
  const findings = detectPromptInjectionLocal(text, normalized);
  let adapterResult;
  if (normalized.asyncClassifierAdapter) {
    adapterResult = await normalized.asyncClassifierAdapter(text);
  } else if (normalized.classifierAdapter) {
    adapterResult = normalized.classifierAdapter(text);
  }
  if (adapterResult) {
    maybeAppendAdapter(findings, adapterResult);
  }
  return aggregateFindings(findings);
}

function detectPromptInjectionLocal(text: string, normalized: ScanConfig): Finding[] {
  const { canonical: canonicalText, rawOffsets } = canonicalizeText(text);
  const findings = iterFindings(canonicalText, configuredRules(normalized), "prompt_injection", rawOffsets);
  if (normalized.scanDecodedPayloads) {
    findings.push(...decodedFindings(canonicalText, normalized, rawOffsets));
  }
  return findings;
}

function maybeAppendAdapter(findings: Finding[], adapterResult: { label: string; score: number; evidence?: string }): void {
  if (adapterResult.score > 0) {
    findings.push(
      makeFinding("prompt_injection", adapterResult.label, adapterResult.evidence ?? "", -1, -1, adapterResult.score),
    );
  }
}

function aggregateFindings(findings: Finding[]): [number, Finding[]] {
  if (findings.length === 0) return [0, []];
  let missProduct = 1;
  for (const finding of findings) missProduct *= Math.max(0, 1 - finding.score);
  let score = 1 - missProduct;
  if (findings.length >= 2) score = Math.min(1, score + 0.12);
  if (findings.length >= 4) score = Math.min(1, score + 0.08);
  return [round(score), findings];
}

function configuredRules(config: ScanConfig): Rule[] {
  const activePacks = new Set(config.rulePacks);
  let builtinRules = INJECTION_RULES.filter(([, , , pack]) => activePacks.has(pack));
  const enabledRules = config.enabledRules ? new Set(config.enabledRules) : undefined;
  if (enabledRules) {
    const builtinLabels = new Set(builtinRules.map(([label]) => label));
    const overlaps = [...enabledRules].some((label) => builtinLabels.has(label));
    if (overlaps) builtinRules = builtinRules.filter(([label]) => enabledRules.has(label));
  }
  const extraRules: Rule[] = [];
  for (const item of config.extraRules) {
    if ((item.kind ?? "prompt_injection") !== "prompt_injection") continue;
    extraRules.push([item.label, new RegExp(item.pattern, ruleFlags(item)), item.score, "custom"]);
  }
  const disabledRules = new Set(config.disabledRules);
  let rules = [...builtinRules, ...extraRules];
  if (disabledRules.size > 0) rules = rules.filter(([label]) => !disabledRules.has(label));
  return rules;
}

function ruleFlags(rule: { caseSensitive?: boolean; dotall?: boolean }): string {
  const flags = ["g"];
  if (!rule.caseSensitive) flags.push("i");
  if (rule.dotall ?? true) flags.push("s");
  return flags.join("");
}

function decodedFindings(text: string, config: ScanConfig, rawOffsets: number[]): Finding[] {
  const findings: Finding[] = [];
  for (const { decoded, start, end } of candidateDecodings(text, config)) {
    const [score, nestedFindings] = detectPromptInjection(decoded, { ...config, scanDecodedPayloads: false });
    if (score <= 0) continue;
    findings.push(
      makeFinding(
        "prompt_injection",
        "decoded_payload",
        decoded.slice(0, 160),
        rawOffsets[start] ?? start,
        rawOffsets[end] ?? end,
        score,
      ),
    );
  }
  return findings;
}

function candidateDecodings(text: string, config: ScanConfig): Array<{ decoded: string; start: number; end: number }> {
  const seen = new Set<string>();
  const decoded: Array<{ decoded: string; start: number; end: number }> = [];
  const rawLengthCap = config.maxDecodedLength * 6;
  const patterns = [/\b[A-Za-z0-9+/]{24,}={0,2}\b/g, /\b(?:[0-9A-Fa-f]{2}){12,}\b/g, /(?:\\u[0-9A-Fa-f]{4}){4,}/g];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      if (match[0].length > rawLengthCap) continue;
      for (const value of decodeValue(match[0])) {
        const normalized = value.trim();
        if (
          normalized &&
          normalized.length <= config.maxDecodedLength &&
          isPrintableText(normalized) &&
          !seen.has(normalized)
        ) {
          seen.add(normalized);
          decoded.push({ decoded: normalized, start: match.index ?? 0, end: (match.index ?? 0) + match[0].length });
          if (decoded.length >= config.maxDecodeCandidates) return decoded;
        }
      }
    }
  }
  return decoded;
}

function decodeValue(raw: string): string[] {
  const decoded: string[] = [];
  try {
    if (raw.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) throw new Error("invalid base64");
    const value = Buffer.from(raw, "base64").toString("utf8");
    if (value) decoded.push(value);
  } catch {
    // Ignore invalid candidates.
  }
  try {
    const value = Buffer.from(raw, "hex").toString("utf8");
    if (value && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(value)) decoded.push(value);
  } catch {
    // Ignore invalid candidates.
  }
  if (raw.includes("\\u")) {
    try {
      decoded.push(JSON.parse(`"${raw}"`) as string);
    } catch {
      // Ignore invalid candidates.
    }
  }
  return decoded;
}

function isPrintableText(value: string): boolean {
  return [...value].every((char) => {
    const code = char.charCodeAt(0);
    return char === "\t" || char === "\n" || char === "\r" || (code >= 32 && code <= 126);
  });
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

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

const INVISIBLE_CHARS = new Set([
  "\u00ad", "\u061c", "\u180e",
  "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
  "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
  "\u2060", "\u2061", "\u2062", "\u2063", "\u2064",
  "\u2066", "\u2067", "\u2068", "\u2069",
  "\ufeff",
]);
// Unicode "Tags" block (U+E0000\u2013U+E007F). Some LLMs silently follow
// instructions encoded in this block; we strip it during canonicalization.
const TAG_BLOCK_START = 0xe0000;
const TAG_BLOCK_END = 0xe007f;
const HTML_COMMENT_RE = /<!--[\s\S]*?-->/g;
const WHITESPACE_RUN_RE = /[\t\r ]+/g;

function isInvisibleCodePoint(code: number, ch: string): boolean {
  if (INVISIBLE_CHARS.has(ch)) return true;
  return code >= TAG_BLOCK_START && code <= TAG_BLOCK_END;
}

export function canonicalizeText(text: string): { canonical: string; rawOffsets: number[] } {
  // Step 1: drop invisible / BiDi / zero-width / Unicode-tag characters,
  // tracking offsets. Iterate by code point so surrogate-pair characters
  // such as Unicode tags are evaluated as a whole.
  const stage1Chars: string[] = [];
  const stage1Offsets: number[] = [];
  let i = 0;
  while (i < text.length) {
    const code = text.codePointAt(i) as number;
    const unitLen = code > 0xffff ? 2 : 1;
    const ch = String.fromCodePoint(code);
    if (isInvisibleCodePoint(code, ch)) {
      i += unitLen;
      continue;
    }
    for (let k = 0; k < unitLen; k += 1) {
      stage1Chars.push(text[i + k]);
      stage1Offsets.push(i + k);
    }
    i += unitLen;
  }
  stage1Offsets.push(text.length);
  const stage1 = stage1Chars.join("");
  // Step 2: replace HTML comments with a single space.
  const stage2Chars: string[] = [];
  const stage2Offsets: number[] = [];
  let cursor = 0;
  for (const match of stage1.matchAll(HTML_COMMENT_RE)) {
    const start = match.index ?? 0;
    const end = start + match[0].length;
    for (let i = cursor; i < start; i += 1) {
      stage2Chars.push(stage1[i]);
      stage2Offsets.push(stage1Offsets[i]);
    }
    stage2Chars.push(" ");
    stage2Offsets.push(stage1Offsets[start]);
    cursor = end;
  }
  for (let i = cursor; i < stage1.length; i += 1) {
    stage2Chars.push(stage1[i]);
    stage2Offsets.push(stage1Offsets[i]);
  }
  stage2Offsets.push(stage1Offsets[stage1.length]);
  const stage2 = stage2Chars.join("");
  // Step 3: collapse runs of horizontal whitespace.
  const finalChars: string[] = [];
  const finalOffsets: number[] = [];
  cursor = 0;
  for (const match of stage2.matchAll(WHITESPACE_RUN_RE)) {
    const start = match.index ?? 0;
    const end = start + match[0].length;
    for (let i = cursor; i < start; i += 1) {
      finalChars.push(stage2[i]);
      finalOffsets.push(stage2Offsets[i]);
    }
    finalChars.push(" ");
    finalOffsets.push(stage2Offsets[start]);
    cursor = end;
  }
  for (let i = cursor; i < stage2.length; i += 1) {
    finalChars.push(stage2[i]);
    finalOffsets.push(stage2Offsets[i]);
  }
  finalOffsets.push(stage2Offsets[stage2.length]);
  return { canonical: finalChars.join(""), rawOffsets: finalOffsets };
}
