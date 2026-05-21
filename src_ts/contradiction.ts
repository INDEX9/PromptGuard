import type { Contradiction } from "./types.js";

export const EXPERIMENTAL = true;

const NEGATION_PATTERN =
  "\\b(no|not|never|isn't|is not|aren't|are not|cannot|can't|doesn't|does not|won't|will not|without)\\b";
const NEGATION_TEST_RE = new RegExp(NEGATION_PATTERN, "i");
const NEGATION_STRIP_RE = new RegExp(NEGATION_PATTERN, "gi");
const SPLIT_RE = /[.;!?]\s+|\n+/;
const CLAIM_RE =
  /\b(?<subject>[A-Za-z][A-Za-z0-9 _-]{1,48}?)\s+(?<verb>is|are|was|were|has|have|can|cannot|can't|does|does not|doesn't|supports?|allows?|requires?)\s+(?<predicate>[^.;!?]{2,90})/i;

export function detectContradictions(text: string): [number, Contradiction[]] {
  const claims = new Map<string, Map<boolean, string>>();
  const contradictions: Contradiction[] = [];

  for (const sentence of sentences(text)) {
    const extracted = extractClaim(sentence);
    if (!extracted) continue;
    const [subject, predicate, isNegative] = extracted;
    const key = `${normalize(subject)}\u0000${normalize(predicate)}`;
    if (key === "\u0000") continue;
    const bucket = claims.get(key) ?? new Map<boolean, string>();
    claims.set(key, bucket);
    const opposite = !isNegative;
    if (bucket.has(opposite)) {
      contradictions.push({
        subject: subject.trim(),
        positive: isNegative ? bucket.get(opposite) ?? "" : sentence.trim(),
        negative: isNegative ? sentence.trim() : bucket.get(opposite) ?? "",
        confidence: 0.78,
      });
    }
    bucket.set(isNegative, sentence);
  }

  return [Math.min(1, contradictions.length * 0.6), contradictions];
}

function sentences(text: string): string[] {
  return text
    .split(SPLIT_RE)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
}

function extractClaim(sentence: string): [string, string, boolean] | undefined {
  const match = sentence.match(CLAIM_RE);
  if (!match?.groups) return undefined;
  const subject = match.groups.subject;
  const verb = match.groups.verb;
  const rawPredicate = match.groups.predicate;
  const isNegative = NEGATION_TEST_RE.test(`${verb} ${rawPredicate}`);
  let predicate = stripNegation(rawPredicate);
  if (["support", "supports", "allow", "allows", "require", "requires"].includes(verb.toLowerCase())) {
    predicate = `${lemma(verb)} ${predicate}`;
  }
  return [subject, predicate, isNegative];
}

function stripNegation(value: string): string {
  return value
    .replace(NEGATION_STRIP_RE, " ")
    .replace(/\bany\b/gi, " ")
    .replace(/\s+/g, " ")
    .replace(/^[,\s]+|[,\s]+$/g, "");
}

function normalize(value: string): string {
  return value
    .toLowerCase()
    .replace(/\b(the|a|an|any)\b/g, " ")
    .replace(/\s+/g, " ")
    .replace(/^[,\s]+|[,\s]+$/g, "");
}

function lemma(verb: string): string {
  const value = verb.toLowerCase();
  return value.endsWith("s") ? value.slice(0, -1) : value;
}
