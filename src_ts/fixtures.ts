import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface BenchmarkCase {
  id: string;
  family: string;
  text: string;
  promptInjection?: boolean;
  pii?: boolean;
  contradictory?: boolean;
  rulePacks?: string[];
  piiLocales?: string[];
  scanDecodedPayloads?: boolean;
}

interface RawBenchmarkCase {
  id: string;
  family: string;
  text: string;
  prompt_injection?: boolean;
  pii?: boolean;
  contradictory?: boolean;
  config?: { rule_packs?: string[]; pii_locales?: string[]; scan_decoded_payloads?: boolean };
}

export function loadBenchmarkCases(path = defaultCasesPath()): BenchmarkCase[] {
  const rawCases = JSON.parse(readFileSync(path, "utf8")) as RawBenchmarkCase[];
  return rawCases.map((item) => ({
    id: item.id,
    family: item.family,
    text: item.text,
    promptInjection: item.prompt_injection ?? false,
    pii: item.pii ?? false,
    contradictory: item.contradictory ?? false,
    rulePacks: item.config?.rule_packs ?? ["core"],
    piiLocales: item.config?.pii_locales ?? ["us"],
    scanDecodedPayloads: item.config?.scan_decoded_payloads ?? false,
  }));
}

export const BENCHMARK_CASES: BenchmarkCase[] = loadBenchmarkCases();

function defaultCasesPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "..", "benchmarks", "cases.json");
}
