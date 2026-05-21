import { scanText } from "./index.js";
import { BENCHMARK_CASES, loadBenchmarkCases, type BenchmarkCase } from "./fixtures.js";

export { loadBenchmarkCases, BENCHMARK_CASES, type BenchmarkCase } from "./fixtures.js";

interface Count {
  correct: number;
  total: number;
}

interface Metrics {
  tp: number;
  tn: number;
  fp: number;
  fn: number;
}

export function runBenchmark(cases: BenchmarkCase[] = BENCHMARK_CASES): Record<string, unknown> {
  const tasks: Record<string, Metrics> = {
    prompt_injection: emptyMetrics(),
    pii: emptyMetrics(),
    contradictory: emptyMetrics(),
  };
  const families = new Map<string, Count>();
  const caseResults = [];
  const latenciesMs: number[] = [];

  for (const item of cases) {
    const started = performance.now();
    const report = scanText(item.text, {
      config: {
        rulePacks: item.rulePacks ?? ["core"],
        piiLocales: item.piiLocales ?? ["us"],
        scanDecodedPayloads: item.scanDecodedPayloads ?? false,
      },
    });
    latenciesMs.push(performance.now() - started);
    const expected = {
      prompt_injection: item.promptInjection ?? false,
      pii: item.pii ?? false,
      contradictory: item.contradictory ?? false,
    };
    const actual = {
      prompt_injection: report.isPromptInjection,
      pii: report.hasPii,
      contradictory: report.isContradictory,
    };

    record(tasks.prompt_injection, actual.prompt_injection, expected.prompt_injection);
    record(tasks.pii, actual.pii, expected.pii);
    record(tasks.contradictory, actual.contradictory, expected.contradictory);

    if (expected.prompt_injection) {
      const count = families.get(item.family) ?? { correct: 0, total: 0 };
      count.correct += Number(actual.prompt_injection);
      count.total += 1;
      families.set(item.family, count);
    }

    caseResults.push({
      id: item.id,
      family: item.family,
      expected,
      actual,
      scores: {
        prompt_injection: report.promptInjectionScore,
        pii: report.piiScore,
        contradictory: report.contradictionScore,
      },
      top_prompt_injection_rules: report.promptInjectionFindings.slice(0, 3).map((finding) => finding.label),
    });
  }

  const familyStats = Object.fromEntries(
    [...families.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([family, count]) => [family, { detected: count.correct, total: count.total, rate: rate(count) }]),
  );

  return {
    headline: headline(families),
    families: familyStats,
    tasks: Object.fromEntries(
      Object.entries(tasks).map(([name, count]) => [name, summarizeMetrics(count)]),
    ),
    latency: summarizeLatency(latenciesMs),
    cases: caseResults,
  };
}

function summarizeLatency(latenciesMs: number[]): Record<string, number> {
  if (latenciesMs.length === 0) return { scans: 0, mean_ms: 0, p95_ms: 0, max_ms: 0 };
  const ordered = [...latenciesMs].sort((a, b) => a - b);
  const p95Index = Math.min(ordered.length - 1, Math.round(0.95 * (ordered.length - 1)));
  const mean = ordered.reduce((sum, value) => sum + value, 0) / ordered.length;
  const round4 = (value: number) => Math.round(value * 10000) / 10000;
  return {
    scans: ordered.length,
    mean_ms: round4(mean),
    p95_ms: round4(ordered[p95Index]),
    max_ms: round4(ordered[ordered.length - 1]),
  };
}

export function formatBenchmark(result: Record<string, unknown>): string {
  const lines = [String(result.headline), "", "Attack-family detection:"];
  const families = result.families as Record<string, { detected: number; total: number; rate: number }>;
  for (const [family, stats] of Object.entries(families)) {
    lines.push(`- ${family}: ${(stats.rate * 100).toFixed(1)}% (${stats.detected}/${stats.total})`);
  }
  lines.push("", "Task accuracy:");
  const tasks = result.tasks as Record<string, { correct: number; total: number; accuracy: number }>;
  for (const [task, stats] of Object.entries(tasks)) {
    const label = task === "contradictory" ? "contradictory (experimental)" : task;
    lines.push(`- ${label}: ${(stats.accuracy * 100).toFixed(1)}% (${stats.correct}/${stats.total})`);
  }
  const latency = result.latency as { scans: number; mean_ms: number; p95_ms: number; max_ms: number };
  lines.push(
    "",
    "Scan latency:",
    `- ${latency.scans} scans: mean ${latency.mean_ms.toFixed(3)} ms, ` +
      `p95 ${latency.p95_ms.toFixed(3)} ms, max ${latency.max_ms.toFixed(3)} ms`,
  );
  lines.push("", "JSON:", JSON.stringify(result, null, 2));
  return lines.join("\n");
}

function emptyMetrics(): Metrics {
  return { tp: 0, tn: 0, fp: 0, fn: 0 };
}

function record(count: Metrics, actual: boolean, expected: boolean): void {
  if (actual && expected) count.tp += 1;
  else if (actual && !expected) count.fp += 1;
  else if (!actual && expected) count.fn += 1;
  else count.tn += 1;
}

function rate(count: Count): number {
  return count.total === 0 ? 0 : count.correct / count.total;
}

function divide(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

function summarizeMetrics(count: Metrics): Record<string, unknown> {
  const correct = count.tp + count.tn;
  const total = count.tp + count.tn + count.fp + count.fn;
  const precision = divide(count.tp, count.tp + count.fp);
  const recall = divide(count.tp, count.tp + count.fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return {
    correct,
    total,
    accuracy: divide(correct, total),
    precision,
    recall,
    f1,
    confusion: { ...count },
  };
}

function headline(families: Map<string, Count>): string {
  const minja = families.get("MINJA") ?? { correct: 0, total: 0 };
  return `Included MINJA fixture detection: ${minja.correct}/${minja.total} synthetic cases`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const casesArgIndex = process.argv.indexOf("--cases");
  const jsonOnly = process.argv.includes("--json");
  const cases =
    casesArgIndex >= 0 && process.argv[casesArgIndex + 1]
      ? loadBenchmarkCases(process.argv[casesArgIndex + 1])
      : BENCHMARK_CASES;
  const result = runBenchmark(cases);
  console.log(jsonOnly ? JSON.stringify(result, null, 2) : formatBenchmark(result));
}
