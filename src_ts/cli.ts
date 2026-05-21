#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { reportToDict, scanConfigFromObject, scanText } from "./index.js";
import type { DetectionReport, ScanConfigInput } from "./index.js";

type FailOn = "injection" | "pii" | "contradiction" | "any" | "none";

interface CliOptions {
  paths: string[];
  configPath?: string;
  json: boolean;
  noEvidence: boolean;
  failOn: FailOn;
}

const FAIL_ON_VALUES: FailOn[] = ["injection", "pii", "contradiction", "any", "none"];

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = { paths: [], json: false, noEvidence: false, failOn: "any" };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--no-evidence") {
      options.noEvidence = true;
    } else if (arg === "--config") {
      options.configPath = argv[(index += 1)];
    } else if (arg === "--fail-on") {
      const value = argv[(index += 1)] as FailOn;
      if (!FAIL_ON_VALUES.includes(value)) throw new Error(`Invalid --fail-on value: ${value}`);
      options.failOn = value;
    } else if (arg === "-h" || arg === "--help") {
      printHelp();
      process.exit(0);
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      options.paths.push(arg);
    }
  }
  return options;
}

function printHelp(): void {
  process.stdout.write(
    "Usage: prompt-guard [--config FILE] [--json] [--no-evidence] [--fail-on MODE] [files...]\n" +
      "Scan text for prompt injection, PII, and contradictions. Reads stdin when no files are given.\n",
  );
}

function readInputs(paths: string[]): Array<[string, string]> {
  if (paths.length === 0) return [["<stdin>", readFileSync(0, "utf8")]];
  return paths.map((path) => [path, readFileSync(path, "utf8")] as [string, string]);
}

function shouldFail(report: DetectionReport, failOn: FailOn): boolean {
  if (failOn === "none") return false;
  if (failOn === "injection") return report.isPromptInjection;
  if (failOn === "pii") return report.hasPii;
  if (failOn === "contradiction") return report.isContradictory;
  return report.isPromptInjection || report.hasPii || report.isContradictory;
}

function printHuman(name: string, report: DetectionReport): void {
  const flags: string[] = [];
  if (report.isPromptInjection) flags.push(`prompt_injection=${report.promptInjectionScore}`);
  if (report.hasPii) flags.push(`pii=${report.piiScore}`);
  if (report.isContradictory) flags.push(`contradiction=${report.contradictionScore}`);
  process.stdout.write(`${name}: ${flags.length > 0 ? flags.join("; ") : "clean"}\n`);
  for (const finding of [...report.promptInjectionFindings, ...report.piiFindings]) {
    process.stdout.write(`  - [${finding.severity}] ${finding.label} (${finding.category}) score=${finding.score}\n`);
  }
}

export function main(argv: string[] = process.argv.slice(2)): number {
  const options = parseArgs(argv);
  const config: ScanConfigInput = options.configPath
    ? scanConfigFromObject(JSON.parse(readFileSync(options.configPath, "utf8")))
    : {};
  const includeEvidence = !options.noEvidence;

  const reports: Array<[string, DetectionReport]> = [];
  let flagged = false;
  for (const [name, text] of readInputs(options.paths)) {
    const report = scanText(text, { includeEvidence, config });
    reports.push([name, report]);
    if (shouldFail(report, options.failOn)) flagged = true;
  }

  if (options.json) {
    const payload = reports.map(([name, report]) => ({ source: name, ...reportToDict(report) }));
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  } else {
    for (const [name, report] of reports) printHuman(name, report);
  }

  return flagged ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main());
}
