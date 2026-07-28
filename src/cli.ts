#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { scan } from "./rules.js";

function help(): void { console.log(`mcp-config-scan\nUsage: mcp-config-scan <config.json> [--json] [--fail-on-risk=N]`); }

function main(argv: string[]): void {
  const a = argv.slice(2);
  if (!a[0]||a[0]==="--help") { help(); return; }
  try {
    const r = scan(readFileSync(a[0], "utf-8"));
    if (a.includes("--json")) { console.log(JSON.stringify(r, null, 2)); }
    else { console.log(`Servers: ${r.servers} | Risk: ${r.riskScore}/100 (${r.verdict})\n`); for (const f of r.findings) console.log(`  [${f.severity}] ${f.path}: ${f.message}`); console.log(`\nResult: ${r.passed ? "SAFE" : "NEEDS REVIEW"}`); }
    const thr = parseInt(a.find(x=>x.startsWith("--fail-on-risk="))?.split("=")[1]??"0");
    if (thr > 0 && r.riskScore >= thr) process.exit(1);
  } catch (e) { console.error("Error:", (e as Error).message); process.exit(2); }
}
main(process.argv);
