import type { Finding, ScanReport, Severity } from "./types.js";

const W: Record<Severity, number> = { critical: 35, high: 20, medium: 8, low: 2 };

interface MC { mcpServers?: Record<string, SC>; servers?: Record<string, SC>; }
interface SC { type?: string; url?: string; command?: string; args?: string[]; env?: Record<string, string>; headers?: Record<string, string>; transport?: string; disabled?: boolean; trust?: boolean; }

export function scan(raw: string): ScanReport {
  let c: MC;
  try { c = JSON.parse(raw); } catch { return { servers: 0, findings: [{ ruleId: "invalid-json", severity: "critical", path: ".", message: "Invalid JSON" }], riskScore: 35, verdict: "dangerous", passed: false }; }
  const svrs = c.mcpServers ?? c.servers ?? {};
  const entries = Object.entries(svrs).filter(([,s]) => !s.disabled);
  const fs: Finding[] = [];

  for (const [n, s] of entries) {
    if (s.transport === "http" && s.url?.startsWith("http://")) fs.push({ ruleId: "insecure-http", severity: "high", path: `servers.${n}`, message: "HTTP without TLS" });
    if (s.type === "stdio" && s.command) fs.push({ ruleId: "stdio-command", severity: "medium", path: `servers.${n}`, message: "Stdio runs local commands" });
    if (s.transport === "http" && !s.headers?.["Authorization"] && !s.env?.["API_KEY"]) fs.push({ ruleId: "missing-auth", severity: "high", path: `servers.${n}`, message: "No auth" });
    const env = s.env ?? {};
    for (const [k, v] of Object.entries(env)) {
      if (/key|token|secret|password/i.test(k) && v && v.length > 5 && !v.startsWith("${")) fs.push({ ruleId: "exposed-secret", severity: "critical", path: `servers.${n}.env.${k}`, message: `Hardcoded ${k}` });
    }
    if (s.trust === true) fs.push({ ruleId: "blind-trust", severity: "high", path: `servers.${n}`, message: "Marked trusted" });
    if ((s.command || s.type === "stdio") && (!s.args || s.args.length === 0)) fs.push({ ruleId: "no-args", severity: "low", path: `servers.${n}`, message: "No command args" });
  }

  if (entries.length === 0) fs.push({ ruleId: "empty-config", severity: "info" as Severity, path: ".", message: "No active servers" });
  let risk = 0; for (const f of fs) risk += W[f.severity] ?? 0;
  risk = Math.min(100, risk);
  return { servers: entries.length, findings: fs, riskScore: risk, verdict: risk >= 50 ? "dangerous" : risk >= 20 ? "review" : "safe", passed: risk < 20 };
}
