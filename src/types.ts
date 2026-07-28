export type Severity = "critical" | "high" | "medium" | "low";
export interface Finding { ruleId: string; severity: Severity; path: string; message: string; }
export interface ScanReport { servers: number; findings: Finding[]; riskScore: number; verdict: "safe" | "review" | "dangerous"; passed: boolean; }
