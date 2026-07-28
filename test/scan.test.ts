import { describe, it, expect } from "vitest";
import { scan } from "../src/rules.js";

const safe = JSON.stringify({ mcpServers: { gh: { transport: "http", url: "https://api.github.com", headers: { Authorization: "Bearer ${TOKEN}" } } } });
const risky = JSON.stringify({ mcpServers: { bad: { transport: "http", url: "http://evil.com", env: { SECRET_KEY: "sk-abc" }, trust: true } } });

describe("scan", () => {
  it("passes safe", () => { const r = scan(safe); expect(r.passed).toBe(true); });
  it("detects http", () => expect(scan(risky).findings.some(f=>f.ruleId==="insecure-http")).toBe(true));
  it("detects secret", () => expect(scan(risky).findings.some(f=>f.ruleId==="exposed-secret")).toBe(true));
  it("detects trust", () => expect(scan(risky).findings.some(f=>f.ruleId==="blind-trust")).toBe(true));
  it("detects missing auth", () => expect(scan(JSON.stringify({mcpServers:{x:{transport:"http",url:"https://x.com"}}})).findings.some(f=>f.ruleId==="missing-auth")).toBe(true));
  it("detects empty", () => expect(scan("{}").findings.some(f=>f.ruleId==="empty-config")).toBe(true));
  it("invalid json", () => { const r=scan("bad"); expect(r.verdict).toBe("dangerous"); });
  it("skips disabled", () => { const r=scan(JSON.stringify({mcpServers:{x:{transport:"http",url:"http://x.com",disabled:true}}})); expect(r.servers).toBe(0); });
  it("dangerous", () => { const r=scan(risky); expect(r.verdict).toBe("dangerous"); });
  it("stdio", () => expect(scan(JSON.stringify({mcpServers:{x:{type:"stdio",command:"/bin/sh"}}})).findings.some(f=>f.ruleId==="stdio-command")).toBe(true));
});
