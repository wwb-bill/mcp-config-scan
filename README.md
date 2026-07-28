# mcp-config-scan

Security scanner for MCP client config files. MCP 2026-07-28 release + enterprise readiness.

```bash
npm install -g mcp-config-scan
mcp-config-scan mcp-config.json --fail-on-risk=30
```

7 rules: exposed-secret (critical), insecure-http, missing-auth, blind-trust, stdio-command, no-args, invalid-json.

```ts
import { scan } from "mcp-config-scan";
console.log(scan(configJson).verdict);
```

MIT
