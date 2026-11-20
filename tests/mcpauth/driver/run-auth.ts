// Runs the conformance framework's server auth scenarios against an MCP
// server and writes each scenario's checks to <out>/<scenario>/checks.json
// (issue 495). cmd/exercise runs it with `npx tsx` from the framework
// checkout.
//
// It calls each scenario's run(ctx) directly, as the framework's own
// auth.test.ts does, rather than through the framework CLI. The auth
// scenarios read only ctx.serverUrl.
//
// Usage: tsx run-auth.ts <checkout> <mcp-url> <out-dir> [scenario...]
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

type Check = { id: string; status: string };
type Scenario = { name: string; run(ctx: { serverUrl: string }): Promise<Check[]> };

async function main() {
  const [checkout, url, out, ...only] = process.argv.slice(2);
  if (!checkout || !url || !out) {
    console.error('usage: run-auth.ts <checkout> <mcp-url> <out-dir> [scenario...]');
    process.exit(2);
  }
  const mod = await import(
    pathToFileURL(resolve(checkout, 'src/scenarios/server/auth/auth.ts')).href
  );
  const scenarios: Scenario[] = Object.values(mod)
    .filter((v): v is new () => Scenario => typeof v === 'function' && /^Auth\w+Scenario$/.test((v as Function).name))
    .map((C) => new C())
    .filter((s) => only.length === 0 || only.includes(s.name));
  for (const s of scenarios) {
    const dir = join(out, s.name);
    mkdirSync(dir, { recursive: true });
    let checks: Check[];
    try {
      checks = await s.run({ serverUrl: url });
    } catch (err) {
      checks = [{ id: s.name, status: 'FAILURE', errorMessage: String(err) } as Check];
    }
    writeFileSync(join(dir, 'checks.json'), JSON.stringify(checks, null, 2));
    console.log(`${s.name}: ${checks.length} checks`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
