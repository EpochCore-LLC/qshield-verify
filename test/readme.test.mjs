// The public verifier's README (verify-kit/README.md, exported to EpochCore-LLC/qshield-verify) lists the key ids, so
// the keys are named somewhere other than epochcoreqcs.com (site audit 11-06, T5). The list must be exactly the keys
// in KEYS.json: when a key rotates, this test fails until the README's table is updated with it.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const README = readFileSync(new URL("../README.md", import.meta.url), "utf8");
const KEYS = JSON.parse(readFileSync(new URL("../KEYS.json", import.meta.url), "utf8")).keys;

test("the verifier README's key table names exactly the keys in KEYS.json, each with its algorithm", () => {
  const rows = [...README.matchAll(/^\| `([0-9A-F]{16})` \| ([A-Za-z0-9-]+) \|/gm)].map((m) => `${m[2]} ${m[1]}`).sort();
  assert.deepEqual(rows, KEYS.map((k) => `${k.alg} ${k.key_id}`).sort());
});
