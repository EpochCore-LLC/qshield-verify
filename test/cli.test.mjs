// The verify-only command-line tool (src/verify-cli.mjs; src/cli.mjs in the public qshield-verify repository), run as a
// command, the way an auditor runs it. Reports are signed here with throwaway keys made for the test; the one real
// signature is EpochCore's signed collector release v0.2.0, checked against the published KEYS.json.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { buildReport, generateKeyFile, publicKeys, signReport } from "../src/report.mjs";

const CLI = fileURLToPath(new URL("../src/cli.mjs", import.meta.url));
const RELEASE = fileURLToPath(new URL("./fixtures/release-v0.2.0.json", import.meta.url));
const run = (...args) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { code: r.status, out: r.stdout ? JSON.parse(r.stdout) : null, err: r.stderr };
};

function signedReport() {
  const dir = mkdtempSync(join(tmpdir(), "qshield-verify-"));
  const keyFile = generateKeyFile();
  const report = signReport(buildReport({
    engagementId: "example-2026-11-04-0001", profile: "mid_market", findings: [], audit: { verdict: "pass" },
    generatedAt: "2026-11-04T12:00:00Z",
  }), keyFile);
  const files = { dir, report: join(dir, "report.json"), keys: join(dir, "keys.json") };
  writeFileSync(files.report, JSON.stringify(report));
  writeFileSync(files.keys, JSON.stringify(publicKeys(keyFile)));
  return { ...files, data: report };
}

test("verify: a signed report checks out against its published keys (exit 0); a changed one doesn't (exit 1)", () => {
  const r = signedReport();
  const ok = run("verify", r.report, "--keys", r.keys);
  assert.equal(ok.code, 0);
  assert.equal(ok.out.ok, true);
  assert.deepEqual(ok.out.results.map((x) => [x.alg, x.ok]), [["Ed25519", true], ["ML-DSA-87", true]]);

  writeFileSync(r.report, JSON.stringify({ ...r.data, audit: { verdict: "fail" } }));
  const bad = run("verify", r.report, "--keys", r.keys);
  assert.equal(bad.code, 1);
  assert.deepEqual(bad.out.results.map((x) => x.reason), ["signature does not match this report", "signature does not match this report"]);
});

test("verify: the default keys are the published KEYS.json, and a report signed with other keys fails against them", () => {
  const r = signedReport();
  const res = run("verify", r.report);
  assert.equal(res.code, 1);
  assert.ok(res.out.results.every((x) => x.reason === "signed by a key that is not published"));
});

test("verify-release: EpochCore's signed v0.2.0 release checks out against the published keys", () => {
  const res = run("verify-release", RELEASE);
  assert.equal(res.code, 0);
  assert.equal(res.out.digest, "d72e2a3f18a25ad219e41dcc7fa661ecc3a485373fa90c172d21570b0e52cec6");
  assert.deepEqual(res.out.results.map((x) => [x.alg, x.key_id, x.ok]), [["Ed25519", "D72A8F9C5DE25146", true], ["ML-DSA-87", "11055C6262215FAB", true]]);
  // A changed field breaks both signatures.
  const dir = mkdtempSync(join(tmpdir(), "qshield-verify-"));
  const changed = join(dir, "release.json");
  writeFileSync(changed, JSON.stringify({ ...JSON.parse(readFileSync(RELEASE, "utf8")), version: "0.2.1" }));
  const bad = run("verify-release", changed);
  assert.equal(bad.code, 1);
  assert.ok(bad.out.results.every((x) => !x.ok));
});

test("verify-release --file: a file whose SHA-256 isn't the signed one fails, with the hash it computed", () => {
  const dir = mkdtempSync(join(tmpdir(), "qshield-verify-"));
  const tar = join(dir, "qshield.tar");
  writeFileSync(tar, "not the released archive");
  const res = run("verify-release", RELEASE, "--file", tar);
  assert.equal(res.code, 1);
  assert.deepEqual(res.out.file, { path: tar, sha256: createHash("sha256").update("not the released archive").digest("hex"), matches: false });
  assert.ok(res.out.problems.includes("the file's SHA-256 is not the one signed"));
  assert.ok(res.out.results.every((x) => x.ok));          // the signatures themselves are still EpochCore's
});

test("export-openssl writes message.bin, the keys, the signatures and VERIFY.txt", () => {
  const r = signedReport();
  const out = join(r.dir, "openssl");
  const res = run("export-openssl", r.report, "--dir", out, "--keys", r.keys);
  assert.equal(res.code, 0);
  for (const f of ["message.bin", "ed25519.pub.der", "ed25519.sig", "ml-dsa-87.pub.der", "ml-dsa-87.sig", "VERIFY.txt"]) {
    assert.ok(existsSync(join(out, f)), f);
  }
  assert.equal(readFileSync(join(out, "message.bin"), "utf8"), `qshield-proof-report-v1:${res.out.digest}`);
});

test("it has no way to sign: unknown commands (sign, keygen, build) are refused", () => {
  for (const cmd of ["sign", "keygen", "build", "render"]) {
    const res = run(cmd, "x");
    assert.equal(res.code, 2, cmd);
    assert.match(res.err, /^qshield-verify: usage: verify REPORT\.json/);
  }
});
