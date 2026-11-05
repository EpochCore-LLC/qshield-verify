#!/usr/bin/env node
// qshield-verify: check a Q-Shield proof report or a signed collector release against EpochCore's published keys.
// It only checks. It has no signing command and no keys that could sign: those stay with EpochCore.
//
//   node src/cli.mjs verify REPORT.json [--keys KEYS.json]
//       exit 0 only if both signatures on the report check out against the published keys
//   node src/cli.mjs verify-release RELEASE.json [--file qshield.tar] [--keys KEYS.json]
//       exit 0 only if both signatures on the release check out, and (with --file) the file's SHA-256 is the one signed
//   node src/cli.mjs export-openssl REPORT.json --dir DIR [--keys KEYS.json]
//       the files and commands to check the report with OpenSSL 3.5+ alone, without this code
//
// --keys defaults to the KEYS.json beside this package. Check that file against https://epochcoreqcs.com/qshield-keys
// (the page prints its SHA-256) before you rely on it: the signatures only show that these keys signed; the published
// key ids show the keys are EpochCore's.
//
// In the EpochCore-LLC/q-shield repository this file is prove/src/verify-cli.mjs; the public qshield-verify repository
// carries it as src/cli.mjs, next to unchanged copies of the modules that sign and check reports there.
import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { opensslBundle, verifyInstructions, verifyReport } from "./report.mjs";
import { verifyRelease } from "./release.mjs";

export const DEFAULT_KEYS = join(dirname(fileURLToPath(import.meta.url)), "..", "KEYS.json");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const print = (value) => process.stdout.write(JSON.stringify(value, null, 2) + "\n");

/** SHA-256 of a file, read as a stream (a collector archive is about 150 MB). */
export function fileSha256(path) {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    createReadStream(path).on("error", reject).on("data", (b) => h.update(b)).on("end", () => resolve(h.digest("hex")));
  });
}

/** Runs one command; returns the exit code. */
export async function main(argv) {
  const [command, ...rest] = argv;
  const { values: opt, positionals } = parseArgs({
    args: rest, allowPositionals: true,
    options: { keys: { type: "string" }, dir: { type: "string" }, file: { type: "string" } },
  });
  const keys = () => readJson(opt.keys ?? DEFAULT_KEYS);
  switch (command) {
    case "verify": {
      if (!positionals[0]) throw new Error("verify needs REPORT.json");
      const result = verifyReport(readJson(positionals[0]), keys());
      print(result);
      return result.ok ? 0 : 1;
    }
    case "verify-release": {
      if (!positionals[0]) throw new Error("verify-release needs RELEASE.json");
      const statement = readJson(positionals[0]);
      const result = verifyRelease(statement, keys());
      if (opt.file) {
        if (!existsSync(opt.file)) throw new Error(`${opt.file} not found`);
        const sha256 = await fileSha256(opt.file);
        result.file = { path: opt.file, sha256, matches: sha256 === statement.sha256 };
        if (!result.file.matches) { result.ok = false; result.problems.push("the file's SHA-256 is not the one signed"); }
      }
      print(result);
      return result.ok ? 0 : 1;
    }
    case "export-openssl": {
      if (!positionals[0] || !opt.dir) throw new Error("export-openssl needs REPORT.json and --dir DIR");
      const bundle = opensslBundle(readJson(positionals[0]), keys());
      mkdirSync(opt.dir, { recursive: true });
      for (const [name, bytes] of Object.entries(bundle.files)) writeFileSync(join(opt.dir, name), bytes);
      writeFileSync(join(opt.dir, "VERIFY.txt"), verifyInstructions(bundle).join("\n"));
      print({ dir: opt.dir, digest: bundle.digest, commands: bundle.commands });
      return 0;
    }
    default:
      throw new Error("usage: verify REPORT.json | verify-release RELEASE.json [--file qshield.tar] | export-openssl REPORT.json --dir DIR  (each takes --keys KEYS.json)");
  }
}

const realOr = (p) => { try { return realpathSync(p); } catch { return p; } };
// run as a command, not when imported by the tests
if (process.argv[1] && realOr(fileURLToPath(import.meta.url)) === realOr(process.argv[1])) main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => {
  process.stderr.write(`qshield-verify: ${e.message}\n`);
  process.exitCode = 2;
});
