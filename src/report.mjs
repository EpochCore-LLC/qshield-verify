// Build, sign and verify a Q-Shield proof report (GUIDE.md §3, ProofReport).
//
// What is signed, exactly, so anyone can check it with any library:
//   body    = the report without its "signatures" field
//   digest  = lowercase hex SHA-256 of the RFC 8785 canonical JSON of body (UTF-8)
//   message = the ASCII bytes "qshield-proof-report-v1:" + digest
// Ed25519 (RFC 8032) and one ML-DSA key (FIPS 204, empty context) each sign `message`. New keys are ML-DSA-87
// (CNSA 2.0 level, the bar our own audit holds customers to); reports signed with the older ML-DSA-65 key still verify.
// Verification uses the published keys (prove/KEYS.json), never keys inside the report.
//
// Signing randomness: Ed25519 is deterministic. ML-DSA signs in its hedged mode with 32 random bytes:
//   rnd = SHA-256("qshield-mldsa-hedge-v1" || 32 fresh CSPRNG bytes || 32 IBM Heron bytes)   when Heron bytes are given
//   rnd = 32 fresh CSPRNG bytes                                                             otherwise
// The CSPRNG part alone is full strength, so the Heron part can only add. The report says which, in
// `signing_entropy` (inside the signed body, so it cannot be changed after signing). Verification does not take
// rnd: any rnd verifies, so `signing_entropy` records where the randomness came from; it cannot be checked from
// the signature.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

import { canonicalize } from "./jcs.mjs";

export const SCHEMA = "qshield/proof-report/v1";
export const KEYS_SCHEMA = "qshield/keys/v1";
export const MESSAGE_PREFIX = "qshield-proof-report-v1:";
/** What a NEW key file holds. */
export const ALGS = ["Ed25519", "ML-DSA-87"];
/** Post-quantum signature levels a report may carry (exactly one of them). */
export const PQ_ALGS = ["ML-DSA-87", "ML-DSA-65"];

const SCHEMES = {
  "Ed25519": {
    publicFromSeed: (seed) => ed25519.getPublicKey(seed),
    sign: (message, seed) => ed25519.sign(message, seed),
    verify: (sig, message, pub) => ed25519.verify(sig, message, pub),
  },
  "ML-DSA-65": {
    publicFromSeed: (seed) => ml_dsa65.keygen(seed).publicKey,
    sign: (message, seed, rnd) => ml_dsa65.sign(message, ml_dsa65.keygen(seed).secretKey, { extraEntropy: rnd }),
    verify: (sig, message, pub) => ml_dsa65.verify(sig, message, pub),
  },
  "ML-DSA-87": {
    publicFromSeed: (seed) => ml_dsa87.keygen(seed).publicKey,
    sign: (message, seed, rnd) => ml_dsa87.sign(message, ml_dsa87.keygen(seed).secretKey, { extraEntropy: rnd }),
    verify: (sig, message, pub) => ml_dsa87.verify(sig, message, pub),
  },
};

/** The algorithms a key file can sign with: Ed25519 + exactly one ML-DSA level. */
function keyFileAlgs(keyFile) {
  const algs = Object.keys(keyFile?.keys ?? {});
  const pq = algs.filter((a) => PQ_ALGS.includes(a));
  if (!algs.includes("Ed25519") || pq.length !== 1) throw new Error("a key file needs Ed25519 and exactly one of " + PQ_ALGS.join(", "));
  return ["Ed25519", pq[0]];
}

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const unb64 = (text) => new Uint8Array(Buffer.from(text, "base64"));

export function keyId(publicKey) {
  return bytesToHex(sha256(publicKey)).slice(0, 16).toUpperCase();
}

/** The digest and the exact bytes both keys sign. */
export function signedMessage(report) {
  const { signatures: _ignored, ...body } = report;
  const digest = bytesToHex(sha256(new TextEncoder().encode(canonicalize(body))));
  return { digest, message: new TextEncoder().encode(MESSAGE_PREFIX + digest) };
}

/** A new signing key file: one 32-byte seed per algorithm. Secret: never commit it. */
export function generateKeyFile(algs = ALGS) {
  const keys = {};
  for (const alg of algs) {
    const seed = randomBytes(32);
    const pub = SCHEMES[alg].publicFromSeed(seed);
    keys[alg] = { seed_b64: b64(seed), public_b64: b64(pub), key_id: keyId(pub) };
  }
  return { schema: "qshield/signing-key/v1", created_at: new Date().toISOString(), keys };
}

/** Throws unless every key's public_b64 and key_id match what its seed derives (a mismatched file signs reports
 *  that then fail verification). */
export function checkKeyFile(keyFile) {
  for (const alg of keyFileAlgs(keyFile)) {
    const k = keyFile.keys[alg];
    if (!k?.seed_b64) throw new Error(`key file has no ${alg} seed`);
    const pub = SCHEMES[alg].publicFromSeed(unb64(k.seed_b64));
    if (k.public_b64 !== b64(pub) || k.key_id !== keyId(pub)) {
      throw new Error(`key file's ${alg} public key or key id does not match its seed`);
    }
  }
}

/** The public half of a key file, in the published KEYS.json shape. */
export function publicKeys(keyFile) {
  return {
    schema: KEYS_SCHEMA,
    keys: keyFileAlgs(keyFile).map((alg) => ({ alg, key_id: keyFile.keys[alg].key_id, public_b64: keyFile.keys[alg].public_b64 })),
  };
}

/**
 * A report body. `provenance` is given only for results a customer collected on their own systems and uploaded (GUIDE.md,
 * ProofReport): a report of EpochCore's own scan has no such field at all, so every report built and signed before the
 * field existed canonicalizes, and verifies, exactly as it did.
 */
export function buildReport({ engagementId, profile, findings, audit, triage = null, migrations = [], generatedAt, provenance = null }) {
  if (!engagementId) throw new Error("engagementId is required");
  if (!Array.isArray(findings)) throw new Error("findings must be a list of Findings");
  if (!audit || typeof audit !== "object") throw new Error("audit is required (qshield audit findings.json)");
  const bad = provenance === null ? null : provenanceProblem(provenance);
  if (bad) throw new Error(`provenance: ${bad}`);
  return {
    schema: SCHEMA,
    engagement_id: engagementId,
    generated_at: generatedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    profile,
    findings,
    audit,
    triage,
    migrations,
    ...(provenance === null ? {} : { provenance }),
  };
}

/** Who collected a report's findings when EpochCore's scan server did not. The only value is "customer" (GUIDE.md). */
export const COLLECTED_BY = ["customer"];
export const PROVENANCE_FIELDS = ["collected_by", "org", "collector_versions", "source_commit", "file_sha256", "uploaded_by", "uploaded_at"];

/** Why a provenance record can't go in a report, or null. Every field is required; only source_commit may be null. */
export function provenanceProblem(p) {
  if (p === null || typeof p !== "object" || Array.isArray(p)) return "must be a record";
  if (Object.keys(p).sort().join() !== [...PROVENANCE_FIELDS].sort().join()) return `needs exactly ${PROVENANCE_FIELDS.join(", ")}`;
  if (!COLLECTED_BY.includes(p.collected_by)) return `collected_by must be one of ${COLLECTED_BY.join(", ")}`;
  for (const k of ["org", "uploaded_by", "uploaded_at"]) if (typeof p[k] !== "string" || !p[k].trim()) return `${k} must be a non-empty string`;
  if (typeof p.file_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(p.file_sha256)) return "file_sha256 must be 64 lowercase hex characters";
  if (!Array.isArray(p.collector_versions) || !p.collector_versions.every((v) => typeof v === "string" && v)) return "collector_versions must be a list of strings";
  if (p.source_commit !== null && (typeof p.source_commit !== "string" || !p.source_commit)) return "source_commit must be a non-empty string or null";
  return null;
}

export const HEDGE_LABEL = "qshield-mldsa-hedge-v1";

/** ML-DSA's 32 signing random bytes: fresh CSPRNG bytes, mixed with 32 Heron bytes when given. */
export function mlDsaRandomness(csprng, heron = null) {
  if (!(csprng instanceof Uint8Array) || csprng.length !== 32) throw new Error("csprng must be 32 bytes");
  if (!heron) return csprng;
  if (!(heron instanceof Uint8Array) || heron.length !== 32) throw new Error("Heron bytes must be 32 bytes");
  const label = new TextEncoder().encode(HEDGE_LABEL);
  const ikm = new Uint8Array(label.length + 64);
  ikm.set(label, 0); ikm.set(csprng, label.length); ikm.set(heron, label.length + 32);
  return sha256(ikm);
}

/** Sign both ways. `qrng` (optional): { bytes: 32 Heron bytes, job_id, backend } from the Dataplane's draw. */
export function signReport(report, keyFile, { qrng = null, csprng = randomBytes(32) } = {}) {
  if (qrng && !(qrng.bytes instanceof Uint8Array && qrng.bytes.length === 32)) {
    throw new Error("Heron provenance needs the 32 Heron bytes");
  }
  if (qrng && !(typeof qrng.job_id === "string" && qrng.job_id && typeof qrng.backend === "string" && qrng.backend)) {
    throw new Error("Heron bytes need their IBM job id and backend");
  }
  const algs = keyFileAlgs(keyFile);
  const { signatures: _old, signing_entropy: _oldEntropy, ...rest } = report;
  const body = {
    ...rest,
    signing_entropy: qrng
      ? { applies_to: algs[1], sources: ["csprng", "ibm_heron"], qrng_job_id: qrng.job_id, qrng_backend: qrng.backend }
      : { applies_to: algs[1], sources: ["csprng"] },
  };
  const { message } = signedMessage(body);
  return { ...body, signatures: signMessage(message, keyFile, mlDsaRandomness(csprng, qrng ? qrng.bytes : null)) };
}

/** Both keys of a key file sign `message` (bytes); ML-DSA in its hedged mode with `rnd`. Shared by the report and by
 *  release.mjs, whose statement has its own prefix: the message passed in must already carry its type's prefix. */
export function signMessage(message, keyFile, rnd = randomBytes(32)) {
  return keyFileAlgs(keyFile).map((alg) => {
    const seed = unb64(keyFile.keys[alg].seed_b64);
    return { alg, key_id: keyFile.keys[alg].key_id, sig_b64: b64(SCHEMES[alg].sign(message, seed, rnd)) };
  });
}

/** Problems with the signature list itself: exactly one Ed25519 and exactly one ML-DSA (65 or 87), nothing else. */
function signatureListProblems(signatures) {
  if (!Array.isArray(signatures)) return ["signatures is not a list"];
  const problems = [];
  const ed = signatures.filter((s) => s?.alg === "Ed25519").length, pq = signatures.filter((s) => PQ_ALGS.includes(s?.alg)).length;
  if (ed > 1) problems.push(`${ed} Ed25519 signatures; exactly one allowed`);
  if (pq > 1) problems.push(`${pq} ML-DSA signatures; exactly one allowed`);
  const unexpected = signatures.filter((s) => s?.alg !== "Ed25519" && !PQ_ALGS.includes(s?.alg)).map((s) => String(s?.alg));
  if (unexpected.length) problems.push(`unexpected signatures: ${unexpected.join(", ")}`);
  return problems;
}

/** The two algorithms this report must carry: Ed25519 + the ML-DSA level it was signed with (null if it has none). */
function requiredAlgs(signatures) {
  const pq = (Array.isArray(signatures) ? signatures : []).find((s) => PQ_ALGS.includes(s?.alg));
  return ["Ed25519", pq ? pq.alg : null];
}
const MISSING_PQ = "ML-DSA signature missing (needs " + PQ_ALGS.join(" or ") + ")";

/** Check every required signature against the published keys. ok only if all pass. */
export function verifyReport(report, published) {
  const { digest, message } = signedMessage(report);
  const { problems, results } = checkSignatures(report.signatures, message, published);
  const schemaOk = report.schema === SCHEMA && published.schema === KEYS_SCHEMA;
  return {
    ok: schemaOk && problems.length === 0 && results.every((r) => r.ok),
    schema_ok: schemaOk,
    problems,
    digest,
    results,
  };
}

/** A signature list over `message` against the published keys, by the report's rules: exactly one Ed25519 and one
 *  ML-DSA, each by a published key. Shared with release.mjs; `what` names the signed thing in a failure reason. */
export function checkSignatures(signatures, message, published, what = "this report") {
  const problems = signatureListProblems(signatures);
  const results = requiredAlgs(signatures).map((alg) => {
    if (alg === null) return { alg: null, family: "ML-DSA", ok: false, reason: MISSING_PQ };
    const sig = (Array.isArray(signatures) ? signatures : []).find((s) => s?.alg === alg);
    if (!sig) return { alg, ok: false, reason: "signature missing" };
    const key = (published.keys ?? []).find((k) => k.alg === alg && k.key_id === sig.key_id);
    if (!key) return { alg, key_id: sig.key_id, ok: false, reason: "signed by a key that is not published" };
    let ok = false;
    try {
      ok = SCHEMES[alg].verify(unb64(sig.sig_b64), message, unb64(key.public_b64));
    } catch {
      ok = false;
    }
    return { alg, key_id: sig.key_id, ok, reason: ok ? "valid" : `signature does not match ${what}` };
  });
  return { problems, results };
}

// DER SubjectPublicKeyInfo prefixes, so OpenSSL (3.5+) can verify without this code.
const SPKI_PREFIX = {
  "Ed25519": "302a300506032b6570032100",
  "ML-DSA-65": "308207b2300b0609608648016503040312038207a100",
  "ML-DSA-87": "30820a32300b060960864801650304031303820a2100",
};

/** Files an auditor needs to verify with the openssl command line. */
export function opensslBundle(report, published) {
  const { digest, message } = signedMessage(report);
  const { files, commands } = opensslKeyFiles(report.signatures, published);
  return { digest, files: { "message.bin": message, ...files }, commands };
}

/** Each signature and its published key as DER files, and the openssl command that checks the pair against
 *  message.bin. Shared with release.mjs. */
export function opensslKeyFiles(signatures, published) {
  const files = {};
  const commands = [];
  const problems = signatureListProblems(signatures);
  if (problems.length) throw new Error(`cannot export: ${problems.join("; ")}`);
  for (const alg of requiredAlgs(signatures)) {
    if (alg === null) throw new Error(`cannot export: ${MISSING_PQ}`);
    const sig = signatures.find((s) => s.alg === alg);
    if (!sig) throw new Error(`cannot export: no ${alg} signature`);
    const key = (published.keys ?? []).find((k) => k.alg === alg && k.key_id === sig.key_id);
    if (!key) throw new Error(`cannot export: ${alg} key ${sig.key_id} is not published`);
    const name = alg.toLowerCase();
    files[`${name}.pub.der`] = Buffer.concat([Buffer.from(SPKI_PREFIX[alg], "hex"), Buffer.from(key.public_b64, "base64")]);
    files[`${name}.sig`] = Buffer.from(sig.sig_b64, "base64");
    commands.push(
      `openssl pkeyutl -verify -pubin -keyform DER -inkey ${name}.pub.der -rawin -in message.bin -sigfile ${name}.sig`,
    );
  }
  return { files, commands };
}

/** The text of VERIFY.txt, one entry per line: shared by `export-openssl` and the PDF appendix so they cannot drift. */
export function verifyInstructions(bundle) {
  return [
    `digest (SHA-256 of the RFC 8785 canonical report without "signatures"): ${bundle.digest}`,
    `message.bin is "qshield-proof-report-v1:" followed by that digest.`,
    "Run in this folder; each line must print \"Signature Verified Successfully\":",
    ...bundle.commands,
    "",
  ];
}
