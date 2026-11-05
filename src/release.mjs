// A signed collector release: EpochCore's statement that one qshield.tar (the self-run collector, deploy/COLLECTOR.md)
// is the file it built and published, signed with the same published keys as a proof report (KEYS.json).
//
// What is signed, exactly, so anyone can check it with OpenSSL alone:
//   statement = { schema, artifact, version, sha256, source_commit, image_id, signed_at }   (no "signatures")
//   release.json = the RFC 8785 canonical JSON of statement (UTF-8): the exact bytes a partner downloads
//   digest  = lowercase hex SHA-256 of release.json
//   message = the ASCII bytes "qshield-collector-release-v1:" + digest
// Ed25519 and one ML-DSA key each sign `message`, as for a report, but under this statement's own prefix: a report
// signature can never be passed off as a release signature, or the other way round.
// `sha256` is the SHA-256 of qshield.tar itself, so the chain a partner checks is: their file's hash equals `sha256`
// in release.json, release.json hashes to `digest`, and both signatures over prefix + digest verify with the
// published keys.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { canonicalize } from "./jcs.mjs";
import { KEYS_SCHEMA, checkSignatures, opensslKeyFiles, signMessage } from "./report.mjs";

export const RELEASE_SCHEMA = "qshield/collector-release/v1";
export const RELEASE_PREFIX = "qshield-collector-release-v1:";
export const RELEASE_ARTIFACT = "qshield.tar";
export const RELEASE_FILE = "release.json";

/** What each field must look like: the publish run's own values (collector.yml outputs). */
const FIELDS = {
  version: [/^\d{1,4}\.\d{1,4}\.\d{1,4}$/, "The version must look like 0.2.0"],
  sha256: [/^[0-9a-f]{64}$/, "The SHA-256 must be 64 lower-case hex characters"],
  source_commit: [/^[0-9a-f]{40}$/, "The source commit must be the full 40-character commit hash"],
  image_id: [/^sha256:[0-9a-f]{64}$/, "The image ID must be sha256: followed by 64 lower-case hex characters"],
};

/** Why these fields can't be signed (a sentence without its full stop), or null. */
export function releaseProblem(fields) {
  for (const [name, [re, want]] of Object.entries(FIELDS)) {
    if (typeof fields?.[name] !== "string" || !re.test(fields[name])) return want;
  }
  return null;
}

/** The statement, unsigned. Throws on a field the publish run could not have produced. */
export function buildRelease({ version, sha256: hash, sourceCommit, imageId, signedAt }) {
  const fields = { version, sha256: hash, source_commit: sourceCommit, image_id: imageId };
  const problem = releaseProblem(fields);
  if (problem) throw new Error(problem);
  return {
    schema: RELEASE_SCHEMA, artifact: RELEASE_ARTIFACT, ...fields,
    signed_at: signedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  };
}

/** release.json: the canonical statement without its signatures, byte for byte what is hashed. */
export function releaseText(statement) {
  const { signatures: _ignored, ...body } = statement;
  return canonicalize(body);
}

/** The digest and the exact bytes both keys sign. */
export function releaseMessage(statement) {
  const digest = bytesToHex(sha256(new TextEncoder().encode(releaseText(statement))));
  return { digest, message: new TextEncoder().encode(RELEASE_PREFIX + digest) };
}

/** Sign a statement with both keys of a key file (CSPRNG randomness for ML-DSA; nothing else is recorded). */
export function signRelease(statement, keyFile) {
  const { signatures: _old, ...body } = statement;
  return { ...body, signatures: signMessage(releaseMessage(body).message, keyFile) };
}

/** Every required signature checked against the published keys, never keys carried in the statement. */
export function verifyRelease(signed, published) {
  const { digest, message } = releaseMessage(signed);
  const { problems, results } = checkSignatures(signed?.signatures, message, published, "this release");
  const fieldProblem = releaseProblem(signed);
  if (fieldProblem) problems.push(fieldProblem);
  const schemaOk = signed?.schema === RELEASE_SCHEMA && signed?.artifact === RELEASE_ARTIFACT && published.schema === KEYS_SCHEMA;
  return { ok: schemaOk && problems.length === 0 && results.every((r) => r.ok), schema_ok: schemaOk, problems, digest, results };
}

/** The files and OpenSSL commands a partner uses to check qshield.tar without Q-Shield. message.bin is not handed
 *  over: the partner makes it from release.json, so the digest they check is one they computed. `key_ids` ties each
 *  .pub.der the partner used to EpochCore: a key id is the first 16 hex characters (upper case) of the SHA-256 of the
 *  raw public key (report.mjs keyId), which is the last bytes of the DER file. The partner compares what it prints with
 *  the ids published at epochcoreqcs.com/qshield-keys, not with any id this app shows. */
export function releaseBundle(signed, published) {
  const { digest } = releaseMessage(signed);
  const { files, commands } = opensslKeyFiles(signed.signatures, published);
  const keyIds = signed.signatures.map((s) => {
    const raw = published.keys.find((k) => k.alg === s.alg && k.key_id === s.key_id).public_b64;
    const n = Buffer.from(raw, "base64").length;
    return { alg: s.alg, key_id: s.key_id, command: `tail -c ${n} ${s.alg.toLowerCase()}.pub.der | openssl dgst -sha256 -r | cut -c 1-16 | tr a-f A-F` };
  });
  return {
    key_ids: keyIds,
    digest,
    files: { [RELEASE_FILE]: new TextEncoder().encode(releaseText(signed)), ...files },
    hash_file: `openssl dgst -sha256 ${RELEASE_ARTIFACT}`,
    hash_statement: `openssl dgst -sha256 ${RELEASE_FILE}`,
    make_message: `printf '${RELEASE_PREFIX}%s' "$(openssl dgst -sha256 -r ${RELEASE_FILE} | cut -d ' ' -f 1)" > message.bin`,
    verify: commands,
  };
}
