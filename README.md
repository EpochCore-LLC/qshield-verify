# qshield-verify

Check a Q-Shield proof report, or a signed Q-Shield collector release, against EpochCore's published keys, without
trusting EpochCore's software.

The command-line tool only **checks** signatures: it has no signing command, and this repository holds no private
keys. A report or release that checks out against the published keys can only have been signed by whoever holds
EpochCore's private keys, and those never leave EpochCore.

## What a report's signatures show

Every Q-Shield proof report is signed twice: once with Ed25519 and once with ML-DSA (FIPS 204, the post-quantum
signature standard; ML-DSA-87 since 2026-11-03, ML-DSA-65 before). If both signatures check out against the published
keys, the report has not changed since EpochCore signed it. It is evidence for an auditor, not a certification, and it
covers only the hosts listed in the report.

## Check a report

You need Node 20 or newer.

```
git clone https://github.com/EpochCore-LLC/qshield-verify
cd qshield-verify
npm ci
node src/cli.mjs verify report.json
```

It prints the report's digest and, for each signature, whether it checks out. It exits with 0 only if both do. The
digest must equal the one printed on page 1 of the report's PDF.

## Check a collector release

A design partner who runs Q-Shield's collector on their own network downloads `qshield.tar` and its signed
`release.json` from the Q-Shield app.

```
node src/cli.mjs verify-release release.json --file qshield.tar
```

It exits with 0 only if both signatures check out and the file's SHA-256 is the one EpochCore signed.

## Check without this code

`node src/cli.mjs export-openssl report.json --dir check` writes the signed bytes, the public keys, the signatures and
the OpenSSL commands into `check/`. OpenSSL 3.5 or newer then checks both signatures on its own. [VERIFY.md](VERIFY.md)
walks through the whole check with OpenSSL only, from the PDF, with no Node at all.

## Are these EpochCore's keys?

The signatures show only that the keys in [KEYS.json](KEYS.json) signed. To know they are EpochCore's keys, compare
with the page EpochCore publishes at https://epochcoreqcs.com/qshield-keys:

- the SHA-256 of `KEYS.json` must equal the one printed there (`openssl dgst -sha256 KEYS.json`);
- each key id is the first 16 characters, in capitals, of the SHA-256 of the raw public key, and must equal an id
  printed there.

Compare against that page, not against this README: keys change when EpochCore rotates them, and `--keys FILE` checks
against a key file you downloaded from the page instead of the one in this repository.

## What is signed

```
body    = the report without its "signatures" field
digest  = lowercase hex SHA-256 of the RFC 8785 canonical JSON of body (UTF-8)
message = "qshield-proof-report-v1:" + digest            (a release: "qshield-collector-release-v1:" + digest)
```

Ed25519 (RFC 8032) and ML-DSA (FIPS 204, empty context) each sign `message`. The different prefixes keep a report
signature from ever passing as a release signature. The cryptography is the audited
[noble](https://paulmillr.com/noble/) libraries.

## Where this code comes from

`src/report.mjs`, `src/release.mjs` and `src/jcs.mjs` are unchanged copies of the modules EpochCore's Q-Shield uses to
sign and check reports, so what this repository checks is exactly what Q-Shield signs. `report.mjs` and `release.mjs`
also hold the signing functions Q-Shield calls; without EpochCore's private keys they can only make signatures that
fail against the published keys. `SOURCE.txt` names the Q-Shield commit these files were exported from.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
