# Check a Q-Shield proof report yourself

This guide is for someone who receives a Q-Shield proof report (a PDF, and sometimes the signed JSON file behind
it) and wants to check it without trusting our software. You do not need our repository, and you do not need
Node. You need OpenSSL 3.5 or newer and about 30 minutes the first time, including any Docker setup.

What the check shows: the two signatures on the report match the report's digest, so the digest was signed by the
private keys that match the public keys in the report. What it does not show: who holds those keys (you compare
that against what EpochCore publishes), anything about hosts that were not scanned, or anything about EpochCore's
systems. The report is evidence for an auditor, not a certification.

## 1. Get OpenSSL 3.5 or newer

Run `openssl version`. You need `OpenSSL 3.5` or higher. The ML-DSA signature cannot be checked with older
versions.

- Linux: most current distributions ship 3.5 or newer. If yours does not, use the Docker route below.
- macOS: the `openssl` that ships with macOS is LibreSSL and cannot do this. Homebrew's OpenSSL is installed
  "keg-only", which means a plain `openssl` in your terminal still finds LibreSSL. Run Homebrew's by its full
  path (`brew --prefix openssl@3` prints the folder; the program is in its `bin` folder) or put that folder first
  in your `PATH`, then run `openssl version` with the same command you will use below and confirm it says
  OpenSSL 3.5 or newer. Or use the Docker route.
- Windows: use the Docker route below. The steps in the PDF are written for bash or zsh; they have not been
  tested in PowerShell.

### Docker route (any system, including Windows)

Install Docker Desktop, then open a terminal in the folder that holds the report PDF.

macOS or Linux:

```
docker run --rm -it -v "$(pwd):/work" -w /work debian:sid-slim bash
```

Windows PowerShell:

```
docker run --rm -it -v "${PWD}:/work" -w /work debian:sid-slim bash
```

The prompt changes to `root@...:/work#`. Everything below runs in this shell. Install OpenSSL and check it:

```
apt-get update && apt-get install -y openssl
openssl version
```

The version must be 3.5 or newer. If it is lower, stop: the later steps cannot work. The image is not pinned, so
which OpenSSL you get depends on what Debian sid ships that day. This version check is the real test, not the image name.

## 2. Follow the appendix in the PDF

The last pages of the PDF are titled "Appendix: check the signatures without Q-Shield". They contain the commands
for that report, including its own digest and its own public keys and signatures, so there is nothing to download.

**Read every block before you run it.** You are about to paste text from a PDF you have not verified yet, and a
forged PDF can print any command. A genuine block does only the things below, and every file name in it is one of
five names in the folder you are working in: `message.bin`, `ed25519.pub.der`, `ed25519.sig`, and the two ML-DSA
files named for the level the PDF prints (`ml-dsa-65.pub.der` and `ml-dsa-65.sig`, or `ml-dsa-87.pub.der` and
`ml-dsa-87.sig`). A file name never contains `/`, `..`, `~`, `$` or a backtick.

- `printf '%s' 'qshield-proof-report-v1:<digest>' > message.bin`, where `<digest>` is the 64 hex characters printed
  on page 1 and nothing else follows them;
- `cat > <name>.b64 <<'EOF'` or `cat >> <name>.b64 <<'EOF'`, where `<name>` is one of the file names above, then
  lines that contain only base64 characters, then `EOF`;
- `openssl base64 -d -in <name>.b64 -out <name>`, with the same `<name>` in both places;
- `wc -c` followed by only the file names above;
- the two `openssl pkeyutl -verify` lines in step 4, exactly as written there. The only allowed difference is the level
  name in the ML-DSA file names (`ml-dsa-65` or `ml-dsa-87`), to match the level the PDF prints.

If a block contains anything else (`curl`, `sudo`, `rm`, `sh`, a pipe, a download, a path outside the folder you are
working in, a different `-out` name or a different option), stop and do not run it. You can also type the
verification lines in step 4 yourself from this guide, so that nothing the PDF prints is run as a check.

1. Make a new, empty folder and work inside it (in Docker: `mkdir /tmp/check && cd /tmp/check`).
2. Paste each block from the appendix one at a time, in the order printed, after reading it. Each file is made by
   one block; the long ML-DSA signature is split into blocks marked "part 1 of N", and you paste them in order.
3. Run the `wc -c` line. The byte counts must equal the ones printed in the PDF. A different count means a
   pasting mistake (a line break, a curly quote, a missing line). Paste that block again.
4. Check the two signatures. Each line must print `Signature Verified Successfully`. These are the lines to
   type yourself (the ML-DSA file is named for its level, so use the name the PDF prints, for example
   `ml-dsa-65` or `ml-dsa-87`):

   ```
   openssl pkeyutl -verify -pubin -keyform DER -inkey ed25519.pub.der -rawin -in message.bin -sigfile ed25519.sig
   openssl pkeyutl -verify -pubin -keyform DER -inkey ml-dsa-65.pub.der -rawin -in message.bin -sigfile ml-dsa-65.sig
   ```

   `message.bin` must contain the text `qshield-proof-report-v1:` followed directly by the digest printed on page 1
   (no spaces, no newline). `printf '%s' 'qshield-proof-report-v1:<digest>' > message.bin` makes it.

If a PDF viewer adds line breaks or odd characters when you paste, paste into a plain-text editor first, or use
the signed JSON file as in section 4.

## 3. Compare against what EpochCore publishes

The signatures prove the digest was signed by the keys in the PDF. They do not tell you those keys belong to
EpochCore. For that, compare with the public key page at `epochcoreqcs.com/qshield-keys`:

- Work out each key's id from the `.pub.der` file you used in step 4: the key id is the first 16 characters, in
  capitals, of the SHA-256 of the raw public key, which is the last 32 bytes of `ed25519.pub.der` and the last 1952
  (ML-DSA-65) or 2592 (ML-DSA-87) bytes of the ML-DSA file. For example
  `tail -c 32 ed25519.pub.der | openssl dgst -sha256 -r | cut -c 1-16 | tr a-f A-F`. Each must equal a key id
  published there. Don't rely on the key ids the PDF prints: a forged PDF can print any id.
- The SHA-256 of the key file printed on page 1 must equal the SHA-256 published there.

Compare against the page, not against this guide: the keys change when EpochCore rotates them, and a value copied
into a guide goes stale and would look like a failed match. The PDF does not fetch the page for you, on purpose.

## 4. Optional: recompute the digest from the report file

Steps 2 and 3 check the digest the PDF prints. If you also have the signed JSON file and want to confirm that the
file really has that digest, use the public checking code at https://github.com/EpochCore-LLC/qshield-verify. Its
command-line tool only checks reports and releases; it has no signing command. You need Node 20 or newer.

```
git clone https://github.com/EpochCore-LLC/qshield-verify
cd qshield-verify
npm ci
node src/cli.mjs verify report.json
```

`verify` prints the digest and, for each signature, `ok: true` or `ok: false`. The digest must equal the one on
page 1 of the PDF. It exits with 0 only if both signatures check out. The same repository checks a signed collector
release and the archive it names: `node src/cli.mjs verify-release release.json --file qshield.tar`.

## 5. What a failed report looks like

If either signature does not match, `verify` prints `"ok": false` and exits with 1, and the PDF is stamped with a
red "VERIFICATION FAILED" banner on every page. The PDF prints no OpenSSL steps in that case, because there is
nothing to follow. It shows the digest it computed from the file, labelled "Computed from this file", and the
signatures it found, labelled "not trusted". Do not rely on anything else in that document.

For example, changing one character in a signed report (`mid_market` to `mid_marke7`, first occurrence) turns both
signatures into "signature does not match this report" and makes `verify` exit with 1. The digest it then prints
differs from the digest on page 1 of the genuine report.

## 6. How this was tried

A team member who had not built the report followed the appendix printed in the PDF, then the failure case, on
Windows with Docker, from a clean start, against the sample report at commit `00eed56` (OpenSSL 3.6.5). The digest
on page 1 matched the one `render` printed, all five files had the expected sizes (88, 44, 64, 1974 and 3309
bytes), both `openssl pkeyutl -verify` lines printed `Signature Verified Successfully`, and the key ids and
key-file SHA-256 matched page 1. It took about 30 minutes from unzipping to the second signature, including the
Docker setup. That is one run on one system, not a guarantee for yours. The run followed the PDF, not this guide:
nobody other than its author has yet followed this guide as written.

## Known limits

- The appendix assumes bash or zsh. PowerShell has not been tested.
- OpenSSL older than 3.5 and macOS's LibreSSL cannot check the ML-DSA signature.
- A report signed with the ML-DSA-87 key prints different file sizes and a longer signature in more parts. Use the
  sizes printed in your PDF, not the ones in this guide.
- The check is about the report file only. It says nothing about hosts that were not scanned.
