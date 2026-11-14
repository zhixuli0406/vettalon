# receipt_signing: A receipt signed with your own cosign key

## What it means

`vettalon receipt sign` wraps a `vettalon reproduce --out` receipt, a `vettalon fix check --out` receipt or a `vettalon retest --out` report in an in-toto Statement v1 and signs it with your cosign v3 key. The Statement has one subject, the SHA-256 of the exact receipt bytes. Its predicate type is `https://vettalon.dudustudio.monster/attestation/reproduce/v1`, `https://vettalon.dudustudio.monster/attestation/fix-check/v1` or `https://vettalon.dudustudio.monster/attestation/retest/v2`. The predicate holds fields Vettalon copies from the receipt (outcome, reason, hashes, verdict) plus the receipt kind and the Vettalon version. For a version-2 reproduce receipt it also holds `replays_requested`, `replays_completed` and `replays_observed`; a receipt whose replays do not support its stated outcome is refused. A retest predicate holds the report's hashes, commits, replay count, summary and, per finding, the status, file hashes, receipt target file and function, and replay counts (not titles); a report whose summary or statuses disagree with its receipts is refused. The signed Sigstore bundle is written next to the receipt as `<receipt>.sigstore.json`, with mode 0600, and an existing file is never replaced.

Retest signing and packaging use the same validator. It rejects duplicate finding ids, a new file hash that differs from the embedded receipt, and a `rebound` flag inconsistent with the recorded hashes. With no new hash, `rebound` must be false; otherwise it must equal whether the old hash differs from the new hash (the generator compares the recorded hashes verbatim). Every embedded receipt must have a valid verification event matching its file and function, and the event's finding id must match the result. A legacy Python receipt without an event remains eligible for standalone reproduce signing, but cannot be embedded in a signed or packaged retest report.

Current Python and Node executions produce verification events. When a run cannot produce one, the retest generator emits a result without a receipt: environment failures and unstarted deadlines retain their failure status; other unbound runs become `inconclusive` with reason `unbound_receipt`. Such rows claim no executed evidence. Signing does not compare titles, CWE, old file hashes or commits with the original scan report; packaging performs those additional checks when the scan report is supplied. The retest predicate uses `/retest/v2` to include target file and function; existing pre-release `/retest/v1` statements must be signed again.

A valid signature proves two things: the holder of the key vouched for this receipt, and the receipt has not changed since it was signed.

It does not prove that the receipt's conclusion is correct. It does not prove that the machine, sandbox image or tools that produced the receipt were trustworthy. Anyone with the key can sign any receipt Vettalon accepts.

A signature only means something if the verifier trusts the public key. Get it from the signer by a channel you already trust; a public key shipped next to the receipt and bundle proves nothing. There is no trusted timestamp: a signature made with a key that leaked later cannot be told apart from a genuine earlier one.

The key must be a local file. Vettalon refuses remote, KMS and token key references before cosign runs: anything containing `://` (such as `https://`, `env://`, `k8s://`, `awskms://`, `gcpkms://`, `azurekms://`, `hashivault://`), anything starting with `pkcs11:`, `env:`, `k8s:`, `hashivault:`, `awskms:`, `gcpkms:` or `azurekms:`, and any other `scheme:` prefix that is not an existing path. The key must exist and be a regular file (a symlink to a regular file is resolved; a FIFO or device is refused), and cosign gets its absolute path. Vettalon never reads your key. cosign reads `COSIGN_PASSWORD` from the environment and cannot prompt when Vettalon runs it.

With a local key file, signing and verification were tested with cosign v3.1.3 with the network blocked (a proxy pointing at a dead port, an empty HOME and TUF cache) and needed no network. Vettalon refuses remote and KMS keys, so this holds by construction on Vettalon's side. No public transparency log is used and nothing is uploaded. cosign v3.0.4 or later (v3) is required; other major versions are refused.

The bundle must be a Sigstore bundle v0.3: `mediaType` is exactly `application/vnd.dev.sigstore.bundle.v0.3+json`, and the top level has only `mediaType`, `verificationMaterial` and exactly one `dsseEnvelope`. A bundle with any other top-level field, a duplicated field or a `messageSignature` is refused.

Before `sign` writes the bundle, it decodes the Statement cosign signed and checks that it matches the receipt (one subject, predicate type, predicate). It does not check the signature; `verify` does.

## Why you see it

You ran `vettalon receipt sign` or `vettalon receipt verify`, or someone gave you a receipt with a `.sigstore.json` bundle.

## What to do

Create a key pair once, then sign with the private key and verify with the matching public key.

```sh
cosign generate-key-pair    # prompts for a password; writes cosign.key and cosign.pub
vettalon receipt sign receipt.json --key cosign.key
vettalon receipt verify receipt.json --key cosign.pub --bundle receipt.json.sigstore.json
```

Use a real password for the private key. `cosign generate-key-pair` prompts for it; for non-interactive use (CI), set `COSIGN_PASSWORD` in the environment instead. `vettalon receipt sign` needs `COSIGN_PASSWORD` set for an encrypted key, because cosign cannot prompt when Vettalon runs it.

Exit codes:

| Code | `sign` | `verify` |
|---|---|---|
| 0 | signed, bundle written | verified |
| 1 | (not used) | verification failed: cosign rejected the signature, or the signed Statement does not match the receipt |
| 2 | refused or failed; no bundle written | refused: bad input (receipt, bundle path), missing or invalid key (including remote/KMS references), cosign missing or the wrong version, or cosign could not run |

A third party can verify offline. They need the receipt, the bundle, your public key (obtained from you by a channel they trust) and cosign v3.0.4 or later (v3). No transparency log lookup is made. `verify` runs `cosign verify-blob-attestation` with `--insecure-ignore-tlog`, then decodes the signed Statement and checks that it has exactly one subject matching the receipt bytes, the expected predicate type, and the predicate Vettalon extracts from the receipt again. Only `vettalon_version` may differ.

## ML-DSA hybrid signing (optional)

Add `--pq-key` to sign an ML-DSA-65 layer over the same DSSE PAE bytes that cosign signs. This requires OpenSSL >= 3.5 and < 5 with ML-DSA-65 support; LibreSSL and older OpenSSL releases are refused. No new Rust dependency is used. Windows refuses hybrid signing for now: `ML-DSA signing requires Unix; native Windows key paths and identity-checked cleanup are not yet supported`.

Set `VETTALON_PQ_KEY_PASSWORD` to your chosen private-key password, then generate an encrypted key pair with OpenSSL:

```sh
openssl genpkey -algorithm ML-DSA-65 -aes-256-cbc -pass env:VETTALON_PQ_KEY_PASSWORD -out mldsa.key
openssl pkey -in mldsa.key -passin env:VETTALON_PQ_KEY_PASSWORD -pubout -out mldsa.pub
```

Use the same password environment variable when signing; OpenSSL cannot prompt. Keep `COSIGN_PASSWORD` set for the encrypted cosign key as before.

```sh
vettalon receipt sign receipt.json --key cosign.key --pq-key mldsa.key
vettalon receipt verify receipt.json --key cosign.pub --bundle receipt.json.sigstore.json \
  --pq-pub mldsa.pub --pq-sig receipt.json.mldsa.json
```

Signing writes the classical bundle and a separate `<receipt>.mldsa.json` sidecar (0600, existing outputs refused). `--pq-out PATH` changes the sidecar destination and requires `--pq-key`. The canonical JSON sidecar contains the ML-DSA signature, algorithm and message identifiers, OpenSSL version, and hashes binding the public key, receipt and signed Statement. It is not a replacement for the Sigstore bundle.

Hybrid verification has AND semantics: cosign and ML-DSA must both verify, and the signed Statement must match the receipt. `--pq-pub` and `--pq-sig` must be supplied together; sidecars are never discovered automatically. Exit 0 means signed or verified; every signing failure is exit 2. Verification exits 1 for a rejected signature or a receipt, Statement or public-key binding mismatch, and 2 for refused input (including malformed sidecars or the wrong key algorithm), unavailable or untrusted tools, unsupported versions or tool execution errors.

The additional layer means forging the classical signature alone cannot make a different receipt pass hybrid verification without also forging ML-DSA-65. It protects only the signature layer: it does not establish that the conclusion is correct or that the execution environment was trustworthy, and provides no confidentiality, trusted timestamp or transparency log. Both public keys must be trusted out of band. Removing the sidecar and omitting the PQ verification flags leaves only the classical layer; a verifier who requires hybrid verification must require both flags.

## Tool trust

cosign and OpenSSL executables and every ancestor directory must be owned by root or you, with no group- or world-write permission; root-owned sticky ancestor directories are excepted. Tools must also be outside the working directory, receipt directories and their repositories. Homebrew's default `/opt/homebrew` is group-writable, so tools under that layout are refused. Copy the binaries into a private directory and select their absolute paths:

```sh
install -d -m 0700 ~/.local/vettalon-tools && install -m 0500 "$(command -v cosign)" ~/.local/vettalon-tools/
install -m 0500 "$(command -v openssl)" ~/.local/vettalon-tools/
export VETTALON_COSIGN="$HOME/.local/vettalon-tools/cosign"
export VETTALON_OPENSSL="$HOME/.local/vettalon-tools/openssl"
```

Choose an OpenSSL version meeting the requirement above before copying it. Dynamic libraries are not checked: a copied Homebrew executable can still load Homebrew libraries, whose installation you must trust. Both tools run with a cleared environment and fixed PATH/locales. cosign uses a private HOME and receives `COSIGN_PASSWORD` only for signing; OpenSSL has configuration disabled with `OPENSSL_CONF=""` and receives `VETTALON_PQ_KEY_PASSWORD` only for private-key operations.

## Related

[fix_check](fix_check.md), [fix_context_v1](fix_context_v1.md), [poc_oracle](poc_oracle.md).
