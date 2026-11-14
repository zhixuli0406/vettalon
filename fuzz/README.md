# Fuzzing

Coverage-guided fuzz targets ([cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html), libFuzzer) for the parsers in `vettalon` and `vettalon-contract` that read untrusted input. Each target checks invariants as well as "no panic"; the doc comment at the top of every file in `fuzz_targets/` lists them.

| Target | What it feeds | Main invariant |
|---|---|---|
| `lockfiles` | Cargo.lock/Cargo.toml, package-lock.json, requirements.txt, go.sum/go.mod, PyPI metadata (`hunt` intake) | targets are non-empty, unique, sorted; every registry URL built from them stays on the fetch host allowlist |
| `model_reply` | finder candidate array, verifier verdict, zero-LLM pre-check | a candidate the pre-check accepts always has a real code window |
| `contract_ids` | `SafeRepoPath`, `Fingerprint`, `canonical_id` | accepted paths cannot leave the root; derived fingerprints parse; canonical ids decode back losslessly |
| `archive_extract` | downloaded `.tar.gz` / `.zip` dependency archives | nothing is written outside the destination; no symlinks or special files |
| `redaction` | `mask_sensitive_text` | a credential with a known prefix never survives masking |
| `sarif` | SARIF 2.1.0 logs for `verify --input` (Semgrep, CodeQL, gosec, Snyk Code, vettalon's own export), read with the size and nesting limits against the fixed root `/vettalon-fuzz-root` (it need not exist; the `root_uris` seed names it, so `file:` URIs and `originalUriBaseIds` inside the root are reached) | results within the 5 000 cap with unique `sarif-` ids; a `duplicate` note names a kept claim and no two claims share file, line, rule id and CWE; every claimed file and trace location passes `SafeRepoPath` with a line of at least 1 and at most 10 trace locations; titles are one line of visible text; sources are 1–64 characters of `[A-Za-z0-9._-]`; CWEs are normalized and `cwe` is one of the listed `cwes`; `claim_to_finding` and the refuter's `<claim>` text accept every claim and nothing in that text can close the fence |
| `java_usage` | one Java source file (`Main.java`) through the name-based Java usage analyzer (`cbom-check`) | every line label is one of the three, lines stay within `1..=lines+1`; a source with `@` or a reflection word (`forName`, `invoke`, `ServiceLoader`, `MethodHandle`, `Statement`) has no `not_observed` line |
| `cbom` | CycloneDX 1.6/1.7 CBOM JSON (`cbom-check`, experimental) | an accepted CBOM is spec 1.6/1.7, within the component/per-component/total occurrence caps, with strings clipped to 256 characters (clipping recorded), locations of at most 4096 bytes, a well-formed hash and algorithm links only to `algorithm` assets |

This directory is its own Cargo workspace, so the stable build in the repository root never compiles it. The targets reach private parsers through `vettalon`'s `fuzzing` feature (`audit::fuzzing`), which is not a stable API.

## Run

Requires a nightly toolchain and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

From the repository root:

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run lockfiles fuzz/corpus/lockfiles fuzz/seeds/lockfiles -- -max_total_time=60
```

The first directory is the working corpus (git-ignored, grows as the fuzzer finds new coverage); `fuzz/seeds/<target>` holds small committed starting inputs and is never written to. A crash is saved under `fuzz/artifacts/<target>/`; reproduce and shrink it with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
```

Fix the bug, then add the minimized input as a regular unit test next to the parser, so `cargo test` covers it on stable.

CI (`fuzz` job in `.github/workflows/ci.yml`) builds every target with a pinned nightly and runs each one for 45 seconds on every push and pull request. Crash reproducers are uploaded as the `fuzz-artifacts` artifact.
