# Offline (air-gapped) deployment

This guide sets up the `vettalon` CLI on a host with no outbound network: local models only, container images loaded from files, and scanners with their data copied in. It covers the 0.8 CLI (`crates/vettalon`). The Pro desktop app is out of scope.

The pattern is two machines. A **staging host** with network access downloads, verifies and builds everything. The **target host** never reaches the internet; you carry files across by whatever transfer your site allows. Both hosts must run the same Vettalon version, because some image tags are derived from the binary (see [step 3](#step-3-preload-the-container-images)).

Read [data flow and network boundaries](DATA-FLOW.md) first. It lists every flow this guide turns off, and its limits apply here too: Vettalon's flags are not a firewall, and a loopback model address says nothing about whether the model server itself makes outbound connections.

Statements marked *(not verified)* were not checked against the code or a test run. Treat them as things to confirm on your own hosts.

## What works offline in 0.8

| Command | Needs a model | Network on the target host |
|---|---|---|
| `scan` (quick profile) | no | None, once scanner binaries and the cargo-audit advisory DB are installed ([step 5](#step-5-scanners-and-their-data)) |
| `scan --profile deep` | finder and verifier roles | Loopback to your local model server only. Keep the default `--rank heuristic`; never pass `--rank jev`. `--prescreen cheap-model` calls a roster model, so it stays local only if that model is local. |
| `scan --poc` | `poc` role | Docker with the Python PoC image; containers run with `--network=none` |
| `verify` | exactly one verifier | Loopback to the verifier only |
| `intake` | one verifier, or none with `--claims-only` | Loopback only. Do not pass `--check-duplicates`. |
| `reproduce`, `fix check`, `retest`, `bisect` | no (operator-written TargetCall plans) | Docker images only. Python targets and dependency-free Node targets work; Node targets with dependencies do not ([step 4](#step-4-nodejs-and-typescript-targets)). |
| `cbom-check` | no | None |
| `toolchain audit`, `toolchain pin`, `toolchain pins` | no | None without `--online`. An audit that finds npm launchers needs a local npm MAL index or it reports itself incomplete ([step 5](#malicious-package-index)). |
| `disclose` | no | None without `--check-duplicates` |
| `receipt sign`, `receipt verify` | no | None, with a local cosign v3 key ([step 6](#step-6-sign-receipts-offline)) |
| `mal-index update --from-file` | no | None |
| `verify --joern-keep`, `joern check` (experimental) | `verify` needs its verifier; `joern check` needs none | None after the Joern image is loaded |
| `explain`, `validate`, `triage`, `evidence attach` | no | None |

These do not work offline in 0.8:

- `hunt`, including `hunt --dry-run`, which still queries OSV.
- `mal-index update` without `--from-file`.
- `toolchain audit --online`, and `--check-duplicates` on `disclose`, `intake` and `hunt --disclose-dir`.
- `--rank jev`.
- `agents build`, `agents pull`, `poc-node build` and `joern build`. Run these on the staging host only.
- Any CLI-backend model (`preset = "claude" | "codex" | "grok" | "agy"`). Those CLIs talk to their vendors' cloud services.

## Step 1: Bring the CLI across

### From a GitHub release archive (recommended)

Each release has `vettalon-<platform>.tar.gz` for `darwin-arm64`, `darwin-x64`, `linux-x64` and `linux-arm64`, with `.sha256`, `.sig`, `.pem`, `.sigstore.json`, `.cdx.json` and `.build-record.json` sidecars. The archive holds the `vettalon` binary plus `README.md`, `LICENSE` and `NOTICE`.

On the staging host, download the archive and every sidecar from the same release and verify them online as described in [Verify a downloaded CLI archive](TRUST.md#verify-a-downloaded-cli-archive):

```sh
python3 -m venv .venv-trust
.venv-trust/bin/python -m pip install -r scripts/trust/requirements.txt
PYTHON=.venv-trust/bin/python scripts/trust/verify-release.sh \
  vettalon-linux-x64.tar.gz v<VERSION> <FULL-SOURCE-SHA-OF-THAT-TAG>
```

Carry the archive and its `.sha256` file to the target host. The checksum check needs no network:

```sh
sha256sum -c vettalon-linux-x64.tar.gz.sha256        # macOS: shasum -a 256 -c ...
mkdir vettalon-dist && tar xzf vettalon-linux-x64.tar.gz -C vettalon-dist
install -m 0755 vettalon-dist/vettalon /usr/local/bin/vettalon
vettalon --version
```

The checksum only proves the bytes match what the staging host verified. The publisher check itself happened on the staging host.

**Verifying the signature on the target host.** [TRUST.md](TRUST.md#verify-a-downloaded-cli-archive) points to GitHub's documented bundle and trusted-root process for disconnected verification. The repository's registry alert already verifies npm provenance this way: it fetches Sigstore's trusted root once with `gh attestation trusted-root`, then runs `gh attestation verify` against that file. Applied to a release archive, the flow would look like this *(not verified for release archives; the `gh attestation download` step is not used anywhere in this repository)*:

```sh
# staging host
gh attestation trusted-root > trusted_root.jsonl
gh attestation download vettalon-linux-x64.tar.gz -R zhixuli0406/vettalon
# target host
gh attestation verify vettalon-linux-x64.tar.gz \
  --bundle <downloaded-bundle>.jsonl --custom-trusted-root trusted_root.jsonl \
  -R zhixuli0406/vettalon \
  --cert-identity https://github.com/zhixuli0406/vettalon/.github/workflows/release.yml@refs/tags/v<VERSION> \
  --cert-oidc-issuer https://token.actions.githubusercontent.com
```

Keyless `cosign verify-blob` of the archive also needs Sigstore trust material. Its offline use is *(not verified)*, so run it on the staging host.

### From npm tarballs

The `vettalon` npm package carries no binary. The binary ships in the platform package (`@vettalon/darwin-arm64`, `@vettalon/darwin-x64`, `@vettalon/linux-x64`, `@vettalon/linux-arm64`), which the main package lists as an `optionalDependency`. The main package's `postinstall` script only checks that the platform package can be resolved. It downloads nothing.

On the staging host, check registry signatures and provenance there (for example with `npm audit signatures`), then fetch both tarballs:

```sh
npm pack vettalon@<VERSION> @vettalon/linux-x64@<VERSION>
```

Installing both local tarballs on the target host with `npm install -g ./vettalon-linux-x64-<VERSION>.tgz ./vettalon-<VERSION>.tgz` is *(not verified)*. npm may still try to resolve the optional dependency from the registry. If it fails, use the release archive.

### From source

`cargo install --path crates/vettalon` downloads crates. An offline source build (for example with vendored crates) is not documented or tested *(not verified)*.

## Step 2: Configure local models only

The roster is read from `--config <file>` or from `~/.vettalon/config.toml` (`$VETTALON_HOME/config.toml` when `VETTALON_HOME` is set). It is never read from the repository being scanned.

**Always provide a config on the target host.** Without one, Vettalon builds a roster from the CLIs it finds, which today means a `claude` CLI on `PATH`, and that CLI calls a cloud service.

Two HTTP backends reach a local server:

```toml
# ~/.vettalon/config.toml on the target host

[[model]]
id = "coder-local"
backend = "ollama"            # base_url defaults to http://localhost:11434/v1
family = "qwen"
model = "qwen2.5-coder:7b"
roles = ["finder", "poc"]

[[model]]
id = "reviewer-local"
backend = "openai"            # any OpenAI-compatible server (llama.cpp, vLLM, ...)
family = "deepseek"
base_url = "http://127.0.0.1:8000/v1"
model = "<model name the server expects>"
roles = ["verifier"]
# api_key_env = "LOCAL_LLM_API_KEY"   # only if your server wants a bearer token
```

The rules the config is checked against:

- `backend = "ollama"` needs `model`; `base_url` defaults to `http://localhost:11434/v1`. `backend = "openai"` needs both `base_url` and `model`.
- `base_url` must start with `https://`. Plain `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]`; any other `http://` host fails validation.
- `family` is required for HTTP models. It is a label you choose, and Vettalon uses it to prefer a verifier from a different family than the finder. Set it to the model's real vendor family. Two local models from the same family are not independent reviewers.
- `roles` defaults to `finder`, `verifier` and `poc`.
- `api_key_env` is optional. When set, it must be an UPPER_SNAKE name ending in `_API_KEY`, `_KEY` or `_TOKEN` and not starting with `AWS_`. The variable is read at call time and sent as a bearer token. Keys are never stored in the file.
- Each call is `POST {base_url}/chat/completions` with `stream: false`, `max_tokens` 8192 and `temperature` 0 by default, and a 900-second timeout unless you set `timeout_secs`.
- Per-model `token_limit_param` accepts only `"max_tokens"` (default) or `"max_completion_tokens"`; it selects the request field carrying `max_tokens`.
- `omit_temperature` is a boolean (default `false`). Set it to `true` to leave `temperature` out of the request.
- Optional `reasoning_effort` accepts only `"low"`, `"medium"` or `"high"`. The request includes a `reasoning_effort` field only when configured.
- Optional `max_output_tokens_worst` is a nonnegative integer fitting u32 and must be at least `max_tokens` (8192 if omitted). It sets the effective output ceiling for spend reservations and `over_cap_output` checks, including billed reasoning tokens; it is never sent to the endpoint. Without it the ceiling stays `max_tokens`. The price table's larger `max_billed_output_tokens` still raises the cost reservation.

Preloading model weights on the inference server is up to you. Check the roster from the target host:

```sh
vettalon models --config ~/.vettalon/config.toml --probe   # sends each model a one-line check
```

**A model server on another machine inside the enclave.** It needs `https://`. The HTTP client is built with rustls and the bundled `webpki-roots` certificate set, not the operating system's store, and Vettalon has no option to add a CA. A certificate from an internal CA will therefore probably be rejected *(not verified by a run; based on the dependency graph in `Cargo.lock`)*. Running the server on the target host itself and using a loopback `http://` address avoids the problem.

**Proxy variables.** The model HTTP client does not turn off reqwest's proxy support, so `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` in the environment may route model calls through a proxy *(not verified)*. Unset them on the target host, or set `NO_PROXY=localhost,127.0.0.1,::1`.

**Custom CLI programs.** A `backend = "cli"` model with a custom `program` could wrap a local inference tool, but Vettalon accepts it only with `allow_agent_tools = true`, which runs it on the host with access to local files. Using it with a local model is *(not verified)*. Prefer the HTTP backends.

## Step 3: Preload the container images

| Image | Needed for | How the staging host gets it |
|---|---|---|
| `python:3.12-slim` (default `--poc-image`) | `scan --poc`, Python targets of `reproduce`, `fix check`, `retest`, `bisect`, and `intake --target` | `docker pull python:3.12-slim` |
| `vettalon-poc-node:<12 hex>` (default `--node-image`) | JS/TS targets of `reproduce`, `fix check`, `retest` | `vettalon poc-node build` (pulls a digest-pinned `node:26-bookworm-slim` base and installs `python3` from Debian apt) |
| `vettalon-joern:<12 hex>` (optional, experimental) | `verify --joern-keep`, `joern check` | `vettalon joern build` (downloads the pinned Joern release, about 1.8 GB, and checks its SHA-256 and SHA-512) |

The `vettalon-agents`, `vettalon-agents-base` and `vettalon-egress` images serve the tool-capable cloud CLIs (codex, grok). A local-only setup does not need them.

**How the tags are derived.** The `vettalon-poc-node` and `vettalon-joern` tags are the first 12 hex digits of a SHA-256 over the image definition embedded in the binary. The same binary version always expects the same tag; a version whose Dockerfile changed expects a new one. Print the expected tags without calling Docker, on both hosts:

```sh
vettalon poc-node image
vettalon joern image
```

If the two hosts print different tags, they run different Vettalon versions. Fix that before you move images.

**Move the images.** On the staging host:

```sh
docker save -o vettalon-images.tar \
  python:3.12-slim "$(vettalon poc-node image)" "$(vettalon joern image)"   # drop joern if unused
docker image inspect --format '{{.Id}} {{index .RepoTags 0}}' \
  python:3.12-slim "$(vettalon poc-node image)"
```

On the target host:

```sh
docker load -i vettalon-images.tar
docker image inspect --format '{{.Id}} {{index .RepoTags 0}}' \
  python:3.12-slim "$(vettalon poc-node image)"
```

The image IDs match on both hosts: on 2026-11-13 a `vettalon-poc-node` image saved on macOS (Docker Desktop) loaded on a Linux host (Docker 24.0.7) with the same `sha256:` ID. Build images on the same CPU architecture as the target host.

**What Vettalon does with an image.** Before a sandbox run it asks the daemon for the image with `docker image inspect` and binds the tag to the immutable `sha256:` image ID it gets back. It runs that ID, and receipts record it as `image_id`. Every PoC, Node and Joern `docker run` passes `--pull=never`. The only commands that pull are `vettalon agents pull` and the image builds above. A missing image is reported, never fetched:

- Python image: `sandbox image <name> is not present locally (run \`docker pull <name>\` once)`.
- Node image: `node_runtime_unavailable`, with a hint to run `vettalon poc-node build`. `retest` counts this as `environment_unavailable`, not as a result about the target.

## Step 4: Node.js and TypeScript targets

What works offline:

- **Dependency-free projects**, meaning a `package.json` without `dependencies`, `devDependencies`, `optionalDependencies` or `peerDependencies` entries, or no `package.json` at all (bare `.cjs`/`.mjs` files). Vettalon binds an empty lockfile, skips the install step and runs every phase in `--network=none` containers.

What does not:

- **Projects with dependencies.** They need an npm lockfile (`package-lock.json` or `npm-shrinkwrap.json`); without one the run stops with `node_lockfile_missing`. With one, Vettalon installs once per command in the only container that has network: `--network=bridge`, running `npm ci --ignore-scripts --no-audit --no-fund --bin-links=false --prefer-online`. The registry is fixed to `https://registry.npmjs.org/`, and every `resolved` URL in the lockfile must point there or the lockfile is refused (`node_lockfile_refused`). On an air-gapped host this install cannot reach the registry. A failed `npm ci` maps to `node_deps_install_failed` *(the mapping is in the code; the offline run itself is not verified)*.

0.8 has no supported way to supply Node dependencies offline: no registry mirror setting, no option to hand in a prepared `node_modules`. Whether a `node_modules` directory already in the repository has any effect is *(not verified)*. Do not rely on it.

## Step 5: Scanners and their data

Vettalon finds scanner binaries on `PATH` and in a few fixed user directories (`~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `~/.cargo/bin` and others). It ignores any binary inside the scanned repository. A missing scanner is recorded as a missing engine, which is a coverage gap, not a clean result. Installing the scanners offline is outside this guide.

| Scanner | How Vettalon runs it | Data it needs offline |
|---|---|---|
| Semgrep | `semgrep scan --json --metrics=off --disable-version-check --no-git-ignore --disable-nosem --x-ignore-semgrepignore-files --config <temp file>`; the six-rule ruleset is bundled in the binary and written to a temp file | None. Registry rule packs (`--config auto`, `p/...`) are never used. |
| Gitleaks | `gitleaks dir <repo> --config <file> --gitleaks-ignore-path <empty file> --ignore-gitleaks-allow --report-format json ...`; Vettalon writes the config and an empty ignore file | None found in the adapter |
| cargo-audit | the `cargo-audit` binary directly with `--json --no-fetch`, only when a `Cargo.lock` is at the repository root | The RustSec advisory DB, already cloned (usually `~/.cargo/advisory-db`, or relative to `CARGO_HOME`) |
| osv-scanner | never invoked, because it needs the network | none |

Opengrep is not supported: the adapter looks only for a binary named `semgrep`.

**cargo-audit advisory DB.** `--no-fetch` stops cargo-audit from updating the DB, so it scans against whatever copy exists. Let cargo-audit fetch the DB on the staging host, then copy the directory to the same location on the target host. The exact cargo-audit command that fetches it depends on your cargo-audit version *(not verified)*. Without a DB the engine fails and the run is incomplete; it never counts as zero findings. The DB is only as fresh as your last copy. `--no-fetch` also leaves yanked-package and index checks unestablished.

**The scanners' own network behaviour.** [DATA-FLOW.md](DATA-FLOW.md) records two acceptance runs under an OS network-deny policy: Semgrep 1.181.0 with the bundled rules, and a quick scan with gitleaks. Other versions, and anything the tools do beyond the flags above, are *(not verified)*.

**Version pinning.** Vettalon does not pin scanner versions. Record the versions you install. `crates/vettalon/src/toolchain/pins.rs` is a different thing: the content-hash store for `vettalon toolchain pin` (`$VETTALON_HOME/toolchain/pins.json`), which audits coding-agent skills, plugins and MCP servers. It works offline.

### Malicious-package index

`toolchain audit` checks the npm launchers it finds against a local index of OpenSSF `MAL-*` records. Without an npm index the audit adds `mc002:mal_index_absent` and is incomplete (exit 2 unless `--allow-incomplete`). Build the index from a file:

```sh
# staging host: one GET, the same URL `mal-index update` uses
curl -fLO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
shasum -a 256 all.zip
# target host
vettalon mal-index update --ecosystem npm --from-file all.zip --expect-sha256 <hex>
vettalon mal-index status
```

The index goes to `~/.vettalon/mal-index` (under `VETTALON_HOME` when set), or to `--dir`.

## Step 6: Sign receipts offline

`vettalon receipt sign` and `receipt verify` call your cosign v3 with a local key file. Signing passes `--use-signing-config=false --tlog-upload=false`; verifying passes `--insecure-ignore-tlog`. No transparency log is used. Remote, KMS and token key references are refused before cosign runs. The project tested signing and verification with cosign v3.1.3 with the network blocked, and neither needed it. Bring a cosign v3 binary across with the CLI.

```sh
cosign generate-key-pair                     # once; writes cosign.key and cosign.pub
export COSIGN_PASSWORD=...                    # cosign cannot prompt when Vettalon runs it
vettalon receipt sign receipt.json --key cosign.key
vettalon receipt verify receipt.json --key cosign.pub --bundle receipt.json.sigstore.json
```

This is unrelated to release verification in step 1, which checks keyless signatures and needs Sigstore trust material. See [receipt_signing](explain/receipt_signing.md) for what a signature does and does not prove.

## Step 7: Prove there is no egress

Run these steps yourself on the target host. Vettalon cannot certify its own network isolation: a passing run proves only the commands, versions and configuration you ran, under the policy you applied.

1. **Record the setup.** Binary version and SHA-256, the config file, scanner versions, the advisory DB location and date, image IDs from `docker image inspect`, and the network policy. [DATA-FLOW.md](DATA-FLOW.md#validation-boundary) lists what an offline acceptance record needs.
2. **Block egress below Vettalon.** Use a host firewall, a network namespace or an enclave boundary that drops everything except loopback (and whatever path the Docker daemon needs locally). Do not rely on Vettalon's flags or on unset proxy variables. The repository's own checks use the same idea: CI runs the CLI inside `docker run --network none` (`.github/workflows/oss-cli-network-none.yml`), and `scripts/trust/offline-probe.py` is a macOS `sandbox-exec` diagnostic.
3. **Confirm the block works.** Run a negative control that must fail, for example `vettalon mal-index update --ecosystem npm --dir /tmp/mal-control` (no `--from-file`; it makes one HTTPS GET). It has to fail with a network error. If it succeeds, the block is not in place.
4. **Run the commands you plan to use:**

   ```sh
   vettalon --version
   vettalon explain --list
   vettalon models --config ~/.vettalon/config.toml --probe
   vettalon scan <fixture-repo> --report quick.json
   vettalon scan <fixture-repo> --profile deep --config ~/.vettalon/config.toml --report deep.json
   vettalon cbom-check --cbom fixtures/cbom/sample-py.cbomkit.json --root fixtures/cbom/sample-py
   vettalon receipt sign <receipt> --key cosign.key
   vettalon receipt verify <receipt> --key cosign.pub --bundle <receipt>.sigstore.json
   ```

   Add `scan --poc`, `reproduce` or `retest` if you use them. A deep scan in which no AI engine could run exits 4, so exit 4 means your local models were not reached. Read `run_status`, `incomplete_reason` and the engine records in the report; an exit code of 0 alone does not show complete coverage.
5. **Check the firewall log.** It should show no outbound attempts from `vettalon`, its scanner subprocesses or its containers during step 4. The Docker daemon, your model server and the scanners are separate programs; check their traffic separately.
6. **Repeat after every upgrade** of Vettalon, a scanner, the model server or the images.

---
