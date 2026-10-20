# Go reachability corpus

A labelled corpus for checking whether the reachability adapter ever says
`not-observed` about code that actually ran. Each host is a tiny, self-authored
Go program pinned to a known-vulnerable module version. Ground truth comes from
running the host once with coverage on the advisory packages, never from a
static tool.

These fixtures are deliberately vulnerable. They are never built into or shipped
with Vettalon; each host directory carries an `osv-scanner.toml` that lists the
advisories expected for its pinned `go.mod` requirements.

## Contents

- `corpus.json`: advisories, pinned module versions, hosts and host classes,
  plus the SHA-256 of every file in the advisory snapshot.
- `vulndb/`: 16 advisory documents fetched from `https://vuln.go.dev/ID/<ID>.json`
  on 2026-10-20 (Go vulnerability database, CC-BY-4.0). This is a fixed subset,
  not a full database; govulncheck reads it as a flat directory of OSV files.
- `hosts/<name>/`: `go.mod`, `go.sum`, `main.go`, `osv-scanner.toml`.
- `RESULTS-2026-10-20.json`: the recorded run summary (no paths, tool hashes only).

| Advisory | Module | Pinned version | Symbol the called host executes |
|---|---|---|---|
| GO-2020-0015 | golang.org/x/text | v0.3.2 | `transform.String` → `utf16Decoder.Transform` |
| GO-2022-1059 | golang.org/x/text | v0.3.7 | `language.ParseAcceptLanguage` |
| GO-2020-0036 | gopkg.in/yaml.v2 | v2.2.7 | `yaml.Unmarshal` |
| GO-2022-0603 | gopkg.in/yaml.v3 | v3.0.0-20210107192922-496545a6307b | `yaml.Unmarshal` |
| GO-2021-0265 | github.com/tidwall/gjson | v1.9.2 | `gjson.Get` |
| GO-2020-0017 | github.com/dgrijalva/jwt-go | v3.2.0+incompatible | `MapClaims.VerifyAudience` |
| GO-2025-3553 | github.com/golang-jwt/jwt/v5 | v5.2.1 | `Parser.ParseUnverified` |
| GO-2020-0016 | github.com/ulikunitz/xz | v0.5.7 | `Reader.Read` |
| GO-2022-0411 | github.com/Masterminds/goutils | v1.1.0 | `RandomAlphaNumeric` |
| GO-2022-0244 | github.com/satori/go.uuid | v1.2.1-0.20180103161547-0ef6afb2f6cd | `NewV4` |
| GO-2021-0057 | github.com/buger/jsonparser | v1.1.0 | `GetString` → `searchKeys` |
| GO-2023-1572 | golang.org/x/image | v0.4.0 | `tiff.Decode` |
| GO-2024-3333 | golang.org/x/net | v0.32.0 | `html.Parse` |
| GO-2025-3525 | github.com/expr-lang/expr | v1.16.9 | `parser.ParseWithConfig`, `vm.Run` |
| GO-2025-4188 | github.com/sirupsen/logrus | v1.9.0 | `Logger.Writer` |
| GO-2026-5320 | github.com/yuin/goldmark | v1.7.16 | `Renderer.renderLink` |

Every advisory has a `called` host and a `not-called` host that imports the same
package without executing a listed symbol. Eight more hosts cover the
documented govulncheck blind spots, two per class, and all of them execute the
vulnerable symbol:

| Class | Hosts | How the symbol is reached |
|---|---|---|
| reflection | `blind-reflection-jwt-go`, `blind-reflection-jwt-v5` | `reflect.Value.MethodByName` with a name built at run time |
| interface | `blind-interface-x-text`, `blind-interface-xz` | a `transform.Transformer` value; `io.ReadAll` over an `io.Reader` |
| funcvalue | `blind-funcvalue-yaml-v2`, `blind-funcvalue-gjson` | a map of function values; a channel plus struct field |
| unsafe | `blind-unsafe-linkname-goutils`, `blind-unsafe-pointer-x-image` | `//go:linkname` pull; a function word copied through `unsafe.Pointer` |

## Ground truth

`run_corpus.py run` builds each host with
`go build -cover -covermode=count -coverpkg=./...,<advisory packages>` and runs
the binary once with `GOCOVERDIR` set and a 30-second limit. `go tool covdata
textfmt` and `go tool cover -func` give per-function coverage; the runner maps
each advisory symbol (`Type.Method` or `Func`) to its declaration line in the
module source. A host is `executed` when any listed symbol has nonzero
coverage, `not-executed` when every declared symbol has zero, and `unknown` when
the build, run or report fails, no listed symbol is declared in that version, the
profile has no row for the main package or for a linked advisory package, or a
declared symbol in a linked package has no coverage row. An empty or partial
profile therefore never reads as `not-executed`. Advisory packages that are not
linked into the binary at all (`go list -deps`) cannot run, so their symbols
count as not executed.

The host binary runs once, with the disposable output directory as its working
directory and only `PATH`, `HOME`, `LANG` and `GOCOVERDIR` in its environment.
There is no network or filesystem sandbox around it. The hosts are
self-authored, use fixed in-memory input and make no network calls; do not point
the runner at other code.
(`./...` is included because Go 1.27 writes no coverage meta-data when only
non-main-module packages are instrumented.)

## Network and offline policy

Only `prepare` uses the network:

```bash
python3 benchmarks/reachability/run_corpus.py prepare --modcache /tmp/NEW_CORPUS_CACHE
```

It runs `go mod download` and `go mod verify` per host with
`GOPROXY=https://proxy.golang.org`, `GOSUMDB=sum.golang.org`,
`GOFLAGS=-mod=readonly`, `GOTOOLCHAIN=local`, `GOENV=off`, `GOWORK=off`,
`CGO_ENABLED=0` and `GOMODCACHE=<cache>/pkg/mod` (about 142 MB on 2026-10-20).
The experiment is then offline:

```bash
python3 benchmarks/reachability/run_corpus.py run --modcache /tmp/NEW_CORPUS_CACHE \
  --tool /tmp/TOOLS/v1.4.0/govulncheck --latest-tool /tmp/TOOLS/latest/govulncheck \
  --output /tmp/NEW_CORPUS_RUN
```

Every Go command and govulncheck call in `run` uses `GOPROXY=off`,
`GOSUMDB=off`, `GOFLAGS=-mod=mod`, `GOTOOLCHAIN=local`, `GOENV=off`,
`GOWORK=off`, `CGO_ENABLED=0`, the prepared `GOMODCACHE` and a disposable
`HOME`/`GOCACHE`. A missing module fails the host instead of downloading it.
`-mod=mod` could let Go rewrite `go.mod`, so the runner hashes each host
directory before and after and marks the host `unknown` if anything changed.
The adapter run uses the same `GOFLAGS` and binds it into its cache key.

Install the two govulncheck builds before going offline (`go install
golang.org/x/vuln/cmd/govulncheck@v1.4.0` and `@latest` into separate `GOBIN`
directories). The runner reads `go version -m` and refuses a pinned binary that
is not v1.4.0; the latest version is recorded, not assumed.

## What is compared

For each host the runner records three things side by side:

1. The adapter state (`reachable`, `not-observed`, `unknown`) from the pinned
   govulncheck v1.4.0 JSON stream. The adapter never emits `not_affected`.
2. The OpenVEX status from govulncheck v1.4.0 (`-format openvex`).
3. The OpenVEX status from the latest govulncheck.

Gates (all must hold for exit 0; a `--host` subset run is marked `partial` and
never passes):

- `false_unreachable_zero`: no host with truth `executed` gets `not-observed`.
- `blind_spots_never_not_observed`: every blind-spot host is `unknown` or `reachable`.
- `complete_observation`: every truth is known, every non-blind host has a
  classified adapter state, and both OpenVEX runs produced a statement.
- `adapter_never_not_affected`: every adapter record keeps `under_investigation`.

## Results (2026-10-20)

Go 1.27.0 darwin/arm64, govulncheck v1.4.0 and v1.9.0, adapter 0.3.0, 40 hosts.

| Class | Hosts | Executed | Adapter reachable / not-observed / unknown | False unreachable | False reachable | OpenVEX `not_affected` on executed path (v1.4.0 / v1.9.0) |
|---|---|---|---|---|---|---|
| called | 16 | 16 | 16 / 0 / 0 | 0 | 0 | 0 / 0 |
| not-called | 16 | 0 | 1 / 15 / 0 | 0 | 1 | 0 / 0 |
| reflection | 2 | 2 | 0 / 0 / 2 | 0 | 0 | 2 / 2 |
| interface | 2 | 2 | 2 / 0 / 0 | 0 | 0 | 0 / 0 |
| funcvalue | 2 | 2 | 2 / 0 / 0 | 0 | 0 | 0 / 0 |
| unsafe | 2 | 2 | 0 / 0 / 2 | 0 | 0 | 2 / 2 |

All four gates passed. govulncheck v1.4.0 and v1.9.0 gave the same OpenVEX
status on all 40 hosts. Both versions marked the four reflection/unsafe hosts
`not_affected` with justification `vulnerable_code_not_in_execute_path`, even
though coverage shows the vulnerable function ran. The adapter reports those
four as `unknown` (reason `blind-spot-reflect`, `blind-spot-unsafe` or
`blind-spot-linkname+unsafe`). The one false reachable is
`go-2026-5320-not-called`: goldmark registers `renderLink` for every
conversion, so the static path exists, but plain text never produces a link node.
Interface and function-value hosts were resolved by govulncheck's call graph in
this corpus, so no adapter rule is involved there.

## Blind-spot rule and its limits

When the static result would be `not-observed`, the adapter scans the host's own
non-test `.go` files (skipping `vendor/`, `testdata/`, `.`/`_` directories) for a
`"reflect"` or `"unsafe"` string literal or a `//go:linkname` line, and reports
`unknown` instead. It does not parse Go, so a stray literal only adds a false
`unknown`. It does not look inside dependencies: a third-party library that
reaches the vulnerable symbol by reflection is still a blind spot.

The rule was written with this corpus in view, so these numbers are not a
held-out evaluation. Each truth label comes from one execution with fixed benign
input; a host labelled `not-executed` may still reach the symbol with other input.
Results describe these 40 self-authored hosts only, not arbitrary repositories.

## Tests

```bash
python3 -B -I -S -m unittest discover -s benchmarks/reachability -p 'test_*.py'
```

`test_corpus.py` checks the manifest, snapshot hashes, OSV range evaluation,
coverage labelling, OpenVEX parsing, the gates, and that the recorded summary
recomputes to the same metrics. It runs no Go command.
