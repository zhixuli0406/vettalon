# Vettalon

Vettalon audits your own source code with open-source scanners and, in deep
mode, an adversarial multi-model review. One model family finds candidates and
a different family tries to refute them before they are retained for human
review.

This npm package installs the prebuilt Vettalon CLI for supported macOS and
Linux platforms. The platform binary is delivered by an optional
`@vettalon/*` package with the same version.

## Install

```bash
npm install --global vettalon
vettalon --version
```

Supported targets:

- macOS arm64 and x64
- Linux arm64 and x64

Windows is not currently supported. Building from source requires Rust 1.88 or
later; see the [repository README](https://github.com/zhixuli0406/vettalon#install).

## Quick start

```bash
# Deterministic scanner pass. Optional local scanners run when installed.
vettalon scan .

# Add the multi-model audit and write machine-readable reports.
vettalon scan . --profile deep --report report.json --sarif report.sarif
```

Deep mode requires at least one configured model. Sandboxed proof-of-concept
execution additionally requires Docker and a pre-pulled image. Installation,
model setup, exit codes, and security boundaries are documented in the
[full README](https://github.com/zhixuli0406/vettalon#readme).

## Data and trust boundaries

The default scanner pass operates on the local checkout, but optional scanners
can have their own update or network behavior. Deep mode sends the source
fragments needed for review to the model providers you configure. Review the
[data-flow documentation](https://github.com/zhixuli0406/vettalon/blob/main/docs/DATA-FLOW.md)
before using it on sensitive code.

Findings marked `needs_human` are candidates, not confirmed vulnerabilities.
Use the JSON/SARIF evidence and reproduce the issue before disclosure.

To verify npm registry signatures and provenance in a project that installs
Vettalon:

```bash
npm audit signatures
```

Release verification details are in the
[trust guide](https://github.com/zhixuli0406/vettalon/blob/main/docs/TRUST.md).

## License

Apache-2.0. See the [repository license](https://github.com/zhixuli0406/vettalon/blob/main/LICENSE).
