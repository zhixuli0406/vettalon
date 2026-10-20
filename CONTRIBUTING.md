# Contributing to Vettalon

Thanks for your interest. This page covers where each kind of contribution goes and the quality bar. 繁中使用者：各節開頭附中文摘要。

## What's in this repo

> 這個 repo 是 Vettalon 的**開源核心**（Apache-2.0）：掃描、多模型分工與跨家族覆核、PoC 沙箱、SARIF、漏洞提交草稿。桌面 App、本機 dashboard 與企業報告產生器是另外的付費元件，不在這裡。

The open-source core: OSS scanners (semgrep / gitleaks / cargo-audit) plus an AI audit where modules are split between finder models and every candidate is challenged by a verifier from a **different model family**. Also SARIF output and local-only disclosure drafts. The desktop app, dashboard and the enterprise report generator are a separate paid product and are not part of this repository.

## Code contributions

> 中文摘要：Rust workspace；conventional commits；新功能與修 bug 要在同一個 PR 附自動化測試；本機 build/test/clippy 綠才算完成；行為變更要在同一個 PR 更新文件。

- **Setup**: `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings`. No real model is called in tests.
- **Style**: `cargo fmt`; match the file you are editing. For security or routing decisions, no unanchored `contains` and no raw byte-index string slicing.
- **Branches and PRs**: branch from `main` (`feat/…`, `fix/…`, `docs/…`, `chore/…`), open the PR against `main`. CI runs fmt, clippy and tests on Linux and macOS; desktop Windows builds use a separate pipeline. A separate Windows scanner process-limit job is configured; native and hosted execution evidence is tracked separately. A `fuzz` job runs each cargo-fuzz target for a short fixed time; if you change a parser that reads untrusted input, run its target locally too (see [fuzz/README.md](fuzz/README.md)).
- **Dependency updates**: Dependabot opens weekly PRs for Cargo, GitHub Actions, the trust tools' pip lock and the Docker base images. Maintainers apply them upstream and sync the result here, so a bot PR may be closed after the sync lands instead of being merged.
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) (`feat:` / `fix:` / `docs:` …).
- **Tests**: new functionality and bug fixes must include automated tests in the same PR (`cargo test`, or `python -m unittest` for the Python tools). A PR without tests must say why in its description.
- **Definition of done**: build + tests pass locally; behaviour changes update the docs **in the same PR** (README/CHANGELOG — stale docs are treated as bugs); add a `CHANGELOG.md [Unreleased]` entry.
- **Security gates fail closed**: if your change adds a permission/authz/parsing decision, the unknown case must DENY. A PR that loosens a gate needs an explicit rationale.

A core design rule you'll see enforced: **a model reply that breaks the contract is not silently repaired; one bounded re-query may be attempted before recording failure**, and **a refusal is recorded as a coverage gap, never rerouted to another model**. Please don't add fallbacks that work around either.

## Reporting issues

- **Bugs / features**: open a GitHub Issue (the bug form asks for your version, install method and OS).
- **Questions / show-and-tell**: use [Discussions](https://github.com/zhixuli0406/vettalon/discussions).
- **Security vulnerabilities in Vettalon itself**: report privately via [GitHub's vulnerability reporting](https://github.com/zhixuli0406/vettalon/security/advisories/new); see `SECURITY.md`. Do not open a public issue.
- **Vulnerabilities Vettalon found in *other* projects**: those go to that project's maintainers, not here. `vettalon disclose` drafts the report; it never sends anything.
- **A first task?** Issues labelled [`good first issue`](https://github.com/zhixuli0406/vettalon/labels/good%20first%20issue) are small and self-contained.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

By contributing you agree your contribution is licensed under the repository's license (Apache-2.0, see `LICENSE`).
