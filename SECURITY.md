# Security policy

## Reporting a vulnerability in vettalon

Please report vulnerabilities in vettalon itself through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**, or go straight to
<https://github.com/zhixuli0406/vettalon/security/advisories/new>. Do not open
a public issue for a security bug.

If you cannot use GitHub, email <info@dudustudio.monster>. The same contacts
are published in
<https://vettalon.dudustudio.monster/.well-known/security.txt>.

Useful things to include: the vettalon version (`vettalon --version`), the
command you ran, the model backends in your roster (no keys), and the
smallest input that reproduces the problem.

You should get a first reply within 7 days. We aim to ship a fix within 90
days and will agree on a disclosure date with you.

## What counts

In scope: anything that makes vettalon itself unsafe to run on your code,
for example escaping the model or PoC sandbox, reading files outside the
scanned repository, leaking secrets or API keys into reports or model
prompts, or a scanned repository being able to make vettalon execute code.

Out of scope: vulnerabilities that vettalon reports in *other* projects.
Send those to that project's maintainers (`vettalon disclose` drafts a
report in the format their channel expects; it never sends anything).

## Model spend cap

`vettalon verify --spend-cap-usd` is a budget aid, not a billing guarantee. It
charges list prices from the price table you pass and trusts the token counts
the provider reports in `usage`; a provider that under-reports, a stale price
table or a call billed above its reservation (which can overshoot the cap once)
makes the real bill differ. Set a spend limit in each provider's console as
well, and treat the provider's invoice as the record.

## Known limits when scanning a repository you don't trust

Vettalon validates the repository's Git config before it runs `git`, and every Git process it starts allows only a transport protocol that does not exist, so no fetch or remote helper can start. It also overrides the settings it can name, such as `core.fsmonitor` and `core.hooksPath`, and points the files Git opens during reads (`core.excludesFile`, `core.attributesFile`, `mailmap.file`, `diff.orderFile`) at the null device with `log.mailmap=false`; those keys, and others that name a file or program Git may open or run (such as `core.pager`, `core.editor` or `http.sslCert`), are also refused in the repository's config. Config includes (`include.path`, `includeIf.*.path`) are refused, with one exception for the credentials that actions/checkout persists by default: on GitHub Actions (`GITHUB_ACTIONS=true` and an absolute `RUNNER_TEMP`), at most 16 `includeIf.gitdir:<…>.path` entries in `.git/config` (not `config.worktree`) are accepted when the value is exactly `<RUNNER_TEMP>/git-credentials-<lowercase uuid>.config` and the condition is `gitdir:` followed by the repository's own `.git` directory (as given or with symlinks resolved, forward slashes) or that directory plus `/worktrees/*`, or when the value is exactly `/github/runner_temp/git-credentials-<lowercase uuid>.config` and the condition is `gitdir:/github/workspace/<path>/.git` or that plus `/worktrees/*`, with no wildcard, `.` or `..` in `<path>`. Such a container include only fires for a repository under `/github/workspace`, so it never applies on a Windows or non-container host. The file must be a regular file (not a symlink) of at most 64 KiB that sets only `http.https://….extraheader`, or missing; its contents are never printed. On Unix a missing file under `RUNNER_TEMP` is trusted only when `RUNNER_TEMP` (followed if it is a symlink) is a directory owned by the current user that neither group nor others can write. On Windows a missing file is accepted: on hosted runners `RUNNER_TEMP` is in the runner's own work directory, and a self-hosted Windows runner whose temp dir other local users can write is out of scope. Git's own `git config` calls in this check pass `--no-pager` and run with a fresh, empty, private directory as both `--git-dir` and working directory (with an absolute config file path), so Git does not search for or read any repository during the check: it opens neither the scanned repository's include targets (to decide on a pager, or on macOS on `core.precomposeunicode`) nor `HEAD` or `commondir` in directories above its working directory. `.git/config` and `.git/config.worktree` must be regular files; a FIFO, socket or device there is refused instead of blocking the scan. Git opens many other files without checking their type, so before any Git command starts Vettalon also refuses a FIFO or device anywhere in `.git` (for example `HEAD`, `index`, `packed-refs`, `refs/`, `info/exclude` or a file under `objects/`; symlinks in `.git` are already refused) and a FIFO or device named `.gitignore`, `.gitattributes` or `.gitmodules` at the repository root or anywhere in the working tree, with `"<path>" is not a regular file` (the path is escaped). Sockets are accepted, since opening one fails instead of blocking and macOS Git's builtin fsmonitor keeps one in `.git`. These checks run on Unix, only use `lstat` and never open the files. A symlinked `.gitignore`, `.gitattributes` or `.gitmodules` in the working tree is accepted without looking at its target, so a target on an automounted network path is never touched by Vettalon; Git 2.32 and later does not follow symlinked `.gitignore` and `.gitattributes`, and any other read is bounded by the per-command Git timeout. The working-tree check covers the three root files first, then walks the tree, skipping only entries named exactly `.git` and never following directory symlinks, and stops without refusing after 200,000 entries, 50,000 directories or a depth of 256 (a FIFO past those bounds only stalls a Git command until its timeout). Three gaps remain:

- Filter drivers (`filter.<name>.clean`, `filter.<name>.process`) can have any name, so they cannot be overridden up front. If another process rewrites `.git/config` while a scan runs, a working-tree diff could start a clean filter. Scan a copy that nothing else writes to during the scan.
- A repository whose remotes use a custom remote helper (for example `codecommit://`, `s3://`, `persistent-https://` or `hg::`) is refused before Git runs, and so is one with more than 256 URL rewrite rules or whose rewrite checks would read more than 16 MiB. Only lowercase `http`, `https`, `ftp`, `ftps`, `ssh`, `git`, `file`, `git+ssh` and `ssh+git` URLs are accepted. Git history, diff scope and bisect are then unavailable for that repository.
- Git older than 2.31 ignores the command-scoped overrides (`GIT_CONFIG_COUNT`). With such a Git only the config check before the scan applies; transports stay blocked.

`vettalon intake` treats the pasted report as untrusted input. Its text is never sent to a model, a container or any service, and its PoC is never run; reproduction uses only a TargetCall the operator wrote. A path in the report becomes a claim location only if it is a regular file tracked in the Git index (no `.git` path, secret file, file over 4 MiB, FIFO or other repository's GitHub URL). One limit remains: a report can choose which tracked file inside the repository has a window sent to the model you configured. That is bounded by the review window (at most 10 files) and every file is listed in `files_sent_to_model`. Intake never sends a reply or submits anything.
