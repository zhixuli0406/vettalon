# Toolchain audit reference

`vettalon toolchain` audits what your coding agents have installed: Claude Code skills, Claude Code plugins (skills, hooks, bundled MCP configs), MCP server entries for Claude Code and Codex, and Codex skills. It runs locally, makes no network requests unless `--online` is given, and never executes the audited items. It reports suspicious content, records content hashes you approve, and flags items whose content changed after approval.

This document is the behaviour contract for the first release (phase 1). Semantic model review and sandboxed MCP launch with egress logging are planned as later phases and are not part of phase 1.

## Commands

```text
vettalon toolchain audit [--project PATH] [--scope user|project|all] [--agent claude|codex|all]
                         [--format text|json|sarif] [--out PATH] [--fail-on SEVERITY]
                         [--allow-incomplete] [--online] [--max-file-bytes N]
vettalon toolchain pin   [--project PATH] [--scope ...] [--agent ...] [--item ID]... [--accept-risk]
vettalon toolchain pins  [--format text|json]
```

- `audit` discovers items, runs static rules, compares against pins and prints a report. It never writes pins.
- `pin` records the current content hash of the selected items (all discovered items when no `--item`). It refuses to pin an item that has a `high` or `critical` finding, or whose content could not be read completely, or that contains a bundled dependency tree (TC011; those trees are tracked by size/mode only, so same-size replacements are not detected), unless `--accept-risk` is given; the refusal lists the item ids, pins nothing and exits `1`. An unknown `--item` id exits `2`.
- `pins` lists pinned items, their item hash, file count, pin time and whether the item is still present. It never lists per-file hashes.
- `--project` defaults to the current directory. `--scope all` (default) covers user-level and project-level locations.
- `--fail-on` defaults to `high`. An incomplete audit is never reported as clean: the summary says `complete: false` with reasons, and by default it fails closed.
- `--out` writes a new file with mode `0600` and refuses existing paths and symlinks.

Exit codes of `audit` (the report is always printed or written first):

| Code | Meaning |
| --- | --- |
| `0` | the audit is complete and no finding is at or above `--fail-on` (with `--allow-incomplete`: no finding at or above `--fail-on`, complete or not) |
| `1` | at least one finding at or above `--fail-on` (whether or not the audit is complete) |
| `2` | no finding reached `--fail-on` but the audit is incomplete (any `incomplete_reasons`: `unreadable`, `limit_reached`, `global_limit_reached`, `changed_during_read`, symlink or install-path refusals, config parse errors, MC002 without a MAL index, …), unless `--allow-incomplete`; or an argument, I/O or pin-store error (integrity, location, owner/mode, malformed store) |

`pin` exits `1` when it refuses (see above) and `2` on argument, I/O or pin-store errors; `pins` exits `2` on pin-store errors. `--allow-incomplete` restores threshold-only behaviour for CI that has reviewed the remaining reasons.

## Discovery

Home is the user's home directory. For tests, the hidden environment variable `VETTALON_TOOLCHAIN_HOME` replaces it.

| Agent | Kind | Location |
| --- | --- | --- |
| claude | skill (user) | `~/.claude/skills/**/SKILL.md`, depth ≤ 4 below `skills/` |
| claude | skill (project) | `<project>/.claude/skills/**/SKILL.md`, depth ≤ 4 |
| claude | plugin | each install in `~/.claude/plugins/installed_plugins.json` → `plugins.<name>[].installPath`; inside it: `skills/**/SKILL.md`, `hooks/hooks.json`, `.mcp.json`, `.claude-plugin/plugin.json`. When the manifest is missing or unreadable, fall back to scanning `~/.claude/plugins/cache/*/*/*/` and mark the audit incomplete. |
| claude | mcp (user) | `~/.claude.json` → `mcpServers`; `projects.<path>.mcpServers` for the selected project is reported with scope `project` |
| claude | mcp (project) | `<project>/.mcp.json` → `mcpServers` |
| codex | mcp | `~/.codex/config.toml` → `[mcp_servers.<name>]` (`command`, `args`, `env`, `env_vars`, `url`) |
| codex | skill | `~/.codex/skills/**/SKILL.md` and `~/.agents/skills/**/SKILL.md`, depth ≤ 4 |

A skill item is the directory containing `SKILL.md`; all regular files in it are content. A plugin item's content is the regular files under its `skills/`, `hooks/` and `.claude-plugin/` directories plus `.mcp.json`; `hooks.json`, `.mcp.json` and `plugin.json` are parsed and their hook commands, MCP entries and descriptions are checked structurally (their raw text only gets TC007). The report records the resolved path.

Scope boundaries (every audited file, config and the project are treated as attacker-controlled):

- `<project>/.claude/skills` must be a real directory (not a symlink) whose canonical path is inside the canonical project; otherwise it is not read (`symlink_not_followed:<path>` or `symlink_outside_trusted_roots:<path>`). `<project>/.mcp.json` is read only when it resolves inside the project.
- A symlinked entry under a skills root is followed only when its canonical target is inside the same skills root, inside the canonical project, or (user roots only) inside the canonical `~/.claude/`, `~/.codex/` or `~/.agents/`. Project roots allow only the project. Anything else is not read and marks the audit incomplete: `symlink_outside_trusted_roots:<display path>`.
- A plugin `installPath` from `installed_plugins.json` must canonicalize strictly inside the canonical `~/.claude/plugins/`; otherwise the plugin is reported with `install_path_outside_plugins_root` and nothing under it is read.
- Inside an item, a symlink is followed only when the target stays inside the item (`symlink_outside_item:<path>` otherwise).

Limits. Directories are streamed, never loaded whole: every directory entry (file, directory, empty directory, anything else) counts against 20,000 entries per item and per discovery root, and 500,000 entries audit-wide; at most 5,000 directories are entered per item or root. Names are collected up to the cap and sorted within that bound. Per item also: 5,000 files and 32 MiB read; audit-wide 200,000 files and 1 GiB read. Hitting an item limit stops reading that item and marks it `incomplete` (`limit_reached:<path>`); hitting a global cap marks the current and remaining items `global_limit_reached`. Unreadable files are `incomplete` (`unreadable`), never skipped silently.

Reads. A content file is opened with `O_NOFOLLOW | O_NONBLOCK` (Unix), the opened descriptor is `fstat`ed (regular file, same device and inode as the earlier `lstat`, same size, checked again after the read), and at most `min(8 MiB, remaining budget)` bytes are read; the budget is charged with the bytes actually read. A size or identity change marks the item `changed_during_read:<path>`.

Paths. Relative paths are identified by their raw bytes (Unix `OsStr` bytes); in reports and pins, invalid UTF-8 bytes, `%` and control/invisible characters are percent-encoded (`%XX`), so distinct names stay distinct and the encoding is reversible.

Item ids are stable strings: `<agent>:<kind>:<scope>:<name>`, where name is the skill directory name, `plugin@marketplace/version` for plugin parts, or the MCP server key. Collisions get a `#<n>` suffix in discovery order.

## Content hash and pins

- Skill and plugin items: SHA-256 over the sorted list of `(raw relative path bytes, file digest)` pairs. Hidden files are included. The file digest is the SHA-256 of the content, except for secret-bearing files (see TC012), whose digest is `hmac:` + HMAC-SHA256 under the local key. Dependency trees (`.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `site-packages`, `dist-packages`, `.tox`, `.mypy_cache`, `.pytest_cache`) anywhere inside an item are walked without reading contents or running file/text rules. Only the outermost matching directory gets TC011; a dependency tree does not by itself make the item incomplete. Their files and entries count toward the caps; their sorted relative paths, sizes and Unix mode bits (where available) are hashed as metadata records instead of content, and retained in pins so PN001 can name changed paths. Same-size content changes inside these trees are not detected.
- MCP entries: SHA-256 of the canonical JSON of the entry, where every value under `env`, `headers`, any key matching the secret-name pattern, every secret-shaped argument and every URL userinfo / query / fragment value is replaced by `hmac:` + its HMAC-SHA256 under the local key before hashing. Secret values are never stored, and their digests cannot be checked against guesses without the key.
- Local key: `$VETTALON_HOME/toolchain/key`, 32 random bytes, mode `0600`, created with `create_new` on first use by any `toolchain` command. It must be a regular file owned by the current user with no group/other access. Removing it makes pins of MCP entries with secrets and of items with secret-bearing files show as changed.
- Pin store: `$VETTALON_HOME/toolchain/pins.json` with a `pins.json.sha256` sidecar, directory mode `0700`, files `0600`, atomic replace. Every command refuses (exit `2`) when the canonical store is inside the canonical `--project` (or current directory for `pins`) — unless that project is the canonical user home (the one discovery uses: `VETTALON_TOOLCHAIN_HOME`, else `HOME`) or an ancestor of it, e.g. running from `~` with the default `~/.vettalon` — when `$VETTALON_HOME` or `$VETTALON_HOME/toolchain` is a symlink, or (Unix) when the store directory or a store file is not owned by the current user or is group/world-writable. Files are opened with `O_NOFOLLOW`, checked on the opened descriptor (regular file; `pins.json` ≤ 64 MiB; sidecar ≤ 128 bytes and exactly 64 lowercase hex digits plus an optional newline) and read with a hard cap. On load, every pin is schema-checked (hashes `sha256:`/`hmac:` + 64 hex, RFC 3339 `pinned_at`, ids/paths/projects without control or invisible characters); a malformed store is exit `2`. Every pin field is cleaned again before text output.
- The sidecar is a corruption checksum, not tamper-proofing: anyone able to write the store can rewrite both files. A mismatch is exit `2` with a message; the audit does not silently trust the store. A keyed MAC over the store is future work.
- Each pin keeps the per-file hash list so `audit` can name added, removed and modified files (paths only, no content) when the item hash changes. MCP pins keep one hash per top-level field instead, so PN001 names the changed fields. Project-scope pins are keyed by item id and project path.

## Rules

Each finding has `rule`, `severity`, `item`, `file` (display path with `~`), `line` (when known), `message` and a masked `excerpt` of at most 200 characters. Every excerpt and message passes through `util::mask_sensitive_text`; MCP env, header and secret-named values are never printed, only `<redacted:` + 8 hex of their keyed HMAC + `>`. Every displayed URL (MCP `url`, URL arguments, URLs inside excerpts and messages) has its userinfo and every query and fragment value replaced by `<redacted>` whatever the key name (`https://<redacted>@host/p?code=<redacted>&sig=<redacted>`); scheme, host, port, path and keys stay. Findings in a secret-bearing file (TC012) carry the fixed excerpt `<excerpt omitted: secret-bearing file>`, and text-rule findings there get the rule description instead of a content-derived message.

| Rule | Applies to | Severity | Trigger |
| --- | --- | --- | --- |
| TC001 fetch-and-execute | skill/plugin text, hook commands, MCP command+args | high | download piped or substituted into an interpreter (`curl … \| sh`, `wget -O- … \| bash`, `bash <(curl …)`, `iex (iwr …)`, `python -c "$(curl …)"`) |
| TC002 encoded payload | same | high when decoded output is executed, else medium | `base64 -d`/`--decode` or `atob` feeding a shell or `eval`; base64 runs ≥ 200 chars in instruction text |
| TC003 exfiltration endpoint | same | high | `api.telegram.org/bot`, `discord.com/api/webhooks`, `hooks.slack.com`, `webhook.site`, `requestbin`, `pipedream.net`, `ngrok` hosts, paste sites, raw IPv4 URLs |
| TC004 persistence | same | high; medium under `examples/`, `docs/`, `references/` or README* | command forms of `crontab` (`-e`, `-l`, `-r`, file, pipe), `launchctl load/bootstrap/enable`, `systemctl --user enable`, appending to shell rc files, writes to `Library/LaunchAgents`, `Library/LaunchDaemons` or `authorized_keys`; prose mentions alone do not match |
| TC005 credential access | same | high | concrete SSH key, AWS, gcloud credential-file, Claude credential or Codex auth paths; browser `Cookies` paths under Chrome/Brave/Edge/Chromium profiles, `cookies.sqlite`, `Library/Cookies/Cookies.binarycookies`, `Login Data`, `key4.db`; `security find-generic-password`, `find-internet-password`, `dump-keychain`. Bare cookie/token/credential words do not match |
| TC006 oversized content | skill/plugin files | low | a text file larger than `--max-file-bytes` (default 1 MiB) or a line longer than 10,000 chars. Text is scanned up to 8 MiB; anything beyond is unscanned and the item is incomplete. Binary files are hashed but excluded from TC001–TC009 (including TC006); TC010 still applies outside dependency trees. Binary means a NUL or invalid UTF-8 in the first 8 KiB (allowing a truncated multi-byte sequence at that boundary), or an extension in `png jpg jpeg gif webp ico svgz mp3 wav ogg flac m4a mp4 mov webm woff woff2 ttf otf zip gz tgz bz2 xz 7z pdf`. |
| TC007 hidden characters | skill/plugin text | medium, high for bidi controls | invisible/zero-width characters, bidi overrides, ANSI escapes, Latin tokens mixed with Cyrillic/Greek Latin-confusable letters; ordinary Greek math letters such as Δ and π do not match |
| TC008 prompt injection | skill/plugin instruction text, MCP tool and plugin manifest descriptions | Markdown: medium at most; info under `evals/eval/tests/test/fixtures/examples` or for quoted injection phrases on defensive lines. Manifest descriptions: high when `scan_input` blocks on `instruction_override` or `role_hijack`, otherwise medium | `scan_input` plus `audit::injection` signals; quoted text with EN/ZH negation markers is informational when no unquoted injection remains. Command-oriented signals are covered by TC001–TC005 |
| TC009 prerequisite trap | skill/plugin instruction text | medium | a before/first/prerequisite/setup phrase plus an executable action on the same line or next 3 lines: curl/wget/iwr, npm install/i, pnpm add, pip install, uv pip, brew install, git clone, bash/sh/python script, chmod +x, or a link to .sh/.ps1/.py/.exe/.pkg/.dmg/.zip/.tar.gz. YAML frontmatter is ignored |
| TC010 bundled executable | skill/plugin files outside dependency trees | medium | ELF, Mach-O or PE magic, `.so/.dylib/.dll/.exe`, or executable-bit files without a recognized script format. Text with a shebang or files with `.sh/.bash/.zsh/.py/.js/.mjs/.cjs/.ts/.rb/.pl/.ps1` are exempt from the executable-bit check everywhere |
| TC011 bundled dependency tree | skill/plugin directories | medium | one finding per outermost dependency tree, with file count and total size; contents are not scanned (metadata is hashed), which by itself does not make the item incomplete. Pins of dependency trees detect added/removed/resized/mode-changed files only, not same-size content changes, so `pin` refuses such items without `--accept-risk`. Counts are limited to visited files when a walk limit is reached. |
| TC012 secret-bearing file | skill/plugin files outside dependency trees | medium | one finding per file whose name (case-insensitive; the link name or its in-item target) is `.env` or `.env.<suffix>` (except suffixes `example`, `sample`, `template`, `dist`, `defaults`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*` (never `*.pub`), `credentials`, `credentials.{json,ini,toml,yaml,yml}`, `.npmrc`, `.pypirc`, `.netrc`, `auth.json`; or that contains `secret` or `token` and has no extension or one of `txt json yaml yml toml ini conf cfg dat key`, and does not end (before the extension) in `example`, `sample`, `template`, `dist` or `defaults`. Script/source/style names such as `refresh_token.sh` or `tokens.css` are not flagged; `tokens.json` is (documented trade-off). Templates such as `.env.example` are not secret-bearing, so their (masked) excerpts may be shown. All rules still run on it; its findings' excerpts are withheld and its content digest is keyed |
| MC001 unpinned launcher package | MCP stdio entries | medium | `npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run` without an exact version (missing, `latest`, ranges) |
| MC002 npm malicious signal | MCP entries launched via npm | critical for a strong hunt signal (MAL-ID, security holding package), high for a hunt finding from two medium signals or an unpinned package whose name is in the MAL index, medium for a single signal | `hunt::malicious::offline_check` (local MAL index + typosquat). With `--online`, also `registry_signals` and OSV through the existing allowlisted hosts. Without a MAL index the check is recorded as incomplete. |
| MC003 insecure remote | MCP url entries | high | `http://` to a non-loopback host |
| MC004 inline secret | MCP entries | medium | literal secret-shaped values in `env`, `headers` or `args` (values redacted in output) |
| MC005 risky command path | MCP stdio entries | medium | command under `/tmp`, `/var/tmp`, a world-writable directory, or a relative path |
| MC006 unparseable package spec | MCP entries launched via npm | medium | the npm spec is not a valid `name[@version]`: names must match `^[a-z0-9][a-z0-9._~-]*$` or `^@[a-z0-9][a-z0-9._~-]*/[a-z0-9][a-z0-9._~-]*$`, be at most 214 characters and contain no `..`; a version must match `^[A-Za-z0-9.+_-]{1,64}$` (exact semver or dist-tag; ranges are unparseable). Validation happens before any lookup URL is built; such a spec is never looked up and MC002 is not evaluated for it. The spec is shown redacted |
| PN001 changed since pin | any pinned item | medium | item hash differs from its pin; message lists changed file paths |
| PN002 unpinned item | any | info | discovered item with no pin |
| PN003 pinned item missing | pins | info | pinned item no longer discovered |

Rules are regex and structure based, deliberately conservative, and versioned as `RULES_VERSION = "tc-rules-1"`. A clean result means "no rule matched", not "safe". Prompt-injection findings use the context-dependent severity described above.

## Report

JSON schema id `vettalon.toolchain/1`:

```json
{
  "schema": "vettalon.toolchain/1",
  "vettalon_version": "x.y.z",
  "rules_version": "tc-rules-1",
  "generated_at": "RFC 3339",
  "scope": {"agents": ["claude","codex"], "scopes": ["user","project"], "project": "~/…"},
  "online": false,
  "items": [{"id": "…", "agent": "claude", "kind": "skill", "scope": "user", "path": "~/…",
             "hash": "sha256:…", "pin": "match|changed|unpinned", "files": 12, "complete": true}],
  "findings": [{"id": "TC001:<item>:<n>", "rule": "TC001", "severity": "high", "item": "…",
                "file": "~/…", "line": 14, "message": "…", "excerpt": "…"}],
  "summary": {"items": 0, "findings_by_severity": {}, "complete": true, "incomplete_reasons": []}
}
```

An incomplete item also carries `incomplete_reasons`; `files` is `1` for MCP entries (the config file). `pins --format json` emits `{"schema": "vettalon.toolchain-pins-list/1", "pins": [...]}` where each pin has `id`, `agent`, `kind`, `scope`, `project` (project pins), `path`, the item `hash`, `pinned_at`, `files` (the number of file or field records) and `present: true|false`, or `null` for a pin of another project. Per-file hashes are never listed.

`--format sarif` emits SARIF 2.1.0 with one rule per rule id and `~`-relative artifact URIs. Text output groups findings by item, highest severity first, in the CLI language (`tr!`).

## Privacy and safety

- No network unless `--online`; `--online` only contacts hosts already in `hunt::fetch::ALLOWED_HOSTS` and `api.osv.dev`.
- Audited content is data. It is never executed, never passed to a shell, and phase 1 sends nothing to any model.
- Absolute home paths are shown as `~`. Secret values never appear in output, pins or logs; digests of secret values and of secret-bearing files are keyed with the local key so low-entropy secrets cannot be guessed offline from them.
- File reads are bounded; parsing failures of JSON/TOML manifests are reported per file and mark the audit incomplete.
