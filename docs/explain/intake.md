# intake: One pasted vulnerability report checked as a single claim

## What it means

`vettalon intake <PATH> --input report.md --out intake.json --verifier <ID>` reads one vulnerability report (Markdown or plain text, UTF-8, at most 256 KiB; `--input -` reads stdin), turns it into a single `vettalon.claims/1` claim (id `intake-1`, `source: "intake"`), runs the `verify` refuter on that claim and writes `vettalon.intake/1`. With `--claims-only` it stops after writing the claim and makes no model call.

Extraction uses fixed rules and no model. It finds Markdown sections (summary, details, PoC, impact), CWE ids written as `CWE-<n>`, GitHub blob URLs and path tokens such as `src/app.py:42`. There is no keyword-to-CWE guessing. The CWE comes from `--cwe`, else the only one mentioned, else the first one the trust policy caps, else the first one mentioned. The report text never goes into a prompt: the refuter sees only the CWE, the checked `file:line` and a neutral title such as `CWE-78 ... reported at src/app.py:42` (or your `--title`). The reporter's own severity is ignored; `--severity` defaults to `medium`.

Every location goes through the same check: a safe repository-relative path, no `.git` component (any case, Windows aliases such as `GIT~1` included, before and after symlinks), not a secret file, a regular file of at most 4 MiB (no FIFO or device), and a line inside the file. A location taken from the report must also be tracked in the Git index, both as written and after symlinks. GitHub URLs for another repository are refused (`foreign_repository`). In a linked Git worktree, or when the index cannot be read, `extraction.tracked_check` is `git_unavailable` and every location from the report is refused as `untracked`. `--location FILE:LINE` (repeatable, at most 10) replaces the report's locations and does not need the index. A refused candidate keeps only its reason and `token_sha256`, a digest of the raw text; an accepted one keeps the `file:line` Vettalon rendered.

`intake.json` stores the report's SHA-256, size, format and sections, not its text, plus a masked `report_summary` of at most 300 characters. It also holds the claim, the embedded `verify` output, `reproduction`, `scope_check`, `duplicates`, a `triage` block (`located`, `refuter`, `trust_policy_capped`, `reproduction`, `possibly_out_of_scope`, `possible_duplicates`), `files_sent_to_model` and `limits` text describing the run’s data sharing. `--out`, `--claims-out`, `--receipt-out` and `--trace` must all be new, distinct files (written 0600).

`--target TARGET.json --receipt-out R.json` reproduces the claim from a TargetCall you wrote, as `reproduce --target` does, only for Python command injection, path traversal and SQL injection (CWE-78/77, 22/73, 89) and only when the TargetCall names the claim's file. Other classes are `unsupported_class` and start no container. The report's PoC is never run and never turned into a TargetCall. `--check-duplicates` adds the read-only OSV and GitHub lookups that `disclose --check-duplicates` makes. The pasted report text is never sent to the model provider or duplicate lookup services. When the model is called, tracked repository source windows are sent to the configured provider; `limits` records their count and `files_sent_to_model` lists their files. When duplicate queries run, `limits` names the contacted services (OSV and/or GitHub); missing project metadata can cause a lookup to be skipped. No vulnerability report is submitted.

## Why you see it

You ran `vettalon intake` on a vulnerability report someone sent you.

## What to do

Read the summary lines. On "no verified location", look at the `reason` of each record in `extraction.locations` and rerun with `--location FILE:LINE`. Exit status 0 means the run finished (any verdict), 1 means no verified location or an `incomplete` run, and 2 means refused input or an error; the reproduction result never changes it.

Do not read more into the result than it says. `refuted` does not mean the report is false. `effect_absent` or `inconclusive` does not mean the issue is not exploitable. `possibly_out_of_scope` is a hint from the project's policy files; a person decides. No duplicate found does not mean the issue is new, since private reports are invisible. A report can choose which tracked file window inside the repository is sent to your model; check `files_sent_to_model`.

## Related

[refuted](refuted.md), [trust_policy](trust_policy.md), [poc_oracle](poc_oracle.md), [read_failed_or_outside_repository](read_failed_or_outside_repository.md).
