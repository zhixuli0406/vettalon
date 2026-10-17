# Synthetic linkage process capture — next-release preview

The fixed synthetic linkage tool now uses the reviewed versioned process runtime
in `scripts/runtime/`. It does not add candidate generation, a general exploit
runner, model calls, image downloads, or automatic finding confirmation.

繁中摘要：本改動只補主機程序控制。歷史五組自建差分保留原版本；新版控制器
與原始收據不能用來回填舊資料的未知欄位，也不代表真人確認或真實目標成立。

## Fresh receipt contract

Every validator/Docker command uses the same pinned capture helper and its
supervisor. Missing, changed, or symlinked runtime files fail before a child is
started. There is no runtime lookup or download fallback. Launch implementation
bindings include both helper files and are checked again before bundle creation.

The `vettalon-link-process-v2` receipt retains the actual helper result under
`process`, including control, cleanup, exit, text, captured byte counts/digests,
and base64 for retained invalid UTF-8. Outer fields are exact projections; a
validator rejects conflicting command, exit, time, stream text, or cap metadata.
It requires complete controls, exit zero, strict UTF-8 and consistent capture
hashes. Missing nested controls are rejected by this fresh-run validator;
historical receipts remain historical and are not rewritten. If helper validation
fails during cleanup, the partial container row and its typed cleanup error are
retained; a lost cleanup path cannot produce a verified manifest.

A normal nonzero exit is preserved for its caller to handle. Validation uses a
temporary in-memory view only to check complete control of that observation;
the saved exit/error are never normalized to success. Timeout, invalid UTF-8,
truncation, unknown control/cleanup, or output overflow raises `CommandFailure`
with the actual nested receipt. No automatic retry is performed.

## Resource and environment limits

The successful combined stdout/stderr limit remains 256 KiB. Each stream has a
256 KiB capture limit, so a failed observation can retain up to 512 KiB. The
combined acceptance check occurs after invocation; this is **not** an immediate
combined-stream kill threshold. Tightened test caps follow the same rule.

The existing run/command admission ceiling is 300 seconds; fixed execution
phases use their smaller limits. The shared process cleanup allows at most one
additional second. Existing container cleanup has a separate 15-second allowance
even after the run deadline. These are not a hard whole-batch OS wall guarantee.
Deliberate process-group escapes, external reapers, blocking OS spawn/I/O,
CPU/RSS, and disk writes outside bounded artifacts remain outside this contract.

Child environment forwarding is limited to HOME, PATH, TMPDIR, LANG and LC_ALL.
Provider keys and Docker endpoint/context environment overrides are not forwarded.
Commands run from the trusted tool directory; Docker still requires the explicit
local Unix socket. This is not proof of host filesystem/credential containment.
A helper preflight failure can leave an empty newly owned output directory;
absence of `checks.json` is not success and that directory must not be reused.

## Verification boundary

Nine new process methods passed using self-authored host children: caps,
aggregate acceptance, invalid UTF-8, timeout, inherited-pipe descendants, nonzero
exit preservation, pre-spawn rejection, environment filtering, and receipt
mutation. Eighteen existing linkage methods passed with clearly marked unit
transport stubs. They are not Docker execution evidence.

The 28-method attempt had one unchanged Unix-socket fixture error: first the
owned temporary path was too long; the targeted short-path attempt was denied
by the same no-network policy. Both failures remain recorded. This fixture was
not passed or silently skipped, and the policy was not relaxed. Therefore the
whole suite is not reported green. No new live container/model/target run or
line/branch coverage percentage is established by this preview.

The changed process methods can be selected independently:

```bash
python3 -B -I -S -m unittest discover -s benchmarks/differential-poc -p test_process_command.py -v
```

These are trusted process-control fixtures, not execution of scanned source.
The tool remains limited to its fixed self-authored synthetic candidates,
unsigned operator-supplied evidence and explicit human review boundaries.
