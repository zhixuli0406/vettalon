# Public coverage fixtures

These ten cases use self-built source and fixed loopback model replies. They test report contracts, not detection quality. Environment-specific engine diagnostics are explicitly redacted in the checked-in samples; statuses, scope and counters remain.

Run from the repository root:

```bash
cargo build -p vettalon
python3 fixtures/coverage/generate.py --binary target/debug/vettalon --output /tmp/vettalon-coverage-new
```

Use a new output directory. Each subprocess has a 30-second ceiling; only the time-budget case intentionally delays a fixed reply. Scans retain module, candidate and shared-deadline safety caps. The mock receives disposable fixture source only. Optional external scanners may access their own databases; no real model or automatic PoC runs.

See [contract reference](../../docs/COVERAGE.md) and [observed cases](samples/index.json). Both complete and incomplete reports are valid report shapes; valid does not mean safe or fully scanned.
