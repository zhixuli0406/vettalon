# Versioned process capture

`process_capture_v2.py` is the small POSIX process-control closure extracted from the frozen reachability adapter: `digest`, `decode_status`, `invoke`, and `successful_run`. It contains no vulnerability-analysis, Go, cache, or scanner entry point. Its child supervisor is an exact copy of the frozen supervisor.

Python 3.11+ is required. `invoke` retains the original capture/status/cleanup contract and a default 120-second execution ceiling. An explicit `timeout_ceiling_seconds` may increase the ceiling to at most 600; requested timeout and ceiling must be positive finite numbers (ceiling an integer), with neither above 600. Boolean values are rejected. The effective deadline is `min(timeout, timeout_ceiling_seconds)`; shared cleanup remains at most one additional second. There is no universal OS-spawn/I/O deadline, setsid containment, CPU/RSS or full disk guarantee. Output caps default to 4 MiB stdout / 1 MiB stderr and overrides may only tighten them.

The Claude Code plugin carries exact-byte copies beside its own script, checked against reviewed digests before importing. It does not search the repository or download a runtime. The public `test_process_capture_v2.py` checks source parity against the frozen functions: only the timeout signature, validation and deadline differ. `test_runtime_bundle.py` checks bundle parity and a standalone installed copy outside the repository using a self-authored fake CLI. The old adapter, old supervisor, experiments and their pins remain unchanged.

Tests have been prepared; current RED/GREEN execution and root acceptance are recorded separately. No runtime validation is claimed by this README alone.
