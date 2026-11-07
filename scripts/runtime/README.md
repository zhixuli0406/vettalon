# Versioned process capture

`process_capture_v2.py` is the small POSIX process-control closure extracted from the frozen reachability adapter: `digest`, `decode_status`, `invoke`, and `successful_run`. It contains no vulnerability-analysis, Go, cache, or scanner entry point. Its child supervisor is an exact copy of the frozen supervisor.

Python 3.11+ is required. `invoke` retains the original capture/status/cleanup contract and a default 120-second execution ceiling. An explicit `timeout_ceiling_seconds` may increase the ceiling to at most 600; requested timeout and ceiling must be positive finite numbers (ceiling an integer), with neither above 600. Boolean values are rejected. The effective deadline is `min(timeout, timeout_ceiling_seconds)`; shared cleanup remains at most one additional second. There is no universal OS-spawn/I/O deadline, setsid containment, CPU/RSS or full disk guarantee. Output caps default to 4 MiB stdout / 1 MiB stderr and overrides may only tighten them.

Claude Code plugin 0.2.0 no longer bundles this runtime or its supervisor: it is skills-only and invokes the installed CLI directly under the host's Bash approval policy and sandbox. The separate repo-root utilities remain available to other consumers. `integrations/claude-code/tests/test_process_capture_v2.py` still checks this repo-root implementation against the frozen functions: only the timeout signature, validation and deadline differ. Plugin bundle-parity tests were removed with the bundled runtime. The frozen adapter, supervisor, experiments and their pins remain unchanged.

Tests have been prepared; current RED/GREEN execution and root acceptance are recorded separately. No runtime validation is claimed by this README alone.
