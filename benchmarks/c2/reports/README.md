# C2 results

Two runs made on 2026-11-13/14 (UTC) with the C2 harness. Every file here was produced
by its `run_calibration.py export --calibrate` or `snapshot.py summarize` step and
copied unchanged. The harness scripts are not published yet; the scored item list is
`../items-v1.json` and `calibration.json` uses the `vettalon.calibration/1` format. No
prompt or model reply text is included.

Spend (list prices and provider-reported usage, not invoices): US$28.65 in total on
the shared ledger, of which US$23.33 for the calibration rows exported here and US$2.72
for the snapshot. The rest went to earlier attempts whose rows were not kept (a first
measure pass with wrong request parameters and a run halted by a reservation bug, both
fixed in the harness before the run reported here).

## `c2-s-2026-11-14/`: calibration on SastBench

120 SastBench v0.1 items (`../items-v1.json`, 20 of them injected), each reviewed by
three verifier families (Anthropic `claude-sonnet-5-5`, OpenAI `gpt-6.1-sol`, xAI
`grok-4.7`) with three refuter runs per item. All 360 item/judge rows finished `ok`;
none were excluded. 31 item/judge pairs had no usable run (every run returned no
verdict) and are left out of ECE and Brier, as `calibration.md` states.

Majority verdict against the label, per judge (pairs with at least one verdict):

| Judge | real vulnerability kept | false positive refuted | runs without a verdict |
|---|---|---|---|
| claude-sonnet-5-5 | 21/54 | 50/57 | 45/360 |
| gpt-6.1-sol | 23/53 | 32/50 | 66/360 |
| grok-4.7 | 17/58 | 54/57 | 28/360 |

What the numbers say:

- All three judges lean towards refuting. They remove most false positives, and they
  also refute more than half of the real vulnerabilities.
- 28 of 59 real vulnerabilities were refuted by all three judges (Wilson 95%
  0.353–0.600). Agreement of three vendors is not evidence that a finding is false.
- Injection recall was 4/20, 7/20 and 4/20.
- n_eff/k is 0.44: the judges make correlated errors, so three votes count as about
  1.3 independent ones.

## `c2-snapshot-2026-11-14/`: one public repository

pallets/werkzeug at `6604c3b8784ecc7cf5ac0b7412d916989b4c7d45` (BSD-3-Clause), scanned
with opengrep 1.33.1 (opengrep-rules `f1d2b562b414783763fd02a6ed2736eaed622efa`, Python
rules) and bandit 1.9.4. `manifest.json` pins the tree digest, both SARIF hashes and the
exact commands; `subset.json` lists the 74 results reviewed (46 + 28, no sampling was
needed). The verifier was `claude-sonnet-5-5`.

The model refuted all 74 results. Six (SHA-1 use, CWE-327) stay `needs_human` because
the per-CWE trust policy does not let a model alone close a crypto finding; the summary
counts those as `maintained`. There are no labels for this run, so the refuted share
says how much the verifier would remove from a scanner's output, not how much of that
output is noise. Read it together with the calibration above: the same model refuted
33 of 54 real vulnerabilities there.

## Limits

- "Refuted" is a model judgement, not ground truth.
- No PoC ran, so nothing here is execution-confirmed.
- 120 items is a process check of the pipeline. The ECE bins are thin and the
  calibration numbers are descriptive only.
- Labels are the SastBench v0.1 dataset's own; this run did not re-check them.
