# CBOM fixtures

Inputs for `vettalon cbom-check` (experimental; see [docs/CBOM-CHECK.md](../../docs/CBOM-CHECK.md)).

| Path | What it is |
|---|---|
| `sample-py/` | A tiny hand-written Python app (`app/keys.py`, `app/main.py`) that uses the `cryptography` package. |
| `sample-py.cbomkit.json` | The CBOM that PQCA CBOMkit produced for `sample-py/`. Real tool output, not edited. |
| `sample-java/` | A tiny hand-written Java project in Maven layout (`src/main/java/com/ex/{Main,Crypto,Unused,Unlisted}.java`). |
| `sample-java/hand.cbom.json` | A **hand-written** CycloneDX 1.6 CBOM for `sample-java/`. It follows the structure of the CBOMkit output above, but it is **not** real CBOMkit output. It sits inside the project root on purpose: `cbom-check` leaves the `--cbom` file out of the Java config-file scan, so the class names in its locations (`.../com/ex/Unused.java`) do not give `named_in_config_file`. |

## Provenance

`sample-py.cbomkit.json` was generated on 2026-11-09, offline, with the image
`ghcr.io/cbomkit/cbomkit-action:edge`, digest
`sha256:7dfc905c614549fdb630d41a33b34a039af7f60c982501c6d74dfc63ef700512`,
run against `sample-py/` mounted as the workspace. CBOMkit prefixes every
occurrence location with the workspace directory name (`ws/app/keys.py`), which
is why `cbom-check` strips leading path components when mapping a location onto
`--root`.

## Expected labels

### `sample-py/` (real CBOMkit output)

| Asset | Where | Label | Why |
|---|---|---|---|
| RSA-2048 and its private-key | `app/keys.py:8` | `reachable` | `main.py` `__main__` block -> `main()` -> `make_signing_key()` |
| EC-secp256r1 and its private-key | `app/keys.py:13` | `not_observed` | `legacy_ecdsa_key` is never referenced |
| AES-256-GCM and its secret-key | `app/keys.py:17` | `unknown` (`referenced_but_no_entry_path`) | `encrypt` is never called, but `AESGCM(key).encrypt(...)` on line 18 is a textual reference to the name `encrypt`. An attribute call makes no edge, and the analysis cannot tell it apart from a call of the module function, so the conservative label is `unknown`, not `not_observed` |

### `sample-java/` (hand-written CBOM)

| Asset | Where | Label | Why |
|---|---|---|---|
| AES-GCM | `src/main/java/com/ex/Crypto.java:7` | `reachable` | `Main.main` -> `Crypto.seal` |
| MD5 | `src/main/java/com/ex/Unused.java:7` | `not_observed` | The name `legacy` appears nowhere in the project's `.java` files except its own declaration |

With `--sweep`, `Unlisted.java:7` adds a SHA-256 call with `in_cbom: false`; the two listed calls have `in_cbom: true`.

`not_observed` is not proof that the code is unreachable or safe.

## Known CBOMkit false negative

`app/keys.py:22` calls `key.sign(msg, padding.PSS(...), hashes.SHA256())`, an
RSA-PSS signature. CBOMkit did **not** report it: the CBOM has no RSA-PSS
signature asset and no occurrence at line 22. This is a false negative of the
CBOM tool. `cbom-check` only labels what a CBOM lists by default. The optional `--sweep` inventories Java calls independently; Python calls are not swept.
