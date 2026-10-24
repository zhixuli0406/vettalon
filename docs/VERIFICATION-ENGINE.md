# Verification Engine：可重播證據與工程護城河基礎

本文件描述尚未發版的 verification engine。它把來源綁定的 Python Target PoC 編譯成 language-neutral Verification IR（VIR），從執行事實衍生判決，保存可重播的反例與 sealed evaluation lineage，並產生保留完整分母的工程 scorecard。

這是工程護城河的第一個可運作閉環，不代表護城河已經成立。現在只支援 Python 的 command injection、path traversal 與 SQL injection 三類 target；正式成立仍需跨語言、第二個獨立執行後端、prospective hidden batch、跨 host／版本重播，以及事前門檻達標。

## 資料流與信任邊界

```text
Finding + TargetCall
        │
        ▼
Verification IR ── source / target / plan / harness / policy binding
        │
        ▼
fresh Docker phases ── attack / benign / fresh challenge
        │
        ▼
ExecutionEnvelope ── capture / cleanup / tamper / effect / controls
        │
        ▼
derived VerdictDecision ── model claim 與人工判定不能覆寫
        │
        ├── replay comparison
        ├── stable CounterexampleCell
        └── sealed Evaluation Registry + engineering scorecard
```

受信任的判決只來自固定 schema、identity binding、host 組裝的 observation、required controls 與 `derive_verdict`。模型文字只存於 `model_claim`，人工結論只存於 `human_adjudication`；兩者不參與 verdict。

Target 子程序不接收 marker，stdout／stderr 只作 diagnostic。VIR 的 harness identity 會雜湊固定版本、實際生成的三個 runner template、oracle 類別與 target adapter digest，而不是只記一個手填版本字串。父 harness 仍與 target 位於同一個 container／UID trust domain，因此目前的 Docker backend 只能標為 semantic replay，不能宣稱等同獨立 observer、gVisor 或 microVM。Registry 與 CLI output 會拒絕 final symlink、已存在輸出與可見的 symlink parent；它們尚未以 dirfd／`openat2` 錨定整條 pathname，不能宣稱消除並行 rename race。

## 合約

- `vettalon.verification-ir/1`：subject、effect、required controls、capabilities 與完整 binding。
- `vettalon.execution-envelope/1`：backend identity、fresh challenge、capture、cleanup、tamper signals、effect、controls、exit 與 replay grade。
- `vettalon.verification-event/1`：VIR、envelope 與重新推導的 decision；讀回時若 stored decision 不一致即拒絕。
- `vettalon.evaluation-case/1`：content digest、train／development／sealed／prospective／quarantine split、rights 與 parents。
- `vettalon.counterexample-cell/1`：只存 authorized artifact digest、lineage 與完整 replay event identities；至少兩個不同 fresh challenge 的一致事件，unsupported 不得升格。
- `vettalon.engineering-measurement/1`：每個 effect × language × framework 的事前登錄資料列；unsupported 與 inconclusive 都保留在分母。

所有 identity 都由嚴格驗證後的內容計算。未知 capture、未確認 cleanup、tampering、非零 exit、required control 缺漏／失敗，或 unsupported／diverged replay 一律得到 `inconclusive`。

## CLI

驗證 event 並重新計算 verdict：

```sh
vettalon verification validate --event event.json
```

比較同一 VIR 的兩個 execution envelope：

```sh
vettalon verification compare \
  --ir ir.json \
  --first first-envelope.json \
  --second second-envelope.json \
  --out replay-receipt.json
```

結束碼為 `0`（equivalent）、`1`（diverged）、`4`（至少一側 inconclusive）或 `2`（輸入／binding／輸出錯誤）。收據只新建，不覆寫既有檔案。

建立 registry、加入 case、加入穩定反例，並記錄存取：

```sh
vettalon verification registry add \
  --registry .vettalon-eval \
  --case holdout-case.json

vettalon verification registry add-cell \
  --registry .vettalon-eval \
  --cell counterexample-cell.json

vettalon verification registry access \
  --registry .vettalon-eval \
  --case holdout-1 \
  --purpose development \
  --actor verifier-builder

vettalon verification registry audit \
  --registry .vettalon-eval \
  --case holdout-1 \
  --out holdout-audit.json
```

只要 sealed／prospective case 本身或任何 parent lineage 曾進入 train／development，或被 `development` 讀取，effective split 就永久變成 development，audit 結束碼為 `1`；未污染為 `0`，錯誤為 `2`。Registry 拒絕同內容換新 case ID、缺失 parent、lineage cycle，以及檔名 SHA-256 與實際 bytes 不符；CLI 不提供把 case 洗回 hidden 的操作。

`registry add-cell` 是低階匯入介面，只驗 schema、event identities 與 content-addressed metadata；它不會自行找到或執行那些 VerificationEvent。要證明 replay 真的成立，必須使用核心 `promote_counterexample` 路徑輸入完整事件，或把對應事件 artifact 一起交付稽核。Registry 的檔名／內容核對能抓到意外損壞與只改 bytes 的竄改，但不能抵抗能同時重寫內容、重新命名並替換整個 registry 的攻擊者；正式第三方證據仍需外部簽章或不可變儲存。

從 preregistered rows 重算 scorecard：

```sh
vettalon verification scorecard \
  --measurements engineering-measurements.json \
  --out engineering-scorecard.json
```

Scorecard 明列 roster 的 supported／unsupported／inconclusive、prospective false proofs、replay equivalent／diverged／inconclusive、tamper attempts、positive forgeries、state leaks、cleanup residues，以及包含失敗成本後的每份 conclusive proof 工時與直接成本。它不會自行宣告 GO 或「護城河成立」。

## Counterexample promotion 規則

`minimize_counterexample` 使用 executable predicate 做 deterministic delta reduction，模型文字不能決定候選是否保留。升格 `CounterexampleCell` 前必須：

1. 至少兩份完整 VerificationEvent 都通過 identity 與 derived-verdict 驗證。
2. 原始／最小化 artifact 都有 SHA-256 reference。
3. 每份事件具有不同 fresh challenge 與不同 event identity，且 VIR、derived decision、effect、required controls 與 replay grade 完全一致。
4. Replay grade 不是 unsupported；cell 保存每份 replay event 的 SHA-256，而不是接受呼叫者自報次數。
5. Rights、split 與 parent lineage 明確。

Payload 本身不寫進共用 registry；registry 只保存 digest 與授權 metadata。是否能跨客戶重用仍由 `DataRights` 決定，成功建立 cell 不等於取得訓練或發布權。

## 驗收邊界

目前可驗收的是 schema、fail-closed derivation、三類 Python Target PoC round-trip、semantic replay comparison、counterexample promotion、holdout contamination 與 denominator-preserving scorecard。以下仍是後續 gate：

- 30 個 marker／`/proc`／symlink／rename／timeout／cancel／late-create／cleanup fault-injection cases全部 fail closed。
- 第二個獨立 backend 與兩台 host 的 paired replay。
- JavaScript／TypeScript frontend 與至少四種 effect。
- 事前凍結的 prospective batches；unsupported／inconclusive 不得排除。
- 新 verifier 工時與 manual trusted LOC 相較 Day 30 中位數各下降至少 50%。
- Same-backend replay 至少 95%、跨版本至少 90%、共同子集跨 backend semantic agreement 至少 99%。

在這些條件以前，對外只能稱為「工程護城河原型／驗證引擎基礎」，不能稱已建立不可取代的工程護城河。
