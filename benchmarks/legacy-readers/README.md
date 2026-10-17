# Legacy benchmark observations

`normalize.py` 讀取顯式指定的既有資料，輸出獨立格式 `vettalon-legacy-observations-v1`，方便逐筆檢查固定分母、缺漏與資料來源。它不執行原 benchmark，不呼叫模型、scanner、目標程式、子程序或網路，也不測量歷史執行的資源。

三個 adapter 支援以下實際格式：

| Adapter | Registry | Input | 保留的意義 |
| --- | --- | --- | --- |
| `recall-report-schema2-legacy` | 六欄 TSV：`id/repo/vuln_ref/cve/class/vuln_file` | `schema_version: 2` report，含 findings、coverage 陣列、summary、engines、run status | 原報告的 findings、錯誤、partial coverage 與 evidence JSON pointers；不新增 CVE 命中判定 |
| `owasp-boolean-rows-legacy` | `id/cat/real/cwe/expect_class` JSON rows | 同樣欄位加上 exact bool `finder_pos/crossfamily_pos` | 合成資料集宣告標籤與同一次 crossfamily scan 的兩個成對讀值 |
| `ranking-target-rankers-legacy` | 同 recall TSV | `label/walker/summary/targets`；targets 含各 ranker 的 status/rank/latency/cost/detail | 排序診斷、skipped/error/null 與原 producer identity 宣告 |

舊 OWASP producer 遇到缺失的 report 仍可能留下預設 `false`，因此這裡的 false 不能當成已驗證 TN 或 miss。排序的 hit@K／MRR 使用 registry 的固定分母，另列未觀測 slots；這些是排序診斷，不能解讀成漏洞偵測 recall。原 summary 另存為 reported data，與重算結果不同時會標示差異；summary 或 Markdown 表格不能代替逐筆 input。

每個 cohort 維持獨立的 scope／arm／registry，缺少的 case 或 arm 仍產生 missing slot。格式錯誤、重複／外來 ID、metadata 不符、非有限數字、非 exact bool 或不可能的成對讀值會拒絕整個 bundle，不略過壞列繼續產生成功結果。沒有完整 arm 摘要時不能宣稱與重算值吻合；finding 沒有行號時維持 null。`normalization_status: complete` 只表示讀取及轉換完成。

每列包含 registry／raw SHA256、原始 JSON pointer、case／arm 與 deterministic fingerprint。registry 的 `vuln_ref` 是宣告的目標版本；ranking 的 `walker.git_head` 是 producer metadata。缺失、短版 hash 與 dirty 宣告均保留原狀，不能用目前程式碼 SHA 回填成歷史 execution attestation。Raw 中的 repo／file／path 僅當資料，絕不據此開啟來源或執行命令。

`confirmed` 僅保留為原 finding status，`adjudication` 與 `adjudicated_metrics` 保持 null。沒有歷史 CPU、RSS、token 或人工工時證據時也保留 null。原 ranker `latency_ms` 是該步驟報告值；metadata-LLM 的 USD 是 CLI 報告值，Jev 是當時 token × price 的估計，均非帳單或整個流程成本。已知 USD 小計與 unknown slots 分開列出；有未知值時 `total_usd` 為 null，完全沒有已知值時小計也是 null；實際記錄的 0 可以保留。

## 用法

前置需求為 Python 3 與 POSIX 檔案介面，沒有額外套件或 token 設定。純 API：`normalize_bundle(manifest, blobs)` 接收 JSON-compatible manifest 與 `{relative_path: bytes}`，不讀檔、不修改呼叫者資料。CLI 使用 Python 標準函式庫：

```sh
python3 benchmarks/legacy-readers/normalize.py \
  --manifest /ABS/INPUT-MANIFEST.json \
  --input-root /ABS/ROOT \
  --output /ABS/NEW.json
```

三個 CLI path 必須是沒有 `.`／`..`、重複分隔符號或 symlink ancestor 的 absolute lexical path。manifest 的 `registry.path` 與 `inputs[].path` 必須是 input-root 下的 relative lexical path，不能有 absolute path、反斜線、空元件或 traversal。請直接指定實際 canonical directory，例如 macOS 暫存目錄使用其 `/private/...` 路徑。

manifest 頂層如下；每個 file reference 必須填入實際 bytes 數與 lowercase 64-character SHA256，以下占位內容必須先替換：

```json
{
  "schema": "vettalon-legacy-inputs-v1",
  "datasets": [{
    "id": "explicit-cohort",
    "adapter": "recall-report-schema2-legacy",
    "scope": "focused",
    "arms": ["recorded-scan"],
    "expected_cases": 9,
    "registry": {"path": "targets.tsv", "sha256": "REPLACE_WITH_RAW_SHA256", "bytes": 0},
    "inputs": [{"path": "explicit-report.json", "sha256": "REPLACE_WITH_RAW_SHA256", "bytes": 0, "case_id": "registry-case-id"}]
  }]
}
```

recall 的每份 input 必須顯式綁 `case_id`；檔名不參與猜測。OWASP arms 必須依序為 `finder-readout/crossfamily-readout`，同 cohort 最多一份結果陣列；ranking arms 顯式列出允許的 ranker，同 cohort 最多一份結果物件。兩者的缺失 input 可用空陣列表示，仍保留 registry 分母。Registry 本身及已宣告的 input 缺檔、長度或 SHA 不符會拒絕，不自動把讀取失敗改成 missing case。

CLI 以 directory file descriptor 逐層 `O_NOFOLLOW` 開啟，拒絕 symlink ancestor／leaf 及非 regular file；平台缺少必要 POSIX flags 時直接拒絕。每檔讀取上限使用已驗證的 manifest bytes 宣告，先限制累積讀取，再核 SHA。上限為 manifest 256 KiB、單檔 2 MiB、32 個不同 input／registry files、合計 16 MiB、單 cohort 4096 cases、合計 16384 observation slots、輸出 16 MiB。這些是應用層 I/O／資料量上限，沒有提供 OS 記憶體或 CPU sandbox。

輸出以 mode `0600`、`O_EXCL` 建立，不覆寫現有檔案；寫入失敗留下的 partial artifact 不是有效結果，請保留並以另一個全新 output path 處理。成功 exit 0，讀取／轉換／輸出被拒絕 exit 1，參數錯誤 exit 2。錯誤不輸出 raw body。

## 離線驗證範圍

```sh
python3 -B -I -S -m unittest discover \
  -s benchmarks/legacy-readers -p test_normalize.py -v
```

32 個 unit methods 使用同檔明示的最小合成 specimens，覆蓋三種實際 schema、lineage、固定分母、錯誤與 secure CLI；不依賴私有 phase 或未公開歷史 reports，不啟動外部程式。這個命令是可執行用法，結果須以實際 receipt 為準。

此輸出不接入 `blind-twins/aggregate.py` 的 `vettalon-synthetic-twins-v1` 人工判讀指標，也不偽裝成 `runner-resource-v1` measurement。新格式只提供歷史觀測的共同讀取方式；原 benchmark inputs、runners、摘要及驗收範圍保持各自的來源與限制。

## License

沿用 repository 的 [LICENSE](../../LICENSE)。
