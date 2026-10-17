# Python context selection prototype

獨立 opt-in prototype，未接產品預設路徑。支援 baseline 全檔、functions、sink/callchain 三模式，保留原行號、選段內容與 SHA-256、原檔 SHA-256；每檔最多 64 KiB、40 modules、16 KiB payload、2 秒、深度 3，另有不可超越的參數硬上限。parser/read/time/budget failure、symlink、未納入模組都明列。未知 call 保留函式內容，不因無 sink match 靜默刪除。

由repo根目錄執行；先建立不存在的新output parent，這些命令只解析自建fixture／固定mock，不執行來源、模型或Docker，也不依賴內部歷史raw：

```bash
mkdir ./vettalon-context-reproduction-output
python3 -m unittest discover -s benchmarks/context-selection -p 'test_*.py'
python3 benchmarks/context-selection/selection.py benchmarks/context-selection/fixtures/positive \
  --mode callchain --output ./vettalon-context-reproduction-output/selected.json
```

`fixtures/positive` 與 `fixtures/safe` 只用於語法上下文選取，沒有執行其檔案讀取。兩者都有跨檔呼叫，安全版保留目錄邊界。6 個 fixture × mode run 的完整語法路徑率為 6/6；不是 recall、taint proof、實庫效果或省 token 效果。已有相同 snapshot／module 分母／byte cap 的 dry-run 與固定 mock 比較 manifest；尚未做真 finder 比較，R21 效果仍 pending。

## 固定 snapshot 比較 adapter

```bash
# Uses the new parent created above; each output must not exist.
python3 benchmarks/context-selection/compare.py benchmarks/context-selection/fixtures/positive \
  --output ./vettalon-context-reproduction-output/dry-run.json
python3 benchmarks/context-selection/compare.py benchmarks/context-selection/fixtures/safe \
  --mock --output ./vettalon-context-reproduction-output/mock.json
```

`compare.py` 預設 dry-run，不 dispatch；僅顯式 `--mock` 使用固定回覆 stub。沒有真 provider／CLI adapter，其他 adapter 名稱會拒絕。來源只讀、複製與 AST parse，不 import／execute fixture，不啟動模型或 Docker。輸出必須新檔、不可位於來源內，拒絕 output symlink ancestor；暫存 snapshot 清理後，來源與 ranges 仍可從 artifact 還原。

三 mode 共用 scope 清單、snapshot、implementation hashes 與上限：40 modules、每檔 64 KiB、16 KiB UTF-8 選段、每 mode 的可信 Python selector child 最多 2 秒 wall、32 KiB prompt、256 bytes 固定 mock response、總 3 calls、1 inflight、0 retry。input/output token 數與 USD 不明；byte cap **不是**等 token 比較。超 prompt／response cap 不 dispatch，缺額 call 顯示 call budget，全部模式與 inventoried modules 保留。即使 caller 調小上限，各 mode 仍共用同值；超硬上限拒絕。

Inventory 使用不跟 symlink 的 bounded scandir：8192 entries／4096 Python modules／2 秒；未列完或遇到無法盤點的 symlink／directory failure，`inventory_complete=false`、`module_denominator=null`，僅給 `inventoried_module_lower_bound`，不做 dispatch。source snapshot 只複製模組 cap 內至多 40 檔；cap 外保留 path/stat 與 module_cap，內容 hash 為 unknown，不宣稱整庫 source snapshot 完整。oversize、read/decode/parse failure、time/byte budget、omitted 與 unknown calls 都不變成 safe。

`raw_bytes_sha256` 綁原始 bytes；`source_sha256` 綁嚴格 UTF-8 decode 後再 encode 的文字，不做 CRLF／Unicode normalization。本 adapter 與 selector 使用原 bytes，不靠 `read_text` 換行轉換。每段保存原行號、text、SHA-256 與 truncated，送審 prompt 保存實際 JSON ledger、UTF-8 bytes、prompt hash；mock 另保存 stub 收到的 prompt/hash 及 response/hash。若 UTF-8 解碼失敗，原 bytes 以 base64 留存，沒有假造可讀來源或安全結論。

三 mode 全部完成 selection 後，再核對原 source scope／snapshot 與 frozen copy。若改動，標 snapshot_changed 並全數不 dispatch；各 mode 的 source/scope/implementation binding 不同不可比較。這是有界 filesystem 觀察，不是 OS 原子 snapshot，也無法證明 omitted source 在相同 stat 下從未改動。hash 是版本關聯，非簽章／可信 provenance。

自建 positive／safe 各有 dry-run、mock artifacts，每份都保留 baseline/functions/callchain，總 12 mode records、6 mock dispatches、真模型零次。這些結果只驗 pipeline／scheduling contract，不輸出 recall、每美元收益、token 節省或整庫效果；真正同 snapshot 的 finder 對照仍待 D01／D02。
