# OWASP Benchmark 誤報率實驗

量化 vettalon 的誤報率，並比較「單模型 finder」與「加上跨家族覆核」的差別。

## 方法

用 [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava)（每個 test case 標了 TP／FP 與 CWE）。取跨 SQLi、命令注入、路徑穿越、XSS 四類、TP/FP 各 `N` 個的分層樣本（預設 `N=20`，共 160 個 case，即 RESULTS 用的規模）。

每個 case 用**一次跨家族掃描**同時得到兩個數字：
- **單模型陽性**：finder 有沒有在該檔標出對應類別的發現（不論最終狀態）。
- **跨家族陽性**：該發現有沒有存活成 `needs_human`（通過不同家族 verifier 的對抗覆核）。

在 TP case 上算召回，在 FP case 上算誤報率，兩個配置各算一次。

## 複現

```bash
# 1. clone OWASP BenchmarkJava（淺層）
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git
# 2. 建樣本並掃描（見 sample.py / run.py，依你的環境改路徑與 roster）
python3 sample.py   # 讀 expectedresults-1.2.csv，分層抽樣，每個 case 複製成單檔目錄
python3 run.py      # 對每個 case 跑 vettalon scan --profile deep，聚合召回/誤報
# 不掃描、不呼叫模型，只重算已存的結果
python3 run.py --summarize reports/results-claude-codex.json
```

每個比率都印成 `k/n` 加 95% 區間（Wilson；0/n 與 n/n 用精確界）。單模型與跨家族在同一批 case 上做題目層級配對比較（符號檢定加 bootstrap），並依預先登錄的 20%→30% 效果量標出是否 underpowered。規則見 [../common/README.md](../common/README.md)。

`RESULTS-2026-10.md` 寫的「0/80 上界 ≤ 3.8%」是單側 95% 上界；`--summarize` 印的雙側精確區間上限是 4.5%，兩者都對，引用時要寫明是哪一種。

`roster.example.toml` 示範「claude 找洞、codex 跨家族覆核」與「本機 qwen 找洞、claude 覆核」兩種配置。

結果見 [RESULTS-2026-10.md](RESULTS-2026-10.md)。

## 跨家族 2×2（O13）

量「換家族」和「多看一次」各自值多少：finder 家族 × refuter 家族的 2×2（對角線是同家族的另一個模型），加上同模型 fresh session，共六臂、每臂同一批 160 題。每臂報召回、誤報率、uncertain 率、翻案率與翻案正確率，臂間報錯誤重疊（Jaccard）、方向性與固定 finder 的題目層級配對差，比率都附 95% 區間。統計共用 `../common/stats.py`。

```bash
python3 crossfam_run.py reanalyze                    # 重算既有兩份結果，0 次模型呼叫
python3 crossfam_run.py plan                         # 每臂呼叫數、輸出 token 與牆鐘上限
python3 crossfam_run.py dry-run --out-dir /tmp/xfam  # fake model 跑完整矩陣，0 次真呼叫
python3 -m unittest test_crossfam                    # 離線測試
```

正式跑分（`execute`）在擁有者依 D01 核准、且 roster 每個模型都能強制 1,024 輸出 token 之前一律拒絕。設計、重分析結果與跑分計畫見 [CROSS-FAMILY-2026-10.md](CROSS-FAMILY-2026-10.md)。

### 修訂設計 v2：共用 finder（2026-10-20 真實跑分）

擁有者核准的配置是 Claude 找洞、grok 與 agy 跨家族覆核，只有一個 finder 家族，所以改用 `crossfam_live.py`：每題 finder 只跑一次（`scan`、無 verifier、`--finder-parse-retries 0`），同一份報告交給四臂的 refuter（`vettalon verify`）：claude>grok、claude>agy（跨家族）、claude>另一個 claude 模型（同家族）、claude>同一個 claude（fresh session）。各臂判的是完全相同的主張，finder 的雜訊不會進到臂間比較。修訂內容與理由在 [`reports/crossfam-plan-amendment-2026-10-20.json`](reports/crossfam-plan-amendment-2026-10-20.json)，計畫在 `reports/crossfam-plan-v2.json`，原凍結計畫 `crossfam-plan.json` 不動。

```bash
python3 crossfam_live.py plan                                  # v2 計畫與 SHA-256，0 次呼叫
python3 crossfam_live.py dry-run --out-dir /tmp/xfam2          # fake vettalon，0 次呼叫
python3 crossfam_live.py execute --stage pilot --roster ROSTER.toml --approval reports/crossfam-approval-v2.json \
  --cases-dir cases --out-dir runs/xfam-pilot --vettalon-bin "$(command -v vettalon)"
python3 -m unittest test_crossfam_live
```

每題開跑前帳本先保留一整排上限（finder 1 + 4 臂 × 8 候選 × 3 次 = 97 次），放不下就停；另有 `benchmarks/common/live_guard.py` 守硬上限（核准數加 10%）、錯誤率（任何 50 次呼叫中超過 20%）與限流（15 分鐘）。先導 16 題跑完、呼叫錯誤率 ≤ 10% 且逐題紀錄有效，才跑全量。2026-10-20 的結果見 [CROSS-FAMILY-LIVE-2026-10.md](CROSS-FAMILY-LIVE-2026-10.md)。

### 檢定力補強跑分（2026-10-21 事先登錄）

`power_live.py` 用同樣的四臂，但 finder 開著產品預設的 reflector（`--finder-parse-retries 1`），題目照固定種子的順序跑（`reports/power-sample-2026-10-21.json`：前 160 題是 `sample.json`，之後每格再加到 74 題，共 592 題），跑到下一題放不進擁有者的上限就停。每題先確認放得下 finder 的 2 次，finder 跑完再確認放得下精確的覆核上限（候選數 × 3 次 × 2 × 4 臂）。檢定與 holdout 說明規則寫在 [docs/EVAL-PROTOCOL.md](../../docs/EVAL-PROTOCOL.md) 第 3 節，`analyze` 照那裡的定義計算，不呼叫模型。

```bash
python3 power_live.py sample --bench-dir BenchmarkJava            # 重建順序檔，0 次呼叫
python3 power_live.py stage --bench-dir BenchmarkJava --cases-dir CASES
python3 power_live.py dry-run --out-dir /tmp/xfam-power           # fake vettalon，0 次呼叫
python3 power_live.py execute --roster ROSTER.toml --cases-dir CASES --out-dir DIR --vettalon-bin BIN [--resume]
python3 power_live.py analyze --out-dir DIR --out RESULT.json
```
