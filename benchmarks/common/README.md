# 評測共用統計與報告欄位

`benchmarks/` 底下各實驗共用的兩支模組：小樣本統計（`stats.py`）與逐任務報告欄位（`report_schema.py`）。兩者只用 Python 標準函式庫，不呼叫模型、不連網路。

## 為什麼要這一層

我們的樣本多半是 n=10 到 n=160。這種規模下，裸百分比與 ±1.96·SE 的誤差條都會誤導：0/80 不代表誤報率是 0，兩個配置差 6 個百分點也可能只是兩三題的差別。這裡把報告規則寫成程式，讓每支 runner 印出來的數字都帶同一套區間與 n。

## `stats.py` 的規則

- 每個比率都以 `k/n` 加 95% 區間呈現，不單獨印百分比。預設用 Wilson；0/n 與 n/n 改用 Clopper-Pearson 精確界。
- 0/n 另給單側 95% 上界（`one_sided_upper`），例如 0/80 的單側上界是 3.68%，雙側精確區間上限是 4.5%。引用時要寫明是哪一種。
- n 小於 `CLT_MIN_N`（300）時 `normal_interval` 直接拒絕，不產生常態近似的誤差條。
- 同一批題目上的兩個配置用題目層級的配對差：不一致題目做精確符號檢定，再加上固定種子的題目 bootstrap 區間（`paired_difference`）。
- 同一題重跑多次時按題目分群（`clustered_mean`），不把重跑當成獨立樣本。
- `power_label` 依預先登錄的效果量算每臂所需 n。20%→30%、α=0.05、power=0.8 需要每臂約 294 題；不到就標 `underpowered: descriptive only`，只能描述，不能下比較結論。

## `report_schema.py` 的規則

一筆紀錄是「一個題目上一次任務嘗試」：

```json
{"id": "case-1", "task_type": "detect", "hint_level": "L1",
 "outcome": "success",
 "cost": {"usd": null, "tokens": 1830, "wall_s": 41.2, "human_review_min": null}}
```

- `task_type` 分成 detect、localize、poc、patch，各自計分，不加總。
- `hint_level` 沿用 CyberGym 的提示分級：L0 無提示、L1 只給 CWE、L2 給檔案或位置、L3 給 advisory 原文。主結果只看 L0 與 L1。
- timeout、infra_error、parse_failure、refusal、budget_exhausted 這些執行失敗留在分母裡，另外按種類計數。
- 成本欄位未知就填 `null`。填 0 會被拒絕，因為 0 和「預設值忘了改」分不出來。
- `adjudication_uncertainty(metrics)` 替既有 `adjudication-aware-v3` metrics 的每個比率補上區間與 n，原本的 metrics 不變。

## 誰在用

| 呼叫端 | 加了什麼 |
|---|---|
| `blind-twins/aggregate.py` | 輸出多一個 `uncertainty` 區塊 |
| `formal-transport/report_v1.py` | 同上 |
| `owasp-fp/run.py` | 每個比率附區間；單模型與跨家族做題目配對比較；`--summarize` 可離線重算 |
| `ranking/run.py` | hit@k 附區間與 n；MRR 仍是描述性平均 |

呼叫端以檔案路徑載入這兩支模組（`importlib`），不需要安裝成套件。

## 測試

```bash
python3 -B -I -S -m unittest discover -s benchmarks/common -p 'test_*.py'
```
