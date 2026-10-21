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

## `live_guard.py`：真實模型呼叫的斷路器

所有會花真實模型呼叫的 harness 都經過一個 `LiveGuard`：

- 硬上限 = 核准數加 10%（`cap_for(138) = 151`）。`before_call` 在越界之前就拒絕，所以上限不會被跨過。
- 任何連續 50 次呼叫中，錯誤加拒答超過 20%（第 11 次）就停。
- 限流的回覆另外計，持續 15 分鐘就停；期間 harness 依 `cooldown()` 等待再呼叫下一題。
- 停下後維持停止狀態（`GuardHalt`），沒跑的題目留在分母。它本身不重試任何模型呼叫。

## 誰在用

| 呼叫端 | 加了什麼 |
|---|---|
| `blind-twins/aggregate.py` | 輸出多一個 `uncertainty` 區塊 |
| `formal-transport/report_v1.py` | 同上 |
| `owasp-fp/run.py` | 每個比率附區間；單模型與跨家族做題目配對比較；`--summarize` 可離線重算 |
| `ranking/run.py` | hit@k 附區間與 n；MRR 仍是描述性平均；live prescreen 走 `live_guard` |
| `owasp-fp/crossfam_live.py`、`sastbench/run_live.py` | 真實跑分走 `live_guard` |

呼叫端以檔案路徑載入這兩支模組（`importlib`），不需要安裝成套件。

## 測試

```bash
python3 -B -I -S -m unittest discover -s benchmarks/common -p 'test_*.py'
```
