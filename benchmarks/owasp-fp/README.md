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
```

`roster.example.toml` 示範「claude 找洞、codex 跨家族覆核」與「本機 qwen 找洞、claude 覆核」兩種配置。

結果見 [RESULTS-2026-10.md](RESULTS-2026-10.md)。
