# 校準報告 (vettalon.calibration/1)

所有數字由輸入檔離線計算；一致不等於正確，n_eff 是估計值。

## 樣本
- 題目數 n_items: 119；judge-item 對數: 329；judge 數 k: 3
- 排除的 judge-item 對: 31 {'zero_runs': 31}
- 機率來源: run_counts

## 校準
- Brier: 0.390
- ECE (10 bins, uniform): 0.386
- 0/0 runs 排除: 31

## 一致時的錯誤
- 全體一致時的錯誤率: 31/83 = 0.373 [0.277, 0.481] (wilson)
- 自信判為安全卻有漏洞 (真漏洞中全票 refuted): 28/59 = 0.475 [0.353, 0.600] (wilson)

## 注入 recall
- claude-sonnet-5-5: 4/20 = 0.200 [0.081, 0.416] (wilson)
- gpt-6.1-sol: 7/20 = 0.350 [0.181, 0.567] (wilson)
- grok-4.7: 4/20 = 0.200 [0.081, 0.416] (wilson)

## 有效獨立票數
- k = 3；n_eff = 1.329；n_eff/k = 0.443；平均 ρ = 0.629
- 共同題數: 98
- 家族: {'anthropic': 1, 'openai': 1, 'xai': 1}（3 家）
- 公式: n_eff = k / (1 + (k - 1) * mean_rho), clamped to [1, k]

## 警告
- n_eff/k = 0.44 < 0.5: judges make correlated errors; lower confidence in panel agreement
- 31 judge-item pairs had 0 usable runs and are excluded from ECE and Brier
