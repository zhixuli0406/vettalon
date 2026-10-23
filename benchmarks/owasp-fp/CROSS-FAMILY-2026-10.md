# 跨家族覆核量測（O13）：設計、既有資料重分析、跑分計畫（2026-10-20）

狀態：**0 次模型呼叫。** 正式跑分要等擁有者依 D01 核准具體的呼叫預算；核准前只做離線工作。本文件的數字有兩種來源：既有兩份結果檔的重算（真資料），以及 fake model 的 dry run（只驗流程，不是證據）。

工具：[`crossfam.py`](crossfam.py)（指標與計畫）、[`crossfam_run.py`](crossfam_run.py)（排程、帳本、fake model、關閉中的正式入口）、[`crossfam.arms.example.json`](crossfam.arms.example.json)。統計來自 `../common/stats.py`（隨 O12 評測協定進 main）。

## 1. 要回答的問題

跨家族覆核降誤報，是因為「換了家族」，還是只因為「多看一次」？B8（arXiv 2610.01471）發現頂級跨模型 reviewer 和同模型 fresh session 的 F1 沒有顯著差異；B9（arXiv 2607.21656）發現覆核有方向性，弱審強會把對的改錯。安全領域還沒有人做過同等能力下「同家族 vs 異家族 refuter」的對照，這裡要做。結果決定 roster 的預設搭配，也決定 README 和網站能怎麼寫「跨家族」。

## 2. 設計

finder 家族 × refuter 家族的 2×2，加上同模型 fresh session。對角線用**同家族的另一個模型**，所以「同家族」和「同模型」是兩個不同的臂。

| 臂 | finder | refuter | 類型 |
|---|---|---|---|
| `A>B` | a1 | b1 | 跨家族 |
| `B>A` | b1 | a1 | 跨家族 |
| `A>A2` | a1 | a2 | 同家族、不同模型 |
| `B>B2` | b1 | b2 | 同家族、不同模型 |
| `A>A=` | a1 | a1 | 同模型 fresh session |
| `B>B=` | b1 | b1 | 同模型 fresh session |

- 每臂跑 owasp-fp 同一批 160 個 case（80 TP、80 FP）。每個 case 是一次 `vettalon scan --profile deep`，用 `--finders`／`--verifiers` 釘住該臂的模型，`--cross-check-top 0`、`--max-modules 1`、`--refuter-runs 3`，不開 `--poc`。
- 同模型臂沿用產品的單模型 fallback：finder 自己當 verifier，每次 HTTP 呼叫都是無狀態的新 session。
- 執行順序以 case 為主：同一個 case 六臂跑完才換下一個；case 依（類別 × TP/FP）八格輪流排，臂的順序每個 case 用固定 seed 打亂。預算用完時六臂停在同一個 case，配對不會錯位，已跑的前綴也維持各格平衡。
- 每份報告都核對覆核票：投票模型必須是該臂的 refuter，`cross_family`／`same_model` 必須符合臂的類型，`found_by` 必須是該臂的 finder。不符就記 `arm_mismatch`，不算進比較。
- a2 要和 b1 能力接近，否則家族和能力會混在一起（B8、B9 的限制）。範例檔用佔位名稱，模型由擁有者指定。

## 3. 指標

全部以 `k/n` 加 95% 區間呈現（Wilson；0/n 與 n/n 用 Clopper-Pearson 精確界）。timeout、壞掉的報告、預算停止都留在分母。

- **召回**：TP case 中最終 `needs_human` 的比例。**誤報率**：FP case 中最終 `needs_human` 的比例。另列 finder-only 的召回與誤報率。
- **uncertain 率**：finder 有標的 case 中，三次反駁結論不一致（`verify_uncertain`）的比例。
- **翻案率**：finder 有標的 case 中被 refuter 判 `refuted` 的比例。**翻案正確率**：翻案裡落在 FP case 的比例。另拆成「誤殺率」（TP 被翻）和「抓誤報率」（FP 被翻）。
- **pre-check 推翻**：沒有任何 refuter 票就被判 `refuted` 的（本機 pre-check 或 zero-LLM 路徑）記 `precheck_refuted`，算進召回分母，不算 refuter 翻案。
- 每臂另報只算實際掃描完成題目的比率（`scanned`），分母不含 `not_run`、`infra_error`、`arm_mismatch`。
- **翻案理由**：報告不保存 `refute_basis`，只留理由文字，所以分類是關鍵字比對（`guarded`、`constant_or_dead_flow`、`not_dangerous`、`deployment_context`、`other`），標明是推導值。
- **錯誤重疊**：兩臂最終判錯的 case 集合的 Jaccard，以及 refuter 判錯（翻掉 TP、留下 FP）集合的 Jaccard；共用 finder 的臂另報 finder 陽性集合的重疊，用來看 finder 自己的雜訊。
- **方向性**：六格各自的誤殺率、抓誤報率、翻案正確率。不同格的 finder 不同，只做描述，不做顯著性宣稱。
- **配對比較**（事先登錄）：固定 finder，只換 refuter 類型。每個 finder 三組：跨家族 vs 同家族、跨家族 vs fresh、同家族 vs fresh。題目層級配對差，不一致題目做精確符號檢定，附題目 bootstrap 區間；依 20%→30% 效果量標 power。另報 refuter-only 版本：只取兩臂 finder 都有標的題目，把各臂重跑 finder 帶進來的雜訊拿掉。每類 80 題遠低於每臂 294 題的需求，所以全部會標 `underpowered: descriptive only`。

## 4. 既有兩份結果已經能說什麼（0 次呼叫）

來源：`reports/results-claude-codex.json`（Claude 找洞、Codex 覆核）與 `reports/results-qwen-claude.json`（qwen2.5-coder 7B 找洞、Claude 覆核），完整重算在 [`reports/crossfam-reanalysis.json`](reports/crossfam-reanalysis.json)。這兩份只存布林值：「finder 有標」與「最後是 `needs_human`」。所以這裡的「翻案」是**沒有存活**，包含被推翻、覆核出錯、沒被覆核三種，分不開；這兩次跑在多次反駁之前，uncertain 量不到。

| | claude>codex | qwen>claude |
|---|---|---|
| finder 召回 | 78/80 = 97.5% [91.3, 99.3] | 60/80 = 75.0% [64.5, 83.2] |
| finder 誤報率 | 0/80 [0, 4.5] | 46/80 = 57.5% [46.6, 67.7] |
| 覆核後召回 | 73/80 = 91.3% [83.0, 95.7] | 51/80 = 63.8% [52.8, 73.4] |
| 覆核後誤報率 | 0/80 [0, 4.5] | 0/80 [0, 4.5] |
| 翻案率 | 5/78 = 6.4% [2.8, 14.1] | 55/106 = 51.9% [42.5, 61.2] |
| 翻案正確率 | 0/5 [0, 52.2] | 46/55 = 83.6% [71.7, 91.1] |
| 誤殺率（TP 沒存活） | 5/78 = 6.4% [2.8, 14.1] | 9/60 = 15.0% [8.1, 26.1] |
| 抓誤報率（FP 沒存活） | 0/0，無從估計 | 46/46 [92.3, 100] |

表中「翻案」都是沒有存活，所以誤殺率是 refuter 真正推翻的**上界**；抓誤報率裡也可能混了覆核出錯或沒被覆核的發現。

**被 Codex 翻掉的 5 個 TP**：BenchmarkTest00008（SQLi）、00102（SQLi）、00155（XSS）、00159（命令注入）、00174（命令注入）。翻案理由**沒有紀錄**：結果檔只有布林值，逐 case 的報告、refuter 理由和 log 都沒有進 repo，所以理由類別一律是 `not_recorded`。之後要查，得重跑這 5 題；正式跑分會保存每份報告。

配對（同一批題目、覆核前 vs 覆核後）：

- claude>codex 召回 −6.25 pp，bootstrap [−12.5, −1.25]，5 題只在覆核前成立、0 題相反，**精確符號檢定 p = 0.0625**。TP holdout 門檻判 BLOCKED 是因為降幅超過 5 pp 而且 5 題沒有理由，這和顯著性是兩回事；以 80 題來說，這個降幅本身還不到 0.05 的顯著。
- qwen>claude 召回 −11.25 pp [−18.75, −5.0]，p = 0.0039；誤報率 −57.5 pp [−67.5, −46.3]，p < 1e-13。

兩組之間：

- 最終錯誤集合的 Jaccard = 3/33 = 0.09，refuter 錯誤集合 0/14 = 0。兩組錯的地方幾乎不重疊。
- 兩個 finder 都標出來的 TP 有 58 題。47 題兩邊都保住，**0 題兩邊都翻掉**。Codex 翻掉、Claude 在另一組保住的有 3 題（00008、00102、00155）；Claude 翻掉、Codex 在另一組保住的有 8 題。只看這 58 題的配對差是 −8.6 pp [−19.0, +1.7]，符號檢定 p = 0.23，看不出哪個 refuter 誤殺較多。注意這是不同 finder 寫出的發現，refuter 看到的主張文字不一樣。

可以說的：

1. 在這 160 題上，Claude 當 refuter 時，qwen 的 46 個誤報沒有一個存活成 `needs_human`，60 個真發現裡有 9 個沒存活。被推翻、覆核出錯、沒被覆核各占多少，存下來的資料分不出來。
2. Codex 審 Claude 時翻掉 78 個真發現中的 5 個，而 Claude 這次一個誤報都沒有，所以 Codex 抓誤報的能力在這組資料上**量不到**。
3. 兩個 refuter 翻錯的題目完全不同。這和「錯誤不相關」相容，但樣本小，不足以下結論。

不能說的：

- 「跨家族比同家族好」：兩組同時換了 finder 和 refuter，沒有同家族 refuter 對照。
- 方向性（誰審誰比較好）：誤殺率 15.0% [8.1, 26.1] 對 6.4% [2.8, 14.1]，區間重疊，而且 finder 不同（qwen 7B vs Claude）。兩組覆核後召回差 −27.5 pp（p = 6e-5），主要來自 finder 本身（qwen 在命令注入 20 題全沒標），不是覆核方向。
- 任何兩臂比較都 underpowered（每類 80 題，需要 294 題）。

## 5. Dry run（fake model，0 次真呼叫）

`crossfam_run.py dry-run` 跑完整六臂 × 160 題：同一套排程、帳本、報告解析、指標，只把 `vettalon scan` 換成寫出 vettalon 格式報告與 trace 的 fake scanner。結果：960 筆紀錄、fake 呼叫 2,778 次（帳本與 trace 計數一致）、0 筆 `arm_mismatch`、uncertain 與 verify_error 都有出現並被正確分類、15 組兩兩重疊、6 組配對比較、6 格方向性。fake model 的機率是寫死的，**數字沒有任何證據意義**。

測試另外確認：預算不足或達到 `max_cases` 時六臂停在同一個 case、分母保留 `not_run`；trace 讀不到時扣滿上限並記 `infra_error`；單次掃描超過每 case 上限就先記帳、寫出 `records.partial.json` 再整批停止（每筆紀錄也即時寫進 `records.jsonl`，已付費的呼叫不會遺失）；沒有核准檔時 `execute` 不建立 scanner、不啟動任何程序。

## 6. 跑分計畫（待擁有者核准）

完整數字在 [`reports/crossfam-plan.json`](reports/crossfam-plan.json)，plan SHA-256 `c6075d0bac2ae4ba2bf6ca9a52e9f721842439cbdf081c024be5691495a501f3`。每次呼叫：輸出 ≤ 1,024 token、逾時 90 秒、0 次自動重試、同時 1 個。

**每個 case 的硬上限 = 26 次呼叫**：finder 1 頁 ×（1 + 1 次 reflector 修正）= 2，加上最多 8 個候選 × 3 次反駁 = 24。這些上限來自產品常數（`MAX_CANDIDATES_PER_MODULE`、`AI_AUDIT_PARSE_RETRIES`、`--refuter-runs`），測試會讀 Rust 原始碼核對。

| 臂 | 類型 | case | finder 上限 | 反駁上限 | 呼叫上限 | 輸出 token 上限 | 牆鐘上限 | 預估呼叫 |
|---|---|---|---|---|---|---|---|---|
| A>B | 跨家族 | 160 | 320 | 3,840 | 4,160 | 4,259,840 | 104 h | 640 |
| B>A | 跨家族 | 160 | 320 | 3,840 | 4,160 | 4,259,840 | 104 h | 640 |
| A>A2 | 同家族 | 160 | 320 | 3,840 | 4,160 | 4,259,840 | 104 h | 640 |
| B>B2 | 同家族 | 160 | 320 | 3,840 | 4,160 | 4,259,840 | 104 h | 640 |
| A>A= | fresh | 160 | 320 | 3,840 | 4,160 | 4,259,840 | 104 h | 640 |
| B>B= | fresh | 160 | 320 | 3,840 | 4,160 | 4,259,840 | 104 h | 640 |
| **合計** | | 960 | 1,920 | 23,040 | **24,960** | **25,559,040** | 624 h | **3,840** |

預估值的假設：每 case 1 次 finder 呼叫、平均 1 個候選（× 3 次反駁），每次 30 秒。這是假設，不是量測；既有結果只存布林值，量不到每 case 的候選數。牆鐘上限 = 呼叫數 × 90 秒，單工。

建議核准的預算（帳本強制）：

| 階段 | case | 呼叫 | 輸出 token 上限 | 牆鐘上限 | 預估牆鐘（30 秒/次） |
|---|---|---|---|---|---|
| 先導（`max_cases = 16`） | 前 16 題（八格各 2） | 540 | 552,960 | 13.5 h | 約 3.2 h |
| 全量 | 160 | 3,996 | 4,091,904 | 99.9 h | 約 32 h |

兩者都是「預估值 + 一整排 case 的保留額（6 × 26 = 156）」。帳本在每個 case 開始前保留整排上限，放不下就停，所以實際呼叫**不可能超過核准值**；停下時沒跑的 case 留在分母。建議先核准先導，用實測的每 case 呼叫數和延遲重算全量預算，再決定是否核准全量。美元金額要等供應商與價格決定，公式在 plan 檔。

### 擋住正式執行的事項

| 項目 | 擁有者可接受？ | 說明 |
|---|---|---|
| `finder_reflector_call` | 可 | finder 回覆違反 JSON 合約時，產品會用修正 prompt 再問 1 次（`AI_AUDIT_PARSE_RETRIES = 1`，沒有 CLI 開關）。D01 要求 0 次重試：接受它當成預算內的修正呼叫（上限已算進去），或先加開關 |
| `cli_backend_output_cap` | 否 | CLI preset（claude、codex）沒辦法強制 1,024 輸出 token。正式臂只能用 `backend = "openai"` 或 `"ollama"`，並設 `max_tokens <= 1024`、`timeout_secs <= 90`；`execute` 會檢查 roster |
| `no_verify_only_entry` | 可 | 產品沒有「只覆核既有 finding」的入口，所以每臂都重跑自己的 finder，finder 雜訊會進到臂間比較（以 finder 重疊另報）。之後若補上這個入口，可共用 finder 輸出，呼叫數也會少 640 |
| `capability_matching` | 可 | a2 與 b1 能力要接近，否則家族和能力分不開 |

### 核准方式

擁有者核准時建立一個 JSON（不進 repo 也可以），`execute` 會逐項核對，任何一項不符就拒絕並維持 0 次呼叫：

```json
{
 "schema": "owasp-xfam-approval-v1",
 "plan_sha256": "c6075d0bac2ae4ba2bf6ca9a52e9f721842439cbdf081c024be5691495a501f3",
 "max_calls": 540,
 "max_cases": 16,
 "expires_on": "YYYY-MM-DD",
 "accepted_blockers": ["finder_reflector_call", "no_verify_only_entry", "capability_matching"],
 "approved_by": "<擁有者>",
 "approved_on": "YYYY-MM-DD"
}
```

`max_cases` 把先導限制在前 16 題，即使實際呼叫比預估少也不會繼續往下跑；過了 `expires_on` 核准就失效。改了臂設定或 case 數，plan 的 SHA-256 就會變，舊的核准也會失效。

## 7. 指令

```bash
cd benchmarks/owasp-fp
python3 crossfam_run.py reanalyze                    # 既有兩份結果重算，0 次呼叫
python3 crossfam_run.py plan                         # 跑分計畫（JSON）
python3 crossfam_run.py dry-run --out-dir /tmp/xfam  # fake model 跑完整矩陣
python3 crossfam_run.py analyze /tmp/xfam/records.json
python3 -m unittest test_crossfam                    # 離線測試
# 核准後才會動作；否則拒絕並維持 0 次呼叫
python3 crossfam_run.py execute --arms ARMS.json --roster ROSTER.toml --approval APPROVAL.json \
  --cases-dir cases --out-dir runs/xfam --vettalon-bin "$(command -v vettalon)"
```

## 8. 2026-10-20 修訂（v2，共用 finder）

擁有者核准真實跑分：Claude 找洞，grok 與 agy 跨家族覆核。上面的 2×2 需要兩個 finder 家族，所以另立 v2 計畫，本節以上的 v1 計畫與其 SHA-256 不動。v2 每題只跑一次 finder，四臂 refuter 判同一份候選；reflector 改為 0 次、`vettalon verify` 補上只覆核的入口、CLI 也能強制輸出上限，表中前三個擋住事項因此解除，能力不對等仍是已接受的限制。逾時改 180 秒（grok 實測 70–90 秒）；agy 的 Gemini 把 5 個覆核 prompt 全部擋掉，agy 臂改用同一個 CLI 上的 GPT-OSS 120B。README 的「共用 finder 的真實跑分」一節有摘要；完整修訂紀錄與 v2 runner 不在公開 repo。
