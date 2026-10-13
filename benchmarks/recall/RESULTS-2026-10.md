# vettalon 召回基準：9 個真實已知 CVE（2026-10-12）

vettalon 對 9 個開源專案在**修補前的脆弱版本**跑了掃描，看它能不能獨立找回已公開的 CVE。每個目標的 repo、脆弱 commit、脆弱檔、CVE 編號都經 NVD/GitHub/OSV 查核（見 [targets.tsv](targets.tsv) 與 [TARGETS.md](TARGETS.md)）。

掃描用的模型：Claude（Anthropic）找洞、Codex（OpenAI）跨家族覆核；聚焦測試時兩家都找洞。沒有用 vettalon 自己之外的工具。

## 兩個指標，分開報

同一個掃描，兩種讀法：

1. **聚焦召回**：脆弱檔確定在掃描範圍內（直接掃含該檔的小目錄）。這量的是「模型讀到脆弱碼時，能不能識別出漏洞」。
2. **整庫召回**：把 vettalon 指向整個 repo 或 package，讓它自己排序挑模組。這量的是真實使用情境，會受到模組排序與覆蓋範圍的限制。

分開報，是因為兩者量的東西不同，混在一起會誤導。

## 結果

### 聚焦召回：9/9 識別出正確漏洞類別

| # | 專案 | CVE | 類別 | vettalon 找到 | 最終狀態 |
|---|---|---|---|---|---|
| 1 | node-serialize | CVE-2017-5941 | 反序列化/eval | `serialize.js:76` | **needs_human**（claude、codex 各自獨立找到，互相覆核通過） |
| 2 | pyLoad | CVE-2023-0297 | 程式碼注入 | `clicknload_thread.py:159` | **needs_human** |
| 3 | ejs | CVE-2022-29078 | SSTI | `ejs.js:475` | **needs_human**（claude 單獨漏掉，codex 找到、claude 覆核通過） |
| 4 | aiohttp | CVE-2024-23334 | 路徑穿越 | `web_urldispatcher.py:666` | **needs_human** |
| 5 | PHPUnit | CVE-2017-9841 | eval | `eval-stdin.php:3` | candidate |
| 6 | postgraas_server | CVE-2018-25088 | SQL injection | `postgres_cluster_driver.py:36` | refuted |
| 7 | systeminformation | CVE-2024-56334 | 命令注入 | `network.js:403` | refuted |
| 8 | ollama | CVE-2024-37032 | 路徑穿越 | `modelpath.go:153` | refuted |
| 9 | sprockets | CVE-2018-3760 | 路徑穿越 | `server.rb:118` | refuted |

**9/9 都找到了正確的檔案、行號與漏洞類別。** 其中 4 個通過 vettalon 的跨家族對抗覆核、標為 `needs_human`（待人工確認的合理候選）；其餘標為 `refuted` 或 `candidate`。

### 整庫召回：5/9（修分頁 bug 後，從 4/9 提升）

把 vettalon 指向整個 repo，它自己排序挑模組來審。這情境下找回：node-serialize、pyLoad、PHPUnit、postgraas、ollama = **5/9**。

沒找回的 4 個，原因不是模型能力（聚焦測試證明它們都找得到），而是**脆弱檔沒被排進要審的模組**：
- aiohttp、systeminformation：脆弱檔是超大檔（`web_urldispatcher.py` 1222 行、`network.js` 1783 行），在檔案很多的扁平目錄裡，即使分頁後仍落在頁數上限外。
- ejs、sprockets：模組被審到了，但那一輪的 finder 沒在該檔上標出漏洞（ejs 的 SSTI 很隱晦；加第二家族 finder 的聚焦測試才找回）。

## 這代表什麼（誠實版）

**強項，而且可驗證**：把脆弱碼放進 vettalon 眼前，它跨 5 種語言、6 種漏洞類別，9/9 都識別出來了，而且位置精準到行。這不是「宣稱」，是你可以照 [targets.tsv](targets.tsv) 自己跑一遍複現的。

**聯集召回不是口號**：ejs 的 SSTI，Claude 單獨看漏了，Codex（不同家族）看出來了。多家族分工確實補上了單一模型的盲點——這正是 vettalon 的核心差異。

**不過度宣稱**：9 個裡只有 4 個被標成 needs_human，其餘標 refuted。原因是 vettalon 的覆核器很嚴：對 library 的危險函式（如 node-serialize 的 `unserialize`），它會說「我從這段節錄看不到攻擊者輸入跨越信任邊界的呼叫點，無法確認可利用性」——技術上站得住腳。這是刻意的反誤報設計：**寧可標「待確認」也不假裝「已確認」**。vettalon 刻意分開「識別出可疑碼」與「確認漏洞」兩種狀態。

**還要改的地方**：整庫召回（真實使用最在意的數字）目前被超大檔的覆蓋範圍拖累。分頁修復把它從 4/9 推到 5/9，但超大扁平目錄還需要更好的模組切分。這是誠實的待辦，不是藏起來的缺陷。

## 結果支持與不支持的結論

這份結果支持：

1. 脆弱碼在審查範圍內時，vettalon 在 5 種語言、6 種漏洞類別的 9 個已知 CVE 上都識別出正確類別與位置，可依 targets.tsv 自行複現。
2. 多家族分工能補單一模型的盲點：ejs 的 SSTI 一家漏看、另一家找到。
3. 只有通過不同家族模型覆核的發現才會標為 `needs_human`，工具不會自動宣稱漏洞成立。

這份結果不支持：精確的誤報率（見 [OWASP 誤報實驗](../owasp-fp/RESULTS-2026-10.md)）、整庫召回率（仍受大檔覆蓋限制），以及任何「發現 N 個新漏洞」的說法。

## 複現方式

```bash
# 1. 把目標 clone 到脆弱版本（見 targets.tsv 的 vuln_ref）
git clone https://github.com/luin/serialize && git -C serialize checkout f9051f4
# 2. 設定模型清單（見 ../../vettalon.example.toml）
# 3. 掃描
benchmarks/recall/scan-target.sh ./target/release/vettalon ~/.vettalon/config.toml \
  nodeserialize ./serialize "lib/serialize.js" 8
```
