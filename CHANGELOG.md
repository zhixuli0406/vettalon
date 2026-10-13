# Changelog

格式依 [Keep a Changelog 1.1.0](https://keepachangelog.com/zh-TW/1.1.0/)，版本號依 [SemVer](https://semver.org/lang/zh-TW/)。

## [Unreleased]

### Added
- **zh-TW CWE 知識庫**（`crates/vettalon/src/cwe_kb.json`，58 筆）：由 MITRE CWE v4.20 官方 XML 建立、與 OWASP Top 10 2021 對應雙來源核對；提交草稿依 CWE 查表帶入中文說明，函式庫 API `vettalon::kb` 供其他前端重用。OWASP 類別中文採 OWASP 官方繁中譯名（A08–A10 官方未譯，保留英文）。
- **漏洞提交助手**：`vettalon disclose <report.json> [--finding <id>] [--channel ghsa|email|twcert|hitcon]`。只從 repo 本身判斷管道（git remote、SECURITY.md、套件設定，無網路），產生 GitHub 私密漏洞回報、專案安全信箱、TWCERT/CC（90 天）、HITCON ZeroDay（60 天）格式草稿與建議公開日期；草稿強制要求填寫「已人工重現／尚未重現」。**只產生草稿、永不送出**；只有「需人工研判」或人工確認的項目可產生，誤判與未覆核項目拒絕；輸出附送出前檢查清單。
- **人工判定（triage）函式庫 API**（`audit::triage::apply`）：確認為漏洞／判定誤判／排除，理由必填，依 `OperatorReview` 合約寫入並以 validator 同一規則重算摘要；判定後報告仍須通過 validator 否則不套用。理由進入報告的誤判清單、排除清單（「人工判定：…」）。
- Finding 新增選填欄位 `cwe`／`cve`／`cvss`（向後相容）：AI 審查模型自報 CWE（正規化，壞值丟棄不作廢整份回覆）、semgrep 讀規則 metadata、gitleaks 固定 CWE-798、cargo-audit 帶 CVE alias 並以公告提供的 CVSS 向量計分（CVSS 3.x 計分器依 FIRST 規格，不接受模型自估向量）。SARIF 規則加 GitHub `external/cwe/cwe-NNN` tag，有真實 CVSS 時以其作為 security-severity。
- `vettalon scan`：開源掃描器（semgrep / gitleaks / cargo-audit），加上 `--profile deep` 的 AI 審查。審查流程從 DuDuClaw secaudit 抽出：intake 熱點、零 LLM 前置檢查、對抗式覆核、承接先前報告、報告 validator。
- 多模型分工：模組依序輪流分配給各個 finder；高風險模組（git 安全熱點或進入點，`ModuleTarget.high_risk`）自動再交一家不同家族覆審，`--cross-check-top N` 可擴到前 N 個高分模組，雙審數記在 `ensemble.cross_checked`；每個候選交給不同家族的 verifier 覆核，結果記成 `verification` 投票；報告層級另記 `cross_family` / `mixed_family` / `same_family`。
- 模型後端：`claude` / `codex` / `grok` CLI preset，自訂 CLI，OpenAI 相容 API，Ollama。CLI 一律在空的暫存目錄執行，只傳白名單內的環境變數；逾時會殺掉整個 process group；grok 的 prompt 改由 0600 的檔案傳入。
- `Config` 可序列化並寫回（`to_toml`、`save`，0600、沿用載入時的驗證）；`Config::roster_for` 依指定 id 建構 finder／verifier／poc 名冊。
- `--max-modules 0` ＝審查全部排序模組。大型 repo 完整掃描較慢、較花費。
- 模型清單：`~/.vettalon/config.toml` 或 `--config`，不讀被掃描 repo 裡的設定檔。沒有設定檔時只用 claude。codex、grok 和自訂 CLI 必須設 `allow_agent_tools = true`（它們的工具關不乾淨）。另外：API 必須用 https；`api_key_env` 限定名稱格式；自訂 `program` 必須是絕對路徑。
- 拒答偵測：拒答記到 `ensemble.refusals`，只有該模組或該發現標成未審，不轉送給其他模型。
- `IncompleteReason` 新增 `model_refused`、`units_failed`。部分模組失敗、或有候選沒覆核時，執行會標成 incomplete。
- 投票新增 `same_model`，記錄 finder 自己覆核的情況；覆核獨立性只計算有給出判定的覆核。
- 模型路徑一律 canonicalize 後確認仍在 repo 內，不會讀到 symlink 指向的 repo 外檔案。
- 新增 prompt-injection 偵測（零 LLM）：從 DuDuClaw 抽出 `input_guard` 與 `unicode_normalizer`，另加針對審查場景的「叫模型回報乾淨」規則。命中的模組改交兩家族覆審，記在 `ensemble.suspected_injection`；單一家族無法交叉覆審時標為 incomplete。
- 秘密遮蔽補上：環境變數式名稱（`OPENAI_API_KEY=`）、`sk-`、`xai-`、`AIza`、`ASIA`、`ghs_`、JWT、PEM 私鑰；報告寫出前所有自由文字欄位統一遮蔽；報告與 SARIF 建檔時就是 0600。
- SARIF 2.1.0 輸出（`--sarif`），被證偽的發現標成 suppressed。
- 容器隔離：codex、grok 預設在 `vettalon-agents` 容器裡執行（獨立 `ContainerCliCaller`，不動 host 的 `CliCaller`）。每次呼叫開新容器，只掛入一份複製的 auth 檔與空工作目錄，接在 `--internal` 網路上，唯一出口是只放行廠商網域的 egress proxy。`vettalon agents build` / `stop` 管理映像檔與 proxy。`allow_agent_tools = true` 改為「改在 host 執行、接受讀檔風險」的 opt-out；自訂 `program` 仍只能走 host。
- `--poc`：Docker CLI 沙箱，斷網、根目錄唯讀、`cap-drop=ALL`、非 root、swap 與 ulimit 上限、`--pull=never`；host 端和容器內各有一道時限；啟動時清掉殘留的 PoC 容器；輸出設上限並持續讀空。
- `vettalon models [--probe]`、`vettalon validate`。
- `fixtures/demo-app`：附標準答案的漏洞測試專案。
- 召回基準：對 9 個真實已知 CVE（跨 5 語言 6 類別）的掃描結果與可重現 harness（benchmarks/recall/）。脆弱碼在範圍內時 9/9 識別正確類別，整庫 5/9（分頁修復後）。
- 誤報率實驗（OWASP Benchmark 160-case，FP 各 80，附 95% CI，benchmarks/owasp-fp/）：vettalon 91% 召回 [83–96%]、0 誤報（上界 ≤ 3.8%）；跨家族覆核把 7B 本機模型的誤報率 57%→0%、保住 51/60 真發現。基準抓出並修好 verifier 過度嚴格（看不到部署脈絡就 refute）的 bug，召回 66%→94%、precision 不變。

### Fixed
- Windows 上沒有 `HOME` 時，CLI 改讀 `%USERPROFILE%\.vettalon`（原本落到目前目錄）。
