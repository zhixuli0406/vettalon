# Changelog

格式依 [Keep a Changelog 1.1.0](https://keepachangelog.com/zh-TW/1.1.0/)，版本號依 [SemVer](https://semver.org/lang/zh-TW/)。

## [Unreleased]

## [0.1.1] - 2026-10-16

### Added
- **CLI 英文輸出**：新增全域參數 `--lang en|zh-TW`。終端摘要、進度、提示與錯誤訊息都有英文版；未指定時依序看 `VETTALON_LANG`、`LC_ALL`、`LC_MESSAGES`、`LANG`，中文語系用繁中，其他一律英文。JSON 報告、SARIF、揭露草稿內文與送給模型的 prompt 不受語言影響。函式庫 API：`vettalon::lang`（`set`、`get`、`detect`、`pick`、`tr!`），函式庫預設仍是繁中，不呼叫 `set` 的嵌入方行為不變。

### Changed
- **README 示範 GIF 改成英文畫面**：用新版 CLI 重錄一次真實的深度掃描（claude 找洞、codex 覆核），等待時間剪掉，輸出未修改。
- **CLI 預設輸出語言改為依系統語系**：原本固定繁中；現在非中文語系（含未設定）會輸出英文。要維持繁中可加 `--lang zh-TW` 或設 `VETTALON_LANG=zh-TW`。
- **README 加上 npm 安裝方式**：`npm install -g vettalon` 裝的是同一批簽章發佈的執行檔（macOS arm64／x64、Linux x64／arm64），不需要 Rust 工具鏈；英文版 Quick start 改以 npm 開頭。
- **README 頂端加上 Vettalon 品牌橫幅**（Dudu C1 識別：V 形標誌，深藍＋青綠 `#0C7580`），圖檔在 `docs/assets/brand/vettalon-readme-banner.png`，英文與繁中 README 共用。
- **README 改成英文為主**：`README.md` 換成完整英文版（開頭加 Quick start），原本的繁中版移到 `README.zh-TW.md`，兩份頂端互相切換。

### Fixed
- **npm 發佈腳本解不出執行檔**：發佈用的壓縮檔裡執行檔存成 `./vettalon`，`npm/scripts/publish.sh` 卻指名解出 `vettalon`，GNU tar 找不到就失敗，0.1.0 因此沒有自動上 npm。改成整包解到暫存目錄再複製，找不到執行檔會明確報錯。0.1.0 已用 release 上簽章過的壓縮檔（sha256 核對過）手動發佈。
- **README 的壞連結與錯誤引用**：Jev 排序基準原本指向沒有公開的 `benchmarks/ranking/`，改連官網基準測試段落；injection 偵測原本寫「見第 5 點」，實際是「怎麼運作」第 6 點。

## [0.1.0] - 2026-10-15

### Added
- **`vettalon hunt --dep-concurrency N`：相依套件平行審查**（1–4，預設 2）。原本相依一個接一個審，每個最長 `--dep-timeout`，20 個相依可以跑上一兩個小時。總 token 用量與串行相同，增加的是每個模型同時收到的呼叫數（每個進行中的相依各一個），CLI 帳號遇到限流時調低即可。報告裡相依的順序維持計畫順序，不受誰先審完影響；逐相依進度訊息會交錯：開始行標的是計畫中的位置，完成行改標「完成 N/總數」並帶套件名稱。解壓縮改在 blocking 執行緒跑，不會卡住同時進行的其他相依與它們的逾時計時。函式庫 API：`HuntOptions::dep_concurrency`、`hunt::run::MAX_DEP_CONCURRENCY`。
- **選配的 metadata-only 模組排序 `scan --rank jev`**（TypeSafe Jev）：把模組的 metadata（路徑、副檔名、位元組大小、是否進入點、git 熱點數，**不含程式碼內容**）送 Jev 排序，把高風險檔排進審查名額內。基準上深掃 hit@40 從啟發式 6/9 提到 8/9。**預設關閉**：不給 `--rank jev`，scan 維持零網路、用內建啟發式排序。送出前由 `assert_metadata_only` 逐檔比對原始碼 fail-closed，確保碼不離機；Jev 不可用時自動退回啟發式並出一行提示（報告記 `ensemble.rank_degraded`），不取代 finder／verifier。金鑰兩種存法：`[jev].api_key_env`（環境變數名，優先）或 `[jev].api_key_file`（0600 金鑰檔），config 一律不存 key 本身，key 不進 log／報告。CLI `--rank <heuristic|jev>`、`vettalon.example.toml` 範例。BYOK（自備 TypeSafe 金鑰），CLI 每次執行印出 metadata 送出目的地。
- **`vettalon hunt` 逐相依進度**：每個相依開始審查與結束時回報一行（位置、結果：新漏洞候選數／未發現／未完成），走 stderr（JSON 報告仍走 stdout）。相依是串行審查、每個可達 `--dep-timeout`，原本整段看起來像卡住。函式庫 API：`hunt::run::run_hunt_with_progress` 與 `HuntProgress` trait。
- **供應鏈獵捕 `vettalon hunt <project>`**：稽核專案相依的 OSS 套件**原始碼**，找尚未登錄成 CVE 的新漏洞，用既有跨家族對抗覆核＋PoC 驗證後，標出可向上游負責任揭露的候選。流程：解 lockfile（Cargo.lock、npm `package-lock.json` v1/v2-3、pip `requirements.txt`、Go `go.sum`+`go.mod`）→ 查 OSV 分「已知／可能新」→ 抓官方發佈檔並安全解壓（純 Rust flate2/tar/zip，擋 zip-slip/tar-slip、解壓炸彈、symlink）→ 對每個相依跑 deep audit。成本預設：只審直接依賴、`--max-deps`（預設 20）上限、預設跳過 OSV 已知 CVE 的版本（把 AI 預算集中在未登錄的）；`--include-transitive`、`--reaudit-known` 可放寬，`--dry-run` 只預覽選取不花 token。`--report <檔>` 寫出完整 JSON；`--disclose-dir <目錄>` 對「確認／needs_human 且 OSV 查無」的新候選產上游負責任揭露草稿（接 `disclose`，附送出前檢查清單，只草稿、永不自動送出），上游座標從抓回的套件 manifest `repository` 推得。`--dep-timeout`（預設 300 秒）給每個相依的 fetch+audit 一個時限，逾時就記為錯誤並繼續下一個，一個卡住的相依不會拖垮整個 run；OSV 用 `/v1/querybatch` 批次查詢，`--include-transitive` 大型 repo 也只打少數幾次而非上百次。網路只在獵捕模式、只連 allowlist（套件登錄處＋`api.osv.dev`），逐跳檢查 redirect，`scan` 的零網路行為不變。
- **攻擊模式知識層（CAPEC）＋攻擊情境**（借鑑 PentaGI）：CWE 知識庫為 14 個 OWASP Top 10 類別補上 MITRE CAPEC 對應與一段 zh-TW 攻擊情境（攻擊者進入點、前置條件、可串接後果）。SARIF result 帶 `vettalon.capec`。屬知識庫層，非可直接外用的攻擊步驟。函式庫 API：`vettalon::kb`（`CapecPattern`、`attack_scenario_zh`、`capec_url`）。
- **可利用性分級（exploitability）**：依發現既有的 `conditions` 前置條件零 LLM 推導「直接可達／條件可達／難以觸及」三級，作為 SARIF `vettalon.exploitability`，以及嚴重度帶內的次序鍵（越可達越前）。不覆寫 CVSS 標準分數。函式庫 API：`vettalon::audit::exploitability`。
- **`vettalon scan --trace <檔>`**：逐次模型呼叫的 JSON Lines 追蹤（步驟、模型、家族、prompt／reply 位元組數、延遲、結果），不含任何 prompt／回覆內文，可安全保存。供成本／延遲檢視與基準回歸分析。未給旗標時完全不記錄、零成本。
- **先前報告變動承接提示（episodic）**：同一根因指紋先前有判定、但來源已變動時，不沿用判定，改附一段「此處先前曾判定為 X，建議重新研判」的 episodic 註記（原本只計數、不留痕）。
- **政策門檻 `--gate`**（SonarQube 式條件列，可重複）：`severity>=LEVEL`、`status=…`、`cross_family`（只算跨家族覆核成立或人工確認）、`count>N`／`count>=N`；任一條件不通過即結束碼 1。結果寫入 `summary.policy`（無條件時不輸出），人工判定後自動重算，validator 會檢查是否與 findings 一致。`--fail-on` 改為選填並接受 `none`；有 `--gate` 而未給 `--fail-on` 時視為 `none`。
- **批次人工判定**：`audit::triage::apply_many`（全有或全無），一次套用同一判定與理由。
- **進度事件帶模型與輪次**：`ProgressEvent` 新增選填 `model`、`round`（`primary`／`cross_check`／`verify`／`poc`），PoC 步驟也回報進度。
- 掃描不完整時，CLI 結論會註明「通過只代表已審查的部分」。
- 模型名冊標示每個模型的資料去向（本機／雲端 CLI 帳號／雲端 API 金鑰），並說明 vettalon 不經手、不轉售 token。
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
- 模組排序基準（零審查成本）：量脆弱檔在審查順序中的位置（hit@5/10/40、MRR），比較現行排序與「只看 metadata」的排序器（本機 LLM 代理、Jev 介接）。開發用掛鉤：`cargo run -p vettalon --example rank_snapshot -- <repo>` 輸出排序、分頁與 metadata 特徵（不含檔案內容、不呼叫模型）；函式庫 API `vettalon::audit::rank_snapshot`，與 `scan` 共用同一段排序輸入組裝，不會漂移。

### Changed
- **單一模型家族遇疑似提示注入時的未完成原因更精確**：原本回報「部分模組未取得有效結果（呼叫失敗…）」會誤導，改用新的 `injection_uncrosschecked`：「偵測到疑似提示注入的模組，因只有單一模型家族而無法交叉覆審」。涵蓋 CLI 與報告。新增 `IncompleteReason::InjectionUncrosschecked`。
- **深度審查不再把名額花在別人的程式碼上**：`intake::walk_repo_files` 跳過巢狀的獨立 clone（`.git` 是目錄的子目錄；`.git` 是檔案的 submodule 照常保留），並在根目錄是 git 工作樹時遵守根 `.gitignore` 的純目錄規則；翻譯檔（`i18n`／`locales`／`lang`／`translations` 等目錄下的 json/yaml/properties，以及 `.po`/`.mo`/`.xliff`）視為非程式碼。實測 DuDuClaw：原本 40 個審查名額有 21 個落在 `.gitignore` 排除的 Yocto 第三方 layer、`commercial/` 與 i18n JSON，修正後 40 個全在專案自己的程式碼，並多找到 2 個需人工研判的候選。
- **深度審查的模組選取更省、更可控（治大型 repo 掃好幾小時的問題）**：(1) 文件與非程式碼檔（`.md`/`.rst`/圖片/鎖檔/二進位…）不再列為可審模組——AI 深審只推理程式碼邏輯，審 `docs/` 只是白燒慢的模型呼叫；(2) 單次掃描模組數有安全上限 `MAX_AUDIT_MODULES_CEILING`（40），`--max-modules 0`（全審）也受此限，其餘列為 deferred；(3) 新增 `--time-budget <秒>`：AI 深審的整體時間預算，用完就把待審模組 deferred、把執行標為 incomplete（`time_budget_exhausted`），不再無止境磨下去（已審模組的結果保留）。
- **AI 審查遇格式違約會先自動重問一次再放棄（Reflector）**：回覆違反 JSON 合約時帶著「違反了什麼」重問，至多 `AI_AUDIT_PARSE_RETRIES`（1）次後才記為 `parse_failed`，救回因格式小瑕疵被丟棄的模組；重試情形記入該模組覆蓋 note。原本直接記 `parse_failed`。
- **`--poc` 新增一次掃描 `POC_MAX_RUNS`（20）個的執行上限**：超過即記為 skipped（不靜默），防大量 High／需人工發現各開一個最長 120s 容器的失控成本。
- **`--poc` 生成時依 CWE 類別給最小驗證骨架提示**：SQLi／指令注入／路徑穿越／反序列化／程式碼注入／XSS／SSRF 等類別，提示如何在無網路沙箱、僅用標準庫、只驗自有碼做最小重現，讓模型填空而非從零寫。
- `vettalon scan --fail-on` 不再有固定預設值：未指定時，沒有 `--gate` 為 `high`（與先前相同），有 `--gate` 為 `none`。
- `ai_audit::run_ai_audit_progress` 改收 `AuditProgress` 結構（函式庫 API）。

### Fixed
- semgrep 的規則 ID 前面會被加上規則檔所在的暫存目錄（macOS 是 `var.folders.….T.`，每次執行都不同），SARIF 的 `ruleId` 因此每次都變，GitHub code scanning 會把同一條規則當成新規則，警示反覆關閉又重開。內建規則的 ID 現在會還原成原本的名稱（例如 `python-eval-exec-usage`）。
- `--poc` 的殘留容器清理會刪掉其他正在執行中的 PoC 容器：每次執行 PoC 前都會強制移除所有帶 PoC 標籤的容器，原本只在串行時安全。相依平行審查、或兩個掃描同時跑時，一邊的 PoC 會被另一邊砍掉，結果被記成 PoC 失敗。現在容器帶建立它的程序 PID 標籤（`vettalon.poc.owner`），清理只移除 owner 已不存在、或沒有 owner 標籤（舊版留下）的容器。
- git 安全熱點的一年時間窗改從 HEAD commit 的日期往回算，原本從今天往回算。最後一次 commit 超過一年的 checkout（基準測試的舊版本、很久沒動的 repo）原本完全拿不到熱點訊號，模組排序退化成只看檔名；實測 sprockets v3.7.1（HEAD 2016-12）從 0 個檔案有熱點訊號變成 11 個。
- `vettalon hunt` 在 Cargo workspace（虛擬 manifest）把所有相依都判為間接相依，預設設定下一個都不審；改從 Cargo.lock 裡專案自身套件（無 `source`）的 `dependencies` 判定直接相依，雙版本並存時精確到版本。npm lock v3 的 workspace 成員（`packages/*`）原本被當成第三方套件，現在視為專案自身，其相依標為直接相依。
- 報告與揭露草稿中的 bidi 覆寫字元與零寬字元（來自被審查的程式碼或套件，例如檔名 `run\u202Eexe.js`）改顯示為 `[U+202E]`，避免檔名被顯示成另一個名字（Trojan Source）。涵蓋報告輸出與 `disclose` 產生的草稿。
- Windows 上沒有 `HOME` 時，CLI 改讀 `%USERPROFILE%\.vettalon`（原本落到目前目錄）。
