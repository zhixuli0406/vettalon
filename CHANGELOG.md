# Changelog

格式依 [Keep a Changelog 1.1.0](https://keepachangelog.com/zh-TW/1.1.0/)，版本號依 [SemVer](https://semver.org/lang/zh-TW/)。

## [Unreleased]

## [0.2.1] - 2026-10-20

只更新相依套件的安全修補版，從 0.2.0 分出，不含 main 上尚未發布的變更。

### Security
- rustls 升到 0.23.46，修補 RUSTSEC-2026-0346～0349（`Debug` 輸出可能洩漏 TLS 金鑰、ECH 被拒後緩衝資料送往外層伺服器、brotli 憑證解壓在驗證前可配置到 1 GiB、未驗證的 ServerHello 可讓之後的連線降級為傳統金鑰交換）。CLI 不輸出 TLS session 的 `Debug`，也沒有用 ECH 或 brotli 憑證壓縮；第四項是否有影響取決於加密提供者是否啟用後量子混合金鑰交換，未逐一驗證。
- zip 2.4.2 的 RUSTSEC-2026-0367～0369 只影響 `extract`。`vettalon hunt` 解壓相依原始碼時逐檔讀取並用 `enclosed_name` 限制路徑，沒有呼叫 `extract`，因此這版未升級（修正版需 zip 9.x 大版本）。

## [0.2.0] - 2026-10-17

此版本在 1.0 前以次版號承載 Rust API 的破壞性變更；從 0.1.x 升級須依下列 migration 調整。既有實驗預覽及尚未驗證項目保留各自限制，版本發布不代表完成產品或模型驗收。

### Added
- 0.2.0 formal 報告預覽：加入逐階段worksheet／獨立overlay與成本附件，核對raw／attempt artifact／model／版價來源；人工註記不改metrics，operator價目與分配人時只產明示範圍的估算。缺完整observed tokens或附件資料保留unknown total與known subtotal；無真模型、帳單或人類身分認證。本輪87個離線方法通過（原31＋新增56），另以root自建fixture驗三個CLI入口：0／0／1預期拒收，註記不改metrics。新來源的stage交付依對應manifest與測試收據核對；先前251-source包為歷史版本，不代表本次來源已發行。Worksheet／review-overlay僅支援twins；context／RAG可用預設derived重播與cost，不支援worksheet。
- 0.2.0 實驗預覽：新增 self-authored synthetic identity views、legacy observation readers 與 formal transport 的功能導航及逐檔匯出清單，並附差分程序契約。Identity 僅是合成來源歸屬；legacy 保留固定 registry 分母、missing／failed 與 unknown 成本，不轉成人工判讀指標。2026-10-17 本機檢查點：差分記錄 27 個 unique methods 與 1 個 socket case 環境阻擋，整套非綠；legacy 32 個自包含合成測試通過，另將 9 份既有固定輸入轉成 7 個 cohort／739 個 observation slots，9 檔來源 SHA 不變，僅驗純 reader、不代表新掃描或歷史成效重新認證；formal 先前31個離線測試通過，其中三 arm 的 50 次 fake 扣額／51,200 reservation 僅驗帳本與編排，非真 provider 呼叫或帳單；production provider readiness 維持 unknown-disabled，真 provider 呼叫與正式三 arm 效益執行均為 0，公開stage交付須按各自manifest與測試收據核對。不匯出未覆核 raw、phase 輸出或 denominator manifests，不代表已發行或正式模型比較通過。
- 0.2.0 實驗預覽：新增 query refinement public V2 的顯式 runtime profile／approved lock 與 raw SHA-256 綁定、獨立公開指南及逐檔匯出清單；既有工具須預先覆核，無下載或版本 fallback。離線 parser／自寫 fake CLI 與乾淨公開樹檢查僅驗來源綁定及交付契約；本階段不跑真 scanner 或模型。R27 保持 PARTIAL、budget-control-incomplete、adoption_eligible=false，歷史 8-call batch 保留原來源範圍。
- 新增 opt-in 自建合成 twin 的 fresh runner→finding 連結：核對 file hash、當次 nonce、Docker raw／control／cleanup，自動產可 attach 的五角色附件；仍是 unsigned operator-supplied 資料，不自動 confirmed。
- 實驗工具新增 runner-process CPU／lifetime RSS 觀測，以及同 snapshot 三種選段的 dry-run／mock 比較；不代表真模型成本或召回提升。
- 新增明確 opt-in 的 macOS 本機離線診斷預覽：先驗 supervisor／child 的外網 EPERM 與 loopback／唯讀政策，再以獨立 Ollama daemon、單次 upstream 上限與完整失敗紀錄檢查自建樣本；加入工具與 mock 測試不代表真模型診斷已通過。

- 0.2.0: structured proof artifact records and bounded local `evidence attach`; no command execution or automatic finding confirmation.
- Public self-built coverage examples and loopback CLI generator; SARIF carries incomplete reason, module scope and proof limits.
- 信任包工具：Syft CycloneDX 1.6 adapter、官方 schema 驗證、asset 完整性／digest gate、unsigned build record、具 exact workflow／issuer／source 條件的 release verifier，以及最小憑證 Scorecard 介面。新增資料流矩陣與 Best Practices 自評；新 release provenance workflow 尚待正式執行驗證。

### Changed
- 本機 Claude Code plugin lifecycle 驗證改為核對安裝與更新後的 inventory、版本及固定檔案雜湊；命令成功但觀察仍舊版時保留 partial。使用拋棄式 HOME／設定與精簡環境，不再讀取真實使用者設定計算 fingerprint；此工具不證明 hosted marketplace 更新或模型 session 已載入新版。
- **Breaking change — Rust API migration**（Rust 原始碼不相容）：`HuntReport`／`HuntPlan` 的 struct literal 須補 `intake`，對 `SkipReason` 的窮盡 match 須處理 `DirectnessUnknown`。`targets_from_dir` 簽名不變，但部分 intake 現回傳 `Err`；需保留有效目標與缺口請改用 `intake_from_dir`。新版仍可讀缺 `intake` 的舊 JSON，維持 `None`／unknown，不補造 complete；此 Rust 原始碼相容性變更由 0.2.0 承載。
- 0.2.0：hunt 新增離線 intake ledger，保留混合來源的有效目標並明示解析缺口、未知直接性與已解析分母；舊報告缺證據維持 unknown。指定報告／揭露草稿寫入失敗回傳非零，保留已完成草稿。
- 文件明確區分本機編排、雲模型接收程式碼、Jev metadata opt-in 與 hunt registry／OSV 流量；deep／PoC／hunt 均在免費 CLI，AI 與 pattern PoC 不會自動 confirmed。

### Fixed
- Formal-v1 報表的 twins／context／RAG 統一保留已記錄的 runner CPU、lifetime RSS 與 wall time；異常值拒收、缺值維持 unknown。這些觀察不含模型伺服器或實際費用，RSS 不代表每次執行峰值；舊版 reader 契約不變。
- Formal只讀報告預設從immutable attempt回覆重算parsed／finder／surfaced／detected／root cause／parent lineage，拒絕手改衍生欄位或無proof的human／differential結果；缺stage與producer例外保incomplete。Formal輸入改用POSIX不跟隨symlink的regular bounded讀取與前後核對，legacy不接受新worksheet／review／cost附件。
- 0.2.0: the Claude Code thin plugin now bundles a versioned POSIX capture helper for every metadata, Docker-presence and scan command, with stream caps, preserved raw receipts and bounded shared process-group cleanup. Existing 180-second default / 600-second maximum execution limits and findings exit 1 remain; metadata has separate 15-second limits. Invalid UTF-8, truncation and incomplete cleanup/control cannot become success. Installed plugins need no repository runtime; frozen reachability/research source remains unchanged. Doctor/scan are explicitly POSIX-only, while report-only reading remains available. Native Windows, hosted upgrade and real model-session acceptance are not claimed.
- 0.2.0 實驗預覽：loopback 資料流 probe 限制 subprocess capture、HTTP 讀取與 shutdown，保留部分 raw 與清理狀態；child 使用獨立 HOME 與環境變數允許清單。接收執行緒啟動失敗保留 incomplete／零 CLI attempts，清理證據不足也維持 incomplete。本機 fixture 傳輸的完整記錄不代表完整掃描涵蓋率、雲端留存或硬 OS 資源保證；本機真實 CLI 對 loopback 假模型端點的原始碼傳輸與清理已驗證；固定空回覆不代表模型判斷能力，發行另行驗收。
- Python native graph 的 marker 判斷改為完整輸入環境快照；缺值或錯值明確失敗，條件排除留下紀錄，不再由分析主機補值。
- 揭露草稿明列人工覆核、對應目標沙盒紀錄與送出核准；移除預先同意公開及到期自動公開敘述，日期僅為協調建議，公開另須核准。
- Scanner 程序清理：修正逾時、取消或正常 leader 退出後背景 child 仍存活的問題，保留部分輸出，清理錯誤另記 incomplete。Unix 私有 process group 已有 macOS 活驗；Windows Job Object runner 已在原生 Windows CI 取得限定 scanner 測試結果（12 passed、0 failed、1 ignored、545 filtered）。這不代表完整 Desktop、所有平台安裝或真模型流程已驗收。
- Hunt 的 OSV／registry 傳輸限定 HTTPS／443 與各自允許目的地，最多三次 redirect、30 秒 request timeout、零自動 retry；測試 CA／觀察器僅限測試。
- Scanner 失敗不再被記為成功空結果：缺 RustSec DB、空白／錯誤 JSON、Semgrep 部分錯誤及 Gitleaks 缺報告會顯式標記 incomplete；有效的部分候選保留。
- **只含二進位檔的模組被算成審查失敗**：macOS 的 `.DS_Store` 這類沒有已知副檔名的二進位檔會被收進模組，讀不出文字就記為失敗，掃描因此顯示「部分覆蓋」並少算覆蓋率。現在走訪時略過作業系統產生的中繼檔（`.DS_Store`、`Thumbs.db`、`desktop.ini`、`._*`），排序前也會檢查檔頭，前 8 KB 含 NUL（且不是帶 BOM 的 UTF-16）的檔案不會成為審查對象。Big5、Latin-1 等非 UTF-8 文字檔照舊列為審查對象，讀不出來時在覆蓋率裡顯示為失敗，不會悄悄消失；真正讀取失敗（例如沒有權限）也照舊記為失敗。
- **`.gitignore`、`LICENSE`、`CODEOWNERS` 這類 repo 中繼檔被送審**：沒有程式邏輯，卻各花一次模型呼叫，現在排除。

### Security
- **深度掃描會把 `.env` 等密鑰檔送給模型**：模組選檔只看副檔名，`.env`（被當成副檔名 `env`）、`.env.local`、私鑰（`*.pem`、`*.key`、`id_rsa` 等）、`.npmrc`、`.netrc` 這類檔案都被當成程式碼，內容原封不動放進審查 prompt；用雲端模型時就離開本機。即使檔案已列在 `.gitignore` 也一樣，因為檔案層級的 gitignore 規則不會套用。現在這些檔案不會成為審查對象；覆核與 PoC 階段若模型指名這類檔案，或指名一個指向它的 symlink，讀檔入口也會拒絕。清單另外涵蓋 `*.tfvars`、`terraform.tfstate`、`credentials.json`、`service-account*.json`、`*.p8`、`*.ppk`、`.htpasswd`、`secrets.yaml` 等常見慣例，但不是完整保證：寫死在原始碼裡的密鑰仍會隨原始碼送出。密鑰偵測仍由 gitleaks 在本機處理。影響 0.1.0、0.1.1 的 `--profile deep` 與 `vettalon hunt`。

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
- **選配的 metadata-only 模組排序 `scan --rank jev`**（TypeSafe Jev）：把模組的 metadata（路徑、副檔名、位元組大小、是否進入點、git 熱點數，**不含程式碼內容**）送 Jev 排序，把高風險檔排進審查名額內。基準上深掃 hit@40 從啟發式 6/9 提到 8/9。**預設關閉**：不給 `--rank jev` 時不傳送 Jev metadata、用內建啟發式排序；雲模型仍接收程式碼。送出前由 `assert_metadata_only` 逐檔比對原始碼 fail-closed，確保碼不離機；Jev 不可用時自動退回啟發式並出一行提示（報告記 `ensemble.rank_degraded`），不取代 finder／verifier。金鑰兩種存法：`[jev].api_key_env`（環境變數名，優先）或 `[jev].api_key_file`（0600 金鑰檔），config 一律不存 key 本身，key 不進 log／報告。CLI `--rank <heuristic|jev>`、`vettalon.example.toml` 範例。BYOK（自備 TypeSafe 金鑰），CLI 每次執行印出 metadata 送出目的地。
- **`vettalon hunt` 逐相依進度**：每個相依開始審查與結束時回報一行（位置、結果：新漏洞候選數／未發現／未完成），走 stderr（JSON 報告仍走 stdout）。相依是串行審查、每個可達 `--dep-timeout`，原本整段看起來像卡住。函式庫 API：`hunt::run::run_hunt_with_progress` 與 `HuntProgress` trait。
- **供應鏈獵捕 `vettalon hunt <project>`**：稽核專案相依的 OSS 套件**原始碼**，找尚未登錄成 CVE 的新漏洞，用既有跨家族對抗覆核＋PoC 驗證後，標出可向上游負責任揭露的候選。流程：解 lockfile（Cargo.lock、npm `package-lock.json` v1/v2-3、pip `requirements.txt`、Go `go.sum`+`go.mod`）→ 查 OSV 分「已知／可能新」→ 抓官方發佈檔並安全解壓（純 Rust flate2/tar/zip，擋 zip-slip/tar-slip、解壓炸彈、symlink）→ 對每個相依跑 deep audit。成本預設：只審直接依賴、`--max-deps`（預設 20）上限、預設跳過 OSV 已知 CVE 的版本（把 AI 預算集中在未登錄的）；`--include-transitive`、`--reaudit-known` 可放寬，`--dry-run` 只預覽選取不花 token。`--report <檔>` 寫出完整 JSON；`--disclose-dir <目錄>` 對「確認／needs_human 且 OSV 查無」的新候選產上游負責任揭露草稿（接 `disclose`，附送出前檢查清單，只草稿、永不自動送出），上游座標從抓回的套件 manifest `repository` 推得。`--dep-timeout`（預設 300 秒）給每個相依的 fetch+audit 一個時限，逾時就記為錯誤並繼續下一個，一個卡住的相依不會拖垮整個 run；OSV 用 `/v1/querybatch` 批次查詢，`--include-transitive` 大型 repo 也只打少數幾次而非上百次。獵捕的來源抓取／OSV 查詢只連 allowlist（套件登錄處＋`api.osv.dev`），逐跳檢查 redirect；deep 模型請求另依 provider 設定傳送相依原始碼。
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
