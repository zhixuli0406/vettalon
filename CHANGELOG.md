# Changelog

格式依 [Keep a Changelog 1.1.0](https://keepachangelog.com/zh-TW/1.1.0/)，版本號依 [SemVer](https://semver.org/lang/zh-TW/)。

## [Unreleased]

## [0.6.0] - 2026-10-29

### 升級須知 / Upgrade notes

- **Rust API 有不相容的 struct literal 變更。** `hunt::run::DependencyHunt` 新增 `facade_of: Vec<String>` 與 `promoted_from: Option<String>`，`hunt::graph::DepGraph` 新增 `resolved`。自己用 struct literal 建 `DependencyHunt` 的程式要補上 `facade_of: vec![]`、`promoted_from: None`；`DepGraph` 可改用 `..Default::default()`。JSON 報告相容：兩個欄位空值時不輸出，舊報告照常讀取。
  Rust struct literals must add `facade_of` and `promoted_from` to `hunt::run::DependencyHunt`; `hunt::graph::DepGraph` gains `resolved` (use `..Default::default()`). JSON reports stay compatible: both fields are omitted when empty and older reports still deserialize.

- **報告 schema 升到 3。** 新版仍可讀 v2 報告：匯出、報告庫、比較和前次結果承接都照常運作。比較 v2 與 v3 報告時會附 `schema_difference` 說明，因為 v2 沒有嚴重度拆解與檢查紀錄。舊版 CLI／Pro 讀不了 v3 報告。
  Report schema is now 3. v2 reports still export, open in the workspace, compare (with a `schema_difference` note) and feed prior-run carry-over; older binaries cannot read v3 reports.
- **嚴重度可能被調降，`--fail-on`、`--gate` 用調降後的值。** finder 評的整體嚴重度高於影響時，只有另一家族的 verifier 也評了影響，才會截到兩者中較高的影響等級（`severity_capped`）；沒有獨立評等就維持原值；finder 的影響本來會調降時記 `severity_cap_unconfirmed`，不會調降就不記。原值保留在 `severity_claimed`。同一份程式碼可能比以前少觸發 CI 失敗。
  Severity above the impact rating is lowered only when a verifier from another family also rated impact (`severity_capped`); otherwise the claimed value stands and `severity_cap_unconfirmed` is noted only when the finder's impact would have lowered it. `--fail-on` and `--gate` use the result, so the same code may fail CI less often.
- **「covered」的意思變了。** 模型只回空結果、沒列出檢查過什麼的模組，現在記為 `reviewed_no_checks`，不再算 covered。這不影響 `run_status`、結束碼和 gate，只是報告與完整性診斷會列出來。
  A module whose finder returned no candidates and listed no checks is now `reviewed_no_checks`, not `covered`. Run status, exit codes and gates are unchanged.
- **finder 回覆格式改為物件**（`{"candidates", "checks", "hardening", "leads"}`）。舊的 JSON 陣列仍接受，但這類模組會記為 `reviewed_no_checks`。refuter 判 `plausible` 時另外回 `impact`，缺了不影響判決。
  The finder reply is now an object; a legacy bare array is still accepted (its modules become `reviewed_no_checks`).
- **Rust API 的 struct literal 又多了欄位。** `audit::schema::Finding` 新增 `severity_claimed`、`likelihood`、`impact`；`ModuleCoverage` 新增 `prior_status`、`checks`、`hardening`、`leads`；`CoverageSummary` 新增 `shallow`；`PriorRunInfo` 新增 `carried_not_rediscovered`、`carried_not_rediscovered_overflow`、`hash_budget_exhausted`、`changed_unrediscovered`、`prior_gap_modules`。
  Rust struct literals must add the new fields on `Finding`, `ModuleCoverage`, `CoverageSummary` and `PriorRunInfo`.

### Added

- 嚴重度拆成可能性與影響：finder 對每筆候選分別評 `likelihood` 與 `impact`（各附理由），整體嚴重度不得高於影響，但要另一家族的 refuter 判 `plausible` 時也評了影響，才會截到兩者中較高的影響等級並記 `severity_capped`；沒有獨立評等時維持原值，finder 的影響本來會調降時記 `severity_cap_unconfirmed`（含提議的等級），finder 沒辦法自己把發現壓到門檻以下。兩邊影響評等不同時記 `severity_disagreement`，顯示在 CLI 與 SARIF（`vettalon.severity_disagreement`）。
- 模組的檢查紀錄：finder 要列出檢查過的不變量和檔案（`coverage[].checks`，最多 8 筆，路徑必須是送進 prompt 的檔案）。零候選又沒有有效檢查的模組記為 `reviewed_no_checks`（`shallow_no_checks`），計入 `summary.coverage.shallow`，完整性診斷會列出。
- Hardening 建議與線索另存：模型看到的強化建議（`coverage[].hardening`）和指向其他模組的線索（`coverage[].leads`）各最多 5 筆，不算 finding，不進 SARIF results 與 gate。線索路徑必須是這次掃描看得到的既有檔案，指向敏感路徑的線索會被丟棄；建議與線索的文字先遮罩、截斷後才保留。線索指向本次沒審的模組時，CLI 會逐一列出。
- 前次缺口優先：前次報告裡延後、失敗、部分審查或 `reviewed_no_checks` 的模組，這次優先審（`coverage[].prior_status = prior_gap:<原因>`），最多佔模組上限的四分之一（無條件進位，上限非零時至少 1 個），其餘照一般風險排序。前次報告要先通過完整的報告驗證才會採用，沒通過就在 stderr 印一行並改找更早的報告。
- `scan --diff-base <ref>`（deep）：只審 PR 改到的模組。base 與 HEAD 的 merge-base 透過唯讀、強化過的 git 路徑取得，找不到時 exit 2，不會偷偷改成全掃。改動範圍包含 merge-base 到 HEAD 的 commit，以及已 stage、未 stage 和未追蹤（未被 ignore）的檔案；報告記錄 HEAD 與 base 的 commit OID。git 列出不合法的路徑、或 repo 有 `info/grafts` 時一樣 exit 2，git 指令一律停用 replace objects。改到的模組優先入選，其餘記為 `out_of_scope`（`diff_scope`），不算 covered；`run_status` 為 `partial_by_design`，結束碼不變。改動檔案以外的掃描器發現帶 `outside_diff_scope`，不計入 `--fail-on` 與 `--gate`。cargo-audit 等依賴漏洞只要有 manifest 或 lockfile 改動、或所屬 lockfile 沒被 git 追蹤（例如被 `.gitignore` 排除、在 CI 裡才產生），就算在範圍內；判斷不出所屬檔案的掃描器發現一律算在範圍內。審查結束後會重算一次改動範圍：HEAD、base 或 merge-base 變了就 exit 2、不寫報告；掃描期間才改動的檔案併入範圍（`scope.changed_during_scan`），但開始時挑的模組不會重選。報告新增 `scope` 區塊，SARIF 帶 `vettalon.scope`。
- `--attack-classes off|auto|all`（`scan` 與 `hunt`，預設 `off`，設定檔可用 `attack_classes`，Pro 與桌面版的掃描也照設定檔）：替每個模組挑攻擊類別，把該類的審查方法放進 finder prompt。共 8 類：injection、path_file、ssrf、deserialization、access_control、secrets_crypto、ci_workflow、llm_agent。`auto` 依原始碼裡固定字串的出現次數最多挑 3 類，不呼叫模型，同一份程式碼每次挑的都一樣；沒挑的類別會列出原因（`no_signal`、`cap`）。開啟後，零候選模組要每個選中的類別都有檢查紀錄才算 covered，否則記 `shallow_missing_class_checks`。報告新增 `coverage[].attack_classes`，SARIF 帶 `vettalon.attack_class`。
- `vettalon explain <代碼>` 與 `vettalon explain --list`：Vettalon 自己的 90 個代碼（證據等級、證明缺口、覆蓋狀態與原因、未完成原因、證據種類、前次承接與 diff 範圍標記）各有一頁說明，內建在執行檔裡，離線可查；打錯字會提示最接近的代碼。SARIF 結果帶 `vettalon.explain_uri` 連到對應頁面。說明頁目前只有英文。

### Changed

- 深審的模組排序：沒有 git 歷史時原本只看檔案數，現在資料檔（`.json`、`.yaml`、`.eml` 等）不加分（`.github/` 等 CI 設定除外），`tests`／`benches`／`examples`／`fixtures` 這類輔助目錄一律排在原始碼模組之後（仍列入 coverage，沒有其他程式碼時照樣審）。

### Fixed

- `hunt` 把外殼 crate 報成審完：直接相依若只是 re-export 另一個 crate（xml-rs 1.0 → xml、liquid → liquid-core），實作所在的 crate 原本被當成 transitive 跳過，結果顯示 complete、實際沒審到解析器。現在自身程式碼少於 500 行、且整包 re-export 某個相依（`pub use dep::*;`／`pub extern crate dep;`）的 crate 會被標 `facade_of`，lockfile 實際連結的那個版本（每個外殼最多 3 個、只追一層，不含 derive／macro 輔助 crate）在計畫內的相依之後補審，記 `promoted_from`。補審另受 `--max-deps` 限制，`--hunt-budget` 下平分剩餘時間；有已知 advisory 時照一般政策略過；實作 crate 不在 lockfile 時 hunt 標為未完成（`facade_implementation_unresolved`）。
- `hunt` 審套件原始碼包時，mail-parser 的 `resources/` 測試資料（數百個 `.json`／`.eml`）佔滿模組名額，`src/` 一個檔都沒審；同上排序修正。
- 前次的 `needs_human`／`candidate` 這次沒被重新找到時，會從新報告靜默消失。現在 deep 掃描會把它們以 `Candidate` 帶回來重新驗證（`prior_not_rediscovered`），前提是檔案仍在 repo 內且內容沒變；檔案變了或不見了只列出不帶入，每次最多帶 50 筆。帶入檢查有自己的讀檔預算，和這次發現的檔案雜湊分開計算（各自最多 200 個檔案、合計 256 MiB，前次發現最多看 500 筆）；預算用完時，剩下的筆數記在 `prior_run.hash_budget_exhausted`，CLI 會警告，完整性診斷也會列出，但不改變執行狀態與結束碼。單一檔案超過 256 MiB 視為無法比對。quick 掃描不呼叫模型，只列出並提示改用 `--profile deep`（`quick_profile_not_rechecked`），也不影響 quick 的 gate。

## [0.5.0] - 2026-10-26

### Added

- 新增 `audit::completeness::diagnose` 公開、確定性的掃描完整性診斷：從報告既有的執行狀態、引擎、模組、模型嘗試與來源讀取證據，列出未完成、未知、受影響範圍與處理類型；不改 finding 判定、掃描政策或 CLI 結束碼。
- 新增 `audit::target_poc::preflight_source` 唯讀來源預檢，讓本機介面在執行 Docker 前先拒絕不支援的 oracle 類別、缺少來源身分、雜湊過期或越界路徑。成功只代表目前來源與 finding 身分一致，不代表重現或修補檢查會通過。

## [0.4.0] - 2026-10-25

### 升級須知 / Upgrade notes
- **Rust API 有不相容的 struct literal 變更。** `audit::ScanOptions` 與 `hunt::run::EngineAuditor` 新增必填 `poc_image: String`；可傳 `sandbox::DEFAULT_POC_IMAGE.into()`。`FixCheckRun` 新增 `binding` 並序列化 binding-aware `outcome`，`FixCheckSummary` 新增 `scope` 與選填 `binding`。舊報告仍可讀，但沒有完整相鄰 execution binding 的歷史正向 fix receipt 會降為 `fix_unverified`；負向結果保留。

### Added
- 新增 VIR、ExecutionEnvelope、VerificationEvent、CounterexampleCell 與 EngineeringMeasurement 公開合約，以及 `vettalon verification validate|compare|scorecard|registry`。Replay 的 unknown／inconclusive 使用結束碼 4；反例升格需要不同 fresh challenge 的完整一致事件；sealed holdout 污染沿 parent lineage 傳遞，registry 會核對內容位址，不能換 ID 洗回 hidden。現階段只涵蓋三類 Python target 與 Docker reference backend，不宣稱跨語言工程護城河已成立。
- `vettalon reproduce` 與 `vettalon fix check`：從 validator-clean 報告選定 finding，以封閉的 Python `TargetCall` 呼叫 prepared copy 內雜湊固定的同步 top-level function。`fix check` 要求 `--report-out`，同時產生獨立 receipt 與附上同一 diff、相鄰 check/context 證據的 validator-clean 報告；不改 live tree 或 finding status。

### Security
- 來源綁定執行以不可變 image ID 與 prepared-tree/file/plan/adapter/harness 雜湊產生收據。`reproduce` 的三個 phase 各用新容器；fix 的原版／修補版回歸與明示專案測試 phase 也各用新容器。目標子程序不直接接收 marker，子程序 stdout/stderr 不作判決輸入；父 harness 產生並嚴格解析 verdict，重複或格式錯誤一律拒絕。新 CLI 輸出只准新建並拒絕既存檔、symlink、hardlink 與 symlink parent；父目錄檢查不是 dirfd 錨定，仍不宣稱消除所有並行 rename 競態。

### Changed
- PoC sandbox 的成功 preflight 只在一次有界操作內共用，image ID 固定，但每個 phase 仍使用新容器。n=30 的本機 microbenchmark 在九階段負載觀察到 6.50% paired-median 改善，1／3 階段則沒有改善；它只支持減少 metadata probe 次數，不是 full-scan、release 或 SPACE 效能主張。

## [0.3.2] - 2026-10-24

### 升級須知 / Upgrade notes
- **codex 與 grok 的認證 CLI 後端改為 fail-closed。** 容器內的工具型模型可讀取可重用的 auth 檔，並可經允許的廠商網域將它送出，因此未設 `allow_agent_tools = true` 時現在會拒絕這類設定。請改用能完全關閉工具的 CLI、HTTP/OpenAI-compatible API 或 Ollama；只有在程式碼可信且明確接受 host 檔案與憑證可被讀取的風險時，才設 `allow_agent_tools = true`。
  Authenticated codex and grok CLI backends now fail closed. A tool-capable model in the container can read reusable auth and send it to an allowlisted vendor domain, so such configurations are rejected unless `allow_agent_tools = true` explicitly accepts host file and credential access. Prefer a fully tool-disabled CLI, an HTTP/OpenAI-compatible API, or Ollama.
- **CI：deep 掃描沒有任何 AI 引擎能執行時，結束碼從 0 改成 4。** 報告照樣寫出；要維持舊行為加 `--allow-incomplete`。quick 掃描、或只有部分 AI 引擎無法使用時，結束碼不變。細節見 CHANGELOG 的 Changed。
  CI: a deep scan in which no AI engine could run now exits 4 instead of 0 (the report is still written); `--allow-incomplete` keeps the old exit code.

### Security
- 修復八個發版阻擋：Git metadata 外逸與無界歷史讀取、揭露中繼資料讀取的 symlink 父目錄越界、工具型 CLI 憑證暴露、agent 取消後的容器殘留、可執行檔 PATH 劫持、TLS/ZIP 依賴漏洞、PoC scratch 目錄暴露，並阻擋 gitleaks/semgrep 忽略參數繞過掃描。
- Fixed eight release blockers: Git metadata escape and unbounded history reads, disclosure-metadata reads escaping through symlinked parent directories, tool-capable CLI credential exposure, orphaned agent containers after cancellation, executable PATH hijacking, TLS/ZIP dependency vulnerabilities, PoC scratch-directory exposure, and gitleaks/semgrep ignore-flag bypasses.

### Added
- `verify --joern-keep`（預設關閉，實驗性）與 `vettalon joern build|image|check`：覆核之後，對 refuter 用模型回覆關掉的發現，在本機容器裡用 Joern（Apache-2.0，固定 v4.0.663）找「固定輸入來源 → 主張行上的呼叫」的資料流路徑。有被規則接受的路徑（預設 `strict`：路徑上沒有在同一個非運算子呼叫的兩個參數之間跳躍），發現改回 `candidate`，記 `joern_path: rule=… flows=… strict=…; path=…` 與 `verify_uncertain: joern path (refutation not applied)`；沒有路徑、那行沒有呼叫、語言不支援、沒有映像檔、逾時或任何錯誤都不改判決，只記一行 `joern: …`。它只會讓發現保留，從不關閉發現；零呼叫前置檢查的關閉不會被問到。verify 輸出在開啟時多一個 `joern_keep` 欄位（映像檔、模板、來源樣式版本、規則、每次容器執行的時間與記憶體）。`vettalon joern build` 從 binary 內的定義建 `vettalon-joern:<定義雜湊>` 映像檔：下載固定版本的 Joern（約 1.8 GB），核對寫死的 SHA-256 與 SHA-512，不用官方安裝腳本；這個映像檔不發布、不拉取。分析時容器 `--network=none`、唯讀根目錄、原始碼唯讀掛載、非 root、無 capabilities、記憶體 6 GB、2 CPU、容器內外各一道逾時（`--joern-timeout`，預設 900 秒）。查詢是編進 binary 的固定 Scala 模板，模型不寫查詢；主張的檔名與行號先過白名單，只當資料檔傳入。`vettalon joern check` 對一個 claims 檔回報每個位置的答案（`vettalon.joern-check/1`），不呼叫模型、不下判決，給離線評測用。是否值得用要看事先登錄的量測。
- `scan --refuter-score-threshold P`、`verify --refuter-score-threshold P`（0–100，預設關閉，實驗性，會一併打開 `--refuter-score`）：推翻只有在同一次回覆的 `p_real` 低於 P 時才關閉發現；分數等於或高於 P、缺值或格式錯誤時，那次覆核記為被降級的 `unresolved`，發現維持 `candidate`（`verify_uncertain`），推翻依據行的 `outcome=downgraded`。它只會讓推翻留著不關，從不把沒有推翻的發現關掉。verify 輸出在設定時多一個 `refuter_score_threshold` 欄位。是否改成預設要看事先登錄的確認與 O13 護欄。
- `scan --refuter-score`、`verify --refuter-score`（預設關閉，實驗性）：refuter 每次回覆另給 `p_real`（0–100，主張為真的機率）與五級 `evidence_level`（`safe_shown`、`safe_likely`、`undetermined`、`flow_likely`、`flow_shown`），記成證據行 `refuter_score: run i/n p_real=… evidence=…; verdict=…`；verify 輸出在開啟時多一個 `refuter_score: true`。兩個鍵在一般的嚴格解析之前取出，判決解析看到的是不含這兩個鍵的同一份 JSON；但 prompt 多了一段，模型本身的判決可能因此改變，這要靠量測確認；缺值、格式錯誤或重複鍵照實記下。只用口述分數，不用 token 機率，任何 roster 模型都能回。旗標關閉時 prompt 與解析完全不變，回覆裡多出這兩個鍵仍算違約。分數還在量測，沒有任何判斷使用它。
- `scan --refuter-policy`、`verify --refuter-policy`（預設 `current`，行為不變）：選用正在量測的 refuter 政策。`evidence` 讓關閉需要正向證據：refuter 可以回 `refuted`、`plausible` 或 `unresolved`，每個推翻都要寫出依據並引用摘錄裡的程式碼行，vettalon 逐行機械檢查（安全路徑、在 refuter 看到的摘錄裡、不是空行或註解；`guarded` 另要在主張的 trace 上並說明擋住哪些輸入形式；`defect_absent` 要引用主張檔案的行），不通過就降為 `unresolved`，不重問也不把原因回傳。`unresolved` 的發現維持 `candidate`，記 `verify_uncertain: unresolved k/n`，blockers 寫會改變判決的事實。`evidence-ext` 只對外部掃描器的主張（`verify` 的 claims）套用。`+prosecutor` 在以防護或「不是攻擊者可控」關閉時，多一次只看主張、摘錄與被引用行號的盲測呼叫，找到通過同樣檢查的繞過就不關閉；`+retrieval`（需搭配 evidence）在 refuter 點名看不到的識別字時，用確定性的定義搜尋取回定義再判一次。這些政策在事先登錄的量測通過前都不是預設。
- 每個推翻（任何政策）都多記一行證據 `refute_basis: run i/n <依據>; guard=…; cited=…; outcome=…`，事後可以依推翻依據分層；verify 輸出多一個 `refuter_policy` 欄位。判決與既有證據行不變，這些行排在結論行之前。
- `scan --allow-incomplete`：deep 掃描沒有任何 AI 引擎能執行時，照舊以門檻結果（0 或 1）結束，不回 4。報告內容不受影響。
- `vettalon agents pull`：從 GHCR 下載 egress proxy（`ghcr.io/zhixuli0406/vettalon-egress:<標籤>`）與不含 grok 的基底映像檔（`ghcr.io/zhixuli0406/vettalon-agents-base:<標籤>`，Node 加 codex），先用 cosign 驗證 keyless 簽章（簽署者必須是公開 repo 的 `.github/workflows/images.yml`，在 `main` 或 `vX.Y.Z` 發版 tag 上執行，issuer 為 `https://token.actions.githubusercontent.com`），每個簽章都要指向同一個 repo 與同一個 digest，通過後才以 digest 拉取並在本機加上標籤，最後在使用者自己的機器上從 x.ai 下載 grok，疊成 `vettalon-agents:<標籤>`。grok 的授權（xAI 服務條款）沒有給轉散布的權利，所以任何公開映像檔都不含 grok。沒裝 cosign 時預設拒絕，訊息會請你安裝 cosign 或改用 `vettalon agents build`；`--no-verify` 可略過驗證，說明裡標明不安全。掃描時不會自動拉映像檔（`docker run` 仍是 `--pull=never`，隔離旗標沒改）。缺映像檔的訊息改成先建議 `vettalon agents pull`。
- 公開 repo 新增 `.github/workflows/images.yml`（發版 tag 時由 `release.yml` 呼叫，也能在 `main` 手動執行）：建 linux/amd64 與 linux/arm64，標籤直接取自 CLI 的 `vettalon agents images`；以 digest 用 cosign v2.6.5 keyless 簽章，附 GitHub build provenance、BuildKit SLSA provenance（`mode=max`）與 SBOM。每個映像檔 digest 都有一份對應原始碼的 artifact（標籤 `<標籤>-source`，同時是映像檔的 OCI referrer，也有簽章）：egress 收每個 Alpine 套件建置時那個 commit 的 aports 目錄，加上 APKBUILD 列出的所有檔案（比對 sha512sums）；agents-base 收映像檔裡每個 Debian 原始碼套件的確切版本（比對 snapshot.debian.org 的 SHA-1 與 `.dsc`）、codex 發版 commit 的原始碼樹（含 bubblewrap），以及 codex `voice/sources.json` 列的上游壓縮檔（比對 SHA-256）。任何一項抓不到或對不上，job 就失敗，映像檔不會被加上標籤。已存在的標籤只有確認是這個 workflow 簽的才沿用，絕不覆寫。基底映像檔的 `/usr/share/licenses/INVENTORY.txt` 列出所有元件與授權，並補上上游套件沒附的授權文字（codex 的 Apache-2.0 LICENSE 與 NOTICE、Node 的 LICENSE、bubblewrap 的 LGPL、zsh 授權）。手動驗證與下載原始碼的方法寫在 `docs/TRUST.md`。
- 每日 registry 警報（`.github/workflows/registry-alert.yml`、`scripts/trust/registry_alert.py`）：五個 npm 套件從 0.3.0 起的每個版本，都要有 `v<版本>` tag 與已發布的 GitHub release、該 tag commit 上至少一次成功的 `release.yml` run，以及指向本 repo `release.yml`、同一 tag 與 commit、GitHub 託管 runner、上述 run、且 tarball 摘要相符的 npm provenance。不符就讓 job 失敗，另一個只有 `issues: write` 的 job 開或留言「Registry version without a matching release run」issue；檢查 job 只有 `contents: read`、`actions: read`，只用 `GITHUB_TOKEN`。0.2.1 以前（含 `0.0.0-stage` 佔位版）是 trusted publishing 之前手動或用 token 發的，沒有 provenance，列為不檢查；這份清單寫死在腳本裡，之後若出現其他低於 0.3.0 的版本一律算不符。2026-10-21 實跑：0.3.0、0.3.1 全數通過；0.3.0 四個平台套件的 provenance 來自 run 39410338641 第 4 次 attempt（該次重跑 npm-publish 時主套件已上線而失敗），同一 run 第 3 次成功，報告附註說明。

### Changed
- **結束碼可能和 0.3.1 不同**：`scan --profile deep` 的每個 finder 都在連到模型前失敗（容器映像檔不存在、找不到 CLI、連不上供應商），或有模組要審卻沒有設定任何 finder 時，結束碼改為 4（之前是 0，CI 分不出這種掃描和乾淨的 deep 掃描）。報告與 SARIF 照樣寫出，內容不變（`run_status: incomplete`、`incomplete_reason: engine_unavailable`，原因列在 `engines_missing`）。4 優先於門檻不通過的 1，終端結論寫「未完成」，門檻沒過時另列一行（見下一條）；Vettalon Pro 的 CLI 已用 3 表示需要授權，所以跳過 3。只有部分 finder 無法使用時結束碼不變，終端的執行狀態改寫出「N 個 AI 引擎無法使用，分給它的模組沒有審查」，不再只寫「AI 引擎無法使用」；全部無法使用時寫「沒有任何 AI 引擎能執行」，並在 stderr 說明結束碼與 `--allow-incomplete`。覆核模型連不上（finder 有跑）仍是 `units_failed`，結束碼照門檻。quick 掃描、`vettalon verify`（輸出檔寫出就是 0，看輸出的 `incomplete`）、Vettalon Pro 桌面版與 dashboard（用函式庫回傳值，不看結束碼）都不受影響。2026-10-21 實測（零模型呼叫，隔離 HOME、假的 docker 回報映像檔不存在、另一組設定指向不存在的 CLI）：0.3.1 行為兩組都是 0，改後兩組都是 4，加 `--allow-incomplete` 是 0，quick 是 0。README 新增完整結束碼表。Claude Code 外掛把 4 當成獨立結果（receipt 記 `ai-engines-unavailable`，報告照常讀取），不再顯示成「Scan failed」。Rust API：新增 `audit::cmd_scan_with`、`report::scan_exit_code`、`report::ai_audit_unavailable`、`report::AI_UNAVAILABLE_EXIT`；`audit::cmd_scan` 簽名不變，等同不加 `--allow-incomplete`。
- `scan` 終端摘要：deep 掃描沒有任何 AI 引擎能執行（結束碼 4）時，結論行不再印門檻的通過／未通過，改成「結論：未完成。所有 AI 引擎都無法使用（codex：容器映像檔不存在；ghost：找不到 CLI），AI 審查沒有執行；結果只含已執行的掃描器。結束碼 4。」（英文 `Result: INCOMPLETE. …`）。括號內依 `engines_missing` 列出哪個引擎、哪一類原因（容器映像檔不存在、無法執行 docker、找不到 CLI、API 金鑰環境變數未設定、連不上供應商或請求失敗、沒有設定 finder 模型；其他原因截短照錄），下一行寫對應的處理方式，例如 `vettalon agents pull` 或 `vettalon agents build`。門檻沒過時另印一行「門檻：發現 1 項 high 以上等級的問題，未通過。」（`Gate: FAIL, …`），掃描器找到的問題不會被蓋掉。加 `--allow-incomplete` 時照舊印門檻結論，後面接「注意：本次掃描未完成。…因為有 --allow-incomplete，結束碼照門檻結果。」與處理方式：只有結束碼不同，掃描一樣沒做完。之前兩種情況都印門檻結論（例如「結論：未達 --fail-on 門檻（high），視為通過。」）再加一行注意，容易被讀成通過。只有部分 AI 引擎無法使用（結束碼不是 4）時結論與注意不變。只動終端文字；2026-10-21 零模型呼叫實測 8 組（en／zh-TW、有無 `--allow-incomplete`、有無 high 發現），結束碼與正規化時間戳後的 JSON 報告、SARIF 都和改前相同。
- agents 映像檔拆成兩層：公開的 `vettalon-agents-base`（`docker/agents-base/`）與只在本機建置的 grok 層（`docker/agents/Dockerfile`，基底由 CLI 以 `BASE_IMAGE` 傳入，pull 時是驗證過的 digest）。`vettalon-agents` 的標籤改成基底標籤加本機層定義一起算，任一邊改了都會換；egress 標籤不變。`vettalon agents build` 照樣全部在本機建，不從 GHCR 拉。`vettalon agents images` 改印三行（agents、egress、基底），Claude Code 外掛跟著更新，只檢查掃描會用到的前兩個。agents 標籤因此換了，升級後要跑一次 `vettalon agents pull` 或 `vettalon agents build`。
- `scan` 終端摘要裡每筆發現的證據改成縮排一致的區塊：發現 id 底下依序列出證據等級、還缺哪些證明、實證紀錄，用一般用語取代 `proof_level=`、`proof_gaps=` 這類鍵值與內部術語（證據等級仍附上 JSON 用的鍵，例如 `static_only`）。「結束碼 0、連結或檔案雜湊不能證明漏洞存在」的說明只在區塊後印一次，`Result:`／`結論：` 前面多一行空行。只動終端文字，JSON 報告、SARIF（含 `vettalon.proof_limits`）、CycloneDX 與 `vettalon evidence attach` 的輸出都不變。
- Rust API：`disclose::ProjectMeta` 新增 `github_source`、`non_github_upstream`，`hunt::run::UpstreamInfo` 新增 `github_source`（JSON 舊報告沒有這欄照常讀取）；struct literal 需補上。新增 `disclose::UpstreamOrigin`、`disclose::normalize_github`、`disclose::detect_project_as`、`disclose::go_module_url`、`disclose::CHECKLIST_EN`、`disclose::checklist()`。`disclose::github_slug` 改走同一套正規化，多接受 `git+https`／`git+ssh`／`git://`／`www.github.com`，並拒絕 `..`、開頭 `-` 的名稱與 github.com 站內頁面（`orgs`、`sponsors` 等）。
- GitHub release 內文改由 tag 上的 `CHANGELOG.md` 產生（`scripts/trust/release_notes.py`，`release.yml` 以 `body_path` 傳入）：該版的「升級須知 / Upgrade notes」小節（有的話）、完整變更的連結，後面才接 GitHub 自動產生的 PR 清單。之前內文只有 PR 清單，升級步驟不會出現在 release 頁面。CHANGELOG 沒有該 tag 的 `## [X.Y.Z]` 段落時，release job 在建立 release 前失敗，所以發版 PR 要先切好 CHANGELOG。2026-10-21 用把 `[Unreleased]` 改名成 `[0.3.2]` 的副本實跑，內文帶出本版兩條升級須知。說明在 `docs/TRUST.md`。
- 文件與說明：`--refuter-policy evidence+retrieval` 改稱為量測過的選用保守模式，預設仍是 `current`，行為沒有改變。README 新增「保守模式」一節（英文 Conservative refuter mode）：適用情境（漏掉真漏洞的代價比多看告警高的稽核）、指令、量測與限制。2026-10-22 SastBench 確認集標籤核對過的子集（144 真告警／196 假告警，同一執行檔同日並行，verifier 為 Sonnet，`--refuter-runs 1`）上，被關掉的真告警 52.1% → 32.6%（−19.4 pp [−26.4, −12.5]，Holm p = 4.9 × 10⁻⁷），假告警 83.7% → 62.8%（−20.9 pp [−27.0, −14.8]）；鑑別力 ΔJ −1.5 pp [−11.9, +7.3]，未觀察到差異（檢定力不足，不能當成沒有差異）。只有一個基準與一個 verifier 模型，AI finder 候選上的護欄跑分（含 holdout）沒有跑。`evidence`、`evidence-ext`、`+prosecutor` 標為實驗性，不建議使用。`scan --help`、`verify --help` 的 `--refuter-policy` 說明同步改寫。

### Fixed
- `vettalon disclose`：掃描目錄是直接解開的套件（crates.io `.crate`、PyPI sdist、npm tgz）時沒有 `.git`，抓不到上游 GitHub repo，所以不會建議 GHSA 管道，`--check-duplicates` 也查不了上游。現在 git remote 不在 github.com 時，改讀 `Cargo.toml` `[package] repository`（homepage 只在本身是 GitHub repo 網址時才用）、`package.json` `repository`（字串、`{url}`、`github:` 簡寫）、`pyproject.toml` `[project.urls]`（標籤不分大小寫）與 `[tool.poetry]`、`setup.cfg` `project_urls`、`PKG-INFO` `Project-URL`、`go.mod` `module`（套件自己生態系的檔案先讀）。網址當不可信資料處理：只接受格式正確的 `github.com/<owner>/<repo>`，不是 GitHub 的只記主機名稱；審閱備註與 JSON 都記下來源檔案與欄位。sdist 的版本若在 pyproject 是 dynamic，改從 `PKG-INFO` 讀。`hunt` 的上游偵測共用同一段程式（之前 PyPI 只認 `Repository`／`Source`／`Homepage` 三個大寫標籤），Go 相依一律以模組路徑為準，`github.com/o/r/v2` 這類帶主版本的路徑也能對到 `o/r`。
- 英文草稿（`ghsa`、`email`、`minimal`、`kernel`）混入 zh-TW 文字：CWE 修補建議改用英文知識庫（沒有英文條目時用英文占位，不退回中文），影響說明的「（受影響：…）」、產品名稱占位「【產品／專案名稱】」與「（commit …）」也改成英文。zh-TW 只留在 TWCERT/CC 與 HITCON ZeroDay 表單。
- `vettalon disclose` 在英文終端顯示的管道建議與送出前檢查清單原本固定是中文，現在跟著終端語言。
- `hunt --report` 的相依審查失敗原因（`audited[].error`）會帶入終端語言：在 zh-TW 終端跑出的報告，`audit failed: ` 後面接的是中文訊息，之後用英文開啟或交給英文報告時就混進中文。現在一律存英文（新增 `audit::ScanError::message(lang)`、`ScanError::english()`，終端顯示照舊跟著語言），舊報告裡的中文字串照常讀取。
- 前次掃描結果變動時寫進報告的 `prior_changed_source` 證據原本是中文（「先前在此根因曾判定為…」），英文報告與 SARIF 的抑制理由都可能看到；改成英文，狀態清單用逗號分隔。JSON 結構不變。
- `scan --save` 在同一秒內完成的掃描會寫到同一個 `~/.vettalon/reports/<時間>.json`，後完成的直接覆寫前一份，終端卻每次都顯示「報告副本已存至」，下一次掃描的前次承接（`prior_run`）只看得到剩下的那份。2026-10-21 實測 quick profile 連跑兩次、同時跑四次，都只留下一個檔案。現在檔名帶到微秒（例如 `20261021T061545.249716Z.json`），報告先寫進同目錄的暫存檔，再以不覆寫的方式改成正式檔名；檔名已被占用就改用 `-1`、`-2`…（最多試 100 個），所以不同行程同時存檔也各留一份，讀的一方也不會讀到寫到一半的檔案。挑選最新報告改依檔名裡的時間排序（秒、小數、序號），舊的秒級檔名照常讀取，視為該秒的開頭；原本的純字典序會把舊檔名排在同一秒的新檔名後面，也會把 `-2` 排在 `-10` 後面。
- codex、grok 容器的映像檔標籤原本是 CLI 版本號（例如 `vettalon-agents:0.3.0`），所以每次升級 vettalon，就算 `docker/` 完全沒改，新版本號的映像檔也不存在，容器執行一律失敗，要重跑 `vettalon agents build` 才恢復；這段期間 deep 掃描把這兩個引擎記成略過、標為未完成，結束碼仍是 0。2026-10-21 從 0.3.0 升到 0.3.1 的量測就因此讓 grok 沒有啟動。現在標籤是建置內容的 SHA-256 前 12 個十六進位字元（agents 算 Dockerfile；egress 算 Dockerfile、`tinyproxy.conf`、`allowlist`），`agents build` 寫出的檔案和算標籤用的是同一份清單，定義一改標籤就跟著換，沒改就沿用已建好的映像檔。新增 `vettalon agents images`，印出預期的映像檔標籤（不呼叫 Docker）；Claude Code 外掛改用它檢查映像檔，不再從 `--version` 推算。缺映像檔時的訊息補上「需要 Docker 與網路」。升級到這一版時還是要重建一次，因為標籤格式換了。容器的隔離旗標沒有改。
- 公開版文件與程式註解裡有些路徑和連結指向公開 repo 沒收錄的檔案（評測協定、排序基準、真實跑分 runner、覆蓋率收據與驗收紀錄），點了會 404。改成直接描述內容，Jev 的依據改連官網基準測試段落。只改文字，行為不變。

### Security
- 發版工作流的 cosign 從 v2.5.2 升到 v2.6.5（2026-08-06，v2 最後一版，含 GHSA-whqx-f9j3-ch6m、GHSA-w6c6-c85g-mmv6、GHSA-fx35-mq7g-6g98 修補）。簽章指令與輸出檔（`.sig`、`.pem`、`.sigstore.json` bundle v0.3）不變；`verify-release.sh` 的 `cosign verify-blob` 已用 v2.5.2、v2.6.5、v3.1.3 對 v0.3.1 封包實測通過，錯的 tag 身分與改過的封包三版都拒絕。`docs/TRUST.md` 建議驗證端用 v2.6.5 以上或 v3。
- 公開 repo 啟用 immutable releases（2026-10-21 起，v0.3.2 以後的 release 發布後 tag 與檔案鎖定並附 GitHub release attestation；v0.3.1 以前不受保護）。`release` job 本來就是先建草稿、上傳、再發布，相容；發布後重跑 `release` job 會失敗，npm-publish 失敗時改用「Re-run failed jobs」。驗證方式寫在 `docs/TRUST.md`。
- `release.yml` 收緊：checkout 一律 `persist-credentials: false`，tag 改經環境變數傳入 minisign 與 npm stage 步驟（不在 shell 內展開 `${{ }}`），發布 job 的 `setup-node` 關閉套件快取。

## [0.3.1] - 2026-10-21

### Added
- `scan --verifier-parse-retries 0|1`、`verify --verifier-parse-retries 0|1`（預設 1）：refuter 回覆違反回覆合約（不是 JSON、`plausible` 沒有 blockers 或驗證計畫、`refuted` 沒有 `refute_basis`、推翻時帶修正或前置條件、`plausible` 帶防護引用）時，把違反原因寫進修正 prompt 再問同一次覆核一次，與 finder 的 reflector 同一個模式。修正呼叫另計一次呼叫，證據記 `verifier_reflector: N reply(ies) ... re-asked, M recovered`。防護引用檢查與修正位置檢查不是格式問題，不會重問。
- `agy`（Google Antigravity CLI 1.4.3）CLI preset：prompt 以 stream-json 從 stdin 送入（不進 argv），每次在空的暫存目錄執行，環境變數照白名單過濾，並停用 slash command、加 `--sandbox`。agy 沒有關閉工具的旗標：headless 模式會自動拒絕需要授權的工具（2026-10-20 實測：要求在工作目錄建檔或讀外部檔案都被拒，沒有檔案被建立或讀到），但 `search_web` 不需授權；因此串流裡只要出現任何工具步驟、被拒動作、非 SUCCESS 狀態或空回覆，整個回覆就丟棄並記為錯誤，prompt 前面另加一行不用工具的說明（agy 會讀使用者的 `~/.gemini/GEMINI.md`，無法關閉）。沒有容器映像檔，所以必須設 `allow_agent_tools = true` 才能用。家族只有 Gemini 模型自動帶 `google`，其他模型（agy 也提供 Claude、GPT-OSS）要自己填 `family`。
- `vettalon verify <repo> --input FILE --verifier ID --out FILE [--trace FILE] [--refuter-runs N]`：只跑反駁覆核、不呼叫 finder。輸入可以是 `scan --report` 的報告（只覆核還沒覆核過的 AI 候選，與 scan 用同一套 prompt、摘錄、前置檢查、多次覆核與結算），或其他工具的 `vettalon.claims/1` 檔（每筆主張轉成候選後覆核，`found_by` 記 `external:<source>`，投票的 `cross_family` 一律為 false）。輸出 `vettalon.verify/1` JSON（每筆發現、覆核數、零呼叫結算數、未覆核數、呼叫數）；第一次呼叫就連不上模型時其餘不再嘗試，記 `verify_error` 並標成 incomplete。
- `scan --finder-parse-retries 0|1`（預設 1）：finder 回覆違反 JSON 合約時要不要用修正 prompt 再問一次。0 時直接記為解析失敗，給有零自動重試規定的評測用。
- CLI 模型也吃 `max_tokens`：回覆超過 `max_tokens` × 4 位元組就算錯誤（不截斷後使用），`claude` 另外透過 `CLAUDE_CODE_MAX_OUTPUT_TOKENS` 在每次請求帶上限；其他 CLI 看不到的推理 token 不受限。
- `--trace` 的每筆失敗呼叫多一個 `error` 欄位（遮罩後最多 200 位元組，不含 prompt 與回覆），評測 harness 用來分辨限流與一般錯誤。
- 評測共用的真實模型呼叫斷路器（給不在公開 repo 的真實跑分 harness 使用）。硬上限是核准數加 10%（呼叫前就拒絕越界），任何連續 50 次呼叫中錯誤或拒答超過 20% 就停，限流持續 15 分鐘也停；不重試模型呼叫。排序基準（不在公開 repo）的 `prescreen --prescreen-scorer claude` 改為必須帶 `--approved-calls N`，並記錄 CLI 回報的模型 id。
- O13 修訂設計 v2 的真實跑分 runner（不在公開 repo）：finder 每題只跑一次（Claude，無 reflector），同一批候選交給各臂的 refuter（`vettalon verify`），各臂判的主張完全相同。修訂紀錄與理由另行保存，原凍結計畫（c6075d0b…）不動。
- SastBench 代表樣本 100 題的真實跑分 runner（不在公開 repo）。每題從 `adapter.model_input`（無標籤）轉成一筆 claim，只從 raw.githubusercontent.com 抓各位置指到的檔案到 repo 外的快取，交給 `vettalon verify` 覆核一次；標籤只在 `score` 才接上。

### Changed
- 每次重問都多記一筆證據 `verifier_reflector: run k/n re-asked after contract break (原因); second reply: refuted|plausible|...`，看得出重問的原因與第二次回覆的結果，用來檢查重問是否把模型教成能過檢查的推翻。不影響狀態與 `evidence_level`。
- refuter prompt 收緊兩種推翻：防護或消毒只擋住部分輸入形式（巢狀運算子、其他編碼、其他分支）時不算安全，要回 `plausible` 並把缺口列為 blocker；流向看得到、但決定是否安全的程式碼不在摘錄裡時，缺的程式碼是 blocker，不是推翻的理由。完全看不到流向的主張照舊推翻，refute-by-default 不變。依據是 SastBench 代表樣本 17 個被關掉的真告警的逐題分類（不在公開 repo）。**結果可能和 0.3.0 不同**：有部分防護的發現可能從 `refuted` 變成 `needs_human`。
- **覆核結果可能和 0.3.0 不同**：違反合約的 refuter 回覆不再被當成一個意見。多次覆核中只要有一次在重問後仍違約，該發現記 `verify_error: incomplete refuter runs`（整次 incomplete），不再是 `verify_uncertain`；先前因一次違約而落到 `verify_uncertain` 的發現，現在可能在重問後得到一致結論（`needs_human` 或 `refuted`），或改記 `verify_error`。違約回覆從來不會被記成推翻，這點不變。Rust API：`ReviewPlan` 新增 `parse_retries`，`RunVerdict` 新增 `Malformed`，`ScanOptions` 新增 `verifier_parse_retries`，`verify_only::VerifyOptions` 新增 `parse_retries`。
- Rust API：`ScanOptions` 新增 `finder_parse_retries`（預設 `audit::DEFAULT_FINDER_PARSE_RETRIES`）、`CliSpec` 新增 `max_output_tokens`、`output_cap_env`，`PromptVia`／`OutputMode` 新增 `AgyStreamJson`，`TraceEvent` 新增 `error`；struct literal 與窮舉 match 需補上。新增 `audit::verify_only`。
- 拒答偵測多認得供應商過濾器的回覆（「This request was blocked by Gemini's filters」），這類回覆記為拒答，不再算成違反合約的回覆。

### Fixed
- npm 發布腳本：平台套件（`@vettalon/*`）發布或 staging 失敗時直接中止，不再被誤報成「SKIP (no binary)」後繼續跑（0.3.0 的 npm job 是因為最後的 `vettalon` 也失敗才變紅；若只有平台套件失敗，job 會顯示成功）。

## [0.3.0] - 2026-10-20

### Added
- `scan --prescreen cheap-model --prescreen-model <id>`（預設 `off`，只在 `--profile deep`）：兩段式排序。排序（heuristic 或 Jev）之後，用模型清單裡指定的便宜模型替前 `--prescreen-pool` 個審查單元（預設 40，上限 200）各打 1–5 分（訂閱制 CLI 拿不到 logprob，所以是序數分數），深審只拿前 `--prescreen-top` 百分比（預設 20%），仍受 `--max-modules` 限制；其餘單元在 coverage 記 `deferred`／`prescreen_cut`。每個單元一次呼叫，prompt 上限 6 KiB，含單元路徑、最多 20 個檔案路徑與一個檔案的前 60 行（≤2 KiB），機密檔不取片段；含對 AI 審查者下指令文字的單元不送出、直接給 5 分。失敗、逾時（每次 120 秒）或拒答的單元以 3 分計，沒有任何分數、有單元因時間預算未開始、或超過一半的呼叫沒拿到分數時，維持原排序、不裁切（`degraded`）。沒有 finder 模型時不跑預篩。報告新增 `ensemble.prescreen`（呼叫數、成功／失敗／拒答／強制數、送出與收到的位元組、耗時、每個單元的分數與是否入選），`--trace` 記為 step `prescreen`。效益尚未用真模型量過。
- `scan --finder-budget`／`--refuter-budget`／`--poc-budget <秒>`：各角色從自己的步驟開始計時的上限。finder 上限與 `--time-budget` 取早者，到期的模組 deferred；refuter 上限到期後不再開始新的覆核，未覆核的發現記 `verify_error: refuter budget exhausted` 並以 `critic_budget_exhausted` 標成 incomplete；PoC 上限到期後不再開始新的 PoC，符合條件的發現記 `poc_skipped`，整次標成 incomplete（`time_budget_exhausted`）。啟動時驗證所有預算旗標，0、低於 60 秒（一次模型呼叫的下限）或角色上限大於 `--time-budget` 都在任何掃描器或模型執行前以 exit 2 結束並說明原因；有設定時在 stderr 印出實際預算表。報告新增 `ensemble.budget`（各上限與哪個上限實際截斷了工作）。
- `hunt --hunt-budget <秒>`：總預算取代每個相依固定的時限。每個相依開始時分到「剩餘預算 ÷ 剩餘相依數」，提早結束的額度往後滾給後面的相依（Team Atlanta 在 AIxCC 的做法）；同時給 `--dep-timeout` 時它是單一相依的上限。剩餘預算不足 90 秒的相依不啟動，記 `deferred: the hunt budget could not fund this dependency`，整次加上 `hunt_time_budget_exhausted` 並標成 incomplete。預算以各相依自身耗時加總計算，`--dep-concurrency` 大於 1 時進行中相依的額度保留到它結束；剩餘不足 90 秒但仍有相依在跑時，下一個相依會等它結束、拿回沒用完的時間再判斷，只有沒有相依在跑時才 deferred。開始時印出預算表；報告新增 `budget`（模式、總額、上限、已用、deferred 數與每個相依分到／用掉的時間）。
- 修補建議驗證（O19）：發現新增選填欄位 `suggested_fix`（unified diff，上限 64 KB，讀報告時超過即拒絕，不截斷），JSON 報告另有衍生欄位 `fix_check`、SARIF 有 `vettalon.fix_check`，`outcome` 為 `fix_verified`／`fix_check_partial`／`fix_rejected`／`fix_unverified`；沒有針對這份 diff 的檢查紀錄一律是 `fix_unverified`（`not_checked`）。`--poc` 時，在暫存目錄的兩份副本上檢查（使用者檔案只讀）：A 用 PoC oracle 的 harness，對該類別每個 fixture 輸入比較原始與修補副本，原始仍有效果、修補後沒有，且良性輸入在修補副本仍正常運作才算通過（只把程式改壞的修補會被否決），原始已無效果記為無法判定；B 只在設定 `--fix-test-command` 或 `[fix_check] test_command` 時，以同一套沙箱限制先後在原始與修補副本跑專案測試，不會自動推測指令。修補檢查和 PoC 共用 `--poc-budget`／`--time-budget`，用完時記 `time_budget_exhausted`。碰到目錄外路徑、二進位檔、符號連結、`.git`、秘密檔，或改名、刪檔、改權限的 diff 在執行前拒絕。結果記為新證據種類 `fix_check`（固定格式、嚴格解析、`outcome` 必須與 A／B 一致、綁定 diff SHA-256），模型意見不影響結果。adapter 由模型撰寫且只能 import 專案程式，目前只適用可 import 的 Python 程式；掃描流程目前沒有自動產生 `suggested_fix`。
- `scan --dual-finder-top N`（預設 0，關閉）：排名前 N 的模組由兩個 finder 家族各自獨立審，這些模組的 finder prompt 另外要求每筆候選附一個選填的修補建議（`fix`：單一檔案、最多 10 行的行範圍替換，只用來去重，從不套用到 repo、也不寫進報告）。覆核前依根因合併兩邊的候選：某個可用修補套到檔案的記憶體副本後同時改掉兩筆的 sink 行才合併（`dedupe_basis=same_patch`），有可用修補但沒改到另一筆 sink 行就保留兩筆；兩邊都沒有可用修補時退回同一 sink 檔、sink 行相距 3 行內且 CWE 相同（`location_cwe`），缺 CWE 不合併；同一 id 記為 `identical_claim` 並最先比對；兩筆 CWE 不同時即使同一修補也不合併。合併後的發現 `found_by` 列兩家、帶 `dual_finder_merge` 證據，被合併掉的 id 在 coverage 改指向保留的那筆。這些候選優先交給第三家族的 verifier。報告新增 `ensemble.dual_finder`：各家族候選數、獨有根因數與其中 `needs_human` 數、兩家共同根因數、各去重依據的合併數、可用修補數，以及加開 finder 的邊際產出（呼叫次數、送出原始碼位元組、多出的根因與 `needs_human`、每多一筆 `needs_human` 的呼叫數與 KiB）；CLI 摘要也會列出。成本：這 N 個模組的 finder 呼叫加倍、原始碼多送一家廠商，回覆也較長；Vettalon 看不到價格，金額需自行換算。只有一個 finder 家族時記為 skipped。前 N 個指實際送審的模組（有 `--prescreen` 時為篩選後順序）；第二家族的審查共用 finder 期限（`--finder-budget`／`--time-budget`），用完就照常 deferred，邊際產出只計實際跑完的呼叫。Pro 服務與桌面版維持關閉。
- 反駁覆核（verifier）讀到的程式碼預設去除註解與 docstring（行號不變），去掉的文字另附在標明為作者資料的 `<stripped_comments>` 區塊。依據 ALIBI（arXiv 2607.24964）：植入「已驗證安全」註解或假造工具輸出的攻擊成功率超過 90%，去註解比 prompt 警告有效。支援 Rust、Go、C 系（C/C++/Java/C#/Kotlin/Swift/Scala/Dart）、JavaScript/TypeScript、PHP、Python、Ruby、shell、YAML/TOML、Perl/R/Elixir、Terraform/HCL、SQL、Lua、Haskell，其他檔案原樣送出。保留會影響編譯或檢查的指令註解（`# type:`、`# noqa`、`# pragma`、`//go:build`、`// +build`、cgo preamble、`/// <reference>`、`// @ts-…`、`{-# … #-}`、第一行 shebang、編碼宣告），每種都要完全符合已知格式，只留符合的那段（最多 120 位元組），後面的理由文字照樣去掉（`# nosec: verified safe` 只剩 `# nosec`）。主張引用的行落在多行註解或 docstring 裡時，那段摘錄改用原檔內容。High 以上本來就跑多次覆核時，第 2 次改讀帶註解的原始碼（不多花呼叫，受 `--refuter-budget` 限制，預算用完就不跑也不記錄）（evidence 記 `refuter_run 2/n (with comments)`）；它的結論與所有去註解的覆核相反時記新證據種類 `comment_sensitivity`，此時結論不一致，發現維持 `candidate`（`verify_uncertain`），帶註解那次的推翻理由也不會列為 `strongest_counterevidence`。`injection.rs` 的零 LLM regex 掃描照舊在原始檔上先跑。SARIF 帶 `vettalon.comment_sensitivity: true`，CLI 摘要列出筆數。
- verifier 判 `plausible` 時可回傳自己看到的前置條件（回覆新增選填欄位 `conditions`，種類與 finder 相同的九種，最多 10 筆）；存成發現的 `refuter_conditions`。可利用性等級改取 finder 與 verifier 中摩擦較高者；兩者等級不同時記新證據種類 `tier_disagreement`（`finder=… refuter=… effective=…`）。多次覆核都可能成立時取摩擦最高的那份。`refuted` 回覆帶非空 `conditions` 視為違反合約（`verify_error`）。SARIF 新增 `vettalon.exploitability_finder`、`vettalon.exploitability_refuter`，不一致時 `vettalon.tier_disagreement: true`；CLI 摘要列出不一致筆數。
- 新證據種類 `comment_sensitivity`、`tier_disagreement`、`dual_finder_merge`，都不改變狀態也不影響 `evidence_level`。舊版 binary（含舊版 Pro／桌面版）讀不了含這些種類的報告；新版可讀舊報告。
- 每筆發現新增衍生欄位 `evidence_level`（`static_only` → `refuter_survived` → `refuter_consistent` → `poc_effect_no_control` → `poc_differential` → `maintainer_confirmed`）、`proof_gaps` 與 `strongest_counterevidence`，JSON 報告、SARIF（`vettalon.evidence_level`、`vettalon.proof_gaps`、`vettalon.strongest_counterevidence`）與 CLI 摘要（每筆 `Evidence <id>:` 一行）都會輸出。三者在寫報告時由證據鏈計算，模型無法設定；報告檔裡存的值讀回時忽略，舊報告依既有證據推導、不會被升級。有 `verify_error` 時最高 `static_only`，有 `verify_uncertain` 時最高 `refuter_survived`；`maintainer_confirmed` 只來自人工確認。
- 新證據種類 `verify_uncertain`（多次反駁覆核結論不一致）與 `poc_oracle`（harness 判定的 PoC 結果，`detail` 為固定機器格式，解析嚴格，格式不符一律忽略；由 `--poc` 的 harness oracle 產生，見本節「PoC oracle」一則）。
- `scan --refuter-runs N`（1–5，預設 3）：High 以上的發現跑 N 次獨立反駁覆核，每次各記一票。全部判可能成立才標 `needs_human` 並記 `refuter_consistent: N/N`，全部推翻才證偽，每次都有回覆但結論不一致時維持 `candidate` 並記 `verify_uncertain: k/N plausible`（不讓整次執行變成 incomplete）。額外的覆核在 `--time-budget` 用完後不再開始，某次呼叫失敗也會停掉剩下的次數；這類沒跑完的覆核記 `verify_error: incomplete refuter runs`，整次執行標成 incomplete。舊版 binary（含舊版 Pro／桌面版）讀不了含新證據種類的報告；新版可讀舊報告。
- `vettalon hunt --dep-priority risk`：依 `exposure × reach × criticality` 排序相依並列出每個因子的依據；離線計算，查不到的標 `unknown`，預設排序不變。
- `vettalon hunt --variant-seeds`：把套件過去的 OSV 紀錄與上游 GitHub 提到 security／CVE／GHSA 的 commit 當成 finder 的線索（上限 4 KB，只給 finder）；審完重查 OSV；只有 advisory 的修補版本比鎖定版本新時，同 CWE、同檔案的 finding 才當成已知重複，其餘標為可能的變體、仍列為候選。新增連線 `api.github.com`。
- `vettalon rule-draft`：從人工確認的 finding 產生本機 Semgrep 規則草稿，需人工審閱後才能使用。
- `vettalon hunt --malicious-signals` 與 `vettalon mal-index update|status`：規則型惡意套件訊號（發布時間、新增安裝掛鉤、provenance 變動、`MAL-*` 命中、名稱近似熱門套件、查無名稱），finding 一律 `needs_human`。規則無法判定時報告標為未完成；`--dry-run` 只跑離線規則。單元層級回放：893 筆近 90 天真實 MAL 名稱（索引用同一批紀錄建，全數命中只驗證比對邏輯）；3,000 個熱門套件配固定舊版資料，finding 0。發布時間、安裝掛鉤、provenance 規則尚未用真實套件量測。`mal-index` 只連 `osv-vulnerabilities.storage.googleapis.com`，並記錄封存檔 SHA-256。
- 評測用的共用統計 `benchmarks/common/`：每個比率以 `k/n` 加 95% 區間呈現（Wilson；0/n 與 n/n 用精確界並另給單側上界），n<300 不用常態近似；同一批題目上的兩個配置用題目層級配對差比較，並依預先登錄的效果量標出 underpowered。只用標準函式庫，不呼叫模型。
- PoC oracle：指令注入（CWE-78/77）、路徑穿越（CWE-22/73）與 SQL 注入（CWE-89）的沙箱 PoC 改為 harness 判定——每次容器執行產一組一次性秘密，以真實副作用（注入 shell 複製秘密檔、`../` 讀到允許範圍外的檔、`UNION` 撈出秘密列）決定 effect，PoC 自己印的成功字樣不算數。執行前有零 LLM 靜態反作弊，之後跑良性輸入 control 與換 nonce 重跑。結果記為 `poc_oracle` 證據（`effect／control／rerun／nonce_bound／rejected`），可推到 `poc_effect_no_control`／`poc_differential`，另存一筆已遮罩的執行紀錄；狀態維持 `needs_human`。SSRF（沙箱無網路）與其餘類別維持獨立模式示範。沙箱隔離（`--network=none`、唯讀 root、drop capability、非 root）不變。
- 揭露草稿（`vettalon disclose`、`hunt --disclose-dir`）：`--format ghsa|minimal|kernel|email` 依目的地切換格式；每份草稿固定附「AI 使用聲明」（工具版本、各模型用途、人工審閱者化名與日期）；`--no-patch` 拿掉修補段落；`--check-duplicates` 在送出前查 OSV、上游 GitHub 近 90 天動到該檔的 commit 與未結 issue／PR（只經 hunt 出口 allowlist，新增 `api.github.com`；未查就寫「未檢查」，從不寫「無重複」）；目標 SECURITY.md 當資料處理，只列出需人工確認的要求；依賴類發現分開寫「上游是否有漏洞」與「你的專案是否執行到」（沒有實際執行證據時為未知）。新增 `vettalon disclose-ledger list|close` 管理每個專案的節流紀錄，設定檔新增 `[disclosure] reviewer`。
- Deep scan 加入 opt-in `--source-receipts`，在 JSON／SARIF module coverage 記錄來源快照、實際提交前綴及本機提示 SHA-256；模型回覆與未知傳輸分開標記。這不代表模型已讀、理解或提升召回。
- OpenSSF Scorecard workflow（`.github/workflows/scorecard.yml`）：每週、push 到 main 時執行，結果公開到 Scorecard API 並上傳 code scanning；使用預設 `GITHUB_TOKEN`，所有 action 釘選 commit SHA。
- Claude Code plugin 可從 GitHub 安裝：repo 根目錄新增 `.claude-plugin/marketplace.json`（名稱 `vettalon`），用 `/plugin marketplace add zhixuli0406/vettalon` 加入後 `/plugin install vettalon@vettalon`。原本的 `vettalon-local` 本機開發流程不變。
- `.bestpractices.json`：OpenSSF Best Practices passing 等級的自評答案（66 條有答案：60 Met、4 N/A、2 Unmet，Unmet 都是 SUGGESTED），在 bestpractices.dev 建立專案時會自動帶入，送出前仍由維護者逐條確認。
- README 加上 OpenSSF Best Practices badge：專案 15717 於 2026-10-20 達到 passing 等級（自我認證）。
- CodeQL 掃描（Rust、Python、workflow）與 Dependabot 每週相依更新。
- cargo-fuzz 模糊測試（`fuzz/`）：五個 target 餵不可信輸入給 hunt 的 lockfile 解析、模型回覆合約與 pre-check、路徑與 ID 原語、相依套件壓縮檔解壓、機密遮罩，除了不得 panic 也檢查不變式（例如 pre-check 放行的行號一定取得到程式碼、解壓不會寫到目的地之外、已知前綴的憑證遮罩後不會殘留）。CI 新增 `fuzz` job，用固定日期的 nightly 每個 target 跑 45 秒。用法見 `fuzz/README.md`。`.bestpractices.json` 的 `dynamic_analysis` 與 `dynamic_analysis_fixed` 隨之改為 Met。
- Go 可達性語料（`benchmarks/reachability/corpus/`）：16 個 vuln.go.dev 公告、40 個自寫 host（每個公告 called／not-called 各一，加上 reflection、interface dispatch、function value、unsafe 四類盲點各兩個）。答案用 `go build -cover` 實際執行一次標註；`run_corpus.py` 比對 adapter 三態、govulncheck v1.4.0 與最新版（本次 v1.9.0）的 OpenVEX。只有 `prepare` 連 Go proxy，實驗本身 `GOPROXY=off`、`GOFLAGS=-mod=mod`。2026-10-20 實跑 false-unreachable 為 0、盲點 host 沒有 `not-observed`；兩版 govulncheck 對 4 個實際執行到漏洞函式的 reflection/unsafe host 都給 `not_affected`。盲點規則是對著這份語料寫的，不是 held-out 結果。
- Cargo SBOM 差分測試（`scripts/trust/sbom_diff.py`）：比對 Syft CycloneDX、`cargo metadata --locked` 依 target／features 解析的建置圖，以及 nightly Cargo SBOM precursor（只當測試 oracle）；component precision／recall、版本正確率、license 正確率分開報。另加 7 個 parser confusion fixture（`fixtures/sbom/confusion/`），錄下的結果放在 `fixtures/sbom/differential/`，離線測試可重播。`fixtures/sbom/rust` 上 Syft 列出 12 個套件、實際建置圖 7 個（precision 0.58、recall 1.00）。
- 跨家族覆核量測 `benchmarks/owasp-fp/crossfam_run.py`（O13）：finder 家族 × refuter 家族的 2×2 加同模型 fresh session，每臂報召回、誤報率、uncertain 率、翻案率與翻案正確率，臂間報錯誤重疊 Jaccard、方向性與題目層級配對差；以 case 為主的排程加呼叫帳本，預算用完時各臂停在同一題且未跑的題留在分母；fake model dry run 走完整矩陣。既有兩份 OWASP 結果的 0 次呼叫重分析與待核准的跑分計畫見 `CROSS-FAMILY-2026-10.md`；正式執行在擁有者核准綁定 plan 雜湊、且 roster 能強制 1,024 輸出 token 之前一律拒絕。
- CVSS v4.0 計分：來源給的 `CVSS:4.0/…` 向量現在會計分，用 FIRST v4.0 規範（文件 1.2）的 MacroVector 查表加插值。查表、各 EQ 最高嚴重度向量與指標順序逐字取自 FIRST 官方計算機（FIRSTdotorg/cvss-v4-calculator，commit c5b0d40，BSD-2-Clause，授權全文附在 NOTICE）。測試比對 FIRST 範例頁 51 筆與官方計算機 300 筆輸出；另用官方計算機產生 6 萬筆（含 Threat、Environmental）做過一次比對，全數一致。向量順序不符 Table 23、缺 Base 指標、值不合法都直接丟棄。報告 JSON 的 `cvss` 物件多了寫入時衍生的 `rating`，v4.0 另有 `nomenclature`（CVSS-B／BT／BE／BTE）。讀回報告時只採用向量，分數與版本一律重算，向量算不出分數的項目直接丟棄，手改過的分數不會流到 SARIF、CycloneDX 或 Pro 報告。vettalon 不會自行在來源向量加 Threat 或 Environmental 指標。
- CWE 對應建議：內附從 MITRE CWE List 4.20（2026-04-30）產生的 `cwe_usage.json`（產生器 `scripts/standards/gen_cwe_usage.py`，來源與日期寫在檔內）。每筆發現衍生 `cwe_mapping`：CWE 版本、abstraction、MITRE 的 mapping usage（`allowed`／`allowed-with-review`／`discouraged`／`prohibited`／`not-in-catalog`）與知識庫裡更具體的建議編號。Discouraged／Prohibited（Pillar、Category、View、CWE-20／200／284、CWE-1426 等）與目錄裡沒有的編號，SARIF 會多帶 `vettalon.cwe_mapping_warning`。AI 發現給的 CWE 若屬 Discouraged／Prohibited，而它自己的類別在知識庫裡正好對到該編號的子項，就改用子項，原編號存在新欄位 `cwe_replaced`。
- SARIF 加入 CWE taxonomy：`runs[].taxonomies`（CWE 4.20，taxon 帶 mapping usage）、`tool.driver.supportedTaxonomies`，result 以 `taxa` 參照。result 另帶 `vettalon.cvss_label`（例如 `CVSS v4.0 8.7 High (CVSS-B)`）、`vettalon.cve_refs`、`vettalon.severity`、`vettalon.severity_basis`；既有 `vettalon.*` 鍵不變。
- `scan --cyclonedx <path>`：把相依套件公告類發現輸出成 CycloneDX 1.6 VDR/VEX（JSON）。內容有受影響套件（Package URL）、公告、CVE 參照、來源的 CVSS 評分（含向量）、vettalon 的定性評分（`method: other`，不帶數字）與 CWE。`analysis.state` 只依紀錄的證據：操作者確認為 `exploitable`、操作者判定誤報為 `false_positive`，其餘一律 `in_triage`；`not_affected` 永不輸出（需要操作者的 VEX 理由，目前沒有收集）。程式碼類發現不輸出。實測輸出曾以 CycloneDX 1.6 官方 JSON Schema 手動驗證通過（尚未納入自動測試）。
- CVE 參照狀態：每筆發現衍生 `cve_refs`（`published`／`unverified`），只有 vettalon 手上的 OSV 資料列出該 CVE 時才能標 `published`（`audit::cve::check_against_osv`，狀態每次重算、不存進報告）。`scan` 流程不查 OSV，RustSec 帶來的 CVE 一律 `unverified`。相依套件發現新增 `package`（ecosystem／name／version，可產生 Package URL）。

### Changed
- `--time-budget` 啟動時驗證：0 或低於 60 秒改為 exit 2（先前會接受並立刻把所有模組 deferred）。期限改從 AI 步驟開始（intake 之後）計算，排序（Jev、prescreen）的時間也算在內；期限到後不再開始新的 PoC，符合條件的發現記 `poc_skipped` 並把整次標成 incomplete（先前 PoC 不受此限）。每筆發現的第一次 refuter 覆核仍照跑，只停額外的覆核，與先前相同。
- `hunt --dep-timeout` 低於 90 秒改為 exit 2（先前任何值都接受）；未給時仍是 300 秒。
- Rust API：`ScanOptions` 新增 `prescreen`、`role_caps`；`HuntOptions` 新增 `rollover`；`HuntReport` 新增 `budget`；`EnsembleInfo` 新增 `prescreen`、`budget`。外部以 struct literal 建構者需補上（`None`／`Default::default()`）。JSON 相容：新版讀舊報告時這些欄位視為未設定；報告、`ensemble` 與 hunt 報告不拒絕未知欄位，舊版 binary 讀新報告時略過它們。
- Rust API：`Finding` 新增 `suggested_fix`、`EvidenceKind` 新增 `FixCheck`、`ScanOptions` 新增 `fix_test_command`、`Config` 新增 `fix_check`，struct literal 與窮舉 match 需補上；`DockerSandbox` 新增 `run_args_mounted`、`run_workspace_with_tree`、`run_in_tree`，既有方法行為不變。
- `vettalon.exploitability`（SARIF）與報告排序用的可利用性等級，在 verifier 有給前置條件時改取 finder 與 verifier 中摩擦較高者；沒給時與先前相同。
- finder 回覆合約接受選填的 `fix` 欄位；格式不對只丟掉該修補，不會讓整個模組的回覆作廢。verifier prompt 新增 `conditions` 說明與欄位。
- Rust API：`ScanOptions` 新增 `dual_finder_top`；`Finding` 新增 `refuter_conditions`；`EvidenceKind` 新增 `CommentSensitivity`、`TierDisagreement`、`DualFinderMerge`；`EnsembleInfo` 新增 `dual_finder`。
- 反駁覆核（verifier）只看主張與程式碼：trace 步驟的描述（finder 的推理）不再送進 prompt；prompt 預設「程式碼證明不了就推翻」。`refuted` 回覆必須帶 `refute_basis`（`guarded`／`defect_absent`／`unreachable`／`not_dangerous`）；依賴防禦檢查的推翻必須附 `guard` 檔案與行號，該行要存在且在主張的 trace 上（同檔、任一引用行前後 20 行內），否則記 `verify_error: refutation cites missing guard`，推翻不採用、發現維持 `candidate`。High 以上預設多兩次 verifier 呼叫，成本約三倍；對誤報率與召回率的影響尚未用真實模型重測。
- `benchmarks/owasp-fp/run.py` 的召回與誤報率都附 95% 區間與 n，單模型與跨家族改為同題配對比較；新增 `--summarize` 可離線重算已存結果。`blind-twins/aggregate.py` 與 `formal-transport/report_v1.py` 的報告多一個 `uncertainty` 區塊，原 metrics 不變。
- **揭露草稿預設門檻提高（破壞性）**：預設只為證據達 `poc_effect_no_control` 以上（執行框架判定的 PoC 效果，或人工確認）的項目產生草稿。只過了模型覆核的 `needs_human` 項目須明確加 `--allow-unproven`，草稿開頭會標示 UNPROVEN；只有掃描器命中的項目、以及 `hunt --malicious-signals` 的惡意套件訊號，任何選項都不產生。等級取自共用推導 `Finding::evidence_level()`：舊的 PoC 執行紀錄不算執行框架判定，而`poc_oracle` 目前只由指令注入、路徑穿越與 SQL 注入的 PoC 產生（`--poc`）；其他類型預設只有人工確認的項目會產生草稿。草稿的證據段落列出證據等級、尚缺證據與最強反證。
- **揭露草稿必須指定人工審閱者（破壞性）**：沒有 `--reviewer` 也沒有 `[disclosure] reviewer` 就拒絕產生；`hunt --disclose-dir` 在開始審查前就檢查。化名會公開出現在草稿。
- 揭露草稿不再自填嚴重度與 CVSS：除非嚴重度是人工設定的，否則欄位標示「草擬，待人工覆核」，模型建議另記在審閱備註。
- 同一專案已有未獲回覆的草稿時拒絕產生新草稿，除非加 `--force-throttle <理由>`。
- README 註明 Pro 桌面 App 支援的平台（Apple Silicon Mac、Windows x64、Linux x86_64，不支援 Intel Mac）並連到官網下載頁；開源 CLI 的支援平台不變。
- 貢獻指南要求新功能與修 bug 在同一個 PR 附自動化測試，PR 範本加上對應勾選項。
- 供應鏈固定：CI 與發版 workflow 的所有 action 釘在 commit SHA；trust 工具的 pip 安裝改為 hash 鎖定（`--require-hashes`）；agent 與 egress Docker 基底映像釘在 digest。SECURITY.md 補上回報網址與 email。
- npm 發布改用 trusted publishing（GitHub OIDC，不再使用長期 `NPM_TOKEN`），並只做 staged publish：每個版本先進 npm 的待核准區，由維護者以 2FA 執行 `npm stage approve` 後才上線；npm 對公開套件自動附 provenance。發布 job 會先檢查 npm ≥ 11.5.1。
- 可達性 adapter 升到 0.3.0：可指定單一公告與 `GOFLAGS=-mod=mod`（寫進 cache key）；靜態結果為 `not-observed` 時，若 host 自己的程式碼用到 `reflect`、`unsafe` 或 `//go:linkname`，改報 `unknown`；沒有 `go.mod` 的舊版依賴改由 `go list -m` 的 Dir 綁定。仍然不輸出 `not_affected`。
- 已知限制：Cargo lock 若沒跟著 manifest 更新（stale lock），adapter 仍會接受；它比對 BOM 與 lock 圖，沒有比對各 manifest 的依賴表。對應測試標為 expected failure，發版建置仍以 `cargo --locked` 擋下。
- **SARIF 的 `security-severity` 不再由定性嚴重度換算成 9.5／8.0／5.5／3.0。** 只有同一條 rule 的每筆發現都有來源 CVSS 向量時才設定（取最高分），否則省略；rule 一律帶 `vettalon.security_severity_basis`（`cvss_max`／`omitted_no_cvss`／`omitted_partial_cvss`／`omitted_cvss_zero`，GitHub 不收 0.0），有分數時另帶 `vettalon.cvss_version`、`vettalon.cvss_vector`，v4.0 再加 `vettalon.cvss_nomenclature`。影響：沒有 CVSS 的結果在 GitHub code scanning 不再顯示 Critical／High 等安全嚴重度，改依 SARIF `level`（error／warning／note）；用 security severity 設定的篩選或 code scanning 保護規則需要改用 level。
- SARIF `$schema` 改為 OASIS SARIF 2.1.0 Errata 01 的官方 schema URL。
- CVE 編號依 CVE Record Format 5.2.0 驗證（`CVE-YYYY-` 加 4～19 位數字），不合格式的 alias 丟棄，重複的去掉；測試範例改用 `CVE-1900-` 前綴（CNA Operational Rules 5.4.1）。
- `vettalon agents build` 建置的 agent 映像（codex、grok 在容器內執行時用）基底從 `node:22-bookworm-slim` 改為 `node:26-bookworm-slim`（釘選 digest，建置時為 Node 26.12.0）；codex 0.162.1、grok 1.0.50 不變。映像標籤綁 vettalon 版本，升級後需重跑 `vettalon agents build`。
- 相依套件 toml 從 0.8 升到 1.1（TOML 1.1 規格）。設定檔（`~/.vettalon/config.toml`）與 hunt 讀取的 Cargo.toml／Cargo.lock 現在也接受 TOML 1.1 語法（例如跨行、結尾帶逗號的 inline table）；設定檔寫回的內容不變，解析錯誤訊息的文字有些不同（例如重複鍵只寫 `duplicate key`，不再列出鍵名）。
- 相依套件 sha2 從 0.10 升到 0.11。報告、證據與收據裡的 SHA-256 值、finding id 與 fingerprint 都不變；新增測試以 FIPS 180-2／RFC 4231 測試向量和獨立算出的值鎖住輸出，並在 0.10 與 0.11 下各跑一次確認一致。

### Fixed
- hunt 讀 lockfile 時，名稱或版本是空字串的項目不再變成目標（go.sum 只有 `/go.mod` 欄位、package-lock.json 或 Cargo.lock 的空 `name`／`version`）。由新加的 fuzz target 找到；go.sum 與 npm 的正式 intake 原本就會濾掉，Cargo.lock 的空值則會一路成為目標，下載時打到不存在的 crates.io 網址。
- Release verifier 改用單一 exact certificate identity，避免新版 GitHub CLI 拒絕同時指定 `--cert-identity` 與 `--signer-workflow`；workflow／tag、issuer、來源 SHA 與 hosted runner 限制保留。此修正不改已發布的 binary 或版本 tag。
- 可達性 adapter 把 govulncheck 的 pointer receiver（例如 `*utf16Decoder`）對到公告的 `utf16Decoder.Transform`；先前這類結果一律變成 `unknown`。

### Security
- 相依套件 zip 從 2.4.2 升到 9.0.5，修補 RUSTSEC-2026-0367～0369：解壓時保留 SUID/SGID 位元、`extract` 建立指向目標目錄外的符號連結、權限經由符號連結套用到目錄外。三項都在 `extract` 裡，Vettalon 從未呼叫它：hunt 來源逐檔讀取，用 `enclosed_name` 拒絕跳出目錄的路徑並限制檔案數與大小，這些行為不變。
- 開發相依的 serde_yaml（已棄用）改為 yaml-rust2，只用在檢查內建 semgrep 規則 YAML 語法的測試；不再帶入已無人維護的 unsafe-libyaml（RUSTSEC-2024-0449）。不影響發布的二進位檔。

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
- **README 的壞連結與錯誤引用**：Jev 排序基準原本指向沒有公開的排序基準目錄，改連官網基準測試段落；injection 偵測原本寫「見第 5 點」，實際是「怎麼運作」第 6 點。

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
