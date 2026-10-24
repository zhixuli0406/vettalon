<p align="center">
  <img src="docs/assets/brand/vettalon-readme-banner.png" alt="Vettalon：多家 AI 模型審查你的程式碼，再由另一家模型挑戰每一個發現" width="880">
</p>

# Vettalon

<div align="center">

[English](README.md) · **繁體中文**

</div>

[![CI](https://github.com/zhixuli0406/vettalon/actions/workflows/ci.yml/badge.svg)](https://github.com/zhixuli0406/vettalon/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15717/badge)](https://www.bestpractices.dev/projects/15717)

Vettalon 找出你自己程式碼裡的安全漏洞。做法是讓多家 AI 模型分工審查，再交給另一家模型試著推翻每一個發現，留下推不翻的。

![Vettalon demo](docs/assets/demo.gif)

開源掃描器（semgrep、gitleaks、cargo-audit）先跑一輪確定性檢查，`--profile deep` 再加上 AI 審查。現有的 AI 安全審查工具大多綁定單一模型；Vettalon 可以混用 Claude、Codex、Grok 這類訂閱制 CLI，也能接任何 OpenAI 相容 API 和本機 Ollama。每個模型的回覆都要通過嚴格的格式合約和零 LLM 的位置檢查，捏造了檔名或行號的發現會直接證偽。

## 輸出範例

```
$ vettalon scan fixtures/demo-app --profile deep --poc --finders claude --verifiers codex
程式碼安全審計（vettalon）
  ...
AI 深度審計／對抗式覆核／PoC（deep profile）：
  AI 候選：2　已證偽：0（其中前置檢查證偽 0）　待人工覆核：2　PoC 已執行：2
  模組覆蓋：共 4　已審 4（無候選 2、有候選 2）　延後 0　失敗 0
  覆核獨立性：全部跨家族覆核（找洞：claude；覆核：codex）
結論：未達 --fail-on 門檻（high），視為通過。
```

（AI 找到但還沒有人確認的發現是 `needs_human`，預設不計入 `--fail-on`，加 `--fail-on-needs-human` 才會擋 CI。）

## 安裝

需要：

- macOS 或 Linux（容器隔離、PoC 沙箱與 0600 權限用的是 Unix 專屬機制；暫不支援 Windows）
- Rust 1.88 以上（`cargo`）
- deep 模式至少要有一個模型，下列擇一：
  - 已登入、且能完全關閉工具的 `claude`（Claude Code）。已認證的 `codex`、`grok` 與 `agy` CLI 需明確設定高風險的 `allow_agent_tools = true` 才會在 host 上執行；建議改用 HTTP/OpenAI-compatible API 或 Ollama。細節見下面的「安全邊界」
  - OpenAI 相容 API 的金鑰（放在環境變數裡）
  - 本機 Ollama
- 選用：`semgrep`、`gitleaks`、`cargo-audit`（有裝才會跑）
- 選用，`--poc` 需要：Docker，並先拉好映像檔 `docker pull python:3.12-slim`

```bash
git clone <this repo> vettalon && cd vettalon
cargo install --path crates/vettalon
vettalon models --probe      # 確認找得到哪些模型、能不能連上
docker pull python:3.12-slim  # 只有要用 --poc 才需要
```

也可以直接下載預先建置的執行檔（macOS arm64／x64、Linux x64／arm64）：到 [Releases](https://github.com/zhixuli0406/vettalon/releases) 下載對應平台的 `vettalon-<平台>.tar.gz`，用同名的 `.sha256` 核對，或用 cosign 驗證簽章（`.sig`、`.pem`）。

同一批發佈的執行檔也放在 npm 上，不想裝 Rust 的話可以直接 `npm install -g vettalon`（macOS arm64／x64、Linux x64／arm64）。

在 GitHub Actions 裡掃描、把結果送進 code scanning，用 [vettalon-action](https://github.com/zhixuli0406/vettalon-action)：

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: zhixuli0406/vettalon-action@v1
```

在 Claude Code 裡掃描，可以裝 plugin（預覽版，仍需要上面安裝的 CLI）：`/plugin install vettalon --marketplace zhixuli0406/vettalon`，說明見 [integrations/claude-code](integrations/claude-code/README.md)。

## 使用

```bash
# 只跑開源掃描器（免費、離線）
vettalon scan .

# AI 深度審查：前 5 個高風險模組，分給各個模型
vettalon scan . --profile deep --report report.json --sarif report.sarif

# 指定誰找洞、誰覆核；多審一些模組；對 High 以上的發現跑沙箱 PoC
vettalon scan . --profile deep --finders claude,grok --verifiers codex --max-modules 12 --poc

# 高風險模組預設雙家族審；--cross-check-top 把前 N 個高分模組也納入雙審
vettalon scan . --profile deep --cross-check-top 5

# 預設關閉。前 N 個模組由兩個 finder 家族各自獨立審；同一個修補建議能同時改掉兩邊的 sink 行就合併
# （沒有可用修補時改看同一 sink 前後 3 行內且 CWE 相同），再交第三家族反駁。這些模組的 finder 呼叫加倍，
# 加開的那一家帶來多少新發現記在 ensemble.dual_finder
vettalon scan . --profile deep --finders claude,codex --verifiers grok --dual-finder-top 3

# 存一份到 ~/.vettalon/reports，下次掃描時，沒改過的檔案沿用上次的判定
vettalon scan . --profile deep --save

# 終端輸出語言：系統語系是中文就用繁中，否則英文；可用 --lang 或 VETTALON_LANG 指定（報告與 SARIF 內容不受影響）
vettalon scan . --lang zh-TW

# 檢查報告檔有沒有被改壞
vettalon validate report.json

# 相依套件公告類發現輸出成 CycloneDX 1.6 VDR/VEX（給 Dependency-Track 等 SBOM 工具）
vettalon scan . --cyclonedx bom.cdx.json

# 全部模組都審（--max-modules 0；受安全上限 40 個模組約束，其餘列為 deferred）
vettalon scan . --profile deep --max-modules 0 --report report.json

# 給 AI 深審一個整體時間預算：用完就把待審模組 deferred、標為 incomplete，不再無止境磨
vettalon scan . --profile deep --time-budget 1200 --report report.json

# 在總預算內再給每個角色上限（秒，從該步驟開始算）。0、低於 60、或大於 --time-budget 的值
# 會在任何東西執行前就停下（exit 2）；開始時印出實際預算表，並寫進 report.json 的 ensemble.budget
vettalon scan . --profile deep --poc --time-budget 1800 --finder-budget 1200 --refuter-budget 400 --poc-budget 300

# High 以上的發現預設跑 3 次獨立反駁覆核，必須全部一致；--refuter-runs 1 改回只跑一次（便宜但較弱），上限 5
vettalon scan . --profile deep --refuter-runs 1

# 記錄每次模型呼叫的追蹤（JSON Lines：步驟、模型、位元組數、延遲、結果，不含內文；失敗的呼叫另附遮罩後最多 200 位元組的錯誤訊息）
vettalon scan . --profile deep --trace trace.jsonl

# 不做 reflector 重問：finder 回覆違反 JSON 合約時直接記為解析失敗，不再追問一次
#（預設 1；有「零自動重試」規定的評測用 0）
vettalon scan . --profile deep --finder-parse-retries 0

# 只覆核既有的發現，不呼叫 finder：存下來的報告裡的 AI 候選（例如沒有 verifier 的掃描），
# 或其他工具產生的 vettalon.claims/1 檔
#（{"schema": "vettalon.claims/1", "claims": [{"id", "file", "line", "title", "cwe"?, "severity"?, "locations"?: [...]}]}）
vettalon verify . --input report.json --verifier grok --out verified.json --trace verify.jsonl

# 選擇記錄每次 finder 的來源快照及本機組裝提示 SHA-256 收據，寫入 report.json
vettalon scan . --profile deep --source-receipts --report report.json

# 政策門檻（可重複）：跨家族覆核成立或人工確認的「高」以上發現超過 0 筆就讓 CI 失敗
# 有 --gate 而沒指定 --fail-on 時，只由門檻條件決定結束碼
vettalon scan . --profile deep \
  --gate 'severity>=high status=confirmed,needs_human cross_family count>0'

# deep 掃描沒有任何 AI 引擎能執行時結束碼是 4（見「結束碼」）；
# 加 --allow-incomplete 改以門檻結果結束，跟 0.3.1 以前一樣
vettalon scan . --profile deep --allow-incomplete --report report.json

# 漏洞提交草稿：先列出可提交的項目，再為其中一項產生草稿
# （只產生草稿，不會替你送出；必須給人工審閱者化名，化名會出現在草稿中）
vettalon disclose report.json
vettalon disclose report.json --finding <id> --reviewer <化名> --format minimal --out draft.txt
# 維護者回覆後，解除該專案的節流
vettalon disclose-ledger close github:<owner>/<repo>

# 供應鏈獵捕：稽核專案相依 OSS 套件的原始碼，找尚未登錄的新漏洞
# 先預覽會審哪些（不花 token），再真的跑
vettalon hunt . --dry-run
vettalon hunt . --finders claude --verifiers codex --max-deps 20

# 寫出完整報告，並為新漏洞候選產上游揭露草稿（只草稿，不會送出）
vettalon hunt . --report hunt.json --disclose-dir drafts/ --reviewer <化名>

# 依風險排序相依、把過去的安全修補當成 finder 的線索、檢查惡意套件訊號
vettalon hunt . --dry-run --dep-priority risk --malicious-signals
vettalon hunt . --dep-priority risk --variant-seeds --report hunt.json
vettalon mal-index update --ecosystem npm     # 給 --malicious-signals 用的本機 MAL-* 索引
vettalon rule-draft hunt.json --finding <id>  # 從人工確認的 finding 產 Semgrep 規則草稿
```

### 供應鏈獵捕（`vettalon hunt`）

`vettalon hunt <project>` 從專案的 lockfile（Cargo.lock、npm `package-lock.json`、pip `requirements.txt`、Go `go.sum`）解出相依套件，抓它們的官方發佈原始碼來審，找**還沒被登錄成 CVE** 的新漏洞——和既有 SCA 工具（比對已知 CVE）互補。先查 OSV 分出「已知」與「可能是新的」，預設只審**直接依賴**、跳過 OSV 已有 CVE 的版本（那些 SCA 已在追），把 AI 預算集中在未登錄的；每個相依用跟 `scan --profile deep` 一樣的跨家族對抗覆核。OSV 未命中且覆核留下的發現仍是待人工研判候選（`needs_human`）；未命中不等於已證明新穎性，pattern PoC 跑通也不等於確認。

旗標：`--max-deps N`（上限，預設 20）、`--include-transitive`（連間接依賴）、`--reaudit-known`（連已知 CVE 版本也審）、`--dry-run`（只預覽選取，不抓取不花 token）、`--report <檔>`（寫出完整 JSON）、`--disclose-dir <目錄>`（為新候選產上游負責任揭露草稿，附送出前檢查清單，只草稿、永不送出；可用 `disclose` 的同一組草稿旗標，審閱者會在獵捕開始前檢查）、`--dep-timeout <秒>`（每個相依 fetch+audit 的時限，預設 300、最少 90，逾時記錯誤並續跑）、`--hunt-budget <秒>`（改用總預算：每個相依開始時分到「剩餘預算 ÷ 剩餘相依數」，沒用完的時間往後滾給下一個；同時給 `--dep-timeout` 時，它是單一相依的上限；剩下的預算不夠 90 秒時，若還有相依在跑就等它結束拿回沒用完的時間，沒有相依在跑才記為 deferred，整次標成 incomplete；預算算的是各相依自己的耗時，`--dep-concurrency 2` 時牆鐘時間約一半；計畫與每個相依分到的額度寫在報告的 `budget`）、`--dep-concurrency N`（同時審查幾個相依，1–4，預設 2；總 token 用量不變，但每個模型同時收到 N 個呼叫，CLI 帳號遇到限流就調低）、`--poc`、`--finders`／`--verifiers`。OSV 以批次查詢，大型相依樹也只打少數幾次。獵捕模式會連網抓原始碼與查 OSV，出口限定套件登錄處與 `api.osv.dev`（草稿加 `--check-duplicates` 時另連 `api.github.com`）；登錄處／OSV 查詢傳送相依套件身分；深審仍會把相依套件原始碼送往設定的模型 provider。抓取 allowlist 不限制模型流量，詳見[資料流](docs/DATA-FLOW.md)。

另有三個選配功能，預設都關閉：

- `--dep-priority risk`：在 `--max-deps` 截斷前，依 `exposure × reach × criticality` 排序，並逐項印出分數與依據。exposure 查固定表（套件名稱字詞與常見套件；反序列化與 parser 1.0、網路與壓縮 0.9、加解密 0.8、沒有訊號 0.3），訊號來自下一層相依時乘 0.8。reach 依 lockfile 相依圖（只有 Cargo.lock 與 npm v2/v3 有邊）：直接依賴 1.0、深度 2 為 0.7、更深 0.5；`--reach-evidence <檔>` 的 `reachable` 可提到 1.0，`not-observed` 不會拿來調低。criticality 用內附的熱門套件快照（每個生態系前 1,000 名，前 100 名 1.0、其餘 0.8）與本機被依賴數。查不到訊號的一律標 `unknown`（`?`），以 0.6 計分，不當成安全。這部分完全離線，不查下載數、deps.dev 或 OpenSSF criticality；Scorecard 不列入風險分數。
- `--variant-seeds`（搭配 `--seed-days N`，預設 90）：把該套件最多 5 筆 OSV 紀錄、以及上游 GitHub 近期提到 security／CVE／GHSA 的最多 5 個 commit，整理成有邊界標記、上限 4 KB 的資料區塊交給 finder，內容一律當成不可信資料。只有 finder 的 prompt 會帶，覆核模型看不到。審完後會對鎖定版本再查一次 OSV。CWE 相同、檔名又出現在 advisory 裡的 finding，只有在該 advisory 的修補版本比鎖定版本新時，才記為已知重複、不列入新漏洞候選；否則仍是候選，並標註「可能是該 advisory 的變體」。種子查詢失敗會讓這次 hunt 標為未完成。上游 repo 是套件自己在 manifest 裡寫的，所以會提醒 finder 這段文字可能故意誤導。`vettalon rule-draft <報告> --finding <id>` 可把人工確認的 finding 轉成本機 Semgrep 規則草稿，標記 `review_required`，vettalon 不會自己載入或執行。
- `--malicious-signals`：純規則判定，不經模型。規則有：版本發布未滿 `--cooldown-hours`（預設 72，可用 `--cooldown-exclude` 排除）、比前一版新增安裝期掛鉤（npm `preinstall`／`install`／`postinstall`、Cargo `build.rs`、Python `setup.py` 的 `cmdclass` 與 `.pth` 檔）、npm provenance 消失或 workflow／repository／ref 類型改變（比對 attestation 欄位，不驗簽章）、OSV 或本機 `MAL-*` 命中、名稱與熱門套件編輯距離 1–2、登錄處查無此名稱。一個強訊號（MAL-ID、npm 安全佔位套件）或兩個不同的中訊號才會產生 `malicious_package_signal` finding，狀態固定是 `needs_human`；較弱的訊號只列為觀察。`vettalon mal-index update --ecosystem <npm|PyPI|crates.io|Go>` 下載 OSV 匯出檔，只保留來自 ossf/malicious-packages（Apache-2.0）的 `MAL-*` 紀錄，可用 `--expect-sha256` 鎖定雜湊。任何規則沒辦法判定（OSV 查詢失敗、登錄處錯誤、沒有索引、Go 沒有名稱快照）都會讓報告標為未完成，不會當成「沒有訊號」。加 `--dry-run` 時只跑離線規則（OSV 結果、本機索引、名稱），登錄處規則記為未知。

  回放檢查只到單元層級，不是精確率／召回率：用近 90 天 893 筆真實 `MAL-*` 名稱（只有 metadata）。本機索引是用同一批紀錄建的，全部命中只證明比對邏輯正確。只靠名稱規則命中 11 筆（1.2%），單靠名稱不會產生 finding。拿 3,000 個不在內附清單裡的熱門套件、配固定的舊版登錄資料測：名稱規則標了 55 個（1.8%），finding 為 0。發布時間、安裝掛鉤、provenance 三條規則還沒有用真實套件量過。

`--variant-seeds` 會多連 `api.github.com`；`--malicious-signals` 會向同一批套件登錄處多查 metadata；`mal-index update` 連 `osv-vulnerabilities.storage.googleapis.com`。詳見[資料流](docs/DATA-FLOW.md)。

付費的 Vettalon Pro 另可把獵捕報告產成企業供應鏈報告（Word／PDF／HTML）。

### 漏洞提交草稿

`vettalon disclose` 依本機 repo 資訊（git remote、SECURITY.md、套件設定）建議管道並產生未核准的本機草稿。格式用 `--format ghsa | minimal | kernel | email`（預設依管道；TWCERT/CC 與 HITCON ZeroDay 維持原表單）。每份草稿都遵守這些規則：

- 上游儲存庫：`origin` remote 在 github.com 就用它；沒有的話（直接解開的 crates.io `.crate`、PyPI sdist、npm tarball 都沒有 `.git`）改讀 `Cargo.toml`、`package.json`、`pyproject.toml`、`setup.cfg`、`PKG-INFO` 或 `go.mod` 裡的儲存庫網址。中繼資料當資料看，只採用格式正確的 `github.com/<owner>/<repo>`，審閱備註會寫出來自哪個檔案的哪個欄位。其他主機只記錄，不提供 GitHub 安全公告管道。
- 語言：`ghsa`、`minimal`、`kernel`、`email` 草稿全文英文，CWE 修補建議也是；只有 TWCERT/CC 與 HITCON ZeroDay 表單用 zh-TW。

- 證據門檻：預設只為有執行框架判定 PoC、或已人工確認的項目產生草稿。`--allow-unproven` 也會為只過了覆核的項目產生，並在開頭標示「未證實」。只有掃描器命中的項目一律不產生。
- AI 使用聲明：工具與版本、哪些模型負責發現、覆核與寫 PoC，以及人工審閱者化名與審閱日期（`--reviewer`／`--review-date`，或設定檔 `[disclosure] reviewer`）。沒有審閱者就不產生，化名會公開。
- 嚴重度不由工具自填，除非是人工設定的；模型建議另記在審閱備註供日後對照。
- `--no-patch` 拿掉修補建議段落，給不收工具寫的修補的專案用。`--format kernel` 依 Linux 核心流程：AI 輔助發現視為公開，不要公開重現程式。
- `--check-duplicates` 在送出前查 OSV 與上游 GitHub repo（近 90 天動到該檔案的 commit、未結的 issue／PR）；沒加這個旗標，每項都寫「未檢查」。除此之外不連網。
- 同一專案一次只能有一份未獲回覆的草稿（本機紀錄在 `~/.vettalon`）；`--force-throttle <理由>` 可覆寫，`vettalon disclose-ledger close <專案>` 解除。
- 目標專案的 SECURITY.md 一律當資料：列出需要你確認的要求，裡面的指示不會被照做。

送出前須留下獨立人工覆核、對應目標與來源識別的沙盒重現紀錄，核對維護者／管道現行政策，再取得明確核准。可產生草稿不代表上述條件已成立。日期僅供協調檢查；保留的 90／60 天計算不是已核實的平台政策，也不授權公開。公開須另行核准，vettalon 不會替你送出任何東西。

### 政策門檻（`--gate`）

`--fail-on` 只看嚴重度。`--gate` 是條件式門檻，可以疊好幾條，任一條成立就算不通過，結果寫進報告的 `summary.policy`：

| 寫法 | 意思 | 預設 |
|---|---|---|
| `severity>=LEVEL` | 只算這個等級以上（critical／high／medium／low／info） | `info` |
| `status=a,b` | 只算這些狀態（candidate／confirmed／needs_human；誤判與排除不能當門檻） | `candidate,confirmed` |
| `cross_family` | 只算有跨家族覆核模型判定成立、或已人工確認的發現 | 不限 |
| `count>N`／`count>=N` | 數量達到就不通過（必填） | — |

沒給 `--fail-on` 又有 `--gate` 時，`--fail-on` 視為 `none`；兩者都給時任一不通過即失敗。報告後續的人工判定會重算門檻結果。`summary.policy` 只證明「結果與報告內的條件一致」，不證明條件沒被改過；以掃描當下的結束碼為準。

### 結束碼

`vettalon scan`：

| 結束碼 | 意思 |
|---|---|
| `0` | 沒有達到 `--fail-on` 門檻，`--gate` 條件全部通過。未完成的掃描也可能是 0（時間預算用完、模型拒答、幾個 AI 引擎中有一個掛掉），要看報告的 `run_status` 與 `incomplete_reason`。 |
| `1` | 有發現達到 `--fail-on`，或 `--gate` 條件不通過。 |
| `2` | 掃描本身沒能完成：路徑錯誤、旗標或預算值不合理、門檻條件寫錯、報告寫不出來等等。 |
| `4` | 只在 `--profile deep`：沒有任何 AI 引擎能執行（容器映像檔不存在、找不到 CLI、連不上供應商），沒有模組經過 AI 審查。報告照樣寫出（`run_status: incomplete`、`incomplete_reason: engine_unavailable`，原因在 `engines_missing`）。優先於 `1`：終端摘要的 `結論：` 寫「未完成」，附上每個引擎的原因與處理方式，門檻沒過時另起一行 `門檻：`。加 `--allow-incomplete` 就照舊以 `0`／`1` 結束，摘要改印門檻結論，後面仍註明這次掃描未完成。0.3.1 以前這種情況是 0。 |

`vettalon` 不用 `3`，Vettalon Pro 的 CLI 用它表示「需要授權」。只有部分 AI 引擎無法使用時，整次標為未完成（`engine_unavailable`），終端會寫出幾個引擎沒跑，結束碼照門檻結果。quick 掃描不會出現 4。

`vettalon verify` 只要輸出檔寫出就是 `0`，覆核模型連不上也一樣（看輸出的 `incomplete` 與 `unverified`）；沒辦法執行（輸入檔有誤、模型清單沒有這個 verifier、輸出檔寫不出來）時是 `2`。

### 保守模式

`--refuter-policy evidence+retrieval` 讓 refuter 比較不容易關掉發現。推翻要引用 vettalon 會檢查的程式碼行，refuter 判斷不了的主張維持 `candidate`；refuter 說看不到某個識別字時，vettalon 用確定性的定義搜尋找出定義，再請它判一次。適合漏掉一個真漏洞的代價比多看一些告警高的稽核。這個模式要自己選用，預設仍是 `current`。

```bash
vettalon scan . --profile deep --refuter-policy evidence+retrieval
vettalon verify . --input report.json --verifier claude --refuter-policy evidence+retrieval --out verified.json
```

目前只量過一次（2026-10-22）：用 `vettalon verify` 跑 SastBench 確認集，只算真告警標籤經過人工核對的子集（144 個真告警、196 個假告警）。兩種政策用同一個執行檔、同一天並行，verifier 是透過 `claude` CLI 的 Sonnet，`--refuter-runs 1`。

| 被 refuter 關掉的比例 | `current` | `evidence+retrieval` | 差 [95% 區間] |
|---|---|---|---|
| 真告警（真的漏洞） | 52.1% | 32.6% | −19.4 pp [−26.4, −12.5]，Holm p = 4.9 × 10⁻⁷ |
| 假告警 | 83.7% | 62.8% | −20.9 pp [−27.0, −14.8] |
| 鑑別力（ΔJ） | | | −1.5 pp [−11.9, +7.3] |

代價：真漏洞被關掉的比例少了 19.4 pp，假告警被關掉的比例也少了 20.9 pp，誤關的真漏洞變少，留給你看的告警變多。鑑別力未觀察到差異（檢定力不足，不能當成沒有差異）。340 個告警裡有 42 個回 `unresolved`，這些發現維持 `candidate`。呼叫也比較多：同樣 368 個告警，它用了 476 次模型呼叫，`current` 是 375 次。

這次量測的限制：

- 只有一個基準、一個 verifier 模型。SastBench 的告警來自 SAST 工具；vettalon 自己 AI finder 的候選沒有量，原本為它們準備的護欄跑分（含 holdout 檢查）這個政策沒有跑。
- 每個發現只覆核一次。High 以上預設跑 3 次，這個設定沒有量過。
- 沒有顯示鑑別力比較好，事先登錄的主要檢定也沒有通過，所以沒有改成預設。
- `evidence`、`evidence+prosecutor` 在同一個研究裡篩選過，沒有確認；`evidence-ext` 沒有量過。這些請當成實驗性功能。

### 模組排序（`--rank`）

深掃預設用內建的啟發式排序器決定模組審查順序（git 熱點、進入點、風險分數），**排序器本身不連網**；雲端模型仍接收程式碼。另有選配的 `--rank jev`：把模組的**metadata**（路徑、副檔名、位元組大小、是否進入點、git 熱點數——**不含任何程式碼內容**）送到 TypeSafe Jev，排序後把高風險檔排進審查名額內。基準上 Jev 把深掃的 hit@40 從 6/9 提到 8/9（見[官網基準測試](https://vettalon.dudustudio.monster/#benchmarks)）。

```bash
# 預設啟發式（零網路）
vettalon scan . --profile deep

# 用 Jev 排序（需 config 設好 [jev]）
vettalon scan . --profile deep --rank jev
```

- **只有 `--rank jev` 才啟用 Jev metadata 請求**；啟發式排序本身不連網，使用雲端 HTTP 或訂閱 CLI 的 deep 掃描仍會把程式碼送往模型 provider。
- 送出前由 `assert_metadata_only` 逐檔比對原始碼，任何程式碼內容外洩就 fail-closed。
- Jev 不可用（斷線／逾時／回錯）時自動退回啟發式，出一行提示，不中斷掃描。
- Jev 只排序，**不取代** finder／verifier。

**兩段式排序（`--prescreen`，預設關閉）**：排序之後，用模型清單裡一個便宜的模型替前 40 個審查單元各打 1–5 分，只有前 20% 進入深審（仍受 `--max-modules` 限制）。訂閱制 CLI 拿不到機率，所以分數就是 1–5 的整數。沒進入的單元在 coverage 記為 `deferred`／`prescreen_cut`。

```bash
vettalon scan . --profile deep --prescreen cheap-model --prescreen-model haiku
# --prescreen-pool N（打分的單元數，1–200，預設 40）、--prescreen-top PCT（1–100，預設 20）
```

- 每個打分的單元是一次對該模型的呼叫，prompt **含程式碼片段**（單一檔案最多 60 行／2 KiB，加上檔案路徑），會送到該模型的 provider。機密檔不取片段。程式碼裡有對 AI 審查者下指令的文字時，該單元不送出、一律保留。
- 報告的 `ensemble.prescreen` 記錄呼叫數、送出與收到的位元組、耗時與每個單元的分數，可以拿來判斷值不值得。沒有任何分數、有單元因 `--time-budget` 用完而沒開始、或超過一半的呼叫沒拿到分數時，維持原排序、不裁切。因 injection 文字被強制保留的單元會像 5 分一樣占用入選名額。
- 同樣預算下能不能多找到東西還沒量過；用真模型對照 hit@40 排序基準的測量尚未執行。

金鑰設定（兩種，config 一律不存 key 本身）：
```toml
[jev]
api_key_env = "TYPESAFE_API_KEY"                            # 法一：環境變數名
# api_key_file = "/home/you/.config/vettalon/typesafe.key" # 法二：0600 金鑰檔
```
解析順序：環境變數有值優先，否則讀金鑰檔。金鑰只活在呼叫當下，不落檔、不進報告、不進 log。

**給終端客戶**：Jev 預設關閉，由客戶自己決定要不要開。CLI 每次用 `--rank jev` 都會在輸出印一行「把 metadata 送到 <host>」。客戶用**自己的 TypeSafe 金鑰**（BYOK），計費與資料處理關係在客戶與 TypeSafe 之間。檔案路徑本身可能透露內部專案名稱，要避免 Jev 流量可用啟發式排序（預設）；整次掃描要離線，還需所有模型角色本機化、預載掃描器／規則／DB／映像，並另外封鎖外部連線。TypeSafe 的資料保留期限依其條款而定（非企業方案無固定天數、零保留 ZDR 僅企業方案）。

詳見[資料流與離線前置條件](docs/DATA-FLOW.md)、[發版驗證](docs/TRUST.md)及[信任工具](scripts/trust/README.md)。

### 模型設定

沒有設定檔時，vettalon 只使用 `claude`，因為它是唯一能完全關閉工具的 CLI。這時一切都由同一個模型處理，報告會標示為「同家族、自我覆核」。要多家模型分工，請把 [`vettalon.example.toml`](vettalon.example.toml) 複製到 `~/.vettalon/config.toml`，或用 `--config` 指定。放在被掃描 repo 裡的設定檔會被拒絕，因為設定檔決定要執行哪些程式、金鑰送往哪裡，不能交給被審的程式碼決定。

```toml
[[model]]
id = "claude"
backend = "cli"
preset = "claude"

[[model]]
id = "qwen-local"
backend = "ollama"
family = "qwen"
model = "qwen2.5-coder:7b"
roles = ["finder"]

[[model]]
id = "deepseek"
backend = "openai"
family = "deepseek"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
api_key_env = "DEEPSEEK_API_KEY"   # 金鑰只放在環境變數，設定檔不接受金鑰
```

設定檔的規則：
- API 必須用 `https://`，只有 localhost 可以用 `http://`。
- CLI 模型也吃 `max_tokens`：回覆超過 `max_tokens` × 4 位元組就算錯誤，不會截斷後拿來用；`claude` 另外在每次請求帶上限（`CLAUDE_CODE_MAX_OUTPUT_TOKENS`）。其他 CLI 看不到的推理 token 不受限。
- `preset = "agy"` 必須設 `allow_agent_tools = true`。只有 Gemini 模型會自動帶 `google` 家族；agy 也提供其他廠商的模型（例如 `gpt-oss-120b-medium`），這時要自己填 `family`。
- `api_key_env` 只接受 `_API_KEY`、`_KEY`、`_TOKEN` 結尾的名稱，`AWS_*` 不接受。
- 自訂 CLI 的 `program` 必須是絕對路徑。

## 安全邊界

被審查的程式碼是不可信資料，裡面可能藏著寫給模型看的指令（prompt injection）。vettalon 有這幾層防護：

- 每次呼叫 CLI 都在全新的空暫存目錄裡執行，只傳遞白名單內的環境變數，例如 `HOME`、`PATH`，以及該 CLI 認證需要的變數。
- 模型講出的任何路徑，一律先 canonicalize，確認仍在 repo 內才讀取，指到 repo 外的 symlink 不會被讀。
- 深掃不會把存放密鑰的檔案送給模型：`.env` 與 `.env.*`、私鑰與憑證（`*.pem`、`*.key`、`id_rsa` 等）、存帳密或狀態的檔案（`.npmrc`、`.netrc`、`credentials.json`、`*.tfvars`、`terraform.tfstate` 等），透過 symlink 指過去也一樣擋。這些檔案仍由 gitleaks 在本機掃描。清單依常見慣例整理，不是完整保證：被審查模組裡的其他檔案會原樣送出，寫死在原始碼裡的密鑰也會跟著送出。
- 報告和 SARIF 寫出前，所有自由文字欄位都會遮蔽秘密，檔案權限一建立就是 0600。SARIF 裡不包含本機的絕對路徑。
- 審查前先掃出藏在程式碼裡、寫給模型看的指令（見「怎麼運作」第 6 點），不讓「叫模型回報乾淨」的注入悄悄過關。

**各 CLI 能不能關掉工具不一樣（2026-10-12 實測）：**

| CLI | 關閉工具的旗標 | 實測結果 |
|---|---|---|
| claude | `--tools ""` | 有效，模型沒有任何工具 |
| codex | `--sandbox read-only`，並停用使用者設定、MCP、apps、hooks、plugins | shell 仍然**能讀取本機任何檔案** |
| grok | `--tools ""` | **無效**，仍能讀檔，也能執行指令 |
| agy | 沒有這種旗標 | headless 模式會自動拒絕需要授權的工具（執行指令、讀空工作目錄以外的檔案、寫檔；2026-10-20 實測沒有建立或讀到任何檔案），但 `search_web` 不需授權就執行了 |

已認證的 codex 與 grok 設定現在**預設 fail-closed**。它們的工具控制無法阻止讀檔；若把可重用的 CLI 認證放進沙箱，模型就能讀取，並可能經允許的廠商網域將它送出，所以只有網路隔離不是充分的憑證邊界。除非明確設定 `allow_agent_tools = true`，接受在 host 上直接讀取本機檔案與憑證的風險，Vettalon 會拒絕這類設定；自訂 `program` 也一樣。建議改用能完全關閉工具的 CLI、用環境變數傳入限縮金鑰的 HTTP/OpenAI-compatible API，或本機 Ollama。

`vettalon agents pull`、`build`、`images` 與 `stop` 仍可用於準備不含憑證的映像檔，以及未來有憑證 broker 的流程；這些指令不會授權已認證的 codex 或 grok 模型呼叫，也不會繞過 fail-closed 設定檢查。`pull` 預設驗證公開映像檔的簽章；`--no-verify` 不安全。映像檔標籤取自定義內容，不是 Vettalon 版本號。手動驗證方法見[容器映像檔驗證](docs/TRUST.md#container-images)。

`agy` 沒有容器映像檔（登入資訊沒辦法複製進容器），所以一定要設 `allow_agent_tools = true`，在 host 上跑。vettalon 從 stdin 送 prompt（不放在 argv），在前面加一行「不要用工具，只依這則訊息回答」，CLI 的串流裡只要出現任何工具步驟、被拒的動作或空回覆，就把整個回覆丟掉。關不掉的部分：agy 會讀你自己的 `~/.gemini/GEMINI.md`（可能改變回覆語言），也會保留自己的對話紀錄，裡面有被審的程式碼。2026-10-20 實測時，Gemini 的供應商過濾器把 vettalon 每一個覆核 prompt 都回成「This request was blocked by Gemini's filters」（三個 Flash 等級共 5 次、5 次都被擋），vettalon 會記成拒答；同一個 CLI 換用 GPT-OSS 120B 則正常回答。

管理不含憑證的容器基礎設施：`vettalon agents pull` 下載並驗證公開映像檔、`vettalon agents build` 在本機建出全部映像檔、`vettalon agents images` 印出應有的映像檔標籤、`vettalon agents stop` 收掉 proxy 和內網。

## 怎麼運作

1. **intake**：統計語言、找進入點，讀 git 歷史，把常出安全修補的檔案標為熱點，再依風險排序模組。文件與非程式碼檔（`.md`、`.rst`、圖片、鎖檔、二進位、翻譯檔…）不列為可審模組（AI 深審只推理程式碼），巢狀的獨立 clone 與根 `.gitignore` 排除的目錄也不列入；單次審查的模組數有安全上限（40），`--time-budget` 另給整體時間預算。排序預設用內建啟發式（零網路）；`--rank jev` 可改用只看 metadata 的 Jev 排序（見「模組排序」）。
2. **分工找洞**：前 `--max-modules` 個模組依序輪流分配給各個 finder，一個模組只交給一個模型審，所以成本跟單一模型差不多。
3. **前置檢查**：不呼叫任何模型，只核對模型講的檔案、行號和呼叫鏈是否真的存在，對不上就直接證偽。
4. **高風險模組雙審**：git 安全熱點或進入點的模組（天然少數）會自動再交給一家不同家族的 finder 審一次，兩家各讀一遍；加 `--cross-check-top N` 可把前 N 個高分模組也納入。一家漏看、另一家補上。
   `--dual-finder-top N`（預設關閉）在前 N 個模組上再多做一步：兩家 finder 都被要求替每筆候選附一個選填的修補建議（單一檔案、最多 10 行），覆核前先依根因合併兩邊的清單。兩家回報同一個 id 的主張會最先配對（`identical_claim`）。其餘的，把某個修補套到檔案的記憶體副本上，若兩筆候選的 sink 行都被改掉，就合併成一筆（`dedupe_basis=same_patch`）；修補沒動到另一筆的 sink 行，或兩筆的 CWE 不同，就保留兩筆。兩邊都沒有可用修補時，退回看同一個 sink 檔案、sink 行相距 3 行內且 CWE 相同（`location_cwe`），缺 CWE 一律不合併。在 sink 行上方加防禦、sink 行本身沒變的修補不算數，所以會留下一些重複，這是比較安全的方向。合併後的那筆在 `found_by` 列出兩家 finder，並帶一筆 `dual_finder_merge` 證據。之後每筆候選盡量交給第三個家族的模型反駁。報告的 `ensemble.dual_finder` 逐家族記錄候選數、只有該家族找到的根因數（以及其中幾筆最後是 `needs_human`），也記錄加開那一家的呼叫次數、送出的原始碼量，和每多一筆 `needs_human` 花了幾次呼叫。Vettalon 看不到每次呼叫的價格，金額請用你自己的費率換算。finder 只有一個家族時，這個旗標會記為 skipped。這 N 個模組指的是實際送審模組的前 N 個（有開 `--prescreen` 時是篩選後的順序）。第二家族的模組審查和其他 finder 共用同一個期限（`--finder-budget` 或 `--time-budget`），用完後剩下的模組照常列為 deferred，邊際產出只計實際跑完的呼叫。
5. **跨家族覆核**：每個候選交給一個與 finder 不同家族的 verifier，要它從零開始試著推翻。推翻不了的標成 `needs_human`，附上「還需要確認什麼」的清單。模型清單裡沒有其他家族時，會退回同家族的其他模型，再不行就由 finder 自己覆核，投票紀錄裡會寫明（`same_model`）。
   verifier 只拿到主張（位置、威脅模型、trace 位置、前置條件）和重新讀取的程式碼，看不到 finder 的推理，prompt 預設「程式碼證明不了就推翻」。High 以上的發現跑 3 次獨立覆核（`--refuter-runs`，1 到 5）：3 次都判可能成立才標 `needs_human` 並記 `refuter_consistent: 3/3`，3 次都推翻才算證偽，結論不一致就維持 `candidate` 並記 `verify_uncertain: k/n plausible`。每一次都各記一票。推翻理由若依賴某個防禦檢查，必須附上該檢查的檔案與行號；行號不存在或不在主張的 trace 上，這次推翻不採用（`verify_error: refutation cites missing guard`），發現維持 `candidate`。覆核沒跑完（呼叫失敗、拒答，或 `--time-budget` 用完而不再開始額外的覆核）時，發現維持 `candidate` 並記 `verify_error: incomplete refuter runs`，整次執行標成 incomplete。防護或消毒只有在擋下所有流到 sink 的輸入形式時才算安全；看得出只擋住部分形式，或流向看得到、但決定是否安全的那段程式碼（定義、被呼叫的函式、值的來源）不在摘錄裡時，verifier 會被要求回 `plausible` 並把缺口寫進 blockers，不要推翻。完全看不到流向的主張仍然推翻。回覆違反回覆合約（不是 JSON、`plausible` 沒有 blockers 或驗證計畫、`refuted` 沒有理由類別）不算結論：vettalon 會把問題寫明，請同一次覆核再答一次（`--verifier-parse-retries`，預設 1，設 0 關閉；修正算一次額外呼叫）。第二次仍違約，那次覆核記為 `verify_error`、視為缺席，不會算成推翻也不算意見分歧，發現維持 `candidate`。報告會記 `verifier_reflector: N reply(ies) ... re-asked, M recovered`，另外每次重問各記一行原因與第二次回覆的結果。每個推翻也會記 `refute_basis: run i/n <依據>; guard=…; cited=…; outcome=…`。`--refuter-policy`（預設 `current`，即上述行為）可以選用其他政策。`evidence+retrieval` 是量測過的選用保守模式：關閉要引用 vettalon 會檢查的程式碼行（檢查不過或回 `unresolved` 時，發現維持 `candidate` 並記 `verify_uncertain: unresolved`），refuter 看不到的定義會用確定性搜尋取回，再判一次；代價見[保守模式](#保守模式)。其他政策是實驗性的，不建議使用：`evidence` 與 `evidence+prosecutor`（以防護或信任理由關閉時多一次盲測繞過）篩選過但沒有確認，`evidence-ext`（只對外部掃描器的主張套用）沒有量過。`--refuter-score`（預設關閉，實驗性）會請每次覆核另外給 `p_real`（0 到 100，主張為真的機率）與 `evidence_level`（`safe_shown`、`safe_likely`、`undetermined`、`flow_likely`、`flow_shown`），記成 `refuter_score: run i/n p_real=… evidence=…; verdict=…`。這兩個值在一般解析之前就被取出，解析看到的是同一份 JSON；但 prompt 多了一段，模型的回答會不會因此不同要靠量測，不是保證；缺值或格式錯誤會照實記下。這裡的 `evidence_level` 是 refuter 對摘錄的判讀，不是報告裡由證據鏈算出的 `evidence_level`。分數還在量測。唯一會讀它的是 `--refuter-score-threshold P`（0 到 100，預設關閉，實驗性，會一併打開分數）：推翻只有在該次 `p_real` 低於 P 時才關閉發現；分數較高、缺值或格式錯誤時，發現維持 `candidate`，那次覆核記為被降級的 `unresolved`。它從不關掉 refuter 沒有推翻的發現。`verify --joern-keep`（預設關閉，實驗性）在覆核之後，對 refuter 用模型回覆關掉的每個發現問 [Joern](https://github.com/joernio/joern)：從固定的輸入來源（請求參數、`argv` 這類）到主張那一行的呼叫，有沒有資料流路徑。有被規則接受的路徑，發現就維持 `candidate`，記一行 `joern_path:`（路徑上的檔案、行號與程式碼）和 `verify_uncertain: joern path`；沒有路徑、那行沒有呼叫、語言不支援、逾時或任何錯誤，判決都不變，只記一行 `joern:`。找不到路徑不代表告警是假的，所以它只會讓發現保留，不會關掉任何發現。先跑一次 `vettalon joern build`（下載固定版本的 Joern，約 1.8 GB，核對 SHA-256 與 SHA-512）；分析在沒有網路、原始碼唯讀掛載的容器裡跑，查詢是固定模板，模型不寫查詢。`--joern-timeout` 設定每次容器執行的上限（預設 900 秒）。是否值得用還在量測。
   verifier 讀到的程式碼會先去掉註解與 docstring，行號不變。ALIBI 研究（arXiv 2607.24964）在真實漏洞旁植入「此處已驗證安全」或假造的掃描結果，騙過 LLM 審查的比例超過九成，而且去掉註解比在 prompt 裡警告有效得多。被去掉的文字仍會另外附上，標明是程式作者寫的資料。會改變編譯器或檢查工具行為的註解保留：`# type:`、`# noqa`、`# pragma: no cover`、`//go:build`、`// +build`、cgo preamble、`/// <reference>`、`// @ts-ignore`、`{-# LANGUAGE #-}`、第一行的 shebang 與編碼宣告。每一種都要完全符合已知格式，而且只留符合的那段（最多 120 位元組）：`# nosec: audited, verified safe` 在程式碼裡只剩 `# nosec`，其餘照樣去掉。主張引用的某一行若落在多行註解或 docstring 裡，那段摘錄改用原檔內容，避免 lexer 判斷錯誤或偽裝成註解的程式碼把被指稱的程式碼藏起來。支援的語言有 Rust、Go、C/C++/Java/C#/Kotlin/Swift/Scala/Dart、JavaScript/TypeScript、PHP、Python、Ruby、shell、YAML/TOML、Perl/R/Elixir、Terraform/HCL、SQL、Lua、Haskell，其他檔案原樣送出。一筆發現本來就要跑多次覆核時，第二次會讀帶註解的原始碼；如果這一次的結論跟所有去註解的覆核相反，就記一筆 `comment_sensitivity`，此時各次結論不一致，發現維持 `candidate`。第 6 步的零 LLM injection 掃描照舊先跑，而且掃的是原始檔。帶註解的那一次本來就是 `--refuter-runs` 其中一次，不多花呼叫，也受 refuter 預算限制：`--refuter-budget`（或 `--time-budget`）用完後就不開始，那筆發現也不會有 `comment_sensitivity` 紀錄。
   verifier 判可能成立時，也要列出它自己看到的前置條件（報告裡的 `refuter_conditions`）。可利用性等級取 finder 與 verifier 兩者中摩擦較高的那個；兩邊等級不同時記一筆 `tier_disagreement`，CLI 摘要、SARIF 與 Pro 報告都會標出來。
6. **偵測寫給模型看的指令**：審查前先用零 LLM 的規則掃過每個模組，找出「叫審查模型回報乾淨」這類文字（例如 `respond with {"candidates": []}`、「report no vulnerabilities」、「this file is secure」）。命中的模組會額外交給另一家族的模型再審一次，並記在報告的 `ensemble.suspected_injection`；模型清單只有一個家族、無法交叉覆審時，整次執行標成 `incomplete`。
7. **PoC**（`--poc`）：對 High 以上的 `needs_human`，盡量交給另一家模型寫腳本，在 Docker 沙箱裡執行。沙箱的限制：
   - 斷網、根目錄唯讀、拿掉所有 capabilities、以非 root 身分執行
   - 限制記憶體和行程數
   - host 端和容器內各有一道時限
   - 不自動拉映像檔

   容器裡只有 Python 標準函式庫和 bash，repo 本身不在容器內，所以 PoC 要用標準函式庫重現有漏洞的寫法。沙箱起不來就跳過，絕不在本機執行。PoC 跑通也不會自動把發現標成 confirmed。

   指令注入（CWE-78/77）、路徑穿越／讀檔（CWE-22/73）、SQL 注入（CWE-89）這三類改由 harness 判定，不看 PoC 自己印的結論。harness 每次開容器都產一組一次性秘密，看的是真實副作用：注入的 shell 複製了秘密檔、`../` 讀到允許目錄外的檔、`UNION` 撈出秘密那一列。PoC 只印「成功」沒有用，漏洞得真的被打穿。執行前先跑零 LLM 的靜態檢查，PoC 若寫死秘密、自己寫出效果檔、根本沒呼叫真正的 sink、或去讀 harness 原始碼，直接拒絕。接著用良性輸入跑一次對照（產品路徑沒有上游修補可比），再換新秘密開新容器重跑。結果記成 `poc_oracle` 證據（`effect`／`control`／`rerun`／`nonce_bound`／`rejected`），旁邊另存一份已遮罩的執行紀錄。攻擊時有效果、對照時沒有、重跑也重現，才算差分（`poc_differential`）。SSRF（CWE-918）做不了，因為沙箱沒有網路，也起不了 loopback listener；其他類別同樣沒有可行的 oracle，都維持上面的獨立模式示範。兩條路的狀態都停在 `needs_human`。

**拒答不轉送。** 模型拒絕審查時，只有那個模組記成「未審」，同一個模型分到的其他模組照常進行。拒答會列在 `ensemble.refusals`，整次執行標成 `incomplete`（`model_refused`），不會悄悄改丟給別的模型。覆蓋缺口要攤開給你看，換不換模型由你決定。

**誠實的完成狀態。** 下列情況都會讓報告標成 `incomplete`，並附上原因：
- 某個 finder 完全連不上
- 有模組的呼叫失敗，或回覆不符合格式
- 有候選沒拿到覆核結論（每次覆核都有回覆、只是結論不一致，不算這種情況：`verify_uncertain` 讓發現維持 `candidate`，但整次執行不因此標成 incomplete）

覆核獨立性只計算真正給出判定的覆核，呼叫失敗或拒答都不算。同一個 verifier 第一次就連不上時，同組其餘的候選會直接標成未覆核，不會每一筆都等滿逾時。

**AI 不會自動宣告「確認」。** AI 能做到的最高狀態是 `needs_human`，`confirmed` 只能由人來標。

**用實際原始碼重現與檢查修補。** 已有 validator-clean 的 `report.json` 時，可把一次呼叫寫成封閉 JSON；目前只接受 `.py` 內同步、top-level 的函式，`args` 恰好一個 `payload`，其餘參數只能是有界 JSON literal：

```json
{"file":"app.py","function":"read_file","args":[{"kind":"payload"}]}
```

```bash
vettalon reproduce . --report report.json --finding FINDING_ID \
  --target target.json --out reproduce-receipt.json

vettalon fix check . --report report.json --finding FINDING_ID \
  --target target.json --diff fix.patch --test-command "python3 -m pytest -q" \
  --out fix-receipt.json --report-out report-with-fix-check.json
```

兩個命令都核對 report 的 repo、finding、目標檔與原始碼 hash，只在 prepared copy／新容器執行；不改 live tree，也不自動改 finding status。`reproduce` 是三階段來源綁定收據；`fix check` 另把 exact diff 與相鄰的 check/context evidence 寫進 `--report-out`，更新後報告會再跑 validator。receipt 與 report-out 必須是不存在的新檔，父路徑不能含 symlink；這避免一般覆寫與 link 攻擊，但檢查未以 dirfd 錨定，不能宣稱消除所有並行 rename 競態。`fix_verified` 只描述收據綁定的 prepared snapshot、image 與測試設定，不代表今天的工作樹仍相同，也不會把漏洞改成 `confirmed`。

`reproduce` 收據另可攜帶 language-neutral VerificationEvent：VIR 綁定來源、target、plan、實際 runner／adapter harness 與 policy；ExecutionEnvelope 記 capture、cleanup、tamper、effect、controls 與 replay grade；stored verdict 每次讀回都會重新推導。可用 `vettalon verification validate` 驗證 event、`verification compare` 比較兩次 execution envelope、`verification registry` 管理反例與 sealed holdout lineage、`verification scorecard` 重算包含 unsupported／inconclusive 分母的工程量尺。反例升格需要至少兩份不同 fresh challenge 的一致完整事件；holdout 污染沿 parent lineage 傳遞，registry 也會核對內容位址。完整格式、命令與限制見 [`docs/VERIFICATION-ENGINE.md`](../docs/VERIFICATION-ENGINE.md)。目前只支援 Python 的 command／path／SQL target 與 Docker reference backend，不代表跨語言或工程護城河已成立。

**證據等級。** JSON 報告與 SARIF 的每筆發現都帶 `evidence_level`，由弱到強是 `static_only`、`refuter_survived`、`refuter_consistent`、`poc_effect_no_control`、`poc_differential`、`maintainer_confirmed`（只有人能給）。旁邊的 `proof_gaps` 列出還缺什麼（`no_refuter`、`refuter_inconsistent`、`no_poc`、`poc_not_harness_judged`、`no_control`、`no_fresh_rerun`、`reachability_unknown`、`no_maintainer_confirmation`），`strongest_counterevidence` 引用最不利的推翻理由或失敗的對照組，已遮罩、上限 300 位元組。三者都在寫報告時從證據鏈算出來，模型設定不了，報告檔裡存的值讀回時一律忽略，舊報告則依它本來有的證據推導。有 `verify_error` 時最高只到 `static_only`，有 `verify_uncertain` 時最高只到 `refuter_survived`。沙箱的 pattern PoC 不會提高等級，只有 harness 判定的 oracle 紀錄（`poc_oracle`）可以。

**修補建議。** 發現可以帶 `suggested_fix`（unified diff，上限 64 KB，讀報告時超過就拒絕）。報告不會因為有這段 diff 就當它驗證過：凡是帶修補建議的發現，JSON 報告都有衍生欄位 `fix_check`，SARIF 有 `vettalon.fix_check`，其中 `outcome` 只有 `fix_verified`、`fix_check_partial`、`fix_rejected`、`fix_unverified` 四種。加了 `--poc` 時，對會跑 PoC 的同一批發現，vettalon 把掃描的目錄複製兩份到暫存目錄，只把 diff 套到其中一份，你的檔案只讀不寫。diff 碰到目錄外的路徑、二進位檔、符號連結、`.git` 或秘密檔，或是改名、刪檔、改權限，都在執行任何東西之前拒絕。檢查 A 在同一次執行裡，用 harness 對該類別的每個 fixture 輸入，分別在原始副本與修補副本跑上面的 oracle：原始副本要仍有效果，修補副本要沒有，而且 harness 的良性輸入在修補副本上要照常運作（不拋例外，讀檔與 SQL 類別還要拿到預期結果），只是把程式改壞的修補會被否決。連接 harness 與專案程式的 adapter 由模型撰寫，只能 import 並呼叫專案程式（自己執行危險操作、讀專案檔、檢視已 import 的模組、執行期組程式碼的 adapter 會被靜態檢查擋下），兩份副本用同一個 adapter，所以目前只適用可以 import 的 Python 程式。檢查 B 只在你明確設定測試指令時才跑（`--fix-test-command "python3 -m pytest -q"`，或設定檔 `[fix_check]` 的 `test_command`），vettalon 不會自己猜。它沿用 PoC 沙箱的限制（無網路、120 秒、目錄唯讀、只有 `/tmp` 可寫），先跑原始副本再跑修補副本；原始副本的測試就失敗時，B 記為無法判定。修補檢查和 PoC 共用時間預算（`--poc-budget`／`--time-budget`），預算用完而沒檢查到的修補記為 `fix_unverified`，`reason` 為 `time_budget_exhausted`。結果只看 A 和 B：兩者都通過才是 `fix_verified`；A 通過但沒設定測試指令是 `fix_check_partial`；修補副本仍有效果或測試失敗是 `fix_rejected`；其他情況（被拒絕、沒有沙箱、原始副本已重現不出效果、類別沒有 harness、從沒檢查過）都是 `fix_unverified`，並附 `reason`。結果存成固定格式的 `fix_check` 證據，綁定 diff 的 SHA-256，之後改了 diff，標籤就回到 `fix_unverified`。

報告格式定義在 [`crates/vettalon/src/audit/schema.rs`](crates/vettalon/src/audit/schema.rs)，寫檔前一律先跑 validator。SARIF 2.1.0 輸出可以直接上傳到 GitHub code scanning，被證偽的發現會標成 suppressed，不會刪掉；result 的 properties 另帶該發現對應的 CAPEC 攻擊模式（`vettalon.capec`）、依前置條件推導的可利用性分級（`vettalon.exploitability`：direct／conditional／hard_to_reach，取 finder 與 verifier 中摩擦較高者；verifier 有給自己的前置條件時另帶 `vettalon.exploitability_finder`／`vettalon.exploitability_refuter`，兩者不同時帶 `vettalon.tier_disagreement: true`）、結論隨註解翻轉時的 `vettalon.comment_sensitivity: true`，以及證據等級與缺口（`vettalon.evidence_level`、`vettalon.proof_gaps`、`vettalon.strongest_counterevidence`）。有 CWE 對應的發現，報告會多一段攻擊情境與 CAPEC 參考連結。

**嚴重度、CVSS、CWE 與 CVE。** CVSS 分數只在來源（例如 RustSec 公告）提供向量時才出現，模型不估分。CVSS v3.0／v3.1 算 Base 分數；CVSS v4.0 用 FIRST 的 MacroVector 方法計分，程式移植自 FIRST 官方計算機，測試比對 FIRST 公布的範例和 300 筆官方計算機輸出（另做過一次 6 萬筆的大量比對）。分數一律和版本、等級、向量一起出現，v4.0 再加上命名，例如 `CVSS v4.0 8.7 High (CVSS-B)`。vettalon 不會在來源向量上自行加 Threat 或 Environmental 指標：Environmental 屬於部署方，vettalon 的 PoC 也不公開，所以就算日後加 Threat 指標，也只會是 `E:U`。

SARIF 裡 GitHub 用的 `security-severity`，只有在同一條 rule 的每筆發現都有 CVSS 向量時才設定，值取其中最高分；否則直接不給，定性嚴重度不會被換成看起來像 CVSS 的數字，GitHub 會改用 SARIF `level` 排序。rule 的 `vettalon.security_severity_basis` 註明是哪種情況（`cvss_max`、`omitted_no_cvss`、`omitted_partial_cvss`，分數為 0.0 時是 `omitted_cvss_zero`，GitHub 不收 0.0）。CWE 另外以 SARIF taxonomy（MITRE CWE List 4.20）輸出，有 CWE 的發現都帶 `cwe_mapping`，記錄 CWE 版本和 MITRE 的對應建議（`allowed`、`allowed-with-review`、`discouraged`、`prohibited`、`not-in-catalog`）。MITRE 不建議或禁止拿來對應漏洞的編號，例如 Pillar、Category、View、CWE-20、CWE-200、CWE-284、CWE-1426，會加上警示並列出知識庫裡更具體的編號。AI 發現只有在它自己的類別正好指向某個更具體的子項時才會改用子項，原本的編號留在 `cwe_replaced`。CVE 編號接受 4 到 19 位的流水號；只有 vettalon 手上的 OSV 資料列出某個 CVE 時才能標 `published`；`vettalon scan` 沒有 OSV 資料，它的 CVE 參照都來自本機 RustSec 資料庫，一律是 `unverified`。報告檔裡存的 CVSS 分數不會被採信，讀回時一律從向量重算。

`--cyclonedx` 會把相依套件公告類發現寫成 CycloneDX 1.6 VDR/VEX：受影響套件（Package URL）、公告、CVE 參照、來源給的 CVSS 評分、vettalon 的定性評分（不帶數字）、CWE，以及只依紀錄證據決定的 `analysis.state`。操作者確認過是 `exploitable`，操作者判定誤報是 `false_positive`，其他情況都是 `in_triage`。`not_affected` 一律不輸出，因為它需要操作者提供 VEX 理由，而 vettalon 目前還沒有收這項資料。程式碼類發現仍放在 SARIF。

`--trace` 會另寫一份逐次模型呼叫的 JSON Lines（只記步驟、模型、位元組數、延遲、結果，不含內文）。

## 已知限制

- 一般模組只有一個 finder 審，那個模型漏看就是漏掉。高風險模組（熱點／進入點）、疑似 injection 的模組、以及 `--cross-check-top` 指定的前 N 個會由兩家審；其餘仍是一家。實測時 grok 有一輪漏掉了 `fixtures/demo-app` 的 path traversal，前一輪卻找得到，模型輸出有隨機性。重要的程式碼請多跑幾次，或用 `--finders` 換模型。
- High 以上跑 3 次反駁覆核，這些發現的 verifier 呼叫數變成三倍。預設 prompt 偏向推翻，對誤報率與召回率的影響還沒在 OWASP 樣本上重測。
- `--dual-finder-top N` 讓這 N 個模組的 finder 呼叫加倍（原始碼也多送給一家廠商），要求附修補建議也會讓 finder 的回覆變長。第二家族找到的東西值不值這個成本，還沒用真實模型量過；跑完看 `ensemble.dual_finder.marginal`，加得少就把旗標拿掉。
- 去註解用的是各語言的小型 lexer，不是完整 parser。少見寫法（JavaScript 在 `)` 或 `}` 之後的 regex literal、內含 `#` 或 `//` 的 shell／PHP heredoc、Perl／Ruby 的 quote-like 運算子、Dart raw 字串、Groovy slashy 字串）可能讓那一行多去掉一點程式碼或留下一點註解，但行號一定不變，被引用的行落在多行註解裡時也會改用原檔內容。Python 中獨立一行、前一行以 `:` 結尾的三引號字串會被當成 docstring，即使它其實是 dict 的值。
- 嚴重度是模型自己評的，同一個漏洞，claude 評 high、codex 評 medium，而 PoC 只對 High 以上的發現跑。
- `osv-scanner` 需要連網，刻意不呼叫。
- semgrep 內建規則很少，還沒在實機的 semgrep 上驗證過。
- Grok CLI 每次呼叫會帶約 37k token 的系統 prompt，2026-10 實測一次約 0.027 美元，並且會在 `~/.grok` 留下 session 紀錄，裡面含有被審的程式碼。
- gitleaks、semgrep 會讀取 repo 自帶的 ignore 檔（`.gitleaksignore`、`.semgrepignore`），被審 repo 可以藉此隱藏掃描結果。

## 開發

```bash
cargo build
cargo test                                            # 單元＋整合測試，不呼叫任何真實模型
cargo test -p vettalon --lib sandbox -- --ignored    # 真實 Docker 沙箱測試
cargo clippy --all-targets
```

`fixtures/demo-app` 是故意寫壞的測試專案，標準答案在它的 README。

## Vettalon Pro

這個 repo 是 Vettalon 的開源核心：上面列的掃描、多模型分工與跨家族覆核、PoC 沙箱、SARIF、提交草稿全部免費，沒有功能鎖或次數限制。

另有付費的 Vettalon Pro，提供桌面 App、本機 dashboard（可設時間預算、隨時取消掃描，並有檢視供應鏈獵捕結果、產生上游揭露草稿的「供應鏈」分頁），以及對齊台灣資安檢測報告慣例的企業報告產生器（PDF／Word／HTML）。Pro 讀的是同一份 `scan --report` JSON，核心不依賴 Pro。

Pro 需要授權金鑰，詳見 [官網](https://vettalon.dudustudio.monster/#editions)。桌面 App 支援 Apple Silicon Mac、Windows 10／11（x64）與 Linux（x86_64），不支援 Intel Mac，安裝檔在[下載頁](https://vettalon.dudustudio.monster/download/)。開源核心不需要授權，也不會檢查授權；上面的 CLI 在 Intel Mac 上照常可用。

## Coverage 與證據紀錄（下版預覽）

參閱[coverage 與 proof 契約](docs/COVERAGE.md)及[公開合成範例](fixtures/coverage/README.md)。`vettalon evidence attach` 核對本機 artifact hash 並保留操作人提供的 run／修補對照／control 紀錄，不執行任何命令，也不會將 finding 改為 confirmed。歷史證據缺失維持 unknown；既有沙箱 PoC 仍是獨立模式示範。

[實驗工具（預覽）](docs/EXPERIMENTAL-TOOLS.md)：自建樣本、有限離線原型與重現限制；未證明模型效能優勢。

## License

Apache-2.0，見 [LICENSE](LICENSE)。程式碼來源與第三方 MIT 聲明（Cloudflare security-audit-skill）見 [NOTICE](NOTICE)。
