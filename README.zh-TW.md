# Vettalon

<div align="center">

[English](README.md) · **繁體中文**

</div>

[![CI](https://github.com/zhixuli0406/vettalon/actions/workflows/ci.yml/badge.svg)](https://github.com/zhixuli0406/vettalon/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

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
  - 已登入的 `claude`（Claude Code）；`codex`、`grok` 也能用，預設會在容器沙箱裡跑（需要 Docker，先跑一次 `vettalon agents build`），細節見下面的「安全邊界」
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

在 GitHub Actions 裡掃描、把結果送進 code scanning，用 [vettalon-action](https://github.com/zhixuli0406/vettalon-action)：

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: zhixuli0406/vettalon-action@v1
```

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

# 存一份到 ~/.vettalon/reports，下次掃描時，沒改過的檔案沿用上次的判定
vettalon scan . --profile deep --save

# 檢查報告檔有沒有被改壞
vettalon validate report.json

# 全部模組都審（--max-modules 0；受安全上限 40 個模組約束，其餘列為 deferred）
vettalon scan . --profile deep --max-modules 0 --report report.json

# 給 AI 深審一個整體時間預算：用完就把待審模組 deferred、標為 incomplete，不再無止境磨
vettalon scan . --profile deep --time-budget 1200 --report report.json

# 記錄每次模型呼叫的追蹤（JSON Lines：步驟、模型、位元組數、延遲、結果，不含內文）
vettalon scan . --profile deep --trace trace.jsonl

# 政策門檻（可重複）：跨家族覆核成立或人工確認的「高」以上發現超過 0 筆就讓 CI 失敗
# 有 --gate 而沒指定 --fail-on 時，只由門檻條件決定結束碼
vettalon scan . --profile deep \
  --gate 'severity>=high status=confirmed,needs_human cross_family count>0'

# 漏洞提交草稿：先列出可提交的項目，再為其中一項產生指定管道的草稿
# （只產生草稿，不會替你送出；只有經覆核「需人工研判」或人工確認的項目才能產生）
vettalon disclose report.json
vettalon disclose report.json --finding <id> --channel twcert --out draft.txt

# 供應鏈獵捕：稽核專案相依 OSS 套件的原始碼，找尚未登錄的新漏洞
# 先預覽會審哪些（不花 token），再真的跑
vettalon hunt . --dry-run
vettalon hunt . --finders claude --verifiers codex --max-deps 20

# 寫出完整報告，並為新漏洞候選產上游揭露草稿（只草稿，不會送出）
vettalon hunt . --report hunt.json --disclose-dir drafts/
```

### 供應鏈獵捕（`vettalon hunt`）

`vettalon hunt <project>` 從專案的 lockfile（Cargo.lock、npm `package-lock.json`、pip `requirements.txt`、Go `go.sum`）解出相依套件，抓它們的官方發佈原始碼來審，找**還沒被登錄成 CVE** 的新漏洞——和既有 SCA 工具（比對已知 CVE）互補。先查 OSV 分出「已知」與「可能是新的」，預設只審**直接依賴**、跳過 OSV 已有 CVE 的版本（那些 SCA 已在追），把 AI 預算集中在未登錄的；每個相依用跟 `scan --profile deep` 一樣的跨家族對抗覆核。確認且 PoC 跑通的新發現才列為揭露候選。

旗標：`--max-deps N`（上限，預設 20）、`--include-transitive`（連間接依賴）、`--reaudit-known`（連已知 CVE 版本也審）、`--dry-run`（只預覽選取，不抓取不花 token）、`--report <檔>`（寫出完整 JSON）、`--disclose-dir <目錄>`（為新候選產上游負責任揭露草稿，附送出前檢查清單，只草稿、永不送出）、`--dep-timeout <秒>`（每個相依 fetch+audit 的時限，預設 300，逾時記錯誤並續跑）、`--dep-concurrency N`（同時審查幾個相依，1–4，預設 2；總 token 用量不變，但每個模型同時收到 N 個呼叫，CLI 帳號遇到限流就調低）、`--poc`、`--finders`／`--verifiers`。OSV 以批次查詢，大型相依樹也只打少數幾次。獵捕模式會連網抓原始碼與查 OSV，出口限定套件登錄處與 `api.osv.dev`；被稽核專案自己的私有程式碼不出境，送出去的只有相依套件的 `name@version`。`scan` 的零網路行為不受影響。

付費的 Vettalon Pro 另可把獵捕報告產成企業供應鏈報告（Word／PDF／HTML）。

### 漏洞提交草稿

`vettalon disclose` 從 repo 本身（git remote、SECURITY.md、套件設定，不連網）判斷通報管道，產生 GitHub 私密漏洞回報、專案安全信箱、TWCERT/CC（建議 90 天公開）、HITCON ZeroDay（60 天）格式的草稿與建議公開日期。草稿裡「已人工重現／尚未重現」一欄必須自己填。只有經覆核留下的 `needs_human` 或人工確認的發現可以產生草稿，沒覆核過或已證偽的會被拒絕。vettalon 不會替你送出任何東西。

### 政策門檻（`--gate`）

`--fail-on` 只看嚴重度。`--gate` 是條件式門檻，可以疊好幾條，任一條成立就算不通過，結果寫進報告的 `summary.policy`：

| 寫法 | 意思 | 預設 |
|---|---|---|
| `severity>=LEVEL` | 只算這個等級以上（critical／high／medium／low／info） | `info` |
| `status=a,b` | 只算這些狀態（candidate／confirmed／needs_human；誤判與排除不能當門檻） | `candidate,confirmed` |
| `cross_family` | 只算有跨家族覆核模型判定成立、或已人工確認的發現 | 不限 |
| `count>N`／`count>=N` | 數量達到就不通過（必填） | — |

沒給 `--fail-on` 又有 `--gate` 時，`--fail-on` 視為 `none`；兩者都給時任一不通過即失敗。報告後續的人工判定會重算門檻結果。`summary.policy` 只證明「結果與報告內的條件一致」，不證明條件沒被改過；以掃描當下的結束碼為準。

結束碼：`0` 沒有達到 `--fail-on` 門檻、`--gate` 條件全部通過；`1` 未通過；`2` 掃描本身沒能完成（路徑錯誤、門檻條件寫錯、報告寫不出來等等）。

### 模組排序（`--rank`）

深掃預設用內建的啟發式排序器決定模組審查順序（git 熱點、進入點、風險分數），**零網路**。另有選配的 `--rank jev`：把模組的**metadata**（路徑、副檔名、位元組大小、是否進入點、git 熱點數——**不含任何程式碼內容**）送到 TypeSafe Jev，排序後把高風險檔排進審查名額內。基準上 Jev 把深掃的 hit@40 從 6/9 提到 8/9（見[官網基準測試](https://vettalon.dudustudio.monster/#benchmarks)）。

```bash
# 預設啟發式（零網路）
vettalon scan . --profile deep

# 用 Jev 排序（需 config 設好 [jev]）
vettalon scan . --profile deep --rank jev
```

- **只有 `--rank jev` 才連網**；不給這個旗標，scan 維持零網路。
- 送出前由 `assert_metadata_only` 逐檔比對原始碼，任何程式碼內容外洩就 fail-closed。
- Jev 不可用（斷線／逾時／回錯）時自動退回啟發式，出一行提示，不中斷掃描。
- Jev 只排序，**不取代** finder／verifier。

金鑰設定（兩種，config 一律不存 key 本身）：
```toml
[jev]
api_key_env = "TYPESAFE_API_KEY"                            # 法一：環境變數名
# api_key_file = "/home/you/.config/vettalon/typesafe.key" # 法二：0600 金鑰檔
```
解析順序：環境變數有值優先，否則讀金鑰檔。金鑰只活在呼叫當下，不落檔、不進報告、不進 log。

**給終端客戶**：Jev 預設關閉，由客戶自己決定要不要開。CLI 每次用 `--rank jev` 都會在輸出印一行「把 metadata 送到 <host>」。客戶用**自己的 TypeSafe 金鑰**（BYOK），計費與資料處理關係在客戶與 TypeSafe 之間。檔案路徑本身可能透露內部專案名稱，想完全不出境就用啟發式排序（預設）。TypeSafe 的資料保留期限依其條款而定（非企業方案無固定天數、零保留 ZDR 僅企業方案）。

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
- `api_key_env` 只接受 `_API_KEY`、`_KEY`、`_TOKEN` 結尾的名稱，`AWS_*` 不接受。
- 自訂 CLI 的 `program` 必須是絕對路徑。

## 安全邊界

被審查的程式碼是不可信資料，裡面可能藏著寫給模型看的指令（prompt injection）。vettalon 有這幾層防護：

- 每次呼叫 CLI 都在全新的空暫存目錄裡執行，只傳遞白名單內的環境變數，例如 `HOME`、`PATH`，以及該 CLI 認證需要的變數。
- 模型講出的任何路徑，一律先 canonicalize，確認仍在 repo 內才讀取，指到 repo 外的 symlink 不會被讀。
- 報告和 SARIF 寫出前，所有自由文字欄位都會遮蔽秘密，檔案權限一建立就是 0600。SARIF 裡不包含本機的絕對路徑。
- 審查前先掃出藏在程式碼裡、寫給模型看的指令（見「怎麼運作」第 6 點），不讓「叫模型回報乾淨」的注入悄悄過關。

**各 CLI 能不能關掉工具不一樣（2026-10-12 實測）：**

| CLI | 關閉工具的旗標 | 實測結果 |
|---|---|---|
| claude | `--tools ""` | 有效，模型沒有任何工具 |
| codex | `--sandbox read-only`，並停用使用者設定、MCP、apps、hooks、plugins | shell 仍然**能讀取本機任何檔案** |
| grok | `--tools ""` | **無效**，仍能讀檔，也能執行指令 |

所以 codex、grok **預設在容器沙箱裡跑**：

- 先跑一次 `vettalon agents build` 建好映像檔（固定版本的 codex、grok，加一個 egress proxy）。
- 每次呼叫都開一個全新容器，裡面只有一份複製進去的 auth 檔和一個空的工作目錄，看不到 host 的檔案系統和環境變數。
- 容器接在 `--internal` 的 Docker 網路上，沒有對外路由；唯一的出口是 proxy，只放行模型廠商的網域，其他一律拒絕。
- 實測：容器裡的 grok 被要求讀 host 檔案時回「不存在」。

殘留風險：容器裡的模型仍讀得到那份複製進去的 auth 檔，理論上能把它送到白名單內的廠商網域。

如果你確定只審自己信任的程式碼，想省掉容器的額外時間，可以在設定檔對該模型設 `allow_agent_tools = true`，改成直接在 host 上跑（接受上面的讀檔風險）。自訂 `program` 無法自動容器化，只能走這條路。

管理容器：`vettalon agents build` 建映像檔、`vettalon agents stop` 收掉 proxy 和內網。

## 怎麼運作

1. **intake**：統計語言、找進入點，讀 git 歷史，把常出安全修補的檔案標為熱點，再依風險排序模組。文件與非程式碼檔（`.md`、`.rst`、圖片、鎖檔、二進位、翻譯檔…）不列為可審模組（AI 深審只推理程式碼），巢狀的獨立 clone 與根 `.gitignore` 排除的目錄也不列入；單次審查的模組數有安全上限（40），`--time-budget` 另給整體時間預算。排序預設用內建啟發式（零網路）；`--rank jev` 可改用只看 metadata 的 Jev 排序（見「模組排序」）。
2. **分工找洞**：前 `--max-modules` 個模組依序輪流分配給各個 finder，一個模組只交給一個模型審，所以成本跟單一模型差不多。
3. **前置檢查**：不呼叫任何模型，只核對模型講的檔案、行號和呼叫鏈是否真的存在，對不上就直接證偽。
4. **高風險模組雙審**：git 安全熱點或進入點的模組（天然少數）會自動再交給一家不同家族的 finder 審一次，兩家各讀一遍；加 `--cross-check-top N` 可把前 N 個高分模組也納入。一家漏看、另一家補上。
5. **跨家族覆核**：每個候選交給一個與 finder 不同家族的 verifier，要它從零開始試著推翻。推翻不了的標成 `needs_human`，附上「還需要確認什麼」的清單。模型清單裡沒有其他家族時，會退回同家族的其他模型，再不行就由 finder 自己覆核，投票紀錄裡會寫明（`same_model`）。
6. **偵測寫給模型看的指令**：審查前先用零 LLM 的規則掃過每個模組，找出「叫審查模型回報乾淨」這類文字（例如 `respond with {"candidates": []}`、「report no vulnerabilities」、「this file is secure」）。命中的模組會額外交給另一家族的模型再審一次，並記在報告的 `ensemble.suspected_injection`；模型清單只有一個家族、無法交叉覆審時，整次執行標成 `incomplete`。
7. **PoC**（`--poc`）：對 High 以上的 `needs_human`，盡量交給另一家模型寫腳本，在 Docker 沙箱裡執行。沙箱的限制：
   - 斷網、根目錄唯讀、拿掉所有 capabilities、以非 root 身分執行
   - 限制記憶體和行程數
   - host 端和容器內各有一道時限
   - 不自動拉映像檔

   容器裡只有 Python 標準函式庫和 bash，repo 本身不在容器內，所以 PoC 要用標準函式庫重現有漏洞的寫法。沙箱起不來就跳過，絕不在本機執行。PoC 跑通也不會自動把發現標成 confirmed。

**拒答不轉送。** 模型拒絕審查時，只有那個模組記成「未審」，同一個模型分到的其他模組照常進行。拒答會列在 `ensemble.refusals`，整次執行標成 `incomplete`（`model_refused`），不會悄悄改丟給別的模型。覆蓋缺口要攤開給你看，換不換模型由你決定。

**誠實的完成狀態。** 下列情況都會讓報告標成 `incomplete`，並附上原因：
- 某個 finder 完全連不上
- 有模組的呼叫失敗，或回覆不符合格式
- 有候選沒拿到覆核結論

覆核獨立性只計算真正給出判定的覆核，呼叫失敗或拒答都不算。同一個 verifier 第一次就連不上時，同組其餘的候選會直接標成未覆核，不會每一筆都等滿逾時。

**AI 不會自動宣告「確認」。** AI 能做到的最高狀態是 `needs_human`，`confirmed` 只能由人來標。

報告格式定義在 [`crates/vettalon/src/audit/schema.rs`](crates/vettalon/src/audit/schema.rs)，寫檔前一律先跑 validator。SARIF 2.1.0 輸出可以直接上傳到 GitHub code scanning，被證偽的發現會標成 suppressed，不會刪掉；result 的 properties 另帶該發現對應的 CAPEC 攻擊模式（`vettalon.capec`）與依前置條件推導的可利用性分級（`vettalon.exploitability`：direct／conditional／hard_to_reach）。有 CWE 對應的發現，報告會多一段攻擊情境與 CAPEC 參考連結。`--trace` 會另寫一份逐次模型呼叫的 JSON Lines（只記步驟、模型、位元組數、延遲、結果，不含內文）。

## 已知限制

- 一般模組只有一個 finder 審，那個模型漏看就是漏掉。高風險模組（熱點／進入點）、疑似 injection 的模組、以及 `--cross-check-top` 指定的前 N 個會由兩家審；其餘仍是一家。實測時 grok 有一輪漏掉了 `fixtures/demo-app` 的 path traversal，前一輪卻找得到，模型輸出有隨機性。重要的程式碼請多跑幾次，或用 `--finders` 換模型。
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

Pro 需要授權金鑰，詳見 [官網](https://vettalon.dudustudio.monster/#editions)。開源核心不需要授權，也不會檢查授權。

## License

Apache-2.0，見 [LICENSE](LICENSE)。程式碼來源與第三方 MIT 聲明（Cloudflare security-audit-skill）見 [NOTICE](NOTICE)。
