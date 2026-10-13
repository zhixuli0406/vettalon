# Vettalon

[![CI](https://github.com/zhixuli0406/vettalon/actions/workflows/ci.yml/badge.svg)](https://github.com/zhixuli0406/vettalon/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/vettalon?logo=npm)](https://www.npmjs.com/package/vettalon)
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

# 全部模組都審（--max-modules 0；大型 repo 較慢、較花費）
vettalon scan . --profile deep --max-modules 0 --report report.json

# 漏洞提交草稿：先列出可提交的項目，再為其中一項產生指定管道的草稿
# （只產生草稿，不會替你送出；只有經覆核「需人工研判」或人工確認的項目才能產生）
vettalon disclose report.json
vettalon disclose report.json --finding <id> --channel twcert --out draft.txt
```

### 漏洞提交草稿

`vettalon disclose` 從 repo 本身（git remote、SECURITY.md、套件設定，不連網）判斷通報管道，產生 GitHub 私密漏洞回報、專案安全信箱、TWCERT/CC（建議 90 天公開）、HITCON ZeroDay（60 天）格式的草稿與建議公開日期。草稿裡「已人工重現／尚未重現」一欄必須自己填。只有經覆核留下的 `needs_human` 或人工確認的發現可以產生草稿，沒覆核過或已證偽的會被拒絕。vettalon 不會替你送出任何東西。

結束碼：`0` 沒有達到 `--fail-on` 門檻的發現；`1` 有；`2` 掃描本身沒能完成（路徑錯誤、報告寫不出來等等）。

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
- 審查前先掃出藏在程式碼裡、寫給模型看的指令（見「怎麼運作」第 5 點），不讓「叫模型回報乾淨」的注入悄悄過關。

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

1. **intake**：統計語言、找進入點，讀 git 歷史，把常出安全修補的檔案標為熱點，再依風險排序模組。
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

報告格式定義在 [`crates/vettalon/src/audit/schema.rs`](crates/vettalon/src/audit/schema.rs)，寫檔前一律先跑 validator。SARIF 2.1.0 輸出可以直接上傳到 GitHub code scanning，被證偽的發現會標成 suppressed，不會刪掉。

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

另有付費的 Vettalon Pro，提供桌面 App、本機 dashboard，以及對齊台灣資安檢測報告慣例的企業報告產生器（PDF／HTML）。Pro 讀的是同一份 `scan --report` JSON，核心不依賴 Pro。

## License

Apache-2.0，見 [LICENSE](LICENSE)。程式碼來源與第三方 MIT 聲明（Cloudflare security-audit-skill）見 [NOTICE](NOTICE)。
