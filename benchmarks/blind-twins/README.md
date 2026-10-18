# 匿名合成 twins 評量底座

此目錄是獨立實驗，沒有修改產品的跨模型家族安全政策。資料共有 **10 對、5 家族、每家族 2 個命名變體**，不是 10 種獨立根因，也不是第三方 OSS 漏洞。家族包括物件／租戶／角色授權、測試目錄邊界、SQLite 記憶體查詢；所有效果限合成資料。

目錄：

- [固定同 scope 的消融準備](#固定同-scope-的消融準備)
- [匿名與合成來源歸屬檢視](#匿名與合成來源歸屬檢視離線接線)
- [Runner 資源量測邊界](#runner-資源量測邊界)

- `anonymous/*.json`：僅不透明 ID、來源及來源 SHA-256，可送模型。
- `private/labels.json`：標籤、配對、家族與 split；`private/identity-map.json` 只記自建 synthetic origin，沒有真實 CVE 身分。兩者不進 prompt。
- dev 與 holdout 的家族、合成 repo、snapshot 日期皆不交叉；此設計檢驗 pipeline，不能證明沒有預訓練污染。
- `protocol.py canonical`：逐 specimen 建全新 Docker container，在受限環境編譯／執行 function 和隱藏 canonical oracle。先查安全效果與正常 control，再凍結分母。exit 0 本身不能通過。
- `run.py`：finder-only／samefamily／crossfamily 實驗 arms、嚴格 JSON、lineage、固定分母、超時與預算。samefamily 只在此實驗存在；跨家族須不同 family。
- `aggregate.py`：不呼叫模型，從 raw 重新計算 metrics；拒絕來源／分母不符。
- `measurement.py`：僅量 runner process 的 CPU interval 與 process-lifetime RSS observation；不量模型服務、子程序或 GPU。
- `ledger.py`：只讀固定 D01 排程及既有 formal-transport 持久扣額的跨輪對帳；同一匿名檢視只有 15 輪、250 個 slot、256,000 個預留輸出 token。
- `transport.py`：將既有 `benchmarks/formal-transport/` 的 capability gate 與可重算報表接到 twins；本目錄不另造 provider sender。

在乾淨source checkout重建與測試（由repo根目錄執行）：

單元測試會在暫存目錄建立明示「未執行 oracle」且 `eligible_pairs=[]` 的自建合成分母，因此乾淨公開 checkout 可先離線跑完整測試；測試內的 canonical 可重建分母為 0，不是對實際 10 對案例的測量，也不替代後續 runner 所需的 canonical 分母。另有受控假模型回答命中一筆標籤，測得 `synthetic_label_match_detection_proxy=0.2`；這仍與 canonical 可重建分母 0 及 `exploit_validated_recall=null` 分開記錄，不是 PoC 驗證。執行 canonical 前須備妥可信本機 Docker 與已載入的 `python:3.12-slim` image；它只執行自建合成 fixture，腳本不 pull。以下順序全部 0 真模型；輸出目錄與 raw 必須是新路徑：

```bash
mkdir ./vettalon-twins-reproduction-output
python3 -B -I -S -m unittest discover -s benchmarks/blind-twins -p 'test_*.py'
python3 benchmarks/blind-twins/protocol.py generate
python3 benchmarks/blind-twins/protocol.py canonical
python3 benchmarks/blind-twins/run.py --mock \
  --output ./vettalon-twins-reproduction-output/mock.json
python3 benchmarks/blind-twins/aggregate.py \
  --raw ./vettalon-twins-reproduction-output/mock.json \
  --output ./vettalon-twins-reproduction-output/recomputed.json
python3 benchmarks/blind-twins/rehearse.py \
  --output-dir ./vettalon-twins-reproduction-output/rehearsal
```

`generate`在本機建立匿名source、oracle bookkeeping／labels及固定subset；oracle與labels不送模型。default `canonical`建立runner所需的`reports/evidence-acceptance/experiments/canonical-oracle.json`與`denominator.json`。這些是本機新產物，不是公開包內既有私有證據。runner、aggregator與formal reader會從 canonical 的完整成對 rows 重算可重建資格，核對來源／harness hash、成功 oracle 回覆與隔離執行欄位，再要求凍結的 eligible pairs、分母與排除清單一致；單獨匹配 SHA 或自述 eligible pairs 不能提升分母。檔案內的容器觀察仍是本機記錄，不是不可偽造的遠端證明。aggregate明確讀取本次mock raw，不回退去找歷史pilot。

OSS 匯出清單會將 `run.py`、`aggregate.py`、`rehearse.py`、`ledger.py`、`transport.py` 及其離線測試一併帶出；不匯出已落地的 `anonymous/`、`manifest.json`、`fixed-five-pair-subset.json`、`private/` 或任何歷史 raw。前三種資料由上述 `generate` 在公開 checkout 重建；私有標籤只供當地 canonical／重算使用，不能當成公開、獨立的第三方 OSS 標註。

已有canonical／raw／freeze時須保留；不要重用上述新輸出路徑或覆寫歷史。若只做獨立canonical重建，可另用新檔名／目錄：

```bash
mkdir ./vettalon-twins-alternate-output
python3 benchmarks/blind-twins/protocol.py canonical \
  --output ./vettalon-twins-alternate-output/canonical.json
```

alternate的denominator依輸出檔名另存；它**不替換runner固定使用的default baseline**，不能用它省略乾淨checkout的default準備。重新採用分母要先人工版本化，不可在模型測試後選擇性刪除失敗案例。

舊版匿名本機 pilot 只在已授權的單次有限預算內跑真模型：20 calls、90 秒／call、1024 output tokens、1200 秒總預算、1 inflight、0 retry；它沒有跨次持久總帳，不可將多次執行的上限相加後宣稱仍受 D01 共享預算保護。只連 `127.0.0.1:11434`，不向模型提供工具、host filesystem 或 credentials。啟動先記模型 digest、程式 hash、預算；之後每筆 raw prompt/response 及來源 hash 落地。identified 的非 mock pilot 已 fail closed 停用；完整三 arm、5 repeats 的真消融尚未執行，需要另核定預算。這次未呼叫 Claude CLI。

`synthetic_label_match_*_proxy` 只是 category/label 對照；真實根因是否正確仍需獨立裁定。未裁定候選列 U，precision 給上下界，adjudicated recall 留 unknown／區間。若沒有執行模型提出的 PoC，exploit recall 為 `not-measured`。timeout、parse failure、缺筆、預算不足都留分母；p50/p95 至少 20 個完整量測，樣本不足為 null。原始 schema、重複 ID、來源雜湊錯誤均 fail closed。

## 固定同 scope 的消融準備

`generate` 同時產生 `fixed-five-pair-subset.json`，各家族取同一命名變體，共五對十 specimen；manifest 只含 opaque IDs／source hashes，不含 label。使用 `--subset-path` 在各 arm 固定同 scope，runner 與 aggregator 驗重複、完整 pair、來源與 manifest hash。預設 full-20 並不代表 2-stage arm 能在 20-call cap 內完成；真消融必須明確選 subset。

```bash
python3 benchmarks/blind-twins/protocol.py generate
python3 benchmarks/blind-twins/rehearse.py --output-dir NEW_LOCAL_REHEARSAL_DIR
```

rehearsal 使用純 mock transport 跑三 arms × 五 repeats；250 是 mock invocations，真模型為零。未來 D01 的 call 上限為 finder-only 50、samefamily 100、crossfamily 100，總 output 上限 256000 tokens，USD 與跨家族 provider 尚未核定。每 call 90 秒／每 run 1200 秒可能令 2-stage arm 在最差耗時下不完整，不能事後縮分母或自動重試。

### Formal 批次預檢與對帳（離線）

`run.py --formal-preflight-model-roster ROSTER.json --output NEW_PREFLIGHT.json` 讀取三個明確角色（`finder`、`samefamily_verifier`、`crossfamily_verifier`）的 `{name,digest,family}`；先用既有 formal runner 實讀 materialized sources／凍結分母並逐輪比對同一 plan，再檢查 exact provider/model controls。這個入口不建立 ledger、不扣額、不啟動 HTTP 或模型。正式 registry 目前沒有已核實的生效 1,024 輸出 token／零內部重試控制，因此結果為 `dispatch_enabled=false`、三角色 blocker、真呼叫與扣額 0。填入模型名稱與 SHA 宣告、CLI 已登入或 API 文件本身都不能解除 gate；不可用 mock 模型結果代替正式比較。正式發送仍屬獨立 [`formal-transport/run_v1.py`](../formal-transport/README.md) `execute` 入口。

`aggregate.py` 遇到 `formal-experiment-v1` raw 會先交給既有 formal reader 核對 immutable attempt 與 derived 欄位，再分開呈現 `requested`、`enforced`、`observed`。單筆已預扣 1,024 不等實際輸出 1,024；provider-reported usage 只列已知小計與未知 attempt，未知總量、provider 收到的實際請求與內部 retry 留 `null`。v1 沒有獨立 server receipt，raw 若填入 0 或 1 筆 `provider_requests_received` 會拒絕；`client_recorded_repeat_dispatches` 也只在每個 client entry 都已知時列 0，否則為 `null`。`aggregate_formal_batch(raw_paths, denominator_path, ledger_path)` 僅接受正式 writer 的唯一 canonical budget path，對最多 15 輪 formal raw 做共享 plan／重複輪次／started、request、dispatch-entry 與 attempt artifact 同目錄 SHA 對帳；驗證採有界 nofollow 讀回。完成狀態還要求每份 raw 明示 `complete`，以及 250 筆各有一次 worker invocation、已知的一次 client request entry 與對應 dispatch-entry；單純預扣不算已嘗試。已扣而無 raw attempt 的 slot 不退款、不視為零耗用，也不取得完成狀態。正式模型、帳單、人工裁定與 server／GPU 成本仍待獨立證據。

依 [VulContextBench](https://arxiv.org/abs/2609.32601) 對「探索時看過」與「最後宣告證據」的分別，轉接報表新增 `context_evidence_gap.status=not-measured`。目前 twins prompt 只附單一合成函式，沒有 agent 探索軌跡或角色標註的 gold code blocks；JSON 的 `line/evidence` 不能冒充該論文的 file／block／line context retrieval recall。

本次接線以 Python 3.14 跑 blind-twins 全目錄 **95 methods／0 fail**；formal-transport 全目錄在固定的真實（非 `/var` symlink）`TMPDIR` 下 **94 methods／0 fail**。CI 現設定以 Python 3.12 跑兩套純離線 suite，CI 結果仍須以實際執行為準；正式 reader 仍拒絕 symlink 路徑。新增的 canonical 負測試不會執行 Docker 或真 provider。這些單元測試不能稱為真模型評量。

`aggregate.py --raw ./vettalon-twins-reproduction-output/mock.json --overlay REVIEWER_FILE --output NEW_FILE` 可將獨立審查 overlay 套在記憶體副本，不改 raw。overlay 必須綁 raw SHA、case fingerprint、reviewer、TP/FP/U 與理由；代理初審不能表述為 human label。v3 recall bounds 將 missing、timeout、parse failure 與未裁定候選保留為 unknown；完整 negative answer 是可觀察的 miss。category-match proxy 不篩掉語意可能正確的 TP/U。

Two-stage 必須明確指定非空 verifier model，且同一 model 名稱不能宣告兩種 family。舊版 `run.py` 本機模式的 family 由已安裝 Ollama `tags.details.family` 經保守 registry 分組；宣告不符或來源未知則拒絕。這只是實驗的 architecture-family mapping，不是產品 vendor-lineage 證明。舊版 runner 的非 mock custom transport 仍未開放；正式候選入口另在 `formal-transport/`，但 exact provider controls 尚未驗證而維持 disabled。mock mapping 明列無模型 provenance。finder timeout／parse failure 保留實際 stage／原因，不因少一個 verifier attempt 誤寫 budget exhausted。

## 匿名與合成來源歸屬檢視（離線接線）

`identity_views.py` 提供四個純函式，讓同一個 case／source／scope 可另建 **identified synthetic source attribution** 檢視。`run.py` 與 `rehearse.py` 現已接入離線 mock：每次執行只選一種 view，預設 anonymous；identified 須明確指定 `--identity-view identified --identity-binding-path PATH`。非 mock identified 在建立 raw 或連線之前拒絕；不會自動排兩種 view 或呼叫另一家 provider。

| 函式 | 輸入與用途 |
|---|---|
| `build_view(payload, view='anonymous', identity_binding=None)` | anonymous 原樣複製三個欄位及順序，保留目前 `json.dumps` 序列化；identified 必須明確傳入來源綁定。 |
| `validate_view(payload, view, expected_case, source_manifest_sha256=None)` | 比對呼叫者提供的 case／來源／UTF-8 SHA-256；兩種檢視都保留原匿名文字防洩漏規則。 |
| `build_paired_manifest(payloads, scope_manifest, identity_bindings, source_manifest_sha256)` | 為明確選定的完整 scope 產生兩種檢視的配對雜湊；拒絕缺筆、重複、額外 case 或來源不符。 |
| `validate_paired_manifest(manifest, payloads, scope_manifest, identity_bindings, source_manifest_sha256)` | 重新計算並比對完整配對資料；不驗證檔案系統。 |

直接使用純函式前，呼叫者須先讀取實際 `manifest.json` 原始 bytes，計算其 SHA-256，並逐一核對已落地 `anonymous/<id>.json` 的 ID、source 與 `source_sha256` 是否符合 manifest；確認檔案存在且內容相符後，才將這些已核對資料傳入函式。純模組收到的是**宣告綁定**，不會自行讀檔。runner 的 identified 前置檢查則會以每檔 64 KiB 的 nofollow 有界讀取實際檢查完整 20 個已落地匿名來源、manifest 與 binding、比對凍結產生器，再檢查綁定檔恰好覆蓋所選 scope；reaggregation 亦用相同讀取邊界。任一不符會在建立 raw／模型連線之前拒絕。這只證明本機來源檔與綁定資料一致，不認證上游或資料集獨立性。

每個 identified payload 只多一個 `source_identity`，其 exact keys 為 `kind`、`collection`、`artifact`、`source_manifest_sha256`。值分別為 `self-authored-synthetic`、`vettalon-self-authored-twins`、`benchmarks/blind-twins/anonymous/<同一 opaque id>.json` 及呼叫者核對過的 manifest 原始 bytes SHA-256；不接受 upstream repo／CVE／family／variant／split／label／oracle 等附加欄位。它表示自建合成來源歸屬，沒有恢復真正 upstream 身分；雜湊也不是來源真實性的認證，不能用來宣稱污染效果。

`scope_manifest` 使用既有 `fixed-subset-v1` 三欄格式（`schema`、`case_ids`、`source_sha256`）：可明確選全部 20 個 specimen，也可選既有固定五對十個 specimen。payloads 和 identity_bindings 必須剛好覆蓋所選 scope；函式不會補入其餘案例。配對結果分開保存：manifest 原始 bytes hash、沿用既有 `json.dumps(scope_manifest, sort_keys=True)` 的 scope 語意 hash，以及 JSON `sort_keys=true`／`ensure_ascii=false`／comma-colon separators／UTF-8 的兩種 payload hash；三種雜湊不可互換。

identity 是三種覆核 arms 之外的另一個維度。identified 的 raw 會保存 binding 檔原始 bytes hash、materialized manifest 原始 bytes hash、完整 scope 的 paired view hashes、所選 payload hash、runner／identity module hash、固定執行上限與每次 prompt hash；實際 prompt 只多 `source_identity` 四欄，不讀取 `private/labels.json` 或 `private/identity-map.json`。identified 重算須用 `aggregate.py --raw RAW --denominator DENOMINATOR --identity-binding-path 同一綁定檔 --output NEW_FILE`；reader 會獨立重讀已落地來源與綁定、重建配對 hashes／row fingerprint／每次 prompt，從 raw response 重算 detected／surfaced／root-cause proxy／stage 狀態，並核對每次 1024 output tokens、90 秒 timeout、每輪最多 20 calls／1200 秒、單工與零 retry 後，才計算 metrics。綁定、版本或派生欄位不符即拒絕；匿名歷史 raw 無須此檔。這是同版本本機一致性檢查，不是不可偽造的來源簽章。

原匿名固定五對的三 arms × 五 repeats 正式規劃上限仍為 250 calls／256000 output tokens；單次 mock 演練指定 identified 只會把該次 schedule 的 view 換掉，**不會在該次加跑第二套**。這不限制另一次執行，也不是 D01 持久扣額證據。若未來完整重做兩種 identity views，會是 500 calls／512000 output tokens，必須另行決定預算並實作跨次總帳。現有分母與歷史 raw 維持原版本。

綁定檔為 JSON，頂層 exact keys 是 `schema`、`source_manifest_sha256`、`bindings`，schema 固定 `twins-identity-bindings-v1`。`source_manifest_sha256` 填實際 `manifest.json` 原始 bytes SHA-256；`bindings` 的 key 須恰好等於此次 scope 的 opaque case IDs，值須符合上方四欄 `source_identity` 合約。例如固定五對中的單筆：

```json
{
  "schema": "twins-identity-bindings-v1",
  "source_manifest_sha256": "<實際 manifest.json 原始 bytes SHA-256>",
  "bindings": {
    "c-00e3f6d52d1ba13a": {
      "kind": "self-authored-synthetic",
      "collection": "vettalon-self-authored-twins",
      "artifact": "benchmarks/blind-twins/anonymous/c-00e3f6d52d1ba13a.json",
      "source_manifest_sha256": "<同一 SHA-256>"
    }
  }
}
```

範例僅示意一筆；固定五對須列出全部 10 個，full scope 須列出全部 20 個。可用 `shasum -a 256 benchmarks/blind-twins/manifest.json` 取得本機值。離線 mock 演練（新輸出目錄）：

```bash
python3 benchmarks/blind-twins/rehearse.py --output-dir NEW_LOCAL_REHEARSAL_DIR \
  --identity-view identified --identity-binding-path YOUR_BINDINGS.json
```

同樣可將兩個 identity 旗標傳給 `run.py --mock --subset-path ...`。未指定時維持匿名；若匿名卻提供綁定檔、identified 缺檔或範圍不符，runner 會拒絕。正式模型實驗仍未啟動；兩種 mock 輸出只可比較排程／提示詞契約，不能聲稱污染或效能效果。

### 離線契約測試

先前純資料檢視的 root 驗證在 Python 3.14 實測新增 **9 項**及舊受影響 **4 項**通過，沒有模型／Docker／provider 執行；guard 語意 RED 用修正前模組得到 1 method、7 marker subtests 的預期失敗。另兩次舊測試載入失敗的 receipt 均保留，未算通過：第一次指定錯類別；第二次雖修正類別，舊 `test_protocol.py` 的 `unittest.main()` 位於該類別定義之前，直接執行仍無法載入。最後以 discovery 僅執行先前尚未跑到的 fixed-subset 方法並通過。接線與 reader 驗證後另以 `unittest discover` 離線跑全目錄 **66 tests／0 fail**，包含新 runner 十項測試；新測試自己在暫存目錄建立合成來源與 mock 分母，不依賴既存未追蹤來源／私有標籤。這不是 66 次模型推論或 Docker oracle 實跑。

由 repo 根目錄使用以下篩選方式跑純資料與 runner 離線契約；不執行 Docker canonical 或模型：

```bash
python3 -B -I -S benchmarks/blind-twins/test_identity_views.py -v
python3 -B -I -S benchmarks/blind-twins/test_identity_runner.py -v
python3 -B -I -S -m unittest discover -s benchmarks/blind-twins -p test_protocol.py -k test_fixed_five_pairs_reproducible_and_hashbound -v
```

既有 237-source 公開快照不包含此新模組；本輪已將 runner、reader 與離線測試納入 `export-oss.sh` 逐檔 allowlist，並在乾淨暫存 OSS 樹驗證離線測試。正式公開 repo 的封裝、提交及發版仍須另外驗收；暫存匯出不等於已發布。

## Runner 資源量測邊界

新 raw 的 `resource_evidence` 使用 Python stdlib `resource.getrusage(RUSAGE_SELF)`，綁定該 raw 記錄的 runner／protocol／measurement source SHA-256。`cpu.user_seconds`、`system_seconds` 與 `total_seconds` 是 artifact 初始化後到最終觀察點的 process CPU 差值，包含 timeout、parse failure、budget-exhausted 的實際 runner 作業；它不是模型 inference CPU、wall latency、整個機器或整段 CLI 啟動成本。最終 serialization 在觀察點之後，不包含在該 interval。每次更新 artifact 的 evidence 是同一起點的累計觀察，不可把歷次觀察或 row wall time 相加當 CPU。

`rss_lifetime_observation.start_bytes/end_bytes` 是此 Python process 自啟動以來的高水位觀察；macOS `ru_maxrss` 原生 bytes，Linux 原生 KiB 乘 1024。它不能每 run 重設，同一 process 多 run 可能繼承先前峰值，兩次讀值相同也不能證明此 run 不需記憶體。因此 `metrics.peak_memory_bytes` 持續為 null，不能把 end value 或 start/end 差當成每 run peak。未知平台的 RSS 單位與不具 resource API 的平台明列 unavailable，不補 0。

Aggregator 只從 raw 已保存且與其 implementation 欄位一致的 evidence 重算；hash binding 是版本關聯，不是簽章或可信 provenance。現在程式改版不會否決合法舊版本記錄；沒有 evidence 的歷史 raw 即使有舊 metrics 數字，也不會補造 CPU／RSS。缺筆與失敗仍留原分母；run 的 CPU 值只代表該次已執行 interval，不代表已完成全部分析。未捕捉的程式例外會保留 incomplete artifact、已記 attempts 與可取得的 resource observation，再把例外交回呼叫端；SIGKILL／斷電或無法寫檔仍可能只留下最後一次持久化狀態。

模型 HTTP server／共用 Ollama daemon、子程序、GPU、電力、USD 與人審時間都仍 unknown。新 mock-only subprocess 實測與重算例：

```bash
python3 benchmarks/blind-twins/run.py --mock --output NEW_MOCK_RAW.json
python3 benchmarks/blind-twins/aggregate.py --raw NEW_MOCK_RAW.json --output NEW_RECOMPUTED.json
```

`--mock` 不做模型 inference，也不啟動模型或 Docker。三 arms／五 repeats 的 cap、1 inflight、90 秒／call、1200 秒／run、0 retry 不變；mock 資源數字不能比較真模型成本。
