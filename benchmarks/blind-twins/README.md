# 匿名合成 twins 評量底座

此目錄是獨立實驗，沒有修改產品的跨模型家族安全政策。資料共有 **10 對、5 家族、每家族 2 個命名變體**，不是 10 種獨立根因，也不是第三方 OSS 漏洞。家族包括物件／租戶／角色授權、測試目錄邊界、SQLite 記憶體查詢；所有效果限合成資料。

目錄：

- [固定同 scope 的消融準備](#固定同-scope-的消融準備)
- [匿名與合成來源歸屬檢視](#匿名與合成來源歸屬檢視純資料)
- [Runner 資源量測邊界](#runner-資源量測邊界)

- `anonymous/*.json`：僅不透明 ID、來源及來源 SHA-256，可送模型。
- `private/labels.json`：標籤、配對、家族與 split；`private/identity-map.json` 只記自建 synthetic origin，沒有真實 CVE 身分。兩者不進 prompt。
- dev 與 holdout 的家族、合成 repo、snapshot 日期皆不交叉；此設計檢驗 pipeline，不能證明沒有預訓練污染。
- `protocol.py canonical`：逐 specimen 建全新 Docker container，在受限環境編譯／執行 function 和隱藏 canonical oracle。先查安全效果與正常 control，再凍結分母。exit 0 本身不能通過。
- `run.py`：finder-only／samefamily／crossfamily 實驗 arms、嚴格 JSON、lineage、固定分母、超時與預算。samefamily 只在此實驗存在；跨家族須不同 family。
- `aggregate.py`：不呼叫模型，從 raw 重新計算 metrics；拒絕來源／分母不符。
- `measurement.py`：僅量 runner process 的 CPU interval 與 process-lifetime RSS observation；不量模型服務、子程序或 GPU。

在乾淨source checkout重建與測試（由repo根目錄執行）：

先備妥可信本機Docker與已載入的`python:3.12-slim` image；下列canonical只執行自建合成fixture，腳本不pull。公開source不附內部歷史baseline／raw，不能先跑依賴分母的tests。以下順序全部0真模型；輸出目錄與raw必須是新路徑：

```bash
mkdir ./vettalon-twins-reproduction-output
python3 benchmarks/blind-twins/protocol.py generate
python3 benchmarks/blind-twins/protocol.py canonical
python3 -m unittest discover -s benchmarks/blind-twins -p 'test_*.py'
python3 benchmarks/blind-twins/run.py --mock \
  --output ./vettalon-twins-reproduction-output/mock.json
python3 benchmarks/blind-twins/aggregate.py \
  --raw ./vettalon-twins-reproduction-output/mock.json \
  --output ./vettalon-twins-reproduction-output/recomputed.json
python3 benchmarks/blind-twins/rehearse.py \
  --output-dir ./vettalon-twins-reproduction-output/rehearsal
```

`generate`在本機建立匿名source、oracle bookkeeping／labels及固定subset；oracle與labels不送模型。default `canonical`建立runner所需的`reports/evidence-acceptance/experiments/canonical-oracle.json`與`denominator.json`。這些是本機新產物，不是公開包內既有私有證據。runner及aggregator檢查同一baseline／分母，aggregate明確讀取本次mock raw，不回退去找歷史pilot。

已有canonical／raw／freeze時須保留；不要重用上述新輸出路徑或覆寫歷史。若只做獨立canonical重建，可另用新檔名／目錄：

```bash
mkdir ./vettalon-twins-alternate-output
python3 benchmarks/blind-twins/protocol.py canonical \
  --output ./vettalon-twins-alternate-output/canonical.json
```

alternate的denominator依輸出檔名另存；它**不替換runner固定使用的default baseline**，不能用它省略乾淨checkout的default準備。重新採用分母要先人工版本化，不可在模型測試後選擇性刪除失敗案例。

只在已授權的本機有限預算內跑真模型：20 calls、90 秒／call、1024 output tokens、1200 秒總預算、1 inflight、0 retry。只連 `127.0.0.1:11434`，不向模型提供工具、host filesystem 或 credentials。啟動先記模型 digest、程式 hash、預算；之後每筆 raw prompt/response 及來源 hash 落地。完整三 arm、5 repeats 的真消融尚未執行，需要另核定預算。這次未呼叫 Claude CLI。

`synthetic_label_match_*_proxy` 只是 category/label 對照；真實根因是否正確仍需獨立裁定。未裁定候選列 U，precision 給上下界，adjudicated recall 留 unknown／區間。若沒有執行模型提出的 PoC，exploit recall 為 `not-measured`。timeout、parse failure、缺筆、預算不足都留分母；p50/p95 至少 20 個完整量測，樣本不足為 null。原始 schema、重複 ID、來源雜湊錯誤均 fail closed。

## 固定同 scope 的消融準備

`generate` 同時產生 `fixed-five-pair-subset.json`，各家族取同一命名變體，共五對十 specimen；manifest 只含 opaque IDs／source hashes，不含 label。使用 `--subset-path` 在各 arm 固定同 scope，runner 與 aggregator 驗重複、完整 pair、來源與 manifest hash。預設 full-20 並不代表 2-stage arm 能在 20-call cap 內完成；真消融必須明確選 subset。

```bash
python3 benchmarks/blind-twins/protocol.py generate
python3 benchmarks/blind-twins/rehearse.py --output-dir NEW_LOCAL_REHEARSAL_DIR
```

rehearsal 使用純 mock transport 跑三 arms × 五 repeats；250 是 mock invocations，真模型為零。未來 D01 的 call 上限為 finder-only 50、samefamily 100、crossfamily 100，總 output 上限 256000 tokens，USD 與跨家族 provider 尚未核定。每 call 90 秒／每 run 1200 秒可能令 2-stage arm 在最差耗時下不完整，不能事後縮分母或自動重試。

`aggregate.py --raw ./vettalon-twins-reproduction-output/mock.json --overlay REVIEWER_FILE --output NEW_FILE` 可將獨立審查 overlay 套在記憶體副本，不改 raw。overlay 必須綁 raw SHA、case fingerprint、reviewer、TP/FP/U 與理由；代理初審不能表述為 human label。v3 recall bounds 將 missing、timeout、parse failure 與未裁定候選保留為 unknown；完整 negative answer 是可觀察的 miss。category-match proxy 不篩掉語意可能正確的 TP/U。

Two-stage 必須明確指定非空 verifier model，且同一 model 名稱不能宣告兩種 family。真本機模式的 family 由已安裝 Ollama `tags.details.family` 經保守 registry 分組；宣告不符或來源未知則拒絕。這只是實驗的 architecture-family mapping，不是產品 vendor-lineage 證明。非 mock custom transport/provider adapter 尚未實作；mock mapping 明列無模型 provenance。finder timeout／parse failure 保留實際 stage／原因，不因少一個 verifier attempt 誤寫 budget exhausted。

## 匿名與合成來源歸屬檢視（純資料）

`identity_views.py` 提供四個純函式，讓同一個 case／source／scope 可另建 **identified synthetic source attribution** 檢視。預設仍是 anonymous；本模組沒有接入 `run.py`、`rehearse.py` 或 provider，也不讀標籤、不寫檔、不啟動程序或選擇預算。

| 函式 | 輸入與用途 |
|---|---|
| `build_view(payload, view='anonymous', identity_binding=None)` | anonymous 原樣複製三個欄位及順序，保留目前 `json.dumps` 序列化；identified 必須明確傳入來源綁定。 |
| `validate_view(payload, view, expected_case, source_manifest_sha256=None)` | 比對呼叫者提供的 case／來源／UTF-8 SHA-256；兩種檢視都保留原匿名文字防洩漏規則。 |
| `build_paired_manifest(payloads, scope_manifest, identity_bindings, source_manifest_sha256)` | 為明確選定的完整 scope 產生兩種檢視的配對雜湊；拒絕缺筆、重複、額外 case 或來源不符。 |
| `validate_paired_manifest(manifest, payloads, scope_manifest, identity_bindings, source_manifest_sha256)` | 重新計算並比對完整配對資料；不驗證檔案系統。 |

使用前，呼叫者須先讀取實際 `manifest.json` 原始 bytes，計算其 SHA-256，並逐一核對已落地 `anonymous/<id>.json` 的 ID、source 與 `source_sha256` 是否符合 manifest；確認檔案存在且內容相符後，才將這些已核對資料傳入函式。模組收到的是**宣告綁定**，不會自行讀檔；`True` 只表示資料一致，不能取代這一步實際來源核對。

每個 identified payload 只多一個 `source_identity`，其 exact keys 為 `kind`、`collection`、`artifact`、`source_manifest_sha256`。值分別為 `self-authored-synthetic`、`vettalon-self-authored-twins`、`benchmarks/blind-twins/anonymous/<同一 opaque id>.json` 及呼叫者核對過的 manifest 原始 bytes SHA-256；不接受 upstream repo／CVE／family／variant／split／label／oracle 等附加欄位。它表示自建合成來源歸屬，沒有恢復真正 upstream 身分；雜湊也不是來源真實性的認證，不能用來宣稱污染效果。

`scope_manifest` 使用既有 `fixed-subset-v1` 三欄格式（`schema`、`case_ids`、`source_sha256`）：可明確選全部 20 個 specimen，也可選既有固定五對十個 specimen。payloads 和 identity_bindings 必須剛好覆蓋所選 scope；函式不會補入其餘案例。配對結果分開保存：manifest 原始 bytes hash、沿用既有 `json.dumps(scope_manifest, sort_keys=True)` 的 scope 語意 hash，以及 JSON `sort_keys=true`／`ensure_ascii=false`／comma-colon separators／UTF-8 的兩種 payload hash；三種雜湊不可互換。

identity 是三種覆核 arms 之外的另一個維度；本模組只備妥資料，沒有新增排程或真模型呼叫。原匿名固定五對的三 arms × 五 repeats 上限仍為 250 calls／256000 output tokens；若未來完整重做兩種 identity views，會是 500 calls／512000 output tokens，必須另行決定預算，不能沿用原上限默默加跑。現有分母與歷史 raw 維持原版本。

### 只測純資料檢視

本輪 root 在 Python 3.14 實測新增 **9 項**及舊受影響 **4 項**通過，沒有模型／Docker／provider 執行；guard 語意 RED 用修正前模組得到 1 method、7 marker subtests 的預期失敗。另兩次舊測試載入失敗的 receipt 均保留，未算通過：第一次指定錯類別；第二次雖修正類別，舊 `test_protocol.py` 的 `unittest.main()` 位於該類別定義之前，直接執行仍無法載入。最後以 discovery 僅執行先前尚未跑到的 fixed-subset 方法並通過。

由 repo 根目錄使用以下篩選方式，只跑新模組九項或該一項既有資料測試；不執行整套 canonical／runner：

```bash
python3 -B -I -S benchmarks/blind-twins/test_identity_views.py -v
python3 -B -I -S -m unittest discover -s benchmarks/blind-twins -p test_protocol.py -k test_fixed_five_pairs_reproducible_and_hashbound -v
```

既有 237-source 公開快照不包含此新模組；本輪尚未更新公開匯出或重新封裝。

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
