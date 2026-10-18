# Formal transport v1（離線工程準備）

這個獨立入口把 twins、context selection、counterexample RAG 接到同一個扣額及傳輸路徑，並提供可重算的只讀報告、逐階段覆核註記與成本附件。**正式 provider readiness 仍為 unknown／disabled，真 provider 呼叫為0**。本輪離線測試以實際執行結果為準；twins 的凍結分母現在由 canonical rows 重建，不能只憑檔案 SHA 與自述 eligible pairs 放大。

`transport_v1.py` 保存單 writer ledger、預扣額、固定 localhost HTTP worker 及 usage；`run_v1.py` 建資料與顯式執行入口；`report_v1.py` 只讀新版 formal-v1 和歷史 synthetic twins raw，formal 報告預設從 immutable attempt 重播 derived 欄位；`review_v1.py` 與 `cost_v1.py` 分別處理逐階段註記與估算。它不接管 recall／OWASP／ranking readers，也沒有改產品預設 prompt 或安全政策。

## 前置與離線用法

使用 Python 3.11+ stdlib；正式 process capture 限既有 POSIX helper 範圍，native Windows 未驗。source checkout 必須保有 frozen benchmark helpers 及 `scripts/runtime/{process_capture_v2.py,process_supervisor.py}`。Unit tests 自行建立 temporary synthetic source／manifest／subset 與 control-only denominator，eligible_pairs為空，沒有容器canonical成功或歷史模型證據主張，不依賴私有raw。production twins prepare 另外要求使用者已備妥真實本機 materialized sources與既有canonical／denominator，沒有fixture fallback；公開包存在不代表該前置已完成。本輪不安裝依賴、下載權重或啟動 server。

由 repo 根目錄使用下列離線入口。先前31項控制測試已有本機證據；新版完整 discovery 使用 `test_*.py`，包含 `test_report_integrity.py`。先前 root 曾以受控 driver 實跑87項；目前本機完整 discovery 為 **94 項／0 fail**，公開 CI 仍待執行。下列prepare／report為佔位用法；report CLI 先前另用 root 自建 fixture 驗證，不是這些使用者檔名的實驗。輸出parent須已存在，output必須是新路徑：

```bash
python3 -B -I -S -m unittest discover -s benchmarks/formal-transport -p 'test_*.py' -v
python3 -B -I -S benchmarks/formal-transport/run_v1.py prepare twins --output NEW_OWNED_PARENT/prepared.json
python3 -B -I -S benchmarks/formal-transport/run_v1.py prepare rag --output NEW_OWNED_PARENT/rag-prepared.json
python3 -B -I -S benchmarks/formal-transport/report_v1.py --raw EXISTING_SYNTHETIC_TWINS_RAW.json --output NEW_OWNED_PARENT/recomputed.json
```

twins 與 RAG prepare 只處理本機資料；context prepare 另以固定可信 Python worker 做有界 AST 選段，不執行 target source。context 必須明確指定 `--source`，輸出不得在來源內；預設 baseline/functions/callchain 共三模式，40 module cap、原始 range/hash、未納入／parser／read／unknown 等紀錄保留。它們不是整庫 ground truth 或模型成效。

## 只讀報告、逐階段註記與成本

Formal 報告的預設路徑會核對 raw／prepared／plan、attempt artifact 的原始SHA與內容，再從原始回覆重算 `parsed`、finder candidate、detected、surfaced、root cause 與 verifier parent；手改 derived 欄位會被拒絕。缺 stage／parse failure／budget exhaustion 保留 incomplete 與分母；此formal入口不接受raw自行宣稱human adjudication或differential success；這些欄位維持U／not-measured，逐階段陳述另走overlay。Producer保存來源實作bindings與stage exception，並不把中斷偽裝complete。

Formal-v1 的 twins／context／RAG 報告另以 `resource_summary` 顯示 raw 已記錄的 runner CPU interval、lifetime RSS 與 `wall_seconds`；共用既有 measurement 驗證器，核對記錄中的 implementation binding、CPU 合計與 RSS 單位／順序，不重新取樣。缺失或 null 維持 unknown；wall 僅接受有限、非負的 int／float（不含 bool），壞值會拒絕整份報告。資源範圍僅 runner process；RSS 為整個 process lifetime high-water mark，`peak_memory_bytes` 仍 null，不能當每 run peak。模型 server、child process、GPU、電力、USD 與人工成本不在此量測內；不改 metrics、成效、cost 附件或 provider readiness，legacy 分支維持原契約。自建資料的回歸契約見 [resource report tests](test_resource_report.py)；離線 fixture 不代表真模型實耗。

`--worksheet` 產生 finder／verifier 各階段的候選與 U 初值。填新 overlay 時，須帶同一份 raw SHA、worksheet SHA、case fingerprint、stage、attempt SHA與parent parsed SHA；只有實際解析到的stage可註記，未執行／失敗stage不能取得判定。TP／FP只適用正向finding claim，負向回覆保留U。分類限 `U/code-safe/deployment-unknown/missing-path/unsupported/candidate-survives`。`reviewer`、reason與分類都是提供者的陳述，**不改原raw、metrics、finding狀態或認證人類身分**。

```bash
python3 -B -I -S benchmarks/formal-transport/report_v1.py --raw FORMAL_RAW.json --denominator DENOMINATOR.json --worksheet --output NEW_OWNED_PARENT/worksheet-report.json
python3 -B -I -S benchmarks/formal-transport/report_v1.py --raw FORMAL_RAW.json --denominator DENOMINATOR.json --review-overlay REVIEW_OVERLAY.json --output NEW_OWNED_PARENT/reviewed-report.json
python3 -B -I -S benchmarks/formal-transport/report_v1.py --raw FORMAL_RAW.json --denominator DENOMINATOR.json --cost-attachment COST_ATTACHMENT.json --output NEW_OWNED_PARENT/cost-report.json
```

以上是佔位用法；`--worksheet`／`--review-overlay`僅支援twins，context／RAG可用預設derived重播與cost，不支援worksheet。twins的denominator須對應既有baseline，context／RAG不使用twins分母。Worksheet在輸出報告的 `review_worksheet` 欄；overlay schema為 `formal-stage-review-overlay-v1`，頂層為 `schema/raw_sha256/worksheet_sha256/reviewer/decisions`。每個decision有 `id/fingerprint/stage/attempt_sha256/parent_parsed_sha256/adjudication/classification/reason`；未填stage仍U。每次以未改的raw建立worksheet並綁定新附件，勿把套過overlay的結果當另一份原worksheet。報告另保存overlay原檔bytes SHA，與worksheet內的canonical JSON fingerprint分開。

成本附件schema為 `cost-attachment-v1`，頂層為 `schema/raw_sha256/prices/entries`。Price列精確包含 `price_id/model/price_version/source_ref/provided_by/input_usd_per_million/output_usd_per_million`；entry列為 `attempt_key/model/attempt_artifact_sha256/price_id/price_version/human_minutes/human_source_ref/human_version/human_provided_by`。三處model皆用同一份declared roster的 `{name,digest,family}`，id/version與attempt artifact必須匹配；未知／重複id及錯綁會拒收。未選price時id/version同為null；minutes為null時三個human來源欄同為null，有值時皆須非空。來源與提供者是operator聲明，無下載查價、invoice、billing或serving-model認證。

Rates與minutes只收非負decimal字串，最多12位整數及12位小數；如 `"2"`、`"0.125"` 是synthetic格式示例，不是真單價。USD只由完整observed input/output tokens與宣告版價計算，採精確整數scaled arithmetic，不用reservation、bytes或wall估算。缺附件或任一attempt資料不全時，完整USD／minutes為null，另列known subtotal及unknown attempts；空inventory也不推零費用。人時只代表operator明確分配到recorded artifact-bound attempts的reported effort，排除未嘗試rows及全專案完整人時；不從模型時間推算。

新版formal檔案reader限POSIX逐段不跟隨symlink的regular file開啟；拒絕symlink ancestor、FIFO、超限、strict JSON錯誤及前後內容變動。Raw最多16MiB，單attempt4MiB、合計16MiB／最多40件，overlay／cost／twins denominator各2MiB；這些是reader admission，非provider預算或任意OS資源保證。附件與artifact的actual bytes SHA由reader核對，純cost函式不自行開檔。歷史synthetic-twins raw維持原只讀分支，**不接受新版worksheet／review／cost附件**，不替舊資料補造來源。

## 正式呼叫目前會拒絕

`execute` 需要 prepared artifact、明確 model/digest/family 宣告及 owned output name。production registry 沒有已核對的 exact installed provider/model 控制，所以目前在建立 ledger／扣額／worker／HTTP 之前拒絕；沒有 `--allow-unknown`、fake adapter 或 capability=true 開關。Grok CLI 的已知控制仍 unknown，本模組不啟動 Grok、metadata、登入、quota、profile 或另一個前導。

twins 三個 arm 必須提供同一份固定 roster：`finder`、`samefamily_verifier`、`crossfamily_verifier`；每個 role 都有明確 name/digest/family。三 arm 的 batch plan 完全相同，只在 run 選用對應 role，累計同一個250額帳。readiness 證據也須匹配該 role 的 model name＋digest；另一個模型的控制證據不能移用。

真正的 HTTP code path 已備妥：固定 `127.0.0.1:11434`、一次 POST `/api/chat`、`stream=false`、JSON body、`num_predict=1024`、無 redirect／application retry／metadata request。它是候選 adapter，不是把使用者 D01 已選的 AGY 3.1 Pro／Grok 自動改用 Ollama／Qwen。離線測試用 fake connection 走這段 actual request builder 與三種 view 的 shared dispatch，不把 fake JSON 報告當真 provider 活驗。

Root 於 2026-10-17 讀取的官方資料：[Chat API](https://docs.ollama.com/api/chat) 說明 POST／options、stream 預設 true 及 eval_count／prompt_eval_count；[Modelfile 參數](https://docs.ollama.com/modelfile) 說明 num_predict 是生成 token 上限、預設 -1 表示無限。這些是 API 語意的起點，**沒有證明目前安裝的 server/model 確實套用1024上限**，不會因此啟用 readiness。

## 扣額、token 與失敗紀錄

- requested、client-enforced、provider-control evidence、observed 分列。wire 帶 num_predict 不等 effective cap；provider-reported tokens 也不是獨立帳單或來源真實性認證。
- Canonical purpose ledger 與 output 分開。twins 固定 `d01-anonymous-fixed-five-pair-v1`，仍為250 client-visible inference requests／每次最多1024 output／總 reservation最多256000、單工、0 retry、90秒／request、1200秒／run。換 output／entry 不能重設額度；context／RAG 不偷用 D01 名額。
- 每 attempt 先 exclusive 寫 started，依序 file flush/fsync、parent directory fsync，再進 worker；初建 ledger／debits／owner 同理。同步失敗不 dispatch，保留已寫資料。worker 再核 request／started／purpose／model 綁定，以 file＋directory fsync 保存 exclusive dispatch-entry 才發 HTTP；同 slot 重播不得再發。
- timeout／cancel／parse／capture／cleanup／保存錯誤不退1024 reservation、不補跑；ambiguous 或控制異常停止後續，留下 owner／halted 狀態供 root 稽核，不自動清鎖恢復。這是合作式單 controller 協定，不保證抵抗惡意檔案回滾或任意外部 sender。
- 保留 debit、worker invocation、client request-entry 與 provider received 的不同分母。entry 存在不代表 bytes 已達 server；沒有回應時 tokens／server 收到幾次為 null，不能補零。helper timeout 也不保證上游生成停止、任意 setsid containment 或整 batch 的 OS 硬牆鐘。
- 每次 execution 最多 min(90,run remaining) 秒，既有 helper cleanup 另最多1秒；raw response 1MiB＋檢查byte，worker stdout4MiB／stderr128KiB。截斷／decode／control incomplete／cleanup error都不能成 complete；原始 bytes／base64、receipt、prompt／candidate／refute parent SHA 與失敗 rows 保留。
- observed input/output tokens 只取實際 response，缺失為 unknown；已知小計與 unknown attempts 分列。reservation 不作實耗；未提供附件的USD／人時，以及未測的模型server／GPU／電力為null。選填成本附件的估算與unknown另見上節；runner CPU interval 與 lifetime RSS 不冒每 run peak。
- equal-input-token context／RAG 比較需要對應 model 的可信 tokenizer 或可驗控制；目前沒有就拒絕 formal，不能以 bytes／字元比例／num_ctx 或事後 input count 替代。具體 input cap 也不在此擅定。

## 資料與驗證界線

twins 預設匿名且維持固定五對十 specimens／三 arms／repeat0–4；labels 留本機。identified 只支援 **prepare**：呼叫端實讀 materialized source 與 manifest 後建立自建合成來源歸屬，不代表真 upstream 身分、provenance 認證或污染效果，也沒有第二 identity 的執行預算。既有 Grok B pilot 仍是已停止的1扣額／4未嘗試／0 replacement，不由此重設或補跑。

context 在同 snapshot 上先建完三模式並核來源，再允許 dispatch；reply path／原始行號須映回實際 selected ranges。RAG 的 baseline/random/retrieval 使用匿名 query 與現有 dev references，split／family／label不進 prompt；原 corpus 仍 synthetic-oracle-only、非 human，external_holdout仍false。兩者缺 accepted ground truth／真人定案時，raw findings不能變成recall、每美元收益或RAG效果。

先前31項離線GREEN涵蓋fsync、無退款／重試、worker replay/body binding、fake HTTP builder與三view等底座；三arm合計50個fake requests／50筆shared debits／51200 reservation只驗帳本編排。其舊v2 RED為3項語意回歸與1項新roster介面錯誤，保原版本。本輪新default reader另有6項測試中的5項mutable-field語意RED，原件保留；本輪87項GREEN不與先前31項或重跑次數相加。首輪86 pass／1 fail為scope文字大小寫斷言，僅改casefold後在新job重驗87／87；原失敗保留。真provider controls、效果、帳單、原生Windows與人類定案仍未驗。

本輪root另以自建資料走三次report CLI入口：baseline與附註記各exit0；tampered輸入exit1且不產output，符合預期拒收。14份source copies與6份輸入前後SHA不變，兩份有效報告的metrics一致。Synthetic成本附件的known USD subtotal為`0.000028`、人時subtotal為`2.5`，兩者各有1個unknown attempt，完整總額皆null、billing_verified=false；這是reader整合活驗，非使用者模型實驗、真人判讀或帳單。

新來源的stage交付需另以對應manifest與測試收據核對；251為歷史包，不代表本次來源已發行。本輪沒有新Rust編譯或新模型呼叫。

## License

依專案根目錄 [LICENSE](../../LICENSE)。
