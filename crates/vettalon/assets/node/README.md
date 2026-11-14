# Node sink hook（D6）

這四個 CommonJS 資產供 D7 嵌入並複製到 `/workspace`，在執行 target 前以
`node --require /workspace/vtl_hook.cjs` 載入。只記錄不可信的 sink 診斷，不判斷 effect
或輸出 verdict；同程序的 target 可以偽造、修改或抑制事件。事件只能讓結果降級，
不能證明 sink 已執行、沒有副作用或修補有效，也不能把未知結果提升成可信結論。

從 repo 根目錄執行測試：

```sh
node --test assets/node/test/
```

`assets/node/test/package.json` 透過 `index.mjs` 載入同目錄的 hook 與 net hook 測試，讓此指令在 Node 24 可直接執行。
四個既有資產（`vtl_hook.cjs`、`vtl_shim_sqlite3.cjs`、`vtl_shim_pg.cjs`、
`vtl_shim_mysql2.cjs`）依設計 §2.2 放在 `crates/vettalon/assets/node/`。
SSRF 額外載入 `vtl_hook_net.cjs`，透過 `VTL_NET_EVENT_FD` 記錄不可信的網路 reach 診斷。

## D7 串接契約

- Runner 建立空白 regular file，分別開啟自己的讀取 fd 與 child 的
  `O_WRONLY | O_APPEND` fd，unlink 後才啟動 child。以 `VTL_EVENT_FD` 傳入
  root child 的 fd（至少 3）。舊的 `VTL_HOOK_ROOT` 已不具任何授權或退出碼語義。
  Hook 立即刪除 `VTL_EVENT_FD` 與 `VTL_HOOK_ROOT`，檢查 regular file、
  `nlink == 0` 與初始大小為 0。開啟模式由 runner 保證；Node 沒有內建
  `fcntl(F_GETFL)` 介面可讓 hook 再檢查。
- Instrumentation 僅安裝於第一次載入且有有效設定的主執行緒。缺少／無效 fd、
  channel 不合規或缺少 `module.registerHooks` 時進入 inert 模式；Worker 一律 inert，
  包含自行提供 env 的情況。首次 inert 載入不包裝 API、不註冊 loader hooks，
  hook 與直接載入的 shims 回傳空的 frozen object。
- `fork/spawn/execFile/exec` 與其同步版本會複製 options，清除 child env 的全部
  `VTL_*`，並從 `execArgv`、Node argv 與 `NODE_OPTIONS` 移除指向此 hook **確切路徑**
  的 `--require`／`-r` preload，保留其他 preload 與環境變數。預設繼承與明確傳入
  的設定都會處理，呼叫者的 options 不會被修改。任意 shell command 內容、
  路徑別名、native/internal API 或遭 target 替換的 wrappers 不屬於此清理邊界。
  後代沒有事件不能解讀為未到達 sink；此機制不提供程序內的可信根程序認證。
- `VTL_BASE` 是路徑範圍基準，預設 `/tmp/vtl_base`；`VTL_DB` 是 sqlite3 唯一
  使用的 fixture DB。這兩者在 preload 時擷取，target 改環境變數不會改設定。
- Adapter 在第一次載入 target **之前**，以 `createRequire(import.meta.url)`
  取得 `vtl_hook.cjs`，呼叫一次：

  ```js
  hook.configureTarget({
    target_url: pathToFileURL(targetPath).href,
    target_file_sha256: plan.target_file_sha256
  });
  const target = await import(pathToFileURL(targetPath).href);
  ```

  URL 必須是沒有 query/hash 的 file URL；hash 為 64 個小寫十六進位字元。
  設定不可重複，檔案路徑會 canonicalize，load hook 比對原始 bytes 的 SHA-256，
  並將同一份 bytes 交給 loader 執行。未呼叫此介面就不會有 target identity
  檢查；D7 必須確保呼叫順序，不能先 import 再設定。
- Active hook export 為 frozen、null-prototype object，只保留不寫事件的
  `configureTarget`，以維持上面的 adapter 契約。Hook 使用擷取的 `readFileSync`
  與 `vm.compileFunction` 私下執行 shim source，將 capability 當成函式參數傳入；
  writer、guard 與 capability 從未出現在任何 CommonJS export。
  Cache 只存 driver API；sqlite 引擎延至建立 Database 時載入。
- 第一次載入（包含 inert）會在 `process` 建立不可刪除、不可改寫、不可列舉的
  own property，值是私有 unique symbol，不使用 `Symbol.for`。刪除 `require.cache`
  後重新載入不會重新安裝 instrumentation，也無法重新設定 target；新 hook 僅 export
  一個必定 throw `node_hook_failed: hook already initialized` 的 `configureTarget`。
  Shim cache 遭清除後直接 require 也只取得 inert 空物件。
- Exit code：hook 不再呼叫 exit 70，也不修改程序的 exit code。設定錯誤採 inert；
  事件寫入、序列化失敗或超過上限則停止記錄，原始 API 仍執行。Runner 必須把缺少、
  不完整或格式錯誤的事件視為 `reach=unknown`，降級為 inconclusive，不能依程序
  exit 0 或已有部分事件推定成功。Identity 不符仍 throw
  `node_hook_failed: target identity mismatch`；未捕捉的例外依 Node 原生規則退出。

## 事件與限制

JSONL 每筆含 `v:1`、從 1 遞增的 `seq`、`class`（`CWE-78/22/89`）、`api`。
每筆（含換行）最多 4 KiB，最多 256 筆，總共最多 64 KiB。長字串／參數陣列
會截斷並標記 `truncated:true`。若下一筆將超過數量或總量上限，停止記錄，
不改 exit code。Runner 不可用局部 JSONL 或 exit 0 證明 reach 完整。
記錄使用 preload 時擷取的 primordials、null-prototype event 與固定欄位 serializer；
`JSON.stringify` 只處理原始字串。不呼叫 `toJSON`、自訂 inspect、accessor 或 Proxy
trap；複雜物件以 `[uninspected]` 代替並標記截斷。陣列僅讀取 own data properties。
輸出 Buffer 的長度使用 preload 時擷取的 TypedArray getter，僅讀一次；寫入迴圈與
總量計數使用同一個長度。只有完整寫出一筆後才增加 `seq` 與總量，污染 prototype
上的 `length` 不會造成零位元組寫入卻增加序號。寫入中途失敗則停止記錄，不重試。

- Process：`file`、`argv`、`shell`。`exec/execSync` 的 `file` 是 shell command；
  `execFile/execFileSync` 依真實 API 預設 `shell:false`，只有 options 開啟時才是
  shell 模式（設計表的「exec*」在此依實際語義解讀）。`fork` 記錄 Node
  executable、execArgv、module path 與參數。原函式與 custom promisifier 都攔截，
  複製 own property descriptors，包括 name、length 與 symbols；custom
  promisifier 本身另外包裝，以免原 closure 繞過紀錄。內部呼叫可能產生多筆事件。
- Path：`raw`、`path`、`inside_base`。字串、Buffer、file URL 做 lexical
  `path.resolve(cwd, arg)`，不把 symlink resolution 當作路徑正規化；數字 fd
  overload 的 path 是 null。基準比較包含目錄分隔符，避免同前綴 sibling 誤判。
  `raw` 將 Buffer 記為 UTF-8 字串、URL 記為 href，使用 preload 時擷取的轉換，
  不呼叫 target 的 getter／toString；這兩種支援的型別不會僅因是物件就標記截斷。
- SQL：`driver`、`query`、`params`、`executable`。sqlite3 開啟時另外記錄
  `filename`，只開 `$VTL_DB`；pg/mysql2 查詢永遠記錄 `executable:false`，再以
  `sql_dialect_not_executable` 拒絕，callback 與 Promise 形式皆支援。
  mysql2/promise 使用 loader 提供的虛擬 CJS 模組，不需第五個資產。
- 未知屬性回傳 `undefined`，允許 `if (db.optionalHook)` 特性偵測。只有下列明列、
  真實 driver 存在但 shim 未實作的方法會記錄 `api:"api_unsupported"`、`requested_api` 並 throw
  `node_driver_api_unsupported`。Shim 只提供明列的 API 子集，不宣稱與整個 npm
  driver 套件相容。

明列的 throwing stubs：

- pg Client：`cancel`。
- mysql2 Connection（含 promise facade）：`beginTransaction`、`commit`、`rollback`、`changeUser`、
  `ping`、`prepare`、`unprepare`。
- mysql2 module：`createPoolCluster`、`createServer`、`escape`、`escapeId`、`format`、`raw`。
- sqlite3 Database：`configure`、`loadExtension`、`interrupt`。

sqlite3 提供 Database `all/get/run/each/exec/prepare/close/serialize/parallelize`，
Statement `all/get/run/each/bind/reset/finalize`，以及 `verbose` 與基本 open 常數。
底層工作同步執行，callback 以 nextTick 通知；`run` callback 的 this 有 lastID、
changes。支援 positional array、variadic 與 named dictionary 參數；數字索引
dictionary 明確拒絕。Filename 與 open mode 不決定 fixture DB 的位置或權限；
不提供 native extension、driver tracing、完整排程或並行行為模擬。

Hook 阻擋常見 fs 讀取／關閉 event fd，以及 `/dev/fd/N`、`/proc/self/fd/N`
等直接路徑，也阻擋 stream 接收該 fd。這不是程序內安全邊界：target 仍可猜 fd
並寫入、使用 internal API、inspector 或修改 instrumentation。Runner 的 read fd、
marker、canary effect 檢查與最終 verdict 必須留在另一個受保護程序。

相對 `.js` import/require 僅在 JS 目錄項目的 `lstatSync` 回報 ENOENT／ENOTDIR
且同名 TS 是 regular file 時映射；任何既有項目（包含 dangling symlink）都不映射。
既有 `x.js/` 目錄保留原本的解析行為，例如 CJS 的 `x.js/index.js`。其餘 TypeScript
行為交給 Node 原生 stripping；不轉譯 enum、namespace、JSX/TSX 或 tsconfig aliases。
使用同步 loader hooks 與 `syncBuiltinESMExports`，沒有 `Module._load` fallback。

參考：[Node module hooks](https://nodejs.org/api/module.html)、
[node:sqlite](https://nodejs.org/api/sqlite.html)、
[child_process](https://nodejs.org/api/child_process.html)。固定 Node 26 image 的驗收
由 D1／reviewer 執行；本次本機測試版本為 Node v24.15.0。

## SSRF target-mode oracle

For Node CWE-918 targets, `vtl_hook_net.cjs` records `fetch`, `http.request`,
`http.get`, `https.request` and `https.get` reach events on `VTL_NET_EVENT_FD`.
These are untrusted diagnostics. The protected runner decides the effect from an
HTTP request line or TLS ClientHello at its own in-container loopback listener,
with external networking disabled. The benign control uses a recognized network
error from the adapter's bounded error/cause chain. Python SSRF targets and
scan-time SSRF oracles remain unsupported; SSRF `--emit-test` is refused.
