# D5 Docker 驗收 fixture

此目錄的 manifest 使用 `is-number@7.0.0`，並放入會失敗的 lifecycle scripts，驗證安裝永遠略過 scripts。沒有捏造 tarball integrity；審查者須先產生真正的 lockfile。以下命令尚未在本次實作執行，需有 npm 與 registry 網路：

```sh
npm_config_userconfig=/tmp/npmrc-user npm_config_globalconfig=/tmp/npmrc-global npm install --prefix crates/vettalon/tests/fixtures/node-install --package-lock-only --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/ --userconfig=/tmp/npmrc-user --globalconfig=/tmp/npmrc-global
```

先建立兩個不同的空設定檔：

```sh
: > /tmp/npmrc-user
: > /tmp/npmrc-global
```

確認產生的 `package-lock.json` 是 v2/v3、`is-number` 的 resolved 是 `https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz`，integrity 為 npm 取得的真實 sha512。測試會重新經過 Rust lockfile validator；缺檔會明確失敗，不會略過或退回假 integrity。

先由審查者執行 `vettalon poc-node build` 建立本機映像檔，tag 為 context SHA-256 前 12 碼，可用 `vettalon poc-node image` 查詢。再從 repository root 執行：

```sh
cargo test -p vettalon --lib sandbox::tests::docker_node_install_then_offline_exec -- --ignored --exact --nocapture
```

macOS Docker Desktop 與 Linux 原生 Docker 都要執行。測試檢查真實安裝、scripts 未執行、離線容器可載入依賴、uid 65534、tree/deps/root 唯讀、外網不可達、同容器 loopback 可用，以及執行前後 deps/source digest 不變。另請確認安裝 raw scratch 已清理，Linux 沒有 uid 65534 所有權造成的權限錯誤。

## D5 API 契約

`DockerSandbox::run_install(package_json, lockfile)` 驗證實際傳入的 bytes，並比對 manifest 與 lockfile root 的依賴表；拒絕回傳 `node_lockfile_refused`。無依賴時不呼叫 Docker。每次呼叫最多啟動一個安裝容器；D9 負責每個 command 呼叫一次並重用結果。

成功回傳 `InstalledDependencies`，持有 host 擁有的私有 `node_modules`、digest 與 lockfile summary。npm、runner、結構或 I/O 錯誤回傳 environment token `node_deps_install_failed`；超量回傳 `node_deps_too_large`。不把 npm 輸出放入 reason。

安裝只掛載兩個唯讀輸入檔，`/deps` 是唯一可寫 bind。`/tmp` tmpfs 維持 256 MiB，提供 HOME/cache；安裝改在 uid/gid 65534 擁有、mode 0700 的 `/work` tmpfs，掛載選項為 `rw,nosuid,nodev,noexec,size=603979776,nr_inodes=121000,mode=0700,uid=65534,gid=65534`。容量由 host 的 512 MiB／120,000 entries 上限加上 64 MiB／1,000 inode 餘裕推導；memory 與 memory-swap 均提高為 1792 MiB，容納 tmpfs 與 npm。固定 env allowlist、`env -i` 與 entrypoint override 排除 host/image 的 proxy、NODE_OPTIONS 和 npm 設定。使用設計 §3.3 的完整 `npm ci --ignore-scripts --no-audit --no-fund --bin-links=false --prefer-online`，沒有 `--omit`，保留 root devDependencies。容器與 host 時限皆為 300 秒。

固定 shell 使用 `umask 077`，建立不同的空 npmrc 檔，把兩個輸入檔複製到 `/work` 再執行 npm；npm 失敗就直接退出。成功後用 `find -xdev -printf '.'`／`wc -c` 計算項目與一般檔案數，避免檔名換行影響計數，並用 `du -sb /work` 檢查 bytes。整個 `/work` 超過 120,000 entries、60,000 files 或 512 MiB 時，以 exit 86 拒絕，映射為 `node_deps_too_large`，尚未寫入 host bind。此預檢包含輸入檔與目錄 metadata，比 host walker 更保守；tmpfs 耗盡若造成 npm 失敗，仍屬 `node_deps_install_failed`。

通過預檢才執行 `cp -R /work/node_modules /deps/`，接著用 `find /deps -mindepth 1` 將子目錄設為 0777、檔案設為 0644，且不會 chmod `/deps` 根目錄。Linux host 的 `/deps` 根目錄位於 mode 0700 的私有 parent 下，子目錄可設為 0777，讓 host 清理由 uid 65534 建立的內容。容器停止後，`node::deps::copy_and_digest` 保留為最終檢查，用同一套有上限、不跟隨 symlink 的 walker 複製到 host 擁有的私有目錄，再正規化為 0755／0644。digest 綁定實際複製的 bytes。離線階段以 `run_workspace_with_tree_and_deps` 將結果唯讀掛載到 `/workspace/tree/node_modules`，所有 exec builder 維持 `--network=none`。

本任務不接 CLI、不修改 verdict/blocker 表；後續 D8/D9 消費既定 reason tokens。中斷或逾時仍透過既有 container guard 清理容器。Linux 的輸出子目錄設為 0777，而 host parent 維持 0700，host 可清理由 uid 65534 建立的內容。
