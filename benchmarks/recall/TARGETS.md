# vettalon 召回基準：已知 CVE 目標清單

> 用途：建立「召回已知 CVE」的回歸基準，驗證 vettalon 對原始碼層級漏洞的真召回率與真漏報率。
> 產生日期：2026-10-12。
> 驗證方式：**每一個目標都已實際 `git clone` 並 checkout 到「修補前」ref，直接讀過脆弱原始碼確認**；
> 每個 CVE/GHSA 編號與 commit SHA 皆經 NVD / GitHub Advisory / OSV 或 GitHub commit 頁面查核。
> 未經此流程查核者一律不列。各目標末尾附一手來源 URL。

---

## 0. 狀態聲明（誠實回報）

- 本清單 **9 個目標**，全部通過「clone → checkout 脆弱 ref → 肉眼確認脆弱碼」的活體驗證（COMPLETE）。
- **3 處需明確標註的例外/雜訊**，已在對應卡片中標紅：
  1. `node-serialize`：原 repo 已廢棄，**沒有上游修補 commit**。脆弱狀態＝HEAD，漏洞位置用「直接讀檔」確認而非 diff。因此這個目標沒有修補 commit 可填。
  2. `ollama`：OSV 把一個無關的 merge commit（`adeb40ea`）列為 patch。**真正修 `modelpath.go` 的是 `2a21363b`（PR #4175）**，已用 `git log -- server/modelpath.go` 親自確認。
  3. `ejs`：OSV 把 **v3.1.6 的版本號 bump commit（`80bf3d7`）** 當成「affected/patch」列出——那其實是脆弱版本的 release commit。**真正的修補是 `15ee698`**（新增 `_JS_IDENTIFIER` 驗證），已讀 diff 確認。好處是 `80bf3d7` 剛好可當作「精確的脆弱 commit SHA」。
- CVSS 來源若 NVD 與 GHSA 不一致（如 aiohttp），兩者皆列出。
- `systeminformation` 的 GHSA 標成 CWE-94，但本質是 OS command injection（CWE-78），兩者皆註明。

---

## 1. 總表

| # | 專案 | CVE / GHSA | 類型(CWE) | 語言 | 脆弱檔案 | 行數 | 難度 | 上游 patch |
|---|------|-----------|-----------|------|---------|------|------|-----------|
| 1 | node-serialize | CVE-2017-5941 | 不安全反序列化 / eval (CWE-502/94) | JS | `lib/serialize.js` | 110 | 教科書級 | ❌ 無（已廢棄） |
| 2 | pyLoad | CVE-2023-0297 / GHSA-pf38-5p22-x6h6 | 程式碼注入 (CWE-94) | Python | `clicknload_thread.py` + `misc.py` | 190 / 68 | 教科書級 | ✅ |
| 3 | PHPUnit | CVE-2017-9841 / GHSA-r7c9-c69m-rph8 | 程式碼注入 / eval (CWE-94) | PHP | `src/Util/PHP/eval-stdin.php` | **3** | 教科書級 | ✅ |
| 4 | postgraas_server | CVE-2018-25088 / GHSA-vghm-8cjp-hjw6 | SQL injection (CWE-89) | Python | `…/postgres_cluster_driver.py` | 77 | 教科書級 | ✅ |
| 5 | ejs | CVE-2022-29078 / GHSA-phwq-j96m-2c2q | 程式碼注入 / SSTI (CWE-94) | JS | `lib/ejs.js` | 939 | 較隱晦 | ✅ |
| 6 | aiohttp | CVE-2024-23334 / GHSA-5h86-8mv2-jq9f | 路徑穿越 (CWE-22) | Python | `aiohttp/web_urldispatcher.py` | 1222 | 較隱晦 | ✅ |
| 7 | systeminformation | CVE-2024-56334 / GHSA-cvv5-9h9w-qp2m | 命令注入 (CWE-78，GHSA 標 94) | JS | `lib/network.js` | 1783 | 較隱晦 | ✅ |
| 8 | ollama | CVE-2024-37032 / GHSA-8hqg-whrw-pv92 | 路徑穿越→任意寫檔 (CWE-22) | Go | `server/modelpath.go` | 164 | 較隱晦 | ✅ |
| 9 | sprockets | CVE-2018-3760 / GHSA-pr3h-jjhj-573x | 路徑穿越 / 檔案洩漏 (CWE-22) | Ruby | `lib/sprockets/server.rb` | 292 | 較隱晦 | ✅ |

類型涵蓋：反序列化、程式碼注入 ×3（含 eval）、SSTI、SQLi、命令注入、路徑穿越 ×3。
語言涵蓋：JS ×3、Python ×3、PHP ×1、Go ×1、Ruby ×1。
難度：教科書級 ×4（1–4）、較隱晦 ×5（5–9）。

---

## 2. 目標卡片

### 目標 1 — node-serialize（反序列化 / eval，教科書級）⚠ 無 patch

- Repo：https://github.com/luin/serialize
- CVE：CVE-2017-5941｜CVSS **9.8 Critical**｜CWE-502（不安全反序列化）＋ CWE-94
- 脆弱 git ref：`f9051f4104a3cd873f29b8815796e9f5d065c1a9`（master HEAD，npm `node-serialize@0.0.4`）
- 修補 commit：**無**（repo 廢棄，從未修補；snyk 標 "No fix"）
- 脆弱檔案：`lib/serialize.js`（共 110 行），`unserialize()` 內 **第 76 行**：
  ```js
  obj[key] = eval('(' + obj[key].substring(FUNCFLAG.length) + ')');
  ```
  任何帶 `_$$ND_FUNC$$_` 前綴的字串會被 `eval`。PoC：
  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('...')}()"}`
- 為何好測：單檔 110 行、`eval(user_input)` 一眼可見，找到＝真召回、找不到＝真漏報，零爭議。
- **納入注意**：因無 patch commit，不符需求 #3 的「修補前/後 SHA」欄位；脆弱位置以「讀檔」確認。若基準嚴格要求 patch diff，可改用目標 2/3（同為 eval 類）。
- 來源：NVD https://nvd.nist.gov/vuln/detail/CVE-2017-5941 ｜ snyk https://security.snyk.io/vuln/npm:node-serialize:20170208 ｜ exploit-db https://www.exploit-db.com/docs/41289

---

### 目標 2 — pyLoad（code injection / js2py pyimport，教科書級）

- Repo：https://github.com/pyload/pyload
- CVE：CVE-2023-0297｜GHSA-pf38-5p22-x6h6｜CVSS **9.8 Critical**｜CWE-94（程式碼注入）
- 脆弱 git ref：`6aa71cd99a6f510de7137d17ec99f930916704c0`（patch 的 parent）
- 修補 commit：`7d73ba7919e594d783b3411d7ddb87885aea782d`（"fix arbitrary python code execution by abusing js2py functionality"，改 `src/pyload/core/utils/misc.py`）｜修補版本 `0.5.0b3.dev31`
- 脆弱檔案（source→sink 皆小檔）：
  - 入口 `src/pyload/core/threads/clicknload_thread.py`（190 行），`addcrypted2()` **第 159 行**：
    ```python
    jk = eval_js(f"{jk} f()")   # jk 來自 self.get_post("jk")，未認證
    ```
    （port 9666 的 Click'N'Load 服務，未認證可打）
  - sink `src/pyload/core/utils/misc.py`（**68 行**），**第 25–27 行**：
    ```python
    def eval_js(script, es6=False):
        return (js2py.eval_js6 if es6 else js2py.eval_js)(script)
    ```
    js2py 預設允許 `pyimport`，故 `pyimport os; os.system(...)` 直接 RCE。patch 即在此關閉 pyimport。
- 為何好測：`eval_js(user_input)` 形態明顯；misc.py 只有 68 行，sink 極集中。pyimport 這一跳稍需 js2py 知識，故歸「教科書偏中」。
- 來源：GHSA https://github.com/pyload/pyload/security/advisories/GHSA-pf38-5p22-x6h6 ｜ NVD https://nvd.nist.gov/vuln/detail/CVE-2023-0297 ｜ patch https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d

---

### 目標 3 — PHPUnit（eval(php://input)，教科書級，最乾淨）

- Repo：https://github.com/sebastianbergmann/phpunit
- CVE：CVE-2017-9841｜GHSA-r7c9-c69m-rph8｜CVSS **9.8 Critical**｜CWE-94
- 脆弱 git ref：tag `5.6.2`（受影響：`0`–`4.8.27` 與 `5.0.0`–`5.6.2`）
- 修補 commit：`284a69fb88a2d0845d23f42974a583d8f59bf5a5`（"Correct fix for #1956"，把 `php://input` 改成 `php://stdin`）｜修補版本 `4.8.28` / `5.6.3`
- 脆弱檔案：`src/Util/PHP/eval-stdin.php`（**整檔 3 行**）：
  ```php
  <?php
  eval('?>' . file_get_contents('php://input'));
  ```
  若 `vendor/` 對外可存取，POST body 即為任意 PHP 碼 → RCE（cPanel、Laravel 等大規模被掃）。
- 為何好測：**全清單最乾淨的 recall 目標**——3 行、無任何旁枝、`eval(php://input)`。找不到＝鐵定漏報。
- 來源：NVD https://nvd.nist.gov/vuln/detail/CVE-2017-9841 ｜ OSV https://osv.dev/vulnerability/CVE-2017-9841 ｜ patch https://github.com/sebastianbergmann/phpunit/commit/284a69fb88a2d0845d23f42974a583d8f59bf5a5

---

### 目標 4 — postgraas_server（字串插值 SQLi，教科書級）

- Repo：https://github.com/blue-yonder/postgraas_server
- CVE：CVE-2018-25088｜GHSA-vghm-8cjp-hjw6｜CVSS **9.8 Critical**｜CWE-89（SQL injection）
- 脆弱 git ref：`bd4f1b88e7008a3abd4dbe05c26e7b20bbb99649`（creation-hardening patch 的 parent）
- 修補 commit：`7cd8d016edc74a78af0d81c948bfafbcc93c937c`（"Harden the database creation against SQL injections"，改用 psycopg2 `SQL()/Identifier()`）；刪除面另有 `ed2e895b0f8ad8716730b85fa5b471dabf3b0f18`，GHSA 另列 `f417b5bc898135444fc22b0786faa013faf53f17`｜修補版本 `2.0.0`
- 脆弱檔案：`postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py`（**77 行**），`create_postgres_db()`：
  ```python
  create_role     = "CREATE USER {db_username} WITH PASSWORD '{db_pwd}';".format(**connection_dict)
  create_database = "CREATE DATABASE {db_name} OWNER {db_username};".format(**connection_dict)
  cur.execute(create_role); cur.execute(create_database)
  ```
  `db_username` / `db_name` / `db_pwd` 來自 API 請求，直接 `.format()` 進 SQL。另 `check_db_or_user_exists()`、`delete_database()`、`delete_user()` 同樣用 `.format()` 拼接。
- 為何好測：77 行小檔、`.format()` 拼 SQL 後 `execute()` 是最典型 SQLi 形態，一眼可判。
- 來源：OSV https://osv.dev/vulnerability/CVE-2018-25088 ｜ GHSA https://github.com/advisories/GHSA-vghm-8cjp-hjw6 ｜ patch https://github.com/blue-yonder/postgraas_server/commit/7cd8d016edc74a78af0d81c948bfafbcc93c937c

---

### 目標 5 — ejs（SSTI / 程式碼注入，較隱晦 — 壓力測試）

- Repo：https://github.com/mde/ejs
- CVE：CVE-2022-29078｜GHSA-phwq-j96m-2c2q｜CVSS **9.8 Critical**｜CWE-94
- 脆弱 git ref：tag `v3.1.6`（＝ commit `80bf3d7dcc20dffa38686a58b4e0ba70d5cac8a1`，注意這是 3.1.6 的 release/版本號 commit，可直接當脆弱 SHA）
- 修補 commit：`15ee698583c98dadc456639d6245580d17a24baf`（新增 `_JS_IDENTIFIER = /^[a-zA-Z_$][0-9a-zA-Z_$]*$/` 驗證 `outputFunctionName` / `localsName` / `destructuredLocals`）｜修補版本 `3.1.7`
  - ⚠ OSV 把 `80bf3d7`（版本 bump）誤列為 patch；已讀 diff 確認真正修補是 `15ee698`。
- 脆弱檔案：`lib/ejs.js`（939 行，單檔模組；注入點集中）：
  - **第 589–590 行**（把選項直接拼進產生的 JS 原始碼）：
    ```js
    if (opts.outputFunctionName) {
      prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
    }
    ```
  - 第 608 行 `this.source = prepended + this.source + appended;`，最後第 663 行 `fn = new ctor(..., src)` 編譯執行。
  - 觸發需應用把 `settings['view options']` 之類外部物件併入 `opts`（Express 常見），把 `outputFunctionName` 塞成 OS 指令。
- 為何好測/歸類：注入點單行明顯，但「要理解 opts 來源可被污染」需跨層推理，且 `ejs.js` 939 行（超過 300 行理想值）。適合當**壓力測試**：驗 vettalon 能否在大單檔中定位汙染拼接。
- 來源：OSV https://osv.dev/vulnerability/CVE-2022-29078 ｜ GHSA https://github.com/advisories/GHSA-phwq-j96m-2c2q ｜ patch https://github.com/mde/ejs/commit/15ee698583c98dadc456639d6245580d17a24baf

---

### 目標 6 — aiohttp（follow_symlinks 路徑穿越，較隱晦 — 壓力測試）

- Repo：https://github.com/aio-libs/aiohttp
- CVE：CVE-2024-23334｜GHSA-5h86-8mv2-jq9f｜CVSS **7.5 High（NVD）/ 8.2 High（GHSA）**｜CWE-22
- 脆弱 git ref：tag `v3.9.1`（受影響 `>=1.0.5, <3.9.2`）
- 修補 commit：`1c335944d6a8b1298baf179b7c0b3069f10c514b`（"Validate static paths (#8079)"，改 `aiohttp/web_urldispatcher.py` 18 行）｜修補版本 `3.9.2`
- 脆弱檔案：`aiohttp/web_urldispatcher.py`（1222 行；函式集中），`StaticResource._handle()` **第 665–667 行**：
  ```python
  filepath = self._directory.joinpath(filename).resolve()
  if not self._follow_symlinks:
      filepath.relative_to(self._directory)   # 只有在 follow_symlinks=False 才檢查
  ```
  當應用設 `web.static("/static", "static/", follow_symlinks=True)` 時，`relative_to` 的邊界檢查被整段跳過 → `../../etc/passwd` 讀任意檔。
- 為何好測/歸類：漏洞＝「少了一個 else 分支的邊界檢查」，需理解 `resolve()` 行為與 `follow_symlinks` 語意，屬較隱晦；檔案 1222 行亦偏大。適合壓力測試。
- 來源：GHSA https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f ｜ OSV https://osv.dev/vulnerability/CVE-2024-23334 ｜ patch https://github.com/aio-libs/aiohttp/commit/1c335944d6a8b1298baf179b7c0b3069f10c514b

---

### 目標 7 — systeminformation（SSID 命令注入，較隱晦 — 壓力測試）

- Repo：https://github.com/sebhildebrandt/systeminformation
- CVE：CVE-2024-56334｜GHSA-cvv5-9h9w-qp2m｜CVSS **7.8 High**｜GHSA 標 CWE-94，實為 **OS command injection（CWE-78）**
- 脆弱 git ref：tag `v5.23.6`（受影響 `<5.23.7`）
- 修補 commit：`f7af0a67b78e7894335a6cad510566a25e06ae41`（改 `lib/network.js`，加 `util.sanitizeShellString()`）｜parent `51c7698b91789e00d2308c9f95249ca3bb27a176`｜修補版本 `5.23.7`
- 脆弱檔案：`lib/network.js`（1783 行；函式集中）：
  - `getWindowsWirelessIfaceSSID()`（第 347 行）用 `netsh wlan show interface` 取回 SSID（攻擊者可用惡意 SSID 之 AP 控制）。
  - `getWindowsIEEE8021x()` wireless 分支 **第 401–404 行**：
    ```js
    const SSID = getWindowsWirelessIfaceSSID(iface);
    i8021xState = execSync(`netsh wlan show profiles "${SSID}" | findstr "802.1X"`, util.execOptsWin);
    ```
    SSID 未淨化直接內插進 `execSync` 指令字串 → 跳脫雙引號即命令注入。
- 為何好測/歸類：`execSync(\`... ${SSID} ...\`)` 樣板字串內插是明確命令注入 sink；但觸發面是 Windows/netsh、且 `SSID` 為跨函式傳入，屬較隱晦；檔案 1783 行偏大。適合壓力測試。
- 來源：OSV https://osv.dev/vulnerability/CVE-2024-56334 ｜ NVD https://nvd.nist.gov/vuln/detail/CVE-2024-56334 ｜ patch https://github.com/sebhildebrandt/systeminformation/commit/f7af0a67b78e7894335a6cad510566a25e06ae41

---

### 目標 8 — ollama（digest 路徑穿越→任意寫檔，較隱晦）

- Repo：https://github.com/ollama/ollama
- CVE：CVE-2024-37032（Probllama）｜GHSA-8hqg-whrw-pv92｜CVSS **8.8 High**｜CWE-22（路徑穿越→任意寫檔→RCE）
- 脆弱 git ref：tag `v0.1.33`（受影響 `<0.1.34`）
- 修補 commit：**`2a21363bb756a7341d3d577f098583865bd7603f`**（"validate the format of the digest when getting the model path (#4175)"，確認改 `server/modelpath.go`）｜修補版本 `0.1.34`
  - ⚠ OSV 把 merge commit `adeb40eaf29039b8964425f69a9315f9f1694ba8` 列為 patch，但那改的是 `types/model/file.go`，與本漏洞無關；真正修 `modelpath.go` 的是 `2a21363b`（已用 `git log -- server/modelpath.go` 親自確認）。
- 脆弱檔案：`server/modelpath.go`（**164 行**），`GetBlobsPath(digest string)` **第 146–153 行**：
  ```go
  digest = strings.ReplaceAll(digest, ":", "-")
  path := filepath.Join(dir, "blobs", digest)   // digest 來自 /api/pull 的 OCI manifest，未驗證格式
  ```
  惡意 registry 回傳含 `../` 的 digest → 寫入 `/etc/ld.so.preload` 等任意路徑 → RCE。patch 就是在此函式加上 sha256 格式正則驗證。
- 為何好測/歸類：`filepath.Join(dir, untrusted)` 後接寫檔是明確路徑穿越 sink，且 patch 正是在同函式補驗證，位置極集中、單檔 164 行；惟「digest 可被污染」需跨檔語意，歸較隱晦偏中。
- 來源：GHSA https://github.com/ollama/ollama/security/advisories/GHSA-8hqg-whrw-pv92 ｜ OSV https://osv.dev/vulnerability/CVE-2024-37032 ｜ patch https://github.com/ollama/ollama/commit/2a21363bb756a7341d3d577f098583865bd7603f ｜ Wiz 分析 https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032

---

### 目標 9 — sprockets（denylist 繞過路徑穿越，較隱晦）

- Repo：https://github.com/rails/sprockets
- CVE：CVE-2018-3760｜GHSA-pr3h-jjhj-573x｜CVSS **7.5 High**｜CWE-22（路徑穿越 / 檔案洩漏）
- 脆弱 git ref：tag `v3.7.1`（受影響 `2.0.0`–`2.12.4`、`3.0.0`–`3.7.1`、`4.0.0.beta1`–`beta7`）
- 修補 commit（共 3 個，已確認存在）：
  - `18b8a7f07a50c245e9aee7854ecdbe606bbd8bb5`（"Do not respond to http requests asking for a `file://`"）
  - `9c34fa05900b968d74f08ccf40917848a7be9441`
  - `c09131cf5b2c479263939c8582e22b98ed616c5f`
  修補版本：`2.12.5` / `3.7.2` / `4.0.0.beta8`
- 脆弱檔案：`lib/sprockets/server.rb`（**292 行**）：
  - 第 33 行 `path = Rack::Utils.unescape(env['PATH_INFO'].to_s.sub(/^\//, ''))`
  - `forbidden_request?(path)` **第 113–118 行**：
    ```ruby
    def forbidden_request?(path)
      path.include?("..") || absolute_path?(path)   # denylist 未擋 file:// 等 URI scheme / 二次編碼
    end
    ```
  黑名單只擋 `..` 與絕對路徑，`file:///etc/passwd` 這類 URI scheme 可繞過 → 讀 app 根目錄外檔案。
- 為何好測/歸類：單檔 292 行（符合 <300 理想），denylist 缺漏型漏洞——需判斷「這個黑名單不完整」，比「有明顯 sink」更隱晦，是很好的壓力測試；三個 patch commit 清楚標出缺口。
- 來源：OSV https://osv.dev/vulnerability/CVE-2018-3760 ｜ GHSA https://github.com/advisories/GHSA-pr3h-jjhj-573x ｜ Debian DSA https://www.debian.org/security/dsa-4242 ｜ patch https://github.com/rails/sprockets/commit/18b8a7f07a50c245e9aee7854ecdbe606bbd8bb5

---

## 3. 一鍵重現（最小 clone）

每個目標用淺層 tag clone 即可拿到「脆弱狀態」，體積最小（原始碼多為數百 KB ~ 數 MB）：

```bash
# 可直接 checkout tag 者（最省）
git clone --depth 1 --branch v3.1.6  https://github.com/mde/ejs.git
git clone --depth 1 --branch v3.9.1  https://github.com/aio-libs/aiohttp.git
git clone --depth 1 --branch v5.23.6 https://github.com/sebhildebrandt/systeminformation.git
git clone --depth 1 --branch v0.1.33 https://github.com/ollama/ollama.git
git clone --depth 1 --branch v3.7.1  https://github.com/rails/sprockets.git
git clone --depth 1 --branch 5.6.2   https://github.com/sebastianbergmann/phpunit.git
git clone --depth 1 https://github.com/luin/serialize.git      # HEAD 即脆弱 (node-serialize)

# 需 checkout 特定 commit 者（用 blobless clone 再 checkout parent）
git clone --filter=blob:none https://github.com/pyload/pyload.git
#   → git checkout 6aa71cd99a6f510de7137d17ec99f930916704c0
git clone --filter=blob:none https://github.com/blue-yonder/postgraas_server.git
#   → git checkout bd4f1b88e7008a3abd4dbe05c26e7b20bbb99649
```

用修補 commit 確認「漏洞位置」：`git show <patch-sha> -- <脆弱檔>` 即可看到被改掉的脆弱行。

---

## 4. 選用建議

- **先跑教科書級（目標 1–4）** 確立「真召回」底線：PHPUnit（3 行 eval）、node-serialize（eval line 76）、postgraas（.format SQLi）、pyLoad（eval_js）。這些若漏報，代表 vettalon 連最明顯的 sink 都抓不到。
  - 需「修補前後 SHA」欄位完整 → 用 2/3/4；node-serialize（1）因無 patch，僅供「單檔 eval」能力檢測。
- **再跑較隱晦（目標 5–9）** 當壓力測試：ejs / aiohttp / systeminformation 在 900–1800 行大單檔中定位汙染拼接或缺漏檢查；sprockets / ollama 測「denylist 不完整」「digest 未驗證」這類需要語意推理的缺口。
- 每個目標都能用對應 patch commit 的 diff 當「標準答案」（ground truth 行號），方便自動比對 vettalon 命中與否。
