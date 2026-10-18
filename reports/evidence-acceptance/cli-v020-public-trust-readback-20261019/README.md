# CLI v0.2.0 公開信任證據重驗

觀測日期：2026-10-19（台北；UTC 時間見 [`receipt.json`](receipt.json)）。範圍僅限
[公開 CLI v0.2.0 release](https://github.com/zhixuli0406/vettalon/releases/tag/v0.2.0)。
這是從公開發布頁重新下載與驗證的紀錄，與 2026-10-18 的內部留存紀錄分開。

| 檢查 | 本次結果 | 界線 |
| --- | --- | --- |
| Tag/source | `v0.2.0` 指向 `e3493f620487d23dbbd6a13021c216f415974585`；前後讀回一致 | GitHub 上的 tag 仍可由有權限者日後變更；本次是有時間戳的快照 |
| 發布資產 | 4 個 archive、24 個必要 sidecar；28/28 下載位元組與 GitHub asset SHA-256 相符；tag 名、發表時間、draft/prerelease 狀態及資產清單前後一致 | 單獨 checksum/metadata 不代表簽署者身分 |
| 本機結構 | 4/4 `verify-assets` 通過：sidecar、checksum、檔名/target、CycloneDX 1.6 schema、SBOM/record 綁定 | build record 自身未簽署；SBOM 是 source-lock 庫存，非連結或可達性證明 |
| 發布身分與來源 | 4/4 現行 `verify-release.sh` 回傳 0；每次都要求 Cosign 的精確 workflow/tag 身分與 GitHub OIDC issuer，以及 archive、BOM 各 1 次 GitHub attestation 驗證，總共 4 次 Cosign、8 個 attestation subject | 此紀錄只保存通過狀態與驗證器 SHA-256，未保存原始 CLI 輸出；獨立讀者應重跑命令 |
| 反例 | 複製一份真實 Linux x64 資產與 sidecar、只改 archive 1 位元組；本機驗證器拒絕（exit 1） | 這是 digest/sidecar 拒絕測試，未另測所有錯誤身分、issuer 與撤銷情境 |
| minisign | 28 個資產中無 `.minisig` | 此格式在 release workflow 為可選；不以「未提供」推論簽章失敗，也不宣稱 minisign 驗證通過 |

執行環境為 macOS arm64、Python 3.14.7、GitHub CLI 2.99.0、Cosign
3.1.3。執行時將本 worktree 的 `verify-release.sh`、`trust.py`、`cargo_graph.py`
與三份實際載入的 CycloneDX schema，以 no-follow 有界讀取複製成私有的
**驗證器原始碼與 schema 快照**；各檔雜湊與大小列於收據，檔案設為唯讀，
並在每個封存檔驗證前後重新核對。
入口腳本 SHA-256 為
`ff10865118c39a67b7d77a46e02207d6742cf25025c78fc695262ea1dd8922d8`。
這降低正常工作樹漂移風險，**不保證**抵禦同一使用者在兩次核對間蓄意改動暫存檔。
GitHub CLI、Cosign 與 Python 的版本只在本文記錄；Bash、Curl、Python 套件及
上述執行工具的安裝位元組沒有在收據中以雜湊釘住，快照不涵蓋整個執行環境。
它是目前版本的驗證器，**不是**聲稱 v0.2.0 發版當時執行的驗證器。該腳本先做本機結構檢查，
再依序執行 `cosign verify-blob`、兩次 `gh attestation verify`；任一步失敗會以非零結束。
完整資產雜湊、各項回傳碼及程式入口見 [`receipt.json`](receipt.json)、[`readback.py`](readback.py)。
公開 JSON 不含憑證、Token、本機暫存路徑或原始 attestation 輸出，也沒有自身的獨立簽章。
先前的內部候選版曾缺少內層原始碼快照、私有排他收據與總執行時限；其中一次還把
schema 目錄的說明檔誤判為依賴，並以 `incomplete` 結束。正式 `receipt.json`
已採用修正後的流程；舊候選收據不隨公開證據匯出。

重新執行：

```bash
VETTALON_READBACK_DIR=$(mktemp -d)
python3 -m venv "$VETTALON_READBACK_DIR/venv"
"$VETTALON_READBACK_DIR/venv/bin/python" -m pip install -r scripts/trust/requirements.txt
python3 -B reports/evidence-acceptance/cli-v020-public-trust-readback-20261019/readback.py \
  --output "$VETTALON_READBACK_DIR/receipt.json" \
  --verifier scripts/trust/verify-release.sh \
  --python "$VETTALON_READBACK_DIR/venv/bin/python"
```

腳本以目前公開 GitHub release 的 metadata 先限制 28 個資產、每檔 8 MiB、總量 32 MiB，
每檔下載最長 45 秒、整輪最長 300 秒；下載完以串流逐檔核對大小與 SHA-256。
收據路徑必須是不存在的檔案，父目錄必須由目前使用者擁有、是實體 0700 目錄；
程式以排他建立 0600 檔案，拒絕已存在的檔案與符號連結。
GitHub、Curl 與驗證器程序只繼承必要環境變數，排除 `BASH_ENV`、`ENV`、
`PYTHONPATH`、`PYTHONSTARTUP` 等可改變執行行為的變數；認證值只供子程序使用，
不寫入公開收據。下載暫存目錄只保存於執行期間。
腳本結束碼 0 代表上述完整流程通過，其他值代表不完整或失敗，不能當成發版驗收通過。

仍未驗證：CLI binary 的實際安裝與執行、所有平台行為、完整授權相容性、
依賴實際連結/可達性、現行 private worktree、Desktop/Pro 發版或付費匯出。
桌面版資產與簽章走獨立流程，不可從這份 CLI 證據外推。
