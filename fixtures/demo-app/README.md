# demo-app (deliberately vulnerable test fixture)

Not for deployment. Used by vettalon's end-to-end check. Ground truth:

| File | Line | Class |
|---|---|---|
| api/users.py | 13 | SQL injection (string-built query) |
| files/download.py | 11–12 | path traversal (unsanitized join → send_file) |
| util/slug.py | — | none (control module, should produce no finding) |
