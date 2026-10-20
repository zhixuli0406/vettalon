# Security policy

## Reporting a vulnerability in vettalon

Please report vulnerabilities in vettalon itself through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**, or go straight to
<https://github.com/zhixuli0406/vettalon/security/advisories/new>. Do not open
a public issue for a security bug.

If you cannot use GitHub, email <info@dudustudio.monster>. The same contacts
are published in
<https://vettalon.dudustudio.monster/.well-known/security.txt>.

Useful things to include: the vettalon version (`vettalon --version`), the
command you ran, the model backends in your roster (no keys), and the
smallest input that reproduces the problem.

You should get a first reply within 7 days. We aim to ship a fix within 90
days and will agree on a disclosure date with you.

## What counts

In scope: anything that makes vettalon itself unsafe to run on your code,
for example escaping the model or PoC sandbox, reading files outside the
scanned repository, leaking secrets or API keys into reports or model
prompts, or a scanned repository being able to make vettalon execute code.

Out of scope: vulnerabilities that vettalon reports in *other* projects.
Send those to that project's maintainers (`vettalon disclose` drafts a
report in the format their channel expects; it never sends anything).
