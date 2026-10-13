#!/usr/bin/env python3
"""Scan each sampled case and aggregate recall/FP for single-model vs cross-family.
Env: VETTALON_BIN, VETTALON_CONFIG, CASES_DIR, REPORT_DIR, VETTALON_HOME."""
import json, subprocess, os
BIN=os.environ["VETTALON_BIN"]; CFG=os.environ["VETTALON_CONFIG"]
CASES=os.environ.get("CASES_DIR","cases"); RD=os.environ.get("REPORT_DIR","reports")
os.makedirs(RD,exist_ok=True); sample=json.load(open("sample.json")); res=[]
for i,c in enumerate(sample):
    rep=f"{RD}/{c['id']}.json"
    if not os.path.exists(rep):
        subprocess.run([BIN,"scan",f"{CASES}/{c['id']}","--profile","deep","--config",CFG,
            "--max-modules","1","--report",rep,"--no-prior"],
            stdout=open(f"{RD}/{c['id']}.log","w"), stderr=subprocess.STDOUT)
    fndr=nh=False
    if os.path.exists(rep):
        for f in json.load(open(rep)).get("findings",[]):
            if f.get("source_engine")=="ai_audit" and c["expect_class"] in f.get("rule_id",""):
                fndr=True; nh = nh or f.get("status")=="needs_human"
    res.append(dict(c,finder_pos=fndr,crossfamily_pos=nh))
    print(f"[{i+1}/{len(sample)}] {c['id']} {c['cat']} real={c['real']} finder={fndr} needs_human={nh}")
json.dump(res,open("results.json","w"),indent=1)
tp=[x for x in res if x["real"]]; fp=[x for x in res if not x["real"]]; c=lambda it,k:sum(1 for x in it if x[k])
for lbl,k in [("single-model","finder_pos"),("cross-family","crossfamily_pos")]:
    print(f"{lbl:<14} recall={c(tp,k)}/{len(tp)} FP={c(fp,k)}/{len(fp)}")
