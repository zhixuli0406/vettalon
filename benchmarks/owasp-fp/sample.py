#!/usr/bin/env python3
"""Stratified sample from OWASP BenchmarkJava: N TP + N FP per category.
Env: BENCH_DIR (BenchmarkJava checkout), OUT_DIR (stage), N (default 20)."""
import csv, os, shutil, json, collections
B=os.environ.get("BENCH_DIR","BenchmarkJava"); OUT=os.environ.get("OUT_DIR","cases"); N=int(os.environ.get("N","20"))
cats={"sqli":"sql-injection","cmdi":"command-injection","pathtraver":"path-traversal","xss":"xss"}
rows=[r for r in csv.reader(open(f"{B}/expectedresults-1.2.csv")) if len(r)>=4 and not r[0].startswith("#")]
cnt=collections.Counter(); sample=[]
for name,cat,real,cwe,*_ in rows:
    cat,real=cat.strip(),real.strip()
    if cat not in cats or cnt[(cat,real)]>=N: continue
    cnt[(cat,real)]+=1
    sample.append({"id":name,"cat":cat,"real":real=="true","cwe":cwe.strip(),"expect_class":cats[cat]})
shutil.rmtree(OUT,ignore_errors=True); os.makedirs(OUT)
for c in sample:
    os.makedirs(f"{OUT}/{c['id']}")
    shutil.copy(f"{B}/src/main/java/org/owasp/benchmark/testcode/{c['id']}.java", f"{OUT}/{c['id']}")
json.dump(sample, open("sample.json","w"), indent=1)
print(f"sampled {len(sample)}: {dict(cnt)}")
