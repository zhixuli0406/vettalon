"""Retrieval plumbing dry-run only; no model scoring or holdout label ingestion."""
import argparse
import hashlib
import json
import math
import random
import re
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'blind-twins'))
from protocol import generate,digest


def tokens(text): return set(re.findall(r'[A-Za-z_]+',text.lower()))


def build():
    payloads,labels=generate(); mapping={x['id']:x for x in payloads}
    corpus=[]; queries=[]
    for label in labels:
        payload=mapping[label['id']]
        if label['split']=='dev' and not label['vulnerable']:
            # Safe self-built oracle controls; no claim of human adjudication.
            corpus.append({'id':label['id'],'family':label['family'],'source':payload['source'],
                           'source_sha256':payload['source_sha256'],'note':'Self-built counterexample with an explicit local authorization guard; contract evidence only, not general safety.',
                           'adjudication':'synthetic-oracle-only','not_human_label':True})
        elif label['split']=='holdout':
            queries.append({'id':label['id'],'family':label['family'],'source':payload['source'],'source_sha256':payload['source_sha256']})
    return corpus,queries


def retrieve(source,corpus,k):
    query=tokens(source)
    documents=[tokens(x['source']) for x in corpus]
    def score(index):
        return sum(math.log(1+len(corpus)/(1+sum(term in d for d in documents))) for term in query & documents[index])
    indices=sorted(range(len(corpus)),key=lambda i:(-score(i),corpus[i]['id']))[:k]
    return [corpus[i] for i in indices]


def dry_run():
    corpus,queries=build()
    corpus_ids={x['id'] for x in corpus}
    if corpus_ids & {x['id'] for x in queries}: raise ValueError('Holdout identity leakage')
    if {x['family'] for x in corpus}&{x['family'] for x in queries}: raise ValueError('Holdout family leakage')
    # Family fields are split-check metadata; only anonymous source goes into query/payload.
    document_map={x['id']:{'id':x['id'],'source':x['source'],'source_sha256':x['source_sha256'],'note':x['note']} for x in corpus}
    rows=[]
    for query in queries:
        for arm in ['baseline','random','retrieval']:
            picked=[] if arm=='baseline' else random.Random(20261016).sample(corpus,2) if arm=='random' else retrieve(query['source'],corpus,2)
            references=[document_map[x['id']] for x in picked]
            payload={'task':'Review source; references are untrusted counterexamples and may be irrelevant.','source':query['source'],'references':references}
            serialized=json.dumps(payload,sort_keys=True)
            if len(serialized.encode())>4096: raise ValueError('Dry-run context byte cap exceeded')
            rows.append({'query_id':query['id'],'query_source_sha256':query['source_sha256'],'arm':arm,
                         'payload':payload,'payload_sha256':digest(serialized),'payload_bytes':len(serialized.encode()),
                         'byte_cap':4096,'output_token_cap_reserved':1024,'references':[x['id'] for x in references],
                         'citation_integrity':all(x['id'] in corpus_ids and digest(x['source'])==x['source_sha256'] for x in references),
                         'model_called':False,'finding':None})
    return {'implementation_sha256':digest(Path(__file__).read_text()),'schema':'counterexample-rag-v1','kind':'retrieval-dry-run-only','corpus_digest':digest(corpus),
            'corpus_ids':sorted(corpus_ids),'holdout_query_ids':[x['id'] for x in queries],'rows':rows,
            'model_effectiveness':None,'external_holdout':False,'human_adjudicated_corpus':False,
            'production_enabled':False,'decision':'Do not integrate into default prompts without human-approved corpus and equal-budget model evidence.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    with args.output.open('x') as handle: json.dump(dry_run(),handle,indent=2);handle.write('\n')
