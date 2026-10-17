"""Opt-in, bounded Python AST context-selection prototype, not a taint analyzer."""
import argparse
import ast
import hashlib
import json
import time
from pathlib import Path

SINKS={'read_text','read_bytes','execute','executemany','eval','exec','open'}
KNOWN={'Path','str','int','len','print','resolve','is_relative_to','ValueError','PermissionError'}

def sha(text): return hashlib.sha256(text.encode()).hexdigest()

def select(root,mode='baseline',max_modules=40,byte_budget=16384,time_budget=2.0,depth=3):
    if mode not in ['baseline','functions','callchain']: raise ValueError('Unknown selection mode')
    if not 1<=byte_budget<=1048576 or not 0<time_budget<=10 or not 0<=depth<=5: raise ValueError('Budget outside prototype caps')
    root=Path(root).resolve()
    if not root.is_dir(): raise ValueError('Fixture root must be a directory')
    start=time.monotonic()
    cap=min(max_modules,40) if max_modules>0 else 40
    # Traverse only user-selected fixture roots. Never follow directory symlinks.
    paths=[]
    enumerated=0
    for path in root.rglob('*.py'):
        enumerated+=1
        if enumerated>4096 or time.monotonic()-start>time_budget: break
        paths.append(path)
    paths.sort()
    omitted=[str(x.relative_to(root)) for x in paths[cap:]]
    modules={}
    functions={}
    unknown=[]
    for path in paths[:cap]:
        rel=str(path.relative_to(root))
        module=rel[:-3].replace('/','.')
        row={'path':rel,'ranges':[],'status':'pending','selected_bytes':0}
        modules[module]=row
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p!=root and root in p.parents):
            row['status']='symlink_skipped'; continue
        if time.monotonic()-start>time_budget:
            row['status']='time_budget'; continue
        try:
            with path.open('rb') as handle: raw=handle.read(65537)
            if len(raw)>65536:
                row['status']='oversize'; continue
            source=raw.decode('utf-8')
            row.update(source_sha256=sha(source),source=source,line_count=len(source.splitlines()))
            tree=ast.parse(source)
            row['tree']=tree
        except (SyntaxError,UnicodeDecodeError):
            row['status']='parser_fallback'; continue
        except OSError:
            row['status']='read_failure'; continue
        imports={}
        for node in tree.body:
            if isinstance(node,ast.ImportFrom) and node.module:
                for alias in node.names: imports[alias.asname or alias.name]=node.module+'.'+alias.name
        local={node.name for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
        for node in tree.body:
            if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
            key=module+'.'+node.name
            calls=[]; sink=False; unresolved=False
            for sub in ast.walk(node):
                if not isinstance(sub,ast.Call): continue
                name=sub.func.id if isinstance(sub.func,ast.Name) else sub.func.attr if isinstance(sub.func,ast.Attribute) else ''
                sink=sink or name in SINKS
                if name in imports: calls.append(imports[name])
                elif name in local: calls.append(module+'.'+name)
                elif name not in SINKS|KNOWN: unresolved=True
            functions[key]={'module':module,'node':node,'calls':calls,'sink':sink,'unresolved':unresolved}
            if unresolved: unknown.append(key)
        row['status']='parsed'
    chosen=set(functions)
    edges=sorted([key,target] for key,f in functions.items() for target in f['calls'] if target in functions)
    if mode=='callchain':
        chosen={k for k,f in functions.items() if f['sink'] or f['unresolved']}
        for _ in range(depth):
            chosen |= {caller for caller,target in edges if target in chosen}
        # Unrecognized libraries and unknown sink names preserve function context.
        chosen |= {k for k,f in functions.items() if not f['calls'] and not f['sink']}
    remaining=byte_budget
    output=[]
    selected_functions=[]
    for module,row in modules.items():
        source=row.get('source',''); lines=source.splitlines(keepends=True)
        intervals=[]
        if mode=='baseline' or row['status']=='parser_fallback':
            intervals=[(1,len(lines),'baseline' if mode=='baseline' else 'parser_fallback',None)] if lines else []
        elif row['status']=='parsed':
            for node in row['tree'].body:
                if isinstance(node,(ast.Import,ast.ImportFrom)):
                    intervals.append((node.lineno,node.end_lineno,'imports',None))
            for key,f in functions.items():
                if f['module']==module and key in chosen:
                    node=f['node']
                    intervals.append((node.lineno,node.end_lineno,'function',key))
        for low,high,reason,key in sorted(intervals):
            text=''.join(lines[low-1:high])
            encoded=text.encode()
            if not remaining: break
            clipped=encoded[:remaining].decode('utf-8',errors='ignore')
            if not clipped: continue
            size=len(clipped.encode()); remaining-=size
            row['ranges'].append({'start_line':low,'end_line':low+len(clipped.splitlines())-1,
                                  'sha256':sha(clipped),'text':clipped,'reason':reason,'truncated':size<len(encoded)})
            row['selected_bytes']+=size
            if key and size==len(encoded): selected_functions.append(key)
        if row['status']=='parsed':
            row['status']='selected' if row['ranges'] else 'byte_budget'
        if any(r['truncated'] for r in row['ranges']): row['status']='truncated'
        row.pop('source',None); row.pop('tree',None)
        output.append(row)
    omitted_functions=sorted(set(functions)-set(selected_functions)) if mode!='baseline' else []
    incompleteness=bool(omitted_functions) or not paths or bool(omitted) or enumerated>4096 or time.monotonic()-start>time_budget or any(x['status'] not in ['selected'] for x in output)
    return {'schema':'context-selection-v1','mode':mode,'module_cap':cap,'byte_budget':byte_budget,'time_budget_seconds':time_budget,
            'depth_cap':depth,'wall_seconds':time.monotonic()-start,'selected_bytes':byte_budget-remaining,
            'files':output,'selected_functions':sorted(selected_functions),'edges':edges,'unknown_calls':sorted(unknown),
            'omitted_modules':omitted,'omitted_functions':[{'function':key,'reason':'depth_or_byte_budget'} for key in omitted_functions],'incomplete':incompleteness,
            'limitation':'Syntactic function/call coverage only; no interprocedural taint proof, dependency resolution, or vulnerability verdict.'}

def write_result(root,mode,output):
    if output.exists(): raise FileExistsError('Preserve existing context-selection output')
    result=select(root,mode)
    with output.open('x') as handle: json.dump(result,handle,indent=2);handle.write('\n')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('root',type=Path)
    parser.add_argument('--mode',choices=['baseline','functions','callchain'],default='baseline')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    write_result(args.root,args.mode,args.output)
