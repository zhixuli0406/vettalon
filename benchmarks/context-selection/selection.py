"""Opt-in, bounded Python AST context-selection prototype, not a taint analyzer."""
import argparse
import ast
import hashlib
import json
import os
import re
import stat as file_stat
import time
from pathlib import Path

SINKS={'read_text','read_bytes','execute','executemany','eval','exec','open'}
KNOWN={'Path','str','int','len','print','resolve','is_relative_to','ValueError','PermissionError'}
UNSUPPORTED_SUFFIXES={'.js','.jsx','.mjs','.cjs','.ts','.tsx','.rs','.go','.c','.h','.cc','.cpp','.pyi'}
EXCLUDED_DATA_NAMES={'README.md','README.rst','LICENSE','LICENSE.md','LICENSE.txt',
                     'NOTICE','NOTICE.md','CHANGELOG.md','.gitignore'}
MODES=('baseline','functions','callchain')

def excluded_data_file(path):
    """Only these exact documentation/metadata names are outside source scope."""
    return path.name in EXCLUDED_DATA_NAMES

def sha(value): return hashlib.sha256(value if isinstance(value,bytes) else value.encode()).hexdigest()

def inventory(root,start,time_budget):
    """Bounded, deterministic inventory without following directory symlinks."""
    paths=[];unsupported=[];excluded_data=[];skipped_dir_symlinks=[];skipped_symlinks=[]
    pending=[root];count=0;complete=True
    while pending:
        if time.monotonic()-start>time_budget: complete=False;break
        try:
            with os.scandir(pending.pop()) as directory:
                children=[]
                for entry in directory:
                    count+=1
                    if count>4096 or time.monotonic()-start>time_budget:
                        complete=False;break
                    children.append(entry)
            if not complete: break
        except OSError:
            complete=False;break
        for entry in sorted(children,key=lambda item:item.name,reverse=True):
            path=Path(entry.path)
            if entry.is_symlink():
                try:
                    is_directory=entry.is_dir(follow_symlinks=True)
                except OSError:
                    is_directory=False
                if is_directory:
                    skipped_dir_symlinks.append(path.relative_to(root).as_posix())
                elif path.suffix=='.py':
                    paths.append(path)
                else:
                    skipped_symlinks.append(path.relative_to(root).as_posix())
            elif entry.is_dir(follow_symlinks=False): pending.append(path)
            elif path.suffix=='.py': paths.append(path)
            elif entry.is_file(follow_symlinks=False) and excluded_data_file(path):
                excluded_data.append(path.relative_to(root).as_posix())
            else:
                unsupported.append(path.relative_to(root).as_posix())
    return (sorted(paths),sorted(unsupported),complete and not skipped_dir_symlinks and not skipped_symlinks,
            sorted(skipped_dir_symlinks),sorted(skipped_symlinks),sorted(excluded_data))

def qualified_name(node):
    if isinstance(node,ast.Name): return node.id
    if isinstance(node,ast.Attribute):
        parent=qualified_name(node.value)
        return parent+'.'+node.attr if parent else None
    return None

def start_line(node):
    return min([node.lineno,*(item.lineno for item in getattr(node,'decorator_list',[]))])

def physical_lines(source):
    """Match Python physical line numbering without splitting Unicode separators."""
    lines=re.split(r'(?<=\n)|(?<=\r)(?!\n)',source)
    return lines[:-1] if lines and not lines[-1] else lines

def scope_calls(node):
    """Exclude nested definitions from a statement's own calls."""
    stack=[node]
    while stack:
        current=stack.pop()
        if isinstance(current,ast.Call): yield current
        for child in ast.iter_child_nodes(current):
            if child is not node and isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):
                continue
            stack.append(child)

def select(root,mode='baseline',max_modules=40,byte_budget=16384,time_budget=2.0,depth=3):
    if mode not in MODES: raise ValueError('Unknown selection mode')
    if not 1<=byte_budget<=1048576 or not 0<time_budget<=10 or not 0<=depth<=5: raise ValueError('Budget outside prototype caps')
    root=Path(root).resolve()
    if not root.is_dir(): raise ValueError('Fixture root must be a directory')
    start=time.monotonic()
    cap=min(max_modules,40) if max_modules>0 else 40
    paths,unsupported,inventory_complete,skipped_dir_symlinks,skipped_symlinks,excluded_data=inventory(root,start,time_budget)
    omitted=[str(x.relative_to(root)) for x in paths[cap:]]
    modules={}
    functions={}
    unknown=[]
    for path in paths[:cap]:
        rel=str(path.relative_to(root))
        module=rel[:-3].replace('/','.')
        row={'path':rel,'ranges':[],'status':'pending','selected_bytes':0}
        modules[module]=row
        if path.is_symlink():
            row['status']='symlink_skipped'; continue
        try:
            if not file_stat.S_ISREG(path.lstat().st_mode):
                row['status']='unsupported_file'; continue
        except OSError:
            row['status']='read_failure'; continue
        if time.monotonic()-start>time_budget:
            row['status']='time_budget'; continue
        try:
            with path.open('rb') as handle: raw=handle.read(65537)
            if len(raw)>65536:
                row['status']='oversize'; continue
            source=raw.decode('utf-8')
            row.update(source_sha256=sha(source),raw_bytes_sha256=sha(raw),source=source,line_count=len(physical_lines(source)))
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
            elif isinstance(node,ast.Import):
                for alias in node.names: imports[alias.asname or alias.name]=alias.name
        local={node.name for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
        methods={node.name:{item.name for item in node.body if isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef))}
                 for node in tree.body if isinstance(node,ast.ClassDef)}
        row['module_calls']=[];row['class_headers']=[]
        for node in tree.body:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                candidates=[(node,None)]
            elif isinstance(node,ast.ClassDef):
                candidates=[(item,node) for item in node.body if isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef))]
                evaluated=[*node.decorator_list,*node.bases,*(keyword.value for keyword in node.keywords)]
                if evaluated and (node.decorator_list or any(any(scope_calls(part)) for part in evaluated)):
                    row['class_headers'].append((start_line(node),max(start_line(node),start_line(node.body[0])-1)))
                row['module_calls'].extend(item for item in node.body if not isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef)) and any(scope_calls(item)))
            else:
                candidates=[]
                if not isinstance(node,(ast.Import,ast.ImportFrom)) and any(scope_calls(node)):
                    row['module_calls'].append(node)
            for candidate,class_node in candidates:
                class_name=class_node.name if class_node else None
                key=module+'.'+(class_name+'.' if class_name else '')+candidate.name
                calls=[];sink=False;unresolved=False
                for sub in scope_calls(candidate):
                    name=sub.func.id if isinstance(sub.func,ast.Name) else sub.func.attr if isinstance(sub.func,ast.Attribute) else ''
                    sink=sink or name in SINKS
                    target=None
                    if isinstance(sub.func,ast.Name):
                        if name in imports: target=imports[name]
                        elif name in local: target=module+'.'+name
                    elif isinstance(sub.func,ast.Attribute):
                        owner=sub.func.value.id if isinstance(sub.func.value,ast.Name) else None
                        qualified=qualified_name(sub.func)
                        if class_name and owner in {'self','cls',class_name} and name in methods.get(class_name,set()):
                            target=module+'.'+class_name+'.'+name
                        elif qualified:
                            for binding in sorted(imports,key=len,reverse=True):
                                if qualified.startswith(binding+'.'):
                                    target=imports[binding]+qualified[len(binding):]
                                    break
                    if target: calls.append(target)
                    elif name not in SINKS|KNOWN: unresolved=True
                functions[key]={'module':module,'node':candidate,'class_node':class_node,
                                'calls':calls,'sink':sink,'unresolved':unresolved}
                if unresolved: unknown.append(key)
        row['status']='parsed'
    edges=sorted([key,target] for key,f in functions.items() for target in f['calls'] if target in functions)
    for key,item in functions.items():
        if any(target not in functions for target in item['calls']):
            item['unresolved']=True
            unknown.append(key)
    def render(strategy):
        chosen=set(functions)
        if strategy=='callchain':
            chosen={k for k,f in functions.items() if f['sink'] or f['unresolved']}
            for _ in range(depth):
                chosen |= {caller for caller,target in edges if target in chosen}
            # Unknown leaves remain visible even if their sink is unrecognized.
            chosen |= {k for k,f in functions.items() if not f['calls'] and not f['sink']}
        remaining=byte_budget;output=[];selected_functions=[]
        for module,record in modules.items():
            row={key:value for key,value in record.items() if key not in {'source','tree','module_calls','class_headers'}}
            row['ranges']=[];row['selected_bytes']=0
            source=record.get('source','');lines=physical_lines(source) if source else []
            offsets=[0]
            for line in lines: offsets.append(offsets[-1]+len(line.encode()))
            intervals=[]
            if strategy=='baseline' or row['status']=='parser_fallback':
                if lines: intervals.append((1,len(lines),'baseline' if strategy=='baseline' else 'parser_fallback',None))
            elif row['status']=='parsed':
                for node in record['tree'].body:
                    if isinstance(node,(ast.Import,ast.ImportFrom)):
                        intervals.append((node.lineno,node.end_lineno,'imports',None))
                for node in record['module_calls']:
                    intervals.append((start_line(node),node.end_lineno,'module_call',None))
                for low,high in record['class_headers']:
                    intervals.append((low,high,'class_header',None))
                for key,f in functions.items():
                    if f['module']!=module or key not in chosen: continue
                    node=f['node'];class_node=f['class_node']
                    if class_node:
                        intervals.append((start_line(class_node),start_line(class_node.body[0])-1,'class_header',None))
                    intervals.append((start_line(node),node.end_lineno,'function',key))
            covered=set()
            for low,high,reason,key in sorted(set(intervals),key=lambda item:(item[0],item[1],item[2],item[3] or '')):
                if high<low or low<1 or high>len(lines): continue
                first=None
                runs=[]
                for line_number in range(low,high+1):
                    if line_number in covered:
                        if first is not None: runs.append((first,line_number-1));first=None
                    elif first is None:
                        first=line_number
                if first is not None: runs.append((first,high))
                for run_low,run_high in runs:
                    if not remaining: break
                    encoded=''.join(lines[run_low-1:run_high]).encode()
                    clipped=encoded[:remaining].decode('utf-8',errors='ignore')
                    if not clipped: continue
                    size=len(clipped.encode());remaining-=size
                    start_byte=offsets[run_low-1]
                    row['ranges'].append({'start_line':run_low,'end_line':run_low+len(physical_lines(clipped))-1,
                                          'start_byte':start_byte,'end_byte':start_byte+size,
                                          'sha256':sha(clipped),'text':clipped,'reason':reason,
                                          'truncated':size<len(encoded)})
                    row['selected_bytes']+=size
                    if size==len(encoded): covered.update(range(run_low,run_high+1))
                if key and all(line_number in covered for line_number in range(low,high+1)):
                    selected_functions.append(key)
            if row['status']=='parsed': row['status']='selected' if row['ranges'] else 'byte_budget'
            if any(item['truncated'] for item in row['ranges']): row['status']='truncated'
            output.append(row)
        omitted_functions=sorted(set(functions)-set(selected_functions)) if strategy!='baseline' else []
        return output,sorted(selected_functions),omitted_functions,byte_budget-remaining
    rendered={strategy:render(strategy) for strategy in MODES}
    output,selected_functions,omitted_functions,selected_bytes=rendered[mode]
    def signature(strategy):
        return [(row['path'],item['start_byte'],item['end_byte'],item['sha256'])
                for row in rendered[strategy][0] for item in row['ranges']]
    equivalent_to=[other for other in MODES if other!=mode and signature(other)==signature(mode)]
    strategy_status=('unsupported_language' if unsupported else 'empty_scope' if not paths else
                     'strategies_equivalent' if equivalent_to else 'distinct')
    incompleteness=(bool(omitted_functions) or bool(unknown) or not paths or bool(omitted) or bool(unsupported)
                    or not inventory_complete or time.monotonic()-start>time_budget
                    or any(x['status']!='selected' for x in output))
    return {'schema':'context-selection-v1','mode':mode,'module_cap':cap,'byte_budget':byte_budget,'time_budget_seconds':time_budget,
            'depth_cap':depth,'wall_seconds':time.monotonic()-start,'selected_bytes':selected_bytes,
            'files':output,'selected_functions':selected_functions,'edges':edges,'unknown_calls':sorted(set(unknown)),
            'omitted_modules':omitted,'omitted_functions':[{'function':key,'reason':'depth_or_byte_budget'} for key in omitted_functions],
            'unsupported_sources':unsupported,'inventory_complete':inventory_complete,
            'excluded_data_files':excluded_data,
            'skipped_dir_symlinks':skipped_dir_symlinks,'skipped_symlinks':skipped_symlinks,
            'strategy_status':strategy_status,'equivalent_to':equivalent_to,'incomplete':incompleteness,
            'limitation':'Python syntactic context only; no JS/TS/Rust support, interprocedural taint proof, dependency resolution, or vulnerability verdict.'}

def write_result(root,mode,output):
    if output.exists(): raise FileExistsError('Preserve existing context-selection output')
    result=select(root,mode)
    with output.open('x') as handle: json.dump(result,handle,indent=2);handle.write('\n')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('root',type=Path)
    parser.add_argument('--mode',choices=MODES,default='baseline')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    write_result(args.root,args.mode,args.output)
