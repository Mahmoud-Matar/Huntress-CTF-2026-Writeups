import ast,base64,json,pathlib,re
R=pathlib.Path('/home/remnux/files/output/hatch-mastery2')
answer={}; descriptors={}
js_files={'benign':'host-context.js','stager':'memory-stage.js','dropper':'embedded-write.js','downloader':'remote-write.js','launcher':'local-dispatch.js','chain':'staged-handoff.js','uploader':'outbound-transfer.js','impact':'impact-plan.js','relay':'relay-handoff.js'}
batch_files={'benign':'host-context.cmd','stager':'memory-stage.bat','dropper':'embedded-write.cmd','downloader':'remote-write.bat','uploader':'outbound-transfer.cmd','launcher':'local-dispatch.bat','impact':'impact-plan.cmd','chain':'staged-handoff.bat','relay':'relay-handoff.cmd'}
vbs_files={'benign':'host-context.vbs','stager':'memory-stage.vbs','dropper':'embedded-write.vbs','downloader':'remote-write.vbs','uploader':'outbound-transfer.vbs','launcher':'local-dispatch.vbs','impact':'impact-plan.vbs','chain':'staged-handoff.vbs','relay':'relay-handoff.vbs'}
py_files={'source-benign':'source-context.py','pyc38-dropper':'pyc38-recovered.py','current-pyc-launcher':'current-pyc-recovered.py','zipapp-relay':'zipapp-recovered.py','wheel-stager':'wheel-recovered.py','pyinstaller-onefile':'pyinstaller-onefile-recovered.py','pyinstaller-onedir':'pyinstaller-onedir-recovered.py','py2exe-console':'py2exe-console-recovered.py','py2exe-service':'py2exe-service-recovered.py','cxfreeze-executable':'cxfreeze-recovered.py','cxfreeze-msi':'cxfreeze-msi-recovered.py','pyarmor-source':'pyarmor-source-recovered.py','pyarmor-pyinstaller':'pyarmor-pyinstaller-recovered.py','embedded-runtime-relay':'embedded-runtime-recovered.py'}
subtech={'jscript':'007','batch':'003','vbscript':'005','python':'006'}
def ra(steps,lang):
 s=steps if isinstance(steps,str) else ','.join(steps)
 if 'return_configuration' in s:return 'benign_utility','none'
 if 'write_recovery_note' in s:return 'impact','T1486'
 if 'decode_configuration' in s and 'dispatch_next_stage' in s:return 'relay','T1059.'+subtech[lang]
 if 'handoff_script' in s:return 'staged_chain','T1059.'+subtech[lang]
 if 'profile_host' in s and 'dispatch_process' in s:return 'staged_chain','T1059.'+subtech[lang]
 if 'dispatch_memory' in s or 'dispatch_pipe' in s:return 'stager','T1105'
 if 'decode_embedded' in s and 'write_file' in s:return 'dropper','T1140'
 if 'acquire_remote' in s and 'write_file' in s and 'handoff_script' not in s:return 'downloader','T1105'
 if 'upload_remote' in s or 'transmit_remote' in s:return 'uploader','T1041'
 if 'locate_local' in s and 'dispatch_process' in s:return 'launcher','T1059.'+subtech[lang]
 return 'UNKNOWN','UNKNOWN'
def put(group,suffix,val):answer[group+'-'+suffix]=str(val)
def getfunc(src,pattern):
 m=re.search(pattern,src,re.S|re.I)
 if not m:return ''
 start=m.start(); op=src.find('{',m.start()); depth=0; quote=None; esc=False
 for i in range(op,len(src)):
  c=src[i]
  if quote:
   if esc:esc=False
   elif c=='\\':esc=True
   elif c==quote:quote=None
  elif c in "\"'`":quote=c
  elif c=='{':depth+=1
  elif c=='}':
   depth-=1
   if depth==0:return src[start:i+1]
 return src[start:]
def decode_js(p):
 s=p.read_text();raw=None;m=re.search(r'packedText\s*=\s*"([^"]*)"',s)
 if m:
  x=m.group(1)
  if re.search(r'%[0-9a-f]{2}',x,re.I):raw=bytes(int(z,16) for z in re.findall(r'%([0-9a-f]{2})',x,re.I))
  elif ':' in x and re.fullmatch(r'[0-9a-f:]+',x,re.I):raw=bytes.fromhex(x.replace(':',' '))
  else:raw=base64.b64decode(x+'='*((-len(x))%4))
 else:
  rec=s[s.find('recover_'):]
  m=re.search(r'(?:var\s+characters|var\s+(?:item1|v_a19c))\s*=\s*(\[[^\]]*\])',rec)
  if not m:raise ValueError('JS material not found '+p.name)
  raw=bytes(ast.literal_eval(m.group(1)))
 d=s[s.find('decode_'):s.find('recover_')]
 km=re.search(r'keyBytes\s*=\s*(\[[^\]]*\])',d)
 if km:
  k=ast.literal_eval(km.group(1));raw=bytes(b^k[i%len(k)] for i,b in enumerate(raw))
 elif 'var previous =' in d:
  prev=int(re.search(r'var previous\s*=\s*(\d+)',d).group(1));z=[]
  for b in raw:z.append(b^prev);prev=b
  raw=bytes(z)
 elif 'reverse()' in d:
  raw=raw[::-1];k=int(re.search(r'\^\s*(\d+)',d).group(1));raw=bytes(b^k for b in raw)
 elif re.search(r'\[i\]\s*\^\s*\d+',d):
  k=int(re.search(r'\[i\]\s*\^\s*(\d+)',d).group(1));raw=bytes(b^k for b in raw)
 elif re.search(r'\[i\]\s*\+\s*\d+',d):
  k=int(re.search(r'\[i\]\s*\+\s*(\d+)',d).group(1));raw=bytes((b+k)%256 for b in raw)
 elif re.search(r'\[i\]\s*-\s*\d+',d):
  k=int(re.search(r'\[i\]\s*-\s*(\d+)',d).group(1));raw=bytes((b-k)%256 for b in raw)
 return s,json.loads(raw.decode('ascii'))
from jsdecode_module import decode_candidates
def decode_js(p):
 s=p.read_text(); got=decode_candidates(s)
 if not got: raise ValueError("cannot statically reconstruct "+p.name)
 return s,got[1]
for role,fn in js_files.items():
 p=R/fn;s,obj=decode_js(p);descriptors['jscript-'+role]=obj
 vals=obj['values'];steps=obj['steps'];r,a=ra(steps,'jscript')
 put('jscript-'+role,'role',r);put('jscript-'+role,'attack',a);put('jscript-'+role,'adapter',obj['adapter'])
 if role!='impact':put('jscript-'+role,'campaign',vals['campaign_id'])
 special={'benign':('host','host_id'),'stager':('url','url'),'dropper':('path','file_path'),'downloader':('url','url'),'launcher':('path','file_path'),'chain':('next-stage','next_stage'),'uploader':('url','url'),'impact':('extension','extension'),'relay':('next-stage','next_stage')}.get(role)
 if special:put('jscript-'+role,special[0],vals[special[1]])
 if role=='impact':put('jscript-impact','note',vals['note_name'])
 inspect=getfunc(s,r'(?:var\s+)?inspect_[A-Za-z0-9_]+\s*=\s*function|function\s+inspect_[A-Za-z0-9_]+\s*\(')
 m=re.search(r'=\s*function\s*(\w*)\s*\(',inspect)
 if m:fs='named_expression' if m.group(1) else 'anonymous_expression'
 else:fs='declaration'
 put('jscript-'+role,'function-style',fs)
 call=re.search(r'(recover_\w+)\s*(?:\.\s*(apply|call)\s*\()',inspect)
 inv=call.group(2) if call else 'direct';put('jscript-'+role,'invocation-style',inv)
 m=re.search(r'var\s+(\w+)\s*=\s*eval\s*\(',inspect)
 if not m:prop='unknown'
 else:
  v=m.group(1); body=inspect[m.end():]
  dot=bool(re.search(r'\b'+re.escape(v)+r'\s*\.\s*(?:steps|adapter|values|stageCount)\b',body))
  bracket=bool(re.search(r'\b'+re.escape(v)+r'\s*\[\s*[\"\'](?:steps|adapter|values|stageCount)[\"\']\s*\]',body))
  prop='mixed' if dot and bracket else 'dot' if dot else 'bracket_literal' if bracket else 'unknown'
 put('jscript-'+role,'property-style',prop)
# Batch descriptors from static fragment assignments only.
for role,fn in batch_files.items():
 s=(R/fn).read_text();sec=s[s.find(':HUNTRESS_INSPECT'):];end=sec.find('goto :HUNTRESS_SEPARATOR_DONE');sec=sec[:end if end>=0 else len(sec)];vals={}
 for line in sec.splitlines():
  m=re.search(r'(?i)\bset\s+"?([A-Za-z][A-Za-z0-9_]*)=([^"\r\n]*)',line)
  if m and re.search(r'\d+$',m.group(1)): vals[m.group(1)]=m.group(2).replace('^|','|')
 gr={}
 for n,v in vals.items():
  m=re.search(r'(\d+)$',n);gr.setdefault(n[:m.start()].lower(),[]).append((int(m.group(1)),v))
 opts=[]
 for pref,arr in gr.items():
  text=''.join(v for i,v in sorted(arr))
  if 'v=1' in text and '|steps=' in text:opts.append((pref,text))
 if not opts:raise ValueError('Batch fragments not found '+fn)
 dtext=max(opts,key=lambda x:len(x[1]))[1];desc={}
 for it in dtext.split('|'):
  if '=' in it:k,v=it.split('=',1);desc[k]=v
 descriptors['batch-'+role]=desc;r,a=ra(desc['steps'],'batch')
 put('batch-'+role,'role',r);put('batch-'+role,'attack',a);put('batch-'+role,'adapter',desc['adapter']);put('batch-'+role,'campaign',desc['campaign_id']);put('batch-'+role,'graph',desc['graph'])
 sf={'benign':('host-id','host_id'),'stager':('url','url'),'dropper':('file-path','file_path'),'downloader':('url','url'),'uploader':('upload-url','upload_url'),'launcher':('file-path','file_path'),'impact':('note-name','note_name'),'chain':('next-stage','next_stage'),'relay':('next-stage','next_stage')}[role]
 put('batch-'+role,sf[0],desc[sf[1]])
 # Source-level expansion form used in the reconstruction statement.
 body=s[s.find(':HUNTRESS_SEPARATOR_DONE'):]
 recon=next((ln.lower() for ln in body.splitlines() if re.search(r'(?i)\bset\s+.*=',ln) and ('%' in ln or '!' in ln)), '')
 if '%%' in recon and re.search(r'%%\w+%%g%%',recon):exp='for_indirect'
 elif re.search(r'\bcall\s+set\b',recon) and '%%' in recon:exp='call_double'
 elif '%%' in recon and 'for ' in recon:exp='for_indirect'
 elif '!' in recon:exp='delayed'
 else:exp='percent'
 put('batch-'+role,'expansion',exp)
 # Classify the wrapper around reconstruction, ignoring host guards and ordinary label transfers.
 inspect=body.lower()
 if re.search(r'if\s+errorlevel\s+\d+\s+exit',inspect):control='errorlevel_guard'
 elif re.search(r'goto\s+:huntress_dispatch[\s\S]*?:huntress_dispatch\s+[\s\S]*?set\s+.*(?:%|!)',inspect):control='goto_dispatch'
 elif re.search(r'for\s+/l\s+%%\w+\s+in\s*\([^)]*\)\s+do\s+call\s+:huntress_recover',inspect):control='call_subroutine'
 elif re.search(r'if\s+(?:not\s+)?defined\s+\w+[^\r\n]*set\s+"?\w+=',inspect):control='if_guard'
 elif re.search(r'call\s+:huntress_recover',inspect):control='call_subroutine'
 elif re.search(r'call\s+set\s+"?\w+=',inspect):control='call_subroutine'
 else:control='direct'
 put('batch-'+role,'control',control)
# VB descriptors from static constants and Codec labels.
for role,fn in vbs_files.items():
 s=(R/fn).read_text();mm=re.search(r'Const\s+Material_\w+\s*=\s*"([^"]*)"',s,re.I);cm=re.search(r'Const\s+Codec_\w+\s*=\s*"([^"]*)"',s,re.I);mat=mm.group(1);codec=cm.group(1);parts=codec.split('|');rep,trans=parts[:2];key=parts[2] if len(parts)>2 else ''
 if rep=='reversed_decimal':b=bytes(int(x) for x in mat.split(','))[::-1]
 elif rep=='base64_literal':b=base64.b64decode(mat+'='*((-len(mat))%4))
 elif rep=='base64_chunks':
  w=(len(mat)+3)//4;packed=mat[:w]+mat[w:2*w]+mat[2*w:3*w]+mat[3*w:];b=base64.b64decode(packed+'='*((-len(packed))%4))
 elif rep=='hex_dash':b=bytes.fromhex(mat.replace('-',' '))
 elif rep=='hex_colon':b=bytes.fromhex(mat.replace(':',' '))
 elif rep=='decimal_pipe':b=bytes(int(x) for x in mat.split('|'))
 elif rep=='decimal_comma':b=bytes(int(x) for x in mat.split(','))
 elif rep=='decimal_dash':b=bytes(int(x) for x in mat.split('-'))
 elif rep=='reversed_hex':b=bytes.fromhex(mat.replace(':',' '))[::-1]
 elif rep=='hex_compact':b=bytes.fromhex(mat)
 else:raise ValueError('unknown VBS representation '+rep)
 if trans=='reverse_bytes':b=b[::-1]
 elif trans=='reverse_then_xor':
  b=b[::-1];k=int(key,16);b=bytes(v^k for v in b)
 if trans=='repeating_key_xor':
  kb=[int(x,16) for x in key.split(',')];b=bytes(v^kb[i%len(kb)] for i,v in enumerate(b))
 elif trans=='rolling_xor':
  prev=int(key,16);z=[]
  for v in b:z.append(v^prev);prev=v
  b=bytes(z)
 elif trans=='single_byte_xor':
  k=int(key,16);b=bytes(v^k for v in b)
 elif trans in ('add_modulo_256','subtract_modulo_256'):
  dec=re.search(r'Function\s+Decode_\w+.*?End Function',s,re.I|re.S).group(0);m=re.search(r'\w+\(\w+\)\s*([+-])\s*(\d+)',dec,re.I)
  if m:op,k=m.group(1),int(m.group(2));b=bytes((v+k if op=='+' else v-k)%256 for v in b)
 desc={}
 for item in b.decode('ascii').split('|'):
  if '=' in item:k,v=item.split('=',1);desc[k]=v
 descriptors['vbscript-'+role]=desc;r,a=ra(desc['steps'],'vbscript')
 put('vbscript-'+role,'role',r);put('vbscript-'+role,'attack',a);put('vbscript-'+role,'adapter',desc['adapter']);put('vbscript-'+role,'campaign',desc['campaign_id']);put('vbscript-'+role,'representation',rep);put('vbscript-'+role,'transform',trans)
 sf={'benign':('host-id','host_id'),'stager':('url','url'),'dropper':('file-path','file_path'),'downloader':('url','url'),'uploader':('upload-url','upload_url'),'launcher':('file-path','file_path'),'impact':('extension','extension'),'chain':('next-stage','next_stage'),'relay':('next-stage','next_stage')}[role]
 put('vbscript-'+role,sf[0],desc[sf[1]])
 rec=getfunc(s,r'Function\s+Recover_\w+\s*\(')
 if re.search(r'On Error Resume Next',rec,re.I):control='error_guard'
 elif re.search(r'Select Case[\s\S]*?Decode_',rec,re.I):control='select_case'
 elif re.search(r'For\s+\w+\s*=.*?Decode_',rec,re.I|re.S):control='for_once'
 elif re.search(r'Do[\s\S]*?Decode_[\s\S]*?Exit Do',rec,re.I):control='do_once'
 elif re.search(r'While[\s\S]*?Decode_',rec,re.I):control='while_once'
 else:control='direct'
 put('vbscript-'+role,'control',control)
# Python carriers: static AST parsing, no imports or sample execution.
for key,fn in py_files.items():
 p=R/fn;s=p.read_text();tree=ast.parse(s);names={}
 for n in ast.walk(tree):
  if isinstance(n,(ast.Assign,ast.AnnAssign)):
   for t in (n.targets if isinstance(n,ast.Assign) else [n.target]):
    if isinstance(t,ast.Name):
     try:names[t.id]=ast.literal_eval(n.value)
     except:pass
 mn=next(k for k in names if k.startswith('MATERIAL_'));cn=next(k for k in names if k.startswith('CODEC_'))
 material=names[mn];codec=names[cn];parts=codec.split('|');mode=parts[0];trans=parts[1] if len(parts)>1 else 'identity';keytext=parts[2] if len(parts)>2 else ''
 if mode in ('base64_chunks','base64_literal','urlsafe_base64'):
  z=material+'='*((-len(material))%4)
  if mode=='urlsafe_base64':b=base64.urlsafe_b64decode(z)
  elif mode=='base64_chunks':
   w=(len(material)+3)//4;packed=material[:w]+material[w:2*w]+material[2*w:3*w]+material[3*w:];b=base64.b64decode(packed+'='*((-len(packed))%4))
  else:b=base64.b64decode(z)
 elif mode in ('hex_colon','hex_literal'):b=bytes.fromhex(material.replace(':',' '))
 elif mode=='hex_escape':b=bytes(material) if not isinstance(material,str) else bytes.fromhex(material.replace('\\x','').replace('\\X',''))
 elif mode in ('decimal_csv','decimal_dash','decimal_comma'):b=bytes(int(x) for x in re.split(r'[,\-]',material))
 elif mode=='decimal_pipe':b=bytes(int(x) for x in material.split('|'))
 else:b=bytes(material)
 if mode=='reversed_integer_list':b=b[::-1]
 if trans=='reverse_bytes':b=b[::-1]
 elif trans=='reverse_then_xor':b=bytes(v^int(keytext,16) for v in b[::-1])
 elif trans=='single_byte_xor':b=bytes(v^int(keytext,16) for v in b)
 elif trans=='repeating_key_xor':
  kb=[int(x,16) for x in keytext.split(',')];b=bytes(v^kb[i%len(kb)] for i,v in enumerate(b))
 elif trans=='rolling_xor':
  prev=int(keytext,16);z=[]
  for v in b:z.append(v^prev);prev=v
  b=bytes(z)
 elif trans in ('add_modulo_256','subtract_modulo_256'):
  dec=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name.startswith('decode_'));ds=ast.unparse(dec)
  m=re.search(r'value\s*([+-])\s*(\d+)',ds)
  if m:
   op,k0=m.group(1),int(m.group(2));b=bytes((v+k0 if op=='+' else v-k0)%256 for v in b)
 desc={}
 for item in b.decode('ascii').split('|'):
  if '=' in item:k0,v=item.split('=',1);desc[k0]=v
 descriptors['python-'+key]=desc;r,a=ra(desc['steps'],'python')
 for suff,val in [('role',r),('attack',a),('adapter',desc['adapter']),('campaign',desc['campaign_id']),('syntax',desc['syntax']),('obfuscation',desc['obfuscation']),('carrier',desc['carrier']),('windows-chain',desc['windows_chain'])]:put('python-'+key,suff,val)
 special={'source-benign':'host_id','pyc38-dropper':'file_path','current-pyc-launcher':'file_path','zipapp-relay':'next_stage','wheel-stager':'url','pyinstaller-onefile':'url','pyinstaller-onedir':'upload_url','py2exe-console':'file_path','py2exe-service':'next_stage','cxfreeze-executable':'extension','cxfreeze-msi':'file_path','pyarmor-source':'url','pyarmor-pyinstaller':'handoff_id','embedded-runtime-relay':'next_stage'}[key]
 if special:put('python-'+key,special.replace('_','-'),desc[special])
# PowerShell payloads decoded as data, not run.
ps={}
for fn in ('resource-sample.ps1','collection-sample.ps1','impact-sample.ps1'):
 s=(R/fn).read_text();encoded=re.search(r"FromBase64String\('([^']+)'\)",s).group(1);ps[fn]=json.loads(base64.b64decode(encoded))
res,coll,imp=ps['resource-sample.ps1'],ps['collection-sample.ps1'],ps['impact-sample.ps1']
for k,v in {'resource-scenario':'resource_hijacking','resource-attack':'T1496','resource-url':res['b'],'resource-wallet':res['c'],'resource-mutex':res['h'],'collection-scenario':'synthetic_collection','collection-attack':'T1555.003','collection-url':coll['b'],'collection-file':coll['c'][0],'collection-user-agent':coll['f'],'impact-scenario':'synthetic_impact','impact-attack':'T1486','impact-extension':imp['b'],'impact-note':imp['c'],'impact-url':imp['d']}.items():answer[k]=str(v)
print(json.dumps({'answer_count':len(answer),'answers':answer,'descriptors':descriptors},indent=2))
