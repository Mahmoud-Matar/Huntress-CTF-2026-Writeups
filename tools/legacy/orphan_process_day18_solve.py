import ast,base64,re,json,pathlib,urllib.parse
Q=json.load(open('/home/remnux/huntressCTF-2026/challenges/data/process-story-day18-start.json'))
ROOT=pathlib.Path('/home/remnux/files/samples/process-story-day18-artifacts')

def parse_fields(txt):
 if not txt:return {}
 if txt.lstrip().startswith('{'):
  try:
   obj=json.loads(txt)
   if isinstance(obj,dict):
    out=dict(obj)
    if isinstance(obj.get('values'),dict):out.update(obj['values'])
    if isinstance(obj.get('steps'),list):out['steps']=','.join(obj['steps'])
    if 'stageCount' in obj:out['stage_count']=obj['stageCount']
    return out
   return {'json':obj}
  except:pass
 out={}
 for part in txt.split('|'):
  if '=' in part:
   k,v=part.split('=',1); out[k.strip()]=v.strip()
 return out

def codec_decode(p,s):
 cm=re.search(r'(?:HUNTRESS-CODEC:|[Cc][Oo][Dd][Ee][Cc]_[\w]+\s*=\s*[\"\'])([\w]+\|[^\"\'\r\n]*)',s)
 if not cm:return None
 codec=cm.group(1).strip(); enc,*par=codec.split('|')
 raw=None
 mm=re.search(r'HUNTRESS-MATERIAL:([^\r\n]*)',s)
 if mm: raw=mm.group(1).strip()
 if raw is None and p.suffix=='.py':
  try:
   for n in ast.walk(ast.parse(s)):
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id.lower().startswith('material_') for t in n.targets): raw=ast.literal_eval(n.value); break
  except:pass
 if raw is None:
  mm=re.search(r'(?:MATERIAL|Material)_[\w]+\s*=\s*(b?[\"\'](?:\\.|[^\"\'])*[\"\'])',s,re.I)
  if mm:
   try:raw=ast.literal_eval(mm.group(1))
   except:raw=mm.group(1)[1:-1]
 if raw is None:return None
 if isinstance(raw,(list,tuple)): blob=bytes(int(x)%256 for x in raw)
 elif isinstance(raw,bytes):blob=raw
 else:
  raw=str(raw)
  if enc in ('hex_escape','escaped_octets','unicode_escapes'):
   blob=bytes(int(x,16) for x in re.findall(r'(?:\\x|\\u00)([0-9a-fA-F]{2})',raw))
  elif enc in ('decimal_space','decimal_comma','decimal_csv','decimal_array','decimal_tuple','decimal_dash','decimal_pipe','decimal_colon','decimal_bytes','reversed_decimal','integer_tuple','reversed_integer_list'):
   blob=bytes(int(x)%256 for x in re.findall(r'\d+',raw))
  elif enc in ('hex_dash','hex_compact','xor_hex','hex_pairs','hex_colon','hex_array','hex_buffer','hex_literal','reversed_hex'):
   hx=re.sub(r'[^0-9a-fA-F]','',raw)
   if len(hx)%2:return None
   blob=bytes.fromhex(hx)
  elif enc=='percent_hex':blob=urllib.parse.unquote_to_bytes(raw)
  elif enc in ('base64_literal','base64_chunks','urlsafe_base64','reversed_base64'):
   if enc=='reversed_base64':raw=raw[::-1]
   blob=base64.urlsafe_b64decode(raw+'='*((4-len(raw)%4)%4))
  elif enc in ('reversed_text','plain_fragments'):blob=raw.encode()
  else:return None
 if enc in ('reversed_decimal','reversed_integer_list','reversed_hex'):blob=blob[::-1]
 t=par[0] if par else 'identity'; arg=par[1] if len(par)>1 else ''
 if enc=='xor_hex' and len(par)==1:t='single_byte_xor';arg=par[0]
 try:key=bytes(int(x,16) for x in arg.split(',')) if ',' in arg else bytes([int(arg,16)]) if arg else b''
 except:key=b''
 if t in ('identity',''):pass
 elif t in ('reverse','reverse_bytes'):blob=blob[::-1]
 elif t=='single_byte_xor' and key:blob=bytes(x^key[0] for x in blob)
 elif t=='repeating_key_xor' and key:blob=bytes(x^key[i%len(key)] for i,x in enumerate(blob))
 elif t=='rolling_xor' and key:
  prev=key[0];out=[]
  for x in blob:out.append(x^prev);prev=x
  blob=bytes(out)
 elif t in ('add_modulo_256','subtract_modulo_256') and key:
  d=-key[0] if t=='add_modulo_256' else key[0];blob=bytes((x+d)&255 for x in blob)
 elif t=='add_7':blob=bytes((x-7)&255 for x in blob)
 elif t=='xor_5a':blob=bytes(x^0x5a for x in blob)
 elif t=='reverse_xor':blob=bytes(x^0x5a for x in blob[::-1])
 elif t=='reverse_then_xor' and key:blob=bytes(x^key[0] for x in blob[::-1])
 elif t=='rotate_left':blob=bytes(((x>>1)|((x&1)<<7)) for x in blob)
 else:return None
 try:txt=blob.decode('utf-8')
 except:txt=blob.decode('latin1')
 if re.search(r'\|[12]=v$',txt):txt=txt[::-1]
 return txt

def get_desc(name):
 p=ROOT/name;s=p.read_text(errors='ignore')
 m=re.search(r'HUNTRESS_ANALYSIS_V1:(HEX|B64)-([A-Za-z0-9+/=_-]+)',s)
 if m:
  b=bytes.fromhex(m.group(2)) if m.group(1)=='HEX' else base64.b64decode(m.group(2));return parse_fields(b.decode('utf8','replace'))
 if 'HUNTRESS_ANALYSIS_V1:HB64-' in s:
  m=re.search(r'HUNTRESS_ANALYSIS_V1:HB64-([0-9a-fA-F.]+)',s)
  if m:
   try:
    b=bytes.fromhex(m.group(1).replace('.','')); return parse_fields(base64.b64decode(b).decode('utf8','replace'))
   except:pass
 if 'HUNTRESS_ANALYSIS_V1:FRAG-' in s:
  m=re.search(r'HUNTRESS_ANALYSIS_V1:FRAG-([0-9a-fA-F.]+)',s)
  if m:
   try:return parse_fields(bytes.fromhex(m.group(1).replace('.','')).decode('utf8','replace'))
   except:pass
 if 'HUNTRESS_ANALYSIS_V1:SPLIT' in s:
  m=re.search(r'HUNTRESS_ANALYSIS_V1_SPLIT_[\w]+\s*=\s*\[(.*?)\]',s,re.S)
  if m:
   chunks=re.findall(r'[\"\']([^\"\']+)[\"\']',m.group(1))
   if chunks:
    prefixes=('HB64-','B64-','HEX-','FRAG-')
    prefix=next((x for x in prefixes if chunks[0].startswith(x)),'')
    data=''.join(x.removeprefix(prefix).replace('.','') for x in chunks)
    try:
     b=bytes.fromhex(data) if prefix in ('HB64-','HEX-','FRAG-') else base64.b64decode(data)
     if prefix=='HB64-': b=base64.b64decode(b)
     return parse_fields(b.decode('utf8','replace'))
    except:pass
 t=codec_decode(p,s)
 if t and ('v=' in t or 'role=' in t or 'feature=' in t):return parse_fields(t)
 if name.endswith('.ps1'):
  m=re.search(r"FromBase64String\('([^']+)'\)",s)
  if m:
   try:return json.loads(base64.b64decode(m.group(1)))
   except:pass
 if name.endswith(('.cmd','.bat')):
  fr=[]
  for m in re.finditer(r'(?im)^set\s+"?(?:fragment|frag|h)(\d+)=([^"\r\n]*)',s):fr.append((int(m.group(1)),m.group(2).replace('^','')))
  if fr:return parse_fields(''.join(v for _,v in sorted(fr)))
 if name.endswith('.js'):
  # Recover the inert descriptor from byte arrays in the reconstruction function.
  arrays=[]
  for m in re.finditer(r'(?:var|let|const)\s+(\w+)\s*=\s*\[([0-9,\s]+)\]',s):
   try:arrays.append((m.group(1),[int(x) for x in re.findall(r'\d+',m.group(2))]))
   except:pass
  names={n:a for n,a in arrays}
  body='\n'.join(x for x in s.splitlines() if not x.lstrip().startswith('//'))
  if 'packedText =' in s:
   m=re.search(r'packedText\s*=\s*"([0-9a-fA-F:]+)"',s)
   if m:
    b=bytes(int(x,16) for x in m.group(1).split(':')); b=bytes((x-4)&255 for x in b);return parse_fields(b.decode('utf8','replace'))
   m=re.search(r'packedText\s*=\s*"([A-Za-z0-9+/=]+)"',s)
   if m:
    try:return parse_fields(base64.b64decode(m.group(1)).decode('utf8','replace'))
    except:pass
  arr=[]
  for n in ('firstPart','secondPart'):
   if n in names:arr+=names[n]
  if not arr:
   for n in ('characters','v_a19c','item1','s'):
    if n in names:arr=names[n];break
  if arr:
   # identify common decoder transformation from source
   if 'v_a19c.reverse()' in s or 'item1.reverse()' in s or 'reverse();' in s:arr=arr[::-1]
   prev=re.search(r'previous\s*=\s*(\d+)',s)
   if prev and re.search(r'\^\s*previous',s):
    last=int(prev.group(1)); out=[]
    for x in arr:out.append(x^last);last=x
    arr=out
   keym=re.search(r'keyBytes\s*=\s*\[([0-9,\s]+)\]',s)
   if keym:
    key=[int(x) for x in re.findall(r'\d+',keym.group(1))];arr=[x^key[i%len(key)] for i,x in enumerate(arr)]
   xor=re.search(r'\^\s*(\d+)',s)
   if xor:arr=[x^int(xor.group(1)) for x in arr]
   sub=re.search(r'\(\s*\w+\[\w+\]\s*-\s*(\d+)',s)
   if sub:arr=[(x-int(sub.group(1)))%256 for x in arr]
   text=bytes(x%256 for x in arr).decode('utf8','replace');return parse_fields(text)
 return {}

# Build per-file descriptors
files=sorted({q['artifact'].split(' -> ',1)[-1] for q in Q['questions']})
desc={f:get_desc(f) for f in files}
print('decoded field sources',sum(bool(x) for x in desc.values()),'/',len(files))
for f,d in desc.items():
 if not d: print('NO DESC',f)

def flatten(d):
 out=dict(d)
 vals=d.get('values')
 if isinstance(vals,dict):out.update(vals)
 if isinstance(d.get('steps'),list):out['steps']=','.join(d['steps'])
 if 'stageCount' in d:out['stage_count']=d['stageCount']
 return out

def get_field(q,d):
 d=flatten(d); qid=q['id']; qt=q['question'].lower(); aid=q['id'].lower()
 def graph_class():
  steps=str(d.get('steps','')).split(',')
  # The question is about terminal intent. A graph that writes an intermediate
  # file and then hands off to another stage is a chain, not a downloader.
  if steps and steps[-1]=='handoff_script':return 'staged_chain'
  if len(steps)>=3 and steps[-3:]==['decode_configuration','locate_interpreter','dispatch_next_stage']:return 'relay'
  if steps and steps[-1]=='dispatch_process' and 'write_file' in steps and ('profile_host' in steps or 'acquire_remote' in steps):return 'staged_chain'
  if steps and steps[-1] in ('upload_remote','transmit_remote'):return 'uploader'
  if steps and steps[-1]=='write_recovery_note' and any(x.startswith('transform_') for x in steps):return 'impact'
  if steps==['decode_embedded','write_file']:return 'dropper'
  if steps==['acquire_remote','write_file']:return 'downloader'
  if steps==['decode_configuration','return_configuration']:return 'benign_utility'
  if steps==['acquire_remote','dispatch_memory'] or steps==['acquire_remote','dispatch_pipe']:return 'stager'
  if steps==['locate_local','dispatch_process']:return 'launcher'
  if steps and steps[-1]=='dispatch_next_stage':return 'relay'
  if steps==['build_schedule','register_descriptor']:return 'persistence_descriptor'
  return None
 def graph_attack():
  steps=str(d.get('steps','')).split(','); role=graph_class()
  if 'advanced-' in aid:return 'T1059.004'
  if role=='benign_utility':return 'none'
  if role in ('stager','downloader'):return 'T1105'
  if role=='dropper':return 'T1140'
  if role=='uploader':return 'T1041'
  if role in ('launcher','staged_chain','relay'):
   lang=aid.split('-',1)[0]
   return {'bash':'T1059.004','batch':'T1059.003','vbscript':'T1059.005','python':'T1059.006','nodejs':'T1059.007','jscript':'T1059.007'}.get(lang,'T1059')
  if role=='impact':return 'T1486'
  if role=='persistence_descriptor':return 'T1053.003'
  if steps and steps[-1]=='transmit_remote':return 'T1041'
  return d.get('attack')
 if aid.startswith(('resource-','collection-','impact-')):
  typ=aid.split('-',1)[0]
  if aid.endswith('-scenario'):return {'resource':'resource_hijacking','collection':'synthetic_collection','impact':'synthetic_impact'}[typ]
  if typ=='resource':
   return {'attack':'T1496','url':d.get('b'),'wallet':d.get('c'),'mutex':d.get('h')}.get(aid.rsplit('-',1)[-1])
  if typ=='collection':
   c=d.get('c',[]); tail=next((x for x in ('user-agent','scenario','attack','url','file') if aid.endswith('-'+x)),None)
   return {'attack':'T1555.003','url':d.get('b'),'file':c[0] if c else None,'user-agent':d.get('f')}.get(tail)
  if typ=='impact':return {'attack':'T1486','extension':d.get('b'),'note':d.get('c'),'url':d.get('d')}.get(aid.rsplit('-',1)[-1])
 if 'function-style' in aid:
  f=q['artifact'].split(' -> ')[-1];s=(ROOT/f).read_text(errors='ignore')
  m=re.search(r'(?:var|let|const)\s+inspect_\w+\s*=\s*function(?:\s+(\w+))?\s*\(',s)
  if m:return 'named_expression' if m.group(1) else 'anonymous_expression'
  return 'declaration' if re.search(r'function\s+inspect_\w+\s*\(',s) else None
 if 'invocation-style' in aid:
  f=q['artifact'].split(' -> ')[-1];s=(ROOT/f).read_text(errors='ignore')
  m=re.search(r'function\s+inspect_\w+[\s\S]*?\n}',s)
  block=m.group(0) if m else s
  if re.search(r'recover_\w+\.apply\s*\(',block):return 'apply'
  if re.search(r'recover_\w+\.call\s*\(',block):return 'call'
  if re.search(r'recover_\w+\s*\(',block):return 'direct'
 if 'property-style' in aid:
  f=q['artifact'].split(' -> ')[-1];s=(ROOT/f).read_text(errors='ignore')
  m=re.search(r'function\s+inspect_\w+[\s\S]*?\n}',s)
  block=m.group(0) if m else s
  v=re.search(r'(\w+)\s*=\s*eval\(',block)
  if v:
   var=v.group(1); props=[]
   for prop in ('steps','adapter','values','stageCount'):
    dot=re.search(r'\b'+re.escape(var)+r'\.'+prop+r'\b',block)
    br=re.search(r'\b'+re.escape(var)+r'\[\s*[\"\']'+prop+r'[\"\']\s*\]',block)
    if dot:props.append('dot')
    elif br:props.append('bracket_literal')
   if len(set(props))>1:return 'mixed'
   return props[0] if props else None
 # semantic field aliases from question wording
 if 'attack' in aid or 'mitre att&ck' in qt:return d.get('attack') or graph_attack()
 if 'role' in aid:return d.get('role') or graph_class() or ('advanced_syntax' if 'advanced-' in aid else None)
 if 'adapter' in aid:return d.get('adapter')
 if 'campaign' in aid:return d.get('campaign_id')
 if 'host-id' in aid or aid.endswith('-host') or 'host_id indicator' in qt or 'host identifier' in qt:return d.get('host_id')
 if 'stage-count' in aid or 'stage_count' in qt:return d.get('stage_count')
 if 'steps' in aid or 'behavior graph' in qt or 'analysis steps' in qt:return str(d.get('steps','')).replace(',','>') if d.get('steps') is not None else None
 if 'host-profile' in aid or 'source container' in qt or 'script host' in qt:return d.get('host_profile')
 if 'obfuscation' in aid or 'encoding profile' in qt:return d.get('obfuscation_profile',d.get('obfuscation'))
 if 'stage-profile' in aid or 'relationship profile' in qt:return d.get('stage_profile')
 if 'next-language' in aid or 'next script language' in qt:return d.get('next_language')
 if 'next-stage' in aid or 'next_stage indicator' in qt or 'next-stage filename' in qt:return d.get('next_stage')
 if 'file-path' in aid or 'file_path indicator' in qt or 'output path' in qt or 'local path' in qt:return d.get('file_path')
 if 'upload-url' in aid or 'upload_url indicator' in qt:return d.get('upload_url',d.get('url'))
 if 'url' in aid or ' url ' in (' '+qt+' '):return d.get('url')
 if 'note-name' in aid or 'note_name indicator' in qt or 'recovery-note' in qt:return d.get('note_name')
 if 'extension' in aid or 'extension indicator' in qt:return d.get('extension')
 if 'cron-path' in aid:return d.get('cron_path')
 if 'schedule-path' in aid:return d.get('schedule_path')
 if 'service-name' in aid:return d.get('service_name')
 if 'handoff-id' in aid:return d.get('handoff_id')
 if 'campaign identifier' in qt:return d.get('campaign_id')
 if 'host profile' in qt:return d.get('host_profile')
 if 'carrier' in aid:return d.get('carrier')
 if 'windows-chain' in aid:return d.get('windows_chain')
 if 'syntax' in aid:return d.get('syntax')
 if 'feature' in aid:return d.get('feature')
 if 'primitive' in aid:return d.get('primitive')
 if 'graph' in aid or 'topology' in qt:return d.get('graph')
 if aid.endswith('-expansion'):
  f=q['artifact'].split(' -> ')[-1];s=(ROOT/f).read_text(errors='ignore')
  # Inspect only the recovered-descriptor assignment. Echo statements and
  # unrelated host/separator lines often use a different expansion style.
  m=re.search(r'(?im)^:HUNTRESS_INSPECT\s*$',s)
  block=s[m.end():] if m else s
  block=re.split(r'(?im)^:HUNTRESS_PLAN\s*$',block,maxsplit=1)[0]
  if re.search(r'(?im)^\s*set\s+"?recovered_configuration\s*=\s*%[^\r\n]*',block):return 'percent'
  if re.search(r'(?im)^\s*if\s+defined\s+\w+\s+set\s+"?\w+\s*=\s*%[^\r\n]*',block):return 'percent'
  if re.search(r'(?im)^\s*for\s+%%\w+\s+in\s*\([^\r\n]*\)\s+do\s+call\s+set\b',block):return 'for_indirect'
  if re.search(r'(?im)^\s*call\s+set\s+"?\w+\s*=\s*%%[^\r\n]*',block):return 'call_double'
  if re.search(r'(?i)call\s+set\s+[^\n]*(?:%%[A-Za-z_][\w]*%%|%%%%)',s):return 'call_double'
  if re.search(r'(?i)for\s+/[fF].*%%',s):return 'for_indirect'
  if re.search(r'(?i)for\s+%%',s) and re.search(r'(?i)call\s+set',s):return 'call_double'
  if re.search(r'![A-Za-z_][\w]*\d*!',s):return 'delayed'
  return 'percent'
 if aid.startswith('batch-') and aid.endswith('-control'):
  f=q['artifact'].split(' -> ')[-1];s=(ROOT/f).read_text(errors='ignore')
  m=re.search(r'(?im)^:HUNTRESS_INSPECT\s*$',s)
  block=s[m.end():] if m else s
  block=re.split(r'(?im)^:HUNTRESS_PLAN\s*$',block,maxsplit=1)[0]
  if re.search(r'(?i)for\s+%%\w+\s+in\s*\(\s*[^ )]+\s*\)\s+do\s+call\s+:',block):return 'for_once'
  if re.search(r'(?i)call\s+:HUNTRESS_RECOVER',block):return 'call_subroutine'
  if re.search(r'(?i)if\s+errorlevel',block):return 'errorlevel_guard'
  if re.search(r'(?i)if\s+defined\s+HUNTRESS_READY\s+set',block):return 'if_guard'
  if re.search(r'(?i)goto\s+:HUNTRESS_DISPATCH',block):return 'goto_dispatch'
  return 'direct'
 if aid.startswith('vbscript-') and (aid.endswith('-representation') or aid.endswith('-transform') or aid.endswith('-control')):
  f=q['artifact'].split(' -> ')[-1];s=(ROOT/f).read_text(errors='ignore')
  cm=re.search(r'Codec_[\w]+\s*=\s*[\"\']([^\"\']+)',s,re.I)
  if aid.endswith('-representation') and cm:return cm.group(1).split('|')[0]
  if aid.endswith('-transform') and cm and len(cm.group(1).split('|'))>1:return cm.group(1).split('|')[1]
  if aid.endswith('-control'):
   block=re.search(r'(?is)Function\s+Recover_[\s\S]*?End Function',s)
   pre=(block.group(0).split('Decode_')[0] if block else s)
   if re.search(r'(?i)On Error Resume Next',pre):return 'error_guard'
   if re.search(r'(?i)Select Case',pre):return 'select_case'
   if re.search(r'(?i)\bDo\b',pre):return 'do_once'
   if re.search(r'(?i)\bWhile\b',pre):return 'while_once'
   if re.search(r'(?i)\bFor\b',pre):return 'for_once'
   return 'direct'
 if 'advanced' in aid and 'role' in aid:return 'advanced_syntax'
 if 'advanced' in aid and 'attack' in aid:return 'T1059.004'
 return None

answers={}; missing=[]
for q in Q['questions']:
 f=q['artifact'].split(' -> ',1)[-1];d=desc[f]
 a=get_field(q,d)
 if a is None or a=='':missing.append(q)
 else:answers[q['id']]=str(a)
print('generated',len(answers),'of',len(Q['questions']),'missing',len(missing))
for q in missing[:80]:print('MISSING',q['id'],q['question'],q['artifact'],q['answer_format'])
pathlib.Path('/home/remnux/huntressCTF-2026/challenges/data/orphan-process-day18-candidate-answers.json').write_text(json.dumps(answers))
