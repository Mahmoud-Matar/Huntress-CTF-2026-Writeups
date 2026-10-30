#!/usr/bin/env python3
"""Derive Crash Course answers statically from verified assigned files."""
import base64,hashlib,json,pathlib,re,struct,sys,zipfile
import solve_trust_issues as s

def all_jar_hcfg(path):
 with zipfile.ZipFile(path) as j:
  for n in j.namelist():
   if not n.endswith('.class'):continue
   for t in s.class_info(j.read(n))['utf8']:
    if len(t)<80 or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',t):continue
    try:h=s.valid_hcfg(base64.b64decode(t,validate=True),0)
    except Exception:continue
    if h:return h
 raise ValueError('no valid classfile HCFG')

def solve(startpath,archive,root,out):
 start=json.load(open(startpath));s.ROOT=pathlib.Path(root)
 with zipfile.ZipFile(archive) as z: names=z.namelist()
 s.member_orders={f'd{d:02}':[n for n in names if n.startswith(f'd{d:02}--')] for d in range(1,27)}
 answers={};missing=[]
 for q in start['questions']:
  aid=q['id'];day=aid[:3];b=None;v=None
  try:
   selector='corrected' if '_corrected_' in aid else 'vulnerable'
   if day in ('d24','d25','d26'):
    fn=next(n for n in s.member_orders[day] if day=='d26' or selector in n);p=s.ROOT/fn;b=p.read_bytes()
    h=all_jar_hcfg(p)
    if day in ('d24','d25'):
     other=next(n for n in s.member_orders[day] if n!=fn);assert h['obj']==all_jar_hcfg(s.ROOT/other)['obj']
    if '_artifact_sha256_' in aid:v=hashlib.sha256((s.ROOT/s.member_orders[day][int(aid.rsplit('_',1)[1])-1]).read_bytes()).hexdigest()
    elif aid.endswith('_format'):v='jar'
    elif '_config_' in aid and aid.rsplit('_',1)[1] in ('campaign','domain','mutex','url'):v=h['obj'][aid.rsplit('_',1)[1]]
    elif aid.endswith('_config_crc32_hex'):v=f"0x{h['crc']:08x}"
    elif aid.endswith('_hcfg_version'):v=str(h['version'])
    elif aid.endswith('_xor_key_hex'):v=f"0x{h['key']:02x}"
    else:
     with zipfile.ZipFile(p) as j:
      manifest=j.read('META-INF/MANIFEST.MF').decode();cf=re.search(r'Main-Class:\s*([^\r\n]+)',manifest)[1].replace('.','/')+'.class';ci=s.class_info(j.read(cf));tr=json.loads(j.read('crash/trace.json'))
      if aid.endswith('_crash_fault_method'):v=tr['frames'][0]
      elif aid.endswith('_crash_frames_match_methods'):v=str(all(f in ci['methods'] for f in tr['frames'])).lower()
      elif aid.endswith('_method_count'):v=str(ci['method_count'])
   elif day=='d20' and ('_config_' in aid or aid.endswith(('_hcfg_version','_hcfg_resource_size','_overlay_offset'))):
    b=(s.ROOT/s.member_orders[day][0]).read_bytes();off=b.rfind(b'RS20');rn=struct.unpack_from('<I',b,off+8)[0];sn=struct.unpack_from('<H',b,off+12)[0];cfg=b[off+48:off+48+rn];scratch=b[off+48+rn:];assert len(scratch)==sn and hashlib.sha256(scratch).digest()==b[off+16:off+48];h=s.valid_hcfg(cfg,0);assert h
    if aid.endswith('_overlay_offset'):v=str(off)
    elif aid.endswith('_hcfg_resource_size'):v=str(rn)
    elif aid.endswith('_hcfg_version'):v=str(h['version'])
    elif aid.endswith('_config_crc32_hex'):v=f"0x{h['crc']:08x}"
    else:v=h['obj'][aid.rsplit('_',1)[1]]
   elif aid.endswith('_metadata_version') or (day in ('d03','d22','d23') and aid.endswith('_format')):
    b=(s.ROOT/s.member_for(day)).read_bytes();pe=s.PE(b);v=pe.metadata_version() if aid.endswith('_metadata_version') else 'pe_cli'
   else:v=s.answer_one(q)
   if v is None:raise ValueError('unmapped')
   if q['answer_format']['kind']=='integer':v=int(v)
   answers[aid]=v
  except Exception as e:missing.append((aid,str(e)))
 pathlib.Path(out).write_text(json.dumps(answers,indent=2)+'\n');print(json.dumps({'questions':len(start['questions']),'answers':len(answers),'missing':missing}))
 return answers,missing
if __name__=='__main__':solve(*sys.argv[1:])
