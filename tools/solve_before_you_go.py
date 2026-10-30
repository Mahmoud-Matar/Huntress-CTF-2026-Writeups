#!/opt/dissect/bin/python
"""Derive Day 26 metadata answers from assigned bytes, without specimen execution."""
import sys,json,hashlib,re,struct,zipfile,pathlib
import solve_main_character_energy as old
from dissect.util import lzxpress_huffman
from dissect.regf.regf import RegistryHive


_wav=old.wav_codec

def codec(path):
 b=path.read_bytes()
 if b[:4]==b'RIFF':return _wav(path)
 if b[:3]==b'ID3' or any(b[i:i+2] in (b'\xff\xfb',b'\xff\xf3',b'\xff\xf2') for i in range(min(64,len(b)-1))):return 'mp3'
 fmt=old.exif(path,'AudioFormat')
 if fmt=='mp4a':return 'aac'
 if fmt=='alac':return 'alac'
 if b[:4]==b'fLaC':return 'flac'
 if b'OpusHead' in b:return 'opus'
 if b'vorbis' in b:return 'vorbis'
 raise ValueError(('Unsupported audio',fmt))
old.wav_codec=codec
_macho=old.macho_cpu

def macho(path):
 b=path.read_bytes()
 if b[:4] in [bytes.fromhex('cafebabe'),bytes.fromhex('cafebabf')]:
  n=struct.unpack_from('>I',b,4)[0];step=32 if b[:4]==bytes.fromhex('cafebabf') else 20
  return json.dumps(sorted(set(f"0x{struct.unpack_from('>I',b,8+step*i)[0]:08x}" for i in range(n))),separators=(',',':'))
 return _macho(path)
old.macho_cpu=macho

def prefetch(path):
 b=path.read_bytes()
 if b[:4]==b'MAM\x04':
  size=struct.unpack_from('<I',b,4)[0];b=lzxpress_huffman.decompress(b[8:])[:size]
 assert b[4:8]==b'SCCA'
 return b[16:76].decode('utf-16-le').split('\0')[0]


def evtx_count(path):
 b=path.read_bytes();assert b[:8]==b'ElfFile\0';count=0
 for start in range(4096,len(b),65536):
  chunk=b[start:start+65536]
  if chunk[:8]!=b'ElfChnk\0':continue
  end=struct.unpack_from('<I',chunk,48)[0];pos=512
  while pos+28<=end:
   sig,size=struct.unpack_from('<II',chunk,pos)
   if sig!=0x2a2a:break
   assert size>=28 and pos+size<=end
   assert struct.unpack_from('<I',chunk,pos+size-4)[0]==size
   count+=1;pos+=size
 return str(count)


def solve(start,root):
 answers={}
 for q in start['questions']:
  key=q['id'];setnum=q.get('set');base=root/(f'set{setnum}' if setnum else 'tt')
  localid=key.split('.',1)[1] if key.startswith('set') else key
  if ' -> ' in q['artifact']:name=q['artifact'].split(' -> ')[-1];p=base/name;b=p.read_bytes()
  else:name=None
  text=q['question'];fmt=q['answer_format']['kind']
  if localid.endswith('-filename') and not localid.startswith('d'):
   stem={'roster-filename':'roster-','evidence-note-filename':'evidence-note-','evidence-note-copy-filename':'evidence-note-copy-'}[localid]
   candidates=[p.name for p in base.iterdir() if p.name.startswith(stem) and not (stem=='evidence-note-' and p.name.startswith('evidence-note-copy-'))];assert len(candidates)==1;c=candidates[0]
  elif not localid.startswith('d') and 'synthesis' not in localid:
   if localid.endswith('size-bytes'):c=str(len(b))
   elif localid.endswith('-md5'):c=hashlib.md5(b).hexdigest()
   elif localid.endswith('-sha1'):c=hashlib.sha1(b).hexdigest()
   elif localid.endswith('-sha256'):c=hashlib.sha256(b).hexdigest()
   elif 'magic-prefix' in localid:c=b[:16].hex()
   elif 'bom-present' in localid:c=str(b.startswith(b'\xef\xbb\xbf')).lower()
   else:raise ValueError(key)
  elif 'synthesis' in localid:
   names=json.loads(text.split('Files: ',1)[1]);c=json.dumps(sorted(names,key=lambda n:hashlib.sha256((base/n).read_bytes()).hexdigest()),separators=(',',':'))
  else:
   if not hasattr(solve,'cache'):solve.cache={}
   if str(base) not in solve.cache:
    # Legacy extractor expects canonical names. Use an isolated alias directory.
    alias=base/'_aliases';alias.mkdir(exist_ok=True)
    for src in base.iterdir():
     if src.is_file():
      dest=src.name
      for stem in ['evidence-note-copy','evidence-note','roster']:
       if re.fullmatch(stem+r'-[0-9a-f]+\.(txt|csv)',dest):dest=stem+src.suffix;break
      target=alias/dest
      if not target.exists():target.symlink_to(src.resolve())
    # Some mastery sets omit the roster when no question or synthesis entry
    # uses it. one_set reads it to build a complete value dictionary, so add an
    # empty placeholder only to the temporary alias directory; it is never an
    # answer source for a set that lacks the roster.
    if not (alias/'roster.csv').exists(): (alias/'roster.csv').write_bytes(b'')
    values=old.one_set(alias)
    zkey="d07-zip-001-zip-central-directory-member-names"
    values[zkey]=json.dumps(sorted(json.loads(values[zkey])),separators=(",",":"))
    values.update({'d23-sqlite-001-sqlite-page-size-bytes':str(65536 if struct.unpack_from('>H',(base/'database-001.sqlite').read_bytes(),16)[0]==1 else struct.unpack_from('>H',(base/'database-001.sqlite').read_bytes(),16)[0]),'d24-evtx-001-evtx-record-count':evtx_count(base/'events-001.evtx'),'d25-registry-001-registry-hive-root-name':RegistryHive((base/'hive-001.hiv').open('rb')).root().name,'d26-prefetch-001-prefetch-executable-name':prefetch(base/'trace-001.pf')})
    solve.cache[str(base)]=values
   c=solve.cache[str(base)][localid]
  answers[key]=str(c)
 assert set(answers)==set(start['answer_ids'])
 return answers

if __name__=='__main__':
 start=json.loads(pathlib.Path(sys.argv[1]).read_text());root=pathlib.Path(sys.argv[2]);out=pathlib.Path(sys.argv[3]);a=solve(start,root);out.write_text(json.dumps(a,indent=2));print(json.dumps(a,indent=2))
