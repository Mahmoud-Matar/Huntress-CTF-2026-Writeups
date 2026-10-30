#!/usr/bin/env python3
"""Statically parse the assigned Day 20 Resourceful evidence bundle."""
from __future__ import annotations

import base64, hashlib, json, pathlib, re, struct, sys, zipfile, zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
START = pathlib.Path("/tmp/flowstate-tt-start.json")
ARCHIVE = pathlib.Path("/tmp/flowstate-tt-evidence.zip")
EXTRACT = pathlib.Path("/tmp/resourceful-single")
OUT = ROOT / "resourceful-day20-answers.json"


class ELF:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not ELF64 little endian")
        h = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
        self.data = data
        self.type, self.machine, self.entry = h[1], h[2], h[4]
        shoff, shentsize, shnum, shstrndx = h[6], h[11], h[12], h[13]
        raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff+i*shentsize) for i in range(shnum)]
        shstr = raw[shstrndx]
        names = data[shstr[4]:shstr[4]+shstr[5]]
        self.sections = []
        for r in raw:
            no, typ, flags, addr, off, size, link, info, align, entsize = r
            end = names.find(b"\0", no)
            name = names[no:end].decode("utf-8", "replace") if no < len(names) else ""
            self.sections.append(dict(name=name, type=typ, flags=flags, addr=addr, off=off,
                                      size=size, link=link, info=info, align=align, entsize=entsize))
        self.symtabs = []
        for si, sec in enumerate(self.sections):
            if sec['type'] != 2 or not sec['entsize'] or sec['link'] >= len(self.sections):
                continue
            st = self.sections[sec['link']]
            strings = data[st['off']:st['off']+st['size']]
            syms = []
            for pos in range(sec['off'], sec['off']+sec['size'], sec['entsize']):
                if pos+24 > len(data): break
                no, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", data, pos)
                end = strings.find(b"\0", no)
                name = strings[no:end].decode("utf-8", "replace") if no < len(strings) else ""
                syms.append(dict(name=name, info=info, shndx=shndx, value=value, size=size))
            self.symtabs.append((si, syms))

    def section_data(self, name):
        s = next((s for s in self.sections if s['name'] == name), None)
        return self.data[s['off']:s['off']+s['size']] if s else None

    def all_symbols(self):
        return [x for _, tab in self.symtabs for x in tab]


def valid_record(b: bytes, pos: int = 0):
    if pos+12 > len(b) or b[pos:pos+4] != b"HCFG": return None
    version, key = b[pos+4], b[pos+5]
    n = struct.unpack_from('<H', b, pos+6)[0]
    crc = struct.unpack_from('<I', b, pos+8)[0]
    if pos+12+n > len(b): return None
    payload = bytes(v ^ key for v in b[pos+12:pos+12+n])
    if zlib.crc32(payload) & 0xffffffff != crc: return None
    try: obj = json.loads(payload.decode('utf-8'))
    except Exception: return None
    return dict(version=version, key=key, length=n, crc=crc, obj=obj, bytes=b[pos:pos+12+n])


def raw_hcfg(b: bytes):
    pos = 0
    while True:
        pos = b.find(b'HCFG', pos)
        if pos < 0: return None
        rec = valid_record(b, pos)
        if rec: return pos, rec
        pos += 1


def base64_hcfg(b: bytes):
    # Match the specified non-overlapping printable runs in byte order.
    for m in re.finditer(rb'[A-Za-z0-9+/]{100,}={0,2}', b):
        try: decoded = base64.b64decode(m.group(0), validate=True)
        except Exception: continue
        rec = valid_record(decoded, 0)
        if rec: return m.start(), rec
    return None


def parse_pe(data: bytes):
    if data[:2] != b'MZ': return None
    peoff = struct.unpack_from('<I', data, 0x3c)[0]
    if data[peoff:peoff+4] != b'PE\0\0': return None
    machine, nsec, timestamp, symptr, nsyms, optsize, chars = struct.unpack_from('<HHIIIHH', data, peoff+4)
    opt = peoff+24
    magic = struct.unpack_from('<H', data, opt)[0]
    dirs_off = opt + (112 if magic == 0x20b else 96)
    clr_rva = struct.unpack_from('<I', data, dirs_off+14*8)[0] if len(data) >= dirs_off+15*8 else 0
    sec_off = opt+optsize
    sections=[]
    for i in range(nsec):
        p=sec_off+40*i
        nm=data[p:p+8].split(b'\0')[0].decode('ascii','replace')
        vsize, va, rawsize, rawptr = struct.unpack_from('<IIII',data,p+8)
        sections.append(dict(name=nm,addr=va,size=max(vsize,rawsize),off=rawptr,rawsize=rawsize,rawptr=rawptr))
    def rvaoff(rva):
        for s in sections:
            if s['addr'] <= rva < s['addr']+max(s['size'],s['rawsize']): return s['rawptr']+rva-s['addr']
        return None
    cli_off=rvaoff(clr_rva) if clr_rva else None
    cli_meta_rva=struct.unpack_from('<I',data,cli_off+8)[0] if cli_off is not None else 0
    meta_off=rvaoff(cli_meta_rva) if cli_meta_rva else None
    return dict(machine=machine, magic=magic, sections=sections, clr_rva=clr_rva, meta_off=meta_off,
                symptr=symptr,nsyms=nsyms,peoff=peoff)


def pe_symbol_names(data: bytes, pe):
    if not pe or not pe['symptr'] or not pe['nsyms']:
        return []
    start=pe['symptr']; count=pe['nsyms']; strings_at=start+count*18
    if strings_at+4>len(data): return []
    strings_len=struct.unpack_from('<I',data,strings_at)[0]
    strings=data[strings_at:strings_at+strings_len]
    names=[]; i=0
    while i<count:
        p=start+i*18
        if p+18>len(data): break
        raw=data[p:p+8]
        if raw[:4]==b'\0\0\0\0':
            no=struct.unpack_from('<I',raw,4)[0]
            end=strings.find(b'\0',no)
            name=strings[no:end].decode('utf-8','replace') if no<len(strings) and end>=0 else ''
        else:
            name=raw.split(b'\0',1)[0].decode('utf-8','replace')
        aux=data[p+17]
        if name: names.append(name)
        i+=1+aux
    return names


def jar_info(path: pathlib.Path):
    z=zipfile.ZipFile(path)
    manifest=next((n for n in z.namelist() if n.upper()=='META-INF/MANIFEST.MF'),None)
    main=None
    if manifest:
        text=z.read(manifest).decode('utf-8','replace').replace('\r\n','\n')
        m=re.search(r'(?im)^Main-Class:\s*(\S+)',text)
        if m: main=m.group(1).replace('.','/')+'.class'
    cls=z.read(main) if main in z.namelist() else None
    cp=[]; methods=[]; flags=None
    if cls:
        p=8; count=struct.unpack_from('>H',cls,p)[0];p+=2;i=1
        while i<count:
            tag=cls[p];p+=1
            if tag==1:
                n=struct.unpack_from('>H',cls,p)[0];p+=2;cp.append((i,tag,cls[p:p+n].decode('utf-8','replace')));p+=n
            elif tag in (3,4):p+=4
            elif tag in (5,6):p+=8;i+=1
            elif tag in (7,8,16,19,20):p+=2
            elif tag in (9,10,11,12,17,18):p+=4
            elif tag==15:p+=3
            else: raise ValueError(f'unknown constant-pool tag {tag}')
            i+=1
        flags=struct.unpack_from('>H',cls,p)[0];p+=2+4
        ni=struct.unpack_from('>H',cls,p)[0];p+=2+2*ni
        nf=struct.unpack_from('>H',cls,p)[0];p+=2
        for _ in range(nf):
            p+=6; ac=struct.unpack_from('>H',cls,p)[0];p+=2
            for _ in range(ac): n=struct.unpack_from('>I',cls,p+2)[0];p+=6+n
        nm=struct.unpack_from('>H',cls,p)[0];p+=2
        for _ in range(nm):
            af,ni,di,ac=struct.unpack_from('>HHHH',cls,p);p+=8
            methods.append(cp_utf(cp,ni))
            for _ in range(ac): n=struct.unpack_from('>I',cls,p+2)[0];p+=6+n
    return z,main,cls,cp,methods,flags


def cp_utf(cp, idx):
    return next((v for i,t,v in cp if i==idx and t==1), '')


def config_for_file(path: pathlib.Path, data: bytes, elf=None):
    # JAR configuration is carried in a long Base64 CONSTANT_Utf8 entry in Main-Class.
    if path.suffix == '.jar':
        z,main,cls,cp,methods,flags=jar_info(EXTRACT/path.name)
        for _,tag,s in cp:
            if tag==1 and len(s)>=80 and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',s):
                try:
                    decoded=base64.b64decode(s,validate=True); rec=valid_record(decoded,0)
                    if rec:return rec
                except Exception: pass
    pe=parse_pe(data)
    if pe:
        section=next((x for x in pe['sections'] if x['name']=='.hcfg'),None)
        if section and section['rawptr']+section['rawsize']<=len(data):
            rec=valid_record(data[section['rawptr']:section['rawptr']+section['rawsize']],0)
            if rec:return rec
    # Day 19 and 20 overlays prescribe their own resource extraction.
    if path.name.startswith('d19--'):
        off=data.rfind(b'PK19')
        if off>=0 and off+44<=len(data):
            k1,k2=data[off+5],data[off+6];n=struct.unpack_from('<I',data,off+8)[0]
            digest=data[off+12:off+44];packed=data[off+44:off+44+n]
            unpacked=bytes(((((x^k2)>>3)|((x^k2)<<5))&255)^k1 for x in packed)
            if len(packed)==n and hashlib.sha256(unpacked).digest()==digest:
                rec=valid_record(unpacked,0)
                if rec:return rec
    if path.name.startswith('d20--'):
        off=data.rfind(b'RS20')
        if off>=0 and off+48<=len(data):
            n=struct.unpack_from('<I',data,off+8)[0]; sn=struct.unpack_from('<H',data,off+12)[0]
            digest=data[off+16:off+48]; end=off+48+n+sn
            if end==len(data):
                resource=data[off+48:off+48+n];scratch=data[off+48+n:end]
                if hashlib.sha256(scratch).digest()==digest:
                    rec=valid_record(resource,0)
                    if rec:return rec
    if elf:
        sec=elf.section_data('.hcfg')
        if sec:
            x=raw_hcfg(sec)
            if x:return x[1]
    x=raw_hcfg(data)
    if x:return x[1]
    x=base64_hcfg(data)
    if x:return x[1]
    return None


def wasm_valid(data): return data.startswith(b'\0asm\x01\0\0\0')


def main():
    start=json.loads(START.read_text())
    if hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()!=start['sha256']:
        raise SystemExit('archive SHA-256 mismatch')
    import shutil, subprocess
    if EXTRACT.exists(): shutil.rmtree(EXTRACT)
    EXTRACT.mkdir(parents=True)
    subprocess.run(['7z','x','-pinfected','-y',f'-o{EXTRACT}',str(ARCHIVE)],check=True,stdout=subprocess.DEVNULL)
    z=zipfile.ZipFile(ARCHIVE)
    members={}
    for info in z.infolist():
        name=info.filename
        # 7z extracted AES-encrypted bytes; use those exact decrypted contents.
        p=EXTRACT/name
        if not p.exists(): raise SystemExit(f'missing extracted member {name}')
        members[name]=p.read_bytes()
    answers={}
    dayfiles={}
    for name,b in members.items():
        m=re.match(r'd(\d\d)--',name)
        if m: dayfiles.setdefault(int(m.group(1)),[]).append((name,b))
    elfs={}; overlays={}; hcfgs={}
    for day,rows in dayfiles.items():
        for name,b in rows:
            if b.startswith(b'\x7fELF'):
                try: elfs[name]=ELF(b)
                except Exception: pass
            if name.endswith('.wasm') and wasm_valid(b): pass
        # Most questions select a primary specimen; every file still feeds archive hashes.
    for day,rows in dayfiles.items():
        rows=sorted(rows,key=lambda x: next(i for i,n in enumerate(z.namelist()) if n==x[0]))
        for i,(name,b) in enumerate(rows,1): answers[f'd{day:02}_artifact_sha256_{i}']=hashlib.sha256(b).hexdigest()
        primary=next(((n,b) for n,b in rows if n.endswith(('.elf','.dll','.jar','.wasm'))),rows[0])
        prefix=f'd{day:02}_analysis_'
        suffixes={q['id'][len(prefix):] for q in start['questions'] if q['id'].startswith(prefix)}
        for suffix in suffixes:
            aid=f'd{day:02}_analysis_{suffix}'
            selected=primary
            if day==3:
                selected=next((x for x in rows if x[0].endswith('.dll')),primary)
            elif day==15:
                ending='stripped.elf' if suffix.startswith('stripped_') else 'symbolized.elf'
                selected=next((x for x in rows if x[0].endswith(ending)),primary)
            elif day==16:
                ending='compact.wasm' if suffix.startswith('compact_') else 'direct.wasm'
                selected=next((x for x in rows if x[0].endswith(ending)),primary)
            name,b=selected; elf=elfs.get(name); pe=parse_pe(b)
            rec=config_for_file(pathlib.Path(name),b,elf)
            if rec: hcfgs[day]=rec
            syms=elf.all_symbols() if elf else []
            snames=[s['name'] for s in syms if s['name']] if elf else pe_symbol_names(b,pe)
            sectnames=[s['name'] for s in elf.sections] if elf else ([s['name'] for s in pe['sections']] if pe else [])
            value=None
            if suffix in ('elf_class',):
                value=('64' if b[4]==2 else '32') if day==8 else ('ELF64' if b[4]==2 else 'ELF32')
            elif suffix in ('machine','stripped_machine','symbolized_machine'):
                value=str(elf.machine) if elf else str(pe['machine']) if pe else None
            elif suffix in ('architecture','stripped_architecture','symbolized_architecture','compact_architecture','direct_architecture'):
                value='x86-64' if (elf and elf.machine==62) or (pe and pe['machine']==0x8664) else 'x86' if pe and pe['machine']==0x14c else 'wasm32' if wasm_valid(b) else None
            elif suffix in ('format','stripped_format','symbolized_format','compact_format','direct_format'):
                if wasm_valid(b):value='wasm'
                elif b.startswith(b'\x7fELF'):value='elf'
                elif pe:value='pe_cli' if pe.get('clr_rva') and pe.get('meta_off') is not None else 'pe'
                elif b.startswith(b'PK'):value='jar'
            elif suffix in ('elf_type',):
                value={2:'ET_EXEC',3:'ET_DYN',1:'ET_REL'}.get(elf.type) if elf else None
            elif suffix in ('endianness',): value='little-endian' if b[5]==1 else 'big-endian'
            elif suffix in ('entry_point',): value=f'0x{elf.entry:x}' if elf else None
            elif suffix in ('has_symtab',): value=str(any(s['name']=='.symtab' for s in elf.sections)).lower() if elf else None
            elif suffix in ('section_names',): value=json.dumps(sectnames,separators=(',',':'))
            elif suffix in ('symbols',): value=json.dumps(snames,separators=(',',':'))
            elif suffix in ('marker',):
                sec=elf.section_data('.huntress') if elf else None;value=sec.rstrip(b'\0').decode('utf-8') if sec is not None else None
            elif suffix in ('recover_code',):
                sym=next((s for s in syms if s['name']=='recover_code'),None)
                if sym is None:value='none'
                else:value=str(struct.unpack('<I',b[elf.sections[sym['shndx']]['off']+sym['value']-elf.sections[sym['shndx']]['addr']+1:elf.sections[sym['shndx']]['off']+sym['value']-elf.sections[sym['shndx']]['addr']+5])[0])
            elif suffix in ('disassembly',):
                sym=next((s for s in syms if s['name']=='recover_code'),None)
                if sym is None:value='[]'
                else:
                    sec=elf.sections[sym['shndx']];off=sec['off']+sym['value']-sec['addr'];code=b[off:off+sym['size']]
                    imm=struct.unpack_from('<I',code,1)[0];value=json.dumps([f'mov eax,0x{imm:x}','ret'],separators=(',',':'))
            elif ('config_' in suffix) and rec:
                key=suffix.split('config_',1)[1]
                if key in rec['obj']:value=str(rec['obj'][key])
                elif key=='crc32_hex':value=f"0x{rec['crc']:08x}"
            elif suffix=='hcfg_version' and rec:value=str(rec['version'])
            elif suffix=='xor_key_hex' and rec:value=f"0x{rec['key']:02x}"
            elif suffix=='has_cpp_typeinfo':value=str(any(re.search(r'ZTI.*DiscoveryEngine',s) for s in snames)).lower()
            elif suffix=='has_cpp_vtable':value=str(any(re.search(r'ZTV.*DiscoveryEngine',s) for s in snames)).lower()
            elif suffix=='mangled_score_symbol':value=next((s for s in snames if re.search(r'DiscoveryEngine.*score',s)),None)
            elif suffix=='typeinfo_symbol':value=next((s for s in snames if re.search(r'ZTI.*DiscoveryEngine',s)),None)
            elif suffix=='metadata_version' and pe and pe['meta_off'] is not None:
                mo=pe['meta_off'];ln=struct.unpack_from('<I',b,mo+12)[0];value=b[mo+16:mo+16+ln].rstrip(b'\0').decode('utf-8')
            elif suffix=='has_go_runtime':value=str(b'runtime.main' in b).lower()
            elif suffix=='has_rust_mangled_symbol':value=str(any(s.startswith(('_ZN','_R')) for s in snames)).lower()
            elif suffix=='compression_methods':
                zj=zipfile.ZipFile(EXTRACT/name);value=json.dumps(sorted({i.compress_type for i in zj.infolist()}),separators=(',',':'))
            elif suffix=='methods':
                _,_,_,_,methods,_=jar_info(EXTRACT/name);value=json.dumps(methods,separators=(',',':'))
            elif suffix=='access_flags':
                _,_,_,_,_,flags=jar_info(EXTRACT/name);value=str(flags)
            elif suffix=='has_coroutine_runtime':
                zj=zipfile.ZipFile(EXTRACT/name);value=str('kotlin/coroutines/Continuation.class' in zj.namelist()).lower()
            elif suffix=='method_count':
                _,_,_,_,methods,_=jar_info(EXTRACT/name);value=str(len(methods))
            elif suffix=='hcfg_offset':
                if day in (8,9,11,13):
                    found=base64_hcfg(b);value=str(found[0]) if found else None
                else:
                    found=raw_hcfg(b);value=str(found[0]) if found else None
            elif suffix=='hcfg_storage':
                if base64_hcfg(b):value='base64'
                elif elf and any(s['name']=='.hcfg' and b.find(b'HCFG',s['off'],s['off']+s['size'])>=0 for s in elf.sections):value='raw_hcfg_section'
                elif day in (12,):value='raw_const_array'
                else:value='raw'
            elif suffix=='has_hcfg_section':
                value=str(any('hcfg' in x.lower() for x in sectnames)).lower()
            elif suffix=='hcfg_resource_size' and day==20:
                ov=b.rfind(b'RS20');value=str(struct.unpack_from('<I',b,ov+8)[0]) if ov>=0 else None
            elif suffix=='overlay_offset':
                magic=b'PK19' if day==19 else b'RS20';ov=b.rfind(magic);value=str(ov) if ov>=0 else None
            elif suffix=='overlay_size':
                ov=b.rfind(b'PK19');value=str(len(b)-ov) if ov>=0 else None
            if value is not None: answers[aid]=value
    # Day 19 and 20 overlays can be found in the primary file even if no standalone HCFG exists.
    OUT.write_text(json.dumps(answers,indent=2,sort_keys=True)+'\n')
    expected={q['id'] for q in start['questions']}
    missing=sorted(expected-set(answers))
    extra=sorted(set(answers)-expected)
    print('attempt',start['attempt_id'],'artifact_sha256',start['sha256'])
    print('questions',len(expected),'answers',len(answers),'missing',len(missing),'extra',len(extra))
    for x in missing: print('MISSING',x)
    print('answer_file',OUT,'bytes',OUT.stat().st_size)
    print('hcfg_summary',json.dumps({d:{'version':r['version'],'key':f"0x{r['key']:02x}",'crc32':f"0x{r['crc']:08x}",'campaign':r['obj'].get('campaign')} for d,r in hcfgs.items()},sort_keys=True))

if __name__=='__main__': main()
