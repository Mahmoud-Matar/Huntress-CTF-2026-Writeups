#!/usr/bin/env python3
"""Statically derive Shared Custody answers from its exact assigned ZIP bytes.

Designed to run beside the assigned archive. It does not execute challenge files.
"""
import base64, hashlib, json, re, struct, sys, zipfile, zlib

ARCH={3:'x86',40:'ARM',62:'x86-64',183:'AArch64',243:'RISC-V'}

def uleb(b,p):
    n=s=0
    while True:
        x=b[p]; p+=1; n|=(x&127)<<s
        if not x&128:return n,p
        s+=7

def parse_elf(b):
    if b[:4]!=b'\x7fELF': return None
    cls=b[4]; e='<' if b[5]==1 else '>'
    if cls==2:
        h=struct.unpack_from(e+'HHIQQQIHHHHHH',b,16); typ,mach,ver,entry,phoff,shoff,flags,ehsize,phents,phnum,shents,shnum,shstr=h
        sf=e+'IIQQQQIIQQ'
    else:
        h=struct.unpack_from(e+'HHIIIIIHHHHHH',b,16); typ,mach,ver,entry,phoff,shoff,flags,ehsize,phents,phnum,shents,shnum,shstr=h
        sf=e+'IIIIIIIIII'
    raw=[]
    for i in range(shnum):
        x=struct.unpack_from(sf,b,shoff+i*shents)
        if cls==2: no,st,fl,addr,off,size,link,info,al,ent=x
        else: no,st,fl,addr,off,size,link,info,al,ent=x
        raw.append(dict(no=no,type=st,flags=fl,addr=addr,off=off,size=size,link=link,info=info,ent=ent))
    names=b''
    if shstr<len(raw):
        s=raw[shstr]; names=b[s['off']:s['off']+s['size']]
    for s in raw:
        p=s['no']; z=names.find(b'\0',p) if p<len(names) else -1
        s['name']=names[p:z if z>=0 else len(names)].decode('latin1') if p<len(names) else ''
    secs=[]
    for s in raw:
        q=dict(s); q['data']=b[q['off']:q['off']+q['size']] if q['off']+q['size']<=len(b) else b''; secs.append(q)
    syms=[]
    for i,s in enumerate(raw):
        if s['type']!=2 or s['link']>=len(raw):continue
        st=raw[s['link']]; strings=b[st['off']:st['off']+st['size']]
        ent=s['ent'] or (24 if cls==2 else 16)
        for p in range(s['off'],s['off']+s['size'],ent):
            try:
                if cls==2: no,info,other,ndx,val,size=struct.unpack_from(e+'IBBHQQ',b,p)
                else: no,val,size,info,other,ndx=struct.unpack_from(e+'IIIBBH',b,p)
            except struct.error:continue
            z=strings.find(b'\0',no) if no<len(strings) else -1
            name=strings[no:z if z>=0 else len(strings)].decode('latin1') if no<len(strings) else ''
            syms.append(dict(name=name,info=info,ndx=ndx,val=val,size=size))
    return dict(cls=cls,typ=typ,mach=mach,entry=entry,sections=secs,symbols=syms)

def parse_pe(b):
    if b[:2]!=b'MZ' or len(b)<0x40:return None
    pe=struct.unpack_from('<I',b,0x3c)[0]
    if b[pe:pe+4]!=b'PE\0\0':return None
    mach,nsec,_,symptr,nsyms,optsz,_=struct.unpack_from('<HHIIIHH',b,pe+4)
    op=pe+24; magic=struct.unpack_from('<H',b,op)[0]
    dd=op+(96 if magic==0x10b else 112)
    cli_rva,cli_size=struct.unpack_from('<II',b,dd+14*8) if dd+15*8<=op+optsz else (0,0)
    sh=op+optsz; rawsecs=[]
    stptr=symptr+nsyms*18 if symptr and nsyms else 0
    strtab=b[stptr:] if stptr and stptr+4<=len(b) else b''
    strsz=struct.unpack_from('<I',strtab)[0] if len(strtab)>=4 else 0
    for i in range(nsec):
        x=b[sh+i*40:sh+(i+1)*40]
        if len(x)<40:break
        nm=x[:8].rstrip(b'\0').decode('latin1'); vs,va,rs,ro=struct.unpack_from('<IIII',x,8)
        if nm.startswith('/') and nm[1:].isdigit():
            off=int(nm[1:]); z=strtab.find(b'\0',off, min(len(strtab),strsz))
            if z>=0:nm=strtab[off:z].decode('latin1')
        rawsecs.append(dict(name=nm,va=va,vsize=vs,off=ro,size=rs,flags=struct.unpack_from('<I',x,36)[0]))
    def rva(r):
        for s in rawsecs:
            if s['va']<=r<s['va']+max(s['vsize'],s['size']):return s['off']+(r-s['va'])
        return r
    symbols=[]
    if symptr and nsyms and stptr+4<=len(b):
        i=0
        while i<nsyms:
            p=symptr+i*18
            if p+18>len(b):break
            n=b[p:p+8]
            if n[:4]==b'\0\0\0\0':
                off=struct.unpack_from('<I',n,4)[0]; z=strtab.find(b'\0',off,min(len(strtab),strsz)); name=strtab[off:z].decode('latin1') if z>=0 and off<len(strtab) else ''
            else:name=n.split(b'\0',1)[0].decode('latin1')
            aux=b[p+17]
            if name:symbols.append(name)
            i+=1+aux
    cli=None; metadata=None
    if cli_rva:
        cp=rva(cli_rva)
        if cp+16<=len(b):
            md_rva,md_size=struct.unpack_from('<II',b,cp+8); metadata=rva(md_rva)
            cli=dict(off=cp,size=cli_size,metadata=metadata,metadata_size=md_size)
    return dict(mach=mach,magic=magic,sections=rawsecs,symbols=symbols,cli=cli,metadata=metadata,rva=rva)

def valid_hcfg(x):
    if len(x)<12 or x[:4]!=b'HCFG':return None
    n=struct.unpack_from('<H',x,6)[0]; crc=struct.unpack_from('<I',x,8)[0]
    if 12+n>len(x):return None
    payload=bytes(c^x[5] for c in x[12:12+n])
    if zlib.crc32(payload)&0xffffffff!=crc:return None
    try: obj=json.loads(payload.decode('utf8'))
    except Exception:return None
    return dict(obj=obj,version=x[4],key=x[5],crc=crc,payload=payload)

def find_hcfg(b):
    # Required priority: literal carriers first, then non-overlapping Base64 runs.
    p=0
    while True:
        p=b.find(b'HCFG',p)
        if p<0:break
        h=valid_hcfg(b[p:])
        if h:return p,'raw',h
        p+=1
    text=b.decode('latin1')
    for m in re.finditer(r'[A-Za-z0-9+/]{100,}={0,2}',text):
        try:d=base64.b64decode(m.group(0),validate=True)
        except Exception:continue
        h=valid_hcfg(d)
        if h:return m.start(),'base64',h
    return None,None,None

def config_from_section(b,elf):
    for s in elf['sections']:
        if s['name']=='.hcfg':
            h=valid_hcfg(s['data'])
            if h:return s['off'],h,s
    return None,None,None

def wasm_sections(b):
    if b[:4]!=b'\0asm':return []
    p=8; out=[]
    while p<len(b):
        sid=b[p]; p+=1; n,p=uleb(b,p); start=p; end=p+n
        if end>len(b):break
        out.append((sid,b[start:end],start)); p=end
    return out

def wasm_data(b):
    for sid,sec,start in wasm_sections(b):
        if sid!=11:continue
        p=0; count,p=uleb(sec,p); segs=[]
        for _ in range(count):
            flags,p=uleb(sec,p)
            if flags==2: _,p=uleb(sec,p)
            if flags!=1:
                op=sec[p];p+=1
                if op==0x41:_,p=uleb(sec,p)
                elif op==0x42:
                    while sec[p]&0x80:p+=1
                    p+=1
                elif op not in (0x23,):pass
                if sec[p]==0x0b:p+=1
            n,p=uleb(sec,p); segs.append(sec[p:p+n]);p+=n
        return segs
    return []

def class_info(b):
    if b[:4]!=b'\xca\xfe\xba\xbe':return None
    p=8; count=struct.unpack_from('>H',b,8)[0]; p=10; cp=[None]*count; i=1
    while i<count:
        t=b[p];p+=1
        if t==1:
            n=struct.unpack_from('>H',b,p)[0];p+=2;cp[i]=b[p:p+n].decode('utf8','replace');p+=n
        elif t in (3,4):p+=4
        elif t in (5,6):p+=8;i+=1
        elif t in (7,8,16,19,20):cp[i]=struct.unpack_from('>H',b,p)[0];p+=2
        elif t in (9,10,11,12,17,18):p+=4
        elif t==15:p+=3
        else:raise ValueError('class cp tag '+str(t))
        i+=1
    access,this,super_=struct.unpack_from('>HHH',b,p);p+=6
    ni=struct.unpack_from('>H',b,p)[0];p+=2+ni*2
    nf=struct.unpack_from('>H',b,p)[0];p+=2
    for _ in range(nf):
        p+=6;ac=struct.unpack_from('>H',b,p)[0];p+=2
        for z in range(ac):n=struct.unpack_from('>I',b,p+2)[0];p+=6+n
    nm=struct.unpack_from('>H',b,p)[0];p+=2; methods=[]
    for _ in range(nm):
        af,ni,di,ac=struct.unpack_from('>HHHH',b,p);p+=8
        methods.append(cp[ni] if ni<len(cp) else '')
        for z in range(ac):n=struct.unpack_from('>I',b,p+2)[0];p+=6+n
    return {'access':access,'methods':methods,'cp':cp}

def jar_info(b):
    import io
    z=zipfile.ZipFile(io.BytesIO(b)); names=z.namelist(); methods=sorted(set(i.compress_type for i in z.infolist()))
    mf=next((n for n in names if n.upper()=='META-INF/MANIFEST.MF'),None)
    main=''
    if mf:
        txt=z.read(mf).decode('utf8','replace').replace('\r\n','\n')
        m=re.search(r'(?im)^Main-Class:\s*([^\n]+)',txt); main=m.group(1).strip().replace('.','/')+'.class' if m else ''
    clsname=main if main in names else next((n for n in names if n.endswith('.class')),None)
    cb=z.read(clsname) if clsname else b''; ci=class_info(cb) if cb else None
    h=None
    if ci:
        for s in ci['cp']:
            if isinstance(s,str) and len(s)>=80 and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',s):
                try:d=base64.b64decode(s,validate=True)
                except Exception:continue
                h=valid_hcfg(d)
                if h:break
    return z,names,methods,clsname,ci,h

def machine_name(n):return ARCH.get(n,str(n))

def main(archive,startfile,outfile):
    import pyzipper
    start=json.load(open(startfile)); qs=start['questions']; answers={}
    with pyzipper.AESZipFile(archive) as z:
        z.setpassword(b'infected')
        allnames=z.namelist()
        for day in range(1,22):
            pref=f'd{day:02d}--'; names=[n for n in allnames if n.startswith(pref)]
            if not names: raise ValueError('no members '+pref)
            blobs=[z.read(n) for n in names]; b=blobs[0];
            for q in qs:
                aid=q['id'];
                if not aid.startswith(f'd{day:02d}_'):continue
                key=aid[len(f'd{day:02d}_'):]; value=None; variant=None
                if key.startswith('analysis_'):key=key[len('analysis_'):]
                for prefix in ('stripped','symbolized','compact','direct','plugin'):
                    if key.startswith(prefix+'_'):
                        variant=prefix; key=key[len(prefix)+1:]; break
                el=parse_elf(b); pe=parse_pe(b)
                if key.startswith('artifact_sha256_'):
                    idx=int(key.rsplit('_',1)[1])-1; value=hashlib.sha256(blobs[idx]).hexdigest()
                elif key in ('elf_class',):value=(64 if el['cls']==2 else 32) if day==8 else ('ELF64' if el['cls']==2 else 'ELF32')
                elif key in ('machine','loader_machine','plugin_machine'):
                    target=b
                    if key=='loader_machine':target=next(x for n,x in zip(names,blobs) if n.endswith('loader.elf'))
                    if key=='plugin_machine':target=next(x for n,x in zip(names,blobs) if n.endswith('plugin.cmxs'))
                    if day==21 and variant=='plugin':target=next(x for n,x in zip(names,blobs) if n.endswith('plugin.cmxs'))
                    ee=parse_elf(target); pp=parse_pe(target); value=str(ee['mach'] if ee else pp['mach'])
                elif key in ('architecture','stripped_architecture','symbolized_architecture','compact_architecture','direct_architecture'):
                    nm=key.replace('_architecture',''); target=b
                    if variant in ('stripped','symbolized','compact','direct'):
                        nm=variant
                        target=next(x for n,x in zip(names,blobs) if n.endswith(nm+('.wasm' if nm in ('compact','direct') else '.elf')))
                    ee=parse_elf(target); pp=parse_pe(target)
                    value='wasm32' if target[:4]==b'\0asm' else ('x86-64' if (ee['mach'] if ee else pp['mach'])==62 else machine_name(ee['mach'] if ee else pp['mach']))
                elif key in ('format','stripped_format','symbolized_format','compact_format','direct_format'):
                    nm=key.replace('_format',''); target=b
                    if variant in ('stripped','symbolized','compact','direct'):
                        nm=variant
                        target=next(x for n,x in zip(names,blobs) if n.endswith(nm+('.wasm' if nm in ('compact','direct') else '.elf')))
                    if target[:4]==b'\x7fELF':value='elf'
                    elif target[:2]==b'MZ':value='pe_cli' if (parse_pe(target) or {}).get('cli') else 'pe'
                    elif target[:4]==b'\0asm':value='wasm'
                    elif target[:4]==b'\xca\xfe\xba\xbe':value='neko_bytecode'
                    elif target[:2]==b'PK':value='jar'
                elif key=='section_names':
                    if el:value=json.dumps([s['name'] for s in el['sections']],separators=(',',':'))
                    elif pe:value=json.dumps([s['name'] for s in pe['sections']],separators=(',',':'))
                elif key=='elf_type' and el:value={1:'ET_REL',2:'ET_EXEC',3:'ET_DYN',4:'ET_CORE'}.get(el['typ'],str(el['typ']))
                elif key=='endianness' and el:value='little endian' if b[5]==1 else 'big endian'
                elif key=='entry_point' and el:value=hex(el['entry'])
                elif key=='has_symtab' and el:value=str(any(s['name']=='.symtab' for s in el['sections'])).lower()
                elif key=='symbols' and el:value=json.dumps([s['name'] for s in el['symbols'] if s['name']],separators=(',',':'))
                elif key=='marker' and el:
                    s=next(s for s in el['sections'] if s['name']=='.huntress');value=s['data'].rstrip(b'\0').decode('utf8')
                elif key in ('disassembly','recover_code') and el:
                    sym=next((s for s in el['symbols'] if s['name']=='recover_code'),None)
                    if key=='recover_code':value=str(struct.unpack_from('<I',b, next(s['off'] for s in el['sections'] if s['addr']<=sym['val']<s['addr']+s['size'])+(sym['val']-next(s['addr'] for s in el['sections'] if s['addr']<=sym['val']<s['addr']+s['size']))+1)[0]) if sym else 'none'
                    else:
                        if sym:
                            sec=next(s for s in el['sections'] if s['addr']<=sym['val']<s['addr']+s['size']); p=sec['off']+sym['val']-sec['addr']; raw=b[p:p+sym['size']]
                            if raw[:1]==b'\xb8' and raw[5:6]==b'\xc3': value=json.dumps([f'mov eax,0x{struct.unpack_from("<I",raw,1)[0]:x}','ret'],separators=(',',':'))
                            else:value='[]'
                        else:value='[]'
                elif key in ('config_campaign','config_domain','config_mutex','config_url','config_crc32_hex','hcfg_version','xor_key_hex','hcfg_offset','hcfg_storage','has_hcfg_section','hcfg_resource_size','overlay_offset','overlay_size'):
                    target=b
                    if variant in ('stripped','symbolized'):target=next(x for n,x in zip(names,blobs) if n.endswith(variant+'.elf'))
                    if variant in ('compact','direct'):target=next(x for n,x in zip(names,blobs) if n.endswith(variant+'.wasm'))
                    if day==21:target=next(x for n,x in zip(names,blobs) if n.endswith('plugin.cmxs'))
                    ee=parse_elf(target); pp=parse_pe(target); off=None; h=None; storage=None
                    if day==19:
                        pos=target.rfind(b'PK19');off=pos
                        if pos>=0:
                            k1,k2=target[pos+5],target[pos+6]; n=struct.unpack_from('<I',target,pos+8)[0]; expected=target[pos+12:pos+44]; packed=target[pos+44:pos+44+n]
                            unpack=bytes((((x^k2)>>3)|((x^k2)<<5))&255 ^ k1 for x in packed)
                            if hashlib.sha256(unpack).digest()==expected:h=valid_hcfg(unpack); storage='raw'
                    elif day==20:
                        pos=target.rfind(b'RS20');off=pos
                        if pos>=0:
                            rn=struct.unpack_from('<I',target,pos+8)[0]; sn=struct.unpack_from('<H',target,pos+12)[0]; sh=target[pos+16:pos+48]; cfg=target[pos+48:pos+48+rn]; scratch=target[pos+48+rn:pos+48+rn+sn]
                            if len(scratch)==sn and pos+48+rn+sn==len(target) and hashlib.sha256(scratch).digest()==sh:h=valid_hcfg(cfg);storage='raw'
                    elif day==6 or day==7:
                        jz,jn,jm,cn,ci,h=jar_info(target); off=None
                    elif day==16:
                        segs=wasm_data(target); h=None
                        for seg in segs:
                            zpos=seg.find(b'HCFG')
                            if zpos>=0 and (hh:=valid_hcfg(seg[zpos:])):h=hh;off=target.find(seg)+zpos;storage='wasm_data_segment';break
                    elif day==8:
                        off,storage,h=find_hcfg(target)
                        if h and storage=='raw':
                            sec=next((s for s in ee['sections'] if s['off']<=off<s['off']+s['size']),None) if ee else None
                            if sec and sec['name']=='.hcfg':storage='raw_hcfg_section'
                    elif ee:
                        off,h,sec=config_from_section(target,ee)
                        if h:storage='raw_hcfg_section'
                    if h is None and day not in (6,7,8,16,19,20):off,storage,h=find_hcfg(target)
                    if h and storage=='raw' and ee and key=='hcfg_storage':
                        sec=next((s for s in ee['sections'] if s['off']<=off<s['off']+s['size']),None)
                        if sec and sec['name']=='.hcfg':storage='raw_hcfg_section'
                        elif sec:
                            va=sec['addr']+off-sec['off']; ptr=struct.pack('<Q' if ee['cls']==2 else '<I',va)
                            if any(ptr in s['data'] for s in ee['sections'] if s['flags']&4):storage='raw_const_array'
                    if key=='config_campaign' and h:value=h['obj'].get('campaign')
                    elif key=='config_domain' and h:value=h['obj'].get('domain')
                    elif key=='config_mutex' and h:value=h['obj'].get('mutex')
                    elif key=='config_url' and h:value=h['obj'].get('url')
                    elif key=='config_crc32_hex' and h:value=f"0x{h['crc']:08x}"
                    elif key=='hcfg_version' and h:value=str(h['version'])
                    elif key=='xor_key_hex' and h:value=f"0x{h['key']:02x}"
                    elif key=='hcfg_offset' and off is not None:value=str(off)
                    elif key=='hcfg_storage':
                        if storage is None and h:storage='raw'
                        value=storage
                    elif key=='has_hcfg_section' and (ee or pp):
                        sections=ee['sections'] if ee else pp['sections']; value=str(any(s['name']=='.hcfg' for s in sections)).lower()
                    elif key=='hcfg_resource_size' and day==20:value=str(rn)
                    elif key=='overlay_offset' and off is not None:value=str(off)
                    elif key=='overlay_size' and off is not None:value=str(len(target)-off)
                elif key=='format' and day in (6,7):value='JAR'
                elif key=='compression_methods' and day in (6,7):
                    ji=jar_info(b); value=json.dumps(ji[2],separators=(',',':'))
                elif key=='methods' and day==6:
                    ji=jar_info(b);value=json.dumps(ji[4]['methods'],separators=(',',':'))
                elif key=='access_flags' and day==6:
                    ji=jar_info(b);value=str(ji[4]['access'])
                elif key=='has_coroutine_runtime' and day==7:value=str(any(n=='kotlin/coroutines/Continuation.class' for n in jar_info(b)[1])).lower()
                elif key=='method_count' and day==7:value=str(len(jar_info(b)[4]['methods']))
                elif key=='has_go_runtime' and day==4:value=str(b'runtime.main' in b).lower()
                elif key=='has_rust_mangled_symbol' and day==5:value=str(bool(el and any(s['name'].startswith(('_ZN','_R')) for s in el['symbols'] if s['name']))).lower()
                elif key=='has_cpp_typeinfo' and day==2:
                    syms=[s['name'] for s in el['symbols']] if el else (pe['symbols'] if pe else []); value=str(any(re.search(r'ZTI.*DiscoveryEngine',n) for n in syms if n)).lower()
                elif key=='has_cpp_vtable' and day==2:
                    syms=[s['name'] for s in el['symbols']] if el else (pe['symbols'] if pe else []); value=str(any(re.search(r'ZTV.*DiscoveryEngine',n) for n in syms if n)).lower()
                elif key in ('mangled_score_symbol','typeinfo_symbol') and day==2:
                    syms=[s['name'] for s in el['symbols']] if el else (pe['symbols'] if pe else []); pat='DiscoveryEngine.*score' if key=='mangled_score_symbol' else 'ZTI.*DiscoveryEngine'; value=next((n for n in syms if n and re.search(pat,n)),None)
                elif key=='metadata_version' and day==3 and pe and pe['metadata']:
                    md=pe['metadata']; ln=struct.unpack_from('<I',b,md+12)[0];value=b[md+16:md+16+ln].rstrip(b'\0').decode('utf8')
                elif key=='format' and day==3:value='PE32+_CLR' if pe and pe['magic']==0x20b else 'PE32_CLR'
                elif key=='format' and day in (4,5,8,9,10,11,12,13):value='ELF64' if el and el['cls']==2 else 'ELF32'
                if value is None: raise ValueError('unmapped '+aid)
                fmt=q.get('answer_format',{}).get('kind')
                if fmt=='json' and not isinstance(value,str):value=json.dumps(value,separators=(',',':'))
                elif fmt=='integer':value=int(value)
                else:value=str(value)
                answers[aid]=value
    expected={q['id'] for q in qs}
    if set(answers)!=expected:raise ValueError(f'coverage {len(answers)}/{len(expected)}')
    open(outfile,'w').write(json.dumps(answers,separators=(',',':'))+'\n')
    print(json.dumps({'questions':len(qs),'answers':len(answers),'output':outfile,'bytes':len(open(outfile,'rb').read())}))

if __name__=='__main__':main(sys.argv[1],sys.argv[2],sys.argv[3])
