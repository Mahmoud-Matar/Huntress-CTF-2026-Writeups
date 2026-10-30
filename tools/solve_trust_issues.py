#!/usr/bin/env python3
"""Static answer builder for the Day 23 Trust Issues guided archive."""
import hashlib, json, pathlib, re, struct, subprocess, sys, zipfile, zlib, base64, os

ROOT=pathlib.Path(os.environ.get('TRUST_ISSUES_ROOT','/tmp/day23-trust-issues'))
ARCHIVE=pathlib.Path(os.environ.get('TRUST_ISSUES_ARCHIVE','/tmp/day23-trust-issues-transfer.zip'))
START=pathlib.Path(os.environ.get('TRUST_ISSUES_START','/tmp/day23-trust-issues-start.json'))
OUT=pathlib.Path(os.environ.get('TRUST_ISSUES_OUT','/tmp/day23-trust-issues-answers.json'))

def uleb(b,p):
    out=shift=0
    while p<len(b):
        x=b[p];p+=1;out|=(x&127)<<shift
        if not x&128:return out,p
        shift+=7
    raise ValueError('bad ULEB')

class ELF:
    def __init__(self,b):
        self.b=b; assert b[:4]==b'\x7fELF'
        self.bits=32 if b[4]==1 else 64; self.end='<' if b[5]==1 else '>'; self.byteorder='little' if self.end=='<' else 'big'
        self.etype,self.machine=struct.unpack_from(self.end+'HH',b,16)
        self.entry=struct.unpack_from(self.end+('I' if self.bits==32 else 'Q'),b,24)[0]
        if self.bits==32:
            shoff=struct.unpack_from(self.end+'I',b,32)[0]; ents,num,idx=struct.unpack_from(self.end+'HHH',b,46); fmt=self.end+'IIIIIIIIII'
        else:
            shoff=struct.unpack_from(self.end+'Q',b,40)[0]; ents,num,idx=struct.unpack_from(self.end+'HHH',b,58); fmt=self.end+'IIQQQQIIQQ'
        self.sections=[]
        for i in range(num):
            off=shoff+i*ents
            vals=struct.unpack_from(fmt,b,off)
            self.sections.append({'nameoff':vals[0],'type':vals[1],'flags':vals[2],'addr':vals[3],'off':vals[4],'size':vals[5],'link':vals[6],'info':vals[7],'align':vals[8],'entsize':vals[9]})
        if idx<len(self.sections):
            st=self.sections[idx]; names=b[st['off']:st['off']+st['size']]
        else:names=b''
        for s in self.sections:
            no=s['nameoff']; end=names.find(b'\0',no) if no<len(names) else -1
            s['name']=names[no:end if end>=0 else len(names)].decode('utf-8','replace') if no<len(names) else ''
        self.symtabs=[]; self.symbols=[]
        for sec in self.sections:
            if sec['type']!=2 or not sec['entsize'] or sec['link']>=len(self.sections):continue
            st=self.sections[sec['link']]; strs=b[st['off']:st['off']+st['size']]; table=[]
            for i in range(sec['size']//sec['entsize']):
                p=sec['off']+i*sec['entsize']
                if self.bits==32: no,val,size=struct.unpack_from(self.end+'III',b,p); info=b[p+12]; shndx=struct.unpack_from(self.end+'H',b,p+14)[0]
                else: no=struct.unpack_from(self.end+'I',b,p)[0];info=b[p+4];shndx=struct.unpack_from(self.end+'H',b,p+6)[0];val,size=struct.unpack_from(self.end+'QQ',b,p+8)
                e=strs.find(b'\0',no) if no<len(strs) else -1; name=strs[no:e if e>=0 else len(strs)].decode('utf-8','replace') if no<len(strs) else ''
                rec={'name':name,'value':val,'size':size,'info':info,'shndx':shndx,'section':sec['name']};table.append(rec)
                if name:self.symbols.append(rec)
            self.symtabs.append(table)
    def section(self,name):return next((s for s in self.sections if s['name']==name),None)
    def secbytes(self,s):return self.b[s['off']:s['off']+s['size']] if s else b''

class PE:
    def __init__(self,b):
        self.b=b; self.peoff=struct.unpack_from('<I',b,0x3c)[0]; assert b[self.peoff:self.peoff+4]==b'PE\0\0'
        p=self.peoff+4; self.machine,self.nsec,ts,ptrsym,nsym,optsz,chars=struct.unpack_from('<HHIIIHH',b,p)
        strings=b''
        if ptrsym and nsym:
            strings_at=ptrsym+nsym*18
            if strings_at+4<=len(b):
                strlen=struct.unpack_from('<I',b,strings_at)[0]
                if 4<=strlen<=len(b)-strings_at:strings=b[strings_at:strings_at+strlen]
        self.opt=p+20; magic=struct.unpack_from('<H',b,self.opt)[0]; self.pe64=magic==0x20b
        self.sections=[]; sh=self.opt+optsz
        for i in range(self.nsec):
            rawname=b[sh+i*40:sh+i*40+8];short=rawname.split(b'\0')[0]
            if short.startswith(b'/') and short[1:].isdigit() and strings:
                no=int(short[1:]);e=strings.find(b'\0',no);namebytes=strings[no:e if e>=0 else len(strings)]
            else:namebytes=short
            n=namebytes.decode('ascii','replace');vs,va,rs,rp=struct.unpack_from('<IIII',b,sh+i*40+8)
            self.sections.append({'name':n,'vsize':vs,'rva':va,'size':rs,'off':rp})
        self.symbols=[]
        if ptrsym and nsym:
            strings_at=ptrsym+nsym*18; strlen=struct.unpack_from('<I',b,strings_at)[0] if strings_at+4<=len(b) else 0
            strings=b[strings_at:strings_at+strlen] if strlen>=4 else b''; i=0
            while i<nsym:
                p=ptrsym+i*18; name8=b[p:p+8]
                if name8[:4]==b'\0\0\0\0':
                    no=struct.unpack_from('<I',name8,4)[0];e=strings.find(b'\0',no) if no<len(strings) else -1;name=strings[no:e if e>=0 else len(strings)].decode('utf8','replace') if no<len(strings) else ''
                else:name=name8.split(b'\0')[0].decode('utf8','replace')
                secno=struct.unpack_from('<h',b,p+12)[0]; typ=struct.unpack_from('<H',b,p+14)[0]; aux=b[p+17]
                if name:self.symbols.append({'name':name,'section':secno,'type':typ})
                i+=1+aux
    def rvaoff(self,rva):
        for s in self.sections:
            if s['rva']<=rva<s['rva']+max(s['vsize'],s['size']):return s['off']+rva-s['rva']
        return rva if rva<len(self.b) else None
    def cli(self):
        dd=self.opt+(112 if self.pe64 else 96); cli_rva=struct.unpack_from('<I',self.b,dd+14*8)[0]
        if not cli_rva:return None
        off=self.rvaoff(cli_rva)
        if off is None or off+16>len(self.b):return None
        md_rva=struct.unpack_from('<I',self.b,off+8)[0]
        mo=self.rvaoff(md_rva) if md_rva else None
        if mo is None or self.b[mo:mo+4]!=b'BSJB':return None
        return off
    def metadata_version(self):
        co=self.cli()
        if co is None:return None
        md_rva=struct.unpack_from('<I',self.b,co+8)[0];mo=self.rvaoff(md_rva)
        if mo is None or self.b[mo:mo+4]!=b'BSJB':return None
        n=struct.unpack_from('<I',self.b,mo+12)[0]
        return self.b[mo+16:mo+16+n].rstrip(b'\0').decode('utf8','replace')

def valid_hcfg(b,at):
    if at<0 or at+12>len(b) or b[at:at+4]!=b'HCFG':return None
    ver,key=b[at+4],b[at+5]; n=struct.unpack_from('<H',b,at+6)[0]; crc=struct.unpack_from('<I',b,at+8)[0]
    if at+12+n>len(b):return None
    enc=b[at+12:at+12+n];raw=bytes(x^key for x in enc)
    if zlib.crc32(raw)&0xffffffff!=crc:return None
    try:obj=json.loads(raw.decode('utf8'))
    except Exception:return None
    return {'offset':at,'version':ver,'key':key,'crc':crc,'obj':obj,'header':b[at:at+12],'length':n}

def hcfg_search(b):
    for m in re.finditer(b'HCFG',b):
        x=valid_hcfg(b,m.start())
        if x:return x,'raw',m.start()
    # Only printable, standard Base64 carriers are inspected.  Preserve each run's
    # source offset because that is what the challenge asks for.
    for m in re.finditer(rb'[A-Za-z0-9+/]{100,}={0,2}',b):
        try:d=base64.b64decode(m.group(),validate=True)
        except Exception:continue
        x=valid_hcfg(d,0)
        if x:return x,'base64',m.start()
    return None,None,None

def wasm_data(b):
    assert b[:4]==b'\0asm'; p=8; results=[]
    while p<len(b):
        sid=b[p];p+=1;sz,p=uleb(b,p);end=p+sz
        if sid==11:
            count,p2=uleb(b,p)
            for _ in range(count):
                flags,p2=uleb(b,p2)
                if flags==2:_,p2=uleb(b,p2)
                op=b[p2];p2+=1
                if op==0x41:
                    # signed LEB32
                    val=shift=0
                    while True:
                        x=b[p2];p2+=1;val|=(x&127)<<shift;shift+=7
                        if not x&128:
                            if shift<32 and x&64:val|=-(1<<shift)
                            break
                    if b[p2]!=0x0b:raise ValueError('wasm offset expr')
                    p2+=1
                elif op==0x23:_,p2=uleb(b,p2);p2+=1
                else:raise ValueError('unsupported wasm offset expression')
                n,p2=uleb(b,p2);start=p2;payload=b[p2:p2+n];results.append((start,payload));p2+=n
        p=end
    return results

def class_info(b):
    assert b[:4]==b'\xca\xfe\xba\xbe';minor,major,cpn=struct.unpack_from('>HHH',b,4);p=10;cp=[None]*cpn;i=1
    while i<cpn:
        tag=b[p];p+=1
        if tag==1:n=struct.unpack_from('>H',b,p)[0];p+=2;cp[i]=b[p:p+n].decode('utf8','replace');p+=n
        elif tag in (3,4):p+=4
        elif tag in (5,6):p+=8;i+=1
        elif tag in (7,8,16,19,20):cp[i]=struct.unpack_from('>H',b,p)[0];p+=2
        elif tag in (9,10,11,12,17,18):p+=4
        elif tag==15:p+=3
        else:raise ValueError('unknown class constant tag '+str(tag))
        i+=1
    flags,this,superc=struct.unpack_from('>HHH',b,p);p+=6
    ic=struct.unpack_from('>H',b,p)[0];p+=2+2*ic
    def skip_members(p):
        n=struct.unpack_from('>H',b,p)[0];p+=2;names=[]
        for _ in range(n):
            acc,ni,di,ac=struct.unpack_from('>HHHH',b,p);p+=8
            if names is not None:nm=cp[ni];names.append(nm)
            for j in range(ac):
                ai=struct.unpack_from('>H',b,p)[0];ln=struct.unpack_from('>I',b,p+2)[0];p+=6+ln
        return p,n,names
    p,_,_=skip_members(p);p,nmethods,names=skip_members(p)
    return {'flags':flags,'methods':names,'method_count':nmethods,'major':major,'utf8':[x for x in cp if isinstance(x,str)]}

def hcfg_from_jar(path):
    with zipfile.ZipFile(path) as z:
        names=z.namelist(); main=None
        try:
            manifest=z.read('META-INF/MANIFEST.MF').decode('utf8','replace')
            m=re.search(r'(?im)^Main-Class:\s*([^\r\n]+)',manifest)
            if m:main=m.group(1).strip().replace('.','/')+'.class'
        except KeyError:pass
        if main not in names:main=next((n for n in names if n.endswith('.class') and not n.startswith('META-INF/')),None)
        if not main:return None
        for s in class_info(z.read(main))['utf8']:
            if len(s)<80 or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',s):continue
            try:decoded=base64.b64decode(s,validate=True)
            except Exception:continue
            h=valid_hcfg(decoded,0)
            if h:return h,'base64',None
    return None,None,None

def hcfg_from_d19(b):
    off=b.rfind(b'PK19')
    if off<0 or off+44>len(b):return None,None,None
    k1,k2=b[off+5],b[off+6];n=struct.unpack_from('<I',b,off+8)[0]
    if off+44+n>len(b):return None,None,None
    packed=b[off+44:off+44+n]
    unpacked=bytes(((((x^k2)>>3)|((x^k2)<<5))&255)^k1 for x in packed)
    expected=b[off+12:off+44]
    if hashlib.sha256(unpacked).digest()!=expected:return None,None,None
    h=valid_hcfg(unpacked,0)
    if not h:return None,None,None
    return h,'overlay',off

def member_for(day,selector=''):
    names=member_orders.get(day,[])
    if not names:return None
    if day=='d15':return next((n for n in names if selector in n),None)
    if day=='d16':return next((n for n in names if selector in n),None)
    if day=='d21':return next((n for n in names if selector in n),None)
    if day in ('d03','d22','d23'):
        return next((n for n in names if n.endswith('.dll') and 'runtimeconfig' not in n.lower() and 'fsharp.core' not in n.lower()),names[0])
    if day in ('d06','d07'):return next((n for n in names if n.endswith('.jar')),names[0])
    return names[0]

def fmt_elf_machine(n):return {3:'i386',40:'ARM',62:'x86-64',183:'AArch64',243:'RISC-V'}.get(n,str(n))

def answer_one(q):
    qid=q['id'];day=qid[:3];rest=qid[4:];selector=''
    if day=='d15':selector='stripped' if '_stripped_' in qid else 'symbolized'
    if day=='d16':selector='compact' if '_compact_' in qid else 'direct'
    if day=='d21':selector='plugin' if '_plugin_' in qid or 'plugin.cmxs' in q.get('question','') else 'loader'
    fn=member_for(day,selector)
    if not fn:return None
    path=ROOT/fn;b=path.read_bytes();base=qid.split('_',2)[-1]
    # Every artifact hash uses central-directory order within its day prefix.
    if '_artifact_sha256_' in qid:
        m=re.search(r'_artifact_sha256_(\d+)$',qid);ix=int(m.group(1))-1;ordered=member_orders[day];return hashlib.sha256((ROOT/ordered[ix]).read_bytes()).hexdigest()
    iself=b.startswith(b'\x7fELF'); ipe=b.startswith(b'MZ'); iwasm=b.startswith(b'\0asm'); ijar=b.startswith(b'PK\x03\x04')
    elf=ELF(b) if iself else None; pe=PE(b) if ipe else None
    h,carrier,co=hcfg_search(b)
    if day in ('d06','d07') and ijar and not h:
        h,carrier,co=hcfg_from_jar(path)
    if day=='d19' and not h:
        h,carrier,co=hcfg_from_d19(b)
    # Raw HCFG is sometimes in a mapped data segment or a named native section.
    if iwasm:
        for off,data in wasm_data(b):
            hh=valid_hcfg(data,0)
            if hh:h={'offset':off,'version':hh['version'],'key':hh['key'],'crc':hh['crc'],'obj':hh['obj'],'header':hh['header'],'length':hh['length']};carrier='wasm_data';co=off;break
    low=qid.lower()
    if qid.endswith('_format'):
        if ijar:return 'jar'
        if iwasm:return 'wasm'
        if iself:return 'elf'
        if ipe:return 'pe_cli' if pe and pe.metadata_version() else 'pe'
        return 'neko_bytecode' if b.startswith(b'NEKO') else None
    if qid.endswith('_machine') or qid.endswith('_loader_machine') or qid.endswith('_plugin_machine'):
        machine=elf.machine if elf else pe.machine if pe else None
        if machine is None:return None
        if 'machine' in qid and qid.endswith('_machine') and ('stripped_machine' in qid or 'symbolized_machine' in qid or 'loader_machine' in qid or 'plugin_machine' in qid):return str(machine)
        if pe and machine==0x14c:return 'i386'
        if pe and machine==0x8664:return 'amd64'
        return fmt_elf_machine(machine)
    if qid.endswith('_architecture'):
        mach=elf.machine if elf else pe.machine if pe else None
        return 'x86-64' if mach==62 or mach==0x8664 else 'wasm32' if iwasm else fmt_elf_machine(mach) if mach is not None else None
    if qid.endswith('_elf_class'):
        if not elf:return None
        return ('ELF64' if elf.bits==64 else 'ELF32') if qid.startswith('d01_') else str(elf.bits)
    if qid.endswith('_elf_type'):return {1:'ET_REL',2:'ET_EXEC',3:'ET_DYN',4:'ET_CORE'}.get(elf.etype) if elf else None
    if qid.endswith('_endianness'):return 'little endian' if elf and elf.end=='<' else 'big endian' if elf else None
    if qid.endswith('_entry_point'):return f'0x{elf.entry:x}' if elf else None
    if qid.endswith('_section_names'):
        if elf:
            names=[s['name'] for s in elf.sections];return json.dumps(names[1:] if names and names[0]=='' else names,separators=(',',':'))
        if pe:return json.dumps([s['name'] for s in pe.sections],separators=(',',':'))
        return None
    if qid.endswith('_symbols'):
        if not elf:return None
        syms=[x['name'] for table in elf.symtabs for x in table if x['name']]
        return json.dumps(syms,separators=(',',':'))
    if qid.endswith('_has_symtab'):return str(bool(elf and any(s['name']=='.symtab' for s in elf.sections))).lower()
    if qid.endswith('_marker'):
        s=elf.section('.huntress') if elf else None
        return elf.secbytes(s).rstrip(b'\0').decode('utf8') if s else None
    if qid.endswith('_recover_code'):
        sym=next((x for x in elf.symbols if x['name']=='recover_code'),None) if elf else None
        return 'none' if not sym else str(struct.unpack_from(elf.end+'I',b,elf.sections[sym['shndx']]['off']+sym['value']-elf.sections[sym['shndx']]['addr']+1)[0])
    if qid.endswith('_disassembly'):
        sym=next((x for x in elf.symbols if x['name']=='recover_code'),None) if elf else None
        if not sym:return '[]'
        sh=elf.sections[sym['shndx']];off=sh['off']+sym['value']-sh['addr'];
        out=subprocess.run(['objdump','-d',f'--start-address={sym["value"]}',f'--stop-address={sym["value"]+sym["size"]}',str(path)],capture_output=True,text=True).stdout
        ins=[]
        for line in out.splitlines():
            m=re.match(r'^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*([a-z][a-z0-9.]*)\s*(.*)$',line)
            if m:ins.append((m.group(1)+' '+m.group(2).strip()).strip())
        return json.dumps(ins,separators=(',',':'))
    if qid.endswith('_has_cpp_typeinfo') or qid.endswith('_has_cpp_vtable'):
        names=[s['name'] for s in elf.symbols] if elf else [s['name'] for s in (pe.symbols if pe else [])]
        pat=r'_ZTI.*DiscoveryEngine' if qid.endswith('typeinfo') else r'_ZTV.*DiscoveryEngine'
        return str(any(re.search(pat,n) for n in names)).lower()
    if qid.endswith('_mangled_score_symbol') or qid.endswith('_typeinfo_symbol'):
        names=[s['name'] for table in elf.symtabs for s in table] if elf else [s['name'] for s in pe.symbols] if pe else []
        pat=r'DiscoveryEngine.*score' if qid.endswith('score_symbol') else r'ZTI.*DiscoveryEngine'
        return next((n for n in names if n and re.search(pat,n)),None)
    if qid.endswith('_has_go_runtime'):return str(b'runtime.main' in b).lower()
    if qid.endswith('_has_rust_mangled_symbol'):return str(any(s['name'].startswith(('_ZN','_R')) for s in (elf.symbols if elf else []))).lower()
    if qid.endswith('_has_hcfg_section'):
        names=[s['name'] for s in elf.sections] if elf else [s['name'] for s in pe.sections] if pe else []
        pred=('.hcfg' in names) if day=='d14' else any('hcfg' in n for n in names)
        return str(pred).lower()
    if qid.endswith('_hcfg_offset'):return str(co) if co is not None else None
    if qid.endswith('_hcfg_storage'):
        if carrier=='base64':return 'base64'
        if elf and elf.section('.hcfg'):return 'raw_hcfg_section'
        if carrier=='wasm_data':return 'wasm_data_segment'
        # Further code-reference check distinguishes mapped const arrays from raw overlay bytes.
        if elf and h and h['offset']<len(b):
            try:
                sec=next((s for s in elf.sections if s['off']<=h['offset']<s['off']+s['size']),None)
                va=sec['addr']+h['offset']-sec['off'] if sec else h['offset']
                qx=subprocess.run(['r2','-q','-c',f'aaa; axt @ {va}; q',str(path)],capture_output=True,text=True,timeout=60).stdout
                if qx.strip():return 'raw_const_array'
            except Exception:pass
        return 'raw'
    if qid.endswith('_config_campaign') or qid.endswith('_config_domain') or qid.endswith('_config_mutex') or qid.endswith('_config_url'):
        key=qid.rsplit('_',1)[-1];return str(h['obj'].get(key)) if h and key in h['obj'] else None
    if qid.endswith('_config_crc32_hex'):return f'0x{h["crc"]:08x}' if h else None
    if qid.endswith('_xor_key_hex'):return f'0x{h["key"]:02x}' if h else None
    if qid.endswith('_hcfg_version'):return str(h['version']) if h else None
    if qid.endswith('_overlay_offset'):
        magic=b'PK19' if day=='d19' else b'RS20';return str(b.rfind(magic)) if magic in b else None
    if qid.endswith('_overlay_size'):
        off=b.rfind(b'PK19');return str(len(b)-off) if off>=0 else None
    if qid.endswith('_hcfg_resource_size'):
        off=b.rfind(b'RS20');return str(struct.unpack_from('<I',b,off+8)[0]) if off>=0 else None
    if qid.endswith('_metadata_version'):
        if pe:return pe.metadata_version()
        m=re.search(b'BSJB.{12}(.{1,64}?)\0',b,re.S);return m.group(1).decode('utf8','replace') if m else None
    if qid.endswith('_compression_methods') or qid.endswith('_methods') or qid.endswith('_access_flags') or qid.endswith('_method_count') or qid.endswith('_has_coroutine_runtime'):
        if not ijar:return None
        with zipfile.ZipFile(path) as z:
            if qid.endswith('_compression_methods'):return json.dumps(sorted({i.compress_type for i in z.infolist()}),separators=(',',':'))
            names=z.namelist(); main=None
            try:
                manifest=z.read('META-INF/MANIFEST.MF').decode('utf8','replace');m=re.search(r'(?im)^Main-Class:\s*([^\r\n]+)',manifest);main=m.group(1).strip().replace('.','/')+'.class' if m else None
            except KeyError:pass
            if qid.endswith('_has_coroutine_runtime'):return str('kotlin/coroutines/Continuation.class' in names).lower()
            if qid.endswith('_method_count'):
                cf=main if main in names else next((n for n in names if n.endswith('.class') and not n.startswith('META-INF/')),None);ci=class_info(z.read(cf));return str(ci['method_count'])
            if qid.endswith('_methods') or qid.endswith('_access_flags'):
                cf=main if main in names else next((n for n in names if n.endswith('.class') and not n.startswith('META-INF/')),None);ci=class_info(z.read(cf))
                return json.dumps(ci['methods'],separators=(',',':')) if qid.endswith('_methods') else str(ci['flags'])
    if qid.endswith('_hcfg_offset') and iwasm:
        for off,data in wasm_data(b):
            if data.find(b'HCFG')>=0:return str(off+data.find(b'HCFG'))
    return None

def main():
    global member_orders,ROOT,ARCHIVE
    start=json.loads(START.read_text())
    root_base=ROOT;archive_base=ARCHIVE
    cached={}
    answers={};missing=[]
    for q in start['questions']:
        qid=q['id'];sm=re.match(r'^(set\d+)\.(d\d\d)_',qid)
        if sm:
            setname=sm.group(1);ROOT=root_base/setname/'extracted';ARCHIVE=root_base/setname/'evidence.zip'
            if setname not in cached:
                with zipfile.ZipFile(ARCHIVE) as z:allnames=z.namelist()
                cached[setname]={d:[n for n in allnames if n.startswith(d+'--')] for d in {x['id'][5:8] for x in start['questions'] if x['id'].startswith(setname+'.d')}}
            member_orders=cached[setname]
            qwork=dict(q);qwork['id']=qid.split('.',1)[1]
        else:
            ROOT=root_base;ARCHIVE=archive_base;qwork=q
            if 'default' not in cached:
                with zipfile.ZipFile(ARCHIVE) as z:allnames=z.namelist()
                cached['default']={d:[n for n in allnames if n.startswith(d+'--')] for d in {x['id'][:3] for x in start['questions']}}
            member_orders=cached['default']
        try:v=answer_one(qwork)
        except Exception as e:
            v=None;missing.append((qid,type(e).__name__+': '+str(e)))
        if v is None:missing.append((qid,'unmapped'))
        else:answers[qid]=str(v)
    OUT.write_text(json.dumps(answers,indent=2,sort_keys=True)+'\n')
    print('questions',len(start['questions']),'answers',len(answers),'missing',len(missing))
    for x in missing:print('MISSING',*x)
    print('output',OUT)
if __name__=='__main__':main()
