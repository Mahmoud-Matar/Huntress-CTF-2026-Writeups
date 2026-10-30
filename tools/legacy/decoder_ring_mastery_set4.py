#!/usr/bin/env python3
"""Static parser for the assigned Decoder Ring evidence; never executes specimens."""
import base64, binascii, hashlib, json, os, re, struct, zipfile

ROOT = '/home/remnux/files/samples/decoder-ring-day17-mastery-set4-artifacts'
START = '/home/remnux/huntressCTF-2026/challenges/data/decoder-ring-day17-mastery-set4-start.json'

def cstr(b):
    return b.split(b'\0', 1)[0].decode('utf-8', 'replace')

def elf_info(data, need_symbols=True):
    assert data[:4] == b'\x7fELF'
    cls, enc = data[4], data[5]
    e = '<' if enc == 1 else '>'
    if cls == 2:
        etype, machine, entry, shoff = struct.unpack_from(e+'HHQ', data, 16)[0], struct.unpack_from(e+'H', data, 18)[0], struct.unpack_from(e+'Q', data, 24)[0], struct.unpack_from(e+'Q', data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(e+'HHH', data, 58)
        shfmt = e+'IIQQQQIIQQ'
    else:
        etype, machine, entry, shoff = struct.unpack_from(e+'HHI', data, 16)[0], struct.unpack_from(e+'H', data, 18)[0], struct.unpack_from(e+'I', data, 24)[0], struct.unpack_from(e+'I', data, 32)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(e+'HHH', data, 46)
        shfmt = e+'IIIIIIIIII'
    shdrs = [struct.unpack_from(shfmt, data, shoff+i*shentsize) for i in range(shnum)]
    shstr = data[shdrs[shstrndx][4]:shdrs[shstrndx][4]+shdrs[shstrndx][5]]
    sections=[]
    for i,s in enumerate(shdrs):
        name=cstr(shstr[s[0]:])
        sections.append({'i':i,'name':name,'type':s[1],'flags':s[2],'addr':s[3],'off':s[4],'size':s[5],'link':s[6],'info':s[7],'entsize':s[9]})
    syms=[]
    for sec in sections if need_symbols else []:
        if sec['type'] != 2 or not sec['entsize']: continue
        strings=sections[sec['link']]
        st=data[strings['off']:strings['off']+strings['size']]
        n=sec['size']//sec['entsize']
        for j in range(n):
            o=sec['off']+j*sec['entsize']
            if cls==2:
                no,info,other,shndx,val,size=struct.unpack_from(e+'IBBHQQ',data,o)
            else:
                no,val,size=struct.unpack_from(e+'III',data,o); info,other,shndx=struct.unpack_from('BBH',data,o+12)
            syms.append({'name':cstr(st[no:]) if no else '', 'info':info,'shndx':shndx,'value':val,'size':size,'sec_i':sec['i'],'bind':info>>4,'type':info&15})
    return {'class':cls,'enc':enc,'etype':etype,'machine':machine,'entry':entry,'sections':sections,'symbols':syms}

def valid_hcfg(buf):
    out=[]
    start=0
    while True:
        p=buf.find(b'HCFG',start)
        if p<0: break
        start=p+1
        if p+12>len(buf): continue
        ver,key=buf[p+4],buf[p+5]
        n=struct.unpack_from('<H',buf,p+6)[0]; crc=struct.unpack_from('<I',buf,p+8)[0]
        if p+12+n>len(buf): continue
        raw=bytes(x^key for x in buf[p+12:p+12+n])
        if binascii.crc32(raw)&0xffffffff != crc: continue
        try: obj=json.loads(raw.decode())
        except Exception: continue
        if isinstance(obj,dict): out.append({'offset':p,'version':ver,'key':key,'crc':crc,'obj':obj})
    return out

def decode_b64(buf, day=None):
    out=[]; marker=b'SENGRw'; alphabet=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    pos=0
    while True:
        pos=buf.find(marker,pos)
        if pos<0: break
        start=pos
        while start>0 and buf[start-1] in alphabet: start-=1
        end=pos+len(marker)
        while end<len(buf) and buf[end] in alphabet: end+=1
        raw=buf[start:end]; padded=raw+b'='*((-len(raw))%4)
        try: dec=base64.b64decode(padded,validate=True)
        except Exception: pos+=len(marker); continue
        for h in valid_hcfg(dec): out.append({'offset':start,'decoded_offset':h['offset'],'version':h['version'],'key':h['key'],'crc':h['crc'],'obj':h['obj']})
        pos+=len(marker)
    return out

def cp_class(data):
    # Return class name -> (access_flags, method_names) for an individual class.
    assert data[:4]==b'\xca\xfe\xba\xbe'
    n=struct.unpack_from('>H',data,8)[0]; cp=[None]*n; p=10; i=1
    while i<n:
        tag=data[p]; p+=1
        if tag==1:
            ln=struct.unpack_from('>H',data,p)[0];p+=2;cp[i]=('utf8',data[p:p+ln].decode('utf8','replace'));p+=ln
        elif tag in (3,4): cp[i]=(tag,data[p:p+4]);p+=4
        elif tag in (5,6): cp[i]=(tag,data[p:p+8]);p+=8;i+=1
        elif tag in (7,8,16,19,20): cp[i]=(tag,struct.unpack_from('>H',data,p)[0]);p+=2
        elif tag in (9,10,11,12,17,18): cp[i]=(tag,struct.unpack_from('>HH',data,p));p+=4
        elif tag==15: cp[i]=(tag,data[p:p+3]);p+=3
        else: raise ValueError(('constant pool tag',tag))
        i+=1
    access,this,superc=struct.unpack_from('>HHH',data,p);p+=6
    this_name=cp[cp[this][1]][1]
    ni=struct.unpack_from('>H',data,p)[0];p+=2+2*ni
    nf=struct.unpack_from('>H',data,p)[0];p+=2
    for _ in range(nf):
        p+=6;ac=struct.unpack_from('>H',data,p)[0];p+=2
        for __ in range(ac): ln=struct.unpack_from('>I',data,p+2)[0];p+=6+ln
    nm=struct.unpack_from('>H',data,p)[0];p+=2; methods=[]
    for _ in range(nm):
        flags,name,desc=struct.unpack_from('>HHH',data,p);p+=6;methods.append(cp[name][1])
        ac=struct.unpack_from('>H',data,p)[0];p+=2
        for __ in range(ac): ln=struct.unpack_from('>I',data,p+2)[0];p+=6+ln
    return this_name,access,methods

def pe_info(data):
    pe=struct.unpack_from('<I',data,0x3c)[0]; assert data[pe:pe+4]==b'PE\0\0'
    mach,nsec,ts,ptrsym,nsym,optsz,ch=struct.unpack_from('<HHIIIHH',data,pe+4)
    opt=pe+24; magic=struct.unpack_from('<H',data,opt)[0]; dd=opt+(112 if magic==0x20b else 96)
    cli_rva,cli_size=struct.unpack_from('<II',data,dd+14*8)
    secbase=opt+optsz; secs=[]
    for i in range(nsec):
        off=secbase+40*i; name=data[off:off+8].split(b'\0')[0].decode('ascii','replace')
        vs,va,rs,rp=struct.unpack_from('<IIII',data,off+8);secs.append((name,va,max(vs,rs),rp,rs))
    def rva_file(rva):
        for n,va,sz,rp,rs in secs:
            if va<=rva<va+sz:return rp+(rva-va)
        return None
    cli_off=rva_file(cli_rva) if cli_rva else None
    meta_rva=struct.unpack_from('<I',data,cli_off+8)[0] if cli_off else 0
    meta_off=rva_file(meta_rva) if meta_rva else None
    version=''
    if meta_off is not None and data[meta_off:meta_off+4]==b'BSJB':
        ln=struct.unpack_from('<I',data,meta_off+12)[0];version=data[meta_off+16:meta_off+16+ln].rstrip(b'\0').decode('utf-8','replace')
    return {'machine':mach,'magic':magic,'cli':bool(cli_off),'version':version,'sections':secs,'peoff':pe,'ptrsym':ptrsym,'nsym':nsym}

def pe_symbols(data, pi):
    ptr,count=pi['ptrsym'],pi['nsym']
    if not ptr or not count or ptr+count*18+4>len(data): return []
    stroff=ptr+count*18; strlen=struct.unpack_from('<I',data,stroff)[0]
    strings=data[stroff:stroff+strlen]
    result=[];i=0
    while i<count:
        off=ptr+i*18; n=data[off:off+8]
        if n[:4]==b'\0\0\0\0':
            no=struct.unpack_from('<I',n,4)[0]
            name=cstr(strings[no:]) if no<len(strings) else ''
        else: name=cstr(n)
        aux=data[off+17]
        if name: result.append(name)
        i+=1+aux
    return result

def classfiles(jar):
    z=zipfile.ZipFile(jar)
    return z,[ (n,z.read(n, pwd=b'infected')) for n in z.namelist() if n.endswith('.class') ]

def b64_hcfg_strings(buf):
    found=[]
    for m in re.finditer(rb'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])',buf):
        s=m.group(0)
        try: dec=base64.b64decode(s,validate=True)
        except Exception: continue
        for h in valid_hcfg(dec): found.append({'offset':m.start(),'version':h['version'],'key':h['key'],'crc':h['crc'],'obj':h['obj']})
    return found

def main():
    start=json.load(open(START)); ans={}; report={}
    # exact assigned member bytes, archive central directory order
    z=zipfile.ZipFile('/home/remnux/files/samples/decoder-ring-day17-mastery-set4.zip')
    members=[n for n in z.namelist() if re.match(r'd\d\d--',os.path.basename(n))]
    for day in range(1,18):
        print("processing",day,flush=True)
        prefix=f'd{day:02d}'; names=[n for n in members if os.path.basename(n).startswith(prefix+'--')]
        primary=next((n for n in names if n.lower().endswith(('.elf','.dll','.jar','.wasm'))),names[0])
        if day==3: primary=next(n for n in names if n.lower().endswith('.dll'))
        if day==6 or day==7: primary=next(n for n in names if n.lower().endswith('.jar'))
        if day==15: primary=next(n for n in names if n.endswith('stripped.elf'))
        if day==16: primary=next(n for n in names if n.endswith('compact.wasm'))
        data=open(os.path.join(ROOT,os.path.basename(primary)),'rb').read(); digest=hashlib.sha256(data).hexdigest()
        for q in start['questions']:
            qid=q['id']
            if qid.startswith(prefix+'_artifact_sha256_'):
                ix=int(qid.rsplit('_',1)[1])-1
                group=[n for n in members if os.path.basename(n).startswith(prefix+'--')]
                ans[qid]=hashlib.sha256(open(os.path.join(ROOT,os.path.basename(group[ix])),'rb').read()).hexdigest()
        row={'member':primary,'sha256':digest,'size':len(data)}
        infos=[]
        if data.startswith(b'\x7fELF'):
            info=elf_info(data, day in (1,2,5)); row.update({'format':'elf','class':'ELF'+str(32 if info['class']==1 else 64),'machine':info['machine'],'etype':info['etype'],'entry':hex(info['entry']),'sections':[s['name'] for s in info['sections']], 'symbols':[s for s in info['symbols'] if s['name']]})
            h=valid_hcfg(data); b=decode_b64(data,day); row['hcfg']=h; row['b64_hcfg']=b
            row['hcfg_sections']=[s for s in info['sections'] if s['name']=='.hcfg']
            row['go_runtime']=b'runtime.main' in data
            if day==1:
                syms=[s['name'] for s in info['symbols'] if s['name']]
                ans.update({f'd01_analysis_elf_class':row['class'], 'd01_analysis_machine':'x86-64','d01_analysis_section_names':json.dumps(row['sections'],separators=(',',':')), 'd01_analysis_symbols':json.dumps(syms,separators=(',',':')), 'd01_analysis_elf_type':{2:'ET_EXEC',3:'ET_DYN',1:'ET_REL'}.get(info['etype'],str(info['etype'])), 'd01_analysis_endianness':'little-endian' if info['enc']==1 else 'big-endian','d01_analysis_entry_point':hex(info['entry']),'d01_analysis_has_symtab':str(any(s['name']=='.symtab' for s in info['sections'])).lower()})
                hs=next((s for s in info['sections'] if s['name']=='.huntress'),None)
                ans['d01_analysis_marker']=data[hs['off']:hs['off']+hs['size']].rstrip(b'\0').decode('utf8') if hs else ''
                recover=next((s for s in info['symbols'] if s['name']=='recover_code' and s['type']==2),None)
                if recover:
                    sec=info['sections'][recover['shndx']]; fo=sec['off']+recover['value']-sec['addr']; code=data[fo:fo+recover['size']]
                    ans['d01_analysis_recover_code']=str(struct.unpack_from('<I',code,1)[0]) if code[:1]==b'\xb8' and code[5:6]==b'\xc3' else 'none'
                    ans['d01_analysis_disassembly']=json.dumps([f'mov eax, {struct.unpack_from("<I",code,1)[0]}','ret'],separators=(',',':'))
                else: ans.update({'d01_analysis_recover_code':'none','d01_analysis_disassembly':'[]'})
            if day==5:
                ans['d05_analysis_has_rust_mangled_symbol']=str(any(s['name'].startswith(('_ZN','_R')) for s in row['symbols'])).lower()
            if day==2:
                syms=[s['name'] for s in info['symbols'] if s['name']]
                ans.update({'d02_analysis_format':row['class'],'d02_analysis_has_cpp_typeinfo':str(any(re.search(r'ZTI.*DiscoveryEngine',x) for x in syms)).lower(),'d02_analysis_has_cpp_vtable':str(any(re.search(r'ZTV.*DiscoveryEngine',x) for x in syms)).lower(),'d02_analysis_mangled_score_symbol':next((x for x in syms if re.search(r'DiscoveryEngine.*score',x)),'none'),'d02_analysis_typeinfo_symbol':next((x for x in syms if re.search(r'ZTI.*DiscoveryEngine',x)),'none')})
        elif data.startswith(b'MZ'):
            row['format']='pe'; pi=pe_info(data); row.update(pi)
            row['hcfg']=valid_hcfg(data); row['b64_hcfg']=decode_b64(data)
            row['symbols']=pe_symbols(data,pi)
            row['sections_names']=[s[0] for s in pi['sections']]; row['go_runtime']=b'runtime.main' in data
            if day==3:
                row['format']='pe_cli' if pi['cli'] else 'pe'
            if day==2:
                syms=row['symbols']
                ans.update({'d02_analysis_format':'PE','d02_analysis_has_cpp_typeinfo':str(any(re.search(r'ZTI.*DiscoveryEngine',x) for x in syms)).lower(),'d02_analysis_has_cpp_vtable':str(any(re.search(r'ZTV.*DiscoveryEngine',x) for x in syms)).lower(),'d02_analysis_mangled_score_symbol':next((x for x in syms if re.search(r'DiscoveryEngine.*score',x)),'none'),'d02_analysis_typeinfo_symbol':next((x for x in syms if re.search(r'ZTI.*DiscoveryEngine',x)),'none')})
        elif data.startswith(b'PK'):
            row['format']='jar'; zz,classes=classfiles(os.path.join(ROOT,os.path.basename(primary))); row['compression_methods']=sorted(set(i.compress_type for i in zz.infolist())); row['class_count']=len(classes)
            parsed=[]
            for name,raw in classes:
                try: parsed.append((name,cp_class(raw)))
                except Exception as ex: parsed.append((name,('ERR',str(ex),[])))
            row['classes']=[{'path':n,'name':v[0],'access':v[1],'methods':v[2]} for n,v in parsed]
            mf=next((x for x in zz.namelist() if x.upper()=='META-INF/MANIFEST.MF'),None)
            row['manifest']=zz.read(mf).decode('utf8','replace') if mf else ''
            if day==6:
                maincl=re.search(r'(?im)^Main-Class:\s*(\S+)',row['manifest']); mn=maincl.group(1).replace('.','/')+'.class' if maincl else ''
                target=next((v for n,v in parsed if n==mn),None)
                row['main_class']=mn; row['main_class_parsed']=target
                class_raw=next((raw for n,raw in classes if n==mn),b'')
                row['b64_hcfg']=b64_hcfg_strings(class_raw)
                ans.update({'d06_analysis_format':'jar','d06_analysis_compression_methods':json.dumps(row['compression_methods']),'d06_analysis_methods':json.dumps(target[2] if target else [],separators=(',',':')),'d06_analysis_access_flags':str(target[1] if target else -1)})
            if day==7:
                maincl=re.search(r'(?im)^Main-Class:\s*(\S+)',row['manifest']); mn=maincl.group(1).replace('.','/')+'.class' if maincl else ''
                target=next((v for n,v in parsed if n==mn),None)
                row['main_class']=mn; row['main_class_parsed']=target
                class_raw=next((raw for n,raw in classes if n==mn),b'')
                row['b64_hcfg']=b64_hcfg_strings(class_raw)
                ans.update({'d07_analysis_format':'jar','d07_analysis_compression_methods':json.dumps(row['compression_methods']),'d07_analysis_has_coroutine_runtime':str('kotlin/coroutines/Continuation.class' in zz.namelist()).lower(),'d07_analysis_method_count':str(len(target[2]) if target else -1)})
        elif data.startswith(b'\0asm'):
            row['format']='wasm'; row['machine']='wasm32';row['hcfg']=valid_hcfg(data);row['b64_hcfg']=decode_b64(data)
            if day==16:
                direct=next(n for n in names if n.endswith('direct.wasm'))
                direct_data=open(os.path.join(ROOT,os.path.basename(direct)),'rb').read()
                row['direct_member']=direct;row['direct_sha256']=hashlib.sha256(direct_data).hexdigest();row['direct_hcfg']=valid_hcfg(direct_data)
        report[prefix]=row
    # Fill every remaining player-facing field from the parsed specimens.
    for q in start['questions']:
        qid=q['id']
        if qid in ans: continue
        m=re.match(r'd(\d\d)_(?:analysis_)?(.+)',qid)
        if not m: continue
        day=int(m.group(1)); prefix=f'd{day:02d}'; field=m.group(2); row=report[prefix]
        h=(row.get('hcfg') or row.get('b64_hcfg') or [None])[0]
        obj=h['obj'] if h else {}
        config_prefix=next((p for p in ('stripped_config_','compact_config_','direct_config_','config_') if field.startswith(p)),None)
        if config_prefix:
            k=field[len(config_prefix):]
            useh=((row.get('direct_hcfg') or [h])[0]) if config_prefix=='direct_config_' else h
            useobj=useh['obj'] if useh else {}
            ans[qid]=(useobj.get(k,'') if k in ('campaign','domain','mutex','url') else ('0x%08x'%useh['crc'] if useh and k=='crc32_hex' else ('0x%02x'%useh['key'] if useh and k=='xor_key_hex' else '')))
        elif field in ('hcfg_version','xor_key_hex','hcfg_offset','hcfg_storage','has_hcfg_section'):
            ans[qid]={'hcfg_version':str(h['version']) if h else '', 'xor_key_hex':('0x%02x'%h['key']) if h else '', 'hcfg_offset':str(h['offset']) if h else '', 'has_hcfg_section':str(any('hcfg' in n for n in row.get('sections_names',[])) if day==10 else bool(row.get('hcfg_sections'))).lower(), 'hcfg_storage':('base64' if row.get('b64_hcfg') else ('wasm_data_segment' if day==16 else ('raw_const_array' if day==12 else ('raw_hcfg_section' if row.get('hcfg_sections') else 'raw'))))}[field]
        elif field=='elf_class': ans[qid]='64' if row.get('class')=='ELF64' else '32'
        elif field=='metadata_version': ans[qid]=row.get('version','')
        elif field in ('format','architecture','machine'):
            fmt=row.get('format','')
            if field=='format': ans[qid]=fmt
            elif field=='architecture': ans[qid]='wasm32' if fmt=='wasm' else ('x86-64' if row.get('machine') in (62,34404) else ('x86' if row.get('machine') in (3,332) else 'x86-64'))
            else: ans[qid]=str(row.get('machine',''))
        elif field=='has_go_runtime': ans[qid]=str(bool(row.get('go_runtime'))).lower()
        elif field=='section_names': ans[qid]=json.dumps(row.get('sections_names',row.get('sections',[])),separators=(',',':'))
        elif field=='stripped_architecture' or field=='symbolized_architecture': ans[qid]='x86-64'
        elif field=='stripped_format' or field=='symbolized_format': ans[qid]='elf'
        elif field=='stripped_machine' or field=='symbolized_machine': ans[qid]=str(row.get('machine',62))
        elif field=='compact_architecture' or field=='direct_architecture': ans[qid]='wasm32'
        elif field=='compact_format' or field=='direct_format': ans[qid]='wasm'
        elif field=='compression_methods': ans[qid]=json.dumps(row.get('compression_methods',[]),separators=(',',':'))
        elif field=='has_coroutine_runtime': ans[qid]=str('kotlin/coroutines/Continuation.class' in zipfile.ZipFile(os.path.join(ROOT,'d07--sample.jar')).namelist()).lower()
        elif field=='method_count': ans[qid]=str(len(row.get('main_class_parsed',[None,None,[]])[2]))
    open('/home/remnux/huntressCTF-2026/challenges/data/decoder-ring-day17-mastery-set4-analysis.json','w').write(json.dumps(report,indent=2))
    open('/home/remnux/huntressCTF-2026/challenges/data/decoder-ring-day17-mastery-set4-answers.json','w').write(json.dumps(ans,indent=2))
    print(json.dumps({k:{x:v.get(x) for x in ('member','sha256','size','format','class','machine','etype','entry','hcfg','b64_hcfg','hcfg_sections','go_runtime','compression_methods','manifest','main_class','main_class_parsed')} for k,v in report.items()},indent=2))
    print('answers generated',len(ans),'of',len(start['answer_ids']))

if __name__=='__main__': main()
