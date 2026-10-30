#!/usr/bin/env python3
"""Static answer builder for the assigned Day 22 Bridge Troll archive."""
from __future__ import annotations
import base64, hashlib, json, os, re, struct, subprocess, zipfile, zlib
from pathlib import Path

ARCHIVE = Path(os.environ.get("BRIDGE_ARCHIVE", str(Path(__file__).resolve().parents[1] / "challenges/data/managed-native-bridge-evidence.zip")))
EXTRACTED = Path(os.environ.get("BRIDGE_EXTRACTED", "/tmp/managed-native-bridge/files"))
OUT = Path(os.environ.get("BRIDGE_ANSWERS_OUT", "/tmp/managed-native-bridge-answers.json"))
HCFG_RE = re.compile(rb"[A-Za-z0-9+/]{100,}={0,2}")

def cstr(buf, off):
    if off >= len(buf): return ""
    end = buf.find(b"\0", off)
    if end < 0: end = len(buf)
    return buf[off:end].decode("utf-8", "replace")

def elf_info(data):
    if data[:4] != b"\x7fELF": return None
    cls, enc = data[4], data[5]
    e = "<" if enc == 1 else ">"
    if cls == 2:
        etype, machine = struct.unpack_from(e+"HH", data, 16)
        entry = struct.unpack_from(e+"Q", data, 24)[0]
        shoff = struct.unpack_from(e+"Q", data, 40)[0]
        shentsz, shnum, shstrndx = struct.unpack_from(e+"HHH", data, 58)
        shfmt = e+"IIQQQQIIQQ"
    elif cls == 1:
        etype, machine = struct.unpack_from(e+"HH", data, 16)
        entry = struct.unpack_from(e+"I", data, 24)[0]
        shoff = struct.unpack_from(e+"I", data, 32)[0]
        shentsz, shnum, shstrndx = struct.unpack_from(e+"HHH", data, 46)
        shfmt = e+"IIIIIIIIII"
    else: raise ValueError("unsupported ELF class")
    raw=[]
    for i in range(shnum):
        p=shoff+i*shentsz
        vals=struct.unpack_from(shfmt,data,p)
        if cls==2: name,typ,flags,addr,off,size,link,info,align,entsize=vals
        else: name,typ,flags,addr,off,size,link,info,align,entsize=vals
        raw.append(dict(nameoff=name,type=typ,flags=flags,addr=addr,off=off,size=size,link=link,info=info,entsize=entsize))
    shstr=raw[shstrndx] if raw and shstrndx<len(raw) else {"off":0,"size":0}
    names=data[shstr["off"]:shstr["off"]+shstr["size"]]
    for s in raw: s["name"]=cstr(names,s["nameoff"])
    symbols=[]
    for sec in raw:
        if sec["type"] not in (2,): continue
        if sec["link"]>=len(raw): continue
        st=raw[sec["link"]]; strings=data[st["off"]:st["off"]+st["size"]]
        entsz=sec["entsize"] or (24 if cls==2 else 16)
        for p in range(sec["off"],sec["off"]+sec["size"],entsz):
            if cls==2:
                no,info,other,shndx,val,size=struct.unpack_from(e+"IBBHQQ",data,p)
            else:
                no,val,size=struct.unpack_from(e+"III",data,p)
                info,other,shndx=struct.unpack_from("BBH",data,p+12)
            symbols.append(dict(name=cstr(strings,no),info=info,shndx=shndx,value=val,size=size,table_type=sec["type"]))
    return dict(cls=cls, endian=enc, type=etype, machine=machine, entry=entry, sections=raw, symbols=symbols)

def pe_info(data):
    if data[:2] != b"MZ": return None
    peoff=struct.unpack_from("<I",data,0x3c)[0]
    if data[peoff:peoff+4] != b"PE\0\0": return None
    machine,nsec,_,symoff,nsyms,optlen,_=struct.unpack_from("<HHIIIHH",data,peoff+4)
    strings=b""
    strbase=symoff+nsyms*18 if symoff and nsyms else 0
    if strbase and strbase+4<=len(data):
        strlen=struct.unpack_from("<I",data,strbase)[0]
        strings=data[strbase:strbase+strlen]
    def coff_name(raw):
        if raw[:4]==b"\0\0\0\0":
            return cstr(strings,struct.unpack_from("<I",raw,4)[0])
        return raw.split(b"\0",1)[0].decode("utf-8","replace")
    symbols=[]
    if symoff and nsyms:
        i=0
        while i<nsyms and symoff+i*18+18<=len(data):
            p=symoff+i*18; raw=data[p:p+8]
            name=coff_name(raw)
            value,secnum,typ,storage,aux=struct.unpack_from("<IhHBB",data,p+8)
            symbols.append({"name":name,"value":value,"section":secnum,"type":typ,"storage":storage})
            i+=1+aux
    opt=peoff+24
    magic=struct.unpack_from("<H",data,opt)[0]
    dd=opt+(112 if magic==0x20b else 96)
    cli_rva,cli_size=struct.unpack_from("<II",data,dd+14*8)
    sections=[]
    p=opt+optlen
    for i in range(nsec):
        h=data[p+i*40:p+(i+1)*40]
        rawname=h[:8]
        name=rawname.split(b"\0",1)[0].decode("ascii","replace")
        if name.startswith("/") and name[1:].isdigit():
            name=cstr(strings,int(name[1:]))
        vs,va,rs,ro=struct.unpack_from("<IIII",h,8)
        characteristics=struct.unpack_from("<I",h,36)[0]
        sections.append((name,va,max(vs,rs),ro,rs,characteristics))
    def rvaoff(rva):
        for name,va,size,ro,rs,characteristics in sections:
            if va <= rva < va+size: return ro+(rva-va)
        return None
    cli_off=rvaoff(cli_rva) if cli_rva else None
    has_cli=bool(cli_off is not None and data.find(b"BSJB")>=0)
    bsjb=data.find(b"BSJB") if has_cli else -1
    version=""
    if bsjb>=0 and bsjb+16<=len(data):
        n=struct.unpack_from("<I",data,bsjb+12)[0]
        version=data[bsjb+16:bsjb+16+n].rstrip(b"\0").decode("utf-8","replace")
    return dict(machine=machine,has_cli=has_cli,metadata_version=version,sections=sections,symbols=symbols)

def machine_label(m):
    return {3:"Intel 80386",40:"ARM",62:"Advanced Micro Devices X86-64",183:"AArch64",243:"RISC-V",332:"i386",34404:"x86-64"}.get(m,str(m))

def config_from_record(buf, off):
    if off+12>len(buf) or buf[off:off+4]!=b"HCFG": return None
    ver,key=buf[off+4],buf[off+5]
    n=struct.unpack_from("<H",buf,off+6)[0]
    crc=struct.unpack_from("<I",buf,off+8)[0]
    if off+12+n>len(buf): return None
    decoded=bytes(b^key for b in buf[off+12:off+12+n])
    if zlib.crc32(decoded)&0xffffffff != crc: return None
    try: obj=json.loads(decoded.decode("utf-8"))
    except Exception: return None
    return dict(offset=off,version=ver,key=key,crc=crc,payload=decoded,obj=obj,record=buf[off:off+12+n])

def find_hcfg(data, allow_b64=True):
    raw=[]
    p=0
    while True:
        p=data.find(b"HCFG",p)
        if p<0: break
        r=config_from_record(data,p)
        if r: raw.append(r)
        p+=4
    if raw: return raw[0], "raw"
    if allow_b64:
        for m in HCFG_RE.finditer(data):
            s=m.group(0)
            try: dec=base64.b64decode(s,validate=True)
            except Exception: continue
            r=config_from_record(dec,0)
            if r: r["offset"]=m.start(); return r,"base64"
    return None,None

def class_info(data):
    if data[:4]!=b"\xca\xfe\xba\xbe": return None
    cp_count=struct.unpack_from(">H",data,8)[0]; i=1;p=10; utf={}
    while i<cp_count:
        tag=data[p];p+=1
        if tag==1:
            n=struct.unpack_from(">H",data,p)[0];p+=2
            try: utf[i]=data[p:p+n].decode("utf-8","replace")
            except: utf[i]=""
            p+=n
        elif tag in (3,4): p+=4
        elif tag in (5,6): p+=8;i+=1
        elif tag in (7,8,16,19,20): p+=2
        elif tag in (9,10,11,12,17,18): p+=4
        elif tag==15: p+=3
        else: raise ValueError(f"unknown JVM constant tag {tag}")
        i+=1
    access,thisc,superc=struct.unpack_from(">HHH",data,p);p+=6
    nint=struct.unpack_from(">H",data,p)[0];p+=2+2*nint
    nf=struct.unpack_from(">H",data,p)[0];p+=2
    for _ in range(nf):
        p+=6; na=struct.unpack_from(">H",data,p)[0];p+=2
        for _ in range(na):
            al=struct.unpack_from(">I",data,p+2)[0];p+=6+al
    nm=struct.unpack_from(">H",data,p)[0];p+=2; methods=[]
    for _ in range(nm):
        fl,ni,di=struct.unpack_from(">HHH",data,p);p+=6
        methods.append({"flags":fl,"name":utf.get(ni,""),"descriptor":utf.get(di,"")})
        na=struct.unpack_from(">H",data,p)[0];p+=2
        for _ in range(na):
            al=struct.unpack_from(">I",data,p+2)[0];p+=6+al
    return {"utf":utf,"methods":methods,"access":access}

def get_members(z):
    # Python's stdlib zipfile cannot decode the archive's Zstandard members;
    # use its central-directory order and the already password-verified extraction.
    return [(n,(EXTRACTED/Path(n).name).read_bytes()) for n in z.namelist() if not n.endswith("/") and Path(n).name.startswith("d")]

def overlay_config(data, magic):
    off=data.rfind(magic)
    if off<0: raise ValueError(f"missing {magic}")
    if magic==b"PK19":
        k1,k2=data[off+5],data[off+6]
        n=struct.unpack_from("<I",data,off+8)[0]
        want=data[off+12:off+44]; packed=data[off+44:off+44+n]
        plain=bytes((((b^k2)>>3)|((b^k2)<<5)&255)^k1 for b in packed)
        if hashlib.sha256(plain).digest()!=want: raise ValueError("PK19 unpacked SHA mismatch")
        cfg=config_from_record(plain,0)
        return off,len(data)-off,cfg
    n=struct.unpack_from("<I",data,off+8)[0]
    sn=struct.unpack_from("<H",data,off+12)[0]
    want=data[off+16:off+48]
    start=off+48; cfgbytes=data[start:start+n]; scratch=data[start+n:start+n+sn]
    if len(cfgbytes)!=n or len(scratch)!=sn or hashlib.sha256(scratch).digest()!=want: raise ValueError("RS20 overlay bounds/hash mismatch")
    return off,len(data)-off,config_from_record(cfgbytes,0),n

def main():
    answers={}; meta={}
    with zipfile.ZipFile(ARCHIVE) as z:
        members=get_members(z)
        byday={i:[(n,b) for n,b in members if Path(n).name.startswith(f"d{i:02d}--")] for i in range(1,23)}
        for d,items in byday.items():
            for idx,(name,b) in enumerate(items,1): answers[f"d{d:02d}_artifact_sha256_{idx}"]=hashlib.sha256(b).hexdigest()
        def first(d,ends=None,contains=None):
            a=byday[d]
            if ends: a=[x for x in a if Path(x[0]).name.endswith(ends)]
            if contains: a=[x for x in a if contains in Path(x[0]).name]
            if not a: raise ValueError(f"member not found d{d:02d} {ends} {contains}")
            return a[0][1]
        cfgs={}
        for d in (2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,21,22):
            if d==15: data=first(d,ends="stripped.elf")
            elif d==16: data=first(d,ends="compact.wasm")
            elif d==21: data=first(d,ends="plugin.cmxs")
            elif d==22: data=first(d,ends="sample.dll")
            elif d in (3,): data=first(d,ends="sample.dll")
            else: data=first(d)
            cfg,storage=find_hcfg(data)
            if d==2:
                ei=elf_info(data); pi=pe_info(data)
                if ei:
                    sec=next(s for s in ei["sections"] if s["name"]==".hcfg")
                    cfg,_=find_hcfg(data[sec["off"]:sec["off"]+sec["size"]],False)
                elif pi:
                    sec=next(s for s in pi["sections"] if s[0]==".hcfg")
                    cfg,_=find_hcfg(data[sec[3]:sec[3]+sec[4]],False)
            if d in (6,7):
                jar=first(d,ends="sample.jar")
                with zipfile.ZipFile(__import__("io").BytesIO(jar)) as j:
                    mainclass=""
                    for line in j.read("META-INF/MANIFEST.MF").decode("utf-8","replace").splitlines():
                        if line.lower().startswith("main-class:"): mainclass=line.split(":",1)[1].strip().replace(".","/")+".class"
                    ci=class_info(j.read(mainclass))
                    alltext="\n".join(ci["utf"].values())
                    if d==6:
                        for m in HCFG_RE.finditer(alltext.encode()):
                            try: dec=base64.b64decode(m.group(0),validate=True)
                            except Exception: continue
                            cfg=config_from_record(dec,0)
                            if cfg: break
                    else:
                        cfg,storage=find_hcfg(alltext.encode(),True)
                        if not cfg: cfg,storage=find_hcfg(j.read(mainclass),False)
                    answers[f"d{d:02d}_analysis_format"]="jar"
                    answers[f"d{d:02d}_analysis_compression_methods"]=sorted(set(i.compress_type for i in j.infolist()))
                    if d==6:
                        answers["d06_analysis_methods"]=[m["name"] for m in ci["methods"]]
                        answers["d06_analysis_access_flags"]=ci["access"]
                    else:
                        answers["d07_analysis_method_count"]=len(ci["methods"])
                        answers["d07_analysis_has_coroutine_runtime"]=any(n.startswith("kotlin/coroutines/") for n in j.namelist())
            if cfg: cfgs[d]=(cfg,storage)
        # Day 1 ELF details
        b=first(1); e=elf_info(b)
        answers["d01_analysis_elf_class"]="ELF64" if e["cls"]==2 else "ELF32"
        answers["d01_analysis_machine"]=machine_label(e["machine"])
        answers["d01_analysis_section_names"]=[s["name"] for s in e["sections"]]
        answers["d01_analysis_symbols"]=[s["name"] for s in e["symbols"] if s["name"]]
        answers["d01_analysis_elf_type"]={2:"ET_EXEC",3:"ET_DYN",1:"ET_REL"}.get(e["type"],str(e["type"]))
        answers["d01_analysis_endianness"]="little" if e["endian"]==1 else "big"
        answers["d01_analysis_entry_point"]=f"0x{e['entry']:x}"
        answers["d01_analysis_has_symtab"]=any(s["name"]==".symtab" for s in e["sections"])
        hs=next((s for s in e["sections"] if s["name"]==".huntress"),None)
        answers["d01_analysis_marker"]=b[hs["off"]:hs["off"]+hs["size"]].decode("utf-8").rstrip("\0") if hs else ""
        sym=next((s for s in e["symbols"] if s["name"]=="recover_code" and s["info"]&15==2),None)
        if sym:
            section=e["sections"][sym["shndx"]] if sym["shndx"] < len(e["sections"]) else None
            fileoff=(section["off"]+sym["value"]-section["addr"]) if section else sym["value"]
            code=b[fileoff:fileoff+sym["size"]]
            imm=None
            m=re.match(b"\xb8(.{4})\xc3",code)
            if m: imm=int.from_bytes(m.group(1),"little")
            answers["d01_analysis_recover_code"]=imm if imm is not None else "none"
            d01path=EXTRACTED/Path(next(n for n,data in byday[1] if data==b)).name
            dis=subprocess.run(["objdump","-d","-M","intel","--disassemble=recover_code",str(d01path)],capture_output=True,text=True).stdout
            ins=[]
            for line in dis.splitlines():
                m=re.match(r"\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*([a-z][a-z0-9.]*(?:\s+.*)?)$",line)
                if m: ins.append(re.sub(r"\s+", " ", m.group(1).strip()))
            answers["d01_analysis_disassembly"]=ins
        else:
            answers["d01_analysis_recover_code"]="none";answers["d01_analysis_disassembly"]=[]
        # ELF and PE format/architecture metadata
        for d in range(1,23):
            if d in (6,7,16): continue
            candidates=byday[d]
            if d==3: candidates=[x for x in candidates if Path(x[0]).name.endswith(".dll")]
            elif d==15: candidates=[x for x in candidates if "stripped" in Path(x[0]).name]
            elif d==21: candidates=[x for x in candidates if Path(x[0]).name.endswith("loader.elf")]
            elif d==22: candidates=[x for x in candidates if Path(x[0]).name.endswith("sample.dll")]
            elif d==19 or d==20: candidates=candidates[:1]
            if candidates:
                name,data=candidates[0]; ei=elf_info(data); pi=pe_info(data)
                fmt="elf" if ei else ("pe_cli" if pi and pi["has_cli"] else "pe" if pi else "wasm" if data.startswith(b"\0asm") else "neko_bytecode" if data.startswith(b"NEKO") else "unknown")
                if d==1: pass
                elif d==2:
                    answers["d02_analysis_format"]="elf" if ei else ("pe" if pi else fmt)
                elif d in (15,):
                    answers["d15_analysis_stripped_format"]=fmt
                    answers["d15_analysis_stripped_architecture"]="x86-64" if ei and ei["machine"]==62 else "wasm32" if fmt=="wasm" else machine_label(ei["machine"] if ei else pi["machine"])
                elif d==21:
                    answers["d21_analysis_loader_machine"]=ei["machine"] if ei else pi["machine"]
                else:
                    answers[f"d{d:02d}_analysis_format"]=fmt
                    machine=ei["machine"] if ei else pi["machine"] if pi else None
                    if machine is not None: answers[f"d{d:02d}_analysis_architecture"]=machine_label(machine);answers[f"d{d:02d}_analysis_machine"]=machine_label(machine)
                if d==3: answers["d03_analysis_metadata_version"]=pi["metadata_version"]
                if d==22: answers["d22_analysis_metadata_version"]=pi["metadata_version"]
                if d==15:
                    other=first(15,ends="symbolized.elf");oe=elf_info(other)
                    answers["d15_analysis_symbolized_format"]="elf"
                    answers["d15_analysis_symbolized_architecture"]="x86-64" if oe["machine"]==62 else machine_label(oe["machine"])
                    answers["d15_analysis_symbolized_machine"]=oe["machine"]
                if d==21:
                    plug=first(21,ends="plugin.cmxs");answers["d21_analysis_plugin_machine"]=elf_info(plug)["machine"]
        # Per-day config answer fields
        for d,(cfg,storage) in cfgs.items():
            obj=cfg["obj"]; pre=f"d{d:02d}_analysis_"
            for k in ("campaign","domain","mutex","url"):
                if k in obj: answers[pre+"config_"+k]=obj[k]
            if f"d{d:02d}_analysis_config_crc32_hex" in {q for q in []}: pass
            answers[pre+"config_crc32_hex"]=f"0x{cfg['crc']:08x}"
            answers[pre+"hcfg_version"]=cfg["version"]
            answers[pre+"xor_key_hex"]=f"0x{cfg['key']:02x}"
            answers[pre+"hcfg_offset"]=cfg["offset"]
            answers[pre+"hcfg_storage"]=storage
        # Special per-unit predicates and overlays
        d2data=first(2);d2=elf_info(d2data); d2pe=pe_info(d2data)
        syms=[s["name"] for s in d2["symbols"] if s["name"]] if d2 else [s["name"] for s in d2pe["symbols"] if s["name"]]
        answers["d02_analysis_has_cpp_typeinfo"]=any(re.search(r"ZTI.*DiscoveryEngine",s) for s in syms)
        answers["d02_analysis_has_cpp_vtable"]=any(re.search(r"ZTV.*DiscoveryEngine",s) for s in syms)
        answers["d02_analysis_mangled_score_symbol"]=next(s for s in syms if re.search(r"DiscoveryEngine.*score",s))
        answers["d02_analysis_typeinfo_symbol"]=next(s for s in syms if re.search(r"ZTI.*DiscoveryEngine",s))
        answers["d04_analysis_has_go_runtime"]=b"runtime.main" in first(4)
        answers["d05_analysis_has_rust_mangled_symbol"]=any(s["name"].startswith(("_ZN","_R")) for s in elf_info(first(5))["symbols"] if s["name"])
        for d in (8,9,10,11,12,13,14,17,18):
            b=first(d);e=elf_info(b)
            if d==10:
                pi=pe_info(b)
                if e: answers["d10_analysis_has_hcfg_section"]=any("hcfg" in s["name"] for s in e["sections"])
                else: answers["d10_analysis_has_hcfg_section"]=any("hcfg" in s[0] for s in pi["sections"])
            # Config discovery is generic; offset/storage are adjusted by the scored question rules.
        # d08-d14 carrier details and special wasm
        for d in (8,9,10,11,12,13,14,17,18):
            cfg,storage=cfgs[d]
            data=first(d);ei=elf_info(data)
            if storage!="base64" and ei:
                sec=next((s for s in ei["sections"] if s["name"]==".hcfg"),None)
                if sec and sec["off"]<=cfg["offset"]<sec["off"]+sec["size"]:
                    storage="raw_hcfg_section"
                else:
                    containing=next((s for s in ei["sections"] if s["off"]<=cfg["offset"]<s["off"]+s["size"]),None)
                    ref=False
                    if containing:
                        target=containing["addr"]+cfg["offset"]-containing["off"]
                        path=EXTRACTED/Path(next(n for n,b in byday[d] if b==data)).name
                        dis=subprocess.run(["objdump","-d",str(path)],capture_output=True,text=True).stdout
                        ref=bool(re.search(rf"0x{target:x}(?![0-9a-f])",dis,re.I))
                    storage="raw_const_array" if ref else "raw"
            cfgs[d]=(cfg,storage)
            answers[f"d{d:02d}_analysis_hcfg_storage"]=storage
        for d in (4,5):
            data=first(d);ei=elf_info(data);pi=pe_info(data)
            answers[f"d{d:02d}_analysis_section_names"]=[s["name"] for s in ei["sections"]] if ei else [s[0] for s in pi["sections"]]
        answers["d08_analysis_elf_class"]=64 if elf_info(first(8))["cls"]==2 else 32
        answers["d14_analysis_has_hcfg_section"]=any(s["name"]==".hcfg" for s in elf_info(first(14))["sections"])
        # Day 15's numeric machine code and the two independent WASM configs.
        answers["d15_analysis_stripped_machine"]=elf_info(first(15,ends="stripped.elf"))["machine"]
        for d,ending in ((16,"compact.wasm"),(16,"direct.wasm")):
            data=first(16,ends=ending);cfg,storage=find_hcfg(data,False)
            tag="compact" if "compact" in ending else "direct"
            answers[f"d16_analysis_{tag}_format"]="wasm";answers[f"d16_analysis_{tag}_architecture"]="wasm32"
            keys=("campaign","domain","mutex","url") if tag=="compact" else ("campaign","domain")
            for k in keys:
                if k in cfg["obj"]: answers[f"d16_analysis_{tag}_config_{k}"]=cfg["obj"][k]
        # d15 stripped config from corresponding file
        cfg,_=find_hcfg(first(15,ends="stripped.elf"))
        for k in ("campaign","domain","mutex","url"): answers[f"d15_analysis_stripped_config_{k}"]=cfg["obj"][k]
        # d19/d20 overlays
        b=first(19);off,size,cfg=overlay_config(b,b"PK19")
        answers["d19_analysis_overlay_offset"]=off;answers["d19_analysis_overlay_size"]=size
        for k in ("campaign","domain","mutex","url"): answers[f"d19_analysis_config_{k}"]=cfg["obj"][k]
        answers["d19_analysis_config_crc32_hex"]=f"0x{cfg['crc']:08x}";answers["d19_analysis_hcfg_version"]=cfg["version"]
        b=first(20);off,size,cfg,res=overlay_config(b,b"RS20")
        answers["d20_analysis_overlay_offset"]=off;answers["d20_analysis_hcfg_resource_size"]=res
        for k in ("campaign","domain","mutex","url"): answers[f"d20_analysis_config_{k}"]=cfg["obj"][k]
        answers["d20_analysis_config_crc32_hex"]=f"0x{cfg['crc']:08x}";answers["d20_analysis_hcfg_version"]=cfg["version"]
        # The Day 21 questions distinguish the plugin's config from the loader.
        cfg,_=find_hcfg(first(21,ends="plugin.cmxs"))
        for k in ("campaign","domain","mutex","url"): answers[f"d21_analysis_plugin_config_{k}"]=cfg["obj"][k]
        # Metadata fields omitted by generic loop for special names
        answers["d03_analysis_format"]="pe_cli";answers["d03_analysis_machine"]=machine_label(pe_info(first(3,ends=".dll"))["machine"])
        answers["d22_analysis_format"]="pe_cli";answers["d22_analysis_machine"]=machine_label(pe_info(first(22,ends="sample.dll"))["machine"])
    OUT.write_text(json.dumps(answers,separators=(",",":"),ensure_ascii=False))
    print(json.dumps({"answer_count":len(answers),"output":str(OUT),"unanswered_expected_ids":None},separators=(",",":")))

if __name__=="__main__": main()
