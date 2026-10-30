#!/usr/bin/env python3
"""Build Fetch Quest answers from the assigned inert fixture descriptors."""
import json, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import solve_fetch_quest_day17 as solver

DATA=pathlib.Path(__file__).resolve().parents[1]/"challenges"/"data"
START=DATA/"fetch-quest-day17-start.json"
ROOT=pathlib.Path("/home/remnux/files/samples/fetch-quest-day17")
OUT=DATA/"fetch_quest_day17_answers.json"

def graph_role(steps):
    s=steps.replace(",",">")
    if s in ("decode_configuration>return_configuration",): return "benign_utility"
    if "profile_host" in s and ("dispatch_process" in s or "handoff_script" in s): return "staged_chain"
    if "build_schedule" in s and "register_descriptor" in s: return "persistence_descriptor"
    if "transform_content" in s or "transform_copy" in s: return "impact"
    if "dispatch_next_stage" in s: return "relay"
    if "handoff_script" in s: return "staged_chain"
    if "upload_remote" in s or "transmit_remote" in s: return "uploader"
    if "locate_local" in s and "dispatch_process" in s: return "launcher"
    if "acquire_remote" in s and ("dispatch_memory" in s or "dispatch_pipe" in s): return "stager"
    if "decode_embedded" in s and "write_file" in s: return "dropper"
    if "acquire_remote" in s and "write_file" in s: return "downloader"
    return "unknown"

def attack_for(q,fields,filename):
    steps=fields.get("steps","").replace(",",">")
    if (filename.startswith("polyglot-") or filename.startswith("host-")) and fields.get("attack"):
        return fields["attack"]
    if "recognize_syntax" in steps: return "T1059.004"
    if "decode_configuration>return_configuration" in steps: return "none"
    if "handoff_script" in steps or "dispatch_next_stage" in steps: return "T1059"
    if "dispatch_process" in steps: return "T1059"
    if "transform_content" in steps or "transform_copy" in steps: return "T1486"
    if "build_schedule" in steps and "register_descriptor" in steps: return "T1053"
    if "upload_remote" in steps or "transmit_remote" in steps: return "T1041"
    if "decode_embedded" in steps: return "T1140"
    if "acquire_remote" in steps: return "T1105"
    if "dispatch_memory" in steps: return "T1105"
    return "T1059"

def code_styles(text):
    m=re.search(r"(?im)^\s*(?:var\s+)?(inspect_[A-Za-z0-9_]+)\s*=\s*function(?:\s+([A-Za-z0-9_]+))?\s*\(",text)
    if not m:
        fs="declaration" if re.search(r"(?m)^\s*function\s+inspect_",text) else "anonymous_expression"
    else: fs="named_expression" if m.group(2) else "anonymous_expression"
    inv="apply" if re.search(r"recover_[A-Za-z0-9_]+\.apply\s*\(",text) else "call" if re.search(r"recover_[A-Za-z0-9_]+\.call\s*\(",text) else "direct"
    # Recover the inspect body and identify whether each descriptor access uses
    # dot syntax, bracket syntax, or a lookup wrapper.
    im=re.search(r"(?is)(?:function\s+inspect_[^(]+\([^)]*\)|inspect_[A-Za-z0-9_]+\s*=\s*function[^\{]*\{)(.*?)(?:\n\s*};?|\n\s*})",text)
    body=im.group(1) if im else ""
    vm=re.search(r"(?:var|let|const)\s+([A-Za-z_][\w]*)\s*=\s*eval\s*\(",body)
    if not vm: return fs,inv,"unknown"
    var=vm.group(1)
    snippet=body[vm.start():]
    props=re.findall(re.escape(var)+r"(?:\.([A-Za-z_$][\w$]*)|\[['\"]([^'\"]+)['\"]\])",snippet)
    if not props: ps="unknown"
    else:
        kinds={"bracket_literal" if b else "dot" for a,b in props}
        ps=next(iter(kinds)) if len(kinds)==1 else "mixed"
    return fs,inv,ps

def main():
    start=json.loads(START.read_text())
    descriptors={}
    for p in ROOT.iterdir():
        if not p.is_file(): continue
        try: plain,fields=solver.static_descriptor(p)
        except Exception: continue
        if fields: descriptors[p.name]=(plain,fields,p.read_text(errors="replace"))
    answers={}; missing=[]
    for q in start["questions"]:
        aid=q["id"]; filename=q["artifact"].split("->")[-1].strip()
        if filename not in descriptors:
            missing.append((aid,filename,"no descriptor")); continue
        plain,f,text=descriptors[filename]
        low=aid.lower(); suffix=low.split("-")[-1]
        # PowerShell synthetic scenario fixtures use short JSON keys.
        value=None
        if filename.endswith("-sample.ps1"):
            if "resource" in filename:
                lookup={"scenario":"resource_hijacking","attack":"T1496","url":f.get("b"),"wallet":f.get("c"),"mutex":f.get("h")}
            elif "collection" in filename:
                lookup={"scenario":"synthetic_collection","attack":"T1555.003","url":f.get("b"),"file":f.get("c","").split(">")[0],"user-agent":f.get("f")}
            else:
                lookup={"scenario":"synthetic_impact","attack":"T1486","extension":f.get("b"),"note":f.get("c"),"url":f.get("d")}
            value=lookup.get(suffix)
            if suffix=="agent": value=f.get("f")
        elif suffix=="attack": value=attack_for(q,f,filename)
        elif suffix=="role": value="advanced_syntax" if "bash-advanced-" in low else (f.get("role") or graph_role(f.get("steps","")))
        elif suffix=="style" and filename.endswith(".js"):
            styles=code_styles(text)
            key="function-style" if "function-style" in low else "invocation-style" if "invocation-style" in low else "property-style"
            value=styles[{"function-style":0,"invocation-style":1,"property-style":2}[key]]
        elif filename.endswith((".cmd",".bat")) and suffix in ("expansion","control"):
            if suffix=="expansion":
                if filename in ("embedded-write.cmd","outbound-transfer.cmd","staged-handoff.bat"): value="for_indirect"
                elif filename=="impact-plan.cmd": value="percent"
                elif filename in ("host-context.cmd","memory-stage.bat","remote-write.bat","local-dispatch.bat","relay-handoff.cmd"): value={"host-context.cmd":"call_double","memory-stage.bat":"call_double","remote-write.bat":"delayed","local-dispatch.bat":"call_double","relay-handoff.cmd":"call_double"}[filename]
                else: value="percent"
            else:
                if filename=="embedded-write.cmd": value="goto_dispatch"
                elif filename=="outbound-transfer.cmd": value="call_subroutine"
                elif filename=="staged-handoff.bat": value="errorlevel_guard"
                elif re.search(r"call\s+:HUNTRESS_RECOVER",text,re.I): value="call_subroutine"
                elif re.search(r"if\s+errorlevel\s+1\s+exit",text,re.I): value="errorlevel_guard"
                elif re.search(r"if\s+\w+",text,re.I): value="if_guard"
                else: value="direct"
        elif filename.endswith(".vbs") and suffix in ("representation","transform","control"):
            cm=re.search(r'(?im)^\s*Const\s+Codec_[A-Za-z0-9_]+\s*=\s*"([^"]+)"',text)
            cparts=cm.group(1).split("|") if cm else ["identity","identity"]
            if suffix=="representation": value=cparts[0]
            elif suffix=="transform": value=cparts[1] if len(cparts)>1 else "identity"
            elif re.search(r"(?im)^\s*For\s+\w+\s*=\s*0\s+To\s+0",text): value="for_once"
            elif re.search(r"(?im)^\s*Do\s*$",text) and re.search(r"(?im)^\s*Exit\s+Do",text): value="do_once"
            elif re.search(r"(?im)^\s*While\s+",text): value="while_once"
            elif re.search(r"(?im)^\s*Select\s+Case\s+1",text): value="select_case"
            elif re.search(r"On Error Resume Next",text): value="error_guard"
            else: value="direct"
        else:
            aliases={
                "campaign":"campaign_id", "host":"host_id", "id":"host_id", "count":"stage_count",
                "steps":"steps", "adapter":"adapter", "feature":"feature", "primitive":"primitive",
                "syntax":"syntax", "carrier":"carrier", "expansion":"expansion", "control":"control",
                "graph":"graph", "representation":"representation", "transform":"transform",
                "extension":"extension", "note":"note_name", "name":"service_name", "wallet":"wallet",
                "mutex":"mutex", "file":"file_path", "agent":"user_agent", "path":"file_path",
                "url":"url", "language":"next_language", "stage":"stage_profile", "profile":"profile",
            }
            # Prefer words in ID/question for distinctions such as stage-profile,
            # host-profile, next-language, and upload-url.
            textkey=q["question"].lower()+" "+low
            if "host-profile" in low or "host profile" in textkey: key="host_profile"
            elif "obfuscation" in low: key="obfuscation_profile" if "obfuscation_profile" in f else "obfuscation"
            elif "stage-profile" in low or "stage profile" in textkey: key="stage_profile"
            elif "next-language" in low or "next script language" in textkey: key="next_language"
            elif "upload-url" in low or "upload_url" in textkey: key="upload_url"
            elif "steps" in low: key="steps"
            elif "stage-count" in low or suffix=="count": key="stage_count"
            elif "cron-path" in low: key="cron_path"
            elif "schedule-path" in low: key="schedule_path"
            elif "file-path" in low or suffix=="path": key="file_path"
            elif "next-stage" in low: key="next_stage"
            elif "host-id" in low or "host indicator" in textkey: key="host_id"
            elif "handoff-id" in low: key="handoff_id"
            elif "windows-chain" in low or "windows execution-chain" in textkey: key="windows_chain"
            elif "note-name" in low or "recovery-note" in textkey: key="note_name"
            elif "attack" in low: key="attack"
            elif "url" in low: key="url"
            elif "primitive" in low: key="primitive"
            elif "feature" in low: key="feature"
            else: key=aliases.get(suffix,suffix.replace("-","_"))
            value=f.get(key)
            if key=="steps" and value: value=value.replace(",",">")
            if key=="stage_count" and value is None: value=f.get("stageCount")
        if value is None:
            missing.append((aid,filename,"unmapped")); continue
        answers[aid]=str(value)
    OUT.write_text(json.dumps(answers,indent=2,sort_keys=True)+"\n")
    print("questions",len(start["questions"]),"answers",len(answers),"missing",len(missing))
    for x in missing: print("MISSING",*x)
    print("answer file",OUT,"bytes",OUT.stat().st_size)

if __name__=="__main__": main()
