#!/usr/bin/env python3
"""Derive Actions Speak Louder answers from the assigned inert archive."""
import json, pathlib, re, sys, base64, os
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import solve_fetch_quest_day17 as solver

START = pathlib.Path(os.environ.get('ACTIONS_START_JSON','/tmp/day21-actions-start.json'))
ROOT = pathlib.Path(os.environ.get('ACTIONS_EVIDENCE_DIR','/home/remnux/files/samples/day21-actions-evidence'))
OUT = pathlib.Path(os.environ.get('ACTIONS_ANSWERS_JSON','/tmp/day21-actions-answers.json'))

def graph_role(steps):
    s=steps.replace(',', '>')
    if s == 'decode_configuration>return_configuration': return 'benign_utility'
    if 'profile_host' in s and ('dispatch_process' in s or 'handoff_script' in s): return 'staged_chain'
    if 'build_schedule' in s and 'register_descriptor' in s: return 'persistence_descriptor'
    if 'transform_content' in s or 'transform_copy' in s: return 'impact'
    if 'dispatch_next_stage' in s: return 'relay'
    if 'handoff_script' in s: return 'staged_chain'
    if 'upload_remote' in s or 'transmit_remote' in s: return 'uploader'
    if 'locate_local' in s and 'dispatch_process' in s: return 'launcher'
    if 'acquire_remote' in s and ('dispatch_memory' in s or 'dispatch_pipe' in s): return 'stager'
    if 'decode_embedded' in s and 'write_file' in s: return 'dropper'
    if 'acquire_remote' in s and 'write_file' in s: return 'downloader'
    if 'dispatch_memory' in s: return 'stager'
    return 'unknown'

def attack_for(fields):
    s=fields.get('steps','').replace(',','>')
    if fields.get('attack'): return fields['attack']
    if 'recognize_syntax' in s: return 'T1059.004'
    if s == 'decode_configuration>return_configuration': return 'none'
    if 'handoff_script' in s or 'dispatch_next_stage' in s or 'dispatch_process' in s: return 'T1059'
    if 'transform_content' in s or 'transform_copy' in s: return 'T1486'
    if 'build_schedule' in s and 'register_descriptor' in s:
        return 'T1053.003' if 'cron' in fields.get('adapter','').lower() or fields.get('schedule_path','').startswith('/etc/cron') else 'T1053'
    if 'upload_remote' in s or 'transmit_remote' in s: return 'T1041'
    if 'decode_embedded' in s: return 'T1140'
    if 'acquire_remote' in s or 'dispatch_memory' in s: return 'T1105'
    return 'T1059'

def parse_host_context(path):
    text=path.read_text(errors='replace')
    m=re.search(r'v_a19c\s*=\s*\[([^\]]+)\]',text)
    if not m: return None,{}
    raw=bytes(int(x) & 255 for x in re.findall(r'\d+',m.group(1)))
    # The literal is reversed in recover_* and reversed again by decode_*;
    # the two static reversals cancel. No script execution is needed.
    obj=json.loads(raw.decode('utf-8'))
    fields={}
    for k,v in obj.items():
        if isinstance(v,dict): fields.update({a:('>'.join(b) if isinstance(b,list) else str(b)) for a,b in v.items()})
        else: fields[k]=('>'.join(v) if isinstance(v,list) else str(v))
    if 'stageCount' in fields: fields['stage_count']=fields['stageCount']
    return raw.decode('utf-8'),fields

def code_styles(text):
    m=re.search(r'(?im)^\s*(?:var\s+)?(inspect_[A-Za-z0-9_]+)\s*=\s*function(?:\s+([A-Za-z0-9_]+))?\s*\(',text)
    if not m: fs='declaration' if re.search(r'(?m)^\s*function\s+inspect_',text) else 'anonymous_expression'
    else: fs='named_expression' if m.group(2) else 'anonymous_expression'
    inv='apply' if re.search(r'recover_[A-Za-z0-9_]+\.apply\s*\(',text) else 'call' if re.search(r'recover_[A-Za-z0-9_]+\.call\s*\(',text) else 'direct'
    im=re.search(r'(?is)(?:function\s+inspect_[^(]+\([^)]*\)|inspect_[A-Za-z0-9_]+\s*=\s*function[^\{]*\{)(.*?)(?:\n\s*};?|\n\s*})',text)
    body=im.group(1) if im else ''
    vm=re.search(r'(?:var|let|const)\s+([A-Za-z_][\w]*)\s*=\s*eval\s*\(',body)
    if not vm: return fs,inv,'unknown'
    var=vm.group(1); snippet=body[vm.start():]
    props=re.findall(re.escape(var)+r"(?:\.([A-Za-z_$][\w$]*)|\[['\"]([^'\"]+)['\"]\])",snippet)
    if not props: ps='unknown'
    else:
        kinds={'bracket_literal' if b else 'dot' for a,b in props}
        ps=next(iter(kinds)) if len(kinds)==1 else 'mixed'
    return fs,inv,ps

def batch_reconstruction(text):
    lines=text.splitlines()
    candidates=[]
    for i,line in enumerate(lines):
        low=line.lower()
        # Select the assembled descriptor assignment, not fragment definitions,
        # blank initializers, echo statements, or the host's --plan envelope.
        if re.search(r'\b(?:recovered(?:_configuration)?|cfg|item\d+)\s*=',low) and re.search(r'(?:%[a-z_][\w]*%|![a-z_][\w]*!|%%|fragment|\bh\d|\bv_a\d|item\d)',low):
            if re.match(r'\s*echo\b',low): continue
            candidates.append((i,line))
    if not candidates: return None,None
    idx,line=candidates[-1]; low=line.lower()
    if re.search(r'\bfor\s+(?:/\w+\s+)?%%',low): expansion='for_indirect'
    elif re.search(r'\bcall\s+set\b',low) and '%%' in low: expansion='call_double'
    elif '!' in line: expansion='delayed'
    else: expansion='percent'
    stripped=low.strip()
    if re.match(r'if\s+defined\b',stripped): control='if_guard'
    else:
        preceding=lines[:idx]
        labels=[(n,l.strip().lower()) for n,l in enumerate(preceding) if re.match(r'\s*:huntress_(?:recover|dispatch)\b',l,re.I)]
        nearest=labels[-1][1] if labels else ''
        if 'recover' in nearest:
            call_i=None
            for n,l in enumerate(preceding):
                if re.search(r'\bcall\s+:huntress_recover\b',l,re.I): call_i=n
            if call_i is not None and any(re.search(r'for\s+%%\w+\s+in\s*\(\s*1\s*\)\s*do\s*call\s+:huntress_recover',l,re.I) for l in preceding[:call_i+1]):
                control='for_once'
            else: control='call_subroutine'
        elif 'dispatch' in nearest and any(re.search(r'goto\s+:huntress_dispatch\b',l,re.I) for l in preceding):
            control='goto_dispatch'
        elif any(re.search(r'if\s+errorlevel\s+\d+\s+exit\b',l,re.I) for l in preceding[-5:]):
            control='errorlevel_guard'
        else: control='direct'
    return expansion,control

def main():
    start=json.loads(START.read_text())
    descriptors={}
    for p in ROOT.iterdir():
        if not p.is_file(): continue
        try: plain,fields=solver.static_descriptor(p)
        except Exception: plain,fields=None,{}
        if not fields and p.name=='host-context.js': plain,fields=parse_host_context(p)
        if fields: descriptors[p.name]=(plain,fields,p.read_text(errors='replace'))
    answers={}; missing=[]
    for q in start['questions']:
        aid=q['id']; filename=q['artifact'].split('->')[-1].strip(); suffix=aid.split('-')[-1].lower()
        if filename not in descriptors:
            missing.append((aid,filename,'no descriptor')); continue
        plain,f,text=descriptors[filename]; low=aid.lower(); qtext=q['question'].lower(); value=None
        if filename.endswith('-sample.ps1'):
            if 'resource' in filename:
                lookup={'scenario':'resource_hijacking','attack':'T1496','url':f.get('b'),'wallet':f.get('c'),'mutex':f.get('h')}
            elif 'collection' in filename:
                lookup={'scenario':'synthetic_collection','attack':'T1555.003','url':f.get('b'),'file':f.get('c','').split('>')[0],'agent':f.get('f')}
            else: lookup={'scenario':'synthetic_impact','attack':'T1486','extension':f.get('b'),'note':f.get('c'),'url':f.get('d')}
            value=lookup.get(suffix)
        elif suffix=='attack': value=attack_for(f)
        elif suffix=='role': value='advanced_syntax' if 'bash-advanced-' in low else (f.get('role') or graph_role(f.get('steps','')))
        elif suffix=='style' and filename.endswith('.js'):
            styles=code_styles(text); kind='function-style' if 'function-style' in low else 'invocation-style' if 'invocation-style' in low else 'property-style'
            value=styles[{'function-style':0,'invocation-style':1,'property-style':2}[kind]]
        elif filename.endswith(('.cmd','.bat')) and suffix in ('expansion','control'):
            expansion,control=batch_reconstruction(text)
            value=expansion if suffix=='expansion' else control
        elif filename.endswith('.vbs') and suffix in ('representation','transform','control'):
            cm=re.search(r'(?im)^\s*Const\s+Codec_[A-Za-z0-9_]+\s*=\s*"([^"]+)"',text); cparts=cm.group(1).split('|') if cm else ['identity','identity']
            if suffix=='representation': value=cparts[0]
            elif suffix=='transform': value=cparts[1] if len(cparts)>1 else 'identity'
            elif re.search(r'(?im)^\s*For\s+\w+\s*=\s*0\s+To\s+0',text): value='for_once'
            elif re.search(r'(?im)^\s*Do\s*$',text) and re.search(r'(?im)^\s*Exit\s+Do',text): value='do_once'
            elif re.search(r'(?im)^\s*While\s+',text): value='while_once'
            elif re.search(r'(?im)^\s*Select\s+Case\s+1',text): value='select_case'
            elif re.search(r'On Error Resume Next',text): value='error_guard'
            else: value='direct'
        else:
            textkey=qtext+' '+low
            if 'host-profile' in low or 'host profile' in textkey: key='host_profile'
            elif 'obfuscation' in low: key='obfuscation_profile' if 'obfuscation_profile' in f else 'obfuscation'
            elif 'stage-profile' in low or 'stage profile' in textkey: key='stage_profile'
            elif 'next-language' in low or 'next script language' in textkey: key='next_language'
            elif 'upload-url' in low or 'upload_url' in textkey: key='upload_url'
            elif 'steps' in low: key='steps'
            elif 'stage-count' in low or suffix=='count': key='stage_count'
            elif 'cron-path' in low: key='cron_path'
            elif 'schedule-path' in low: key='schedule_path'
            elif 'file-path' in low or suffix=='path': key='file_path'
            elif 'next-stage' in low: key='next_stage'
            elif 'host-id' in low or 'host indicator' in textkey: key='host_id'
            elif 'handoff-id' in low: key='handoff_id'
            elif 'windows-chain' in low or 'windows execution-chain' in textkey: key='windows_chain'
            elif 'note-name' in low or 'recovery-note' in textkey: key='note_name'
            elif suffix=='attack': key='attack'
            elif suffix=='url': key='url'
            elif suffix=='adapter': key='adapter'
            elif suffix=='campaign': key='campaign_id'
            elif suffix=='count': key='stage_count'
            elif suffix=='steps': key='steps'
            elif suffix=='role': key='role'
            elif suffix=='language': key='next_language'
            elif suffix=='extension': key='extension'
            elif suffix=='note': key='note_name'
            elif suffix=='name': key='service_name'
            elif suffix=='wallet': key='wallet'
            elif suffix=='mutex': key='mutex'
            elif suffix=='file': key='file_path'
            elif suffix=='agent': key='user_agent'
            elif suffix=='host' or suffix=='id': key='host_id'
            elif suffix=='stage': key='stage_profile'
            elif suffix=='profile': key='profile'
            else: key=suffix.replace('-','_')
            value=f.get(key)
            if key=='steps' and value: value=value.replace(',','>')
            if key=='stage_count' and value is None: value=f.get('stageCount')
            if key=='profile' and value is None:
                value=f.get('stage_profile') or f.get('host_profile') or f.get('obfuscation_profile')
        if value is None:
            missing.append((aid,filename,'unmapped')); continue
        if q.get('answer_format',{}).get('kind') == 'integer':
            try: value=int(value)
            except (TypeError,ValueError):
                missing.append((aid,filename,'invalid integer')); continue
        else:
            value=str(value)
        answers[aid]=value
    OUT.write_text(json.dumps(answers,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'questions':len(start['questions']),'answers':len(answers),'missing':missing[:30],'missing_count':len(missing),'answer_file':str(OUT),'answer_bytes':OUT.stat().st_size},separators=(',',':')))

if __name__=='__main__': main()
